// An HTTPS POST built on mbedtls, so the CLI needs no dependency the library
// does not already have and can be linked statically on every platform.
//
// This is deliberately the small 20% of HTTP: one verb, absolute URL, headers,
// Content-Length or chunked response, no redirects, no keep-alive, no
// compression. That is the whole of what the two Midea cloud endpoints need.
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>

#if defined(MBEDTLS_PSA_CRYPTO_C)
#include <psa/crypto.h>
#endif

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "ca_bundle.h"
#include "net.h"

namespace coolth_cli {
namespace {

// Matches the timeout the libcurl implementation used.
constexpr uint32_t kTimeoutMilliseconds = 25000;
constexpr size_t kChunkSize = 4096;
// A cloud reply is a few kilobytes; this only bounds a server gone haywire.
constexpr size_t kMaxResponseBytes = 8u << 20;

std::string mbed_error(const std::string &what, int rc) {
  char detail[128] = {};
  mbedtls_strerror(rc, detail, sizeof(detail));
  return what + ": " + detail;
}

struct Url {
  std::string host;
  std::string port;
  std::string path;
};

bool parse_url(const std::string &url, Url *out) {
  static const std::string kScheme = "https://";
  if (url.size() <= kScheme.size() ||
      url.compare(0, kScheme.size(), kScheme) != 0)
    return false;
  const size_t host_start = kScheme.size();
  size_t host_end = url.find('/', host_start);
  if (host_end == std::string::npos) {
    out->path = "/";
    host_end = url.size();
  } else {
    out->path = url.substr(host_end);
  }
  const std::string authority = url.substr(host_start, host_end - host_start);
  const size_t colon = authority.rfind(':');
  // rfind, but an IPv6 literal would put colons inside brackets. Not a case
  // these endpoints produce; reject it rather than mis-parse it.
  if (!authority.empty() && authority.front() == '[')
    return false;
  if (colon == std::string::npos) {
    out->host = authority;
    out->port = "443";
  } else {
    out->host = authority.substr(0, colon);
    out->port = authority.substr(colon + 1);
  }
  return !out->host.empty() && !out->port.empty();
}

// One TLS connection, torn down by the destructor whatever the exit path.
class TlsConnection {
 public:
  TlsConnection() {
    mbedtls_net_init(&net_);
    mbedtls_ssl_init(&ssl_);
    mbedtls_ssl_config_init(&config_);
    mbedtls_x509_crt_init(&ca_);
    mbedtls_ctr_drbg_init(&ctr_drbg_);
    mbedtls_entropy_init(&entropy_);
  }

  ~TlsConnection() {
    if (handshaken_)
      mbedtls_ssl_close_notify(&ssl_);
    mbedtls_net_free(&net_);
    mbedtls_ssl_free(&ssl_);
    mbedtls_ssl_config_free(&config_);
    mbedtls_x509_crt_free(&ca_);
    mbedtls_ctr_drbg_free(&ctr_drbg_);
    mbedtls_entropy_free(&entropy_);
  }

  TlsConnection(const TlsConnection &) = delete;
  TlsConnection &operator=(const TlsConnection &) = delete;

  bool open(const Url &url, std::string *error) {
    if (!load_trust_roots(error))
      return false;

    const char *seed = "coolth-cpp";
    int rc = mbedtls_ctr_drbg_seed(&ctr_drbg_, mbedtls_entropy_func, &entropy_,
                                   reinterpret_cast<const unsigned char *>(seed),
                                   strlen(seed));
    if (rc != 0) {
      *error = mbed_error("could not seed the random generator", rc);
      return false;
    }

    rc = mbedtls_ssl_config_defaults(&config_, MBEDTLS_SSL_IS_CLIENT,
                                     MBEDTLS_SSL_TRANSPORT_STREAM,
                                     MBEDTLS_SSL_PRESET_DEFAULT);
    if (rc != 0) {
      *error = mbed_error("could not configure TLS", rc);
      return false;
    }
    // The point of carrying the roots around: the certificate is checked, and
    // a failure is fatal rather than a warning.
    mbedtls_ssl_conf_authmode(&config_, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&config_, &ca_, nullptr);
    mbedtls_ssl_conf_rng(&config_, mbedtls_ctr_drbg_random, &ctr_drbg_);
    mbedtls_ssl_conf_read_timeout(&config_, kTimeoutMilliseconds);

    rc = mbedtls_ssl_setup(&ssl_, &config_);
    if (rc != 0) {
      *error = mbed_error("could not set up the TLS session", rc);
      return false;
    }
    // SNI, and the name the certificate is checked against.
    rc = mbedtls_ssl_set_hostname(&ssl_, url.host.c_str());
    if (rc != 0) {
      *error = mbed_error("could not set the TLS hostname", rc);
      return false;
    }

    rc = mbedtls_net_connect(&net_, url.host.c_str(), url.port.c_str(),
                             MBEDTLS_NET_PROTO_TCP);
    if (rc != 0) {
      *error = mbed_error("could not connect to " + url.host, rc);
      return false;
    }
    mbedtls_ssl_set_bio(&ssl_, &net_, mbedtls_net_send, nullptr,
                        mbedtls_net_recv_timeout);

    while ((rc = mbedtls_ssl_handshake(&ssl_)) != 0) {
      if (rc != MBEDTLS_ERR_SSL_WANT_READ && rc != MBEDTLS_ERR_SSL_WANT_WRITE) {
        if (rc == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED) {
          char why[512] = {};
          mbedtls_x509_crt_verify_info(why, sizeof(why), "",
                                       mbedtls_ssl_get_verify_result(&ssl_));
          *error = "TLS certificate rejected for " + url.host + ": " + why;
        } else {
          *error = mbed_error("TLS handshake with " + url.host + " failed", rc);
        }
        return false;
      }
    }
    handshaken_ = true;
    return true;
  }

  bool write_all(const std::string &data, std::string *error) {
    size_t sent = 0;
    while (sent < data.size()) {
      const int rc = mbedtls_ssl_write(
          &ssl_, reinterpret_cast<const unsigned char *>(data.data()) + sent,
          data.size() - sent);
      if (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE)
        continue;
      if (rc <= 0) {
        *error = mbed_error("could not send the request", rc);
        return false;
      }
      sent += static_cast<size_t>(rc);
    }
    return true;
  }

  // Returns the byte count, 0 at end of stream, or -1 on error.
  int read_some(char *buffer, size_t length, std::string *error) {
    for (;;) {
      const int rc = mbedtls_ssl_read(
          &ssl_, reinterpret_cast<unsigned char *>(buffer), length);
      if (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE)
        continue;
      // A server that drops the connection rather than closing it cleanly is
      // still a complete response if we already have the whole body.
      if (rc == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY ||
          rc == MBEDTLS_ERR_NET_CONN_RESET || rc == 0)
        return 0;
      if (rc < 0) {
        *error = mbed_error("could not read the response", rc);
        return -1;
      }
      return rc;
    }
  }

 private:
  bool load_trust_roots(std::string *error) {
    // An explicit bundle wins, for a network that intercepts TLS or a root
    // that rotated after this binary was built.
    if (const char *path = std::getenv("COOLTH_CA_BUNDLE")) {
      const int rc = mbedtls_x509_crt_parse_file(&ca_, path);
      if (rc != 0) {
        *error = mbed_error(std::string("could not read COOLTH_CA_BUNDLE (") +
                                path + ")",
                            rc);
        return false;
      }
      return true;
    }
    for (const char *pem : kCaCertificates) {
      const int rc = mbedtls_x509_crt_parse(
          &ca_, reinterpret_cast<const unsigned char *>(pem), strlen(pem) + 1);
      if (rc != 0) {
        *error = mbed_error("could not parse the built-in CA bundle", rc);
        return false;
      }
    }
    return true;
  }

  mbedtls_net_context net_;
  mbedtls_ssl_context ssl_;
  mbedtls_ssl_config config_;
  mbedtls_x509_crt ca_;
  mbedtls_ctr_drbg_context ctr_drbg_;
  mbedtls_entropy_context entropy_;
  bool handshaken_ = false;
};

// Pulls from the connection, holding what has been read but not consumed.
class ResponseReader {
 public:
  explicit ResponseReader(TlsConnection *tls) : tls_(tls) {}

  bool read_line(std::string *line, std::string *error) {
    for (;;) {
      const size_t end = buffer_.find("\r\n", position_);
      if (end != std::string::npos) {
        *line = buffer_.substr(position_, end - position_);
        position_ = end + 2;
        return true;
      }
      if (!fill(error)) {
        *error = error->empty() ? "the response ended mid-header" : *error;
        return false;
      }
    }
  }

  bool read_exact(size_t count, std::string *out, std::string *error) {
    while (buffer_.size() - position_ < count) {
      if (!fill(error)) {
        *error = error->empty() ? "the response body was truncated" : *error;
        return false;
      }
    }
    out->append(buffer_, position_, count);
    position_ += count;
    return true;
  }

  // For a response delimited by the connection closing.
  bool read_to_end(std::string *out, std::string *error) {
    while (fill(error)) {
    }
    if (!error->empty())
      return false;
    out->append(buffer_, position_, std::string::npos);
    position_ = buffer_.size();
    return true;
  }

 private:
  // False at end of stream or on error; `error` distinguishes them.
  bool fill(std::string *error) {
    if (buffer_.size() > kMaxResponseBytes) {
      *error = "the response was implausibly large";
      return false;
    }
    char chunk[kChunkSize];
    const int n = tls_->read_some(chunk, sizeof(chunk), error);
    if (n <= 0)
      return false;
    buffer_.append(chunk, static_cast<size_t>(n));
    return true;
  }

  TlsConnection *tls_;
  std::string buffer_;
  size_t position_ = 0;
};

std::string lowercase(std::string value) {
  for (char &c : value)
    if (c >= 'A' && c <= 'Z')
      c = static_cast<char>(c - 'A' + 'a');
  return value;
}

std::string trim(const std::string &value) {
  size_t start = value.find_first_not_of(" \t");
  if (start == std::string::npos)
    return "";
  size_t end = value.find_last_not_of(" \t");
  return value.substr(start, end - start + 1);
}

// The cloud code packs extra headers after the content type, one per line, so
// both clouds share the single HttpPost signature. First line is the content
// type; the rest are complete header lines.
std::string render_headers(const std::string &content_type) {
  std::string out;
  size_t start = 0;
  bool first = true;
  while (start <= content_type.size()) {
    size_t end = content_type.find('\n', start);
    if (end == std::string::npos)
      end = content_type.size();
    const std::string line = trim(content_type.substr(start, end - start));
    if (!line.empty())
      out += (first ? "Content-Type: " + line : line) + "\r\n";
    first = false;
    if (end == content_type.size())
      break;
    start = end + 1;
  }
  return out;
}

bool read_body(ResponseReader *reader, bool chunked, bool has_length,
               size_t length, std::string *body, std::string *error) {
  if (chunked) {
    for (;;) {
      std::string header;
      if (!reader->read_line(&header, error))
        return false;
      // A chunk size may carry extensions after a semicolon.
      const size_t semicolon = header.find(';');
      if (semicolon != std::string::npos)
        header = header.substr(0, semicolon);
      const size_t size = strtoul(trim(header).c_str(), nullptr, 16);
      if (size == 0)
        return true;  // trailers, if any, are of no interest
      if (!reader->read_exact(size, body, error))
        return false;
      std::string crlf;
      if (!reader->read_line(&crlf, error))  // the chunk's trailing CRLF
        return false;
    }
  }
  if (has_length)
    return length == 0 || reader->read_exact(length, body, error);
  return reader->read_to_end(body, error);
}

bool https_post(const std::string &url, const std::string &content_type,
                const std::string &body, std::string *response,
                std::string *error) {
  response->clear();
  error->clear();

  Url target;
  if (!parse_url(url, &target)) {
    *error = "not an https URL: " + url;
    return false;
  }

  TlsConnection tls;
  if (!tls.open(target, error))
    return false;

  const std::string request =
      "POST " + target.path + " HTTP/1.1\r\n" +
      "Host: " + target.host + "\r\n" +
      "User-Agent: coolth-cpp\r\n" +
      "Accept: */*\r\n" +
      render_headers(content_type) +
      "Content-Length: " + std::to_string(body.size()) + "\r\n" +
      // No keep-alive: one request per connection keeps this client small.
      "Connection: close\r\n\r\n" + body;
  if (!tls.write_all(request, error))
    return false;

  ResponseReader reader(&tls);
  std::string status;
  if (!reader.read_line(&status, error))
    return false;
  if (status.compare(0, 5, "HTTP/") != 0) {
    *error = "the server did not answer with HTTP";
    return false;
  }

  bool chunked = false;
  bool has_length = false;
  size_t length = 0;
  for (;;) {
    std::string line;
    if (!reader.read_line(&line, error))
      return false;
    if (line.empty())
      break;  // end of headers
    const size_t colon = line.find(':');
    if (colon == std::string::npos)
      continue;
    const std::string name = lowercase(trim(line.substr(0, colon)));
    const std::string value = trim(line.substr(colon + 1));
    if (name == "transfer-encoding")
      chunked = lowercase(value).find("chunked") != std::string::npos;
    else if (name == "content-length") {
      has_length = true;
      length = strtoul(value.c_str(), nullptr, 10);
    }
  }

  // As with libcurl, an HTTP error status is still a successful exchange; the
  // cloud reports its own failures in the body, and the caller parses those.
  return read_body(&reader, chunked, has_length, length, response, error);
}

}  // namespace

bool https_available() { return true; }

coolth::HttpPost make_http_post(std::string *error_out) {
#if defined(MBEDTLS_PSA_CRYPTO_C)
  // mbedtls 3.x drives TLS 1.3 through PSA, which wants initialising once.
  static const bool psa_ready = psa_crypto_init() == PSA_SUCCESS;
  if (!psa_ready && error_out != nullptr)
    *error_out = "could not initialise mbedtls";
#else
  (void) error_out;
#endif
  return [](const std::string &url, const std::string &content_type,
            const std::string &body, std::string *response) {
    std::string error;
    if (https_post(url, content_type, body, response, &error))
      return true;
    // The HttpPost contract has no error channel, so say it here rather than
    // let the cloud report a bare "request failed".
    fprintf(stderr, "https: %s\n", error.c_str());
    return false;
  };
}

}  // namespace coolth_cli
