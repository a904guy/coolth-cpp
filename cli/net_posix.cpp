#include "net_posix.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <set>

#include "../components/coolth/discovery.h"

#ifdef COOLTH_HAVE_CURL
#include <curl/curl.h>
#endif

namespace coolth_cli {

bool tcp_connect(const std::string &host, uint16_t port, int timeout_seconds,
                 int *handle, coolth::Connection *connection) {
  struct addrinfo hints = {};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  struct addrinfo *result = nullptr;
  if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &result) != 0 ||
      result == nullptr)
    return false;

  const int fd = ::socket(result->ai_family, result->ai_socktype, result->ai_protocol);
  if (fd < 0) {
    freeaddrinfo(result);
    return false;
  }
  struct timeval timeout {timeout_seconds, 0};
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
  const int one = 1;
  setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

  const int rc = ::connect(fd, result->ai_addr, result->ai_addrlen);
  freeaddrinfo(result);
  if (rc != 0) {
    ::close(fd);
    return false;
  }

  *handle = fd;
  connection->write = [fd](const coolth::Bytes &data) {
    size_t sent = 0;
    while (sent < data.size()) {
      const ssize_t n = ::send(fd, data.data() + sent, data.size() - sent, 0);
      if (n <= 0)
        return false;
      sent += static_cast<size_t>(n);
    }
    return true;
  };
  connection->read_exact = [fd](size_t length, coolth::Bytes *out) {
    out->assign(length, 0);
    size_t got = 0;
    while (got < length) {
      const ssize_t n = ::recv(fd, out->data() + got, length - got, 0);
      if (n <= 0)
        return false;
      got += static_cast<size_t>(n);
    }
    return true;
  };
  return true;
}

void tcp_close(int handle) {
  if (handle >= 0)
    ::close(handle);
}

bool discover(int seconds,
              const std::function<void(const std::string &,
                                       const coolth::Bytes &)> &on_device,
              std::string *error) {
  const int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) {
    *error = "could not open a UDP socket";
    return false;
  }
  const int one = 1;
  setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &one, sizeof(one));
  struct timeval timeout {1, 0};
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

  const coolth::Bytes probe = coolth::discovery_request();
  // Two ports, because different firmware generations listen on different ones.
  for (uint16_t port : {6445, 20086}) {
    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_BROADCAST;
    for (int i = 0; i < 3; i++)  // UDP; repeat rather than hope
      ::sendto(fd, probe.data(), probe.size(), 0, (struct sockaddr *) &addr,
               sizeof(addr));
  }

  std::set<std::string> seen;
  for (int elapsed = 0; elapsed < seconds; elapsed++) {
    for (;;) {
      uint8_t buffer[2048];
      struct sockaddr_in from = {};
      socklen_t from_len = sizeof(from);
      const ssize_t n = ::recvfrom(fd, buffer, sizeof(buffer), 0,
                                   (struct sockaddr *) &from, &from_len);
      if (n <= 0)
        break;  // timed out for this second
      const std::string ip = inet_ntoa(from.sin_addr);
      if (!seen.insert(ip).second)
        continue;
      on_device(ip, coolth::Bytes(buffer, buffer + n));
    }
  }
  ::close(fd);
  return true;
}

#ifdef COOLTH_HAVE_CURL
namespace {
size_t collect(char *ptr, size_t size, size_t nmemb, void *userdata) {
  static_cast<std::string *>(userdata)->append(ptr, size * nmemb);
  return size * nmemb;
}
}  // namespace

bool https_available() { return true; }

coolth::HttpPost make_http_post(std::string *) {
  return [](const std::string &url, const std::string &content_type,
            const std::string &body, std::string *response) {
    CURL *curl = curl_easy_init();
    if (curl == nullptr)
      return false;
    // The SmartHome path packs extra headers after the content type, one per
    // line, so both clouds can share this single signature.
    struct curl_slist *headers = nullptr;
    size_t start = 0;
    bool first = true;
    while (start <= content_type.size()) {
      size_t end = content_type.find('\n', start);
      if (end == std::string::npos)
        end = content_type.size();
      const std::string line = content_type.substr(start, end - start);
      if (!line.empty())
        headers = curl_slist_append(
            headers, (first ? "Content-Type: " + line : line).c_str());
      first = false;
      if (end == content_type.size())
        break;
      start = end + 1;
    }

    response->clear();
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long) body.size());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, collect);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 25L);
    const CURLcode rc = curl_easy_perform(curl);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return rc == CURLE_OK;
  };
}
#else
bool https_available() { return false; }

coolth::HttpPost make_http_post(std::string *error_out) {
  if (error_out != nullptr)
    *error_out = "built without libcurl; cloud commands are unavailable";
  return [](const std::string &, const std::string &, const std::string &,
            std::string *) { return false; };
}
#endif

}  // namespace coolth_cli
