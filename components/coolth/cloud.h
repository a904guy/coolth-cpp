// Midea cloud access, for the one thing an appliance cannot tell you itself:
// the token and key a V3 device demands before it will talk on the LAN.
//
// Discovery finds the address and the id. Those two secrets come from the
// account that owns the appliance, so this logs in, then asks for them by
// udpid. Once you have them they are stable, so this runs rarely -- typically
// once, or again if the appliance is re-paired.
//
// HTTP is injected rather than implemented here, which keeps the library free
// of a TLS dependency and lets the tests drive it with canned replies.
#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <string>

namespace coolth {

// Returns false on a transport failure. `response` gets the body on success.
using HttpPost = std::function<bool(const std::string &url,
                                    const std::string &content_type,
                                    const std::string &body,
                                    std::string *response)>;

struct DeviceCredentials {
  std::string token;  // 128 hex characters
  std::string key;    // 64 hex characters
};

// sha256 of the device id, folded in half. The endianness of the id is not
// discoverable, so both are tried in turn -- a device answers to exactly one.
std::string udpid_hex(uint64_t device_id, bool little_endian);

class NetHomePlusCloud {
 public:
  NetHomePlusCloud(std::string account, std::string password, HttpPost post);

  // "YYYYMMDDHHMMSS" in UTC. The cloud rejects a stamp that is far out, so the
  // clock needs to be set (SNTP) before calling login().
  void set_timestamp(const std::string &stamp) { this->stamp_ = stamp; }
  // 16 hex characters identifying this client. Any stable value works.
  void set_client_device_id(const std::string &hex) { this->client_id_ = hex; }
  void set_base_url(const std::string &url) { this->base_url_ = url; }

  bool login(std::string *error);
  bool get_token(const std::string &udpid, DeviceCredentials *out,
                 std::string *error);
  // Tries both endianness variants of the id and returns whichever the cloud
  // recognises, so callers do not have to know which one their device uses.
  bool get_credentials(uint64_t device_id, DeviceCredentials *out,
                       std::string *error);

  const std::string &session_id() const { return this->session_id_; }

  // Exposed for tests; these are the two pieces that are easy to get subtly
  // wrong and impossible to debug from a rejected login.
  static std::string sign(const std::string &path,
                          const std::map<std::string, std::string> &body);
  static std::string encrypt_password(const std::string &login_id,
                                      const std::string &password);
  static std::string form_encode(const std::map<std::string, std::string> &body);

 protected:
  std::map<std::string, std::string> base_body() const;
  bool request(const std::string &endpoint,
               std::map<std::string, std::string> body, std::string *result,
               std::string *error);
  bool get_login_id(std::string *error);

  std::string account_;
  std::string password_;
  HttpPost post_;
  std::string base_url_{"https://mapp.appsmb.com"};
  std::string stamp_;
  std::string client_id_{"0123456789abcdef"};
  std::string login_id_;
  std::string session_id_;
};


// The SmartHome / MSmartHome app's cloud. Same purpose as NetHomePlusCloud but
// a different protocol throughout: JSON bodies rather than form data, requests
// tunnelled through a proxy endpoint, an HMAC signature in a header instead of
// a hash in the body, and two separately derived password fields.
//
// Some accounts only exist on one of the two clouds, which is the reason both
// are here.
class SmartHomeCloud {
 public:
  SmartHomeCloud(std::string account, std::string password, HttpPost post,
                 bool use_china_server = false);

  void set_timestamp(const std::string &stamp) { this->stamp_ = stamp; }
  void set_client_device_id(const std::string &hex) { this->client_id_ = hex; }
  // Supplies the random hex this protocol sprinkles through requests. Injected
  // so tests are reproducible; production should pass a real RNG.
  void set_nonce_provider(std::function<std::string(size_t)> provider) {
    this->nonce_ = std::move(provider);
  }

  bool login(std::string *error);
  bool get_token(const std::string &udpid, DeviceCredentials *out,
                 std::string *error);
  bool get_credentials(uint64_t device_id, DeviceCredentials *out,
                       std::string *error);

  const std::string &access_token() const { return this->access_token_; }

  static std::string sign(const std::string &data, const std::string &random,
                          bool use_china_server);
  static std::string encrypt_password(const std::string &login_id,
                                      const std::string &password,
                                      bool use_china_server);
  // The iampwd field, which is derived differently again: MD5 twice, then
  // SHA256 with the login id -- except on the China server, which stops early.
  static std::string encrypt_iam_password(const std::string &login_id,
                                          const std::string &password,
                                          bool use_china_server);

 protected:
  bool request(const std::string &alias, const std::string &json_body,
               std::string *data, std::string *error);
  bool get_login_id(std::string *error);
  std::string base_fields() const;

  std::string account_;
  std::string password_;
  HttpPost post_;
  bool china_;
  std::string base_url_;
  std::string stamp_;
  std::string client_id_{"0123456789abcdef"};
  std::string login_id_;
  std::string access_token_;
  std::function<std::string(size_t)> nonce_;
};

}  // namespace coolth
