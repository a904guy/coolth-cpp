#include "cloud.h"

#include <cctype>
#include <cstdio>

#include "json_lite.h"
#include "protocol.h"

namespace coolth {
namespace {

// NetHome Plus. The SmartHome/MSmartHome app uses a different id and key.
const char APP_ID[] = "1017";
const char APP_KEY[] = "3742e9e5842d4ad59c2db887e12449f9";

std::string sha256_hex(const std::string &text) {
  return to_hex(sha256(Bytes(text.begin(), text.end())));
}

}  // namespace

std::string udpid_hex(uint64_t device_id, bool little_endian) {
  Bytes id(6);
  for (int i = 0; i < 6; i++) {
    const uint8_t byte = static_cast<uint8_t>((device_id >> (8 * i)) & 0xFF);
    id[little_endian ? i : 5 - i] = byte;
  }
  const Bytes digest = sha256(id);
  Bytes folded(16);
  for (size_t i = 0; i < 16; i++) folded[i] = digest[i] ^ digest[i + 16];
  return to_hex(folded);
}

NetHomePlusCloud::NetHomePlusCloud(std::string account, std::string password,
                                   HttpPost post)
    : account_(std::move(account)),
      password_(std::move(password)),
      post_(std::move(post)) {}

std::string NetHomePlusCloud::sign(
    const std::string &path, const std::map<std::string, std::string> &body) {
  // The signed string is the body sorted by key and joined *unencoded* --
  // the reference builds a query string and then un-escapes it again, so an
  // email keeps its "@" here even though the posted form percent-encodes it.
  // std::map already iterates in the byte order Python's sorted() produces.
  std::string query;
  for (const auto &entry : body) {
    if (!query.empty())
      query.push_back('&');
    query += entry.first;
    query.push_back('=');
    query += entry.second;
  }
  return sha256_hex(path + query + APP_KEY);
}

std::string NetHomePlusCloud::encrypt_password(const std::string &login_id,
                                               const std::string &password) {
  // Hashed twice: once alone, then again with the login id and app key. The
  // login id changes per attempt, which is what stops the result being a
  // password-equivalent constant.
  return sha256_hex(login_id + sha256_hex(password) + APP_KEY);
}

std::string NetHomePlusCloud::form_encode(
    const std::map<std::string, std::string> &body) {
  static const char *digits = "0123456789ABCDEF";
  std::string out;
  for (const auto &entry : body) {
    if (!out.empty())
      out.push_back('&');
    for (const std::string *part : {&entry.first, &entry.second}) {
      for (unsigned char c : *part) {
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
          out.push_back(static_cast<char>(c));
        } else {
          out.push_back('%');
          out.push_back(digits[c >> 4]);
          out.push_back(digits[c & 0xF]);
        }
      }
      if (part == &entry.first)
        out.push_back('=');
    }
  }
  return out;
}

std::map<std::string, std::string> NetHomePlusCloud::base_body() const {
  return {
      {"appId", APP_ID},
      {"src", APP_ID},
      {"format", "2"},      // JSON
      {"clientType", "1"},  // Android
      {"language", "en_US"},
      {"deviceId", this->client_id_},
      {"stamp", this->stamp_},
      {"sessionId", this->session_id_},
  };
}

bool NetHomePlusCloud::request(const std::string &endpoint,
                               std::map<std::string, std::string> body,
                               std::string *result, std::string *error) {
  body["sign"] = sign(endpoint, body);

  std::string response;
  if (!this->post_(this->base_url_ + endpoint,
                   "application/x-www-form-urlencoded", form_encode(body),
                   &response)) {
    *error = "HTTP request to " + endpoint + " failed";
    return false;
  }

  std::string code;
  if (!json::find_value(response, "errorCode", &code)) {
    *error = "no errorCode in response to " + endpoint;
    return false;
  }
  if (code != "0") {
    std::string message;
    json::find_value(response, "msg", &message);
    *error = "cloud error " + code + ": " + (message.empty() ? "?" : message);
    return false;
  }
  if (!json::find_object(response, "result", result)) {
    *error = "no result in response to " + endpoint;
    return false;
  }
  return true;
}

bool NetHomePlusCloud::get_login_id(std::string *error) {
  auto body = this->base_body();
  body["loginAccount"] = this->account_;

  std::string result;
  if (!this->request("/v1/user/login/id/get", body, &result, error))
    return false;
  if (!json::find_value(result, "loginId", &this->login_id_)) {
    *error = "no loginId in response";
    return false;
  }
  return true;
}

bool NetHomePlusCloud::login(std::string *error) {
  if (!this->session_id_.empty())
    return true;
  if (this->stamp_.empty()) {
    *error = "timestamp not set; the clock must be synchronised first";
    return false;
  }
  if (this->login_id_.empty() && !this->get_login_id(error))
    return false;

  auto body = this->base_body();
  body["loginAccount"] = this->account_;
  body["password"] = encrypt_password(this->login_id_, this->password_);

  std::string result;
  if (!this->request("/v1/user/login", body, &result, error))
    return false;
  if (!json::find_value(result, "sessionId", &this->session_id_)) {
    *error = "no sessionId in response";
    return false;
  }
  return true;
}

bool NetHomePlusCloud::get_token(const std::string &udpid,
                                 DeviceCredentials *out, std::string *error) {
  auto body = this->base_body();
  body["udpid"] = udpid;

  std::string result;
  if (!this->request("/v1/iot/secure/getToken", body, &result, error))
    return false;

  // The account's whole token list comes back; pick the entry for this device.
  for (const std::string &entry : json::find_array_objects(result, "tokenlist")) {
    std::string id;
    if (!json::find_value(entry, "udpId", &id) || id != udpid)
      continue;
    if (json::find_value(entry, "token", &out->token) &&
        json::find_value(entry, "key", &out->key))
      return true;
  }
  *error = "no token for udpid " + udpid;
  return false;
}

bool NetHomePlusCloud::get_credentials(uint64_t device_id,
                                       DeviceCredentials *out,
                                       std::string *error) {
  if (!this->login(error))
    return false;
  for (const bool little_endian : {true, false}) {
    if (this->get_token(udpid_hex(device_id, little_endian), out, error))
      return true;
  }
  // Both failed; `error` holds whatever the second attempt reported.
  return false;
}

namespace {

const char SH_HMAC_KEY[] = "PROD_VnoClJI9aikS8dyy";
const char SH_IOT_KEY[] = "meicloud";
const char SH_IOT_KEY_CHINA[] = "prod_secret123@muc";
const char SH_LOGIN_KEY[] = "ac21b9f9cbfe4ca5a88562ef25e2b768";
const char SH_LOGIN_KEY_CHINA[] = "ad0ee21d48a64bf49f4fb583ab76e799";
const char SH_APP_ID[] = "1010";

std::string md5_hex(const std::string &text) {
  return to_hex(md5(Bytes(text.begin(), text.end())));
}

std::string json_escape(const std::string &text) {
  std::string out;
  for (char c : text) {
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default: out.push_back(c); break;
    }
  }
  return out;
}

std::string json_field(const std::string &key, const std::string &value) {
  return "\"" + json_escape(key) + "\":\"" + json_escape(value) + "\"";
}

}  // namespace

SmartHomeCloud::SmartHomeCloud(std::string account, std::string password,
                               HttpPost post, bool use_china_server)
    : account_(std::move(account)),
      password_(std::move(password)),
      post_(std::move(post)),
      china_(use_china_server) {
  this->base_url_ = use_china_server ? "https://mp-prod.smartmidea.net"
                                     : "https://mp-prod.appsmb.com";
  // A caller that never sets a provider still produces distinct-looking
  // values; it is only a fallback, and it is not cryptographically random.
  this->nonce_ = [](size_t bytes) { return std::string(bytes * 2, '0'); };
}

std::string SmartHomeCloud::sign(const std::string &data,
                                 const std::string &random,
                                 bool use_china_server) {
  const std::string iot_key = use_china_server ? SH_IOT_KEY_CHINA : SH_IOT_KEY;
  const std::string message = iot_key + data + random;
  const std::string key = SH_HMAC_KEY;
  return to_hex(hmac_sha256(Bytes(key.begin(), key.end()),
                            Bytes(message.begin(), message.end())));
}

std::string SmartHomeCloud::encrypt_password(const std::string &login_id,
                                             const std::string &password,
                                             bool use_china_server) {
  const std::string login_key =
      use_china_server ? SH_LOGIN_KEY_CHINA : SH_LOGIN_KEY;
  const std::string hashed =
      to_hex(sha256(Bytes(password.begin(), password.end())));
  const std::string text = login_id + hashed + login_key;
  return to_hex(sha256(Bytes(text.begin(), text.end())));
}

std::string SmartHomeCloud::encrypt_iam_password(const std::string &login_id,
                                                 const std::string &password,
                                                 bool use_china_server) {
  const std::string twice = md5_hex(md5_hex(password));
  if (use_china_server)
    return twice;
  const std::string login_key = SH_LOGIN_KEY;
  const std::string text = login_id + twice + login_key;
  return to_hex(sha256(Bytes(text.begin(), text.end())));
}

std::string SmartHomeCloud::base_fields() const {
  return json_field("appId", SH_APP_ID) + "," + json_field("src", SH_APP_ID) +
         "," + "\"format\":2," + "\"clientType\":1," +
         json_field("language", "en_US") + "," +
         json_field("deviceId", this->client_id_) + "," +
         json_field("stamp", this->stamp_) + "," +
         json_field("reqId", this->nonce_(16));
}

bool SmartHomeCloud::request(const std::string &alias,
                             const std::string &json_body, std::string *data,
                             std::string *error) {
  // Everything goes through one proxy endpoint; the real target is a query
  // parameter, and the signature covers the body plus a per-request nonce.
  const std::string random = this->nonce_(16);
  const std::string signature = sign(json_body, random, this->china_);
  const std::string url = this->base_url_ + "/mas/v5/app/proxy?alias=" + alias;

  // The transport carries the headers this cloud needs; they are folded into
  // the content-type argument as a newline-separated block so HttpPost stays
  // a single simple signature shared with the other cloud.
  const std::string headers = "application/json\n"
                              "secretVersion: 1\n"
                              "sign: " + signature + "\n"
                              "random: " + random + "\n"
                              "accessToken: " + this->access_token_;

  std::string response;
  if (!this->post_(url, headers, json_body, &response)) {
    *error = "HTTP request to " + alias + " failed";
    return false;
  }

  std::string code;
  if (!json::find_value(response, "code", &code)) {
    *error = "no code in response to " + alias;
    return false;
  }
  if (code != "0") {
    std::string message;
    json::find_value(response, "msg", &message);
    *error = "cloud error " + code + ": " + (message.empty() ? "?" : message);
    return false;
  }
  if (!json::find_object(response, "data", data)) {
    *error = "no data in response to " + alias;
    return false;
  }
  return true;
}

bool SmartHomeCloud::get_login_id(std::string *error) {
  const std::string body =
      "{" + this->base_fields() + "," + json_field("loginAccount", this->account_) + "}";
  std::string data;
  if (!this->request("/v1/user/login/id/get", body, &data, error))
    return false;
  if (!json::find_value(data, "loginId", &this->login_id_)) {
    *error = "no loginId in response";
    return false;
  }
  return true;
}

bool SmartHomeCloud::login(std::string *error) {
  if (!this->access_token_.empty())
    return true;
  if (this->stamp_.empty()) {
    *error = "timestamp not set; the clock must be synchronised first";
    return false;
  }
  if (this->login_id_.empty() && !this->get_login_id(error))
    return false;

  // Two password fields, derived differently, both required.
  const std::string body =
      std::string("{\"data\":{\"platform\":2,") +
      json_field("deviceId", this->client_id_) + "},\"iotData\":{" +
      json_field("appId", SH_APP_ID) + "," + json_field("src", SH_APP_ID) +
      ",\"clientType\":1," + json_field("loginAccount", this->account_) + "," +
      json_field("iampwd", encrypt_iam_password(this->login_id_, this->password_,
                                                this->china_)) +
      "," +
      json_field("password",
                 encrypt_password(this->login_id_, this->password_, this->china_)) +
      "," + json_field("pushToken", this->nonce_(60)) + "," +
      json_field("stamp", this->stamp_) + "," +
      json_field("reqId", this->nonce_(16)) + "}}";

  std::string data;
  if (!this->request("/mj/user/login", body, &data, error))
    return false;

  std::string mdata;
  if (!json::find_object(data, "mdata", &mdata) ||
      !json::find_value(mdata, "accessToken", &this->access_token_)) {
    *error = "no accessToken in response";
    return false;
  }
  return true;
}

bool SmartHomeCloud::get_token(const std::string &udpid, DeviceCredentials *out,
                               std::string *error) {
  const std::string body =
      "{" + this->base_fields() + "," + json_field("udpid", udpid) + "}";
  std::string data;
  if (!this->request("/v1/iot/secure/getToken", body, &data, error))
    return false;

  for (const std::string &entry : json::find_array_objects(data, "tokenlist")) {
    std::string id;
    if (!json::find_value(entry, "udpId", &id) || id != udpid)
      continue;
    if (json::find_value(entry, "token", &out->token) &&
        json::find_value(entry, "key", &out->key))
      return true;
  }
  *error = "no token for udpid " + udpid;
  return false;
}

bool SmartHomeCloud::get_credentials(uint64_t device_id, DeviceCredentials *out,
                                     std::string *error) {
  if (!this->login(error))
    return false;
  for (const bool little_endian : {true, false}) {
    if (this->get_token(udpid_hex(device_id, little_endian), out, error))
      return true;
  }
  return false;
}

}  // namespace coolth
