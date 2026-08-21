#include "cloud_lan.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "json_lite.h"

namespace coolth {
namespace {

const char LOGIN_ID_PATH[] = "/v1/user/login/id/get";
const char LOGIN_PATH[] = "/v1/user/login";
const char SEND_PATH[] = "/v1/appliance/transparent/send/new";
const char FUN_ID[] = "0008";

// A harmless status query, used to provoke the reply that leaks the IV.
const char IV_PROBE_FRAME[] =
    "aa21ac00000000000303418100ff03ff00020000000000000000000000000304560b";

std::string sha256_hex(const std::string &text) {
  return to_hex(sha256(Bytes(text.begin(), text.end())));
}

}  // namespace

CloudLAN::CloudLAN(uint64_t appliance_id, std::string account,
                   std::string password, HttpPost post)
    : appliance_id_(appliance_id),
      account_(std::move(account)),
      password_(std::move(password)),
      post_fn_(std::move(post)) {}

void CloudLAN::set_app(const std::string &app_id, const std::string &app_key) {
  this->app_id_ = app_id;
  this->app_key_ = app_key;
}

void CloudLAN::set_packet_timestamp(const uint8_t timestamp[8]) {
  memcpy(this->timestamp_, timestamp, 8);
}

void CloudLAN::make_timestamp(int year, int month, int day, int hour,
                              int minute, int second, int millisecond,
                              uint8_t out[8]) {
  // Not the same layout as the LAN packet's timestamp: it runs smallest unit
  // first, the month is zero-based, and the hour is modulo 12.
  out[0] = static_cast<uint8_t>(millisecond & 0xFF);
  out[1] = static_cast<uint8_t>(second);
  out[2] = static_cast<uint8_t>(minute);
  out[3] = static_cast<uint8_t>(hour % 12);
  out[4] = static_cast<uint8_t>(day);
  out[5] = static_cast<uint8_t>(month - 1);
  out[6] = static_cast<uint8_t>(year % 100);
  out[7] = static_cast<uint8_t>(year / 100);
}

Bytes CloudLAN::build_5a5a_packet(const Bytes &frame, uint64_t appliance_id,
                                  uint32_t seq, const uint8_t timestamp[8]) {
  // Unlike the LAN packet, the frame rides here in the clear: the transport
  // encryption happens a layer up, around the whole thing.
  const size_t length = frame.size() + 56;
  Bytes packet(length, 0);
  packet[0] = 0x5A;
  packet[1] = 0x5A;
  packet[2] = 0x01;
  packet[4] = static_cast<uint8_t>(length & 0xFF);
  packet[5] = static_cast<uint8_t>(length >> 8);
  packet[6] = 32;
  for (int i = 0; i < 4; i++)
    packet[8 + i] = static_cast<uint8_t>((seq >> (8 * i)) & 0xFF);
  memcpy(packet.data() + 12, timestamp, 8);
  for (int i = 0; i < 6; i++)
    packet[20 + i] = static_cast<uint8_t>((appliance_id >> (8 * i)) & 0xFF);
  memcpy(packet.data() + 40, frame.data(), frame.size());
  return packet;
}

std::string CloudLAN::to_text(const Bytes &packet) {
  std::string out;
  char buffer[8];
  for (size_t i = 0; i < packet.size(); i++) {
    if (i)
      out.push_back(',');
    const int value =
        packet[i] > 127 ? static_cast<int>(packet[i]) - 256 : packet[i];
    snprintf(buffer, sizeof(buffer), "%d", value);
    out += buffer;
  }
  return out;
}

Bytes CloudLAN::from_text(const std::string &text) {
  Bytes out;
  size_t pos = 0;
  while (pos <= text.size()) {
    size_t comma = text.find(',', pos);
    if (comma == std::string::npos)
      comma = text.size();
    const std::string token = text.substr(pos, comma - pos);
    if (!token.empty() && token.find_first_not_of(" \t\r\n") != std::string::npos)
      out.push_back(static_cast<uint8_t>(((atoi(token.c_str()) % 256) + 256) % 256));
    if (comma == text.size())
      break;
    pos = comma + 1;
  }
  return out;
}

bool CloudLAN::extract_aa(const Bytes &packet, Bytes *frame) {
  for (size_t i = 0; i + 1 < packet.size(); i++) {
    if (packet[i] != 0xAA)
      continue;
    // The length byte covers header and data; the checksum is one more.
    const size_t length = static_cast<size_t>(packet[i + 1]) + 1;
    if (i + length > packet.size())
      return false;
    frame->assign(packet.begin() + i, packet.begin() + i + length);
    return true;
  }
  return false;
}

Bytes CloudLAN::derive_key(const std::string &app_key,
                           const std::string &access_token) {
  // The access token is the session key, encrypted under a key derived from
  // the app key.
  const std::string digest = to_hex(md5(Bytes(app_key.begin(), app_key.end())));
  const std::string key_text = digest.substr(0, 16);
  const Bytes key(key_text.begin(), key_text.end());
  Bytes decrypted = aes_ecb_decrypt_raw(key, from_hex(access_token));
  if (!pkcs7_unpad(&decrypted))
    return {};
  return decrypted;
}

std::string CloudLAN::password_hash(const std::string &login_id,
                                    const std::string &password,
                                    const std::string &app_key) {
  return sha256_hex(login_id + sha256_hex(password) + app_key);
}

std::string CloudLAN::sign(const std::string &path,
                           const std::map<std::string, std::string> &body,
                           const std::string &app_key) {
  std::string query;
  for (const auto &entry : body) {
    if (!query.empty())
      query.push_back('&');
    query += entry.first;
    query.push_back('=');
    query += entry.second;
  }
  return sha256_hex(path + query + app_key);
}

std::map<std::string, std::string> CloudLAN::login_body() const {
  return {
      {"appId", this->app_id_}, {"src", this->app_id_},
      {"format", "2"},          {"clientType", "1"},
      {"language", "en_US"},    {"deviceId", this->client_id_},
      {"stamp", this->stamp_},
  };
}

std::map<std::string, std::string> CloudLAN::base_body() const {
  // The relay endpoint wants a smaller body, and src is a fixed 17 rather than
  // the app id.
  std::map<std::string, std::string> body = {
      {"src", "17"}, {"format", "2"}, {"stamp", this->stamp_},
      {"language", "en_US"},
  };
  if (!this->session_id_.empty())
    body["sessionId"] = this->session_id_;
  return body;
}

bool CloudLAN::post(const std::string &path,
                    std::map<std::string, std::string> body,
                    std::string *response, std::string *error) {
  body["sign"] = sign(path, body, this->app_key_);
  if (!this->post_fn_(this->base_url_ + path,
                      "application/x-www-form-urlencoded",
                      NetHomePlusCloud::form_encode(body), response)) {
    *error = "HTTP request to " + path + " failed";
    return false;
  }
  return true;
}

bool CloudLAN::login(std::string *error) {
  if (this->stamp_.empty()) {
    *error = "timestamp not set; the clock must be synchronised first";
    return false;
  }

  auto body = this->login_body();
  body["loginAccount"] = this->account_;
  std::string response;
  if (!this->post(LOGIN_ID_PATH, body, &response, error))
    return false;
  std::string result, login_id;
  if (!json::find_object(response, "result", &result) ||
      !json::find_value(result, "loginId", &login_id)) {
    *error = "login id request failed: " + response;
    return false;
  }

  body = this->login_body();
  body["loginAccount"] = this->account_;
  body["password"] = password_hash(login_id, this->password_, this->app_key_);
  if (!this->post(LOGIN_PATH, body, &response, error))
    return false;
  std::string access_token;
  if (!json::find_object(response, "result", &result) ||
      !json::find_value(result, "sessionId", &this->session_id_) ||
      !json::find_value(result, "accessToken", &access_token)) {
    *error = "login failed: " + response;
    return false;
  }

  this->key_ = derive_key(this->app_key_, access_token);
  if (this->key_.empty()) {
    *error = "could not derive the session key from the access token";
    return false;
  }
  return this->recover_iv(error);
}

bool CloudLAN::recover_iv(std::string *error) {
  // The session IV is never sent. But the server decrypts with the real IV and
  // echoes the result back in an error message, so sending a known plaintext
  // under a zero IV reveals it: with CBC, plaintext ^ zero_iv ^ echoed gives
  // the IV that was actually used.
  const Bytes packet = build_5a5a_packet(from_hex(IV_PROBE_FRAME),
                                         this->appliance_id_, this->next_seq(),
                                         this->timestamp_);
  const std::string text = to_text(packet);
  const Bytes plain(text.begin(), text.end());
  const Bytes zero_iv(16, 0);
  const Bytes order = aes_cbc_encrypt_iv(this->key_, zero_iv, pkcs7_pad(plain));

  auto body = this->base_body();
  body["applianceId"] = std::to_string(this->appliance_id_);
  body["funId"] = FUN_ID;
  body["order"] = to_hex(order);

  std::string response;
  if (!this->post(SEND_PATH, body, &response, error))
    return false;

  std::string message;
  json::find_value(response, "msg", &message);
  const size_t marker = message.find("order:");
  if (marker == std::string::npos) {
    *error = "IV recovery failed; the server did not echo a decryption: " + response;
    return false;
  }
  const std::string echoed = message.substr(marker + 6);
  if (echoed.size() < 16 || plain.size() < 16) {
    *error = "IV recovery failed; echoed block too short";
    return false;
  }

  this->iv_.assign(16, 0);
  for (size_t i = 0; i < 16; i++)
    this->iv_[i] = static_cast<uint8_t>(plain[i] ^ zero_iv[i] ^
                                        static_cast<uint8_t>(echoed[i]));
  return true;
}

bool CloudLAN::send(const Bytes &frame, Bytes *reply, std::string *error) {
  reply->clear();
  if (!this->logged_in()) {
    *error = "not logged in";
    return false;
  }

  const Bytes packet = build_5a5a_packet(frame, this->appliance_id_,
                                         this->next_seq(), this->timestamp_);
  const std::string text = to_text(packet);
  const Bytes order = aes_cbc_encrypt_iv(
      this->key_, this->iv_, pkcs7_pad(Bytes(text.begin(), text.end())));

  auto body = this->base_body();
  body["applianceId"] = std::to_string(this->appliance_id_);
  body["funId"] = FUN_ID;
  body["order"] = to_hex(order);

  std::string response;
  if (!this->post(SEND_PATH, body, &response, error))
    return false;

  std::string code;
  json::find_value(response, "errorCode", &code);
  if (code == "3176") {
    // The cloud took the command but has no frame to hand back. Normal for a
    // set; not an error.
    return true;
  }
  if (code != "0") {
    std::string message;
    json::find_value(response, "msg", &message);
    *error = "cloud error " + code + ": " + (message.empty() ? "?" : message);
    return false;
  }

  std::string result, encoded;
  if (!json::find_object(response, "result", &result) ||
      !json::find_value(result, "reply", &encoded) || encoded.empty())
    return true;  // accepted, nothing to read back

  Bytes decrypted = aes_cbc_decrypt_iv(this->key_, this->iv_, from_hex(encoded));
  if (!pkcs7_unpad(&decrypted)) {
    *error = "could not decrypt the cloud's reply";
    return false;
  }
  const std::string decoded(decrypted.begin(), decrypted.end());
  extract_aa(from_text(decoded), reply);
  return true;
}

}  // namespace coolth
