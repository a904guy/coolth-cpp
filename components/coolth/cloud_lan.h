// Controlling an appliance through the Midea cloud instead of the LAN.
//
// Why bother, when the LAN path is faster and needs no internet? Because it
// lets the air conditioner live on an isolated network. The unit only ever
// talks to Midea; this talks to Midea too, and the two never share a subnet.
//
// The relay carries the same 0xAA frames the LAN path uses, so everything in
// protocol.h, properties.h and capabilities.h works unchanged over it. Only
// the transport differs: the frame goes into a plaintext 0x5A5A packet, is
// rendered as a comma-separated list of *signed* bytes, AES-CBC encrypted, and
// posted as an "order" field.
#pragma once

#include <cstdint>
#include <string>

#include "cloud.h"
#include "protocol.h"

namespace coolth {

class CloudLAN {
 public:
  CloudLAN(uint64_t appliance_id, std::string account, std::string password,
           HttpPost post);

  void set_app(const std::string &app_id, const std::string &app_key);
  void set_base_url(const std::string &url) { this->base_url_ = url; }
  void set_timestamp(const std::string &stamp) { this->stamp_ = stamp; }
  void set_client_device_id(const std::string &hex) { this->client_id_ = hex; }
  // Eight bytes in the appliance's own layout; see make_timestamp().
  void set_packet_timestamp(const uint8_t timestamp[8]);

  bool login(std::string *error);
  // Relays one frame. `reply` is left empty when the cloud accepts the command
  // without a synchronous answer, which is normal for a set.
  bool send(const Bytes &frame, Bytes *reply, std::string *error);

  bool logged_in() const { return !this->session_id_.empty() && this->iv_.size() == 16; }

  // --- pieces exposed for testing -----------------------------------------
  static Bytes build_5a5a_packet(const Bytes &frame, uint64_t appliance_id,
                                 uint32_t seq, const uint8_t timestamp[8]);
  // Bytes above 127 are rendered negative, as a Java-style signed byte would
  // be. Getting this wrong produces an order the cloud accepts and the
  // appliance ignores.
  static std::string to_text(const Bytes &packet);
  static Bytes from_text(const std::string &text);
  static bool extract_aa(const Bytes &packet, Bytes *frame);
  static Bytes derive_key(const std::string &app_key,
                          const std::string &access_token);
  static std::string password_hash(const std::string &login_id,
                                   const std::string &password,
                                   const std::string &app_key);
  static std::string sign(const std::string &path,
                          const std::map<std::string, std::string> &body,
                          const std::string &app_key);
  // Builds the 8 byte packet timestamp from broken-down local time.
  static void make_timestamp(int year, int month, int day, int hour, int minute,
                             int second, int millisecond, uint8_t out[8]);

 protected:
  std::map<std::string, std::string> login_body() const;
  std::map<std::string, std::string> base_body() const;
  bool post(const std::string &path,
            std::map<std::string, std::string> body, std::string *response,
            std::string *error);
  bool recover_iv(std::string *error);
  uint32_t next_seq() { return ++this->seq_; }

  uint64_t appliance_id_;
  std::string account_;
  std::string password_;
  HttpPost post_fn_;
  std::string app_id_{"1121"};
  std::string app_key_{"08822d2f357aa76712189c00fcc0fc4d"};
  std::string base_url_{"https://mapp-us.appsmb.com"};
  std::string stamp_;
  std::string client_id_{"0123456789abcdef"};
  std::string session_id_;
  Bytes key_;
  Bytes iv_;
  uint32_t seq_{1000};
  uint8_t timestamp_[8] = {0};
};

}  // namespace coolth
