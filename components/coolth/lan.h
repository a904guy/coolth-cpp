// The LAN transport: TCP to the appliance on port 6444.
//
// Two generations share the port. V2 devices take a 0x5A5A packet directly.
// V3 devices wrap it in a 0x8370 envelope and refuse to talk until a
// token/key handshake has produced a session key. Which one you have is
// decided by whether a token and key were supplied.
//
// Sockets are injected rather than opened here, so the library stays free of
// platform headers and the whole exchange is testable without a network.
#pragma once

#include <cstdint>
#include <functional>
#include <string>

#include "protocol.h"

namespace coolth {

// Byte-stream transport. Return false on any failure; the caller reconnects.
struct Connection {
  std::function<bool(const Bytes &data)> write;
  // Must fill exactly `length` bytes or fail; short reads are a protocol error
  // rather than something to paper over.
  std::function<bool(size_t length, Bytes *out)> read_exact;
};

class LanTransport {
 public:
  explicit LanTransport(uint64_t device_id) : device_id_(device_id) {}

  // Supplying both selects V3. Leaving them empty selects V2.
  void set_credentials(const Bytes &token, const Bytes &key);
  void set_connection(Connection connection) { this->connection_ = std::move(connection); }
  // Eight bytes, YYYYMMDDHHMMSSmm as two digits each. Not validated by the
  // appliance, but it must be present.
  void set_timestamp(const uint8_t timestamp[8]);

  bool is_v3() const { return !this->token_.empty() && !this->key_.empty(); }
  bool authenticated() const { return !this->is_v3() || !this->local_key_.empty(); }
  // Call after reconnecting: the session key belongs to the socket, not the device.
  void reset_session() { this->local_key_.clear(); }

  // Appliances routinely ignore the first command after a handshake and answer
  // the second. It is not a lost packet -- the request is well formed and
  // simply gets no reply -- so a single-shot send looks like a dead device.
  // coolth retries three times; so do we.
  void set_retries(int retries) { this->retries_ = retries > 0 ? retries : 1; }

  bool authenticate(std::string *error);
  // Sends one command frame and returns the appliance's reply frame.
  bool send_frame(const Bytes &frame, Bytes *reply, std::string *error);

 protected:
  bool read_envelope(Bytes *packet, std::string *error);
  bool send_once(const Bytes &packet, Bytes *reply, std::string *error);

  uint64_t device_id_;
  Bytes token_;
  Bytes key_;
  Bytes local_key_;
  Connection connection_;
  uint16_t packet_id_{0};
  int retries_{3};
  uint8_t timestamp_[8] = {0, 0, 0, 12, 1, 1, 26, 20};
};

}  // namespace coolth
