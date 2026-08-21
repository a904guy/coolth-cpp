#include "lan.h"

#include <cstring>

namespace coolth {

void LanTransport::set_credentials(const Bytes &token, const Bytes &key) {
  this->token_ = token;
  this->key_ = key;
  this->local_key_.clear();
}

void LanTransport::set_timestamp(const uint8_t timestamp[8]) {
  memcpy(this->timestamp_, timestamp, 8);
}

bool LanTransport::read_envelope(Bytes *packet, std::string *error) {
  // The envelope declares its own body length, so read the header first and
  // then exactly that much rather than guessing where the packet ends.
  Bytes header;
  if (!this->connection_.read_exact(6, &header) || header.size() != 6) {
    *error = "no response from the appliance";
    return false;
  }
  if (header[0] != 0x83 || header[1] != 0x70) {
    *error = "unexpected packet start";
    return false;
  }
  // The length field covers the payload and hash but NOT the 2 byte packet
  // id that follows the header, so the rest of the packet is length + 2.
  // Reading `length` alone leaves two bytes in the socket and desynchronises
  // every subsequent packet.
  const size_t body =
      ((static_cast<size_t>(header[2]) << 8) | header[3]) + 2;
  if (body > 2048) {
    *error = "implausible packet length";
    return false;
  }
  Bytes rest;
  if (!this->connection_.read_exact(body, &rest) || rest.size() != body) {
    *error = "truncated packet";
    return false;
  }
  *packet = header;
  packet->insert(packet->end(), rest.begin(), rest.end());
  return true;
}

bool LanTransport::authenticate(std::string *error) {
  if (!this->is_v3()) {
    // V2 has no handshake at all; there is nothing to do and nothing to fail.
    return true;
  }
  if (this->token_.size() != 64 || this->key_.size() != 32) {
    *error = "token must be 64 bytes and key 32";
    return false;
  }

  const Bytes request =
      encode_handshake_request(this->packet_id_++, this->token_);
  if (!this->connection_.write(request)) {
    *error = "could not send the handshake";
    return false;
  }

  Bytes packet;
  if (!this->read_envelope(&packet, error))
    return false;
  if (packet.size() < 8 + 64) {
    *error = "handshake reply too short";
    return false;
  }
  // Header (6) plus the echoed packet id (2), then the 64 byte body.
  const Bytes body(packet.begin() + 8, packet.end());
  if (!derive_local_key(this->key_, body, &this->local_key_)) {
    *error = "handshake rejected; check the token and key";
    return false;
  }
  return true;
}

bool LanTransport::send_frame(const Bytes &frame, Bytes *reply,
                              std::string *error) {
  if (this->is_v3() && !this->authenticated() && !this->authenticate(error))
    return false;

  const Bytes packet =
      encode_packet(this->device_id_, frame, this->timestamp_);

  // See set_retries: the first request after a handshake is commonly dropped
  // on the floor by the appliance with no reply and no error.
  for (int attempt = 0; attempt < this->retries_; attempt++) {
    if (this->send_once(packet, reply, error))
      return true;
    // A failure to *write* means the socket is gone; retrying is pointless.
    if (*error == "could not send the command")
      return false;
  }
  return false;
}

bool LanTransport::send_once(const Bytes &packet, Bytes *reply,
                             std::string *error) {
  if (!this->is_v3()) {
    // V2: the 0x5A5A packet goes on the wire as-is.
    if (!this->connection_.write(packet)) {
      *error = "could not send the command";
      return false;
    }
    // The reply is a bare 0x5A5A packet; its length lives at offset 4 and,
    // unlike the 0x8370 envelope, counts the whole packet.
    Bytes header;
    if (!this->connection_.read_exact(6, &header) || header.size() != 6) {
      *error = "no response from the appliance";
      return false;
    }
    if (header[0] != 0x5A || header[1] != 0x5A) {
      *error = "unexpected packet start";
      return false;
    }
    const size_t length =
        static_cast<size_t>(header[4]) | (static_cast<size_t>(header[5]) << 8);
    if (length < 6 || length > 2048) {
      *error = "implausible packet length";
      return false;
    }
    Bytes rest;
    if (!this->connection_.read_exact(length - 6, &rest) ||
        rest.size() != length - 6) {
      *error = "truncated packet";
      return false;
    }
    Bytes full = header;
    full.insert(full.end(), rest.begin(), rest.end());
    if (!decode_packet(full, reply)) {
      *error = "could not decode the reply packet";
      return false;
    }
    return true;
  }

  // Padding is not a secret; vary it cheaply so it is not a constant on the
  // wire. Each retry also carries a fresh packet id, as coolth's does.
  const uint8_t pad_byte = static_cast<uint8_t>(this->packet_id_ * 31 + 7);
  const Bytes request = encode_encrypted_request(
      this->packet_id_++, this->local_key_, packet, pad_byte);
  if (!this->connection_.write(request)) {
    *error = "could not send the command";
    return false;
  }

  Bytes envelope;
  if (!this->read_envelope(&envelope, error))
    return false;
  Bytes inner;
  if (!decode_encrypted_response(this->local_key_, envelope, &inner)) {
    *error = "could not decrypt the reply";
    return false;
  }
  if (!decode_packet(inner, reply)) {
    *error = "could not decode the reply packet";
    return false;
  }
  return true;
}

}  // namespace coolth
