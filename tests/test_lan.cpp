// The LAN transport, driven against a fake appliance that speaks the real
// protocol back at it. Covers V2 (no handshake) and V3 (handshake required).

#include <cstring>
#include <vector>

#include "../components/coolth/lan.h"
#include "golden_vectors.h"
#include "harness.h"

using namespace coolth;

// A stand-in appliance: a byte queue the transport reads from, plus a record
// of what it was sent.
struct FakeAppliance {
  Bytes inbox;
  Bytes outbox;
  size_t read_pos = 0;
  bool fail_writes = false;
  int reads_attempted = 0;

  Connection connection() {
    return Connection{
        [this](const Bytes &data) {
          if (this->fail_writes)
            return false;
          this->inbox.insert(this->inbox.end(), data.begin(), data.end());
          return true;
        },
        [this](size_t length, Bytes *out) {
          this->reads_attempted++;
          if (this->read_pos + length > this->outbox.size())
            return false;
          out->assign(this->outbox.begin() + this->read_pos,
                      this->outbox.begin() + this->read_pos + length);
          this->read_pos += length;
          return true;
        }};
  }

  void queue(const Bytes &data) {
    this->outbox.insert(this->outbox.end(), data.begin(), data.end());
  }
};

// Builds a well formed encrypted *response* envelope for a given packet.
static Bytes make_response_envelope(const Bytes &session_key,
                                    const Bytes &packet) {
  Bytes envelope = encode_encrypted_request(0, session_key, packet, 0xAB);
  envelope[5] = static_cast<uint8_t>((envelope[5] & 0xF0) | 0x03);
  // The SHA256 covers the header, so it must be recomputed after retyping.
  const size_t pad = envelope[5] >> 4;
  Bytes payload{0, 0};
  payload.insert(payload.end(), packet.begin(), packet.end());
  payload.insert(payload.end(), pad, 0xAB);
  Bytes to_hash(envelope.begin(), envelope.begin() + 6);
  to_hash.insert(to_hash.end(), payload.begin(), payload.end());
  const Bytes digest = sha256(to_hash);
  memcpy(envelope.data() + envelope.size() - 32, digest.data(), 32);
  return envelope;
}

int main() {
  const Bytes token = from_hex(GOLDEN_TOKEN);
  const Bytes key = from_hex(GOLDEN_KEY);
  const Bytes timestamp = from_hex(GOLDEN_TIMESTAMP);
  const Bytes session_key = from_hex(GOLDEN_HANDSHAKE_DERIVED_LOCAL_KEY);

  // Length 0x40 = 64: the body only. The 6 byte header and the 2 byte packet
  // id that follow are not counted -- the bug this fixture guards against.
  Bytes handshake_reply = from_hex("8370004020010000");
  {
    const Bytes body = from_hex(GOLDEN_HANDSHAKE_RESPONSE_SYNTHETIC);
    handshake_reply.insert(handshake_reply.end(), body.begin(), body.end());
  }

  printf("V2 transport (no handshake)\n");
  {
    FakeAppliance device;
    LanTransport lan(GOLDEN_DEVICE_ID);
    lan.set_connection(device.connection());
    lan.set_timestamp(timestamp.data());

    expect_true("a device without credentials is V2", !lan.is_v3());
    expect_true("V2 needs no authentication", lan.authenticated());

    device.queue(encode_packet(GOLDEN_DEVICE_ID,
                               from_hex(GOLDEN_LIVE_STATE_FRAME),
                               timestamp.data()));

    Bytes reply;
    std::string error;
    expect_true("send succeeds",
                lan.send_frame(from_hex(GOLDEN_GET_STATE_FRAME), &reply, &error));
    expect_eq("reply frame", to_hex(reply), GOLDEN_LIVE_STATE_FRAME);
    expect_true("request went out as a bare 5A5A packet",
                device.inbox.size() > 2 && device.inbox[0] == 0x5A &&
                    device.inbox[1] == 0x5A);
  }

  printf("\nV3 transport (handshake required)\n");
  {
    FakeAppliance device;
    LanTransport lan(GOLDEN_DEVICE_ID);
    lan.set_connection(device.connection());
    lan.set_timestamp(timestamp.data());
    lan.set_credentials(token, key);

    expect_true("credentials select V3", lan.is_v3());
    expect_true("not authenticated yet", !lan.authenticated());

    device.queue(handshake_reply);
    device.queue(make_response_envelope(
        session_key, encode_packet(GOLDEN_DEVICE_ID,
                                   from_hex(GOLDEN_LIVE_STATE_FRAME),
                                   timestamp.data())));

    Bytes reply;
    std::string error;
    expect_true("send authenticates then succeeds",
                lan.send_frame(from_hex(GOLDEN_GET_STATE_FRAME), &reply, &error));
    expect_true("authenticated afterwards", lan.authenticated());
    expect_eq("reply frame", to_hex(reply), GOLDEN_LIVE_STATE_FRAME);
    expect_true("request went out inside an 8370 envelope",
                device.inbox.size() > 2 && device.inbox[0] == 0x83 &&
                    device.inbox[1] == 0x70);

    // A session key belongs to its socket. After a reconnect it must be
    // discarded, or every packet after is undecryptable at the far end.
    lan.reset_session();
    expect_true("session dropped on reset", !lan.authenticated());
  }

  printf("\nretry on a dropped first request\n");
  {
    // Appliances routinely ignore the first command after a handshake and
    // answer the second. Without a retry this looks like a dead device, and
    // the request bytes are perfectly valid, so nothing points at the cause.
    FakeAppliance device;
    LanTransport lan(GOLDEN_DEVICE_ID);
    lan.set_connection(device.connection());
    lan.set_timestamp(timestamp.data());
    lan.set_credentials(token, key);

    device.queue(handshake_reply);
    // Nothing queued for the first request, so its read fails; the reply is
    // only made available for the second attempt.
    Bytes reply;
    std::string error;
    expect_true("single attempt would fail here", device.outbox.size() ==
                                                      handshake_reply.size());

    // Queue the answer so the retry finds it.
    device.queue(make_response_envelope(
        session_key, encode_packet(GOLDEN_DEVICE_ID,
                                   from_hex(GOLDEN_LIVE_STATE_FRAME),
                                   timestamp.data())));
    expect_true("send succeeds via the retry",
                lan.send_frame(from_hex(GOLDEN_GET_STATE_FRAME), &reply, &error));
    expect_eq("reply frame", to_hex(reply), GOLDEN_LIVE_STATE_FRAME);
    expect_true("two requests were actually sent",
                device.inbox.size() > 200);
  }

  printf("\nfailure handling\n");
  {
    std::string error;
    FakeAppliance silent;
    LanTransport lan(GOLDEN_DEVICE_ID);
    lan.set_connection(silent.connection());
    lan.set_credentials(token, key);
    expect_true("silence is a failure, not a hang", !lan.authenticate(&error));

    FakeAppliance bad;
    bad.queue(from_hex("5a5a0000ffff"));
    LanTransport lan2(GOLDEN_DEVICE_ID);
    lan2.set_connection(bad.connection());
    lan2.set_credentials(token, key);
    expect_true("wrong packet start rejected", !lan2.authenticate(&error));

    LanTransport lan3(GOLDEN_DEVICE_ID);
    lan3.set_connection(bad.connection());
    lan3.set_credentials(from_hex("0011"), key);
    expect_true("malformed credentials refused up front", !lan3.authenticate(&error));
    expect_true("and say so", error.find("64 bytes") != std::string::npos);

    // A write failure means the socket is gone, so retrying is pointless and
    // must not burn the whole retry budget.
    FakeAppliance unwritable;
    unwritable.fail_writes = true;
    LanTransport lan4(GOLDEN_DEVICE_ID);
    lan4.set_connection(unwritable.connection());
    Bytes reply;
    expect_true("write failure surfaces",
                !lan4.send_frame(from_hex(GOLDEN_GET_STATE_FRAME), &reply, &error));
    expect_int("and is not retried", (long) unwritable.reads_attempted, 0);
  }

  return report();
}
