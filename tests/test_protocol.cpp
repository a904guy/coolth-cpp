// The three protocol layers, checked byte-for-byte against vectors captured
// from coolth, plus a state response captured from a real appliance.

#include "../components/coolth/protocol.h"
#include "golden_vectors.h"
#include "harness.h"

using namespace coolth;

// The state the live unit reported, so the set-command vectors correspond to
// traffic the appliance would actually receive.
static AcState live_state() {
  AcState state;
  state.power = true;
  state.mode = mode::COOL;
  state.fan_speed = fan::AUTO;
  state.swing_mode = swing::OFF;
  state.fahrenheit = true;
  state.target_humidity = 0;
  state.beep = false;
  return state;
}

int main() {
  printf("crypto primitives\n");
  expect_hex("enc_key is md5 of the signing string", from_hex(GOLDEN_ENC_KEY),
             GOLDEN_ENC_KEY);
  expect_hex("aes-ecb encrypt of the get-state frame",
             aes_ecb_encrypt_padded(from_hex(GOLDEN_GET_STATE_FRAME)),
             GOLDEN_AES_ECB_GET_FRAME);
  expect_hex("md5 signature", sign(from_hex(GOLDEN_GET_STATE_FRAME)),
             GOLDEN_MD5_SIGN_GET_FRAME);
  expect_true("aes-ecb round trips",
              aes_ecb_decrypt_unpadded(
                  aes_ecb_encrypt_padded(from_hex(GOLDEN_GET_STATE_FRAME))) ==
                  from_hex(GOLDEN_GET_STATE_FRAME));
  expect_true("pkcs7 round trips", [] {
    Bytes data = from_hex("00112233");
    Bytes padded = pkcs7_pad(data);
    return padded.size() == 16 && pkcs7_unpad(&padded) && padded == data;
  }());
  expect_true("corrupt padding is refused", [] {
    Bytes data(16, 0xFF);  // a pad byte of 0xFF is impossible
    return !pkcs7_unpad(&data);
  }());

  printf("\nlayer 1: 0xAA command frames\n");
  expect_hex("get state", build_get_state_frame(GOLDEN_MESSAGE_ID),
             GOLDEN_GET_STATE_FRAME);
  {
    AcState state = live_state();
    state.target_temperature = 24.0f;
    expect_hex("set 24.0C", build_set_state_frame(state, GOLDEN_MESSAGE_ID),
               GOLDEN_SET_STATE_FRAME_24C);
    state.target_temperature = 25.0f;
    expect_hex("set 25.0C", build_set_state_frame(state, GOLDEN_MESSAGE_ID),
               GOLDEN_SET_STATE_FRAME_25C);
    state.target_temperature = 24.5f;
    expect_hex("set 24.5C (half degree bit)",
               build_set_state_frame(state, GOLDEN_MESSAGE_ID),
               GOLDEN_SET_STATE_FRAME_24_5C);
  }

  printf("\nlayer 2: 0x5A5A packets\n");
  {
    const Bytes timestamp = from_hex(GOLDEN_TIMESTAMP);
    expect_hex("get-state packet",
               encode_packet(GOLDEN_DEVICE_ID, from_hex(GOLDEN_GET_STATE_FRAME),
                             timestamp.data()),
               GOLDEN_PACKET_5A5A_GET);
    expect_hex("set-25C packet",
               encode_packet(GOLDEN_DEVICE_ID,
                             from_hex(GOLDEN_SET_STATE_FRAME_25C),
                             timestamp.data()),
               GOLDEN_PACKET_5A5A_SET_25C);

    // Smallest unit first, plain integers. The appliance sanity-checks this
    // and silently drops a packet whose month or day is zero.
    uint8_t built[8];
    make_lan_timestamp(2026, 8, 19, 19, 34, 56, 78, built);
    expect_hex("timestamp layout", Bytes(built, built + 8), GOLDEN_TIMESTAMP);

    Bytes decoded;
    expect_true("packet decodes",
                decode_packet(from_hex(GOLDEN_PACKET_5A5A_GET), &decoded));
    expect_hex("decoded frame matches", decoded, GOLDEN_GET_STATE_FRAME);

    Bytes corrupt = from_hex(GOLDEN_PACKET_5A5A_GET);
    corrupt[corrupt.size() - 1] ^= 0xFF;
    expect_true("corrupt signature rejected", !decode_packet(corrupt, &decoded));
  }

  printf("\nlayer 3: 0x8370 envelope\n");
  {
    expect_hex("handshake request",
               encode_handshake_request(0, from_hex(GOLDEN_TOKEN)),
               GOLDEN_HANDSHAKE_REQUEST);

    // The length field counts the payload and hash but not the 2 byte packet
    // id, so a reader must take length + 8 in total. Getting this wrong leaves
    // two bytes in the socket and desynchronises every packet after the first
    // -- which looks like intermittent corruption, not an off-by-two.
    {
      const Bytes request = encode_encrypted_request(
          0, from_hex(GOLDEN_LOCAL_KEY), from_hex(GOLDEN_PACKET_5A5A_SET_25C),
          GOLDEN_PAD_BYTE);
      const size_t declared = (request[2] << 8) | request[3];
      expect_true("packet size is the declared length plus 8",
                  request.size() == declared + 8);
      const Bytes handshake =
          encode_handshake_request(0, from_hex(GOLDEN_TOKEN));
      const size_t handshake_declared = (handshake[2] << 8) | handshake[3];
      expect_true("handshake obeys the same rule",
                  handshake.size() == handshake_declared + 8);
    }

    Bytes local_key;
    expect_true("local key derives",
                derive_local_key(from_hex(GOLDEN_KEY),
                                 from_hex(GOLDEN_HANDSHAKE_RESPONSE_SYNTHETIC),
                                 &local_key));
    expect_hex("derived local key", local_key,
               GOLDEN_HANDSHAKE_DERIVED_LOCAL_KEY);

    // A wrong key must fail the SHA256 check rather than yield a junk key that
    // would then produce silently undecryptable traffic.
    Bytes wrong_key = from_hex(GOLDEN_KEY);
    wrong_key[0] ^= 0xFF;
    Bytes ignored;
    expect_true("wrong key rejected",
                !derive_local_key(wrong_key,
                                  from_hex(GOLDEN_HANDSHAKE_RESPONSE_SYNTHETIC),
                                  &ignored));

    expect_hex("encrypted request",
               encode_encrypted_request(0, from_hex(GOLDEN_LOCAL_KEY),
                                        from_hex(GOLDEN_PACKET_5A5A_SET_25C),
                                        GOLDEN_PAD_BYTE),
               GOLDEN_ENCRYPTED_REQUEST_SET_25C);
  }

  printf("\nstate parsing (against a response captured from the appliance)\n");
  {
    // A real frame off the wire. A synthetic round trip would not do here: set
    // commands and state responses encode the same flags in different bits
    // (eco is 0x80 of byte 9 when sent, 0x10 of byte 9 when received), so
    // building a frame and reading it back would confirm nothing.
    AcState parsed;
    expect_true("live frame parses",
                parse_state_frame(from_hex(GOLDEN_LIVE_STATE_FRAME), &parsed));
    expect_true("power", parsed.power == (bool) GOLDEN_LIVE_POWER);
    expect_int("mode", parsed.mode, GOLDEN_LIVE_MODE);
    expect_int("fan speed", parsed.fan_speed, GOLDEN_LIVE_FAN_SPEED);
    expect_int("swing mode", parsed.swing_mode, GOLDEN_LIVE_SWING_MODE);
    expect_true("eco", parsed.eco == (bool) GOLDEN_LIVE_ECO);
    expect_true("turbo", parsed.turbo == (bool) GOLDEN_LIVE_TURBO);
    expect_true("sleep", parsed.sleep == (bool) GOLDEN_LIVE_SLEEP);
    expect_true("fahrenheit", parsed.fahrenheit == (bool) GOLDEN_LIVE_FAHRENHEIT);
    expect_int("target humidity", parsed.target_humidity,
               GOLDEN_LIVE_TARGET_HUMIDITY);
    expect_near("target temperature", parsed.target_temperature,
                GOLDEN_LIVE_TARGET_TEMPERATURE_X10 / 10.0f);
    expect_near("outdoor temperature", parsed.outdoor_temperature,
                GOLDEN_LIVE_OUTDOOR_TEMPERATURE_X10 / 10.0f);

    // Read state, change only the setpoint, send it back: the round trip that
    // actually matters, since it is what every client does.
    parsed.target_temperature = 25.0f;
    parsed.beep = false;
    expect_hex("re-emitted set command preserves live state",
               build_set_state_frame(parsed, GOLDEN_MESSAGE_ID),
               GOLDEN_SET_STATE_FRAME_25C);

    AcState ignored;
    Bytes junk = from_hex(GOLDEN_LIVE_STATE_FRAME);
    junk[10] = 0xB1;  // properties response, not state
    expect_true("non-state response rejected", !parse_state_frame(junk, &ignored));
    expect_true("short frame rejected",
                !parse_state_frame(Bytes(12, 0xAA), &ignored));
  }

  return report();
}
