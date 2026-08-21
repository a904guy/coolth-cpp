// Midea V3 LAN protocol -- pure logic, no ESPHome or ESP-IDF dependencies.
//
// Kept free of platform headers on purpose: this file compiles and runs on a
// workstation, which is how it gets checked byte-for-byte against vectors
// captured from coolth (the reference implementation) without a device.
//
// Three nested layers, outermost last:
//   0xAA   command frame   -- what the appliance actually acts on
//   0x5A5A packet          -- AES-ECB encrypted frame + MD5 signature
//   0x8370 envelope        -- AES-CBC encrypted packet + SHA256, session keyed
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace coolth {

using Bytes = std::vector<uint8_t>;

// --- crypto primitives ------------------------------------------------------
Bytes sha256(const Bytes &data);
Bytes md5(const Bytes &data);
// All AES here uses a zero IV; that is what the protocol specifies, not an
// oversight. Confidentiality rests on the per-session local key.
Bytes aes_cbc_encrypt(const Bytes &key, const Bytes &data);
Bytes aes_cbc_decrypt(const Bytes &key, const Bytes &data);
// The 0x5A5A layer uses a fixed, publicly known key derived from a constant
// string, so it is obfuscation rather than security. The real protection is
// the token/key pair at the 0x8370 layer.
Bytes aes_ecb_encrypt_padded(const Bytes &data);
Bytes aes_ecb_decrypt_unpadded(const Bytes &data);

// Generic variants, for the cloud relay, which uses its own keys and a real IV.
Bytes aes_cbc_encrypt_iv(const Bytes &key, const Bytes &iv, const Bytes &data);
Bytes aes_cbc_decrypt_iv(const Bytes &key, const Bytes &iv, const Bytes &data);
Bytes aes_ecb_decrypt_raw(const Bytes &key, const Bytes &data);
Bytes pkcs7_pad(const Bytes &data);
bool pkcs7_unpad(Bytes *data);
Bytes sign(const Bytes &data);  // md5(data + SIGN_KEY)
Bytes hmac_sha256(const Bytes &key, const Bytes &data);

Bytes from_hex(const std::string &hex);
std::string to_hex(const Bytes &data);

// --- layer 1: the 0xAA command frame ---------------------------------------

// Values the appliance understands. Names follow coolth so the two are easy to
// read side by side.
namespace mode {
enum OperationalMode : uint8_t {
  AUTO = 1, COOL = 2, DRY = 3, HEAT = 4, FAN_ONLY = 5, SMART_DRY = 6,
};
}  // namespace mode

namespace fan {
// Anything 0-100 is a percentage; 102 asks the unit to decide. A device only
// accepts arbitrary percentages if it reports CUSTOM_FAN_SPEED.
enum FanSpeed : uint8_t {
  AUTO = 102, FULL = 100, HIGH = 80, MEDIUM = 60, LOW = 40, SILENT = 20,
};
}  // namespace fan

namespace swing {
enum SwingMode : uint8_t {
  OFF = 0x0, VERTICAL = 0xC, HORIZONTAL = 0x3, BOTH = 0xF,
};
// Discrete louvre positions, set through properties rather than the state frame.
enum SwingAngle : uint8_t {
  ANGLE_OFF = 0, POS_1 = 1, POS_2 = 25, POS_3 = 50, POS_4 = 75, POS_5 = 100,
};
}  // namespace swing

namespace preset {
enum CascadeMode : uint8_t { CASCADE_OFF = 0, CASCADE_UP = 1, CASCADE_DOWN = 2 };
// 100 means off. Units expose either the two-gear or the five-level set.
enum RateSelect : uint8_t {
  RATE_OFF = 100, GEAR_50 = 50, GEAR_75 = 75,
  LEVEL_1 = 1, LEVEL_2 = 20, LEVEL_3 = 40, LEVEL_4 = 60, LEVEL_5 = 80,
};
enum BreezeMode : uint8_t {
  BREEZE_OFF = 1, BREEZE_AWAY = 2, BREEZE_MILD = 3, BREEZELESS = 4,
};
enum FreshAirFanSpeed : uint8_t {
  FRESH_OFF = 0, FRESH_LOW = 40, FRESH_MEDIUM = 60, FRESH_HIGH = 80, FRESH_BOOST = 100,
};
enum AuxHeatMode : uint8_t { AUX_OFF = 0, AUX_HEAT = 1, AUX_ONLY = 2 };
}  // namespace preset

// Everything a set command must carry. A set replaces the appliance's entire
// state, so changing only the temperature still means sending every other
// field back exactly as it was read -- otherwise the unit switches off or
// changes mode as a side effect.
struct AcState {
  bool power = false;
  uint8_t mode = 0;       // 1 auto, 2 cool, 3 dry, 4 heat, 5 fan
  uint8_t fan_speed = 102;  // 102 = auto
  uint8_t swing_mode = 0;
  bool eco = false;
  bool turbo = false;
  bool sleep = false;
  bool fahrenheit = false;  // display unit only; the wire is always Celsius
  bool purifier = false;
  bool follow_me = false;
  bool freeze_protection = false;
  bool aux_heat = false;
  bool independent_aux_heat = false;
  bool beep = false;
  uint8_t target_humidity = 0;
  float target_temperature = 25.0f;
  float indoor_temperature = 0.0f;
  float outdoor_temperature = 0.0f;
  uint8_t error_code = 0;
  bool filter_alert = false;
  bool display_on = true;
  float indoor_humidity = 0.0f;
  bool indoor_humidity_valid = false;
  bool valid = false;

  // Carried in properties rather than the state frame. Reading state leaves
  // these at their defaults; query the matching properties to populate them.
  uint8_t vertical_swing_angle = swing::ANGLE_OFF;
  uint8_t horizontal_swing_angle = swing::ANGLE_OFF;
  uint8_t breeze_mode = preset::BREEZE_OFF;
  uint8_t cascade_mode = preset::CASCADE_OFF;
  uint8_t rate_select = preset::RATE_OFF;
  uint8_t fresh_air_fan_speed = preset::FRESH_OFF;
  bool ieco = false;
  bool self_clean = false;
  bool flash = false;
  bool out_silent = false;
};

// Each command carries an incrementing message id and a CRC8 over the payload.
// The appliance does not appear to check the id, but the CRC must be right and
// the id must be present -- both are inside the length the frame declares.
uint8_t crc8(const uint8_t *data, size_t length);
Bytes build_get_state_frame(uint8_t message_id);
Bytes build_set_state_frame(const AcState &state, uint8_t message_id);
bool parse_state_frame(const Bytes &frame, AcState *out);

// Toggles the panel display. There is no "set display to X" -- the appliance
// only offers a toggle, so callers must track the current state themselves.
Bytes build_toggle_display_frame(bool beep, uint8_t message_id);

// --- layer 2: the 0x5A5A packet --------------------------------------------
// Builds the 8 byte packet timestamp. Smallest unit first, and each byte is a
// plain integer, not BCD. The appliance does sanity-check this: a month of 0
// or an hour of 25 gets the packet dropped with no reply at all, which is
// indistinguishable from a network problem. Use this rather than hand-rolling.
void make_lan_timestamp(int year, int month, int day, int hour, int minute,
                        int second, int centisecond, uint8_t out[8]);

// `timestamp` is the 8 bytes make_lan_timestamp produces.
Bytes encode_packet(uint64_t device_id, const Bytes &frame,
                    const uint8_t timestamp[8]);
bool decode_packet(const Bytes &packet, Bytes *frame_out);

// --- layer 3: the 0x8370 envelope ------------------------------------------
enum PacketType : uint8_t {
  HANDSHAKE_REQUEST = 0x0,
  HANDSHAKE_RESPONSE = 0x1,
  ENCRYPTED_RESPONSE = 0x3,
  ENCRYPTED_REQUEST = 0x6,
  PACKET_ERROR = 0xF,
};

Bytes encode_handshake_request(uint16_t packet_id, const Bytes &token);
// Turns the handshake reply into the per-session local key. Fails if the
// SHA256 does not match, which is what catches a wrong or stale token/key.
bool derive_local_key(const Bytes &key, const Bytes &response,
                      Bytes *local_key_out);
// `pad_byte` fills the alignment padding. Production passes random bytes; the
// tests pin it so the output is reproducible.
Bytes encode_encrypted_request(uint16_t packet_id, const Bytes &local_key,
                               const Bytes &data, uint8_t pad_byte);
bool decode_encrypted_response(const Bytes &local_key, const Bytes &packet,
                               Bytes *data_out);

}  // namespace coolth
