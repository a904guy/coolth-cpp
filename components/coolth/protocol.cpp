#include "protocol.h"

#include <cmath>
#include <cstring>

#include "mbedtls/aes.h"
#include "mbedtls/md5.h"
#include "mbedtls/md.h"
#include "mbedtls/sha256.h"

namespace coolth {
namespace {

// Constant from the Midea app. Public knowledge; not a secret we are keeping.
const char SIGN_KEY[] = "xhdiwjnchekd4d512chdjx5d8e4c394D2D7S";

Bytes sign_key_bytes() {
  return Bytes(SIGN_KEY, SIGN_KEY + sizeof(SIGN_KEY) - 1);
}

// The 0x5A5A layer's AES-ECB key is just md5 of the signing string.
const Bytes &enc_key() {
  static const Bytes key = md5(sign_key_bytes());
  return key;
}

void put_u16_be(Bytes *out, uint16_t value) {
  out->push_back(static_cast<uint8_t>(value >> 8));
  out->push_back(static_cast<uint8_t>(value & 0xFF));
}

}  // namespace

Bytes sha256(const Bytes &data) {
  Bytes out(32);
  mbedtls_sha256(data.data(), data.size(), out.data(), 0);
  return out;
}

Bytes md5(const Bytes &data) {
  Bytes out(16);
  mbedtls_md5(data.data(), data.size(), out.data());
  return out;
}

Bytes sign(const Bytes &data) {
  Bytes buffer = data;
  const Bytes key = sign_key_bytes();
  buffer.insert(buffer.end(), key.begin(), key.end());
  return md5(buffer);
}

Bytes hmac_sha256(const Bytes &key, const Bytes &data) {
  Bytes out(32);
  const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if (info == nullptr)
    return {};
  mbedtls_md_hmac(info, key.data(), key.size(), data.data(), data.size(),
                  out.data());
  return out;
}

Bytes aes_cbc_encrypt(const Bytes &key, const Bytes &data) {
  Bytes out(data.size());
  if (data.empty() || data.size() % 16 != 0)
    return {};
  mbedtls_aes_context ctx;
  mbedtls_aes_init(&ctx);
  mbedtls_aes_setkey_enc(&ctx, key.data(), static_cast<unsigned>(key.size() * 8));
  uint8_t iv[16] = {0};
  mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, data.size(), iv, data.data(),
                        out.data());
  mbedtls_aes_free(&ctx);
  return out;
}

Bytes aes_cbc_decrypt(const Bytes &key, const Bytes &data) {
  Bytes out(data.size());
  if (data.empty() || data.size() % 16 != 0)
    return {};
  mbedtls_aes_context ctx;
  mbedtls_aes_init(&ctx);
  mbedtls_aes_setkey_dec(&ctx, key.data(), static_cast<unsigned>(key.size() * 8));
  uint8_t iv[16] = {0};
  mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, data.size(), iv, data.data(),
                        out.data());
  mbedtls_aes_free(&ctx);
  return out;
}

Bytes aes_cbc_encrypt_iv(const Bytes &key, const Bytes &iv, const Bytes &data) {
  if (data.empty() || data.size() % 16 != 0 || iv.size() != 16)
    return {};
  Bytes out(data.size());
  uint8_t iv_copy[16];
  memcpy(iv_copy, iv.data(), 16);  // mbedtls advances the IV in place
  mbedtls_aes_context ctx;
  mbedtls_aes_init(&ctx);
  mbedtls_aes_setkey_enc(&ctx, key.data(), static_cast<unsigned>(key.size() * 8));
  mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, data.size(), iv_copy,
                        data.data(), out.data());
  mbedtls_aes_free(&ctx);
  return out;
}

Bytes aes_cbc_decrypt_iv(const Bytes &key, const Bytes &iv, const Bytes &data) {
  if (data.empty() || data.size() % 16 != 0 || iv.size() != 16)
    return {};
  Bytes out(data.size());
  uint8_t iv_copy[16];
  memcpy(iv_copy, iv.data(), 16);
  mbedtls_aes_context ctx;
  mbedtls_aes_init(&ctx);
  mbedtls_aes_setkey_dec(&ctx, key.data(), static_cast<unsigned>(key.size() * 8));
  mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, data.size(), iv_copy,
                        data.data(), out.data());
  mbedtls_aes_free(&ctx);
  return out;
}

Bytes aes_ecb_decrypt_raw(const Bytes &key, const Bytes &data) {
  if (data.empty() || data.size() % 16 != 0)
    return {};
  Bytes out(data.size());
  mbedtls_aes_context ctx;
  mbedtls_aes_init(&ctx);
  mbedtls_aes_setkey_dec(&ctx, key.data(), static_cast<unsigned>(key.size() * 8));
  for (size_t offset = 0; offset < data.size(); offset += 16)
    mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_DECRYPT, data.data() + offset,
                          out.data() + offset);
  mbedtls_aes_free(&ctx);
  return out;
}

Bytes pkcs7_pad(const Bytes &data) {
  const size_t pad = 16 - (data.size() % 16);
  Bytes out = data;
  out.insert(out.end(), pad, static_cast<uint8_t>(pad));
  return out;
}

bool pkcs7_unpad(Bytes *data) {
  if (data->empty() || data->size() % 16 != 0)
    return false;
  const uint8_t pad = data->back();
  if (pad == 0 || pad > 16 || pad > data->size())
    return false;
  data->resize(data->size() - pad);
  return true;
}

Bytes aes_ecb_encrypt_padded(const Bytes &data) {
  // PKCS#7: a full block of padding is added even when already aligned.
  const size_t pad = 16 - (data.size() % 16);
  Bytes padded = data;
  padded.insert(padded.end(), pad, static_cast<uint8_t>(pad));

  Bytes out(padded.size());
  mbedtls_aes_context ctx;
  mbedtls_aes_init(&ctx);
  const Bytes &key = enc_key();
  mbedtls_aes_setkey_enc(&ctx, key.data(), 128);
  for (size_t offset = 0; offset < padded.size(); offset += 16)
    mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, padded.data() + offset,
                          out.data() + offset);
  mbedtls_aes_free(&ctx);
  return out;
}

Bytes aes_ecb_decrypt_unpadded(const Bytes &data) {
  if (data.empty() || data.size() % 16 != 0)
    return {};
  Bytes out(data.size());
  mbedtls_aes_context ctx;
  mbedtls_aes_init(&ctx);
  const Bytes &key = enc_key();
  mbedtls_aes_setkey_dec(&ctx, key.data(), 128);
  for (size_t offset = 0; offset < data.size(); offset += 16)
    mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_DECRYPT, data.data() + offset,
                          out.data() + offset);
  mbedtls_aes_free(&ctx);

  const uint8_t pad = out.back();
  if (pad == 0 || pad > 16 || pad > out.size())
    return {};  // corrupt padding: treat as a decode failure, not a partial read
  out.resize(out.size() - pad);
  return out;
}

Bytes from_hex(const std::string &hex) {
  Bytes out;
  out.reserve(hex.size() / 2);
  auto nibble = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  };
  for (size_t i = 0; i + 1 < hex.size(); i += 2) {
    const int hi = nibble(hex[i]), lo = nibble(hex[i + 1]);
    if (hi < 0 || lo < 0) return {};
    out.push_back(static_cast<uint8_t>(hi << 4 | lo));
  }
  return out;
}

std::string to_hex(const Bytes &data) {
  static const char *digits = "0123456789abcdef";
  std::string out;
  out.reserve(data.size() * 2);
  for (uint8_t byte : data) {
    out.push_back(digits[byte >> 4]);
    out.push_back(digits[byte & 0xF]);
  }
  return out;
}

// --- layer 1: 0xAA command frame -------------------------------------------
namespace {

constexpr uint8_t DEVICE_TYPE_AC = 0xAC;
constexpr uint8_t FRAME_TYPE_CONTROL = 0x02;
constexpr uint8_t FRAME_TYPE_QUERY = 0x03;
constexpr uint8_t CONTROL_SOURCE = 0x02;  // "app control"

uint8_t frame_checksum(const Bytes &data, size_t begin, size_t end) {
  uint32_t sum = 0;
  for (size_t i = begin; i < end; i++) sum += data[i];
  return static_cast<uint8_t>((~sum + 1) & 0xFF);
}

// CRC-8/854 lookup table, as used by the Midea appliance protocol.
const uint8_t CRC8_854_TABLE[256] = {
    0x00, 0x5E, 0xBC, 0xE2, 0x61, 0x3F, 0xDD, 0x83, 0xC2, 0x9C, 0x7E, 0x20,
    0xA3, 0xFD, 0x1F, 0x41, 0x9D, 0xC3, 0x21, 0x7F, 0xFC, 0xA2, 0x40, 0x1E,
    0x5F, 0x01, 0xE3, 0xBD, 0x3E, 0x60, 0x82, 0xDC, 0x23, 0x7D, 0x9F, 0xC1,
    0x42, 0x1C, 0xFE, 0xA0, 0xE1, 0xBF, 0x5D, 0x03, 0x80, 0xDE, 0x3C, 0x62,
    0xBE, 0xE0, 0x02, 0x5C, 0xDF, 0x81, 0x63, 0x3D, 0x7C, 0x22, 0xC0, 0x9E,
    0x1D, 0x43, 0xA1, 0xFF, 0x46, 0x18, 0xFA, 0xA4, 0x27, 0x79, 0x9B, 0xC5,
    0x84, 0xDA, 0x38, 0x66, 0xE5, 0xBB, 0x59, 0x07, 0xDB, 0x85, 0x67, 0x39,
    0xBA, 0xE4, 0x06, 0x58, 0x19, 0x47, 0xA5, 0xFB, 0x78, 0x26, 0xC4, 0x9A,
    0x65, 0x3B, 0xD9, 0x87, 0x04, 0x5A, 0xB8, 0xE6, 0xA7, 0xF9, 0x1B, 0x45,
    0xC6, 0x98, 0x7A, 0x24, 0xF8, 0xA6, 0x44, 0x1A, 0x99, 0xC7, 0x25, 0x7B,
    0x3A, 0x64, 0x86, 0xD8, 0x5B, 0x05, 0xE7, 0xB9, 0x8C, 0xD2, 0x30, 0x6E,
    0xED, 0xB3, 0x51, 0x0F, 0x4E, 0x10, 0xF2, 0xAC, 0x2F, 0x71, 0x93, 0xCD,
    0x11, 0x4F, 0xAD, 0xF3, 0x70, 0x2E, 0xCC, 0x92, 0xD3, 0x8D, 0x6F, 0x31,
    0xB2, 0xEC, 0x0E, 0x50, 0xAF, 0xF1, 0x13, 0x4D, 0xCE, 0x90, 0x72, 0x2C,
    0x6D, 0x33, 0xD1, 0x8F, 0x0C, 0x52, 0xB0, 0xEE, 0x32, 0x6C, 0x8E, 0xD0,
    0x53, 0x0D, 0xEF, 0xB1, 0xF0, 0xAE, 0x4C, 0x12, 0x91, 0xCF, 0x2D, 0x73,
    0xCA, 0x94, 0x76, 0x28, 0xAB, 0xF5, 0x17, 0x49, 0x08, 0x56, 0xB4, 0xEA,
    0x69, 0x37, 0xD5, 0x8B, 0x57, 0x09, 0xEB, 0xB5, 0x36, 0x68, 0x8A, 0xD4,
    0x95, 0xCB, 0x29, 0x77, 0xF4, 0xAA, 0x48, 0x16, 0xE9, 0xB7, 0x55, 0x0B,
    0x88, 0xD6, 0x34, 0x6A, 0x2B, 0x75, 0x97, 0xC9, 0x4A, 0x14, 0xF6, 0xA8,
    0x74, 0x2A, 0xC8, 0x96, 0x15, 0x4B, 0xA9, 0xF7, 0xB6, 0xE8, 0x0A, 0x54,
    0xD7, 0x89, 0x6B, 0x35};

Bytes wrap_frame(uint8_t frame_type, const Bytes &payload) {
  Bytes frame(10, 0);
  frame[0] = 0xAA;
  frame[1] = static_cast<uint8_t>(payload.size() + 10);
  frame[2] = DEVICE_TYPE_AC;
  frame[8] = 0;  // protocol version
  frame[9] = frame_type;
  frame.insert(frame.end(), payload.begin(), payload.end());
  frame.push_back(frame_checksum(frame, 1, frame.size()));
  return frame;
}

// Appends the message id and CRC8 that every command carries, then frames it.
Bytes wrap_command(uint8_t frame_type, Bytes payload, uint8_t message_id) {
  payload.push_back(message_id);
  payload.push_back(crc8(payload.data(), payload.size()));
  return wrap_frame(frame_type, payload);
}

}  // namespace

uint8_t crc8(const uint8_t *data, size_t length) {
  uint8_t value = 0;
  for (size_t i = 0; i < length; i++)
    value = CRC8_854_TABLE[(value ^ data[i]) & 0xFF];
  return value;
}

Bytes build_get_state_frame(uint8_t message_id) {
  return wrap_command(FRAME_TYPE_QUERY, Bytes{
                                          0x41,                          // get state
                                          0x81, 0x00, 0xFF, 0x03, 0xFF,  // unknown
                                          0x00,
                                          0x02,  // indoor temperature
                                          0x00, 0x00, 0x00, 0x00,
                                          0x00, 0x00, 0x00, 0x00,
                                          0x00, 0x00, 0x00, 0x00,
                                          0x03,
                                      },
                      message_id);
}

Bytes build_set_state_frame(const AcState &state, uint8_t message_id) {
  const uint8_t beep = state.beep ? 0x40 : 0x00;
  const uint8_t power = state.power ? 0x01 : 0x00;

  // Temperature rides in two fields: 17-30C in the primary nibble, anything
  // outside that in the alternate byte. The half-degree is a separate bit.
  float integral_part = 0.0f;
  const float fractional = std::modf(state.target_temperature, &integral_part);
  const int integral = static_cast<int>(integral_part);
  uint8_t temperature, temperature_alt;
  if (integral >= 17 && integral <= 30) {
    temperature = static_cast<uint8_t>((integral - 16) & 0x0F);
    temperature_alt = 0;
  } else {
    temperature = 0;
    temperature_alt = static_cast<uint8_t>((integral - 12) & 0x1F);
  }
  if (fractional > 0.0f) temperature |= 0x10;

  const uint8_t mode = static_cast<uint8_t>((state.mode & 0x07) << 5);
  const uint8_t swing = static_cast<uint8_t>(0x30 | (state.swing_mode & 0x3F));

  return wrap_command(
      FRAME_TYPE_CONTROL,
      Bytes{
          0x40,                                             // set state
          static_cast<uint8_t>(CONTROL_SOURCE | beep | power),
          static_cast<uint8_t>(temperature | mode),
          state.fan_speed,
          0x7F, 0x7F, 0x00,                                 // timer: disabled
          swing,
          static_cast<uint8_t>((state.follow_me ? 0x80 : 0) |
                               (state.turbo ? 0x20 : 0)),
          static_cast<uint8_t>((state.eco ? 0x80 : 0) |
                               (state.purifier ? 0x20 : 0) |
                               (state.aux_heat ? 0x08 : 0)),
          static_cast<uint8_t>((state.sleep ? 0x01 : 0) |
                               (state.turbo ? 0x02 : 0) |
                               (state.fahrenheit ? 0x04 : 0)),
          0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00,
          temperature_alt,
          static_cast<uint8_t>(state.target_humidity & 0x7F),
          0x00,
          static_cast<uint8_t>(state.freeze_protection ? 0x80 : 0),
          static_cast<uint8_t>(state.independent_aux_heat ? 0x08 : 0),
          0x00,
      },
      message_id);
}

namespace {

constexpr uint8_t RESPONSE_ID_STATE = 0xC0;

float parse_temperature(uint8_t data, float decimals, bool fahrenheit,
                        bool *present) {
  if (data == 0xFF) {
    *present = false;
    return 0.0f;
  }
  *present = true;
  const float temperature = (static_cast<float>(data) - 50.0f) / 2.0f;
  // Celsius readings carry an extra tenth in a separate nibble; Fahrenheit
  // ones only ever resolve to a half degree.
  if (!fahrenheit && decimals != 0.0f) {
    const float whole = std::trunc(temperature);
    return whole + (temperature >= 0 ? decimals : -decimals);
  }
  if (decimals >= 0.5f) {
    const float whole = std::trunc(temperature);
    return whole + (temperature >= 0 ? 0.5f : -0.5f);
  }
  return temperature;
}

}  // namespace

bool parse_state_frame(const Bytes &frame, AcState *out) {
  // 10 byte header, then the payload, then a trailing checksum byte.
  if (frame.size() < 10 + 21 + 1 || frame[0] != 0xAA)
    return false;
  const uint8_t *payload = frame.data() + 10;
  const size_t payload_len = frame.size() - 10 - 1;
  // A set command is answered with a state response too, so both paths land
  // here; anything else (capabilities, property acks) is not our business.
  if (payload[0] != RESPONSE_ID_STATE)
    return false;

  out->power = (payload[1] & 0x01) != 0;
  out->target_temperature = static_cast<float>(payload[2] & 0x0F) + 16.0f;
  if (payload[2] & 0x10) out->target_temperature += 0.5f;
  out->mode = static_cast<uint8_t>((payload[2] >> 5) & 0x07);
  out->fan_speed = static_cast<uint8_t>(payload[3] & 0x7F);
  out->swing_mode = static_cast<uint8_t>(payload[7] & 0x0F);
  out->turbo = (payload[8] & 0x20) != 0;
  out->independent_aux_heat = (payload[8] & 0x40) != 0;
  out->follow_me = (payload[8] & 0x80) != 0;
  out->eco = (payload[9] & 0x10) != 0;
  out->purifier = (payload[9] & 0x20) != 0;
  out->aux_heat = (payload[9] & 0x08) != 0;
  out->sleep = (payload[10] & 0x01) != 0;
  out->turbo = out->turbo || (payload[10] & 0x02) != 0;
  out->fahrenheit = (payload[10] & 0x04) != 0;

  bool present = false;
  out->indoor_temperature = parse_temperature(
      payload[11], static_cast<float>(payload[15] & 0x0F) / 10.0f,
      out->fahrenheit, &present);
  out->outdoor_temperature = parse_temperature(
      payload[12], static_cast<float>(payload[15] >> 4) / 10.0f,
      out->fahrenheit, &present);

  // Out-of-range setpoints arrive in an alternate field instead.
  const uint8_t target_alt = payload[13] & 0x1F;
  if (target_alt != 0) {
    out->target_temperature = static_cast<float>(target_alt) + 12.0f;
    if (payload[2] & 0x10) out->target_temperature += 0.5f;
  }

  out->filter_alert = (payload[13] & 0x20) != 0;
  // 0x70 is the one value that means "off"; everything else is a brightness.
  out->display_on = payload[14] != 0x70;
  out->error_code = payload[16];
  if (payload_len >= 20)
    out->target_humidity = static_cast<uint8_t>(payload[19] & 0x7F);
  if (payload_len >= 22 && payload[21] != 0) {
    out->indoor_humidity = static_cast<float>(payload[21]);
    out->indoor_humidity_valid = true;
  }

  out->beep = false;  // never echoed back; we always send it off
  out->valid = true;
  return true;
}

// --- layer 2: 0x5A5A packet -------------------------------------------------

void make_lan_timestamp(int year, int month, int day, int hour, int minute,
                        int second, int centisecond, uint8_t out[8]) {
  out[0] = static_cast<uint8_t>(centisecond);
  out[1] = static_cast<uint8_t>(second);
  out[2] = static_cast<uint8_t>(minute);
  out[3] = static_cast<uint8_t>(hour);
  out[4] = static_cast<uint8_t>(day);
  out[5] = static_cast<uint8_t>(month);
  out[6] = static_cast<uint8_t>(year % 100);
  out[7] = static_cast<uint8_t>(year / 100);
}

Bytes encode_packet(uint64_t device_id, const Bytes &frame,
                    const uint8_t timestamp[8]) {
  const Bytes encrypted = aes_ecb_encrypt_padded(frame);
  const size_t length = 40 + encrypted.size() + 16;

  Bytes packet;
  packet.reserve(length);
  packet.push_back(0x5A);
  packet.push_back(0x5A);
  packet.push_back(0x01);
  packet.push_back(0x11);
  packet.push_back(static_cast<uint8_t>(length & 0xFF));   // little endian
  packet.push_back(static_cast<uint8_t>(length >> 8));
  packet.push_back(0x20);
  packet.push_back(0x00);
  packet.insert(packet.end(), 4, 0x00);                    // message id
  packet.insert(packet.end(), timestamp, timestamp + 8);
  for (int i = 0; i < 8; i++)                              // device id, LE
    packet.push_back(static_cast<uint8_t>((device_id >> (8 * i)) & 0xFF));
  packet.insert(packet.end(), 12, 0x00);
  packet.insert(packet.end(), encrypted.begin(), encrypted.end());

  const Bytes digest = sign(packet);
  packet.insert(packet.end(), digest.begin(), digest.end());
  return packet;
}

bool decode_packet(const Bytes &packet, Bytes *frame_out) {
  if (packet.size() < 56 || packet[0] != 0x5A || packet[1] != 0x5A)
    return false;
  const size_t length =
      static_cast<size_t>(packet[4]) | (static_cast<size_t>(packet[5]) << 8);
  if (length < 56 || packet.size() < length)
    return false;

  const Bytes body(packet.begin(), packet.begin() + length - 16);
  const Bytes rx_digest(packet.begin() + length - 16, packet.begin() + length);
  if (sign(body) != rx_digest)
    return false;

  const Bytes encrypted(packet.begin() + 40, packet.begin() + length - 16);
  Bytes frame = aes_ecb_decrypt_unpadded(encrypted);
  if (frame.empty())
    return false;
  *frame_out = std::move(frame);
  return true;
}

// --- layer 3: 0x8370 envelope -----------------------------------------------
namespace {

Bytes build_envelope_header(size_t length, uint8_t extra) {
  Bytes header;
  header.push_back(0x83);
  header.push_back(0x70);
  put_u16_be(&header, static_cast<uint16_t>(length));
  header.push_back(0x20);
  header.push_back(extra);
  return header;
}

}  // namespace

Bytes encode_handshake_request(uint16_t packet_id, const Bytes &token) {
  Bytes packet = build_envelope_header(token.size(), HANDSHAKE_REQUEST);
  put_u16_be(&packet, packet_id);
  packet.insert(packet.end(), token.begin(), token.end());
  return packet;
}

bool derive_local_key(const Bytes &key, const Bytes &response,
                      Bytes *local_key_out) {
  if (response.size() != 64 || key.size() != 32)
    return false;
  const Bytes payload(response.begin(), response.begin() + 32);
  const Bytes rx_hash(response.begin() + 32, response.end());

  const Bytes decrypted = aes_cbc_decrypt(key, payload);
  if (decrypted.empty() || sha256(decrypted) != rx_hash)
    return false;  // wrong or stale token/key -- the caller must re-pair

  Bytes local_key(32);
  for (size_t i = 0; i < 32; i++) local_key[i] = decrypted[i] ^ key[i];
  *local_key_out = std::move(local_key);
  return true;
}

Bytes encode_encrypted_request(uint16_t packet_id, const Bytes &local_key,
                               const Bytes &data, uint8_t pad_byte) {
  // The 2 byte packet id counts toward 16 byte alignment but not toward the
  // length field -- an easy off-by-two if you go by the header alone.
  const size_t remainder = (data.size() + 2) % 16;
  const size_t pad = remainder != 0 ? 16 - remainder : 0;
  const size_t length = data.size() + pad + 32;

  const Bytes header = build_envelope_header(
      length, static_cast<uint8_t>(pad << 4 | ENCRYPTED_REQUEST));

  Bytes payload;
  put_u16_be(&payload, packet_id);
  payload.insert(payload.end(), data.begin(), data.end());
  payload.insert(payload.end(), pad, pad_byte);

  Bytes to_hash = header;
  to_hash.insert(to_hash.end(), payload.begin(), payload.end());
  const Bytes digest = sha256(to_hash);

  Bytes packet = header;
  const Bytes encrypted = aes_cbc_encrypt(local_key, payload);
  packet.insert(packet.end(), encrypted.begin(), encrypted.end());
  packet.insert(packet.end(), digest.begin(), digest.end());
  return packet;
}

bool decode_encrypted_response(const Bytes &local_key, const Bytes &packet,
                               Bytes *data_out) {
  if (packet.size() < 6 + 16 + 32 || packet[0] != 0x83 || packet[1] != 0x70 ||
      packet[4] != 0x20)
    return false;
  if ((packet[5] & 0x0F) != ENCRYPTED_RESPONSE)
    return false;

  const Bytes header(packet.begin(), packet.begin() + 6);
  const Bytes encrypted(packet.begin() + 6, packet.end() - 32);
  const Bytes rx_hash(packet.end() - 32, packet.end());

  const Bytes decrypted = aes_cbc_decrypt(local_key, encrypted);
  if (decrypted.empty())
    return false;

  Bytes to_hash = header;
  to_hash.insert(to_hash.end(), decrypted.begin(), decrypted.end());
  if (sha256(to_hash) != rx_hash)
    return false;

  const size_t pad = packet[5] >> 4;
  if (decrypted.size() < 2 + pad)
    return false;
  *data_out = Bytes(decrypted.begin() + 2, decrypted.end() - pad);
  return true;
}

Bytes build_toggle_display_frame(bool beep, uint8_t message_id) {
  // Oddly this uses the query frame type even though it changes something.
  return wrap_command(FRAME_TYPE_QUERY,
                      Bytes{
                          0x41,
                          static_cast<uint8_t>(CONTROL_SOURCE | (beep ? 0x40 : 0)),
                          0x00, 0xFF, 0x02,
                          0x00, 0x02, 0x00, 0x00,
                          0x00, 0x00, 0x00, 0x00,
                          0x00, 0x00, 0x00, 0x00,
                          0x00, 0x00, 0x00, 0x00,
                      },
                      message_id);
}

}  // namespace coolth
