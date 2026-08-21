#include "capabilities.h"

#include <initializer_list>

namespace coolth {
namespace {

constexpr uint8_t FRAME_TYPE_QUERY = 0x03;
constexpr uint8_t REQUEST_CAPABILITIES = 0xB5;
constexpr uint8_t RESPONSE_CAPABILITIES = 0xB5;

bool in(uint8_t value, std::initializer_list<uint8_t> set) {
  for (uint8_t item : set)
    if (item == value)
      return true;
  return false;
}

uint8_t frame_checksum(const Bytes &data) {
  uint32_t sum = 0;
  for (size_t i = 1; i < data.size(); i++) sum += data[i];
  return static_cast<uint8_t>((~sum + 1) & 0xFF);
}

Bytes wrap(uint8_t frame_type, Bytes payload, uint8_t message_id) {
  payload.push_back(message_id);
  payload.push_back(crc8(payload.data(), payload.size()));

  Bytes frame(10, 0);
  frame[0] = 0xAA;
  frame[1] = static_cast<uint8_t>(payload.size() + 10);
  frame[2] = 0xAC;
  frame[9] = frame_type;
  frame.insert(frame.end(), payload.begin(), payload.end());
  frame.push_back(frame_checksum(frame));
  return frame;
}

}  // namespace

bool Capabilities::supports_fan_silent() const {
  // A unit that reported nothing about its fan is assumed to do the usual
  // four. One that reported anything is taken at its word.
  if (!this->any_fan_capability)
    return false;
  return this->fan_silent || this->fan_custom;
}
bool Capabilities::supports_fan_low() const {
  if (!this->any_fan_capability)
    return true;
  return this->fan_low || this->fan_custom;
}
bool Capabilities::supports_fan_medium() const {
  if (!this->any_fan_capability)
    return true;
  return this->fan_medium || this->fan_custom;
}
bool Capabilities::supports_fan_high() const {
  if (!this->any_fan_capability)
    return true;
  return this->fan_high || this->fan_custom;
}
bool Capabilities::supports_fan_auto() const {
  if (!this->any_fan_capability)
    return true;
  return this->fan_auto || this->fan_custom;
}

Bytes build_get_capabilities_frame(bool additional, uint8_t message_id) {
  const Bytes payload = additional
                            ? Bytes{REQUEST_CAPABILITIES, 0x01, 0x01, 0x01}
                            : Bytes{REQUEST_CAPABILITIES, 0x01, 0x00};
  return wrap(FRAME_TYPE_QUERY, payload, message_id);
}

bool parse_capabilities_frame(const Bytes &frame, Capabilities *out) {
  if (frame.size() < 10 + 2 + 1 || frame[0] != 0xAA)
    return false;
  const uint8_t *payload = frame.data() + 10;
  const size_t payload_len = frame.size() - 10 - 1;
  if (payload[0] != RESPONSE_CAPABILITIES)
    return false;

  const uint8_t count = payload[1];
  size_t pos = 2;
  for (uint8_t i = 0; i < count; i++) {
    // Note the header here is 3 bytes, not the 4 the property channel uses.
    if (pos + 3 > payload_len)
      break;
    const uint16_t id =
        static_cast<uint16_t>(payload[pos] | (payload[pos + 1] << 8));
    const uint8_t size = payload[pos + 2];
    if (size == 0) {
      pos += 3;
      continue;
    }
    if (pos + 3 + size > payload_len)
      break;

    const uint8_t *value = payload + pos + 3;
    const uint8_t v0 = value[0];

    switch (id) {
      case CAP_ANION: out->anion = v0 == 1; break;
      case CAP_AUX_ELECTRIC_HEAT: out->aux_electric_heat = v0 == 1; break;
      case CAP_AUX_FAN_SPEED_CONTROL: out->aux_fan_speed = v0 == 1; break;
      case CAP_AUX_HEAT_FAN_SPEED_CONTROL: out->aux_heat_fan_speed = v0 == 1; break;
      case CAP_BREEZE_AWAY: out->breeze_away = v0 == 1; break;
      case CAP_BREEZE_CONTROL: out->breeze_control = v0 == 1; break;
      case CAP_BREEZELESS: out->breezeless = v0 == 1; break;
      case CAP_BUZZER: out->buzzer = v0 == 1; break;
      case CAP_CASCADE: out->cascade = v0 == 1; break;
      case CAP_DISPLAY_CONTROL: out->display_control = in(v0, {1, 2, 100}); break;
      case CAP_ENERGY:
        out->energy_stats = in(v0, {2, 3, 4, 5});
        out->energy_setting = in(v0, {3, 5});
        out->energy_bcd = in(v0, {2, 3});
        break;
      // Note the inversion: 0 means the unit can display Fahrenheit.
      case CAP_FAHRENHEIT: out->fahrenheit = v0 == 0; break;
      case CAP_FAN_SPEED_CONTROL:
        out->any_fan_capability = true;
        out->fan_silent = in(v0, {6, 9});
        out->fan_low = in(v0, {3, 4, 5, 6, 7, 9});
        out->fan_medium = in(v0, {5, 6, 7});
        out->fan_high = in(v0, {3, 4, 5, 6, 7, 9});
        out->fan_auto = in(v0, {4, 5, 6, 9});
        out->fan_custom = v0 == 1;
        break;
      case CAP_FILTER_REMIND:
        out->filter_notice = in(v0, {1, 2, 4});
        out->filter_clean = in(v0, {3, 4});
        break;
      case CAP_FLASH: out->flash = in(v0, {1, 2, 3, 4}); break;
      case CAP_FRESH_AIR: out->fresh_air = v0 == 1; break;
      case CAP_HUMIDITY:
        out->humidity_auto_set = in(v0, {1, 2});
        out->humidity_manual_set = in(v0, {2, 3});
        break;
      case CAP_MODES:
        out->heat_mode = in(v0, {1, 2, 4, 6, 7, 9, 10, 11, 12, 13});
        out->cool_mode = in(v0, {0, 1, 3, 4, 5, 6, 7, 8, 9, 11, 13, 14, 15});
        out->dry_mode = in(v0, {0, 1, 5, 6, 9, 11, 13, 14, 15});
        out->auto_mode = in(v0, {0, 1, 2, 7, 8, 9, 13, 14});
        out->aux_heat_mode = v0 == 9;
        out->aux_mode = in(v0, {9, 10, 11, 13, 14, 15});
        break;
      case CAP_OUT_SILENT: out->out_silent = in(v0, {1, 3}); break;
      case CAP_PRESET_ECO: out->eco = in(v0, {1, 2}); break;
      case CAP_PRESET_FREEZE_PROTECTION: out->freeze_protection = v0 == 1; break;
      case CAP_PRESET_IECO:
        out->ieco = v0;
        if (size > 1)
          out->ieco_end = value[1];
        break;
      case CAP_PRESET_TURBO:
        out->turbo_heat = in(v0, {1, 3});
        out->turbo_cool = in(v0, {0, 1});
        break;
      case CAP_RATE_SELECT:
        out->rate_select_2_level = v0 == 1;
        out->rate_select_5_level = in(v0, {2, 3});
        break;
      case CAP_SELF_CLEAN: out->self_clean = v0 == 1; break;
      case CAP_SMART_EYE: out->smart_eye = v0 == 1; break;
      case CAP_SWING_LR_ANGLE: out->swing_horizontal_angle = v0 == 1; break;
      case CAP_SWING_UD_ANGLE: out->swing_vertical_angle = v0 == 1; break;
      case CAP_SWING_MODES:
        out->swing_horizontal = in(v0, {1, 3});
        out->swing_vertical = in(v0, {0, 1});
        break;
      case CAP_WIND_OFF_ME: out->wind_off_me = v0 == 1; break;
      case CAP_WIND_ON_ME: out->wind_on_me = v0 == 1; break;
      case CAP_TEMPERATURES:
        // Six limits at half-degree resolution, plus a decimals flag that
        // lives in a seventh byte when the capability is long enough.
        if (size >= 6) {
          out->cool_min_temperature = value[0] * 0.5f;
          out->cool_max_temperature = value[1] * 0.5f;
          out->auto_min_temperature = value[2] * 0.5f;
          out->auto_max_temperature = value[3] * 0.5f;
          out->heat_min_temperature = value[4] * 0.5f;
          out->heat_max_temperature = value[5] * 0.5f;
          out->decimals = (size > 6 ? value[6] : size) != 0;
        }
        break;
      default:
        // Unknown or unsupported: step over it using its declared length so a
        // firmware we do not recognise does not blind the rest of the walk.
        break;
    }
    pos += 3 + size;
  }

  // A trailing byte says whether a second query would return more.
  if (payload_len > pos + 1)
    out->additional_capabilities = payload[payload_len - 2] != 0;
  return true;
}

}  // namespace coolth
