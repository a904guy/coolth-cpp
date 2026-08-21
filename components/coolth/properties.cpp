#include "properties.h"

namespace coolth {
namespace {

constexpr uint8_t FRAME_TYPE_CONTROL = 0x02;
constexpr uint8_t FRAME_TYPE_QUERY = 0x03;
constexpr uint8_t REQUEST_GET_PROPERTIES = 0xB1;
constexpr uint8_t REQUEST_SET_PROPERTIES = 0xB0;
constexpr uint8_t RESPONSE_PROPERTIES_ACK = 0xB0;
constexpr uint8_t RESPONSE_PROPERTIES = 0xB1;

}  // namespace

bool property_supported(PropertyId id) {
  switch (id) {
    case PROP_BREEZE_AWAY:
    case PROP_BREEZE_CONTROL:
    case PROP_BREEZELESS:
    case PROP_BUZZER:
    case PROP_CASCADE:
    case PROP_FLASH:
    case PROP_FRESH_AIR:
    case PROP_IECO:
    case PROP_OUT_SILENT:
    case PROP_RATE_SELECT:
    case PROP_SELF_CLEAN:
    case PROP_SWING_LR_ANGLE:
    case PROP_SWING_UD_ANGLE:
      return true;
    default:
      return false;
  }
}

Bytes encode_property(PropertyId id, int value) {
  if (!property_supported(id))
    return {};
  switch (id) {
    case PROP_BREEZE_AWAY:
      // 2 is on, 1 is off. Zero is not a valid value for this one.
      return Bytes{static_cast<uint8_t>(value ? 2 : 1)};
    case PROP_CASCADE:
      // First byte is the on/off flag, second is the direction.
      return Bytes{static_cast<uint8_t>(value ? 1 : 0),
                   static_cast<uint8_t>(value)};
    case PROP_FRESH_AIR:
      // Power, fan speed, then a fixed byte.
      return Bytes{static_cast<uint8_t>(value ? 1 : 0),
                   static_cast<uint8_t>(value), 0xFF};
    case PROP_IECO: {
      // A frame byte, the ieco number, the switch, then padding.
      Bytes out{0x00, 0x01, static_cast<uint8_t>(value ? 1 : 0)};
      out.resize(13, 0x00);
      return out;
    }
    case PROP_OUT_SILENT:
      return Bytes{static_cast<uint8_t>(value ? 3 : 0)};
    default:
      return Bytes{static_cast<uint8_t>(value)};
  }
}

int decode_property(PropertyId id, const Bytes &data, bool *ok) {
  *ok = false;
  if (!property_supported(id) || data.empty())
    return 0;
  switch (id) {
    case PROP_BUZZER:
      return 0;  // write-only; the device echoes nothing meaningful
    case PROP_BREEZELESS:
    case PROP_FLASH:
    case PROP_SELF_CLEAN:
      *ok = true;
      return data[0] ? 1 : 0;
    case PROP_BREEZE_AWAY:
      *ok = true;
      return data[0] == 2 ? 1 : 0;
    case PROP_CASCADE:
      if (data.size() < 2)
        return 0;
      *ok = true;
      return data[0] ? data[1] : 0;
    case PROP_FRESH_AIR:
      if (data.size() < 2)
        return 0;
      *ok = true;
      return data[0] ? data[1] : 0;
    case PROP_IECO:
      if (data.size() < 2)
        return 0;
      *ok = true;
      return data[1] ? 1 : 0;
    case PROP_OUT_SILENT:
      *ok = true;
      return data[0] == 3 ? 1 : 0;
    default:
      *ok = true;
      return data[0];
  }
}

namespace {

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

Bytes build_get_properties_frame(const std::vector<PropertyId> &ids,
                                 uint8_t message_id) {
  Bytes payload{REQUEST_GET_PROPERTIES, static_cast<uint8_t>(ids.size())};
  for (PropertyId id : ids) {
    payload.push_back(static_cast<uint8_t>(id & 0xFF));  // little endian
    payload.push_back(static_cast<uint8_t>(id >> 8));
  }
  return wrap(FRAME_TYPE_QUERY, payload, message_id);
}

Bytes build_set_properties_frame(const std::map<PropertyId, int> &values,
                                 uint8_t message_id) {
  Bytes payload{REQUEST_SET_PROPERTIES, static_cast<uint8_t>(values.size())};
  for (const auto &entry : values) {
    payload.push_back(static_cast<uint8_t>(entry.first & 0xFF));
    payload.push_back(static_cast<uint8_t>(entry.first >> 8));
    const Bytes encoded = encode_property(entry.first, entry.second);
    payload.push_back(static_cast<uint8_t>(encoded.size()));
    payload.insert(payload.end(), encoded.begin(), encoded.end());
  }
  return wrap(FRAME_TYPE_CONTROL, payload, message_id);
}

bool parse_properties_frame(const Bytes &frame,
                            std::map<PropertyId, int> *out) {
  if (frame.size() < 10 + 2 + 1 || frame[0] != 0xAA)
    return false;
  const uint8_t *payload = frame.data() + 10;
  const size_t payload_len = frame.size() - 10 - 1;
  if (payload[0] != RESPONSE_PROPERTIES && payload[0] != RESPONSE_PROPERTIES_ACK)
    return false;

  const uint8_t count = payload[1];
  size_t pos = 2;
  for (uint8_t i = 0; i < count; i++) {
    if (pos + 4 > payload_len)
      break;
    const uint16_t raw_id =
        static_cast<uint16_t>(payload[pos] | (payload[pos + 1] << 8));
    const uint8_t flags = payload[pos + 2];
    const uint8_t size = payload[pos + 3];

    // A zero-length entry is the device saying "I have nothing for this".
    if (size == 0) {
      pos += 4;
      continue;
    }
    if (pos + 4 + size > payload_len)
      break;

    const PropertyId id = static_cast<PropertyId>(raw_id);
    // Bit 4 means the device rejected it. Recording the value anyway would
    // report a setting that never took.
    const bool errored = (flags & 0x10) != 0;
    if (!errored && property_supported(id)) {
      const Bytes data(payload + pos + 4, payload + pos + 4 + size);
      bool ok = false;
      const int value = decode_property(id, data, &ok);
      if (ok)
        (*out)[id] = value;
    }
    pos += 4 + size;
  }
  return true;
}

void apply_properties(const std::map<PropertyId, int> &values, AcState *state) {
  for (const auto &entry : values) {
    switch (entry.first) {
      case PROP_SWING_UD_ANGLE:
        state->vertical_swing_angle = static_cast<uint8_t>(entry.second);
        break;
      case PROP_SWING_LR_ANGLE:
        state->horizontal_swing_angle = static_cast<uint8_t>(entry.second);
        break;
      case PROP_CASCADE:
        state->cascade_mode = static_cast<uint8_t>(entry.second);
        break;
      case PROP_RATE_SELECT:
        state->rate_select = static_cast<uint8_t>(entry.second);
        break;
      case PROP_FRESH_AIR:
        state->fresh_air_fan_speed = static_cast<uint8_t>(entry.second);
        break;
      case PROP_IECO:
        state->ieco = entry.second != 0;
        break;
      case PROP_SELF_CLEAN:
        state->self_clean = entry.second != 0;
        break;
      case PROP_FLASH:
        state->flash = entry.second != 0;
        break;
      case PROP_OUT_SILENT:
        state->out_silent = entry.second != 0;
        break;
      // The three breeze properties are alternative spellings of one setting;
      // whichever the device answers with wins.
      case PROP_BREEZE_CONTROL:
        state->breeze_mode = static_cast<uint8_t>(entry.second);
        break;
      case PROP_BREEZE_AWAY:
        if (entry.second)
          state->breeze_mode = preset::BREEZE_AWAY;
        break;
      case PROP_BREEZELESS:
        if (entry.second)
          state->breeze_mode = preset::BREEZELESS;
        break;
      default:
        break;
    }
  }
}

}  // namespace coolth
