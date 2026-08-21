#include "device_cc.h"

namespace coolth {
namespace {

constexpr uint8_t DEVICE_TYPE_CC = 0xCC;
constexpr uint8_t FRAME_TYPE_CONTROL = 0x02;
constexpr uint8_t FRAME_TYPE_QUERY = 0x03;

float parse_temperature(uint8_t raw) { return (raw / 2.0f) - 40.0f; }

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
  frame[2] = DEVICE_TYPE_CC;
  frame[9] = frame_type;
  frame.insert(frame.end(), payload.begin(), payload.end());
  frame.push_back(frame_checksum(frame));
  return frame;
}

}  // namespace

Bytes encode_control(ControlId id, float value) {
  if (id == CC_TARGET_TEMPERATURE)
    return Bytes{static_cast<uint8_t>(static_cast<int>(2 * value + 80))};
  return Bytes{static_cast<uint8_t>(static_cast<int>(value))};
}

float decode_control(ControlId id, const Bytes &data, bool *ok) {
  if (data.empty()) {
    *ok = false;
    return 0.0f;
  }
  *ok = true;
  if (id == CC_TARGET_TEMPERATURE)
    return parse_temperature(data[0]);
  return static_cast<float>(data[0]);
}

Bytes build_cc_query_frame(uint8_t message_id) {
  Bytes payload(22, 0);
  payload[0] = 0x01;
  return wrap(FRAME_TYPE_QUERY, payload, message_id);
}

Bytes build_cc_control_frame(const std::map<ControlId, float> &controls,
                             uint8_t message_id) {
  Bytes payload;
  for (const auto &entry : controls) {
    // Big-endian here, unlike the 0xAC property channel.
    payload.push_back(static_cast<uint8_t>(entry.first >> 8));
    payload.push_back(static_cast<uint8_t>(entry.first & 0xFF));
    const Bytes encoded = encode_control(entry.first, entry.second);
    payload.push_back(static_cast<uint8_t>(encoded.size()));
    payload.insert(payload.end(), encoded.begin(), encoded.end());
    payload.push_back(0xFF);  // per-entry terminator
  }
  return wrap(FRAME_TYPE_CONTROL, payload, message_id);
}

bool parse_cc_query_frame(const Bytes &frame, CcState *out) {
  if (frame.size() < 10 + 88 + 1 || frame[0] != 0xAA)
    return false;
  const uint8_t *p = frame.data() + 10;
  // The payload announces itself; without this a control response could be
  // read as state and every offset would be wrong.
  if (p[0] != 0x01 || p[1] != 0xFE)
    return false;

  out->power = p[8] != 0;
  out->target_temperature = parse_temperature(p[11]);
  out->indoor_temperature = ((p[12] << 8) | p[13]) / 10.0f;
  if (p[14] != 0) {
    out->outdoor_temperature = parse_temperature(p[14]);
    out->outdoor_temperature_valid = true;
  }
  out->fahrenheit = p[21] != 0;
  out->target_humidity = p[24];
  if (p[25] != 0xFF) {
    out->indoor_humidity = p[25];
    out->indoor_humidity_valid = true;
  }
  out->mode = p[31];
  out->fan_speed = p[34];
  out->vert_swing_angle = p[41];
  out->horz_swing_angle = p[43];
  out->wind_sense = p[45];
  out->eco = p[56] != 0;
  out->silent = p[58] != 0;
  out->sleep = p[60] != 0;
  out->purifier = p[75];
  out->beep = p[80] != 0;
  out->display = p[81] != 0;
  out->aux_mode = p[87];
  out->valid = true;
  return true;
}

bool parse_cc_capabilities(const Bytes &frame, CcState *out) {
  if (frame.size() < 10 + 88 + 1 || frame[0] != 0xAA)
    return false;
  const uint8_t *p = frame.data() + 10;
  if (p[0] != 0x01 || p[1] != 0xFE)
    return false;

  out->target_temperature_min = parse_temperature(p[9]);
  out->target_temperature_max = parse_temperature(p[10]);
  out->supports_humidity = p[23] != 0;
  out->supported_modes.assign(p + 26, p + 31);
  out->supports_fan_speed = p[32] != 0;
  out->supports_vert_swing_angle = p[40] != 0;
  out->supports_horz_swing_angle = p[42] != 0;
  out->supports_wind_sense = p[44] != 0;
  out->supports_co2_level = p[52] != 0;
  out->supports_eco = p[55] != 0;
  out->supports_silent = p[57] != 0;
  out->supports_sleep = p[59] != 0;
  out->supports_self_clean = p[61] != 0;
  out->supports_purifier = p[73] != 0;
  out->supports_purifier_auto = p[74] != 0;
  out->supports_filter_level = p[78] != 0;
  out->supported_aux_modes.clear();
  if (p[82] != 0)
    out->supported_aux_modes.assign(p + 83, p + 87);
  return true;
}

bool parse_cc_control_frame(const Bytes &frame,
                            std::map<ControlId, float> *out) {
  if (frame.size() < 10 + 6 + 1 || frame[0] != 0xAA)
    return false;
  const uint8_t *p = frame.data() + 10;
  const size_t len = frame.size() - 10 - 1;

  size_t pos = 0;
  // Entries are id (2, big endian), length, value, terminator -- so the step
  // is 4 + size, one more than the value itself accounts for.
  while (pos + 5 <= len) {
    const uint8_t size = p[pos + 2];
    if (size == 0) {
      pos += 5;
      continue;
    }
    if (pos + 4 + size > len)
      break;
    const uint16_t raw_id =
        static_cast<uint16_t>((p[pos] << 8) | p[pos + 1]);
    const ControlId id = static_cast<ControlId>(raw_id);
    const Bytes data(p + pos + 3, p + pos + 3 + size);
    bool ok = false;
    const float value = decode_control(id, data, &ok);
    if (ok)
      (*out)[id] = value;
    pos += 4 + size;
  }
  return true;
}

}  // namespace coolth
