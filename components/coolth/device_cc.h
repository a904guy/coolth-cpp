// Commercial air conditioners (device type 0xCC).
//
// A different appliance family with its own command set, sharing only the
// outer framing and transport with the 0xAC units. Watch for two reversals
// against everything else in this library: control ids are big-endian here,
// and each control value is followed by a 0xFF terminator.
#pragma once

#include <cstdint>
#include <map>
#include <vector>

#include "protocol.h"

namespace coolth {

enum ControlId : uint16_t {
  CC_POWER = 0x0000,
  CC_TARGET_TEMPERATURE = 0x0003,
  CC_TEMPERATURE_UNIT = 0x000C,
  CC_TARGET_HUMIDITY = 0x000F,
  CC_MODE = 0x0012,
  CC_FAN_SPEED = 0x0015,
  CC_VERT_SWING_ANGLE = 0x001C,
  CC_HORZ_SWING_ANGLE = 0x001E,
  CC_WIND_SENSE = 0x0020,
  CC_ECO = 0x0028,
  CC_SILENT = 0x002A,
  CC_SLEEP = 0x002C,
  CC_SELF_CLEAN = 0x002E,
  CC_PURIFIER = 0x003A,
  CC_BEEP = 0x003F,
  CC_DISPLAY = 0x0040,
  CC_AUX_MODE = 0x0043,
};

struct CcState {
  bool power = false;
  float target_temperature = 24.0f;
  float indoor_temperature = 0.0f;
  float outdoor_temperature = 0.0f;
  bool outdoor_temperature_valid = false;
  bool fahrenheit = false;
  uint8_t target_humidity = 40;
  uint8_t indoor_humidity = 0;
  bool indoor_humidity_valid = false;
  uint8_t mode = 0;
  uint8_t fan_speed = 0;
  uint8_t vert_swing_angle = 0;
  uint8_t horz_swing_angle = 0;
  uint8_t wind_sense = 0;  // 0 close, 1 follow, 2 avoid, 3 soft, 4 strong
  bool eco = false;
  bool silent = false;
  bool sleep = false;
  uint8_t purifier = 0;  // 0 auto, 1 on, 2 off
  bool beep = false;
  bool display = false;
  uint8_t aux_mode = 0;  // 0 auto, 1 on, 2 off, 4 separate
  bool valid = false;

  // Filled in by parse_cc_capabilities, which reads the same payload.
  float target_temperature_min = 17.0f;
  float target_temperature_max = 30.0f;
  bool supports_humidity = false;
  std::vector<uint8_t> supported_modes;
  bool supports_fan_speed = false;
  bool supports_vert_swing_angle = false;
  bool supports_horz_swing_angle = false;
  bool supports_wind_sense = false;
  bool supports_co2_level = false;
  bool supports_eco = false;
  bool supports_silent = false;
  bool supports_sleep = false;
  bool supports_self_clean = false;
  bool supports_purifier = false;
  bool supports_purifier_auto = false;
  bool supports_filter_level = false;
  std::vector<uint8_t> supported_aux_modes;
};

// Only the temperature is scaled; every other control is a raw byte.
Bytes encode_control(ControlId id, float value);
float decode_control(ControlId id, const Bytes &data, bool *ok);

Bytes build_cc_query_frame(uint8_t message_id);
Bytes build_cc_control_frame(const std::map<ControlId, float> &controls,
                             uint8_t message_id);

bool parse_cc_query_frame(const Bytes &frame, CcState *out);
// Capabilities share the query payload rather than having their own command.
bool parse_cc_capabilities(const Bytes &frame, CcState *out);
bool parse_cc_control_frame(const Bytes &frame,
                            std::map<ControlId, float> *out);

}  // namespace coolth
