// What a particular appliance can actually do.
//
// Midea sells one protocol across a wide range of hardware, so most of the
// command surface is optional. Querying capabilities first is what stops the
// caller offering a setting the unit will silently ignore -- or reject.
//
// The encoding is a walk of (id, size, value) triples, but the meaning of each
// value is per-capability: some are "1 means yes", others are a set membership
// test over a mode bitmap. Those tables are transcribed from coolth.
#pragma once

#include <cstdint>
#include <string>

#include "protocol.h"

namespace coolth {

enum CapabilityId : uint16_t {
  CAP_SWING_UD_ANGLE = 0x0009,
  CAP_SWING_LR_ANGLE = 0x000A,
  CAP_BREEZELESS = 0x0018,
  CAP_SMART_EYE = 0x0030,
  CAP_WIND_ON_ME = 0x0032,
  CAP_WIND_OFF_ME = 0x0033,
  CAP_SELF_CLEAN = 0x0039,
  CAP_UNKNOWN = 0x0040,
  CAP_BREEZE_AWAY = 0x0042,
  CAP_BREEZE_CONTROL = 0x0043,
  CAP_RATE_SELECT = 0x0048,
  CAP_FRESH_AIR = 0x004B,
  CAP_CASCADE = 0x0059,
  CAP_FLASH = 0x0067,
  CAP_AUX_FAN_SPEED_CONTROL = 0x0093,
  CAP_AUX_HEAT_FAN_SPEED_CONTROL = 0x0094,
  CAP_OUT_SILENT = 0x00CD,
  CAP_PRESET_IECO = 0x00E3,
  CAP_FAN_SPEED_CONTROL = 0x0210,
  CAP_PRESET_ECO = 0x0212,
  CAP_PRESET_FREEZE_PROTECTION = 0x0213,
  CAP_MODES = 0x0214,
  CAP_SWING_MODES = 0x0215,
  CAP_ENERGY = 0x0216,
  CAP_FILTER_REMIND = 0x0217,
  CAP_AUX_ELECTRIC_HEAT = 0x0219,
  CAP_PRESET_TURBO = 0x021A,
  CAP_ANION = 0x021E,
  CAP_HUMIDITY = 0x021F,
  CAP_FAHRENHEIT = 0x0222,
  CAP_DISPLAY_CONTROL = 0x0224,
  CAP_TEMPERATURES = 0x0225,
  CAP_BUZZER = 0x022C,
};

struct Capabilities {
  bool anion = false;
  bool aux_electric_heat = false;
  bool aux_fan_speed = false;
  bool aux_heat_fan_speed = false;
  bool breeze_away = false;
  bool breeze_control = false;
  bool breezeless = false;
  bool buzzer = false;
  bool cascade = false;
  bool display_control = false;
  bool energy_stats = false;
  bool energy_setting = false;
  bool energy_bcd = false;
  bool fahrenheit = false;
  bool filter_notice = false;
  bool filter_clean = false;
  bool flash = false;
  bool fresh_air = false;
  bool humidity_auto_set = false;
  bool humidity_manual_set = false;
  bool out_silent = false;
  bool eco = false;
  bool freeze_protection = false;
  uint8_t ieco = 0;
  uint8_t ieco_end = 0;
  bool turbo_heat = false;
  bool turbo_cool = false;
  bool rate_select_2_level = false;
  bool rate_select_5_level = false;
  bool self_clean = false;
  bool smart_eye = false;
  bool swing_horizontal_angle = false;
  bool swing_vertical_angle = false;
  bool swing_horizontal = false;
  bool swing_vertical = false;
  bool wind_off_me = false;
  bool wind_on_me = false;

  // Modes
  bool heat_mode = false;
  bool cool_mode = false;
  bool dry_mode = false;
  bool auto_mode = false;
  bool aux_heat_mode = false;
  bool aux_mode = false;

  // Fan speeds. Read them through supports_fan_* rather than directly: a unit
  // that reports no fan capability at all still supports the common four.
  bool fan_silent = false;
  bool fan_low = false;
  bool fan_medium = false;
  bool fan_high = false;
  bool fan_auto = false;
  bool fan_custom = false;
  bool any_fan_capability = false;

  // Per-mode limits, in Celsius. The defaults are what a unit that does not
  // report the capability is assumed to accept.
  float cool_min_temperature = 16.0f;
  float cool_max_temperature = 30.0f;
  float auto_min_temperature = 16.0f;
  float auto_max_temperature = 30.0f;
  float heat_min_temperature = 16.0f;
  float heat_max_temperature = 30.0f;
  bool decimals = false;

  // The device has more to say; query again with additional = true.
  bool additional_capabilities = false;

  bool supports_fan_silent() const;
  bool supports_fan_low() const;
  bool supports_fan_medium() const;
  bool supports_fan_high() const;
  bool supports_fan_auto() const;
};

Bytes build_get_capabilities_frame(bool additional, uint8_t message_id);

// Accumulates into `out` rather than clearing it, so the reply to the
// additional query can be folded into the same struct -- which is what
// coolth's merge() does.
bool parse_capabilities_frame(const Bytes &frame, Capabilities *out);

}  // namespace coolth
