// The property channel: 0xB1 to read, 0xB0 to write.
//
// Everything Midea added after the original state frame ran out of room lives
// here instead -- swing angles, the breeze modes, rate select, fresh air. Each
// property is a 16 bit id with a short, per-property payload, so the encoding
// rules are specific to each one rather than uniform.
#pragma once

#include <cstdint>
#include <map>
#include <vector>

#include "protocol.h"

namespace coolth {

enum PropertyId : uint16_t {
  PROP_SWING_UD_ANGLE = 0x0009,
  PROP_SWING_LR_ANGLE = 0x000A,
  PROP_INDOOR_HUMIDITY = 0x0015,
  PROP_BREEZELESS = 0x0018,
  PROP_BUZZER = 0x001A,
  PROP_SELF_CLEAN = 0x0039,
  PROP_BREEZE_AWAY = 0x0042,
  PROP_BREEZE_CONTROL = 0x0043,
  PROP_RATE_SELECT = 0x0048,
  PROP_FRESH_AIR = 0x004B,
  PROP_CASCADE = 0x0059,
  PROP_FLASH = 0x0067,
  PROP_OUT_SILENT = 0x00CD,
  PROP_IECO = 0x00E3,
  PROP_ANION = 0x021E,
};

// True for the properties whose encoding is known. The others are recognised
// so they can be skipped cleanly, but sending one would be a guess.
bool property_supported(PropertyId id);

// Turn a logical value into the bytes that property expects. Returns empty for
// an unsupported id.
Bytes encode_property(PropertyId id, int value);
// The inverse. `ok` is set false if the id is unsupported or the data is short.
int decode_property(PropertyId id, const Bytes &data, bool *ok);

Bytes build_get_properties_frame(const std::vector<PropertyId> &ids,
                                 uint8_t message_id);
Bytes build_set_properties_frame(const std::map<PropertyId, int> &values,
                                 uint8_t message_id);

// Decoded values from a properties response. Properties the device reported an
// error for, or that carried no data, are left out rather than guessed at.
bool parse_properties_frame(const Bytes &frame,
                            std::map<PropertyId, int> *out);

// Fold a properties response into the state struct, for the fields the state
// frame does not carry.
void apply_properties(const std::map<PropertyId, int> &values, AcState *state);

}  // namespace coolth
