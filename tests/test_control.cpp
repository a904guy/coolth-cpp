// The full control surface: display toggle, the property channel that carries
// everything the state frame has no room for, and capability discovery.

#include <map>
#include <vector>

#include "../components/coolth/capabilities.h"
#include "../components/coolth/properties.h"
#include "golden_vectors.h"
#include "harness.h"

using namespace coolth;

static int decode(PropertyId id, const char *hex) {
  bool ok = false;
  const int value = decode_property(id, from_hex(hex), &ok);
  return ok ? value : -1;
}

static Bytes ac_response(const std::string &body) {
  return make_response(body, 0xAC, 0x03);
}

int main() {
  printf("display toggle\n");
  expect_hex("toggle frame", build_toggle_display_frame(true, GOLDEN_MESSAGE_ID),
             GOLDEN_TOGGLE_DISPLAY_FRAME);

  printf("\nproperty frames\n");
  {
    expect_hex("get properties",
               build_get_properties_frame(
                   {PROP_SWING_UD_ANGLE, PROP_BREEZE_CONTROL, PROP_RATE_SELECT},
                   GOLDEN_MESSAGE_ID),
               GOLDEN_GET_PROPERTIES_FRAME);

    const std::map<PropertyId, int> values = {
        {PROP_SWING_UD_ANGLE, 50}, {PROP_BREEZE_AWAY, 1},
        {PROP_CASCADE, 2},         {PROP_FRESH_AIR, 60},
        {PROP_OUT_SILENT, 1},
    };
    expect_hex("set properties",
               build_set_properties_frame(values, GOLDEN_MESSAGE_ID),
               GOLDEN_SET_PROPERTIES_FRAME);
  }

  printf("\nproperty encodings\n");
  {
    expect_hex("swing angle", encode_property(PROP_SWING_UD_ANGLE, 50),
               GOLDEN_PROP_ENCODE_SWING_UD);
    // These do not encode as a plain byte, which is where a port goes wrong
    // quietly: the frame stays well formed and the setting does nothing.
    expect_hex("breeze away on", encode_property(PROP_BREEZE_AWAY, 1),
               GOLDEN_PROP_ENCODE_BREEZE_AWAY_ON);
    expect_hex("breeze away off", encode_property(PROP_BREEZE_AWAY, 0),
               GOLDEN_PROP_ENCODE_BREEZE_AWAY_OFF);
    expect_hex("cascade", encode_property(PROP_CASCADE, 2),
               GOLDEN_PROP_ENCODE_CASCADE);
    expect_hex("fresh air", encode_property(PROP_FRESH_AIR, 60),
               GOLDEN_PROP_ENCODE_FRESH_AIR);
    expect_hex("fresh air off", encode_property(PROP_FRESH_AIR, 0),
               GOLDEN_PROP_ENCODE_FRESH_AIR_OFF);
    expect_hex("out silent on", encode_property(PROP_OUT_SILENT, 1),
               GOLDEN_PROP_ENCODE_OUT_SILENT_ON);
    expect_hex("out silent off", encode_property(PROP_OUT_SILENT, 0),
               GOLDEN_PROP_ENCODE_OUT_SILENT_OFF);
    expect_hex("rate select", encode_property(PROP_RATE_SELECT, 75),
               GOLDEN_PROP_ENCODE_RATE_SELECT);
    expect_hex("self clean", encode_property(PROP_SELF_CLEAN, 1),
               GOLDEN_PROP_ENCODE_SELF_CLEAN);
    expect_true("unsupported property encodes to nothing",
                encode_property(PROP_ANION, 1).empty());
  }

  printf("\nproperty decodings\n");
  {
    expect_int("cascade on", decode(PROP_CASCADE, "0102"),
               GOLDEN_PROP_DECODE_CASCADE_ON);
    expect_int("cascade off", decode(PROP_CASCADE, "0002"),
               GOLDEN_PROP_DECODE_CASCADE_OFF);
    expect_int("fresh air on", decode(PROP_FRESH_AIR, "013cff"),
               GOLDEN_PROP_DECODE_FRESH_AIR_ON);
    expect_int("fresh air off", decode(PROP_FRESH_AIR, "003cff"),
               GOLDEN_PROP_DECODE_FRESH_AIR_OFF);
    expect_int("breeze away on", decode(PROP_BREEZE_AWAY, "02"),
               GOLDEN_PROP_DECODE_BREEZE_AWAY_ON);
    expect_int("breeze away off", decode(PROP_BREEZE_AWAY, "01"),
               GOLDEN_PROP_DECODE_BREEZE_AWAY_OFF);
    expect_int("out silent on", decode(PROP_OUT_SILENT, "03"),
               GOLDEN_PROP_DECODE_OUT_SILENT_ON);
    expect_int("ieco on", decode(PROP_IECO, "0101"), GOLDEN_PROP_DECODE_IECO_ON);
    expect_int("ieco off", decode(PROP_IECO, "0100"), GOLDEN_PROP_DECODE_IECO_OFF);
    expect_int("swing angle", decode(PROP_SWING_UD_ANGLE, "32"),
               GOLDEN_PROP_DECODE_SWING_UD);

    bool ok = true;
    decode_property(PROP_CASCADE, from_hex("01"), &ok);
    expect_true("truncated data is refused, not half-read", !ok);
    ok = true;
    decode_property(PROP_ANION, from_hex("01"), &ok);
    expect_true("unsupported property is refused", !ok);
  }

  printf("\nproperties response\n");
  {
    // Each entry is: id (2, little endian), flags, length, then data.
    // 0x0009 = swing angle, 0x0048 = rate select.
    // id(2) + flags(1) + length(1) + data(length) -- a four byte header, one
    // more than the capability channel uses.
    const std::string swing_50 = "0900" "00" "01" "32";
    const std::string rate_75 = "4800" "00" "01" "4b";

    std::map<PropertyId, int> values;
    expect_true("two properties parse",
                parse_properties_frame(ac_response("b102" + swing_50 + rate_75),
                                       &values));
    expect_int("count", (long) values.size(), 2);
    expect_int("swing angle", values[PROP_SWING_UD_ANGLE], 50);
    expect_int("rate select", values[PROP_RATE_SELECT], 75);

    // Flags bit 4 means the device rejected it. Reporting the value anyway
    // would show a setting that never took effect.
    values.clear();
    parse_properties_frame(ac_response("b101" "0900" "10" "01" "32"), &values);
    expect_int("errored property omitted", (long) values.size(), 0);

    // Zero length: the device has nothing to say about that one.
    values.clear();
    parse_properties_frame(ac_response("b102" "0900" "00" "00" + rate_75), &values);
    expect_true("empty property skipped",
                values.find(PROP_SWING_UD_ANGLE) == values.end());
    expect_int("later property still read", values[PROP_RATE_SELECT], 75);

    // An unknown id must be stepped over using its declared length, not
    // abandoned -- otherwise one firmware addition blinds the whole read.
    values.clear();
    parse_properties_frame(ac_response("b102" "ffff" "00" "02" "0102" + rate_75),
                           &values);
    expect_int("unknown id skipped, later ones still read",
               values[PROP_RATE_SELECT], 75);

    // A length running past the end of the frame must stop the walk rather
    // than read whatever follows in memory.
    values.clear();
    expect_true("overlong length is contained",
                parse_properties_frame(ac_response("b101" "0900" "00" "40" "32"),
                                       &values));
    expect_int("nothing invented from truncated data", (long) values.size(), 0);

    values.clear();
    expect_true("state response rejected",
                !parse_properties_frame(ac_response("c001486600"), &values));
  }

  printf("\nfolding properties into state\n");
  {
    AcState state;
    apply_properties({{PROP_SWING_UD_ANGLE, 50},
                      {PROP_RATE_SELECT, 75},
                      {PROP_FRESH_AIR, 60},
                      {PROP_BREEZELESS, 1}},
                     &state);
    expect_int("vertical angle", state.vertical_swing_angle, 50);
    expect_int("rate select", state.rate_select, 75);
    expect_int("fresh air", state.fresh_air_fan_speed, 60);
    expect_int("breeze mode from breezeless", state.breeze_mode,
               preset::BREEZELESS);
  }

  printf("\ncapabilities\n");
  {
    expect_hex("query", build_get_capabilities_frame(false, GOLDEN_MESSAGE_ID),
               GOLDEN_GET_CAPABILITIES_FRAME);
    expect_hex("additional query",
               build_get_capabilities_frame(true, GOLDEN_MESSAGE_ID),
               GOLDEN_GET_CAPABILITIES_ADDITIONAL_FRAME);

    // A response captured from a real Cooper & Hunter unit, checked field by
    // field against what coolth derives from the same bytes.
    Capabilities caps;
    expect_true("live response parses",
                parse_capabilities_frame(from_hex(GOLDEN_LIVE_CAPABILITIES_FRAME),
                                         &caps));
    expect_int("eco", caps.eco, GOLDEN_LIVE_CAP_ECO);
    expect_int("freeze protection", caps.freeze_protection,
               GOLDEN_LIVE_CAP_FREEZE_PROTECTION);
    expect_int("heat mode", caps.heat_mode, GOLDEN_LIVE_CAP_HEAT_MODE);
    expect_int("cool mode", caps.cool_mode, GOLDEN_LIVE_CAP_COOL_MODE);
    expect_int("dry mode", caps.dry_mode, GOLDEN_LIVE_CAP_DRY_MODE);
    expect_int("auto mode", caps.auto_mode, GOLDEN_LIVE_CAP_AUTO_MODE);
    expect_int("aux heat mode", caps.aux_heat_mode, GOLDEN_LIVE_CAP_AUX_HEAT_MODE);
    expect_int("aux mode", caps.aux_mode, GOLDEN_LIVE_CAP_AUX_MODE);
    expect_int("swing horizontal", caps.swing_horizontal,
               GOLDEN_LIVE_CAP_SWING_HORIZONTAL);
    expect_int("swing vertical", caps.swing_vertical,
               GOLDEN_LIVE_CAP_SWING_VERTICAL);
    expect_int("energy stats", caps.energy_stats, GOLDEN_LIVE_CAP_ENERGY_STATS);
    expect_int("filter notice", caps.filter_notice, GOLDEN_LIVE_CAP_FILTER_NOTICE);
    expect_int("turbo heat", caps.turbo_heat, GOLDEN_LIVE_CAP_TURBO_HEAT);
    expect_int("turbo cool", caps.turbo_cool, GOLDEN_LIVE_CAP_TURBO_COOL);
    expect_int("additional flag", caps.additional_capabilities,
               GOLDEN_LIVE_CAPABILITIES_ADDITIONAL);

    // This unit reports nothing about its fan, so the fallback decides: the
    // common four are assumed, silent is not.
    expect_int("fan silent", caps.supports_fan_silent(), GOLDEN_LIVE_CAP_FAN_SILENT);
    expect_int("fan low", caps.supports_fan_low(), GOLDEN_LIVE_CAP_FAN_LOW);
    expect_int("fan medium", caps.supports_fan_medium(), GOLDEN_LIVE_CAP_FAN_MEDIUM);
    expect_int("fan high", caps.supports_fan_high(), GOLDEN_LIVE_CAP_FAN_HIGH);
    expect_int("fan auto", caps.supports_fan_auto(), GOLDEN_LIVE_CAP_FAN_AUTO);
  }

  printf("\ncapability edge cases\n");
  {
    // Temperature limits: six half-degree bytes, then a decimals flag.
    Capabilities caps;
    parse_capabilities_frame(ac_response("b501" "2502" "07" "203c203c203c01"),
                             &caps);
    expect_true("cool min 16C", caps.cool_min_temperature == 16.0f);
    expect_true("cool max 30C", caps.cool_max_temperature == 30.0f);
    expect_true("heat max 30C", caps.heat_max_temperature == 30.0f);
    expect_int("decimals", caps.decimals, 1);

    // A short temperature capability must be ignored, not half-applied.
    Capabilities partial;
    parse_capabilities_frame(ac_response("b501" "2502" "03" "203c20"), &partial);
    expect_true("short temperatures leaves defaults",
                partial.cool_min_temperature == 16.0f &&
                    partial.cool_max_temperature == 30.0f);

    // Fahrenheit is inverted: 0 means the unit can show it.
    Capabilities f;
    parse_capabilities_frame(ac_response("b501" "2202" "01" "00"), &f);
    expect_int("fahrenheit when value is 0", f.fahrenheit, 1);
    Capabilities f2;
    parse_capabilities_frame(ac_response("b501" "2202" "01" "01"), &f2);
    expect_int("no fahrenheit when value is 1", f2.fahrenheit, 0);

    // A device that does report fan capability is taken at its word.
    Capabilities fan_caps;
    parse_capabilities_frame(ac_response("b501" "1002" "01" "06"), &fan_caps);
    expect_int("fan silent from capability", fan_caps.supports_fan_silent(), 1);
    expect_int("fan medium from capability", fan_caps.supports_fan_medium(), 1);

    // Custom fan speed implies every named speed.
    Capabilities custom;
    parse_capabilities_frame(ac_response("b501" "1002" "01" "01"), &custom);
    expect_int("custom implies silent", custom.supports_fan_silent(), 1);

    Capabilities unknown;
    parse_capabilities_frame(
        ac_response("b502" "ffff" "02" "0102" "1202" "01" "01"), &unknown);
    expect_int("later capability still read", unknown.eco, 1);

    Capabilities ignored;
    expect_true("non-capability response rejected",
                !parse_capabilities_frame(ac_response("c00148"), &ignored));
  }

  return report();
}
