// Commercial (0xCC) appliances: a separate command set sharing only the frame.

#include <map>

#include "../components/coolth/device_cc.h"
#include "golden_vectors.h"
#include "harness.h"

using namespace coolth;

static Bytes cc_response(const std::string &body, uint8_t frame_type) {
  return make_response(body, 0xCC, frame_type);
}

int main() {
  printf("commands\n");
  {
    expect_hex("query", build_cc_query_frame(GOLDEN_MESSAGE_ID),
               GOLDEN_CC_QUERY_FRAME);
    const std::map<ControlId, float> controls = {
        {CC_POWER, 1}, {CC_TARGET_TEMPERATURE, 24.0f},
        {CC_MODE, 2},  {CC_FAN_SPEED, 60},
    };
    expect_hex("control", build_cc_control_frame(controls, GOLDEN_MESSAGE_ID),
               GOLDEN_CC_CONTROL_FRAME);

    // The frame declares 0xCC, not 0xAC. An appliance silently ignores the
    // wrong type rather than refusing it.
    expect_int("device type byte", build_cc_query_frame(GOLDEN_MESSAGE_ID)[2], 0xCC);
  }

  printf("\ncontrol encoding\n");
  {
    // Only the temperature is scaled, and not by the same rule the 0xAC frames
    // use.
    expect_hex("24C", encode_control(CC_TARGET_TEMPERATURE, 24.0f),
               GOLDEN_CC_ENCODE_TEMPERATURE_24);
    expect_hex("17.5C", encode_control(CC_TARGET_TEMPERATURE, 17.5f),
               GOLDEN_CC_ENCODE_TEMPERATURE_17_5);
    expect_hex("power", encode_control(CC_POWER, 1), GOLDEN_CC_ENCODE_POWER);
    expect_hex("mode", encode_control(CC_MODE, 2), GOLDEN_CC_ENCODE_MODE);

    bool ok = false;
    expect_int("temperature decodes",
               (long) (decode_control(CC_TARGET_TEMPERATURE, from_hex("80"), &ok) * 10),
               GOLDEN_CC_DECODE_TEMPERATURE);
    expect_true("decode reports success", ok);
    decode_control(CC_POWER, Bytes(), &ok);
    expect_true("empty data refused", !ok);
  }

  printf("\nquery response\n");
  {
    CcState state;
    expect_true("parses",
                parse_cc_query_frame(from_hex(GOLDEN_CC_QUERY_RESPONSE), &state));
    expect_int("power", state.power, GOLDEN_CC_STATE_POWER);
    expect_int("target temperature", (long) (state.target_temperature * 10),
               GOLDEN_CC_STATE_TARGET_X10);
    expect_int("indoor temperature", (long) (state.indoor_temperature * 10 + 0.5f),
               GOLDEN_CC_STATE_INDOOR_X10);
    expect_int("outdoor temperature", (long) (state.outdoor_temperature * 10 + 0.5f),
               GOLDEN_CC_STATE_OUTDOOR_X10);
    expect_int("fahrenheit", state.fahrenheit, GOLDEN_CC_STATE_FAHRENHEIT);
    expect_int("mode", state.mode, GOLDEN_CC_STATE_MODE);
    expect_int("fan speed", state.fan_speed, GOLDEN_CC_STATE_FAN_SPEED);
    expect_int("vertical swing", state.vert_swing_angle, GOLDEN_CC_STATE_VERT_SWING);
    expect_int("horizontal swing", state.horz_swing_angle, GOLDEN_CC_STATE_HORZ_SWING);
    expect_int("wind sense", state.wind_sense, GOLDEN_CC_STATE_WIND_SENSE);
    expect_int("eco", state.eco, GOLDEN_CC_STATE_ECO);
    expect_int("sleep", state.sleep, GOLDEN_CC_STATE_SLEEP);
    expect_int("purifier", state.purifier, GOLDEN_CC_STATE_PURIFIER);
    expect_int("aux mode", state.aux_mode, GOLDEN_CC_STATE_AUX_MODE);
    expect_int("target humidity", state.target_humidity,
               GOLDEN_CC_STATE_TARGET_HUMIDITY);
    expect_int("indoor humidity", state.indoor_humidity,
               GOLDEN_CC_STATE_INDOOR_HUMIDITY);

    // The 0x01FE header distinguishes state from anything else; without it
    // every offset below would be read from the wrong place.
    Bytes bad = from_hex(GOLDEN_CC_QUERY_RESPONSE);
    bad[11] = 0x00;
    CcState ignored;
    expect_true("payload without the 0x01FE header rejected",
                !parse_cc_query_frame(bad, &ignored));
    expect_true("short frame rejected",
                !parse_cc_query_frame(Bytes(20, 0xAA), &ignored));
  }

  printf("\ncapabilities from the same payload\n");
  {
    CcState state;
    expect_true("parses",
                parse_cc_capabilities(from_hex(GOLDEN_CC_QUERY_RESPONSE), &state));
    expect_int("minimum temperature", (long) (state.target_temperature_min * 10),
               GOLDEN_CC_CAP_MIN_X10);
    expect_int("maximum temperature", (long) (state.target_temperature_max * 10),
               GOLDEN_CC_CAP_MAX_X10);
    expect_int("supports fan speed", state.supports_fan_speed,
               GOLDEN_CC_CAP_SUPPORTS_FAN_SPEED);
    expect_int("supports humidity", state.supports_humidity,
               GOLDEN_CC_CAP_SUPPORTS_HUMIDITY);
    expect_hex("supported modes", state.supported_modes, GOLDEN_CC_CAP_MODES);
    expect_hex("supported aux modes", state.supported_aux_modes,
               GOLDEN_CC_CAP_AUX_MODES);

    // Aux modes are only meaningful when the support flag is set; otherwise
    // those four bytes are whatever happened to be there.
    Bytes no_aux = from_hex(GOLDEN_CC_QUERY_RESPONSE);
    no_aux[10 + 82] = 0x00;
    CcState without;
    parse_cc_capabilities(no_aux, &without);
    expect_true("no aux modes when unsupported", without.supported_aux_modes.empty());
  }

  printf("\ncontrol response\n");
  {
    // id (big endian, unlike the 0xAC channel), length, value, 0xFF terminator.
    std::map<ControlId, float> states;
    expect_true("parses",
                parse_cc_control_frame(
                    cc_response("0000" "01" "01" "ff" "0003" "01" "80" "ff", 0x02),
                    &states));
    expect_int("power", (long) states[CC_POWER], 1);
    expect_int("temperature", (long) (states[CC_TARGET_TEMPERATURE] * 10), 240);

    // An unknown id is still walked over correctly: the length describes it.
    states.clear();
    parse_cc_control_frame(
        cc_response("7fff" "02" "0102" "ff" "0003" "01" "80" "ff", 0x02), &states);
    expect_int("later control still read",
               (long) (states[CC_TARGET_TEMPERATURE] * 10), 240);

    // Zero-length entries still occupy five bytes.
    states.clear();
    parse_cc_control_frame(
        cc_response("0000" "00" "00" "ff" "0003" "01" "80" "ff", 0x02), &states);
    expect_int("empty entry skipped",
               (long) (states[CC_TARGET_TEMPERATURE] * 10), 240);
  }

  return report();
}
