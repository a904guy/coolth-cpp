"""Generate protocol test vectors from coolth, the reference implementation.

The C++ port has to produce byte-identical output to coolth at every layer. The
only way to be sure of that without a device in hand is to capture what coolth
actually emits and assert the C++ reproduces it exactly.

Two sources of nondeterminism are pinned so the vectors are reproducible: the
random padding in encrypted requests, and the timestamp in the 0x5A5A packet
header. Both are pinned to values the C++ tests feed in explicitly.
"""

from __future__ import annotations

import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "reference"))

import coolth.lan as lan  # noqa: E402
from coolth.device.AC.command import (  # noqa: E402
    CapabilitiesResponse,
    GetCapabilitiesCommand,
    GetPropertiesCommand,
    GetStateCommand,
    PropertyId,
    SetPropertiesCommand,
    SetStateCommand,
    ToggleDisplayCommand,
)
from coolth.device.AC.command import Command  # noqa: E402
from coolth.cloud import NetHomePlusCloud, SmartHomeCloud  # noqa: E402
from coolth.cloud_lan import CH_APP_KEY, CloudLAN, build_5a5a_packet  # noqa: E402
from coolth.const import DISCOVERY_MSG  # noqa: E402
from coolth.lan import Security, _Packet  # noqa: E402

# --- pin the nondeterminism -------------------------------------------------
PAD_BYTE = 0xAB
# 2026-08-19 19:34:56.78 UTC, packed the way coolth packs it: smallest unit
# first, plain integers. The old placeholder here decoded to month 52 and
# hour 25, which a real appliance silently drops.
FIXED_TIMESTAMP = bytes([78, 56, 34, 19, 19, 8, 26, 20])

lan.get_random_bytes = lambda n: bytes([PAD_BYTE]) * n
_Packet._timestamp = classmethod(lambda cls: FIXED_TIMESTAMP)

# --- fixtures ---------------------------------------------------------------
# Synthetic throughout. A real token and key would let anyone on the owner's
# network drive their air conditioner, and these vectors are published; the
# protocol does not care what the bytes are, only how they are transformed.
DEVICE_ID = 123456789012345
TOKEN = bytes(range(64))
KEY = bytes((i * 7 + 3) & 0xFF for i in range(32))
# A local key is normally derived during the handshake; pin one so the
# encrypted-request vector is reproducible without a live device.
LOCAL_KEY = bytes((i * 11 + 5) & 0xFF for i in range(32))
ACCOUNT = "user@example.com"


# What the anonymised discovery fixture reports.
FAKE_IP = "192.0.2.10"
FAKE_SN = "000000P0000000Q0000000000000FAKE"
FAKE_NAME = "net_ac_1234"


def anonymise_discovery(raw: bytes) -> bytes:
    """Strip identifiers from a captured discovery response.

    The capture is real -- real framing, real encryption, real field offsets --
    but the serial number, address and appliance id belong to somebody's air
    conditioner and these vectors get published. Substituting them inside the
    encrypted payload and re-signing keeps the fixture honest as a parser test
    without shipping a stranger's hardware details.

    Field lengths are preserved so every offset stays where it was.
    """
    body = bytearray(raw[8:-16])
    payload = bytearray(Security.decrypt_aes(bytes(body[40:-16])))

    payload[0:4] = bytes(int(o) for o in reversed(FAKE_IP.split(".")))
    payload[8:40] = FAKE_SN.encode()
    name_length = payload[40]
    assert len(FAKE_NAME) == name_length, "replacement name must be same length"
    payload[41:41 + name_length] = FAKE_NAME.encode()

    body[20:26] = DEVICE_ID.to_bytes(6, "little")
    rebuilt = bytes(body[:40]) + Security.encrypt_aes(bytes(payload))
    # The outer V3 trailer is not checked by the parser, so it rides along
    # unchanged; the inner MD5 is recomputed so the packet stays self-consistent.
    return raw[:8] + rebuilt + Security.sign(rebuilt) + raw[-16:]


def pin_message_id(value: int = 0) -> None:
    """Commands carry an incrementing message id and a CRC8 over it.

    The counter is global in coolth, so vector output would otherwise depend on
    the order these are generated in. Reset it before each capture and the C++
    can pass the same id in explicitly.
    """
    Command._message_id = value


def build_set_command(target_c: float) -> bytes:
    """A set command carrying the real unit's current state, temp changed.

    Mirrors AirConditioner.apply(): every field is carried over from the
    device's last known state, because a set command replaces all of them.
    """
    cmd = SetStateCommand()
    cmd.beep_on = False
    cmd.power_on = True
    cmd.target_temperature = target_c
    cmd.operational_mode = 2  # COOL
    cmd.fan_speed = 102  # AUTO
    cmd.swing_mode = 0
    cmd.eco = False
    cmd.turbo = False
    cmd.freeze_protection = False
    cmd.sleep = False
    cmd.fahrenheit = True
    cmd.follow_me = False
    cmd.purifier = False
    cmd.target_humidity = 0
    cmd.aux_heat = False
    cmd.independent_aux_heat = False
    pin_message_id()
    return cmd.tobytes()


def main() -> None:
    vectors: dict[str, object] = {
        "pad_byte": PAD_BYTE,
        "timestamp": FIXED_TIMESTAMP.hex(),
        "device_id": DEVICE_ID,
        "token": TOKEN.hex(),
        "key": KEY.hex(),
        "local_key": LOCAL_KEY.hex(),
        "enc_key": Security.ENC_KEY.hex(),
        "sign_key": Security.SIGN_KEY.hex(),
    }

    # Layer 1: the 0xAA command frame.
    pin_message_id()
    get_frame = GetStateCommand().tobytes()
    set_frame_24 = build_set_command(24.0)
    set_frame_25 = build_set_command(25.0)
    set_frame_245 = build_set_command(24.5)
    vectors["message_id"] = 1  # every frame vector above uses id 1
    vectors["get_state_frame"] = get_frame.hex()
    vectors["set_state_frame_24c"] = set_frame_24.hex()
    vectors["set_state_frame_25c"] = set_frame_25.hex()
    vectors["set_state_frame_24_5c"] = set_frame_245.hex()

    # Layer 2: AES-ECB with the fixed key, and the MD5 signature.
    vectors["aes_ecb_get_frame"] = Security.encrypt_aes(get_frame).hex()
    vectors["md5_sign_get_frame"] = Security.sign(get_frame).hex()

    # Layer 3: the 0x5A5A packet.
    vectors["packet_5a5a_get"] = _Packet.encode(DEVICE_ID, get_frame).hex()
    vectors["packet_5a5a_set_25c"] = _Packet.encode(DEVICE_ID, set_frame_25).hex()

    # Layer 4: the 0x8370 envelope.
    protocol = lan._LanProtocolV3()
    vectors["handshake_request"] = protocol._encode_handshake_request(0, TOKEN).hex()

    protocol._local_key = LOCAL_KEY
    packet = _Packet.encode(DEVICE_ID, set_frame_25)
    vectors["encrypted_request_set_25c"] = protocol._encode_encrypted_request(
        0, packet
    ).hex()

    # Local key derivation: build a synthetic handshake response whose
    # decryption is known, so the C++ can be checked without a device.
    plaintext = bytes(range(32))
    from hashlib import sha256

    encrypted = Security.encrypt_aes_cbc(KEY, plaintext)
    response = encrypted + sha256(plaintext).digest()
    derived = protocol._get_local_key(KEY, memoryview(response))
    vectors["handshake_response_synthetic"] = response.hex()
    vectors["handshake_derived_local_key"] = derived.hex()

    # A real response captured from the appliance, with the field values
    # coolth's own parser extracts from it. This is what the C++ parser is
    # checked against -- a synthetic round trip would not catch the fact that
    # set frames and state responses use different bits for the same flag.
    live = pathlib.Path(__file__).resolve().parent.parent / "tests" / "live_state_response.hex"
    if live.exists():
        from coolth.device.AC.command import StateResponse

        frame = bytes.fromhex(live.read_text().strip())
        response = StateResponse(memoryview(frame[10:-1]))
        vectors["live_state_frame"] = frame.hex()
        vectors["live_power"] = int(bool(response.power_on))
        vectors["live_mode"] = int(response.operational_mode)
        vectors["live_fan_speed"] = int(response.fan_speed)
        vectors["live_swing_mode"] = int(response.swing_mode)
        vectors["live_eco"] = int(bool(response.eco))
        vectors["live_turbo"] = int(bool(response.turbo))
        vectors["live_sleep"] = int(bool(response.sleep))
        vectors["live_fahrenheit"] = int(bool(response.fahrenheit))
        vectors["live_target_temperature_x10"] = int(round(response.target_temperature * 10))
        vectors["live_outdoor_temperature_x10"] = int(round(response.outdoor_temperature * 10))
        vectors["live_target_humidity"] = int(response.target_humidity or 0)

    # --- display toggle and properties ----------------------------------------
    pin_message_id()
    vectors["toggle_display_frame"] = ToggleDisplayCommand().tobytes().hex()

    pin_message_id()
    vectors["get_properties_frame"] = GetPropertiesCommand(
        sorted([PropertyId.SWING_UD_ANGLE, PropertyId.RATE_SELECT,
                PropertyId.BREEZE_CONTROL])
    ).tobytes().hex()

    # A set covering the encodings that are not just "one raw byte".
    pin_message_id()
    # Ordered by property id. The device does not care, but the C++ side uses
    # a std::map, so matching the ordering keeps the vector byte-exact.
    vectors["set_properties_frame"] = SetPropertiesCommand(dict(sorted({
        PropertyId.SWING_UD_ANGLE: 50,
        PropertyId.BREEZE_AWAY: True,
        PropertyId.CASCADE: 2,
        PropertyId.FRESH_AIR: 60,
        PropertyId.OUT_SILENT: True,
    }.items()))).tobytes().hex()

    # Per-property encodings, so a mismatch points at the property not the frame.
    for name, prop, value in (
        ("swing_ud", PropertyId.SWING_UD_ANGLE, 50),
        ("breeze_away_on", PropertyId.BREEZE_AWAY, True),
        ("breeze_away_off", PropertyId.BREEZE_AWAY, False),
        ("cascade", PropertyId.CASCADE, 2),
        ("fresh_air", PropertyId.FRESH_AIR, 60),
        ("fresh_air_off", PropertyId.FRESH_AIR, 0),
        ("out_silent_on", PropertyId.OUT_SILENT, True),
        ("out_silent_off", PropertyId.OUT_SILENT, False),
        ("rate_select", PropertyId.RATE_SELECT, 75),
        ("self_clean", PropertyId.SELF_CLEAN, True),
    ):
        vectors[f"prop_encode_{name}"] = prop.encode(value).hex()

    for name, prop, raw in (
        ("cascade_on", PropertyId.CASCADE, "0102"),
        ("cascade_off", PropertyId.CASCADE, "0002"),
        ("fresh_air_on", PropertyId.FRESH_AIR, "013cff"),
        ("fresh_air_off", PropertyId.FRESH_AIR, "003cff"),
        ("breeze_away_on", PropertyId.BREEZE_AWAY, "02"),
        ("breeze_away_off", PropertyId.BREEZE_AWAY, "01"),
        ("out_silent_on", PropertyId.OUT_SILENT, "03"),
        ("ieco_on", PropertyId.IECO, "0101"),
        ("ieco_off", PropertyId.IECO, "0100"),
        ("swing_ud", PropertyId.SWING_UD_ANGLE, "32"),
    ):
        vectors[f"prop_decode_{name}"] = int(prop.decode(bytes.fromhex(raw)))

    # --- commercial 0xCC device ----------------------------------------------
    from coolth.device.CC.command import (
        ControlCommand,
        ControlId,
        QueryCommand,
        QueryResponse,
    )
    from coolth.device.CC import command as cc_command

    cc_command.Command._message_id = 0
    vectors["cc_query_frame"] = QueryCommand().tobytes().hex()

    cc_command.Command._message_id = 0
    vectors["cc_control_frame"] = ControlCommand(dict(sorted({
        ControlId.POWER: True,
        ControlId.TARGET_TEMPERATURE: 24.0,
        ControlId.MODE: 2,
        ControlId.FAN_SPEED: 60,
    }.items()))).tobytes().hex()

    for name, control, value in (
        ("temperature_24", ControlId.TARGET_TEMPERATURE, 24.0),
        ("temperature_17_5", ControlId.TARGET_TEMPERATURE, 17.5),
        ("power", ControlId.POWER, True),
        ("mode", ControlId.MODE, 2),
    ):
        vectors[f"cc_encode_{name}"] = control.encode(value).hex()
    vectors["cc_decode_temperature"] = int(
        ControlId.TARGET_TEMPERATURE.decode(bytes([128])) * 10
    )

    # A synthetic query response: the payload layout is well documented in the
    # reference, and no commercial unit is available to capture from.
    cc_payload = bytearray(90)
    cc_payload[0:2] = b"\x01\xfe"
    cc_payload[8] = 1              # power on
    cc_payload[9] = 114            # min 17C
    cc_payload[10] = 140           # max 30C
    cc_payload[11] = 128           # target 24C
    cc_payload[12], cc_payload[13] = 0x00, 0xF5   # indoor 24.5C
    cc_payload[14] = 147           # outdoor 33.5C
    cc_payload[21] = 1             # fahrenheit display
    cc_payload[23] = 1             # supports humidity
    cc_payload[24] = 45            # target humidity
    cc_payload[25] = 50            # indoor humidity
    cc_payload[26:31] = bytes([1, 2, 3, 4, 5])
    cc_payload[31] = 2             # mode cool
    cc_payload[32] = 1             # supports fan speed
    cc_payload[34] = 60            # fan speed
    cc_payload[40] = 1
    cc_payload[41] = 25            # vert swing angle
    cc_payload[42] = 1
    cc_payload[43] = 50            # horz swing angle
    cc_payload[44] = 1
    cc_payload[45] = 3             # wind sense soft
    cc_payload[55] = 1
    cc_payload[56] = 1             # eco on
    cc_payload[57] = 1
    cc_payload[58] = 0             # silent off
    cc_payload[59] = 1
    cc_payload[60] = 1             # sleep on
    cc_payload[73] = 1
    cc_payload[75] = 2             # purifier off
    cc_payload[80] = 1             # beep
    cc_payload[81] = 1             # display
    cc_payload[82] = 1             # supports aux heat
    cc_payload[83:87] = bytes([0, 1, 2, 4])
    cc_payload[87] = 1             # aux mode on

    cc_frame = bytearray(10)
    cc_frame[0] = 0xAA
    cc_frame[2] = 0xCC
    cc_frame[9] = 0x03
    cc_frame += cc_payload
    cc_frame[1] = len(cc_payload) + 10
    cc_frame.append((~sum(cc_frame[1:]) + 1) & 0xFF)
    vectors["cc_query_response"] = bytes(cc_frame).hex()

    response = QueryResponse(memoryview(bytes(cc_payload)))
    response.parse_capabilities()
    vectors["cc_state_power"] = int(response.power_on)
    vectors["cc_state_target_x10"] = int(round(response.target_temperature * 10))
    vectors["cc_state_indoor_x10"] = int(round(response.indoor_temperature * 10))
    vectors["cc_state_outdoor_x10"] = int(round(response.outdoor_temperature * 10))
    vectors["cc_state_fahrenheit"] = int(response.fahrenheit)
    vectors["cc_state_mode"] = int(response.operational_mode)
    vectors["cc_state_fan_speed"] = int(response.fan_speed)
    vectors["cc_state_vert_swing"] = int(response.vert_swing_angle)
    vectors["cc_state_horz_swing"] = int(response.horz_swing_angle)
    vectors["cc_state_wind_sense"] = int(response.wind_sense)
    vectors["cc_state_eco"] = int(response.eco)
    vectors["cc_state_sleep"] = int(response.sleep)
    vectors["cc_state_purifier"] = int(response.purifier)
    vectors["cc_state_aux_mode"] = int(response.aux_mode)
    vectors["cc_state_target_humidity"] = int(response.target_humidity)
    vectors["cc_state_indoor_humidity"] = int(response.indoor_humidity)
    vectors["cc_cap_min_x10"] = int(round(response.target_temperature_min * 10))
    vectors["cc_cap_max_x10"] = int(round(response.target_temperature_max * 10))
    vectors["cc_cap_modes"] = "".join(f"{m:02x}" for m in response.supported_op_modes)
    vectors["cc_cap_aux_modes"] = "".join(f"{m:02x}" for m in response.supported_aux_modes)
    vectors["cc_cap_supports_fan_speed"] = int(response.supports_fan_speed)
    vectors["cc_cap_supports_humidity"] = int(response.supports_humidity)

    # --- cloud relay (cloud_lan) ---------------------------------------------
    import coolth.cloud_lan as cloud_lan_mod

    CL_TIMESTAMP = bytes([0x64, 0x38, 0x1E, 0x05, 0x13, 0x07, 0x1A, 0x14])
    cloud_lan_mod._timestamp = lambda: CL_TIMESTAMP
    vectors["cl_timestamp"] = CL_TIMESTAMP.hex()
    vectors["cl_app_key"] = CH_APP_KEY

    cl_frame = build_set_command(24.0)
    vectors["cl_frame"] = cl_frame.hex()
    vectors["cl_packet"] = build_5a5a_packet(cl_frame, DEVICE_ID, 1001).hex()

    relay = CloudLAN(DEVICE_ID, ACCOUNT, "hunter2")
    vectors["cl_to_text"] = relay._to_text(bytes([0x00, 0x7F, 0x80, 0xFF, 0xAA])).decode()
    vectors["cl_from_text"] = relay._from_text("0,127,-128,-1,-86").hex()
    vectors["cl_password_hash"] = relay._password_hash(
        "ffffffffffffffffffffffffffffffff"
    )
    # An access token is the session key encrypted under a key from the app key.
    from Crypto.Cipher import AES as _AES
    from Crypto.Util import Padding as _Pad
    import hashlib as _hashlib

    session_key = bytes(range(16))
    kek = _hashlib.md5(CH_APP_KEY.encode()).hexdigest()[:16].encode()
    token_hex_value = _AES.new(kek, _AES.MODE_ECB).encrypt(
        _Pad.pad(session_key, 16)
    ).hex()
    vectors["cl_access_token"] = token_hex_value
    vectors["cl_derived_key"] = relay._derive_key(token_hex_value).hex()

    sign_body = {
        "src": "17", "format": "2", "stamp": "20260819123456",
        "language": "en_US", "sessionId": "SESSION456",
        "applianceId": str(DEVICE_ID), "funId": "0008", "order": "abcdef",
    }
    vectors["cl_sign"] = relay._sign("/v1/appliance/transparent/send/new", sign_body)

    # --- SmartHome / MSmartHome cloud ----------------------------------------
    for suffix, china in (("", False), ("_china", True)):
        sec = SmartHomeCloud._Security(china)
        vectors[f"sh_sign{suffix}"] = sec.sign("{\"a\":1}", "0011223344556677")
        vectors[f"sh_password{suffix}"] = sec.encrypt_password(
            "ffffffffffffffffffffffffffffffff", "hunter2"
        )
        vectors[f"sh_iampwd{suffix}"] = sec.encrypt_iam_password(
            "ffffffffffffffffffffffffffffffff", "hunter2"
        )
    vectors["sh_sign_data"] = "{\"a\":1}"
    vectors["sh_sign_random"] = "0011223344556677"

    # --- capabilities ---------------------------------------------------------
    pin_message_id()
    vectors["get_capabilities_frame"] = GetCapabilitiesCommand(False).tobytes().hex()
    pin_message_id()
    vectors["get_capabilities_additional_frame"] = (
        GetCapabilitiesCommand(True).tobytes().hex()
    )

    caps_file = pathlib.Path(__file__).resolve().parent.parent / "tests" / "live_capabilities.hex"
    if caps_file.exists():
        frame = bytes.fromhex(caps_file.read_text().strip().splitlines()[0])
        response = CapabilitiesResponse(memoryview(frame[10:-1]))
        raw = response.raw_capabilities
        vectors["live_capabilities_frame"] = frame.hex()
        vectors["live_capabilities_additional"] = int(response.additional_capabilities)
        # Every flag coolth derived, so a divergence names the exact capability.
        for name in (
            "eco", "freeze_protection", "heat_mode", "cool_mode", "dry_mode",
            "auto_mode", "aux_heat_mode", "aux_mode", "swing_horizontal",
            "swing_vertical", "energy_stats", "energy_setting", "energy_bcd",
            "filter_notice", "filter_clean", "turbo_heat", "turbo_cool",
        ):
            vectors[f"live_cap_{name}"] = int(bool(raw.get(name, False)))
        # Fan speeds go through the fallback, which is the subtle part.
        for name in ("silent", "low", "medium", "high", "auto"):
            vectors[f"live_cap_fan_{name}"] = int(bool(getattr(response, f"fan_{name}")))

    # --- discovery -----------------------------------------------------------
    vectors["discovery_request"] = DISCOVERY_MSG.hex()

    disco = pathlib.Path(__file__).resolve().parent.parent / "tests" / "live_discovery_response.hex"
    if disco.exists():
        raw = anonymise_discovery(bytes.fromhex(disco.read_text().strip()))
        vectors["live_discovery_response"] = raw.hex()
        # Mirrors Discover._get_device_info for a V3 device.
        body = raw[8:-16]
        encrypted = body[40:-16]
        decrypted = Security.decrypt_aes(encrypted)
        name_length = decrypted[40]
        vectors["live_discovery_device_id"] = int.from_bytes(body[20:26], "little")
        vectors["live_discovery_ip"] = ".".join(str(b) for b in decrypted[3::-1])
        vectors["live_discovery_port"] = int.from_bytes(decrypted[4:6], "little")
        vectors["live_discovery_sn"] = decrypted[8:40].decode()
        vectors["live_discovery_name"] = decrypted[41:41 + name_length].decode()
        vectors["live_discovery_device_type"] = int(
            vectors["live_discovery_name"].split("_")[1], 16
        )

    # --- udpid ---------------------------------------------------------------
    # Both endians are tried in turn; a device answers to exactly one.
    for endian in ("little", "big"):
        vectors[f"udpid_{endian}"] = Security.udpid(
            DEVICE_ID.to_bytes(6, endian)
        ).hex()

    # --- cloud (NetHome Plus) ------------------------------------------------
    security = NetHomePlusCloud._Security()
    vectors["cloud_app_key"] = security.APP_KEY
    vectors["cloud_password_hash"] = security.encrypt_password(
        "ffffffffffffffffffffffffffffffff", "hunter2"
    )
    vectors["cloud_password_login_id"] = "ffffffffffffffffffffffffffffffff"
    vectors["cloud_password_plain"] = "hunter2"
    # Signing takes the request body sorted by key, joined unencoded.
    sign_body = {
        "appId": "1017",
        "src": "1017",
        "format": 2,
        "clientType": 1,
        "language": "en_US",
        "deviceId": "0123456789abcdef",
        "stamp": "20260819123456",
        "sessionId": "",
        "loginAccount": ACCOUNT,
    }
    vectors["cloud_account"] = ACCOUNT
    vectors["cloud_sign_endpoint"] = "/v1/user/login/id/get"
    vectors["cloud_sign_body_json"] = json.dumps(sign_body, sort_keys=True)
    vectors["cloud_sign"] = security.sign("/v1/user/login/id/get", sign_body)

    native = pathlib.Path(__file__).resolve().parent.parent / "tests"
    out = native / "golden_vectors.json"
    out.write_text(json.dumps(vectors, indent=2) + "\n", encoding="utf-8")

    # Also emit a header so the C++ tests need no JSON parser.
    header = ["// Generated by tools/golden_vectors.py -- do not edit.", "#pragma once", ""]
    for name in sorted(vectors):
        value = vectors[name]
        if isinstance(value, str):
            # Values can contain quotes and backslashes (JSON fixtures do), so
            # escape them for the C string literal.
            escaped = value.replace("\\", "\\\\").replace('"', '\\"')
            header.append(f'#define GOLDEN_{name.upper()} "{escaped}"')
        else:
            header.append(f"#define GOLDEN_{name.upper()} {value}ULL")
    (native / "golden_vectors.h").write_text("\n".join(header) + "\n", encoding="utf-8")
    print(f"wrote {out} and golden_vectors.h")
    for name in sorted(vectors):
        value = vectors[name]
        if isinstance(value, str) and len(value) > 60:
            value = f"{value[:56]}… ({len(value)//2} bytes)"
        print(f"  {name}: {value}")


if __name__ == "__main__":
    main()
