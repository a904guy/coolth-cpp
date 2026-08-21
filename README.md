# coolth-cpp

A C++ implementation of Midea's **V3 LAN protocol**, the one their air
conditioners speak on TCP port 6444, with no dependency beyond mbedtls.

It exists because nothing else does. Every open-source Midea integration for
microcontrollers goes through a UART dongle wired inside the appliance, or
through IR. If you want an ESP32 to control a Midea AC the same way a phone on
the same WiFi does, over the network, authenticated, with state read back,
this is that.

It's a port of [coolth](https://github.com/a904guy/coolth-ac-controller), and
it's verified against it byte-for-byte.

## Supported air conditioners

Midea makes air conditioners for a lot of other labels. If your unit works with
one of these apps, it should work here:

| Brand | App |
|---|---|
| Artic King | `com.arcticking.ac` |
| Cooper & Hunter | `com.ch.air` |
| Midea Air | `com.midea.aircondition.obm` |
| NetHome Plus | `com.midea.aircondition` |
| SmartHome / MSmartHome | `com.midea.ai.overseas` |
| Toshiba AC NA | `com.midea.toshiba` |
| 美的美居 | `com.midea.ai.appliances` |

Developed against a Cooper & Hunter unit. Only air conditioners (`0xAC`) are
handled; commercial units (`0xCC`) are not.

## Status

Working, and verified against a real appliance:

* **Discovery** by UDP broadcast, V2 and V3, with V1 detected and reported
* **Cloud login and token/key retrieval**, on both the NetHome Plus and the
  SmartHome / MSmartHome clouds, so a device can be set up without running
  anything else first
* **LAN transport**, V2 direct, V3 with the token/key handshake and per-session
  key
* **Cloud relay** (`cloud_lan.h`), the same frames tunnelled through Midea's
  servers, for an appliance on an isolated network
* **State**: power, mode, fan, swing, setpoint, indoor and outdoor temperature,
  humidity, display, filter alert, error code
* **Control**: everything above, plus the property channel, swing angles,
  breeze modes, rate select, fresh air, self clean, jet cool, outdoor silent
* **Capabilities**, so you can ask what a unit supports before offering it
* **Commercial 0xCC units**, query, control, and capabilities
* **A command line tool**, mirroring the Python one

Not there:

* V1 appliances. They answer discovery with XML and need a second query whose
  format is undocumented; coolth stops at the same place.
* Downloading the per-device Lua protocol files and app plugins. Only useful
  for reverse engineering new models, and not on a microcontroller.
* Energy statistics and a handful of rarely-supported extras.

## A device quirk worth knowing

An appliance will routinely **ignore the first command after a handshake**,
no reply, no error, and the request is perfectly well formed. Send it again and
it answers immediately.

This is not packet loss; it reproduces on every fresh session. If you write
your own client and it looks like the device is dead despite byte-perfect
requests, this is why. `LanTransport` retries three times, which is what
coolth does too.

## The protocol

Three nested layers. Outermost is last on the wire:

```
0xAA    command frame     what the appliance acts on; message id + CRC8
0x5A5A  packet            AES-ECB(frame) + MD5 signature, fixed public key
0x8370  envelope          AES-CBC(packet) + SHA256, keyed per session
```

Two things about this are easy to get wrong:

**A set command replaces the entire state.** There is no "change only the
temperature" message. You must read current state, modify one field, and send
all of them back, otherwise adjusting the setpoint also switches the unit off
and resets its mode, because those fields defaulted to zero in your command.

**Set frames and state responses use different bits for the same flag.** Eco is
`0x80` of payload byte 9 when you send it and `0x10` of byte 9 when you receive
it. A round-trip test that builds a frame and parses it back will pass while
being completely wrong; the tests here parse a response captured from real
hardware instead.

Also worth knowing: the AES-CBC uses a zero IV, and the 0x5A5A layer's key is
`md5("xhdiwjnchekd4d512chdjx5d8e4c394D2D7S")`, a constant from the Midea app.
That layer is obfuscation, not security. The actual protection is the
token/key pair, which is per-device and comes from your Midea account.

## Setting a device up from scratch

Discovery gets you the address and id; the cloud gets you the token and key.
After that, everything is local.

```cpp
#include "coolth/cloud.h"
#include "coolth/discovery.h"

// 1. Broadcast coolth::discovery_request() to UDP 6445 and 20086, then:
coolth::DiscoveredDevice device;
if (!coolth::parse_discovery_response(datagram, &device))
  return;

// 2. Ask the cloud for this device's credentials. Needs a real clock, since
//    requests carry a UTC timestamp the server checks.
coolth::NetHomePlusCloud cloud(account, password, my_http_post);
cloud.set_timestamp("20260819123456");

coolth::DeviceCredentials creds;
std::string error;
if (!cloud.get_credentials(device.device_id, &creds, &error))
  return;
// creds.token and creds.key are stable -- store them and skip this next time.
```

HTTP is injected rather than built in, so the library needs no TLS stack of its
own. On ESP-IDF, wire `HttpPost` to `esp_http_client` with `esp_crt_bundle`.

## Using it

```cpp
#include "coolth/protocol.h"

// One-time: get token, key and device id from `coolth discover`.
const auto token = coolth::from_hex("0011223344...");  // 128 hex chars
const auto key   = coolth::from_hex("aabbccddee...");  // 64 hex chars

// 1. Handshake.
auto request = coolth::encode_handshake_request(packet_id++, token);
// ...send over TCP, read the 72 byte reply...
coolth::Bytes local_key;
if (!coolth::derive_local_key(key, reply_body, &local_key))
  return;  // wrong or stale credentials

// 2. Read state.
auto frame  = coolth::build_get_state_frame(message_id++);
auto packet = coolth::encode_packet(device_id, frame, timestamp);
auto out    = coolth::encode_encrypted_request(packet_id++, local_key, packet, random_byte);
// ...send, read...
coolth::Bytes inner, response_frame;
coolth::decode_encrypted_response(local_key, envelope, &inner);
coolth::decode_packet(inner, &response_frame);

coolth::AcState state;
coolth::parse_state_frame(response_frame, &state);

// 3. Change one field and send it all back.
state.target_temperature = 24.0f;   // always Celsius on the wire
state.beep = false;
auto set = coolth::build_set_state_frame(state, message_id++);
```

`state.fahrenheit` is the *display* unit on the appliance's panel. The wire
format is always Celsius, in half-degree steps, so 75 °F is 24.0 °C.

For a complete worked example including sockets, session lifetime and retries,
see `../esphome/components/midea_lan/midea_lan.cpp`.

## Building

Needs only mbedtls (`libmbedtls-dev` on Debian/Ubuntu; already present in
ESP-IDF). Two files, no build system required:

```bash
g++ -std=c++17 -c components/coolth/*.cpp -lmbedcrypto
```

The command line tool additionally wants libcurl for the cloud commands; it
builds without it and the LAN commands still work:

```bash
make -C cli
./cli/coolth-cpp discover
./cli/coolth-cpp query 192.0.2.10 --token TOKEN --key KEY --id 123456789012345
./cli/coolth-cpp control 192.0.2.10 --auto --account you@example.com \
    --password secret target_temperature=24 mode=cool fan_speed=auto
```

## Layout

```
components/coolth/     the library
  protocol.h/.cpp      framing, crypto, state, 0xAC commands
  lan.h/.cpp           the V2/V3 TCP transport
  properties.h/.cpp    the 0xB0/0xB1 property channel
  capabilities.h/.cpp  what a given unit supports
  device_cc.h/.cpp     commercial 0xCC appliances
  discovery.h/.cpp     finding devices on the LAN
  cloud.h/.cpp         login and token/key retrieval, both clouds
  cloud_lan.h/.cpp     relaying frames through the cloud
  json_lite.h/.cpp     just enough JSON for the cloud's replies
cli/                   the command line tool
tests/                 host tests and golden vectors
tools/                 vector generator
```

It is also a valid ESPHome component; see below.

## Using it from ESPHome

The library doubles as an ESPHome external component, so it can be consumed
straight from git:

```yaml
external_components:
  - source: github://a904guy/coolth-cpp
    components: [coolth]
```

Then `#include "esphome/components/coolth/protocol.h"`. The component carries
no configuration of its own; including it is what compiles the sources. See
`../esphome/components/midea_lan/` for a component built on top of it.

## Tests

```bash
cd tests && make check
```

260 checks. They are golden vectors captured from coolth, the Python reference,
plus state, discovery and capability responses captured from a real Cooper &
Hunter unit. Every layer is asserted byte-for-byte. Because mbedtls is the same
library on a workstation and on an ESP32, passing here means the bytes are right
on the device.

The cloud flow is driven end to end against canned replies, which checks the
things a rejected login will never tell you: that the signature covers the right
string, that the password is hashed rather than sent, and that the session id is
carried forward.

Regenerate the vectors after changing anything (needs `reference/`, a vendored
copy of coolth, and its dependencies):

```bash
cd tests && make vectors
```

Nondeterminism is pinned so vectors are reproducible: the random padding in
encrypted requests, the packet timestamp, and coolth's global message-id
counter.

## Licence

MIT. coolth itself is a fork of
[mill1000/midea-msmart](https://github.com/mill1000/midea-msmart); the protocol
understanding encoded here descends from that work and from
[dudanov/MideaUART](https://github.com/dudanov/MideaUART).

Not affiliated with or endorsed by Midea.
