// Finding Midea appliances on the local network.
//
// Broadcast a fixed 64 byte probe to UDP 6445 and 20086; anything Midea on the
// subnet answers with a packet describing itself. Parsing is pure, so the
// caller owns the socket and this stays testable without a network.
#pragma once

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "protocol.h"

namespace coolth {

struct DiscoveredDevice {
  std::string ip;
  uint16_t port = 6444;
  uint64_t device_id = 0;
  std::string name;         // e.g. "net_ac_9E06"
  std::string serial;
  uint8_t device_type = 0;  // 0xAC for an air conditioner
  uint8_t version = 0;      // 1, 2 or 3; see discovery_version
};

// The probe to broadcast. Same bytes every time.
Bytes discovery_request();

// 2 or 3 from the reply's first bytes, 1 for the XML a V1 device sends, or 0
// if it is none of those.
//
// V1 is detected but not supported: the reply carries only a port, and the
// real details need a second TCP query whose response format is undocumented.
// coolth stops at the same point. Detecting it at least lets a caller say
// "found a device I cannot talk to" rather than staying silent.
uint8_t discovery_version(const Bytes &response);

bool parse_discovery_response(const Bytes &response, DiscoveredDevice *out);

}  // namespace coolth
