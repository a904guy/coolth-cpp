#include "discovery.h"

namespace coolth {
namespace {

// Fixed probe from the Midea app. The trailing 32 bytes are a constant blob;
// the appliance does not appear to inspect them but will not answer without.
const uint8_t DISCOVERY_MSG[] = {
    0x5a, 0x5a, 0x01, 0x11, 0x48, 0x00, 0x92, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x7f, 0x75, 0xbd, 0x6b, 0x3e, 0x4f, 0x8b, 0x76,
    0x2e, 0x84, 0x9c, 0x6e, 0x57, 0x8d, 0x65, 0x90, 0x03, 0x6e, 0x9d, 0x43,
    0x42, 0xa5, 0x0f, 0x1f, 0x56, 0x9e, 0xb8, 0xec, 0x91, 0x8e, 0x92, 0xe5};

}  // namespace

Bytes discovery_request() {
  return Bytes(DISCOVERY_MSG, DISCOVERY_MSG + sizeof(DISCOVERY_MSG));
}

uint8_t discovery_version(const Bytes &response) {
  if (response.size() < 2)
    return 0;
  if (response[0] == 0x5A && response[1] == 0x5A)
    return 2;
  if (response[0] == 0x83 && response[1] == 0x70)
    return 3;
  // A V1 device answers with an XML document rather than a binary packet.
  const std::string text(response.begin(),
                         response.begin() + (response.size() < 64 ? response.size() : 64));
  if (text.find("<?xml") != std::string::npos || text.find("<body") != std::string::npos)
    return 1;
  return 0;
}

bool parse_discovery_response(const Bytes &response, DiscoveredDevice *out) {
  const uint8_t version = discovery_version(response);
  if (version == 1) {
    // Report what was found so the caller can say something useful, but there
    // is nothing more to extract without the follow-up query.
    out->version = 1;
    return false;
  }
  if (version != 2 && version != 3)
    return false;

  // V3 wraps the V2 packet in an 8 byte header and a 16 byte trailer.
  const size_t begin = version == 3 ? 8 : 0;
  const size_t end = version == 3 ? response.size() - 16 : response.size();
  if (end <= begin || end - begin < 104)
    return false;
  const Bytes body(response.begin() + begin, response.begin() + end);

  // The id sits in the clear; everything descriptive is in the encrypted tail.
  uint64_t device_id = 0;
  for (int i = 5; i >= 0; i--)
    device_id = (device_id << 8) | body[20 + i];

  const Bytes encrypted(body.begin() + 40, body.end() - 16);
  const Bytes decrypted = aes_ecb_decrypt_unpadded(encrypted);
  if (decrypted.size() < 41)
    return false;

  // The address is stored back to front.
  char ip[16];
  snprintf(ip, sizeof(ip), "%u.%u.%u.%u", decrypted[3], decrypted[2],
           decrypted[1], decrypted[0]);

  const size_t name_length = decrypted[40];
  if (41 + name_length > decrypted.size())
    return false;

  out->ip = ip;
  out->port = static_cast<uint16_t>(decrypted[4] | (decrypted[5] << 8));
  out->device_id = device_id;
  out->serial.assign(decrypted.begin() + 8, decrypted.begin() + 40);
  out->name.assign(decrypted.begin() + 41, decrypted.begin() + 41 + name_length);
  out->version = version;

  // The name is "<something>_<type hex>_<suffix>", e.g. net_ac_9E06 -> 0xAC.
  out->device_type = 0;
  const size_t first = out->name.find('_');
  if (first != std::string::npos) {
    const size_t second = out->name.find('_', first + 1);
    if (second != std::string::npos) {
      const std::string type = out->name.substr(first + 1, second - first - 1);
      out->device_type =
          static_cast<uint8_t>(strtoul(type.c_str(), nullptr, 16) & 0xFF);
    }
  }
  return true;
}

}  // namespace coolth
