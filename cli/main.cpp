// coolth-cpp command line tool. Mirrors the Python coolth CLI:
//   coolth-cpp discover
//   coolth-cpp query <HOST> [--token T --key K --id N]
//   coolth-cpp control <HOST> [auth] key=value ...

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <map>
#include <string>
#include <vector>

#include "../components/coolth/capabilities.h"
#include "../components/coolth/cloud.h"
#include "../components/coolth/cloud_lan.h"
#include "../components/coolth/discovery.h"
#include "../components/coolth/lan.h"
#include "../components/coolth/properties.h"
#include "net.h"

using namespace coolth;

namespace {

struct Options {
  std::string host;
  std::string token;
  std::string key;
  uint64_t device_id = 0;
  bool cloud = false;
  bool auto_credentials = false;
  std::string account;
  std::string password;
  int timeout = 10;
  std::vector<std::pair<std::string, std::string>> settings;
};

void usage() {
  printf(
      "usage: coolth-cpp <command> [options]\n"
      "\n"
      "commands:\n"
      "  discover                       find appliances on the local network\n"
      "  query <HOST>                   read state and capabilities\n"
      "  control <HOST> key=value ...   change settings\n"
      "\n"
      "authentication (V3 devices):\n"
      "  --token HEX --key HEX --id N   credentials from `discover`\n"
      "  --auto                         fetch them from the cloud instead\n"
      "  --cloud                        route commands via the cloud;\n"
      "                                 HOST is the appliance id, not an address\n"
      "  --account EMAIL --password P   cloud credentials\n"
      "\n"
      "settings for control:\n"
      "  power=on|off            mode=auto|cool|dry|heat|fan\n"
      "  target_temperature=24.5 fan_speed=auto|silent|low|medium|high|0-100\n"
      "  swing_mode=off|vertical|horizontal|both\n"
      "  eco=on|off  turbo=on|off  sleep=on|off  beep=on|off\n"
      "  fahrenheit=on|off  target_humidity=0-100\n");
}

// gmtime_r is POSIX; the Windows CRT spells it gmtime_s, with the arguments
// the other way round.
void utc_now(struct tm *out) {
  const time_t now = time(nullptr);
#ifdef _WIN32
  gmtime_s(out, &now);
#else
  gmtime_r(&now, out);
#endif
}

std::string now_stamp() {
  struct tm utc;
  utc_now(&utc);
  char buffer[32];
  strftime(buffer, sizeof(buffer), "%Y%m%d%H%M%S", &utc);
  return buffer;
}

void now_packet_timestamp(uint8_t out[8]) {
  struct tm utc;
  utc_now(&utc);
  make_lan_timestamp(utc.tm_year + 1900, utc.tm_mon + 1, utc.tm_mday,
                     utc.tm_hour, utc.tm_min, utc.tm_sec, 0, out);
}

bool truthy(const std::string &value) {
  return value == "1" || value == "on" || value == "true" || value == "yes" ||
         value == "True";
}

const char *mode_name(uint8_t mode) {
  switch (mode) {
    case mode::AUTO: return "auto";
    case mode::COOL: return "cool";
    case mode::DRY: return "dry";
    case mode::HEAT: return "heat";
    case mode::FAN_ONLY: return "fan_only";
    case mode::SMART_DRY: return "smart_dry";
    default: return "unknown";
  }
}

bool parse_mode(const std::string &text, uint8_t *out) {
  if (text == "auto") *out = mode::AUTO;
  else if (text == "cool") *out = mode::COOL;
  else if (text == "dry") *out = mode::DRY;
  else if (text == "heat") *out = mode::HEAT;
  else if (text == "fan" || text == "fan_only") *out = mode::FAN_ONLY;
  else if (isdigit((unsigned char) text[0])) *out = (uint8_t) atoi(text.c_str());
  else return false;
  return true;
}

bool parse_fan(const std::string &text, uint8_t *out) {
  if (text == "auto") *out = fan::AUTO;
  else if (text == "silent") *out = fan::SILENT;
  else if (text == "low") *out = fan::LOW;
  else if (text == "medium") *out = fan::MEDIUM;
  else if (text == "high") *out = fan::HIGH;
  else if (text == "full") *out = fan::FULL;
  else if (isdigit((unsigned char) text[0])) *out = (uint8_t) atoi(text.c_str());
  else return false;
  return true;
}

bool parse_swing(const std::string &text, uint8_t *out) {
  if (text == "off") *out = swing::OFF;
  else if (text == "vertical") *out = swing::VERTICAL;
  else if (text == "horizontal") *out = swing::HORIZONTAL;
  else if (text == "both") *out = swing::BOTH;
  else return false;
  return true;
}

void print_state(const AcState &state) {
  printf("  power              %s\n", state.power ? "on" : "off");
  printf("  mode               %s\n", mode_name(state.mode));
  printf("  target_temperature %.1f C (%.0f F)\n", state.target_temperature,
         state.target_temperature * 9.0f / 5.0f + 32.0f);
  printf("  indoor_temperature %.1f C\n", state.indoor_temperature);
  if (state.outdoor_temperature != 0.0f)
    printf("  outdoor_temperature %.1f C\n", state.outdoor_temperature);
  printf("  fan_speed          %u\n", state.fan_speed);
  printf("  swing_mode         %u\n", state.swing_mode);
  printf("  eco                %s\n", state.eco ? "on" : "off");
  printf("  turbo              %s\n", state.turbo ? "on" : "off");
  printf("  sleep              %s\n", state.sleep ? "on" : "off");
  printf("  display            %s\n", state.display_on ? "on" : "off");
  printf("  fahrenheit_display %s\n", state.fahrenheit ? "on" : "off");
  printf("  target_humidity    %u\n", state.target_humidity);
  if (state.filter_alert)
    printf("  filter_alert       yes\n");
  if (state.error_code != 0)
    printf("  error_code         %u\n", state.error_code);
}

void print_capabilities(const Capabilities &caps) {
  printf("  modes              %s%s%s%s\n", caps.auto_mode ? "auto " : "",
         caps.cool_mode ? "cool " : "", caps.dry_mode ? "dry " : "",
         caps.heat_mode ? "heat" : "");
  printf("  fan speeds         %s%s%s%s%s\n",
         caps.supports_fan_silent() ? "silent " : "",
         caps.supports_fan_low() ? "low " : "",
         caps.supports_fan_medium() ? "medium " : "",
         caps.supports_fan_high() ? "high " : "",
         caps.supports_fan_auto() ? "auto" : "");
  printf("  cool range         %.1f - %.1f C\n", caps.cool_min_temperature,
         caps.cool_max_temperature);
  printf("  heat range         %.1f - %.1f C\n", caps.heat_min_temperature,
         caps.heat_max_temperature);
  printf("  presets            %s%s%s\n", caps.eco ? "eco " : "",
         caps.turbo_cool || caps.turbo_heat ? "turbo " : "",
         caps.freeze_protection ? "freeze_protection" : "");
}

int command_discover() {
  printf("Discovering appliances...\n");
  int found = 0;
  std::string error;
  coolth_cli::discover(5, [&](const std::string &ip, const Bytes &response) {
    DiscoveredDevice device;
    if (!parse_discovery_response(response, &device)) {
      if (device.version == 1)
        printf("  %s  V1 device, not supported\n", ip.c_str());
      else
        printf("  %s  unrecognised reply (%zu bytes)\n", ip.c_str(), response.size());
      return;
    }
    found++;
    printf("\n  %s:%u\n", device.ip.c_str(), device.port);
    printf("    id       %llu\n", (unsigned long long) device.device_id);
    printf("    name     %s\n", device.name.c_str());
    printf("    serial   %s\n", device.serial.c_str());
    printf("    type     0x%02X%s\n", device.device_type,
           device.device_type == 0xAC ? " (air conditioner)" : "");
    printf("    version  %u%s\n", device.version,
           device.version == 3 ? " (needs a token and key)" : "");
  }, &error);
  printf("\nFound %d device(s).\n", found);
  return found > 0 ? 0 : 1;
}

// Fetches a token and key from the cloud, for --auto.
bool resolve_credentials(Options *options) {
  if (options->account.empty() || options->password.empty()) {
    fprintf(stderr, "--auto needs --account and --password\n");
    return false;
  }
  std::string error;
  NetHomePlusCloud cloud(options->account, options->password,
                         coolth_cli::make_http_post(&error));
  if (!error.empty()) {
    fprintf(stderr, "%s\n", error.c_str());
    return false;
  }
  cloud.set_timestamp(now_stamp());
  DeviceCredentials credentials;
  if (!cloud.get_credentials(options->device_id, &credentials, &error)) {
    fprintf(stderr, "could not fetch credentials: %s\n", error.c_str());
    return false;
  }
  options->token = credentials.token;
  options->key = credentials.key;
  fprintf(stderr, "Fetched credentials for %llu.\n",
          (unsigned long long) options->device_id);
  return true;
}

// One exchange, over whichever transport the options select.
bool exchange(const Options &options, const Bytes &frame, Bytes *reply,
              std::string *error) {
  if (options.cloud) {
    CloudLAN relay(options.device_id, options.account, options.password,
                   coolth_cli::make_http_post(error));
    if (!error->empty())
      return false;
    relay.set_timestamp(now_stamp());
    uint8_t stamp[8];
    CloudLAN::make_timestamp(2026, 1, 1, 0, 0, 0, 0, stamp);
    relay.set_packet_timestamp(stamp);
    if (!relay.login(error))
      return false;
    return relay.send(frame, reply, error);
  }

  coolth_cli::Socket handle = coolth_cli::kInvalidSocket;
  Connection connection;
  if (!coolth_cli::tcp_connect(options.host, 6444, options.timeout, &handle,
                               &connection)) {
    *error = "could not connect to " + options.host + ":6444";
    return false;
  }
  LanTransport lan(options.device_id);
  lan.set_connection(connection);
  uint8_t stamp[8];
  now_packet_timestamp(stamp);
  lan.set_timestamp(stamp);
  if (!options.token.empty() && !options.key.empty())
    lan.set_credentials(from_hex(options.token), from_hex(options.key));
  const bool ok = lan.send_frame(frame, reply, error);
  coolth_cli::tcp_close(handle);
  return ok;
}

int command_query(const Options &options) {
  std::string error;
  Bytes reply;
  if (!exchange(options, build_get_state_frame(1), &reply, &error)) {
    fprintf(stderr, "query failed: %s\n", error.c_str());
    return 1;
  }
  AcState state;
  if (!parse_state_frame(reply, &state)) {
    fprintf(stderr, "unexpected reply: %s\n", to_hex(reply).c_str());
    return 1;
  }
  printf("State:\n");
  print_state(state);

  Bytes caps_reply;
  if (exchange(options, build_get_capabilities_frame(false, 2), &caps_reply,
               &error)) {
    Capabilities caps;
    if (parse_capabilities_frame(caps_reply, &caps)) {
      printf("\nCapabilities:\n");
      print_capabilities(caps);
    }
  }
  return 0;
}

int command_control(const Options &options) {
  std::string error;
  // Read first: a set command replaces every field, so anything not named on
  // the command line has to be carried over rather than defaulted.
  Bytes reply;
  if (!exchange(options, build_get_state_frame(1), &reply, &error)) {
    fprintf(stderr, "could not read current state: %s\n", error.c_str());
    return 1;
  }
  AcState state;
  if (!parse_state_frame(reply, &state)) {
    fprintf(stderr, "unexpected reply: %s\n", to_hex(reply).c_str());
    return 1;
  }
  state.beep = false;

  for (const auto &setting : options.settings) {
    const std::string &name = setting.first;
    const std::string &value = setting.second;
    if (name == "power") state.power = truthy(value);
    else if (name == "target_temperature") state.target_temperature = atof(value.c_str());
    else if (name == "mode" || name == "operational_mode") {
      if (!parse_mode(value, &state.mode)) {
        fprintf(stderr, "unknown mode: %s\n", value.c_str());
        return 2;
      }
    } else if (name == "fan_speed") {
      if (!parse_fan(value, &state.fan_speed)) {
        fprintf(stderr, "unknown fan speed: %s\n", value.c_str());
        return 2;
      }
    } else if (name == "swing_mode") {
      if (!parse_swing(value, &state.swing_mode)) {
        fprintf(stderr, "unknown swing mode: %s\n", value.c_str());
        return 2;
      }
    }
    else if (name == "eco") state.eco = truthy(value);
    else if (name == "turbo") state.turbo = truthy(value);
    else if (name == "sleep") state.sleep = truthy(value);
    else if (name == "beep") state.beep = truthy(value);
    else if (name == "fahrenheit") state.fahrenheit = truthy(value);
    else if (name == "purifier") state.purifier = truthy(value);
    else if (name == "freeze_protection") state.freeze_protection = truthy(value);
    else if (name == "target_humidity")
      state.target_humidity = (uint8_t) atoi(value.c_str());
    else {
      fprintf(stderr, "unknown setting: %s\n", name.c_str());
      return 2;
    }
  }

  Bytes confirm;
  if (!exchange(options, build_set_state_frame(state, 3), &confirm, &error)) {
    fprintf(stderr, "control failed: %s\n", error.c_str());
    return 1;
  }
  AcState applied;
  if (parse_state_frame(confirm, &applied)) {
    printf("Applied:\n");
    print_state(applied);
  } else {
    printf("Command accepted.\n");
  }
  return 0;
}

}  // namespace

int main(int argc, char **argv) {
  if (argc < 2) {
    usage();
    return 2;
  }
  const std::string command = argv[1];
  if (command == "-h" || command == "--help" || command == "help") {
    usage();
    return 0;
  }

  Options options;
  int index = 2;
  if (command != "discover" && index < argc && argv[index][0] != '-' &&
      strchr(argv[index], '=') == nullptr) {
    options.host = argv[index++];
  }
  for (; index < argc; index++) {
    const std::string argument = argv[index];
    auto next = [&]() -> std::string {
      return index + 1 < argc ? argv[++index] : std::string();
    };
    if (argument == "--token") options.token = next();
    else if (argument == "--key") options.key = next();
    else if (argument == "--id") options.device_id = strtoull(next().c_str(), nullptr, 10);
    else if (argument == "--cloud") options.cloud = true;
    else if (argument == "--auto") options.auto_credentials = true;
    else if (argument == "--account") options.account = next();
    else if (argument == "--password") options.password = next();
    else if (argument == "--timeout") options.timeout = atoi(next().c_str());
    else if (argument.find('=') != std::string::npos) {
      const size_t split = argument.find('=');
      options.settings.emplace_back(argument.substr(0, split),
                                    argument.substr(split + 1));
    } else {
      fprintf(stderr, "unknown argument: %s\n", argument.c_str());
      return 2;
    }
  }

  // With --cloud the host is the appliance id rather than an address.
  if (options.cloud && options.device_id == 0 && !options.host.empty())
    options.device_id = strtoull(options.host.c_str(), nullptr, 10);

  if (command == "discover")
    return command_discover();

  if (options.host.empty() && !options.cloud) {
    fprintf(stderr, "a host is required\n");
    return 2;
  }
  if (options.auto_credentials && !resolve_credentials(&options))
    return 1;

  if (command == "query")
    return command_query(options);
  if (command == "control")
    return command_control(options);

  fprintf(stderr, "unknown command: %s\n", command.c_str());
  usage();
  return 2;
}
