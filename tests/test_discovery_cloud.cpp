// Discovery and both clouds, checked against coolth and against a discovery
// response captured from a real appliance.

#include <map>
#include <vector>

#include "../components/coolth/cloud.h"
#include "../components/coolth/discovery.h"
#include "../components/coolth/json_lite.h"
#include "golden_vectors.h"
#include "harness.h"

using namespace coolth;

int main() {
  printf("discovery\n");
  {
    expect_eq("probe matches coolth", to_hex(discovery_request()),
              GOLDEN_DISCOVERY_REQUEST);

    const Bytes response = from_hex(GOLDEN_LIVE_DISCOVERY_RESPONSE);
    expect_true("version is 3", discovery_version(response) == 3);

    DiscoveredDevice device;
    expect_true("live response parses",
                parse_discovery_response(response, &device));
    expect_eq("ip", device.ip, GOLDEN_LIVE_DISCOVERY_IP);
    expect_int("port", device.port, GOLDEN_LIVE_DISCOVERY_PORT);
    expect_true("device id", device.device_id == GOLDEN_LIVE_DISCOVERY_DEVICE_ID);
    expect_eq("name", device.name, GOLDEN_LIVE_DISCOVERY_NAME);
    expect_eq("serial", device.serial, GOLDEN_LIVE_DISCOVERY_SN);
    expect_int("device type is 0xAC", device.device_type,
               GOLDEN_LIVE_DISCOVERY_DEVICE_TYPE);

    DiscoveredDevice ignored;
    expect_true("short response rejected",
                !parse_discovery_response(Bytes(10, 0x83), &ignored));
    expect_true("unknown start byte rejected",
                discovery_version(Bytes{0x3C, 0x3F}) == 0);

    // V1 appliances answer with XML. They cannot be driven, but recognising
    // them lets a caller say so instead of reporting nothing found.
    const std::string xml =
        "<?xml version=" "\"1.0\"" "?><body><device port=" "\"6444\"" "/></body>";
    const Bytes v1(xml.begin(), xml.end());
    expect_int("V1 recognised", discovery_version(v1), 1);
    DiscoveredDevice v1_device;
    expect_true("V1 not parsed", !parse_discovery_response(v1, &v1_device));
    expect_int("V1 version still reported", v1_device.version, 1);
  }

  printf("\nudpid\n");
  {
    // The id's endianness is not discoverable, so both are tried in turn.
    expect_eq("little endian", udpid_hex(GOLDEN_DEVICE_ID, true),
              GOLDEN_UDPID_LITTLE);
    expect_eq("big endian", udpid_hex(GOLDEN_DEVICE_ID, false),
              GOLDEN_UDPID_BIG);
  }

  printf("\nNetHome Plus cloud\n");
  {
    const std::map<std::string, std::string> body = {
        {"appId", "1017"},        {"src", "1017"},
        {"format", "2"},          {"clientType", "1"},
        {"language", "en_US"},    {"deviceId", "0123456789abcdef"},
        {"stamp", "20260819123456"}, {"sessionId", ""},
        {"loginAccount", GOLDEN_CLOUD_ACCOUNT},
    };
    expect_eq("signature",
              NetHomePlusCloud::sign(GOLDEN_CLOUD_SIGN_ENDPOINT, body),
              GOLDEN_CLOUD_SIGN);
    expect_eq("password hash",
              NetHomePlusCloud::encrypt_password(GOLDEN_CLOUD_PASSWORD_LOGIN_ID,
                                                 GOLDEN_CLOUD_PASSWORD_PLAIN),
              GOLDEN_CLOUD_PASSWORD_HASH);

    // The posted form is percent-encoded even though the signed string is not.
    const std::string form = NetHomePlusCloud::form_encode(body);
    expect_true("form encodes the @ in an email",
                form.find("user%40example.com") != std::string::npos);
    expect_true("signed string is a sha256",
                NetHomePlusCloud::sign("/x", body).size() == 64);
  }

  printf("\njson reader\n");
  {
    std::string value;
    expect_true("string field",
                json::find_value(R"({"a":"x","b":"y"})", "b", &value) && value == "y");
    expect_true("numeric field",
                json::find_value(R"({"errorCode":0})", "errorCode", &value) && value == "0");
    expect_true("quoted number",
                json::find_value(R"({"errorCode":"0"})", "errorCode", &value) && value == "0");
    expect_true("escaped quote",
                json::find_value(R"({"msg":"a\"b"})", "msg", &value) && value == "a\"b");
    // A key that appears as a *value* must not be mistaken for a field.
    expect_true("value that looks like a key is skipped",
                json::find_value(R"({"a":"\"token\":1","token":"real"})", "token", &value) &&
                    value == "real");
    expect_true("missing key", !json::find_value(R"({"a":1})", "zzz", &value));
    // Control bytes arrive u-escaped. They must decode back to single bytes:
    // the cloud relay's IV recovery reads a fixed-length block out of an error
    // string, and passing them through would leave it the wrong length.
    expect_true("unicode escape decodes to one byte",
                json::find_value(R"({"a":"x\u0007y"})", "a", &value) &&
                    value == std::string("x\x07y"));
    expect_true("non-latin escape becomes utf-8",
                json::find_value(R"({"a":"\u00e9"})", "a", &value) &&
                    value == "\xc3\xa9");

    std::string object;
    expect_true("nested object",
                json::find_object(R"({"result":{"loginId":"abc"}})", "result", &object));
    expect_true("nested lookup",
                json::find_value(object, "loginId", &value) && value == "abc");

    const auto items = json::find_array_objects(
        R"({"tokenlist":[{"udpId":"a","token":"t1"},{"udpId":"b","token":"t2"}]})",
        "tokenlist");
    expect_int("array split into 2", (long) items.size(), 2);
    if (items.size() == 2)
      expect_true("second element",
                  json::find_value(items[1], "token", &value) && value == "t2");
  }

  printf("\nNetHome Plus flow (canned responses)\n");
  {
    std::vector<std::string> urls, bodies;
    auto fake_post = [&](const std::string &url, const std::string &,
                         const std::string &body, std::string *response) {
      urls.push_back(url);
      bodies.push_back(body);
      if (url.find("/v1/user/login/id/get") != std::string::npos)
        *response = R"({"errorCode":"0","result":{"loginId":"LOGIN123"}})";
      else if (url.find("/v1/user/login") != std::string::npos)
        *response = R"({"errorCode":"0","result":{"sessionId":"SESSION456"}})";
      else if (url.find("getToken") != std::string::npos)
        *response = std::string(R"({"errorCode":"0","result":{"tokenlist":[)") +
                    R"({"udpId":"nope","token":"AA","key":"BB"},)" +
                    R"({"udpId":")" + udpid_hex(GOLDEN_DEVICE_ID, true) +
                    R"(","token":"TOKEN","key":"KEY"}]}})";
      else
        return false;
      return true;
    };

    NetHomePlusCloud cloud(GOLDEN_CLOUD_ACCOUNT, "hunter2", fake_post);
    cloud.set_timestamp("20260819123456");

    DeviceCredentials creds;
    std::string error;
    expect_true("get_credentials succeeds",
                cloud.get_credentials(GOLDEN_DEVICE_ID, &creds, &error));
    expect_eq("token", creds.token, "TOKEN");
    expect_eq("key", creds.key, "KEY");
    expect_eq("session captured", cloud.session_id(), "SESSION456");
    expect_int("three requests made", (long) urls.size(), 3);
    expect_true("every request is signed",
                bodies[0].find("sign=") != std::string::npos &&
                    bodies[2].find("sign=") != std::string::npos);
    expect_true("password never sent in the clear",
                bodies[1].find("hunter2") == std::string::npos);
    expect_true("session id carried into the token request",
                bodies[2].find("sessionId=SESSION456") != std::string::npos);

    auto failing_post = [](const std::string &, const std::string &,
                           const std::string &, std::string *response) {
      *response = R"({"errorCode":"3106","msg":"invalid session"})";
      return true;
    };
    NetHomePlusCloud bad("a@b.com", "x", failing_post);
    bad.set_timestamp("20260819123456");
    expect_true("cloud error propagates", !bad.login(&error));
    expect_true("error mentions the code",
                error.find("3106") != std::string::npos);

    // Without a clock the stamp is empty and the cloud rejects the login; fail
    // early with something actionable instead.
    NetHomePlusCloud unstamped("a@b.com", "x", fake_post);
    expect_true("missing timestamp is caught", !unstamped.login(&error));
    expect_true("error names the clock",
                error.find("clock") != std::string::npos);
  }

  printf("\nSmartHome cloud crypto\n");
  {
    // Same job, none of the same primitives: HMAC rather than a plain hash,
    // and two password fields derived by different routes.
    expect_eq("hmac signature",
              SmartHomeCloud::sign(GOLDEN_SH_SIGN_DATA, GOLDEN_SH_SIGN_RANDOM, false),
              GOLDEN_SH_SIGN);
    expect_eq("password",
              SmartHomeCloud::encrypt_password(GOLDEN_CLOUD_PASSWORD_LOGIN_ID,
                                               GOLDEN_CLOUD_PASSWORD_PLAIN, false),
              GOLDEN_SH_PASSWORD);
    expect_eq("iampwd",
              SmartHomeCloud::encrypt_iam_password(GOLDEN_CLOUD_PASSWORD_LOGIN_ID,
                                                   GOLDEN_CLOUD_PASSWORD_PLAIN, false),
              GOLDEN_SH_IAMPWD);

    // The China server swaps two constants and short-circuits iampwd, so all
    // three differ. Getting this wrong looks like a bad password.
    expect_eq("hmac signature (china)",
              SmartHomeCloud::sign(GOLDEN_SH_SIGN_DATA, GOLDEN_SH_SIGN_RANDOM, true),
              GOLDEN_SH_SIGN_CHINA);
    expect_eq("password (china)",
              SmartHomeCloud::encrypt_password(GOLDEN_CLOUD_PASSWORD_LOGIN_ID,
                                               GOLDEN_CLOUD_PASSWORD_PLAIN, true),
              GOLDEN_SH_PASSWORD_CHINA);
    expect_eq("iampwd (china)",
              SmartHomeCloud::encrypt_iam_password(GOLDEN_CLOUD_PASSWORD_LOGIN_ID,
                                                   GOLDEN_CLOUD_PASSWORD_PLAIN, true),
              GOLDEN_SH_IAMPWD_CHINA);
    expect_true("the two clouds derive different passwords",
                SmartHomeCloud::encrypt_password(GOLDEN_CLOUD_PASSWORD_LOGIN_ID,
                                                 GOLDEN_CLOUD_PASSWORD_PLAIN, false) !=
                    NetHomePlusCloud::encrypt_password(GOLDEN_CLOUD_PASSWORD_LOGIN_ID,
                                                       GOLDEN_CLOUD_PASSWORD_PLAIN));
  }

  printf("\nSmartHome flow (canned responses)\n");
  {
    std::vector<std::string> urls, bodies, header_blocks;
    auto fake_post = [&](const std::string &url, const std::string &headers,
                         const std::string &body, std::string *response) {
      urls.push_back(url);
      bodies.push_back(body);
      header_blocks.push_back(headers);
      if (url.find("/v1/user/login/id/get") != std::string::npos)
        *response = R"({"code":"0","data":{"loginId":"LOGIN123"}})";
      else if (url.find("/mj/user/login") != std::string::npos)
        *response = R"({"code":"0","data":{"mdata":{"accessToken":"ACCESS789"}}})";
      else if (url.find("getToken") != std::string::npos)
        *response = std::string(R"({"code":"0","data":{"tokenlist":[{"udpId":")") +
                    udpid_hex(GOLDEN_DEVICE_ID, true) +
                    R"(","token":"TOKEN","key":"KEY"}]}})";
      else
        return false;
      return true;
    };

    SmartHomeCloud cloud(GOLDEN_CLOUD_ACCOUNT, "hunter2", fake_post);
    cloud.set_timestamp("20260819123456");
    cloud.set_nonce_provider([](size_t bytes) { return std::string(bytes * 2, 'a'); });

    DeviceCredentials creds;
    std::string error;
    expect_true("get_credentials succeeds",
                cloud.get_credentials(GOLDEN_DEVICE_ID, &creds, &error));
    expect_eq("token", creds.token, "TOKEN");
    expect_eq("access token captured", cloud.access_token(), "ACCESS789");
    expect_true("requests go through the proxy endpoint",
                urls[0].find("/mas/v5/app/proxy?alias=") != std::string::npos);
    expect_true("signature travels in a header, not the body",
                header_blocks[0].find("sign: ") != std::string::npos &&
                    bodies[0].find(R"("sign")") == std::string::npos);
    expect_true("bodies are JSON, not form encoded",
                bodies[0].front() == '{' && bodies[0].find("&") == std::string::npos);
    expect_true("password never sent in the clear",
                bodies[1].find("hunter2") == std::string::npos);
    expect_true("login carries both password fields",
                bodies[1].find("iampwd") != std::string::npos &&
                    bodies[1].find(R"("password")") != std::string::npos);
    expect_true("access token carried into later requests",
                header_blocks[2].find("accessToken: ACCESS789") != std::string::npos);

    // This cloud reports failure as "code", not "errorCode".
    auto failing = [](const std::string &, const std::string &,
                      const std::string &, std::string *response) {
      *response = R"({"code":"40001","msg":"password error"})";
      return true;
    };
    SmartHomeCloud bad("a@b.com", "x", failing);
    bad.set_timestamp("20260819123456");
    expect_true("cloud error propagates", !bad.login(&error));
    expect_true("error carries the message",
                error.find("password error") != std::string::npos);
  }

  return report();
}
