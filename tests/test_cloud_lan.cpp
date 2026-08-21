// The cloud relay: same 0xAA frames, a completely different way of moving them.

#include <cstring>
#include <vector>

#include "../components/coolth/cloud_lan.h"
#include "golden_vectors.h"
#include "harness.h"

using namespace coolth;

int main() {
  const Bytes timestamp = from_hex(GOLDEN_CL_TIMESTAMP);

  printf("relay packet\n");
  {
    expect_eq("5A5A packet",
              to_hex(CloudLAN::build_5a5a_packet(from_hex(GOLDEN_CL_FRAME),
                                                 GOLDEN_DEVICE_ID, 1001,
                                                 timestamp.data())),
              GOLDEN_CL_PACKET);

    // The frame rides in the clear here, unlike the LAN packet where it is
    // AES-ECB encrypted. Easy to conflate the two.
    const Bytes packet = CloudLAN::build_5a5a_packet(
        from_hex(GOLDEN_CL_FRAME), GOLDEN_DEVICE_ID, 1001, timestamp.data());
    Bytes recovered;
    expect_true("frame is recoverable from the packet",
                CloudLAN::extract_aa(packet, &recovered));
    expect_eq("recovered frame", to_hex(recovered), GOLDEN_CL_FRAME);

    Bytes none;
    expect_true("no frame in a packet without one",
                !CloudLAN::extract_aa(Bytes(40, 0x00), &none));
    expect_true("truncated frame rejected",
                !CloudLAN::extract_aa(Bytes{0xAA, 0x40, 0x01}, &none));
  }

  printf("\nsigned-byte text encoding\n");
  {
    // Values above 127 are written negative. Send them unsigned and the cloud
    // accepts the order while the appliance quietly ignores it.
    expect_eq("to text", CloudLAN::to_text(from_hex("007f80ffaa")),
              GOLDEN_CL_TO_TEXT);
    expect_eq("from text", to_hex(CloudLAN::from_text(GOLDEN_CL_TO_TEXT)),
              GOLDEN_CL_FROM_TEXT);
    expect_eq("round trip",
              to_hex(CloudLAN::from_text(CloudLAN::to_text(from_hex(GOLDEN_CL_PACKET)))),
              GOLDEN_CL_PACKET);
    expect_eq("trailing separators tolerated",
              to_hex(CloudLAN::from_text("1,2,3,")), "010203");
  }

  printf("\nsession crypto\n");
  {
    expect_eq("session key from access token",
              to_hex(CloudLAN::derive_key(GOLDEN_CL_APP_KEY, GOLDEN_CL_ACCESS_TOKEN)),
              GOLDEN_CL_DERIVED_KEY);
    expect_eq("password hash",
              CloudLAN::password_hash(GOLDEN_CLOUD_PASSWORD_LOGIN_ID,
                                      GOLDEN_CLOUD_PASSWORD_PLAIN,
                                      GOLDEN_CL_APP_KEY),
              GOLDEN_CL_PASSWORD_HASH);

    const std::map<std::string, std::string> body = {
        {"src", "17"},               {"format", "2"},
        {"stamp", "20260819123456"}, {"language", "en_US"},
        {"sessionId", "SESSION456"},
        {"applianceId", std::to_string(GOLDEN_DEVICE_ID)},
        {"funId", "0008"},           {"order", "abcdef"},
    };
    expect_eq("request signature",
              CloudLAN::sign("/v1/appliance/transparent/send/new", body,
                             GOLDEN_CL_APP_KEY),
              GOLDEN_CL_SIGN);
  }

  printf("\npacket timestamp\n");
  {
    // A different layout again from the LAN packet's: month is zero-based and
    // the hour is modulo 12, so 19:00 becomes 7.
    uint8_t out[8];
    CloudLAN::make_timestamp(2026, 8, 19, 19, 7, 30, 100, out);
    expect_eq("layout", to_hex(Bytes(out, out + 8)), "641e070713071a14");
  }

  printf("\nfull relay flow (canned responses)\n");
  {
    // The IV is never sent. The server decrypts with the real one and echoes
    // the result in an error string, so a known plaintext under a zero IV
    // reveals it. Reproduce that here to check the recovery arithmetic.
    const Bytes session_key = from_hex(GOLDEN_CL_DERIVED_KEY);
    const Bytes real_iv = from_hex("000102030405060708090a0b0c0d0e0f");

    std::vector<std::string> urls;
    auto post = [&](const std::string &url, const std::string &,
                    const std::string &body, std::string *response) {
      urls.push_back(url);
      if (url.find("/login/id/get") != std::string::npos) {
        *response = R"({"result":{"loginId":"LOGIN123"}})";
        return true;
      }
      if (url.find("/v1/user/login") != std::string::npos) {
        *response = std::string(R"({"result":{"sessionId":"SESSION456",)") +
                    R"("accessToken":")" + GOLDEN_CL_ACCESS_TOKEN + R"("}})";
        return true;
      }
      const size_t at = body.find("order=");
      const std::string order = body.substr(at + 6, body.find('&', at) - at - 6);
      const Bytes cipher = from_hex(order);

      static bool first = true;
      if (first) {
        first = false;
        const Bytes plain = aes_cbc_decrypt_iv(session_key, real_iv, cipher);
        // The echoed block is arbitrary bytes inside a JSON string, so a real
        // server escapes whatever would break it. Reproduce that, or the
        // fixture stops testing what it claims to.
        std::string echoed;
        char buffer[8];
        for (size_t i = 0; i < 16; i++) {
          const uint8_t byte = plain[i];
          if (byte == '"' || byte == '\\') {
            echoed.push_back('\\');
            echoed.push_back(static_cast<char>(byte));
          } else if (byte < 0x20) {
            snprintf(buffer, sizeof(buffer), "\\u%04x", byte);
            echoed += buffer;
          } else {
            echoed.push_back(static_cast<char>(byte));
          }
        }
        *response = R"({"msg":"illegal order:)" + echoed + R"("})";
        return true;
      }
      const Bytes packet = CloudLAN::build_5a5a_packet(
          from_hex(GOLDEN_LIVE_STATE_FRAME), GOLDEN_DEVICE_ID, 1,
          from_hex(GOLDEN_CL_TIMESTAMP).data());
      const std::string text = CloudLAN::to_text(packet);
      const Bytes encrypted = aes_cbc_encrypt_iv(
          session_key, real_iv, pkcs7_pad(Bytes(text.begin(), text.end())));
      *response = R"({"errorCode":"0","result":{"reply":")" + to_hex(encrypted) +
                  R"("}})";
      return true;
    };

    CloudLAN relay(GOLDEN_DEVICE_ID, "user@example.com", "hunter2", post);
    relay.set_timestamp("20260819123456");
    uint8_t stamp[8];
    memcpy(stamp, from_hex(GOLDEN_CL_TIMESTAMP).data(), 8);
    relay.set_packet_timestamp(stamp);

    std::string error;
    expect_true("login and IV recovery succeed", relay.login(&error));
    expect_true("logged in", relay.logged_in());

    Bytes reply;
    expect_true("send succeeds",
                relay.send(from_hex(GOLDEN_GET_STATE_FRAME), &reply, &error));
    expect_eq("reply is the appliance's state frame", to_hex(reply),
              GOLDEN_LIVE_STATE_FRAME);

    // A set is accepted without a synchronous frame; that is success, and the
    // caller must not read the empty reply as a failure.
    auto async_post = [](const std::string &url, const std::string &,
                         const std::string &, std::string *response) {
      if (url.find("/login/id/get") != std::string::npos)
        *response = R"({"result":{"loginId":"L"}})";
      else if (url.find("/v1/user/login") != std::string::npos)
        *response = std::string(R"({"result":{"sessionId":"S","accessToken":")") +
                    GOLDEN_CL_ACCESS_TOKEN + R"("}})";
      else
        *response = R"({"errorCode":"3176","msg":"async"})";
      return true;
    };
    CloudLAN async_relay(GOLDEN_DEVICE_ID, "a@b.com", "x", async_post);
    async_relay.set_timestamp("20260819123456");
    expect_true("IV recovery fails without an echo", !async_relay.login(&error));
    expect_true("and says why", error.find("IV recovery") != std::string::npos);

    CloudLAN unstamped(GOLDEN_DEVICE_ID, "a@b.com", "x", post);
    expect_true("missing clock is caught", !unstamped.login(&error));
  }

  return report();
}
