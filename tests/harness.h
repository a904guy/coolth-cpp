// Shared assertion helpers for the golden-vector tests.
#pragma once

#include <cstdio>
#include <string>

#include "../components/coolth/protocol.h"

inline int g_failures = 0;
inline int g_checks = 0;

inline void expect_hex(const char *name, const coolth::Bytes &actual,
                       const std::string &expected) {
  g_checks++;
  const std::string got = coolth::to_hex(actual);
  if (got == expected) {
    printf("  ok   %s (%zu bytes)\n", name, actual.size());
    return;
  }
  g_failures++;
  printf("  FAIL %s\n    expected %s\n    actual   %s\n", name,
         expected.c_str(), got.c_str());
}

inline void expect_eq(const char *name, const std::string &actual,
                      const std::string &expected) {
  g_checks++;
  if (actual == expected) {
    printf("  ok   %s%s\n", name,
           actual.size() < 40 ? (" = " + actual).c_str() : "");
    return;
  }
  g_failures++;
  printf("  FAIL %s\n    expected %s\n    actual   %s\n", name,
         expected.c_str(), actual.c_str());
}

inline void expect_int(const char *name, long actual, long expected) {
  g_checks++;
  if (actual == expected) {
    printf("  ok   %s = %ld\n", name, actual);
    return;
  }
  g_failures++;
  printf("  FAIL %s: expected %ld, actual %ld\n", name, expected, actual);
}

inline void expect_near(const char *name, float actual, float expected) {
  g_checks++;
  if (actual > expected - 0.01f && actual < expected + 0.01f) {
    printf("  ok   %s (%.2f)\n", name, actual);
    return;
  }
  g_failures++;
  printf("  FAIL %s: expected %.2f, actual %.2f\n", name, expected, actual);
}

inline void expect_true(const char *name, bool condition) {
  g_checks++;
  if (condition) {
    printf("  ok   %s\n", name);
    return;
  }
  g_failures++;
  printf("  FAIL %s\n", name);
}

inline int report() {
  printf("\n%d checks, %d failures\n", g_checks, g_failures);
  return g_failures == 0 ? 0 : 1;
}

// Wraps a payload in a 0xAA frame so response fixtures read like real ones.
inline coolth::Bytes make_response(const std::string &hex, uint8_t device_type,
                                   uint8_t frame_type) {
  coolth::Bytes payload = coolth::from_hex(hex);
  coolth::Bytes frame(10, 0);
  frame[0] = 0xAA;
  frame[2] = device_type;
  frame[9] = frame_type;
  frame.insert(frame.end(), payload.begin(), payload.end());
  frame[1] = static_cast<uint8_t>(payload.size() + 10);
  frame.push_back(0x00);  // checksum, not verified on the read path
  return frame;
}
