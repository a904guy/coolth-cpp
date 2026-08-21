// Just enough JSON to read the cloud's replies.
//
// The responses have a known, shallow shape, and pulling cJSON in would cost
// the library its "mbedtls and nothing else" property. This reads string and
// integer fields by key and splits an array of objects. It is not a general
// parser and does not try to be: it handles escapes and skips over nested
// structures so a key match is never taken from the wrong depth.
#pragma once

#include <string>
#include <vector>

namespace coolth {
namespace json {

// Value of "key" as a string, searched at any depth. Numbers and quoted
// strings both come back as text, since the cloud is inconsistent about
// quoting numeric fields (errorCode arrives as "0" in some replies, 0 in
// others).
bool find_value(const std::string &text, const std::string &key,
                std::string *out);

// The object at "key", as a substring, so a nested lookup can be scoped to it.
bool find_object(const std::string &text, const std::string &key,
                 std::string *out);

// Each element of the array at "key", as a substring.
std::vector<std::string> find_array_objects(const std::string &text,
                                            const std::string &key);

}  // namespace json
}  // namespace coolth
