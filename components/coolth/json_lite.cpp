#include "json_lite.h"

#include <cctype>

namespace coolth {
namespace json {
namespace {

// Index just past the value starting at `pos`, skipping nested braces,
// brackets and strings. Returns npos if the document is malformed.
size_t skip_value(const std::string &text, size_t pos) {
  while (pos < text.size() && isspace((unsigned char) text[pos])) pos++;
  if (pos >= text.size())
    return std::string::npos;

  if (text[pos] == '"') {
    for (size_t i = pos + 1; i < text.size(); i++) {
      if (text[i] == '\\') {
        i++;
        continue;
      }
      if (text[i] == '"')
        return i + 1;
    }
    return std::string::npos;
  }

  if (text[pos] == '{' || text[pos] == '[') {
    const char open = text[pos], close = open == '{' ? '}' : ']';
    int depth = 0;
    for (size_t i = pos; i < text.size(); i++) {
      if (text[i] == '"') {
        const size_t end = skip_value(text, i);
        if (end == std::string::npos)
          return std::string::npos;
        i = end - 1;
        continue;
      }
      if (text[i] == open)
        depth++;
      else if (text[i] == close && --depth == 0)
        return i + 1;
    }
    return std::string::npos;
  }

  // A bare literal: number, true, false, null.
  size_t i = pos;
  while (i < text.size() && text[i] != ',' && text[i] != '}' && text[i] != ']')
    i++;
  return i;
}

std::string unescape(const std::string &raw) {
  std::string out;
  out.reserve(raw.size());
  for (size_t i = 0; i < raw.size(); i++) {
    if (raw[i] != '\\') {
      out.push_back(raw[i]);
      continue;
    }
    if (++i >= raw.size())
      break;
    switch (raw[i]) {
      case 'n': out.push_back('\n'); break;
      case 't': out.push_back('\t'); break;
      case 'r': out.push_back('\r'); break;
      case 'b': out.push_back('\b'); break;
      case 'f': out.push_back('\f'); break;
      case 'u': {
        // The cloud escapes control bytes this way, and the IV-recovery echo
        // is raw bytes inside an error string -- so these must be decoded, not
        // passed through, or the recovered block is the wrong length.
        if (i + 4 >= raw.size()) {
          i = raw.size();
          break;
        }
        int value = 0;
        bool valid = true;
        for (int digit = 1; digit <= 4; digit++) {
          const char c = raw[i + digit];
          value <<= 4;
          if (c >= '0' && c <= '9') value |= c - '0';
          else if (c >= 'a' && c <= 'f') value |= c - 'a' + 10;
          else if (c >= 'A' && c <= 'F') value |= c - 'A' + 10;
          else { valid = false; break; }
        }
        if (!valid) {
          out.push_back(raw[i]);
          break;
        }
        i += 4;
        // Only the Latin-1 range is emitted as a single byte; anything higher
        // is genuine text, so encode it as UTF-8 rather than truncating.
        if (value < 0x80) {
          out.push_back(static_cast<char>(value));
        } else if (value < 0x800) {
          out.push_back(static_cast<char>(0xC0 | (value >> 6)));
          out.push_back(static_cast<char>(0x80 | (value & 0x3F)));
        } else {
          out.push_back(static_cast<char>(0xE0 | (value >> 12)));
          out.push_back(static_cast<char>(0x80 | ((value >> 6) & 0x3F)));
          out.push_back(static_cast<char>(0x80 | (value & 0x3F)));
        }
        break;
      }
      default: out.push_back(raw[i]); break;
    }
  }
  return out;
}

// Locate `"key"` used as a key (followed by a colon), not as a value.
size_t find_key(const std::string &text, const std::string &key, size_t from) {
  const std::string needle = "\"" + key + "\"";
  size_t pos = from;
  while ((pos = text.find(needle, pos)) != std::string::npos) {
    size_t after = pos + needle.size();
    while (after < text.size() && isspace((unsigned char) text[after])) after++;
    if (after < text.size() && text[after] == ':')
      return after + 1;
    pos += needle.size();
  }
  return std::string::npos;
}

}  // namespace

bool find_value(const std::string &text, const std::string &key,
                std::string *out) {
  const size_t start = find_key(text, key, 0);
  if (start == std::string::npos)
    return false;
  const size_t end = skip_value(text, start);
  if (end == std::string::npos)
    return false;

  size_t begin = start;
  while (begin < end && isspace((unsigned char) text[begin])) begin++;
  if (begin < end && text[begin] == '"') {
    *out = unescape(text.substr(begin + 1, end - begin - 2));
    return true;
  }
  *out = text.substr(begin, end - begin);
  // Trim trailing whitespace left by a bare literal.
  while (!out->empty() && isspace((unsigned char) out->back())) out->pop_back();
  return true;
}

bool find_object(const std::string &text, const std::string &key,
                 std::string *out) {
  const size_t start = find_key(text, key, 0);
  if (start == std::string::npos)
    return false;
  size_t begin = start;
  while (begin < text.size() && isspace((unsigned char) text[begin])) begin++;
  if (begin >= text.size() || text[begin] != '{')
    return false;
  const size_t end = skip_value(text, begin);
  if (end == std::string::npos)
    return false;
  *out = text.substr(begin, end - begin);
  return true;
}

std::vector<std::string> find_array_objects(const std::string &text,
                                            const std::string &key) {
  std::vector<std::string> items;
  const size_t start = find_key(text, key, 0);
  if (start == std::string::npos)
    return items;
  size_t pos = start;
  while (pos < text.size() && isspace((unsigned char) text[pos])) pos++;
  if (pos >= text.size() || text[pos] != '[')
    return items;

  const size_t array_end = skip_value(text, pos);
  if (array_end == std::string::npos)
    return items;

  pos++;  // step into the array
  while (pos < array_end) {
    while (pos < array_end && (isspace((unsigned char) text[pos]) || text[pos] == ','))
      pos++;
    if (pos >= array_end || text[pos] == ']')
      break;
    const size_t end = skip_value(text, pos);
    if (end == std::string::npos)
      break;
    items.push_back(text.substr(pos, end - pos));
    pos = end;
  }
  return items;
}

}  // namespace json
}  // namespace coolth
