#pragma once
// Lossless identifiers: no floats, signs, whitespace, prefixes or truncation.
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>

namespace wxcx { namespace ids {
inline bool ParseDecimalUint64(std::string_view text, uint64_t& out)
{
    if (text.empty()) return false;
    uint64_t value = 0;
    for (const char c : text)
    {
        if (c < '0' || c > '9') return false;
        const uint64_t digit = static_cast<uint64_t>(c - '0');
        if (value > ((std::numeric_limits<uint64_t>::max)() - digit) / 10)
            return false;
        value = value * 10 + digit;
    }
    out = value;
    return true;
}

// Accept json or ordered_json; leave out unchanged on failure. In particular,
// reject JSON floats, including integer tokens the JSON parser overflowed to REAL.
template<class Json> bool ParseUint64(const Json& value, uint64_t& out)
{
    if (value.is_string())
        return ParseDecimalUint64(value.template get_ref<const typename Json::string_t&>(), out);
    if (value.is_number_unsigned())
    {
        out = value.template get<uint64_t>();
        return true;
    }
    if (value.is_number_integer())
    {
        const auto signedValue = value.template get<typename Json::number_integer_t>();
        if (signedValue < 0) return false;
        out = static_cast<uint64_t>(signedValue);
        return true;
    }
    return false;
}

template<class Json> bool ParseLocalId(const Json& value, uint64_t& out)
{
    uint64_t parsed = 0;
    if (!ParseUint64(value, parsed) || parsed == 0 ||
        parsed > (std::numeric_limits<uint32_t>::max)()) return false;
    out = parsed;
    return true;
}

inline std::string_view Basename(std::string_view path)
{
    const auto pos = path.find_last_of("/\\");
    return pos == std::string_view::npos ? path : path.substr(pos + 1);
}

// Filename evidence ONLY, never a verified native database index. Match exactly
// MSG<1..10 decimal digits>.db in the basename and bound it to uint32_t.
inline bool ParseDbIndexCandidate(std::string_view path, uint32_t& out)
{
    const auto name = Basename(path);
    if (name.size() < 7 || name.size() > 16 || name.substr(0, 3) != "MSG" ||
        name.substr(name.size() - 3) != ".db") return false;
    uint64_t parsed = 0;
    if (!ParseDecimalUint64(name.substr(3, name.size() - 6), parsed) ||
        parsed > (std::numeric_limits<uint32_t>::max)()) return false;
    out = static_cast<uint32_t>(parsed);
    return true;
}
} }
