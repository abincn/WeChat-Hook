#include "wxcx_forward_response.h"
#include <cstring>
#include <limits>
namespace wxcx { namespace forward { namespace {
struct Reader {
    const uint8_t* bytes; size_t size, pos = 0;
    bool Varint(uint64_t& value) {
        value = 0;
        for (unsigned n = 0; n < 10; ++n) {
            if (pos == size) return false;
            const auto b = bytes[pos++];
            if (n == 9 && b > 1) return false;
            value |= static_cast<uint64_t>(b & 127) << (n * 7);
            if (!(b & 128)) return true;
        }
        return false;
    }
    bool Block(const uint8_t*& data, size_t& length) {
        uint64_t n = 0; if (!Varint(n) || n > size - pos) return false;
        data = bytes + pos; length = static_cast<size_t>(n); pos += length; return true;
    }
    bool Skip(unsigned wire) {
        uint64_t value = 0; const uint8_t* block = nullptr; size_t length = 0;
        if (wire == 0) return Varint(value);
        if (wire == 2) return Block(block, length);
        const size_t take = wire == 1 ? 8 : wire == 5 ? 4 : 0;
        if (!take || take > size - pos) return false;
        pos += take; return true;
    }
    bool Tag(uint32_t& field, unsigned& wire) {
        uint64_t tag = 0;
        if (!Varint(tag) || (tag >> 3) == 0 || (tag >> 3) > 0x1FFFFFFFULL) return false;
        field = static_cast<uint32_t>(tag >> 3); wire = static_cast<unsigned>(tag & 7); return true;
    }
};
ResponseStatus Invalid(const char* why) { return {ResponseParseState::Invalid, {}, why}; }
ResponseStatus Base(const uint8_t* bytes, size_t size) {
    Reader reader{bytes, size}; std::optional<int32_t> result;
    while (reader.pos < reader.size) {
        uint32_t field = 0; unsigned wire = 0;
        if (!reader.Tag(field, wire)) return Invalid("Invalid BaseResponse tag/varint.");
        if (field == 1) {
            if (wire != 0 || result) return Invalid("Ambiguous or wrongly typed BaseResponse.ret.");
            uint64_t value = 0;
            if (!reader.Varint(value) || (value > UINT32_MAX && value < 0xFFFFFFFF80000000ULL))
                return Invalid("BaseResponse.ret is not an int32 varint.");
            const auto low = static_cast<uint32_t>(value); int32_t signedValue = 0;
            std::memcpy(&signedValue, &low, sizeof(low)); result = signedValue;
        } else if (!reader.Skip(wire)) return Invalid("Invalid/truncated BaseResponse field.");
    }
    if (!result) return {ResponseParseState::Missing, {}, "No explicit BaseResponse.ret."};
    return {ResponseParseState::Parsed, result, "Explicit BaseResponse.ret parsed; delivery remains unverified."};
}
} // namespace
ResponseStatus ParseSendAppMsgResponse(const uint8_t* bytes, size_t size) {
    if ((!bytes && size) || size > 8 * 1024 * 1024) return Invalid("Response buffer is absent or exceeds 8 MiB.");
    if (!size) return {ResponseParseState::Missing, {}, "No response bytes."};
    Reader reader{bytes, size}; ResponseStatus result; bool seen = false;
    while (reader.pos < reader.size) {
        uint32_t field = 0; unsigned wire = 0;
        if (!reader.Tag(field, wire)) return Invalid("Invalid response tag/varint.");
        if (field == 1) {
            if (wire != 2 || seen) return Invalid("Ambiguous or wrongly typed BaseResponse.");
            seen = true; const uint8_t* data = nullptr; size_t length = 0;
            if (!reader.Block(data, length)) return Invalid("Truncated BaseResponse.");
            result = Base(data, length);
            if (result.state == ResponseParseState::Invalid) return result;
        } else if (!reader.Skip(wire)) return Invalid("Invalid/truncated response field.");
    }
    if (!seen) return {ResponseParseState::Missing, {}, "BaseResponse is absent."};
    return result;
}
} }
