#include "wxcx_addmsg.h"
#include <algorithm>
#include <limits>

namespace wxcx::messages {
namespace {
bool Add(uintptr_t value, size_t offset, uintptr_t& out) {
    if (offset > (std::numeric_limits<uintptr_t>::max)() - value) return false;
    out = value + offset; return true;
}
struct Reader {
    ReadMemory read; void* context;
    bool Bytes(uintptr_t base, size_t offset, void* out, size_t count) const {
        uintptr_t address;
        return base >= 0x10000 && Add(base, offset, address) && count <= (std::numeric_limits<uintptr_t>::max)() - address &&
            read(address, out, count, context);
    }
    template<class T> bool Value(uintptr_t base, size_t offset, T& out) const {
        return Bytes(base, offset, &out, sizeof(out));
    }
};
bool CopyString(const Reader& reader, uintptr_t representation, char* out, size_t max,
                uint32_t& copied, bool& complete) {
    uint64_t length = 0, capacity = 0;
    copied = 0; complete = true;
    if (!reader.Value(representation, 16, length) || !reader.Value(representation, 24, capacity) ||
        length > capacity || length > 1048576 || capacity > 1048576 || capacity < 15) return false;
    uintptr_t data = representation;
    if (capacity >= 16 && !reader.Value(representation, 0, data)) return false;
    const size_t count = static_cast<size_t>((std::min)(length, static_cast<uint64_t>(max)));
    if (count && !reader.Bytes(data, 0, out, count)) return false;
    copied = static_cast<uint32_t>(count); complete = count == length;
    return true;
}
bool ArenaString(const Reader& reader, uintptr_t item, size_t offset, uintptr_t module,
                 char* out, size_t max, uint32_t& copied, bool& complete) {
    uintptr_t wrapper = 0, vtable = 0, representation = 0, expected = 0;
    return Add(module, 0x82643A8, expected) && reader.Value(item, offset, wrapper) &&
        reader.Value(wrapper, 0, vtable) && vtable == expected && reader.Value(wrapper, 8, representation) &&
        CopyString(reader, representation, out, max, copied, complete);
}
}
bool DecodeAddMsg(uintptr_t item, uintptr_t module, ReadMemory memory, void* context, RawMessage& out) noexcept {
    if (!memory || module < 0x10000) return false;
    const Reader reader{memory, context};
    uintptr_t vtable = 0, expected = 0; uint32_t bits = 0;
    if (!Add(module, 0x83DF408, expected) || !reader.Value(item, 0, vtable) || vtable != expected ||
        !reader.Value(item, 0x6C, bits) || (bits & 0x1E) != 0x1E || !reader.Value(item, 0x14, out.type)) return false;
    bool full = false;
    if (!ArenaString(reader, item, 8, module, out.from, sizeof(out.from), out.from_size, full) || !full || !out.from_size ||
        !ArenaString(reader, item, 0x18, module, out.to, sizeof(out.to), out.to_size, full) || !full || !out.to_size ||
        !ArenaString(reader, item, 0x20, module, out.content, sizeof(out.content), out.content_size, out.content_complete)) return false;
    // Generated AddMsg parser: field 9/bit0x100 -> +0x48 (seconds);
    // field 12/bit0x800 -> +0x50 (64-bit NewMsgId). No old 32-bit fallback.
    if ((bits & 0x100) && !reader.Value(item, 0x48, out.create_time)) return false;
    if ((bits & 0x800) && !reader.Value(item, 0x50, out.server_id)) return false;
    // Field10 is a pointer to a std::string, not an ArenaStringPtr wrapper.
    out.msgsource_known = true;
    if (bits & 0x200) {
        uintptr_t source = 0;
        if (!reader.Value(item, 0x38, source) ||
            !CopyString(reader, source, out.msgsource, sizeof(out.msgsource), out.source_size, out.msgsource_complete)) {
            out.msgsource_known = false; out.msgsource_complete = false; out.source_size = 0;
        }
    }
    return true;
}
}
