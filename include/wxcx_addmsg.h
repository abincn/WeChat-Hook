#pragma once
#include <cstddef>
#include <cstdint>

namespace wxcx::messages {
// Fixed buffers cross the native hook boundary. No borrowed native pointers
// survive publication. Offsets apply only to the fingerprinted 4.1.10.27 DLL.
struct RawMessage {
    uint64_t sequence = 0, epoch = 0, received_tick = 0, server_id = 0;
    uint32_t type = 0, create_time = 0;
    uint32_t from_size = 0, to_size = 0, content_size = 0, source_size = 0;
    bool msgsource_known = false, content_complete = true, msgsource_complete = true;
    char from[256]{}, to[256]{}, content[16384]{}, msgsource[8192]{};
};
using ReadMemory = bool (*)(uintptr_t address, void* output, size_t size, void* context);
// Caller initializes out; sequence/epoch/tick are caller-owned. False means
// required fields were not verified. Optional malformed metadata stays unknown.
bool DecodeAddMsg(uintptr_t item, uintptr_t module, ReadMemory, void* context, RawMessage& out) noexcept;
}
