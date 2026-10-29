#pragma once
#include <cstdint>
#include <memory>
#include <string>

namespace wxcx::native {
enum class ProbePhase { Queued, Running, Observed, Discarded };
enum class ContextState { Absent, Present, Unreadable };
struct SchedulerObservation {
    ProbePhase phase = ProbePhase::Queued;
    uint32_t thread_id = 0;
    bool coroutine_context_present = false;
    bool context_readable = false;
    // This is a raw native queue return value, not a download/success result.
    bool post_returned = false;
    uint32_t post_result = 0;
};
class SchedulerProbe {
public:
    struct State;
    explicit SchedulerProbe(std::shared_ptr<State>);
    SchedulerObservation Snapshot() const;
private:
    std::shared_ptr<State> state_;
};
struct SchedulerProbeStart {
    std::shared_ptr<SchedulerProbe> probe;
    std::string error;
};
// Diagnostic binding, exposed only through the fixed scheduler diagnostic.
// Uses fresh module identity and the native queue; performs NO await, source
// lookup, key derivation, media download or send. Context presence alone does
// not verify that other native calls are safe. No captured heap addresses.
SchedulerProbeStart StartSchedulerProbe();

namespace detail {
// Exact header operations read from this binary's 0xFC880 / 0xFC9D0.
// The native queue consumes one reference through void** and may retain it.
// Storage/destruction belong to this DLL, never the native allocator.
struct CallableHeader {
    volatile long references;
    uint32_t padding;
    void (*invoke)(CallableHeader*) noexcept;
    void (*destroy)(CallableHeader*) noexcept;
    bool (*predicate)(CallableHeader*, int) noexcept;
    uintptr_t reserved;
};
using Post = uint32_t (*)(const void* source_location, void** owned_callable);
using Observe = ContextState (*)(uint32_t& thread_id) noexcept;
// Shared by real binding and offline queue ownership tests. Observer runs only
// after the posted callable is invoked; exceptions cannot cross its ABI.
SchedulerProbeStart PostProbe(Post, Observe);
}
}
