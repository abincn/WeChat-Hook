#pragma once
#include "wxcx_native_scheduler.h"
#include <functional>

namespace wxcx::native::coroutine {
struct Observation {
    ProbePhase phase=ProbePhase::Queued;
    uint32_t thread_id=0;
    ContextState context=ContextState::Unreadable;
    bool launch_returned=false, capture_destroyed=false;
};
class Probe {
public:
    struct State;
    explicit Probe(std::shared_ptr<State>);
    Observation Snapshot() const;
private:
    std::shared_ptr<State> state_;
};
struct Result {std::shared_ptr<Probe> probe;std::string error;};
// AI04 one-shot diagnostic binding. Performs context observation only,
// never await/query/send; native execution remains pending live acceptance.
Result StartProbe();
// Same version/context gates as the live-tested probe. Work is invoked on the
// native coroutine; callers must handle their own outcomes and account fences.
using Work=std::function<void(ContextState,uint32_t)>;
Result StartTask(Work);
namespace detail {
struct SharedPair {void* object=nullptr;void* control=nullptr;};
// Prototype from 2BA700: kernel, returned native job owner, trace location,
// consumed MSVC std::function<void()> object, observed naming-style argument.
using Go=void*(*)(void*,SharedPair*,const void*,std::function<void()>*,uint32_t);
using Release=void(*)(SharedPair*) noexcept;
using Observe=ContextState(*)(uint32_t&) noexcept;
Result Submit(void* kernel,Go,Release,Observe,Work={});
}
}
