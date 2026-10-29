#pragma once
#include "wxcx_native_scheduler.h"
#include "wxcx_native_coroutine.h"
#include <chrono>
#include <functional>
namespace httplib { class Server; }
namespace wxcx::native {
constexpr const char* kSchedulerDiagnosticId="MEDIA-SCHED-20261029-01";
constexpr const char* kCoroutineDiagnosticId="MEDIA-CO-20261029-01";
// One attempt per registry; duplicates only read the retained observation.
// Timeout never cancels native-owned storage or resubmits the callable.
void RegisterSchedulerProbeRoutes(httplib::Server&,
    std::function<SchedulerProbeStart()> start=StartSchedulerProbe,
    std::chrono::milliseconds observation_timeout=std::chrono::milliseconds{5000});
void RegisterCoroutineProbeRoutes(httplib::Server&,
    std::function<coroutine::Result()> start=coroutine::StartProbe,
    std::chrono::milliseconds observation_timeout=std::chrono::milliseconds{5000});
}
