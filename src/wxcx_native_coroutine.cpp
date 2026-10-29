#include "wxcx_native_coroutine.h"
#include "wxcx_identity.h"
#include "global.h"
#include <windows.h>
#include <intrin.h>
#include <atomic>
#include <cstddef>
#include <climits>
#include <mutex>
#include <utility>

namespace wxcx::native::coroutine {
static_assert(sizeof(std::function<void()>)==64,"Native function ABI requires 64-byte Release x64 representation");
static_assert(sizeof(detail::SharedPair)==16 && offsetof(detail::SharedPair,control)==8);
struct Probe::State {
    std::atomic<ProbePhase> phase{ProbePhase::Queued};
    std::atomic<ContextState> context{ContextState::Unreadable};
    std::atomic<uint32_t> thread{0};
    std::atomic<bool> returned{false},destroyed{false};
};
Probe::Probe(std::shared_ptr<State> state):state_(std::move(state)){}
Observation Probe::Snapshot()const {
    Observation out;out.phase=state_->phase.load(std::memory_order_acquire);
    out.thread_id=state_->thread.load();out.context=state_->context.load();
    out.launch_returned=state_->returned.load();out.capture_destroyed=state_->destroyed.load();return out;
}
namespace {
struct Capture {
    std::shared_ptr<Probe::State> state;
    explicit Capture(std::shared_ptr<Probe::State> value):state(std::move(value)){}
    ~Capture(){
        auto queued=ProbePhase::Queued;
        state->phase.compare_exchange_strong(queued,ProbePhase::Discarded);
        state->destroyed.store(true,std::memory_order_release);
    }
};
struct Owner {
    detail::SharedPair pair;
    detail::Release release;
    explicit Owner(detail::Release value):release(value){}
    ~Owner(){if(pair.control){auto held=pair;pair={};release(&held);}}
};
struct Location {const char* tag;const char* file;int line;uintptr_t return_address;};
static_assert(sizeof(Location)==32);
const Location kLocation{"wxcx_co_probe",__FILE__,__LINE__,0};
bool Entry(uintptr_t address,const unsigned char* expected)noexcept {
    __try{for(size_t i=0;i<16;++i)if(*reinterpret_cast<const unsigned char*>(address+i)!=expected[i])return false;return true;}
    __except(EXCEPTION_EXECUTE_HANDLER){return false;}
}
bool AcquireKernel(uintptr_t base,detail::SharedPair& pair)noexcept {
    // Same process-global ownership acquisition as native caller 0x52440.
    // The process kernel is initialized during app startup; never initialize a
    // second kernel here. Refuse null/stopped kernel and retain its owner.
    __try {
        const auto app=*reinterpret_cast<const uintptr_t*>(base+0xA83AB20);if(app<0x10000)return false;
        const auto kernel=*reinterpret_cast<const uintptr_t*>(app+784);
        const auto owner=*reinterpret_cast<const uintptr_t*>(app+792);
        if(kernel<0x10000||owner<0x10000)return false;
        if((*reinterpret_cast<const unsigned char*>(kernel+96)&1)!=0)return false;
        const auto scope=*reinterpret_cast<const uintptr_t*>(kernel+8);if(scope<0x10000)return false;
        if(!*reinterpret_cast<const uintptr_t*>(scope+320))return false;
        auto* strong=reinterpret_cast<volatile long*>(owner+8);
        long count=*strong;
        while(count>0&&count<LONG_MAX){const auto old=InterlockedCompareExchange(strong,count+1,count);if(old==count){pair={reinterpret_cast<void*>(kernel),reinterpret_cast<void*>(owner)};return true;}count=old;}
    }__except(EXCEPTION_EXECUTE_HANDLER){return false;}
    return false;
}
ContextState ObserveContext(uint32_t& thread)noexcept {
    thread=GetCurrentThreadId();
    __try{
        const auto base=reinterpret_cast<uintptr_t>(g_hWeixinDll);
        const auto index=*reinterpret_cast<const uint32_t*>(base+0xA83C2F0);if(index>4096)return ContextState::Unreadable;
        const auto slots=reinterpret_cast<const uintptr_t*>(__readgsqword(0x58));if(!slots)return ContextState::Absent;
        const auto local=slots[index];if(!local)return ContextState::Absent;if(local<0x10000)return ContextState::Unreadable;
        const auto current=*reinterpret_cast<const uintptr_t*>(local+496);if(!current)return ContextState::Absent;if(current<0x10000)return ContextState::Unreadable;
        const auto object=*reinterpret_cast<const uintptr_t*>(current),owner=*reinterpret_cast<const uintptr_t*>(current+8);
        if(!object||!owner)return ContextState::Absent;if(object<0x10000||owner<0x10000)return ContextState::Unreadable;
        return *reinterpret_cast<const long*>(owner+8)>0?ContextState::Present:ContextState::Absent;
    }__except(EXCEPTION_EXECUTE_HANDLER){return ContextState::Unreadable;}
}
}
namespace detail {
Result Submit(void* kernel,Go go,Release release,Observe observe,Work work){
    if(!kernel||!go||!release||!observe)return {{},"coroutine_binding_missing"};
    auto state=std::make_shared<Probe::State>();auto probe=std::make_shared<Probe>(state);
    Owner job(release);
    try {
        auto capture=std::make_shared<Capture>(state);
        std::function<void()> body=[capture,observe,work=std::move(work)]()noexcept{
            auto queued=ProbePhase::Queued;
            if(!capture->state->phase.compare_exchange_strong(queued,ProbePhase::Running))return;
            uint32_t thread=0;const auto context=observe(thread);
            capture->state->thread=thread;capture->state->context=context;
            // Native job code must never receive a C++ exception from our DLL.
            // A business adapter reports its failure through its own completion.
            if(work){try{work(context,thread);}catch(...){}}
            capture->state->phase.store(ProbePhase::Observed,std::memory_order_release);
        };
        // Go consumes/moves body using native virtual function operations. Its
        // captured state remains in the native job after these local copies end.
        go(kernel,&job.pair,&kLocation,&body,1);
        state->returned.store(true,std::memory_order_release);
        if(!job.pair.object||!job.pair.control)return {probe,"native_job_missing"};
    }catch(...){return {probe,"coroutine_launch_exception"};}
    // Existing callers release this external job owner after launch. The native
    // coroutine's captured strong self owner carries execution to completion.
    return {probe,{}};
}
}
Result StartTask(Work work){
    try{const auto id=RuntimeIdentity().at("weixin");if(!id.value("verified",false)||!id.value("mapped_headers_match",false))return {{},"version_unverified"};}
    catch(...){return {{},"version_unverified"};}
    if(g_IsLogin!=1||!g_hWeixinDll)return {{},"login_not_ready"};
    const auto base=reinterpret_cast<uintptr_t>(g_hWeixinDll);
    constexpr unsigned char goEntry[]={0x55,0x41,0x57,0x41,0x56,0x56,0x57,0x53,0x48,0x81,0xec,0x88,0,0,0,0x48};
    constexpr unsigned char releaseEntry[]={0x56,0x48,0x83,0xec,0x20,0x48,0x8b,0x71,8,0x48,0x85,0xf6,0x74,0x23,0xf0,0xff};
    if(!Entry(base+0x2BA700,goEntry)||!Entry(base+0x2130,releaseEntry))return {{},"coroutine_binding_unverified"};
    HMODULE pinned=nullptr;
    if(!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN,reinterpret_cast<LPCWSTR>(&StartProbe),&pinned))return {{},"module_retention_failed"};
    Owner kernel(reinterpret_cast<detail::Release>(base+0x2130));
    if(!AcquireKernel(base,kernel.pair))return {{},"kernel_not_ready"};
    try{return detail::Submit(kernel.pair.object,reinterpret_cast<detail::Go>(base+0x2BA700),kernel.release,&ObserveContext,std::move(work));}
    catch(...){return {{},"coroutine_launch_exception"};}
}
Result StartProbe(){
    static std::mutex mutex;static bool attempted=false;static Result retained;
    std::lock_guard<std::mutex> lock(mutex);if(attempted)return retained;
    retained=StartTask({});
    if(retained.probe||retained.error=="coroutine_launch_exception")attempted=true;
    return retained;
}
}
