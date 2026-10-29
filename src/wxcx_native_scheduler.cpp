#include "wxcx_native_scheduler.h"
#include "wxcx_identity.h"
#include "global.h"
#include <windows.h>
#include <intrin.h>
#include <atomic>
#include <cstddef>
#include <mutex>
#include <utility>

namespace wxcx::native {
struct SchedulerProbe::State {
    std::atomic<ProbePhase> phase{ProbePhase::Queued};
    std::atomic<uint32_t> thread{0}, result{0};
    std::atomic<ContextState> context{ContextState::Unreadable};
    std::atomic<bool> returned{false};
};
SchedulerProbe::SchedulerProbe(std::shared_ptr<State> state):state_(std::move(state)){}
SchedulerObservation SchedulerProbe::Snapshot() const {
    SchedulerObservation result;
    result.phase=state_->phase.load(std::memory_order_acquire);
    result.thread_id=state_->thread.load();
    const auto context=state_->context.load();
    result.context_readable=context!=ContextState::Unreadable;
    result.coroutine_context_present=context==ContextState::Present;
    result.post_returned=state_->returned.load(std::memory_order_acquire);result.post_result=state_->result.load();
    return result;
}
namespace {
using detail::CallableHeader;
static_assert(sizeof(long)==4 && sizeof(void*)==8);
static_assert(sizeof(CallableHeader)==40 && offsetof(CallableHeader,invoke)==8 &&
    offsetof(CallableHeader,destroy)==16 && offsetof(CallableHeader,predicate)==24);
struct Callable {
    CallableHeader header;
    std::shared_ptr<SchedulerProbe::State> state;
    detail::Observe observe;
};
static_assert(offsetof(Callable,header)==0);
void Invoke(CallableHeader* header) noexcept {
    auto* task=reinterpret_cast<Callable*>(header);
    auto expected=ProbePhase::Queued;
    if(!task->state->phase.compare_exchange_strong(expected,ProbePhase::Running))return;
    uint32_t thread=0;
    const auto context=task->observe(thread);
    task->state->thread=thread;task->state->context=context;
    task->state->phase.store(ProbePhase::Observed,std::memory_order_release);
}
void Destroy(CallableHeader* header) noexcept {
    auto* task=reinterpret_cast<Callable*>(header);
    auto expected=ProbePhase::Queued;
    task->state->phase.compare_exchange_strong(expected,ProbePhase::Discarded);
    delete task;
}
bool Predicate(CallableHeader*,int value) noexcept {return value!=0;}
struct SourceLocation {const char* tag;const char* file;int line;uintptr_t return_address;};
static_assert(sizeof(SourceLocation)==32);
// The native post path consumes stack source-location records in existing
// callers. Strings here remain alive with the pinned module.
const SourceLocation kLocation{"wxcx_scheduler_probe",__FILE__,__LINE__,0};
uintptr_t ModuleBase(){return reinterpret_cast<uintptr_t>(g_hWeixinDll);}
bool QueueReady(uintptr_t base) noexcept {
    constexpr unsigned char prologue[]={0x55,0x56,0x57,0x53,0x48,0x83,0xec,0x48,0x48,0x8d,0x6c,0x24,0x40,0x48,0xc7,0x45};
    __try {
        for(size_t i=0;i<sizeof(prologue);++i)if(*reinterpret_cast<const unsigned char*>(base+0x352F60+i)!=prologue[i])return false;
        const auto executor=*reinterpret_cast<const uintptr_t*>(base+0xA83D438);
        return executor>=0x10000 && *reinterpret_cast<const uintptr_t*>(executor)>=0x10000;
    } __except(EXCEPTION_EXECUTE_HANDLER){return false;}
}
ContextState ObserveLiveContext(uint32_t& thread) noexcept {
    thread=GetCurrentThreadId();
    // The native await path uses TlsIndex and TLS+496. Only observe existence;
    // do not acquire, export or invoke the coroutine object from this snapshot.
    __try {
        const auto index=*reinterpret_cast<const uint32_t*>(ModuleBase()+0xA83C2F0);
        if(index>4096)return ContextState::Unreadable;
        const auto slots=reinterpret_cast<uintptr_t*>(__readgsqword(0x58));
        if(!slots)return ContextState::Absent;
        const auto local=slots[index];if(!local)return ContextState::Absent;if(local<0x10000)return ContextState::Unreadable;
        const auto pair=*reinterpret_cast<const uintptr_t*>(local+496);if(!pair)return ContextState::Absent;if(pair<0x10000)return ContextState::Unreadable;
        const auto object=*reinterpret_cast<const uintptr_t*>(pair);
        const auto owner=*reinterpret_cast<const uintptr_t*>(pair+8);
        if(!object||!owner)return ContextState::Absent;
        if(object<0x10000||owner<0x10000)return ContextState::Unreadable;
        return *reinterpret_cast<const long*>(owner+8)>0?ContextState::Present:ContextState::Absent;
    } __except(EXCEPTION_EXECUTE_HANDLER){return ContextState::Unreadable;}
}
}
namespace detail {
SchedulerProbeStart PostProbe(Post post,Observe observe){
    if(!post||!observe)return {{},"scheduler_binding_missing"};
    auto state=std::make_shared<SchedulerProbe::State>();
    auto result=std::make_shared<SchedulerProbe>(state);
    auto* task=new Callable{{1,0,&Invoke,&Destroy,&Predicate,0},state,observe};
    void* owned=&task->header;
    try {
        state->result=post(&kLocation,&owned);
        state->returned.store(true,std::memory_order_release);
    }catch(...){
        // Well-formed post implementations null the caller slot on transfer.
        // Do not reclaim queue-owned storage after a later native exception.
        if(owned){auto* header=static_cast<CallableHeader*>(owned);if(!InterlockedDecrement(&header->references))header->destroy(header);}
        return {result,"scheduler_post_exception"};
    }
    if(owned){auto* header=static_cast<CallableHeader*>(owned);if(!InterlockedDecrement(&header->references))header->destroy(header);}
    return {result,{}};
}
}
SchedulerProbeStart StartSchedulerProbe(){
    // HTTP server route re-registration must not create a second native post
    // in this process. Retain the original result, including unknown outcomes.
    static std::mutex mutex;
    static bool attempted=false;
    static SchedulerProbeStart retained;
    std::lock_guard<std::mutex> lock(mutex);
    if(attempted)return retained;
    try {
        const auto identity=RuntimeIdentity().at("weixin");
        if(!identity.value("verified",false)||!identity.value("mapped_headers_match",false))return {{},"version_unverified"};
    }
    catch(...){return {{},"version_unverified"};}
    if(g_IsLogin!=1||!g_hWeixinDll)return {{},"login_not_ready"};
    const auto base=ModuleBase();
    if(!QueueReady(base))return {{},"scheduler_binding_unverified"};
    HMODULE pinned=nullptr;
    if(!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN,
        reinterpret_cast<LPCWSTR>(&StartSchedulerProbe),&pinned))return {{},"module_retention_failed"};
    attempted=true;
    try {retained=detail::PostProbe(reinterpret_cast<detail::Post>(base+0x352F60),&ObserveLiveContext);}
    catch(...){retained.error="scheduler_post_exception";}
    return retained;
}
}
