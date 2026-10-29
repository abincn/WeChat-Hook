#include "wxcx_native_coroutine.h"
#include "wxcx_identity.h"
#include "global.h"
#include <windows.h>
#include <array>
#include <cstring>
#include <iostream>
#include <stdexcept>

HMODULE g_hWeixinDll=nullptr;volatile uint64_t g_IsLogin=0;
static nlohmann::json identity={{"weixin",{{"verified",false}}}};
namespace wxcx {nlohmann::json RuntimeIdentity(){return identity;}}
using namespace wxcx::native;
namespace co=wxcx::native::coroutine;
namespace {
int checks=0,releases=0,observations=0;std::function<void()> queued;
void Check(bool value){++checks;if(!value)throw std::runtime_error("check "+std::to_string(checks));}
ContextState Observe(uint32_t& thread)noexcept{++observations;thread=123;return ContextState::Present;}
ContextState Absent(uint32_t& thread)noexcept{thread=456;return ContextState::Absent;}
ContextState Unreadable(uint32_t& thread)noexcept{thread=789;return ContextState::Unreadable;}
void Release(co::detail::SharedPair* owner)noexcept{if(owner->control)++releases;*owner={};}
void Fill(co::detail::SharedPair* job){job->object=reinterpret_cast<void*>(1);job->control=reinterpret_cast<void*>(2);}
void* Queue(void*,co::detail::SharedPair* job,const void*,std::function<void()>* body,uint32_t naming){Check(naming==1);queued=std::move(*body);Fill(job);return job;}
void* Inline(void*,co::detail::SharedPair* job,const void*,std::function<void()>* body,uint32_t){(*body)();(*body)();Fill(job);return job;}
void* Drop(void*,co::detail::SharedPair* job,const void*,std::function<void()>*,uint32_t){Fill(job);return job;}
void* Missing(void*,co::detail::SharedPair*,const void*,std::function<void()>* body,uint32_t){queued=std::move(*body);return nullptr;}
void* ThrowBefore(void*,co::detail::SharedPair*,const void*,std::function<void()>*,uint32_t){throw std::runtime_error("before transfer");}
void* ThrowAfter(void* kernel,co::detail::SharedPair* job,const void* location,std::function<void()>* body,uint32_t naming){Queue(kernel,job,location,body,naming);throw std::runtime_error("after transfer");}
void* Kernel(){return reinterpret_cast<void*>(0x10000);}
// Emulate the native 64-byte std::function operations observed in 2BA700,
// CC0230 and CC0640, rather than assuming C++ move syntax proves native ABI.
void FunctionAbi(bool heap){
    int calls=0,destroys=0;
    struct Count {int* value;~Count(){++*value;}};
    auto life=std::make_shared<Count>();life->value=&destroys;
    std::function<void()> source;
    if(heap){std::array<char,256> padding{};padding[9]=7;source=[life,padding,&calls]{calls+=padding[9];};}
    else source=[life,&calls]{++calls;};
    life.reset();
    alignas(std::function<void()>) unsigned char storage[64]{};
    auto** sourceSlot=reinterpret_cast<void**>(reinterpret_cast<unsigned char*>(&source)+56);
    auto* impl=*sourceSlot;Check(impl!=nullptr);Check((impl!=&source)==heap);
    auto** table=*reinterpret_cast<void***>(impl);
    void* moved=impl;
    if(impl==&source){
        using Move=void*(*)(void*,void*);moved=reinterpret_cast<Move>(table[1])(impl,storage);
        using Delete=void(*)(void*,bool);reinterpret_cast<Delete>(table[4])(impl,false);
    }
    *sourceSlot=nullptr;
    *reinterpret_cast<void**>(storage+56)=moved;
    table=*reinterpret_cast<void***>(moved);
    using Invoke=void(*)(void*);reinterpret_cast<Invoke>(table[2])(moved);
    Check(calls==(heap?7:1));Check(destroys==0);Check(!source);
    using Delete=void(*)(void*,bool);reinterpret_cast<Delete>(table[4])(moved,moved!=storage);
    *reinterpret_cast<void**>(storage+56)=nullptr;Check(destroys==1);
}
}
int main(){try{
    Check(co::StartProbe().error=="version_unverified");
    identity={{"weixin",{{"verified",true}}}};Check(co::StartProbe().error=="version_unverified");
    identity={{"weixin",{{"verified",true},{"mapped_headers_match",true}}}};Check(co::StartProbe().error=="login_not_ready");
    g_IsLogin=1;Check(co::StartProbe().error=="login_not_ready");g_hWeixinDll=reinterpret_cast<HMODULE>(0x10000);
    Check(co::StartProbe().error=="coroutine_binding_unverified");
    Check(co::detail::Submit(nullptr,&Queue,&Release,&Observe).error=="coroutine_binding_missing");
    Check(co::detail::Submit(Kernel(),nullptr,&Release,&Observe).error=="coroutine_binding_missing");
    Check(co::detail::Submit(Kernel(),&Queue,nullptr,&Observe).error=="coroutine_binding_missing");
    Check(co::detail::Submit(Kernel(),&Queue,&Release,nullptr).error=="coroutine_binding_missing");
    auto result=co::detail::Submit(Kernel(),&Queue,&Release,&Observe);Check(result.error.empty());Check(releases==1);
    auto status=result.probe->Snapshot();Check(status.phase==ProbePhase::Queued&&status.launch_returned&&!status.capture_destroyed);Check(observations==0);
    queued();queued();Check(observations==1);status=result.probe->Snapshot();Check(status.phase==ProbePhase::Observed&&status.context==ContextState::Present&&status.thread_id==123);
    queued={};Check(result.probe->Snapshot().capture_destroyed);
    result=co::detail::Submit(Kernel(),&Queue,&Release,&Observe);queued={};Check(result.probe->Snapshot().phase==ProbePhase::Discarded);Check(result.probe->Snapshot().capture_destroyed);
    result=co::detail::Submit(Kernel(),&Inline,&Release,&Absent);status=result.probe->Snapshot();Check(status.phase==ProbePhase::Observed&&status.context==ContextState::Absent&&status.thread_id==456&&status.capture_destroyed);
    result=co::detail::Submit(Kernel(),&Inline,&Release,&Unreadable);Check(result.probe->Snapshot().context==ContextState::Unreadable);
    result=co::detail::Submit(Kernel(),&Drop,&Release,&Observe);Check(result.probe->Snapshot().phase==ProbePhase::Discarded);
    const int prior=releases;result=co::detail::Submit(Kernel(),&ThrowBefore,&Release,&Observe);Check(result.error=="coroutine_launch_exception");
    Check(result.probe->Snapshot().phase==ProbePhase::Discarded&&!result.probe->Snapshot().launch_returned);Check(releases==prior);
    result=co::detail::Submit(Kernel(),&ThrowAfter,&Release,&Observe);Check(result.error=="coroutine_launch_exception");Check(releases==prior+1);
    Check(result.probe->Snapshot().phase==ProbePhase::Queued&&!result.probe->Snapshot().capture_destroyed);queued();queued={};Check(result.probe->Snapshot().phase==ProbePhase::Observed&&result.probe->Snapshot().capture_destroyed);
    result=co::detail::Submit(Kernel(),&Missing,&Release,&Observe);Check(result.error=="native_job_missing");Check(result.probe->Snapshot().phase==ProbePhase::Queued);
    queued();queued={};Check(result.probe->Snapshot().phase==ProbePhase::Observed);
    result=co::detail::Submit(Kernel(),&Queue,&Release,&Observe);result.probe.reset();queued();queued={};
    FunctionAbi(false);FunctionAbi(true);
    int workCalls=0;
    result=co::detail::Submit(Kernel(),&Queue,&Release,&Observe,[&](ContextState context,uint32_t thread){Check(context==ContextState::Present&&thread==123);++workCalls;});
    Check(workCalls==0);queued();queued();queued={};Check(workCalls==1&&result.probe->Snapshot().capture_destroyed);
    result=co::detail::Submit(Kernel(),&Drop,&Release,&Observe,[&](ContextState,uint32_t){++workCalls;});Check(workCalls==1&&result.probe->Snapshot().phase==ProbePhase::Discarded);
    result=co::detail::Submit(Kernel(),&Inline,&Release,&Absent,[&](ContextState context,uint32_t){Check(context==ContextState::Absent);throw std::runtime_error("business failure");});Check(result.probe->Snapshot().phase==ProbePhase::Observed);
    std::cout<<checks<<" coroutine ownership/function ABI checks passed; no native calls/network\n";return 0;
}catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}}
