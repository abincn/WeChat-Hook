#include "httplib.h"
#include "wxcx_native_scheduler.h"
#include "wxcx_media_diagnostics.h"
#include "wxcx_identity.h"
#include "global.h"
#include <windows.h>
#include <iostream>
#include <stdexcept>

HMODULE g_hWeixinDll=nullptr;
volatile uint64_t g_IsLogin=0;
static nlohmann::json identity={{"weixin",{{"verified",false}}}};
namespace wxcx { nlohmann::json RuntimeIdentity(){return identity;} }
using namespace wxcx::native;
namespace {
int checks=0,observed=0;
detail::CallableHeader* queued=nullptr;
void Check(bool condition){++checks;if(!condition)throw std::runtime_error("check "+std::to_string(checks));}
ContextState Observe(uint32_t& thread) noexcept {++observed;thread=77;return ContextState::Present;}
ContextState NoContext(uint32_t& thread) noexcept {++observed;thread=88;return ContextState::Absent;}
ContextState Unreadable(uint32_t& thread) noexcept {thread=99;return ContextState::Unreadable;}
void Release(detail::CallableHeader* task){if(!InterlockedDecrement(&task->references))task->destroy(task);}
uint32_t Queue(const void*,void** owned){queued=static_cast<detail::CallableHeader*>(*owned);*owned=nullptr;return 123;}
uint32_t Inline(const void*,void** owned){auto* task=static_cast<detail::CallableHeader*>(*owned);*owned=nullptr;task->invoke(task);Release(task);return 7;}
uint32_t Reject(const void*,void**){return 0;}
uint32_t ThrowBefore(const void*,void**){throw std::runtime_error("test rejection");}
uint32_t ThrowAfter(const void* location,void** owned){Queue(location,owned);throw std::runtime_error("after transfer");}
using Json=nlohmann::json;
struct Response {int status;Json body;};
class MemoryServer:public httplib::Server {
public:
    Response Call(const std::string& method,const std::string& body={},const std::string& path="/wxcx/media/diagnostics/scheduler"){
        const auto request=method+" "+path+" HTTP/1.1\r\nHost: offline\r\nContent-Type: application/json\r\nContent-Length: "+
            std::to_string(body.size())+"\r\nConnection: close\r\n\r\n"+body;
        httplib::detail::BufferStream stream;stream.write(request.data(),request.size());bool closed=false;
        Check(process_request(stream,true,closed,{}));
        const auto response=stream.get_buffer().substr(request.size());
        return {std::stoi(response.substr(9,3)),Json::parse(response.substr(response.find("\r\n\r\n")+4))};
    }
};
const std::string kRequest=Json{{"diagnostic_id",kSchedulerDiagnosticId}}.dump();
std::function<void()> coQueued;int coReleases=0;
void CoRelease(coroutine::detail::SharedPair* pair)noexcept{if(pair->control)++coReleases;*pair={};}
void* CoGo(void*,coroutine::detail::SharedPair* pair,const void*,std::function<void()>* body,uint32_t){coQueued=std::move(*body);pair->object=reinterpret_cast<void*>(1);pair->control=reinterpret_cast<void*>(2);return pair;}
void CoroutineRoutes(){
    MemoryServer server;int starts=0;
    const std::string path="/wxcx/media/diagnostics/coroutine";
    const auto request=Json{{"diagnostic_id",kCoroutineDiagnosticId}}.dump();
    RegisterCoroutineProbeRoutes(server,[&]{++starts;return coroutine::detail::Submit(reinterpret_cast<void*>(1),&CoGo,&CoRelease,&Observe);},std::chrono::milliseconds{0});
    auto call=[&](const std::string& method,const std::string& body=std::string()){return server.Call(method,body,path);};
    Check(call("GET").body["state"]=="not_started");Check(starts==0);
    Check(call("POST",kRequest).status==400);Check(call("POST",Json{{"diagnostic_id",kCoroutineDiagnosticId},{"msgsvrid","1"}}.dump()).status==400);
    Check(call("POST",Json{{"diagnostic_id",1}}.dump()).status==400);Check(starts==0);
    auto result=call("POST",request);Check(result.status==202&&result.body["state"]=="result_unknown");Check(starts==1&&coReleases==1);
    Check(call("POST",request).status==200&&starts==1);coQueued();coQueued={};
    result=call("GET");Check(result.body["state"]=="observed"&&result.body["coroutine_context_present"]==true);
    Check(result.body["capture_destroyed"]==true&&result.body["launch_returned"]==true);Check(!result.body.contains("native_post_result"));
    Check(result.body["download_available"]==false&&result.body["native_scheduler_verified"]==false);
    MemoryServer failure;RegisterCoroutineProbeRoutes(failure,[]()->coroutine::Result{throw std::runtime_error("SECRET");});
    result=failure.Call("POST",request,path);Check(result.status==503);Check(result.body.dump().find("SECRET")==std::string::npos);
}
void Routes(){
    MemoryServer server;int starts=0;
    RegisterSchedulerProbeRoutes(server,[&]{++starts;
        Check(server.Call("GET").body["state"]=="starting");
        Check(server.Call("POST",kRequest).body["state"]=="starting");
        return detail::PostProbe(&Queue,&Observe);});
    auto response=server.Call("GET");Check(response.status==200&&response.body["state"]=="not_started");Check(starts==0);
    for(const auto& body:{std::string("{"),std::string("null"),std::string("{}"),std::string("[]"),std::string(513,'x'),
        Json{{"diagnostic_id","old"}}.dump(),Json{{"diagnostic_id",kSchedulerDiagnosticId},{"rva","0x1"}}.dump()})Check(server.Call("POST",body).status==400);
    Check(starts==0);
    response=server.Call("POST",kRequest);Check(response.status==202&&response.body["state"]=="queued");Check(starts==1);
    Check(response.body["native_post_result"]==123);Check(response.body["coroutine_context_present"].is_null());
    Check(server.Call("POST",kRequest).status==200&&starts==1);
    queued->invoke(queued);Release(queued);queued=nullptr;
    response=server.Call("GET");Check(response.body["state"]=="observed"&&response.body["coroutine_context_present"]==true);
    Check(!response.body["download_available"].get<bool>()&&!response.body["native_scheduler_verified"].get<bool>());
    Check(server.Call("POST",kRequest).status==200&&starts==1);
    MemoryServer timeout;int timedStarts=0;
    RegisterSchedulerProbeRoutes(timeout,[&]{++timedStarts;return detail::PostProbe(&Queue,&NoContext);},std::chrono::milliseconds{0});
    response=timeout.Call("POST",kRequest);Check(response.status==202&&response.body["state"]=="result_unknown");
    Check(timeout.Call("POST",kRequest).body["state"]=="result_unknown"&&timedStarts==1);
    queued->invoke(queued);Release(queued);queued=nullptr;
    response=timeout.Call("GET");Check(response.body["state"]=="observed"&&response.body["observation_deadline_elapsed"]==true);
    Check(response.body["coroutine_context_present"]==false);
    MemoryServer failure;int failedStarts=0;
    RegisterSchedulerProbeRoutes(failure,[&]()->SchedulerProbeStart{++failedStarts;throw std::runtime_error("SECRET");});
    response=failure.Call("POST",kRequest);Check(response.status==503&&response.body["state"]=="failed");
    Check(response.body.dump().find("SECRET")==std::string::npos);Check(failure.Call("POST",kRequest).status==200&&failedStarts==1);
    MemoryServer abandoned;RegisterSchedulerProbeRoutes(abandoned,[]{return detail::PostProbe(&Reject,&Observe);});
    Check(abandoned.Call("POST",kRequest).body["state"]=="discarded");
    MemoryServer throwingAfter;RegisterSchedulerProbeRoutes(throwingAfter,[]{return detail::PostProbe(&ThrowAfter,&Observe);});
    response=throwingAfter.Call("POST",kRequest);Check(response.status==202&&response.body["state"]=="result_unknown");
    Release(queued);queued=nullptr;
    MemoryServer unreadable;RegisterSchedulerProbeRoutes(unreadable,[]{return detail::PostProbe(&Inline,&Unreadable);});
    response=unreadable.Call("POST",kRequest);Check(response.body["state"]=="observed");
    Check(response.body["context_read_status"]=="unreadable");Check(response.body["coroutine_context_present"].is_null());
}
}
int main(){try{
    Check(StartSchedulerProbe().error=="version_unverified");
    identity={{"unexpected",true}};Check(StartSchedulerProbe().error=="version_unverified");
    identity={{"weixin",{{"verified",true}}}};Check(StartSchedulerProbe().error=="version_unverified");
    identity={{"weixin",{{"verified",true},{"mapped_headers_match",true}}}};Check(StartSchedulerProbe().error=="login_not_ready");
    g_IsLogin=1;Check(StartSchedulerProbe().error=="login_not_ready");
    g_hWeixinDll=reinterpret_cast<HMODULE>(0x10000);Check(StartSchedulerProbe().error=="scheduler_binding_unverified");
    Check(detail::PostProbe(nullptr,&Observe).error=="scheduler_binding_missing");
    Check(detail::PostProbe(&Queue,nullptr).error=="scheduler_binding_missing");
    auto start=detail::PostProbe(&Queue,&Observe);Check(start.error.empty());Check(observed==0);
    auto snapshot=start.probe->Snapshot();Check(snapshot.phase==ProbePhase::Queued);Check(snapshot.post_returned&&snapshot.post_result==123);
    Check(queued->references==1);Check(!queued->predicate(queued,0));Check(queued->predicate(queued,1));Check(queued->predicate(queued,-1));
    queued->invoke(queued);queued->invoke(queued);Check(observed==1);
    snapshot=start.probe->Snapshot();Check(snapshot.phase==ProbePhase::Observed);Check(snapshot.thread_id==77&&snapshot.coroutine_context_present);
    Release(queued);queued=nullptr;Check(start.probe->Snapshot().phase==ProbePhase::Observed);
    start=detail::PostProbe(&Queue,&Observe);Release(queued);queued=nullptr;Check(observed==1);Check(start.probe->Snapshot().phase==ProbePhase::Discarded);
    start=detail::PostProbe(&Inline,&NoContext);snapshot=start.probe->Snapshot();Check(start.error.empty());Check(snapshot.phase==ProbePhase::Observed);
    Check(snapshot.thread_id==88&&!snapshot.coroutine_context_present);Check(snapshot.post_result==7&&snapshot.post_returned);
    start=detail::PostProbe(&Reject,&Observe);Check(start.error.empty());Check(start.probe->Snapshot().phase==ProbePhase::Discarded);
    start=detail::PostProbe(&ThrowBefore,&Observe);Check(start.error=="scheduler_post_exception");Check(start.probe->Snapshot().phase==ProbePhase::Discarded);Check(!start.probe->Snapshot().post_returned);
    start=detail::PostProbe(&ThrowAfter,&Observe);Check(start.error=="scheduler_post_exception");Check(start.probe->Snapshot().phase==ProbePhase::Queued);
    queued->invoke(queued);Release(queued);queued=nullptr;Check(start.probe->Snapshot().phase==ProbePhase::Observed);
    // Queue can hold multiple references; dropping the caller's snapshot does
    // not end native callable ownership, and the last queue drop is final.
    start=detail::PostProbe(&Queue,&Observe);InterlockedIncrement(&queued->references);Release(queued);Check(queued->references==1);
    start.probe.reset();queued->invoke(queued);Release(queued);queued=nullptr;
    Check(observed==4);
    Routes();
    CoroutineRoutes();
    std::cout<<checks<<" scheduler ownership/gate checks passed (no native calls/network)\n";return 0;
}catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}}
