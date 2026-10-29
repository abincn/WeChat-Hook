#include "wxcx_media_diagnostics.h"
#include "httplib.h"
#include "json.hpp"
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>

namespace wxcx::native {
namespace {
using Json=nlohmann::json;
using Clock=std::chrono::steady_clock;
struct Registry {
    std::mutex mutex;
    bool attempted=false,starting=false;
    Clock::time_point started;
    std::chrono::milliseconds timeout;
    SchedulerProbeStart result;
    std::function<SchedulerProbeStart()> start;
};
std::string ErrorCode(const std::string& value){
    for(const char* allowed:{"version_unverified","login_not_ready","scheduler_binding_unverified",
        "module_retention_failed","scheduler_post_exception","scheduler_binding_missing"})if(value==allowed)return value;
    return value.empty()?"":"diagnostic_start_failed";
}
Json Snapshot(const std::shared_ptr<Registry>& registry){
    SchedulerProbeStart result;bool attempted,starting;Clock::time_point started;
    {std::lock_guard<std::mutex> lock(registry->mutex);result=registry->result;attempted=registry->attempted;starting=registry->starting;started=registry->started;}
    Json out{{"diagnostic_id",kSchedulerDiagnosticId},{"attempted",attempted},{"one_attempt_per_process",true},
        {"download_available",false},{"native_source_lookup_verified",false},{"native_scheduler_verified",false},
        {"automatic_sends",false},{"error",ErrorCode(result.error)}};
    if(!attempted){out["state"]="not_started";return out;}
    const bool overdue=Clock::now()-started>=registry->timeout;
    out["observation_deadline_elapsed"]=overdue;
    if(starting){out["state"]=overdue?"result_unknown":"starting";return out;}
    if(!result.probe){out["state"]="failed";return out;}
    const auto observation=result.probe->Snapshot();
    const char* phase=observation.phase==ProbePhase::Queued?"queued":observation.phase==ProbePhase::Running?"running":
        observation.phase==ProbePhase::Observed?"observed":"discarded";
    out["native_phase"]=phase;
    out["state"]=(overdue&&(observation.phase==ProbePhase::Queued||observation.phase==ProbePhase::Running))||!result.error.empty()?
        "result_unknown":phase;
    out["thread_id"]=observation.thread_id;
    out["context_read_status"]=observation.phase!=ProbePhase::Observed?"not_observed":observation.context_readable?"read":"unreadable";
    out["coroutine_context_present"]=observation.phase==ProbePhase::Observed&&observation.context_readable?Json(observation.coroutine_context_present):Json(nullptr);
    out["post_returned"]=observation.post_returned;
    out["native_post_result"]=observation.post_returned?Json(observation.post_result):Json(nullptr);
    out["result_scope"]="scheduler_context_observation_only";
    return out;
}
void Respond(httplib::Response& response,int status,const Json& body){response.status=status;response.set_content(body.dump(),"application/json");}
}
void RegisterSchedulerProbeRoutes(httplib::Server& server,std::function<SchedulerProbeStart()> start,
    std::chrono::milliseconds timeout){
    auto registry=std::make_shared<Registry>();registry->start=std::move(start);registry->timeout=timeout;
    server.Get("/wxcx/media/diagnostics/scheduler",[registry](const httplib::Request&,httplib::Response& response){Respond(response,200,Snapshot(registry));});
    server.Post("/wxcx/media/diagnostics/scheduler",[registry](const httplib::Request& request,httplib::Response& response){
        try{
            if(request.body.size()>512)throw std::invalid_argument("large body");
            const auto input=Json::parse(request.body);
            if(!input.is_object()||input.size()!=1||!input.contains("diagnostic_id")||!input["diagnostic_id"].is_string()||
                input["diagnostic_id"]!=kSchedulerDiagnosticId)throw std::invalid_argument("invalid diagnostic");
        }catch(...){Respond(response,400,{{"error","diagnostic_id_required"},{"diagnostic_id",kSchedulerDiagnosticId}});return;}
        bool already=false;
        {std::lock_guard<std::mutex> lock(registry->mutex);already=registry->attempted;
            if(!already){registry->attempted=true;registry->starting=true;registry->started=Clock::now();}}
        if(already){Respond(response,200,Snapshot(registry));return;}
        SchedulerProbeStart result;
        try{if(registry->start)result=registry->start();else result.error="scheduler_binding_missing";}
        catch(...){result.error="diagnostic_start_failed";}
        const bool hasProbe=static_cast<bool>(result.probe);
        {std::lock_guard<std::mutex> lock(registry->mutex);registry->result=std::move(result);registry->starting=false;}
        Respond(response,hasProbe?202:503,Snapshot(registry));
    });
}
void RegisterCoroutineProbeRoutes(httplib::Server& server,std::function<coroutine::Result()> start,
    std::chrono::milliseconds timeout){
    struct CoRegistry {
        std::mutex mutex;bool attempted=false,starting=false;
        Clock::time_point started;coroutine::Result result;
    };
    auto registry=std::make_shared<CoRegistry>();
    auto snapshot=[registry,timeout]{
        coroutine::Result result;bool attempted,starting;Clock::time_point started;
        {std::lock_guard<std::mutex> lock(registry->mutex);result=registry->result;attempted=registry->attempted;starting=registry->starting;started=registry->started;}
        Json out{{"diagnostic_id",kCoroutineDiagnosticId},{"attempted",attempted},{"one_attempt_per_process",true},
            {"download_available",false},{"native_source_lookup_verified",false},{"native_scheduler_verified",false},{"automatic_sends",false}};
        std::string error;
        if(!result.error.empty()){
            error="coroutine_launch_exception";
            for(const char* known:{"version_unverified","login_not_ready","coroutine_binding_unverified","kernel_not_ready",
                "module_retention_failed","coroutine_binding_missing","coroutine_launch_exception","native_job_missing"})if(result.error==known)error=known;
        }
        out["error"]=error;
        if(!attempted){out["state"]="not_started";return out;}
        const bool overdue=Clock::now()-started>=timeout;out["observation_deadline_elapsed"]=overdue;
        if(starting){out["state"]=overdue?"result_unknown":"starting";return out;}
        if(!result.probe){out["state"]="failed";return out;}
        const auto value=result.probe->Snapshot();
        const char* phase=value.phase==ProbePhase::Queued?"queued":value.phase==ProbePhase::Running?"running":value.phase==ProbePhase::Observed?"observed":"discarded";
        out["native_phase"]=phase;
        out["state"]=((overdue&&(value.phase==ProbePhase::Queued||value.phase==ProbePhase::Running))||!error.empty())?"result_unknown":phase;
        out["thread_id"]=value.thread_id;out["launch_returned"]=value.launch_returned;out["capture_destroyed"]=value.capture_destroyed;
        out["context_read_status"]=value.phase!=ProbePhase::Observed?"not_observed":value.context==ContextState::Unreadable?"unreadable":"read";
        out["coroutine_context_present"]=value.phase==ProbePhase::Observed&&value.context!=ContextState::Unreadable?Json(value.context==ContextState::Present):Json(nullptr);
        out["result_scope"]="native_coroutine_context_only";
        return out;
    };
    server.Get("/wxcx/media/diagnostics/coroutine",[snapshot](const httplib::Request&,httplib::Response& response){Respond(response,200,snapshot());});
    server.Post("/wxcx/media/diagnostics/coroutine",[registry,start=std::move(start),snapshot](const httplib::Request& request,httplib::Response& response){
        try{if(request.body.size()>512)throw std::invalid_argument("body");const auto input=Json::parse(request.body);
            if(!input.is_object()||input.size()!=1||input.value("diagnostic_id",std::string())!=kCoroutineDiagnosticId)throw std::invalid_argument("id");}
        catch(...){Respond(response,400,{{"error","diagnostic_id_required"},{"diagnostic_id",kCoroutineDiagnosticId}});return;}
        bool already;
        {std::lock_guard<std::mutex> lock(registry->mutex);already=registry->attempted;if(!already){registry->attempted=true;registry->starting=true;registry->started=Clock::now();}}
        if(already){Respond(response,200,snapshot());return;}
        coroutine::Result result;try{if(start)result=start();else result.error="coroutine_binding_missing";}catch(...){result.error="coroutine_launch_exception";}
        const bool retained=static_cast<bool>(result.probe);
        {std::lock_guard<std::mutex> lock(registry->mutex);registry->result=std::move(result);registry->starting=false;}
        Respond(response,retained?202:503,snapshot());
    });
}
}
