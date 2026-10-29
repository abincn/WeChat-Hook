#include "wxcx_media_tasks.h"
#include "wxcx_ids.h"
#include "wxcx_media_files.h"
#include "wxcx_utf8_path.h"
#include "httplib.h"
#include <map>
#include <mutex>
#include <algorithm>
#include <fstream>
#include <filesystem>
#include <stdexcept>
#include <vector>

namespace wxcx::media {
namespace {
bool Text(const Json& j,const char* key,std::string& out,size_t max,bool required=false){
 if(!j.contains(key))return !required;
 if(!j[key].is_string())return false;out=j[key].get<std::string>();
 return out.size()<=max&&out.find('\0')==std::string::npos&&(!required||!out.empty());
}
bool Parse(const Json& j,Request& out){
 if(!j.is_object()||j.size()>6)return false;
 for(auto i=j.begin();i!=j.end();++i)if(i.key()!="msgsvrid"&&i.key()!="source_talker"&&i.key()!="kind"&&i.key()!="request_id"&&i.key()!="download"&&i.key()!="image_quality")return false;
 if(!j.contains("msgsvrid")||!ids::ParseUint64(j["msgsvrid"],out.msgsvrid)||!out.msgsvrid||
 !Text(j,"source_talker",out.source_talker,256)||!Text(j,"kind",out.kind,16,true)||!Text(j,"request_id",out.request_id,128))return false;
 if(out.kind!="image"&&out.kind!="video"&&out.kind!="file")return false;
 if(j.contains("image_quality")&&(out.kind!="image"||!Text(j,"image_quality",out.image_quality,16,true)))return false;
 if(out.image_quality!="full"&&out.image_quality!="original")return false;
 if(out.request_id.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-.:")!=std::string::npos)return false;
 if(j.contains("download")){if(!j["download"].is_boolean())return false;out.download=j["download"].get<bool>();}return true;
}
bool Same(const Request& a,const Request& b){return a.msgsvrid==b.msgsvrid&&a.source_talker==b.source_talker&&a.kind==b.kind&&a.download==b.download&&a.image_quality==b.image_quality;}
std::string SafeError(const std::string& error){
 for(const char* code:{"source_not_found","source_ambiguous","source_lookup_incomplete","source_identity_mismatch","type_unsupported","resource_missing","resource_failed","native_exception","native_binding_unverified","native_task_discarded","coroutine_context_missing","account_changed","version_unverified","image_key_derivation_failed","image_key_or_padding_invalid","image_payload_incomplete","image_crypto_failed","image_lengths_invalid","unsupported_image_container","unsupported_image_format","file_invalid","file_too_large","output_failed","native_result_invalid","native_job_missing","coroutine_launch_exception","kernel_not_ready","login_not_ready","module_retention_failed"})if(error==code)return code;
 for(const char* code:{"wxgf_codec_unverified","wxgf_invalid","wxgf_dimensions_invalid","wxgf_output_invalid","wxgf_conversion_failed"})if(error==code)return code;
 for(const char* code:{"wxgf_component_identity_mismatch","wxgf_component_load_failed","wxgf_export_unverified","wxgf_import_unverified","wxgf_component_retention_failed"})if(error==code)return code;
 for(const char* code:{"source_metadata_invalid","resource_integrity_mismatch"})if(error==code)return code;
 for(const char* code:{"image_thumbnail_rejected","image_resource_kind_mismatch"})if(error==code)return code;
 return error.empty()?"":"native_failed";
}
}
struct Service::State {
 struct Task {Request request;std::string id,account,phase="queued",last_stage="queued",error;Clock::time_point started;bool active=true,download_started=false,unknown=false;Outcome result;};
 std::mutex mutex;std::shared_ptr<Backend> backend;std::string stream;Options options;
 std::function<Clock::time_point()> now;uint64_t sequence=0;bool stopped=false;
 std::map<std::string,std::shared_ptr<Task>> tasks;std::map<std::string,std::string> requests;
 void Expire(Task& t){if(t.active&&now()-t.started>=options.timeout){t.unknown=true;t.phase=t.download_started?"result_unknown":"timed_out";t.error="timeout";}}
 Json Snapshot(Task& t){Expire(t);Json out{{"task_id",t.id},{"msgsvrid",std::to_string(t.request.msgsvrid)},{"source_talker",t.request.source_talker},{"kind",t.request.kind},{"state",t.phase},{"error",t.error},{"native_pending",t.active},{"retry_automatically",false},{"live_verified",false},{"native_code",t.result.native_code},{"native_detail",t.result.native_detail}};
 out["last_stage"]=t.last_stage;out["download_started"]=t.download_started;
 if(t.request.kind=="image")out["image_quality"]=t.request.image_quality;
 if(t.phase=="ready"){out["artifact"]={{"format",t.result.artifact.format},{"extension",t.result.artifact.extension},{"bytes",t.result.artifact.bytes},{"sha256",t.result.artifact.sha256},{"url","/wxcx/media/tasks/"+t.id+"/content"}};
 if(!t.result.artifact.image_quality.empty())out["artifact"]["image_quality"]=t.result.artifact.image_quality;}return out;}
 size_t Active(){size_t n=0;for(auto& pair:tasks){Expire(*pair.second);if(pair.second->active)++n;}return n;}
 void Fence(const std::string& account){for(auto& pair:tasks){auto& t=*pair.second;if(t.account!=account){t.unknown=true;t.phase="account_changed";t.error="account_changed";}}}
};
Service::Service(std::shared_ptr<Backend> backend,std::string stream,Options options,std::function<Clock::time_point()> now):state_(std::make_shared<State>()){
 if(!backend||stream.empty()||!options.max_active||!options.max_tasks||options.timeout.count()<=0||!now)throw std::invalid_argument("invalid media service options");
 state_->backend=std::move(backend);state_->stream=std::move(stream);state_->options=options;state_->now=std::move(now);
}
Reply Service::Submit(const Json& body){
 Request request;if(!Parse(body,request))return {400,{{"error","invalid_media_request"}}};
 auto s=state_;std::string account;try{account=s->backend->Account();}catch(...){}
 std::shared_ptr<State::Task> task;
 {std::lock_guard<std::mutex> lock(s->mutex);s->Fence(account);
 if(s->stopped)return {503,{{"error","stopped"}}};if(account.empty())return {503,{{"error","account_not_ready"}}};
 const std::string key=account+'\n'+request.request_id;
 if(!request.request_id.empty()){auto existing=s->requests.find(key);if(existing!=s->requests.end()){
 auto record=s->tasks.find(existing->second);if(record==s->tasks.end())return {410,{{"error","request_id_expired"},{"task_id",existing->second},{"retry_automatically",false}}};
 auto t=record->second;if(!Same(request,t->request))return {409,{{"error","request_id_conflict"}}};return {200,s->Snapshot(*t)};}}
 if(!request.request_id.empty()&&s->requests.size()>=1024)return {429,{{"error","request_id_capacity"}}};
 if(s->Active()>=s->options.max_active||s->tasks.size()>=s->options.max_tasks)return {429,{{"error","media_capacity"}}};
 task=std::make_shared<State::Task>();task->request=request;task->account=account;task->started=s->now();task->id=s->stream+"-media-"+std::to_string(++s->sequence);
 s->tasks.emplace(task->id,task);if(!request.request_id.empty())s->requests.emplace(key,task->id);}
 auto progress=[s,task](const std::string& phase){
 std::string current;try{current=s->backend->Account();}catch(...){}
 std::lock_guard<std::mutex> lock(s->mutex);s->Fence(current);s->Expire(*task);
 if(!task->active||task->unknown||s->stopped)return false;
 if(phase!="locating"&&phase!="querying"&&phase!="checking"&&phase!="downloading"&&phase!="decoding"&&phase!="verifying")return false;
 if(phase=="downloading")task->download_started=true;task->last_stage=phase;task->phase=phase;return true;};
 auto complete=[s,task](Outcome outcome){
 std::string current;try{current=s->backend->Account();}catch(...){}
 std::unique_lock<std::mutex> lock(s->mutex);if(!task->active)return;s->Fence(current);s->Expire(*task);task->active=false;
 if(task->unknown||s->stopped){lock.unlock();s->backend->Discard(outcome.artifact);return;}
 if(outcome.result_unknown){task->unknown=true;task->phase="result_unknown";task->error=SafeError(outcome.error);lock.unlock();s->backend->Discard(outcome.artifact);return;}
 if(outcome.error.empty()&&(outcome.artifact.path.empty()||(outcome.artifact.bytes==0&&task->request.kind!="file")||outcome.artifact.sha256.size()!=64))outcome.error="file_invalid";
 task->result=std::move(outcome);task->error=SafeError(task->result.error);task->phase=task->error.empty()?"ready":"failed";};
 StartResult started;
 try{started=s->backend->Start(request,account,progress,complete);}catch(...){started={"native_exception",true};}
 {std::lock_guard<std::mutex> lock(s->mutex);
 if(!started.error.empty()&&task->active){task->error=SafeError(started.error);if(started.may_have_started){task->unknown=true;task->phase="result_unknown";}else{task->phase="failed";task->active=false;}}
 return {202,s->Snapshot(*task)};}
}
Reply Service::Get(const std::string& id){auto s=state_;std::string account;try{account=s->backend->Account();}catch(...){}
 std::lock_guard<std::mutex> lock(s->mutex);s->Fence(account);auto i=s->tasks.find(id);if(i==s->tasks.end()||i->second->account!=account)return {404,{{"error","task_not_found"}}};return {200,s->Snapshot(*i->second)};}
Reply Service::Content(const std::string& id){auto s=state_;std::string account;try{account=s->backend->Account();}catch(...){}
 std::lock_guard<std::mutex> lock(s->mutex);s->Fence(account);auto i=s->tasks.find(id);if(i==s->tasks.end()||i->second->account!=account)return {404,{{"error","task_not_found"}}};
 s->Expire(*i->second);if(i->second->phase!="ready")return {409,{{"error","artifact_not_ready"}}};auto& a=i->second->result.artifact;
 return {200,{{"path",a.path},{"bytes",a.bytes},{"sha256",a.sha256},{"format",a.format}}};}
Reply Service::FindRequest(const std::string& request){auto s=state_;std::string account;try{account=s->backend->Account();}catch(...){}
 std::lock_guard<std::mutex> lock(s->mutex);s->Fence(account);auto i=s->requests.find(account+'\n'+request);
 if(account.empty()||i==s->requests.end())return {404,{{"error","request_not_found"}}};auto task=s->tasks.find(i->second);
 if(task==s->tasks.end())return {410,{{"error","request_id_expired"},{"task_id",i->second},{"retry_automatically",false}}};return {200,s->Snapshot(*task->second)};}
Json Service::Status(){auto s=state_;std::string account;try{account=s->backend->Account();}catch(...){}
 std::lock_guard<std::mutex> lock(s->mutex);s->Fence(account);return {{"tasks",s->tasks.size()},{"active",s->Active()},{"stopped",s->stopped},{"live_verified",false},{"timeout_ms",s->options.timeout.count()},{"max_active",s->options.max_active},{"max_tasks",s->options.max_tasks}};}
Reply Service::Release(const std::string& id){auto s=state_;std::string account;try{account=s->backend->Account();}catch(...){}
 Artifact retired;{std::lock_guard<std::mutex> lock(s->mutex);s->Fence(account);auto i=s->tasks.find(id);if(i==s->tasks.end()||i->second->account!=account)return {404,{{"error","task_not_found"}}};
 if(i->second->active)return {409,{{"error","native_pending"}}};retired=i->second->result.artifact;s->tasks.erase(i);}
 s->backend->Discard(retired);return {200,{{"released",true},{"task_id",id}}};}
void Service::Stop(){auto s=state_;std::vector<Artifact> retired;{std::lock_guard<std::mutex> lock(s->mutex);s->stopped=true;for(auto& pair:s->tasks){auto& t=*pair.second;if(t.active){t.unknown=true;t.phase=t.download_started?"result_unknown":"stopped";t.error="stopped";}else{retired.push_back(t.result.artifact);t.result.artifact={};if(t.phase=="ready")t.phase="stopped";}}}
 for(const auto& artifact:retired)s->backend->Discard(artifact);}
void RegisterRoutes(httplib::Server& server,std::shared_ptr<Service> service){
 auto respond=[](httplib::Response& response,const Reply& reply){response.status=reply.status;response.set_content(reply.body.dump(),"application/json");};
 server.Post("/wxcx/media/tasks",[service,respond](const httplib::Request& req,httplib::Response& res){try{if(req.body.size()>2048)throw std::invalid_argument("body");respond(res,service->Submit(Json::parse(req.body)));}catch(...){respond(res,{400,{{"error","invalid_media_request"}}});}});
 server.Get("/wxcx/media/status",[service](const httplib::Request&,httplib::Response& res){res.set_content(service->Status().dump(),"application/json");});
 server.Post("/wxcx/media/stop",[service,respond](const httplib::Request& req,httplib::Response& res){
  try{if(!req.body.empty()){auto body=Json::parse(req.body);if(!body.is_object()||!body.empty())throw std::invalid_argument("body");}}catch(...){respond(res,{400,{{"error","empty_object_required"}}});return;}
  service->Stop();respond(res,{200,service->Status()});});
 server.Get(R"(/wxcx/media/tasks/([A-Za-z0-9_-]+))",[service,respond](const httplib::Request& req,httplib::Response& res){respond(res,service->Get(req.matches[1]));});
 server.Get(R"(/wxcx/media/requests/([A-Za-z0-9_.:-]+))",[service,respond](const httplib::Request& req,httplib::Response& res){respond(res,service->FindRequest(req.matches[1]));});
 server.Delete(R"(/wxcx/media/tasks/([A-Za-z0-9_-]+))",[service,respond](const httplib::Request& req,httplib::Response& res){respond(res,service->Release(req.matches[1]));});
 // Never accept a caller-provided filesystem path. Only a completed task can expose bytes.
 server.Get(R"(/wxcx/media/tasks/([A-Za-z0-9_-]+)/content)",[service,respond](const httplib::Request& req,httplib::Response& res){auto found=service->Content(req.matches[1]);if(found.status!=200){respond(res,found);return;}
 const auto size=found.body.at("bytes").get<uint64_t>();if(size>200*1024*1024){respond(res,{413,{{"error","file_too_large"}}});return;}
 std::ifstream input(Utf8Path(found.body.at("path").get<std::string>()),std::ios::binary);std::string bytes(static_cast<size_t>(size),'\0');
 if(!input.read(bytes.data(),static_cast<std::streamsize>(bytes.size()))||input.peek()!=std::char_traits<char>::eof()||Sha256(reinterpret_cast<const unsigned char*>(bytes.data()),bytes.size())!=found.body.at("sha256").get<std::string>()){respond(res,{409,{{"error","artifact_changed"}}});return;}
 if(service->Content(req.matches[1]).status!=200){respond(res,{409,{{"error","account_changed"}}});return;}
 // Native artifact writer creates immutable task-specific copies. Its SHA is exposed for the client.
 res.set_content(std::move(bytes),"application/octet-stream");});
}
}
