#pragma once
#include "json.hpp"
#include <chrono>
#include <functional>
#include <memory>
#include <string>
#include <cstdint>
namespace httplib {class Server;}
namespace wxcx::media {
using Json=nlohmann::json;
struct Reply {int status;Json body;};
struct Request {uint64_t msgsvrid=0;std::string source_talker,kind,request_id;bool download=true;std::string image_quality="full";};
struct Artifact {std::string path,format,sha256;uint64_t bytes=0;std::string extension,image_quality;};
struct Outcome {std::string error;Artifact artifact;int native_code=0,native_detail=0;bool result_unknown=false;};
using Progress=std::function<bool(const std::string&)>;
using Complete=std::function<void(Outcome)>;
struct StartResult {std::string error;bool may_have_started=false;};
class Backend {
public:
 virtual ~Backend()=default;
 // Empty means account/version/login is not usable. Called without service locks.
 virtual std::string Account()=0;
 virtual StartResult Start(const Request&,const std::string& account,Progress,Complete)=0;
 virtual void Discard(const Artifact&)noexcept{}
};
struct Options {size_t max_tasks=128,max_active=4;std::chrono::milliseconds timeout{300000};};
class Service {
public:
 using Clock=std::chrono::steady_clock;
 Service(std::shared_ptr<Backend>,std::string stream,Options={},std::function<Clock::time_point()> now=Clock::now);
 Reply Submit(const Json&);
 Reply Get(const std::string&);
 Reply FindRequest(const std::string&);
 Reply Content(const std::string&);
 Reply Release(const std::string&);
 Json Status();
 void Stop();
private:
 struct State;std::shared_ptr<State> state_;
};
void RegisterRoutes(httplib::Server&,std::shared_ptr<Service>);
}
