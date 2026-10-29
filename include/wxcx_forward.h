#pragma once
// Task protocol is independent of the native ABI. A backend must own native
// messages and marshal every operation/release to the verified native thread.
#include "json.hpp"
#include <chrono>
#include <functional>
#include <memory>
#include <string>
#include <cstdint>
#include <optional>

namespace httplib { class Server; }
namespace wxcx { namespace forward {
using Json = nlohmann::json;
struct Request {
    uint64_t msg_svr_id = 0;
    std::string toid, source_talker, request_id;
};
struct Error {
    std::string code, message;
    explicit operator bool() const { return !code.empty(); }
};
struct Context {
    std::chrono::steady_clock::time_point deadline;
    std::function<bool()> stopping;
    bool Expired() const { return std::chrono::steady_clock::now() >= deadline; }
    bool Cancelled() const { return stopping && stopping(); }
};
struct Message {
    virtual ~Message() = default;
    // raw database type is evidence only; native kind requires verified decoding.
    std::string kind;
    Json evidence = Json::object();
};
struct Resolution { std::shared_ptr<Message> message; Error error; };
enum class SubmissionState { Submitted, Rejected, Unknown };
struct Submission {
    SubmissionState state = SubmissionState::Unknown;
    Error error;
    std::optional<int32_t> server_return; // only set after explicit, valid response parsing
};
class Backend {
public:
    virtual ~Backend() = default;
    // Blocking operations MUST observe the context and retain objects through
    // completion. Once Submit starts, exceptions/timeouts are uncertain outcomes.
    virtual Resolution Resolve(const Request&, const Context&) = 0;
    virtual Error PrepareMedia(const Request&, const std::shared_ptr<Message>&, const Context&) = 0;
    virtual Submission Submit(const Request&, const std::shared_ptr<Message>&, const Context&) = 0;
    virtual Json Capabilities() = 0;
};
struct Reply { int status; Json body; };
struct Options {
    size_t max_tasks = 4096, max_pending = 64;
    std::chrono::milliseconds timeout{300000};
};
class Service {
public:
    explicit Service(std::shared_ptr<Backend> backend, Options options = {});
    ~Service();
    Service(const Service&) = delete;
    Service& operator=(const Service&) = delete;
    Reply Enqueue(const Json& input);
    Reply Get(const std::string& task_id) const;
    Json Capabilities() const;
    void Shutdown();
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
void RegisterTaskRoutes(httplib::Server&, std::shared_ptr<Service>);
void RegisterRoutes(httplib::Server&); // production backend; no runtime RVA setter
} }
