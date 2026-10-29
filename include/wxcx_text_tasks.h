#pragma once
#include "json.hpp"
#include <chrono>
#include <cstddef>
#include <memory>
#include <string>

namespace httplib { class Server; }
namespace wxcx { namespace text {
using Json = nlohmann::json;
struct Request { std::string toid, msg, atlist, request_id; };
struct Error { std::string code, message; };
enum class SubmissionState { Submitted, Rejected, Unknown };
struct Submission { SubmissionState state = SubmissionState::Unknown; Error error; };
class Backend {
public:
    virtual ~Backend() = default;
    // All calls occur on the service worker. Readiness probes must have no side
    // effects. Every call MUST return within a bounded time (including native
    // waits); Submit is attempted once. There is no unsafe forced cancellation.
    virtual bool LoginReady() = 0;
    virtual bool VersionReady() = 0;
    virtual Submission Submit(const Request&) = 0;
};
struct Reply { int status; Json body; };
struct Options {
    size_t max_pending = 64, max_tasks = 1024;
    std::chrono::milliseconds timeout{30000};
};
class Service {
public:
    explicit Service(std::shared_ptr<Backend>, Options = {});
    ~Service();
    Service(const Service&) = delete;
    Service& operator=(const Service&) = delete;
    Reply Enqueue(const Json&);
    Reply Get(const std::string&) const;
    Json Status() const;
    // Marks tasks immediately, then joins the bounded, cooperative worker.
    // May wait for the current backend call; cannot cancel arbitrary native code.
    void Stop();
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
void RegisterRoutes(httplib::Server&, std::shared_ptr<Service>);
} }
