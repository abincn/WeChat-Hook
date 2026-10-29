#include "httplib.h"
#include "wxcx_forward.h"
#include "wxcx_ids.h"
#include <condition_variable>
#include <deque>
#include <map>
#include <mutex>
#include <random>
#include <sstream>
#include <stdexcept>
#include <thread>

namespace wxcx { namespace forward {
namespace {
int64_t Now() { return std::chrono::duration_cast<std::chrono::milliseconds>(
    std::chrono::system_clock::now().time_since_epoch()).count(); }
Reply Fail(int status, const char* code, const std::string& message) {
    return {status, {{"code", "-1"}, {"error_code", code}, {"msg", message}}};
}
bool Text(const Json& in, const char* key, std::string& out, size_t max, bool required) {
    if (!in.contains(key)) return !required;
    if (!in[key].is_string()) return false;
    out = in[key].get<std::string>();
    if (out.empty() || out.size() > max) return false;
    bool nonspace = false;
    for (unsigned char c : out) { if (c < 32 || c == 127) return false; if (c != ' ') nonspace = true; }
    return nonspace;
}
bool Same(const Request& a, const Request& b) {
    return a.msg_svr_id == b.msg_svr_id && a.toid == b.toid && a.source_talker == b.source_talker;
}
}
struct Service::Impl {
    struct Task {
        Request request;
        Json view;
        std::chrono::steady_clock::time_point deadline;
    };
    std::shared_ptr<Backend> backend;
    Options options;
    mutable std::mutex mutex;
    std::mutex shutdown_mutex;
    std::condition_variable changed;
    std::map<std::string, Task> tasks;
    std::map<std::string, std::string> requests;
    std::deque<std::string> queue;
    std::thread worker;
    bool stopping = false;
    std::string nonce;
    uint64_t sequence = 0;

    Impl(std::shared_ptr<Backend> b, Options o) : backend(std::move(b)), options(o) {
        if (!backend || !options.max_tasks || !options.max_pending || options.timeout.count() <= 0)
            throw std::invalid_argument("invalid forward service options/backend");
        std::random_device random;
        std::ostringstream id; id << std::hex << Now() << '-' << random() << random(); nonce = id.str();
        worker = std::thread([this] { Run(); });
    }
    bool Stopping() { std::lock_guard<std::mutex> lock(mutex); return stopping; }
    void Expire(Task& task) { // caller owns mutex; backend ownership stays alive until it returns
        if (task.view.contains("finished_at_ms") || std::chrono::steady_clock::now() < task.deadline) return;
        const bool attempted = task.view.value("submission_attempted", false);
        task.view["state"] = attempted ? "unknown" : "failed";
        task.view["error_code"] = "timeout";
        task.view["msg"] = attempted ? "Native outcome is unknown; do not automatically retry." : "Task deadline expired before native submission.";
        task.view["finished_at_ms"] = Now(); task.view["updated_at_ms"] = Now();
    }
    void State(const std::string& id, const char* state, Error error = {}) {
        std::lock_guard<std::mutex> lock(mutex);
        auto& v = tasks.at(id).view;
        if (v.contains("finished_at_ms")) return; // late completion cannot erase an uncertain timeout
        v["state"] = state; v["updated_at_ms"] = Now();
        if (error) { v["error_code"] = error.code; v["msg"] = error.message; }
        if (std::string(state) == "failed" || std::string(state) == "unknown" || std::string(state) == "submitted")
            v["finished_at_ms"] = Now();
    }
    bool Interrupted(const std::string& id, const Context& c, bool submitted = false) {
        if (!c.Cancelled() && !c.Expired()) return false;
        State(id, submitted ? "unknown" : "failed", {c.Cancelled() ? "service_stopping" : "timeout",
            submitted ? "Native submission outcome is unknown; do not automatically retry." : "Task ended before native submission."});
        return true;
    }
    void Run() {
        for (;;) {
            std::string id; Request request; std::chrono::steady_clock::time_point deadline;
            {
                std::unique_lock<std::mutex> lock(mutex);
                changed.wait(lock, [this] { return stopping || !queue.empty(); });
                if (stopping) return;
                id = queue.front(); queue.pop_front();
                request = tasks.at(id).request; deadline = tasks.at(id).deadline;
            }
            Context context{deadline, [this] { return Stopping(); }};
            bool attempting = false;
            try {
                if (Interrupted(id, context)) continue;
                State(id, "resolving");
                auto resolved = backend->Resolve(request, context);
                if (Interrupted(id, context)) continue;
                if (resolved.message) {
                    std::lock_guard<std::mutex> lock(mutex);
                    tasks.at(id).view["source_evidence"] = resolved.message->evidence;
                    tasks.at(id).view["message_kind"] = resolved.message->kind;
                }
                if (resolved.error || !resolved.message) {
                    State(id, "failed", resolved.error ? resolved.error : Error{"native_resolve_failed", "No native message returned."});
                    continue;
                }
                if (resolved.message->kind == "image" || resolved.message->kind == "file") {
                    State(id, "downloading");
                    auto error = backend->PrepareMedia(request, resolved.message, context);
                    if (Interrupted(id, context)) continue;
                    if (error) { State(id, "failed", error); continue; }
                } else if (resolved.message->kind != "text" && resolved.message->kind != "link") {
                    State(id, "failed", {"type_not_supported", "Only text, link, image and file are supported."}); continue;
                }
                // Claim the submission under the same lock as shutdown. The
                // backend must still check context before any native side effect.
                {
                    std::lock_guard<std::mutex> lock(mutex);
                    if (stopping || context.Expired()) {
                        auto& v = tasks.at(id).view;
                        v["state"] = "failed"; v["error_code"] = stopping ? "service_stopping" : "timeout";
                        v["msg"] = "Task ended before native submission."; v["finished_at_ms"] = Now();
                        continue;
                    }
                    tasks.at(id).view["state"] = "submitting";
                    tasks.at(id).view["submission_attempted"] = true;
                    tasks.at(id).view["updated_at_ms"] = Now();
                    attempting = true;
                }
                auto result = backend->Submit(request, resolved.message, context);
                if (Interrupted(id, context, true)) continue;
                if (result.server_return) {
                    {
                        std::lock_guard<std::mutex> lock(mutex);
                        tasks.at(id).view["server_response"] = {{"parsed", true}, {"ret", *result.server_return},
                            {"status", *result.server_return == 0 ? "accepted" : "rejected"}};
                    }
                    if (*result.server_return != 0) {
                        State(id, "failed", {"server_rejected", "Server explicitly rejected submission: " + std::to_string(*result.server_return)});
                        continue;
                    }
                    State(id, "submitted"); continue;
                }
                if (result.state == SubmissionState::Submitted) State(id, "submitted");
                else if (result.state == SubmissionState::Rejected)
                    State(id, "failed", result.error ? result.error : Error{"native_call_failed", "Native operation rejected the submission."});
                else State(id, "unknown", result.error ? result.error : Error{"outcome_unknown", "Submission result is not confirmed; do not automatically retry."});
            } catch (const std::exception& e) {
                State(id, attempting ? "unknown" : "failed", {attempting ? "outcome_unknown" : "backend_exception", e.what()});
            } catch (...) {
                State(id, attempting ? "unknown" : "failed", {attempting ? "outcome_unknown" : "backend_exception", "Unhandled backend failure."});
            }
        }
    }
};
Service::Service(std::shared_ptr<Backend> b, Options o) : impl_(new Impl(std::move(b), o)) {}
Service::~Service() { Shutdown(); }
void Service::Shutdown() {
    std::lock_guard<std::mutex> shutdown(impl_->shutdown_mutex);
    {
        std::lock_guard<std::mutex> lock(impl_->mutex);
        impl_->stopping = true;
        for (auto& task : impl_->tasks) {
            auto& v = task.second.view;
            if (v.contains("finished_at_ms")) continue;
            const bool attempted = v.value("submission_attempted", false);
            v["state"] = attempted ? "unknown" : "failed"; v["error_code"] = "service_stopping";
            v["msg"] = attempted ? "Service stopped with uncertain native outcome; do not automatically retry." : "Service stopped before native submission.";
            v["finished_at_ms"] = Now(); v["updated_at_ms"] = Now();
        }
        impl_->queue.clear();
    }
    impl_->changed.notify_all();
    if (impl_->worker.joinable()) impl_->worker.join();
}
Reply Service::Enqueue(const Json& input) {
    if (!input.is_object()) return Fail(400, "invalid_request", "Request must be a JSON object.");
    if (input.contains("quad_id")) return Fail(400, "unsupported_legacy_identifier", "quad_id cannot identify a native WeChat 4.x message; supply msgsvrid.");
    Request req;
    if (!Text(input, "toid", req.toid, 256, true)) return Fail(400, "target_invalid", "toid must be a nonempty identifier without control characters.");
    if (!Text(input, "source_talker", req.source_talker, 256, false) || !Text(input, "request_id", req.request_id, 128, false))
        return Fail(400, "invalid_request", "Invalid source_talker or request_id.");
    for (unsigned char c : req.request_id)
        if (!(c >= '0' && c <= '9') && !(c >= 'A' && c <= 'Z') && !(c >= 'a' && c <= 'z') &&
            c != '-' && c != '_' && c != '.' && c != ':') return Fail(400, "invalid_request", "request_id uses letters, digits, dash, underscore, dot or colon only.");
    bool hasId = false;
    for (const char* field : {"msgsvrid", "msgid"}) {
        if (!input.contains(field)) continue;
        uint64_t value = 0;
        if (!ids::ParseUint64(input[field], value) || value == 0 || (hasId && req.msg_svr_id != value))
            return Fail(400, "invalid_message_id", "msgsvrid/msgid must be matching positive uint64 decimal strings or JSON integers.");
        req.msg_svr_id = value; hasId = true;
    }
    if (!hasId) return Fail(400, "invalid_message_id", "msgsvrid is required.");
    std::lock_guard<std::mutex> lock(impl_->mutex);
    if (!req.request_id.empty()) {
        auto found = impl_->requests.find(req.request_id);
        if (found != impl_->requests.end()) {
            auto& task = impl_->tasks.at(found->second);
            if (!Same(task.request, req)) return Fail(409, "request_id_conflict", "request_id already identifies different parameters.");
            impl_->Expire(task);
            return {200, {{"code", "0"}, {"accepted", true}, {"replayed", true}, {"task_id", found->second}, {"request_id", req.request_id}, {"task", task.view}}};
        }
    }
    if (impl_->stopping) return Fail(503, "service_stopping", "Forward service is stopping.");
    if (impl_->tasks.size() >= impl_->options.max_tasks || impl_->queue.size() >= impl_->options.max_pending)
        return Fail(503, "task_capacity", "Task or queue capacity reached; no task was submitted.");
    std::string id;
    do { id = "fw-" + impl_->nonce + '-' + std::to_string(++impl_->sequence); }
    while (impl_->tasks.count(id) || (req.request_id.empty() && impl_->requests.count(id)));
    if (req.request_id.empty()) req.request_id = id;
    Impl::Task task;
    task.request = req; task.deadline = std::chrono::steady_clock::now() + impl_->options.timeout;
    const auto now = Now();
    task.view = {{"task_id", id}, {"request_id", req.request_id}, {"state", "queued"}, {"msgsvrid", std::to_string(req.msg_svr_id)},
        {"toid", req.toid}, {"source_talker", req.source_talker}, {"created_at_ms", now}, {"updated_at_ms", now},
        {"deadline_at_ms", now + impl_->options.timeout.count()}, {"submission_attempted", false}, {"delivery_status", "unverified"}};
    impl_->tasks.emplace(id, std::move(task)); impl_->requests.emplace(req.request_id, id); impl_->queue.push_back(id);
    impl_->changed.notify_one();
    return {202, {{"code", "0"}, {"accepted", true}, {"replayed", false}, {"task_id", id}, {"request_id", req.request_id},
        {"msg", "Task accepted; neither native submission nor delivery is confirmed."}}};
}
Reply Service::Get(const std::string& id) const {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    auto found = impl_->tasks.find(id);
    if (found == impl_->tasks.end()) return Fail(404, "task_not_found", "Task does not exist in this process.");
    impl_->Expire(found->second);
    return {200, {{"code", "0"}, {"task", found->second.view}}};
}
Json Service::Capabilities() const {
    auto out = impl_->backend->Capabilities();
    out["async_tasks"] = true; out["timeout_seconds"] = impl_->options.timeout.count() / 1000;
    out["max_tasks"] = impl_->options.max_tasks; out["max_pending"] = impl_->options.max_pending;
    out["deduplication_scope"] = "current_process";
    out["delivery_confirmation"] = "unavailable";
    {
        std::lock_guard<std::mutex> lock(impl_->mutex);
        out["accepting_tasks"] = !impl_->stopping;
        out["current_tasks"] = impl_->tasks.size(); out["queued_tasks"] = impl_->queue.size();
    }
    return out;
}
void RegisterTaskRoutes(httplib::Server& svr, std::shared_ptr<Service> service) {
    svr.Post("/ForwardMsg", [service](const httplib::Request& req, httplib::Response& res) {
        Reply out{400, {}};
        try { out = service->Enqueue(Json::parse(req.body)); }
        catch (const Json::exception&) { out = Fail(400, "invalid_json", "Malformed JSON request."); }
        res.status = out.status; res.set_content(out.body.dump(), "application/json");
    });
    svr.Get(R"(/wxcx/forward/tasks/([A-Za-z0-9_-]+))", [service](const httplib::Request& req, httplib::Response& res) {
        auto out = service->Get(req.matches[1].str()); res.status = out.status; res.set_content(out.body.dump(), "application/json");
    });
    svr.Get("/wxcx/forward/capabilities", [service](const httplib::Request&, httplib::Response& res) {
        res.set_content(service->Capabilities().dump(), "application/json");
    });
    svr.Post("/wxcx/forward/stop", [service](const httplib::Request&, httplib::Response& res) {
        service->Shutdown();
        res.set_content(Json({{"code", "0"}, {"accepting_tasks", false}, {"state", "stopped"}}).dump(), "application/json");
    });
}
} }
