#include "httplib.h"
#include "wxcx_text_tasks.h"
#include <algorithm>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <map>
#include <mutex>
#include <random>
#include <sstream>
#include <stdexcept>
#include <thread>

namespace wxcx { namespace text {
namespace {
int64_t Now() { return std::chrono::duration_cast<std::chrono::milliseconds>(
    std::chrono::system_clock::now().time_since_epoch()).count(); }
Reply Fail(int status, const char* code, const char* message) {
    return {status, {{"code", "-1"}, {"error_code", code}, {"msg", message}}};
}
// Decode scalars explicitly: reject overlong encodings, surrogates, truncated
// sequences, out-of-range values and C0/C1 controls. Text permits CR/LF/TAB.
bool Valid(const std::string& s, size_t limit, bool text = false) {
    if (s.empty() || s.size() > limit) return false;
    bool visible = false;
    for (size_t i = 0; i < s.size();) {
        uint32_t cp = static_cast<unsigned char>(s[i++]);
        unsigned n = 0; uint32_t minimum = 0;
        if (cp >= 0x80) {
            if (cp >= 0xc2 && cp <= 0xdf) { n = 1; cp &= 31; minimum = 0x80; }
            else if (cp >= 0xe0 && cp <= 0xef) { n = 2; cp &= 15; minimum = 0x800; }
            else if (cp >= 0xf0 && cp <= 0xf4) { n = 3; cp &= 7; minimum = 0x10000; }
            else return false;
            if (i + n > s.size()) return false;
            while (n--) {
                auto c = static_cast<unsigned char>(s[i++]);
                if ((c & 0xc0) != 0x80) return false;
                cp = (cp << 6) | (c & 63);
            }
            if (cp < minimum || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return false;
        }
        if (cp < 32 || (cp >= 127 && cp <= 159)) {
            if (!text || (cp != 9 && cp != 10 && cp != 13)) return false;
        } else if (cp != 32) visible = true;
        if (!text && (cp == 32 || cp == ',')) return false;
    }
    return visible;
}
bool Alias(const Json& in, std::initializer_list<const char*> keys, std::string& out, size_t limit) {
    bool found = false;
    for (auto key : keys) if (in.contains(key)) {
        if (!in[key].is_string()) return false;
        const auto& s = in[key].get_ref<const std::string&>();
        if (s.size() > limit) return false;
        if (found && s != out) return false;
        out = s; found = true;
    }
    return found;
}
bool Recipients(const Json& value, std::string& out) {
    if (value.is_string()) {
        if (value.get_ref<const std::string&>().size() > 64 * 257) return false;
        out = value.get<std::string>();
    }
    else if (value.is_array() && value.size() <= 64) {
        for (const auto& v : value) {
            if (!v.is_string() || !Valid(v.get_ref<const std::string&>(), 256)) return false;
            if (!out.empty()) out += ',';
            out += v.get_ref<const std::string&>();
        }
    } else return false;
    if (out.empty()) return true;
    if (out.size() > 64 * 257) return false;
    size_t start = 0, count = 0;
    for (;;) {
        auto end = out.find(',', start);
        if (++count > 64 || !Valid(out.substr(start, end - start), 256)) return false;
        if (end == std::string::npos) break;
        start = end + 1;
    }
    return true;
}
bool Same(const Request& a, const Request& b) {
    return a.toid == b.toid && a.msg == b.msg && a.atlist == b.atlist;
}
}
struct Service::Impl {
    struct Task { Request request; Json view; std::chrono::steady_clock::time_point deadline; };
    std::shared_ptr<Backend> backend;
    Options options;
    mutable std::mutex mutex;
    std::mutex shutdown;
    std::condition_variable changed;
    std::map<std::string, Task> tasks;
    std::map<std::string, std::string> requests;
    std::deque<std::string> queue;
    std::thread worker;
    bool stopping = false;
    Json login = nullptr, version = nullptr;
    std::string nonce;
    uint64_t sequence = 0;
    Impl(std::shared_ptr<Backend> b, Options o) : backend(std::move(b)), options(o) {
        if (!backend || !o.max_pending || o.max_pending > 64 || !o.max_tasks || o.max_tasks > 1024 || o.timeout.count() <= 0)
            throw std::invalid_argument("Invalid text backend/options");
        std::random_device random; std::ostringstream s;
        s << std::hex << Now() << '-' << random() << random(); nonce = s.str();
        worker = std::thread([this] { Run(); });
    }
    void Finish(Task& t, const char* state, Error error = {}) {
        if (t.view.contains("finished_at_ms")) return;
        t.view["state"] = state; t.view["updated_at_ms"] = Now(); t.view["finished_at_ms"] = Now();
        t.view["local_submission_complete"] = std::string(state) == "submitted";
        if (!error.code.empty()) {
            t.view["error_code"] = Json::parse(Json(error.code).dump(-1, ' ', false, Json::error_handler_t::replace));
            // Do not trust exception/backend strings to contain valid UTF-8.
            t.view["msg"] = Json::parse(Json(error.message).dump(-1, ' ', false, Json::error_handler_t::replace));
        }
    }
    void Expire(Task& t) {
        if (std::chrono::steady_clock::now() >= t.deadline)
            Finish(t, t.view["submission_attempted"] == true ? "unknown" : "failed",
                {"timeout", "Deadline expired; attempted submissions must not be automatically retried."});
    }
    void Run() {
        for (;;) {
            std::string id; Request request;
            {
                std::unique_lock<std::mutex> lock(mutex);
                changed.wait(lock, [this] { return stopping || !queue.empty(); });
                if (stopping) return;
                id = queue.front(); queue.pop_front();
                auto& task = tasks.at(id); Expire(task);
                if (task.view.contains("finished_at_ms")) continue;
                task.view["state"] = "checking"; request = task.request;
            }
            try {
                const bool readyLogin = backend->LoginReady();
                const bool readyVersion = backend->VersionReady();
                {
                    std::lock_guard<std::mutex> lock(mutex);
                    login = readyLogin; version = readyVersion;
                    auto& t = tasks.at(id); Expire(t);
                    if (stopping || t.view.contains("finished_at_ms")) continue;
                    if (!readyLogin || !readyVersion) {
                        Finish(t, "failed", {!readyLogin ? "login_not_ready" : "version_not_ready", "Native readiness gate rejected the task."});
                        continue;
                    }
                    t.view["state"] = "submitting"; t.view["submission_attempted"] = true;
                    t.view["updated_at_ms"] = Now();
                }
                auto result = backend->Submit(request);
                std::lock_guard<std::mutex> lock(mutex);
                auto& t = tasks.at(id); Expire(t);
                if (result.state == SubmissionState::Submitted) Finish(t, "submitted");
                else if (result.state == SubmissionState::Rejected)
                    Finish(t, "failed", result.error.code.empty() ? Error{"submission_rejected", "Local submission rejected."} : result.error);
                else Finish(t, "unknown", result.error.code.empty() ? Error{"outcome_unknown", "Local submission uncertain; do not automatically retry."} : result.error);
            } catch (...) {
                std::lock_guard<std::mutex> lock(mutex);
                Finish(tasks.at(id), "unknown", {"backend_exception", "Backend threw; outcome is unknown. Do not automatically retry."});
            }
        }
    }
};
Service::Service(std::shared_ptr<Backend> b, Options o) : impl_(new Impl(std::move(b), o)) {}
Service::~Service() { Stop(); }
void Service::Stop() {
    std::lock_guard<std::mutex> shutdown(impl_->shutdown);
    {
        std::lock_guard<std::mutex> lock(impl_->mutex);
        impl_->stopping = true;
        for (auto& item : impl_->tasks)
            impl_->Finish(item.second, item.second.view["submission_attempted"] == true ? "unknown" : "failed",
                {"service_stopping", "Service stopped; uncertain submissions must not be automatically retried."});
        impl_->queue.clear();
    }
    impl_->changed.notify_all();
    if (impl_->worker.joinable()) impl_->worker.join();
}
Reply Service::Enqueue(const Json& in) {
    if (!in.is_object()) return Fail(400, "invalid_request", "JSON object required.");
    for (auto key : {"quote", "refermsg", "quote_msgsvrid", "reply_to", "reference_id", "reference", "card", "appmsg"})
        if (in.contains(key)) return Fail(501, "structured_send_unsupported", "Native quote/card sending is unavailable; request was not queued.");
    Request r;
    if (!Alias(in, {"wxidorgid", "toid", "to_wxid", "wxid", "gid", "username"}, r.toid, 256) || !Valid(r.toid, 256))
        return Fail(400, "target_invalid", "Target aliases must match and contain a valid identifier (1..256 UTF-8 bytes).");
    if (!Alias(in, {"msg", "content", "text"}, r.msg, 32768) || !Valid(r.msg, 32768, true))
        return Fail(400, "message_invalid", "Message aliases must match and contain valid text (1..32768 UTF-8 bytes).");
    if (in.contains("request_id")) {
        if (!in["request_id"].is_string() || in["request_id"].get_ref<const std::string&>().size() > 128)
            return Fail(400, "request_id_invalid", "Invalid request_id.");
        r.request_id = in["request_id"].get<std::string>();
        if (!Valid(r.request_id, 128)) return Fail(400, "request_id_invalid", "Invalid request_id.");
    }
    bool atFound = false;
    for (auto key : {"atlist", "at"}) if (in.contains(key)) {
        std::string recipients;
        if (!Recipients(in[key], recipients) || (atFound && recipients != r.atlist))
            return Fail(400, "atlist_invalid", "Mention recipients must be matching lists of at most 64 valid identifiers.");
        r.atlist = recipients; atFound = true;
    }
    std::lock_guard<std::mutex> lock(impl_->mutex);
    if (!r.request_id.empty()) {
        auto found = impl_->requests.find(r.request_id);
        if (found != impl_->requests.end()) {
            auto& t = impl_->tasks.at(found->second);
            if (!Same(t.request, r)) return Fail(409, "request_id_conflict", "request_id already identifies different parameters.");
            impl_->Expire(t);
            return {200, {{"code", "0"}, {"replayed", true}, {"task_id", found->second}, {"task", t.view}}};
        }
    }
    if (impl_->stopping) return Fail(503, "service_stopping", "Text service has stopped.");
    size_t pending = 0;
    for (auto& item : impl_->tasks) {
        impl_->Expire(item.second);
        if (!item.second.view.contains("finished_at_ms")) ++pending;
    }
    if (impl_->tasks.size() >= impl_->options.max_tasks || pending >= impl_->options.max_pending)
        return Fail(503, "task_capacity", "Task capacity reached; no task was accepted. Retained tasks are never evicted.");
    auto id = "text-" + impl_->nonce + '-' + std::to_string(++impl_->sequence);
    const auto now = Now();
    Json view = {{"task_id", id}, {"request_id", r.request_id}, {"state", "queued"},
        {"toid", r.toid}, {"atlist", r.atlist}, {"created_at_ms", now}, {"updated_at_ms", now},
        {"deadline_at_ms", now + impl_->options.timeout.count()}, {"submission_attempted", false},
        {"local_submission_complete", false}, {"delivery_status", "unverified"}};
    impl_->tasks.emplace(id, Impl::Task{r, view, std::chrono::steady_clock::now() + impl_->options.timeout});
    if (!r.request_id.empty()) impl_->requests.emplace(r.request_id, id);
    // Expired queued entries are removed before enqueue, keeping the physical
    // queue bounded even while a backend call is waiting.
    impl_->queue.erase(std::remove_if(impl_->queue.begin(), impl_->queue.end(), [this](const std::string& key) {
        return impl_->tasks.at(key).view.contains("finished_at_ms");
    }), impl_->queue.end());
    impl_->queue.push_back(id); impl_->changed.notify_one();
    return {202, {{"code", "0"}, {"accepted", true}, {"replayed", false}, {"task_id", id}, {"task", view},
        {"msg", "Queued; submission and delivery are not confirmed."}}};
}
Reply Service::Get(const std::string& id) const {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    auto found = impl_->tasks.find(id);
    if (found == impl_->tasks.end()) return Fail(404, "task_not_found", "Task not found in this process.");
    impl_->Expire(found->second);
    return {200, {{"code", "0"}, {"task", found->second.view}}};
}
Json Service::Status() const {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    size_t pending = 0;
    for (auto& item : impl_->tasks) { impl_->Expire(item.second); if (!item.second.view.contains("finished_at_ms")) ++pending; }
    return {{"accepting_tasks", !impl_->stopping && impl_->tasks.size() < impl_->options.max_tasks && pending < impl_->options.max_pending},
        {"stopping", impl_->stopping}, {"current_tasks", impl_->tasks.size()}, {"pending_tasks", pending},
        {"max_pending", impl_->options.max_pending}, {"max_tasks", impl_->options.max_tasks},
        {"login_ready", impl_->login}, {"version_ready", impl_->version}, {"readiness_source", "last_worker_probe"},
        {"timeout_ms", impl_->options.timeout.count()}, {"deduplication_scope", "current_process"}, {"delivery_status", "unverified"}};
}
void RegisterRoutes(httplib::Server& server, std::shared_ptr<Service> service) {
    if (!service) throw std::invalid_argument("Null text service");
    auto send = [service](const httplib::Request& req, httplib::Response& res) {
        Reply reply;
        if (req.body.size() > 262144) reply = Fail(413, "request_too_large", "Request exceeds 262144 bytes.");
        else {
            try { reply = service->Enqueue(Json::parse(req.body)); }
            catch (const Json::exception&) { reply = Fail(400, "invalid_json", "Malformed JSON or UTF-8."); }
        }
        res.status = reply.status; res.set_content(reply.body.dump(), "application/json");
    };
    for (auto path : {"/SendTextMsg", "/SendTextMsg_NoSrc", "/SendAtMsg_NoSrc"}) server.Post(path, send);
    for (auto path : {"/SendQuoteMsg", "/SendCardMsg_NoSrc", "/SendFinderMsg_NoSrc"})
        server.Post(path, [](const httplib::Request&, httplib::Response& res) {
            res.status = 501;
            res.set_content(Json({{"error", "structured_send_unsupported"}, {"supported", false},
                {"message", "Native quote/card sending is unavailable; no message was queued."}}).dump(), "application/json");
        });
    server.Get(R"(/wxcx/text/tasks/([A-Za-z0-9_-]+))", [service](const httplib::Request& req, httplib::Response& res) {
        auto out = service->Get(req.matches[1].str()); res.status = out.status; res.set_content(out.body.dump(), "application/json");
    });
    server.Get("/wxcx/text/status", [service](const httplib::Request&, httplib::Response& res) {
        res.set_content(service->Status().dump(), "application/json");
    });
    server.Post("/wxcx/text/stop", [service](const httplib::Request&, httplib::Response& res) {
        service->Stop(); res.set_content(Json({{"code", "0"}, {"state", "stopped"}}).dump(), "application/json");
    });
}
} }
