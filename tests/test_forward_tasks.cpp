// Offline: real task engine/routes, cooperative backend substitutes, no sockets,
// native WeChat calls, deployment, message sends or target module loading.
#include "httplib.h"
#include "wxcx_forward.h"
#include "wxcx_forward_response.h"
#include "wxcx_msgloc.h"
#include <atomic>
#include <condition_variable>
#include <iostream>
#include <mutex>
#include <thread>
#include <stdexcept>
#include <vector>
using namespace wxcx::forward;
namespace {
int checks = 0;
#define CHECK(...) do { ++checks; if (!(__VA_ARGS__)) throw std::runtime_error("line " + std::to_string(__LINE__) + ": " #__VA_ARGS__); } while (0)
bool verified = true;
std::string lookupStatus = "found";
Json Input(std::string id = "one") { return {{"toid", "filehelper"}, {"msgsvrid", "9007199254740993"}, {"request_id", id}}; }
Json Wait(Service& service, const std::string& id) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (std::chrono::steady_clock::now() < deadline) {
        auto result = service.Get(id).body.at("task");
        auto state = result["state"].get<std::string>();
        if (state == "submitted" || state == "failed" || state == "unknown") return result;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    throw std::runtime_error("task did not finish");
}
class Fake : public Backend {
public:
    std::string kind = "text", mode;
    std::atomic<int> resolves{0}, prepares{0}, submissions{0}, alive{0};
    std::atomic<bool> release{false};
    std::thread::id nativeThread;
    struct Owned : Message {
        std::atomic<int>& alive;
        Owned(std::atomic<int>& value, const std::string& k) : alive(value) { kind = k; ++alive; evidence = {{"owned", true}}; }
        ~Owned() override { --alive; }
    };
    Resolution Resolve(const Request&, const Context& c) override {
        ++resolves; nativeThread = std::this_thread::get_id();
        if (mode == "held_resolve") while (!release) std::this_thread::sleep_for(std::chrono::milliseconds(1));
        if (mode == "resolve_pause") while (!c.Cancelled() && !c.Expired()) std::this_thread::sleep_for(std::chrono::milliseconds(1));
        if (mode == "ambiguous") return {{}, {"source_ambiguous", "two sources"}};
        if (mode == "missing") return {{}, {"source_not_found", "no source"}};
        if (mode == "version") return {{}, {"version_mismatch", "different binary"}};
        return {std::make_shared<Owned>(alive, kind), {}};
    }
    Error PrepareMedia(const Request&, const std::shared_ptr<Message>&, const Context& c) override {
        ++prepares;
        if (mode == "media_fail") return {"resource_failed", "download failed"};
        if (mode == "media_timeout") while (!c.Expired() && !c.Cancelled()) std::this_thread::sleep_for(std::chrono::milliseconds(1));
        return {};
    }
    Submission Submit(const Request&, const std::shared_ptr<Message>& message, const Context& c) override {
        ++submissions;
        if (mode == "held_submit") while (!release) std::this_thread::sleep_for(std::chrono::milliseconds(1));
        if (!message || alive != 1) throw std::runtime_error("owner missing before submit");
        if (mode == "submit_throw") throw std::runtime_error("native completion unavailable");
        if (mode == "server_reject") return {SubmissionState::Submitted, {}, -2};
        if (mode == "server_accept") return {SubmissionState::Unknown, {}, 0};
        if (mode == "submit_timeout") while (!c.Expired() && !c.Cancelled()) std::this_thread::sleep_for(std::chrono::milliseconds(1));
        if (mode == "reject") return {SubmissionState::Rejected, {"target_invalid", "target disappeared"}};
        if (mode == "unknown") return {};
        return {SubmissionState::Submitted, {}};
    }
    Json Capabilities() override { return {{"test_backend", true}}; }
};
class MemoryServer : public httplib::Server {
public:
    Reply Call(const std::string& method, const std::string& path, const std::string& body = {}) {
        const auto request = method + " " + path + " HTTP/1.1\r\nHost: offline\r\nContent-Type: application/json\r\nContent-Length: " +
            std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
        httplib::detail::BufferStream stream; stream.write(request.data(), request.size()); bool closed = false;
        CHECK(process_request(stream, true, closed, {}));
        const auto response = stream.get_buffer().substr(request.size());
        return {std::stoi(response.substr(9, 3)), Json::parse(response.substr(response.find("\r\n\r\n") + 4))};
    }
};
void InputsAndDeduplication() {
    auto backend = std::make_shared<Fake>(); Service service(backend);
    for (const Json& id : std::vector<Json>{0, -1, true, 1.0, "0", "18446744073709551616", "1.0", "-1"}) {
        auto in = Input(); in["msgsvrid"] = id; CHECK(service.Enqueue(in).status == 400);
    }
    auto in = Input(); in["quad_id"] = 12; CHECK(service.Enqueue(in).body["error_code"] == "unsupported_legacy_identifier");
    in = Input(); in["toid"] = "\n"; CHECK(service.Enqueue(in).body["error_code"] == "target_invalid");
    in = Input(); in["request_id"] = "a b"; CHECK(service.Enqueue(in).status == 400);
    in = Input(); in["msgid"] = "3"; CHECK(service.Enqueue(in).status == 400);
    in = Input(); in["msgsvrid"] = "18446744073709551615";
    auto first = service.Enqueue(in); CHECK(first.status == 202);
    auto id = first.body["task_id"].get<std::string>();
    CHECK(Wait(service, id)["msgsvrid"] == "18446744073709551615");
    std::vector<std::thread> readers; std::atomic<int> replayed{0};
    for (int n = 0; n < 12; ++n) readers.emplace_back([&] { auto r = service.Enqueue(in); if (r.status == 200 && r.body["task_id"] == id) ++replayed; });
    for (auto& reader : readers) reader.join();
    CHECK(replayed == 12); CHECK(backend->resolves == 1); CHECK(backend->submissions == 1);
    in["toid"] = "different"; CHECK(service.Enqueue(in).status == 409);
    CHECK(service.Get("missing").status == 404);
    CHECK(service.Capabilities()["deduplication_scope"] == "current_process");
    service.Shutdown(); CHECK(backend->alive == 0);
    CHECK(service.Enqueue(Input("new-after-stop")).status == 503);
}
void ExecutionStatesAndOwnership() {
    for (const std::string& kind : {"text", "link", "image", "file"}) {
        auto backend = std::make_shared<Fake>(); backend->kind = kind; Service service(backend);
        auto accepted = service.Enqueue(Input()); auto task = Wait(service, accepted.body["task_id"]);
        CHECK(task["state"] == "submitted"); CHECK(task["delivery_status"] == "unverified");
        CHECK(task["submission_attempted"] == true); CHECK(backend->submissions == 1);
        CHECK(backend->prepares == ((kind == "image" || kind == "file") ? 1 : 0));
        CHECK(backend->nativeThread != std::this_thread::get_id());
        service.Shutdown(); CHECK(backend->alive == 0);
    }
    const std::vector<std::pair<std::string, std::string>> cases = {
        {"ambiguous", "failed"}, {"missing", "failed"}, {"version", "failed"}, {"media_fail", "failed"},
        {"media_timeout", "failed"}, {"submit_throw", "unknown"}, {"submit_timeout", "unknown"}, {"reject", "failed"}, {"unknown", "unknown"}, {"server_reject", "failed"}, {"server_accept", "submitted"}};
    for (const auto& item : cases) {
        auto backend = std::make_shared<Fake>(); backend->mode = item.first; backend->kind = "file";
        Options options; options.timeout = std::chrono::milliseconds(25); Service service(backend, options);
        auto accepted = service.Enqueue(Input()); auto task = Wait(service, accepted.body["task_id"]);
        CHECK(task["state"] == item.second); CHECK(task["delivery_status"] == "unverified");
        if (item.first == "server_reject") { CHECK(task["error_code"] == "server_rejected"); CHECK(task["server_response"]["ret"] == -2); }
        if (item.first == "server_accept") { CHECK(task["server_response"]["status"] == "accepted"); CHECK(task["server_response"]["ret"] == 0); }
        if (item.first == "media_fail" || item.first == "media_timeout" || item.first == "ambiguous" || item.first == "missing" || item.first == "version") CHECK(backend->submissions == 0);
        auto replay = service.Enqueue(Input()); CHECK(replay.status == 200);
        CHECK(replay.body["task_id"] == accepted.body["task_id"]);
        service.Shutdown(); CHECK(backend->alive == 0);
    }
    auto unsupported = std::make_shared<Fake>(); unsupported->kind = "video"; Service service(unsupported);
    auto accepted = service.Enqueue(Input()); CHECK(Wait(service, accepted.body["task_id"])["error_code"] == "type_not_supported");
    CHECK(unsupported->submissions == 0);
}
void CapacityAndShutdown() {
    auto backend = std::make_shared<Fake>(); backend->mode = "resolve_pause";
    Options options; options.max_pending = 1; options.max_tasks = 3;
    Service service(backend, options); auto first = service.Enqueue(Input("first"));
    const auto until = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (backend->resolves == 0 && std::chrono::steady_clock::now() < until) std::this_thread::yield();
    CHECK(backend->resolves == 1);
    auto second = service.Enqueue(Input("second")); CHECK(second.status == 202);
    CHECK(service.Enqueue(Input("third")).body["error_code"] == "task_capacity");
    service.Shutdown();
    CHECK(Wait(service, first.body["task_id"])["state"] == "failed");
    CHECK(Wait(service, second.body["task_id"])["error_code"] == "service_stopping");
    CHECK(backend->submissions == 0); CHECK(backend->alive == 0);
    auto completed = std::make_shared<Fake>(); Options bound; bound.max_tasks = 1;
    Service bounded(completed, bound); auto one = bounded.Enqueue(Input()); Wait(bounded, one.body["task_id"]);
    CHECK(bounded.Enqueue(Input("two")).status == 503); CHECK(bounded.Enqueue(Input()).status == 200);
}
void RoutesAndProductionGate() {
    auto backend = std::make_shared<Fake>(); auto service = std::make_shared<Service>(backend);
    MemoryServer server; RegisterTaskRoutes(server, service);
    CHECK(server.Call("POST", "/ForwardMsg", "{").status == 400);
    CHECK(server.Call("POST", "/ForwardMsg", R"({"toid":"filehelper","quad_id":12})").status == 400);
    auto response = server.Call("POST", "/ForwardMsg", Input().dump()); CHECK(response.status == 202);
    auto id = response.body["task_id"].get<std::string>(); Wait(*service, id);
    CHECK(server.Call("GET", "/wxcx/forward/tasks/" + id).body["task"]["state"] == "submitted");
    CHECK(server.Call("GET", "/wxcx/forward/tasks/not-found").status == 404);
    CHECK(server.Call("GET", "/wxcx/forward/capabilities").body["async_tasks"] == true);
    CHECK(server.Call("POST", "/wxcx/forward/stop", "{}").body["state"] == "stopped");
    CHECK(server.Call("GET", "/wxcx/forward/capabilities").body["accepting_tasks"] == false);
    CHECK(server.Call("POST", "/ForwardMsg", Input("stopped").dump()).status == 503);
    MemoryServer native; RegisterRoutes(native);
    auto caps = native.Call("GET", "/wxcx/forward/capabilities").body;
    for (const char* kind : {"text", "link", "image", "file"}) CHECK(caps["types"][kind]["available"] == false);
    for (const std::string& expected : {"native_abi_unverified", "version_mismatch", "source_ambiguous", "source_not_found", "source_lookup_incomplete"}) {
        verified = expected != "version_mismatch";
        lookupStatus = expected == "source_ambiguous" ? "ambiguous" : expected == "source_not_found" ? "not_found" : expected == "source_lookup_incomplete" ? "lookup_incomplete" : "found";
        auto req = Input(expected); auto accepted = native.Call("POST", "/ForwardMsg", req.dump()); CHECK(accepted.status == 202);
        Json task; const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
        do { task = native.Call("GET", "/wxcx/forward/tasks/" + accepted.body["task_id"].get<std::string>()).body["task"]; std::this_thread::sleep_for(std::chrono::milliseconds(1)); }
        while (task["state"] != "failed" && std::chrono::steady_clock::now() < deadline);
        CHECK(task["state"] == "failed"); CHECK(task["error_code"] == expected); CHECK(task["submission_attempted"] == false);
        if (expected == "native_abi_unverified") CHECK(task["source_evidence"]["lookup_status"] == "found");
    }
}
void DeadlineWhileBackendOwnsMessage() {
    for (const std::string& phase : {"held_resolve", "held_submit"}) {
        auto backend = std::make_shared<Fake>(); backend->mode = phase;
        Options options; options.timeout = std::chrono::milliseconds(200);
        Service service(backend, options);
        struct ReleaseOnExit { Fake& backend; ~ReleaseOnExit() { backend.release = true; } } releaseOnExit{*backend};
        auto accepted = service.Enqueue(Input());
        const auto startedDeadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
        while ((phase == "held_submit" ? backend->submissions.load() : backend->resolves.load()) == 0 && std::chrono::steady_clock::now() < startedDeadline)
            std::this_thread::yield();
        CHECK((phase == "held_submit" ? backend->submissions.load() : backend->resolves.load()) == 1);
        auto terminal = Wait(service, accepted.body["task_id"]);
        // GET expires the public task even while native cleanup/completion is
        // still pending; the backend owner is not destroyed by the HTTP thread.
        CHECK(terminal["state"] == (phase == "held_submit" ? "unknown" : "failed"));
        CHECK(terminal["error_code"] == "timeout");
        if (phase == "held_submit") CHECK(backend->alive == 1);
        backend->release = true; service.Shutdown();
        CHECK(service.Get(accepted.body["task_id"]).body["task"]["state"] == terminal["state"]);
        CHECK(backend->alive == 0); CHECK(backend->submissions <= 1);
    }
}
void ExplicitResponseParsing() {
    auto parse = [](std::initializer_list<uint8_t> bytes) { return ParseSendAppMsgResponse(bytes.begin(), bytes.size()); };
    auto zero = parse({0x0a, 0x02, 0x08, 0x00});
    CHECK(zero.state == ResponseParseState::Parsed && zero.server_return && *zero.server_return == 0);
    auto negative = parse({0x0a, 0x0b, 0x08, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01});
    CHECK(negative.state == ResponseParseState::Parsed && *negative.server_return == -2);
    auto negative32 = parse({0x0a, 0x06, 0x08, 0xfe, 0xff, 0xff, 0xff, 0x0f});
    CHECK(negative32.state == ResponseParseState::Parsed && *negative32.server_return == -2);
    CHECK(parse({}).state == ResponseParseState::Missing);
    CHECK(parse({0x0a, 0x00}).state == ResponseParseState::Missing);
    CHECK(parse({0x10, 0x07}).state == ResponseParseState::Missing);
    CHECK(parse({0x0a, 0x03, 0x12, 0x01, 0x61}).state == ResponseParseState::Missing);
    CHECK(parse({0x0a, 0x05, 0x08, 0x00, 0x12, 0x01, 0x61, 0x15, 0, 0, 0, 0}).state == ResponseParseState::Parsed);
    for (const std::vector<uint8_t>& bytes : std::vector<std::vector<uint8_t>>{
        {0x00}, {0x0a}, {0x0a,0x02,0x08}, {0x0a,0x02,0x08,0x80}, {0x0a,0x02,0x08,0x00,0x00},
        {0x0a,0x04,0x08,0x00,0x08,0x00}, {0x0a,0x02,0x08,0x00,0x0a,0x02,0x08,0x01},
        {0x0a,0x02,0x08,0x00,0x13}, {0x0a,0x06,0x08,0x80,0x80,0x80,0x80,0x10},
        {0x0a,0x0b,0x08,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x02}}) {
        auto result = ParseSendAppMsgResponse(bytes.data(), bytes.size());
        CHECK(result.state == ResponseParseState::Invalid); CHECK(!result.server_return);
    }
    CHECK(ParseSendAppMsgResponse(nullptr, 1).state == ResponseParseState::Invalid);
    CHECK(ParseSendAppMsgResponse(nullptr, 8 * 1024 * 1024 + 1).state == ResponseParseState::Invalid);
}
} // namespace
// Production dependency substitutes, not native implementations.
namespace wxcx {
nlohmann::json RuntimeIdentity() { return {{"weixin", {{"verified", ::verified}}}}; }
namespace msgloc {
UniqueResult LocateUnique(uint64_t id, const std::string&, const std::function<bool()>&) {
    UniqueResult result; result.status = ::lookupStatus; result.complete = result.status != "lookup_incomplete";
    result.detail = "offline lookup substitute";
    if (result.status == "found") result.matches.push_back({"MSG1.db", "MSG", "source", "49", 7, id});
    return result;
}
} }
int main() {
    try {
        InputsAndDeduplication(); ExecutionStatesAndOwnership(); CapacityAndShutdown(); RoutesAndProductionGate(); DeadlineWhileBackendOwnsMessage(); ExplicitResponseParsing();
        std::cout << "PASS " << checks << " checks: task protocol, native gate, ownership, deadlines, deduplication and HTTP memory transport\n";
        return 0;
    } catch (const std::exception& e) { std::cerr << "FAIL after " << checks << " checks: " << e.what() << '\n'; return 1; }
}
