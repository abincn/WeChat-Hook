// Offline real service and HTTP parser; no sockets or native WeChat code.
#include "httplib.h"
#include "wxcx_text_tasks.h"
#include <atomic>
#include <condition_variable>
#include <future>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <vector>
using namespace wxcx::text;
namespace {
int checks = 0;
#define CHECK(...) do { ++checks; if (!(__VA_ARGS__)) throw std::runtime_error("line " + std::to_string(__LINE__) + ": " #__VA_ARGS__); } while (0)
Json Input(const std::string& id = "one") { return {{"toid", "filehelper"}, {"msg", "hello"}, {"request_id", id}}; }
template<class Predicate> void Until(Predicate predicate) {
    const auto end = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (!predicate()) {
        if (std::chrono::steady_clock::now() >= end) throw std::runtime_error("bounded wait expired");
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}
Json Wait(Service& service, const std::string& id) {
    Json out;
    Until([&] { out = service.Get(id).body.at("task"); return out.contains("finished_at_ms"); });
    CHECK(out["delivery_status"] == "unverified");
    return out;
}
class Fake : public Backend {
public:
    bool login = true, version = true, throwGate = false, throwSubmit = false, hold = false;
    Submission result{SubmissionState::Submitted, {}};
    std::atomic<int> calls{0}, probes{0};
    std::atomic<bool> release{false};
    std::thread::id worker;
    Request received;
    bool LoginReady() override { ++probes; worker = std::this_thread::get_id(); if (throwGate) throw 7; return login; }
    bool VersionReady() override { ++probes; return version; }
    Submission Submit(const Request& r) override {
        received = r; ++calls;
        // Even a failed test cannot leave the service destructor blocked forever.
        if (hold) {
            const auto end = std::chrono::steady_clock::now() + std::chrono::seconds(2);
            while (!release && std::chrono::steady_clock::now() < end)
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        if (throwSubmit) throw std::runtime_error("uncertain");
        return result;
    }
};
class MemoryServer : public httplib::Server {
public:
    Reply Call(const std::string& method, const std::string& path, const std::string& body = {}) {
        auto request = method + " " + path + " HTTP/1.1\r\nHost: offline\r\nContent-Type: application/json\r\nContent-Length: " +
            std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
        httplib::detail::BufferStream stream; stream.write(request.data(), request.size()); bool closed = false;
        CHECK(process_request(stream, true, closed, {}));
        const auto response = stream.get_buffer().substr(request.size());
        return {std::stoi(response.substr(9, 3)), Json::parse(response.substr(response.find("\r\n\r\n") + 4))};
    }
};
void Validation() {
    auto b = std::make_shared<Fake>(); Service s(b);
    CHECK(s.Enqueue(Json::array()).status == 400);
    CHECK(s.Status()["login_ready"].is_null()); CHECK(b->probes == 0);
    for (auto key : {"wxidorgid", "toid", "to_wxid", "wxid", "gid", "username"}) {
        Json in = {{key, "filehelper"}, {"text", "hello"}};
        CHECK(s.Enqueue(in).status == 202);
        in["toid"] = "different";
        if (std::string(key) != "toid") CHECK(s.Enqueue(in).status == 400);
    }
    for (auto key : {"msg", "content", "text"}) {
        Json in = {{"toid", "filehelper"}, {key, "hello"}};
        CHECK(s.Enqueue(in).status == 202);
        in["msg"] = "different";
        if (std::string(key) != "msg") CHECK(s.Enqueue(in).status == 400);
    }
    for (const auto& bad : std::vector<std::string>{"", " ", "a b", "a,b", "a\nb", std::string("x\0y", 3),
        std::string("\xc0\xaf", 2), std::string("\xed\xa0\x80", 3), std::string("\xf4\x90\x80\x80", 4),
        std::string("\xe2\x82", 2), std::string("\xc2\x85", 2), std::string(257, 'x')}) {
        auto in = Input(); in["toid"] = bad; CHECK(s.Enqueue(in).status == 400);
    }
    for (const auto& bad : std::vector<std::string>{"", " \r\n\t", std::string("a\0b", 3),
        std::string("\xff", 1), std::string(32769, 'x')}) {
        auto in = Input(); in["msg"] = bad; CHECK(s.Enqueue(in).status == 400);
    }
    for (const auto& bad : std::vector<Json>{false, 5, Json::array(), nullptr}) {
        auto in = Input(); in["toid"] = bad; CHECK(s.Enqueue(in).status == 400);
        in = Input(); in["msg"] = bad; CHECK(s.Enqueue(in).status == 400);
        in = Input(); in["request_id"] = bad; CHECK(s.Enqueue(in).status == 400);
    }
    auto in = Input("mention"); in["at"] = {"wxid_A", "wxid_B"}; in["atlist"] = "wxid_A,wxid_B";
    in["msg"] = "你好\n\t🌍";
    auto a = s.Enqueue(in); CHECK(a.status == 202);
    CHECK(Wait(s, a.body["task_id"])["atlist"] == "wxid_A,wxid_B");
    in["atlist"] = "wxid_B,wxid_A"; CHECK(s.Enqueue(in).status == 400);
    for (const auto& bad : std::vector<Json>{"a,", "a,,b", " a", "a,b\n", 42, Json::array({"a,b"})}) {
        in = Input(); in["at"] = bad; CHECK(s.Enqueue(in).status == 400);
    }
    in = Input(); in["request_id"] = std::string(129, 'x'); CHECK(s.Enqueue(in).status == 400);
    CHECK(s.Get("missing").status == 404);
}
void Outcomes() {
    for (int mode = 0; mode < 7; ++mode) {
        auto b = std::make_shared<Fake>();
        if (mode == 1) b->login = false;
        if (mode == 2) b->version = false;
        if (mode == 3) b->result = {SubmissionState::Rejected, {"fake_rejection", "Rejected"}};
        if (mode == 4) b->result = {};
        if (mode == 5) b->throwSubmit = true;
        if (mode == 6) b->throwGate = true;
        Service s(b); auto a = s.Enqueue(Input()); CHECK(a.status == 202);
        auto t = Wait(s, a.body["task_id"]);
        CHECK(t["state"] == (mode == 0 ? "submitted" : mode <= 3 ? "failed" : "unknown"));
        CHECK(t["local_submission_complete"] == (mode == 0));
        CHECK(b->worker != std::this_thread::get_id());
        CHECK(b->calls == ((mode == 1 || mode == 2 || mode == 6) ? 0 : 1));
        auto replay = s.Enqueue(Input()); CHECK(replay.status == 200); CHECK(replay.body["task_id"] == a.body["task_id"]);
        CHECK(s.Enqueue({{"toid", "other"}, {"msg", "hello"}, {"request_id", "one"}}).status == 409);
        s.Stop(); CHECK(s.Enqueue(Input("new")).status == 503);
    }
}
void ConcurrentDedup() {
    auto b = std::make_shared<Fake>(); Service s(b);
    std::vector<std::future<Reply>> work;
    for (int i = 0; i < 24; ++i) work.push_back(std::async(std::launch::async, [&] { return s.Enqueue(Input()); }));
    std::string id; int accepted = 0;
    for (auto& f : work) {
        auto r = f.get(); CHECK(r.status == 200 || r.status == 202);
        if (r.status == 202) ++accepted;
        if (id.empty()) id = r.body["task_id"];
        CHECK(r.body["task_id"] == id);
    }
    CHECK(accepted == 1); Wait(s, id); CHECK(b->calls == 1);
    auto in = Input(); in["at"] = "wxid_other"; CHECK(s.Enqueue(in).status == 409);
    in = Input(); in["msg"] = "changed"; CHECK(s.Enqueue(in).status == 409);
}
void BoundsStopAndDeadline() {
    {
        auto b = std::make_shared<Fake>(); b->hold = true; Service s(b);
        auto first = s.Enqueue(Input("first")); Until([&] { return b->calls == 1; });
        for (int i = 0; i < 63; ++i) CHECK(s.Enqueue(Input(std::to_string(i))).status == 202);
        CHECK(s.Enqueue(Input("overflow")).status == 503);
        auto stopping = std::async(std::launch::async, [&] { s.Stop(); });
        Until([&] { return s.Status()["stopping"] == true; });
        CHECK(s.Get(first.body["task_id"]).body["task"]["state"] == "unknown");
        auto queued = s.Enqueue(Input("0")); CHECK(queued.body["task"]["state"] == "failed");
        b->release = true; CHECK(stopping.wait_for(std::chrono::seconds(3)) == std::future_status::ready); stopping.get();
        CHECK(b->calls == 1); CHECK(s.Status()["pending_tasks"] == 0); s.Stop();
    }
    {
        auto b = std::make_shared<Fake>(); b->hold = true; Options o; o.timeout = std::chrono::milliseconds(30);
        Service s(b, o); auto a = s.Enqueue(Input("active")); Until([&] { return b->calls == 1; });
        auto q = s.Enqueue(Input("queued"));
        CHECK(Wait(s, a.body["task_id"])["state"] == "unknown");
        CHECK(Wait(s, q.body["task_id"])["state"] == "failed");
        b->release = true; s.Stop(); CHECK(b->calls == 1);
        CHECK(s.Get(a.body["task_id"]).body["task"]["state"] == "unknown");
    }
    {
        auto b = std::make_shared<Fake>(); Service s(b);
        std::string first;
        for (int i = 0; i < 1024; ++i) {
            auto a = s.Enqueue(Input(std::to_string(i))); CHECK(a.status == 202);
            if (i == 0) first = a.body["task_id"];
            Wait(s, a.body["task_id"]);
        }
        CHECK(s.Status()["current_tasks"] == 1024);
        CHECK(s.Enqueue(Input("full")).status == 503);
        CHECK(s.Get(first).status == 200); CHECK(s.Enqueue(Input("0")).body["task_id"] == first);
    }
}
void Http() {
    auto b = std::make_shared<Fake>(); auto s = std::make_shared<Service>(b); MemoryServer server; RegisterRoutes(server, s);
    for (auto path : {"/SendTextMsg", "/SendTextMsg_NoSrc", "/SendAtMsg_NoSrc"}) {
        auto in = Input(path); in["at"] = {"wxid_A", "wxid_B"};
        auto a = server.Call("POST", path, in.dump()); CHECK(a.status == 202);
        const auto id = a.body["task_id"].get<std::string>(); Wait(*s, id);
        auto t = server.Call("GET", "/wxcx/text/tasks/" + id); CHECK(t.status == 200);
        CHECK(t.body["task"]["delivery_status"] == "unverified");
        CHECK(t.body["task"]["state"] == "submitted");
        CHECK(server.Call("POST", path, in.dump()).status == 200);
    }
    CHECK(server.Call("POST", "/SendTextMsg", "{").status == 400);
    CHECK(server.Call("POST", "/SendTextMsg", std::string(262145, 'x')).status == 413);
    CHECK(server.Call("POST", "/SendTextMsg", "{\"toid\":\"x\",\"msg\":\"\xff\"}").status == 400);
    CHECK(server.Call("GET", "/wxcx/text/tasks/missing").status == 404);
    CHECK(server.Call("GET", "/wxcx/text/status").body["max_pending"] == 64);
    CHECK(server.Call("POST", "/wxcx/text/stop").status == 200);
    CHECK(server.Call("POST", "/SendTextMsg", Input("after").dump()).status == 503);
}
}
void StructuredSendsRejected() {
    auto backend = std::make_shared<Fake>();
    auto service = std::make_shared<Service>(backend);
    for (const auto key : {"quote", "refermsg", "quote_msgsvrid", "reply_to", "reference_id", "reference", "card", "appmsg"}) {
        auto input = Input(); input[key] = nullptr;
        auto result = service->Enqueue(input);
        CHECK(result.status == 501);
        CHECK(result.body["error_code"] == "structured_send_unsupported");
    }
    MemoryServer server; RegisterRoutes(server, service);
    for (const auto path : {"/SendQuoteMsg", "/SendCardMsg_NoSrc", "/SendFinderMsg_NoSrc"}) {
        auto result = server.Call("POST", path, Input().dump());
        CHECK(result.status == 501); CHECK(result.body["supported"] == false);
    }
    CHECK(backend->calls == 0); CHECK(service->Status()["current_tasks"] == 0);
}
int main() {
    try {
        Validation(); Outcomes(); ConcurrentDedup(); BoundsStopAndDeadline(); Http(); StructuredSendsRejected();
        std::cout << "PASS " << checks << " checks: real text service, bounded registry, gates, dedup, stop, deadlines, HTTP memory transport\n";
        return 0;
    } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
