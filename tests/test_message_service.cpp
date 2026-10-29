// Real service + httplib HTTP parser in memory. No sockets, network or WeChat.
#include "httplib.h"
#include "wxcx_message_service.h"
#include <atomic>
#include <condition_variable>
#include <functional>
#include <iostream>
#include <limits>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <vector>
using namespace wxcx::messages;
namespace {
int checks = 0;
#define CHECK(...) do { ++checks; if (!(__VA_ARGS__)) throw std::runtime_error("line " + std::to_string(__LINE__) + ": " #__VA_ARGS__); } while (0)
template<class Predicate> void Until(Predicate predicate) {
    const auto end = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (!predicate()) {
        if (std::chrono::steady_clock::now() >= end) throw std::runtime_error("bounded wait expired");
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}
class FakeSource : public Source {
public:
    std::atomic<bool> enabled{true}, gate{true}, throws{false}, status_throws{false};
    std::atomic<uint64_t> epoch{0};
    std::atomic<int> calls{0};
    std::function<void()> on_enable;
    Json Status() override {
        if (status_throws) throw std::runtime_error("source-private");
        return {{"version_ready", gate.load()}, {"enabled", enabled.load()}, {"epoch", epoch.load()},
            {"callback_token", "forbidden"}, {"diagnostic", "SECRET-current source"}};
    }
    bool SetEnabled(bool value, std::string& error) override {
        ++calls;
        if (on_enable) on_enable();
        if (throws) throw std::runtime_error("SECRET-current native failure");
        if (value && !gate) { error = "SECRET-current unsupported native version"; return false; }
        enabled = value; return true;
    }
    void SetEpoch(uint64_t value) override { epoch = value; }
};
class FakeTransport : public Transport {
public:
    struct Call { std::string url, token, id; Json payload; std::thread::id thread; };
    mutable std::mutex mutex;
    std::condition_variable changed;
    std::vector<Call> calls;
    std::vector<int> replies;
    bool hold = false, released = false, throw_delivery = false;
    DeliveryResult Deliver(const std::string& url, const std::string& token,
        const std::string& id, const Json& payload) override {
        std::unique_lock<std::mutex> lock(mutex);
        const size_t index = calls.size();
        calls.push_back({url, token, id, payload, std::this_thread::get_id()}); changed.notify_all();
        if (hold) changed.wait_for(lock, std::chrono::seconds(2), [&] { return released; });
        if (throw_delivery) throw std::runtime_error(token + " private transport error");
        return {index < replies.size() ? replies[index] : 204, token + " private transport error"};
    }
    size_t Count() const { std::lock_guard<std::mutex> lock(mutex); return calls.size(); }
    Call At(size_t i) const { std::lock_guard<std::mutex> lock(mutex); return calls.at(i); }
    void Release() { std::lock_guard<std::mutex> lock(mutex); released = true; changed.notify_all(); }
};
Options Small() {
    Options o; o.max_events = 8; o.max_outbox = 4; o.max_dedup = 8;
    o.retry_initial = std::chrono::milliseconds(1); o.retry_max = std::chrono::milliseconds(4); return o;
}
Input Message(uint64_t id = 0, std::string from = "peer", std::string to = "self") {
    Input in; in.from = std::move(from); in.to = std::move(to); in.content = "hello";
    in.server_id = id; in.type = 1; return in;
}
void Enable(Service& service, const std::string& self = "self", bool callback = false) {
    Json config = {{"self_id", self}, {"enabled", true}};
    if (callback) { config["callback_url"] = "http://127.0.0.1:8181/old"; config["callback_token"] = "SECRET-current"; }
    CHECK(service.Configure(config).status == 200);
}
Json Event(Service& service, size_t index = 0) { return service.Events(0, 512).body.at("events").at(index); }
void WaitState(Service& service, const std::string& state, size_t index = 0) {
    Until([&] { return Event(service, index)["delivery"]["state"] == state; });
}
class MemoryServer : public httplib::Server {
public:
    Reply Call(const std::string& method, const std::string& path, const std::string& body = {}) {
        const auto request = method + " " + path + " HTTP/1.1\r\nHost: offline\r\nContent-Type: application/json\r\nContent-Length: " +
            std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
        httplib::detail::BufferStream stream; stream.write(request.data(), request.size()); bool closed = false;
        CHECK(process_request(stream, true, closed, {}));
        const auto response = stream.get_buffer().substr(request.size());
        const auto raw = response.substr(response.find("\r\n\r\n") + 4);
        auto parsed = Json::parse(raw, nullptr, false);
        return {std::stoi(response.substr(9, 3)), parsed.is_discarded() ? Json{{"raw", raw}} : parsed};
    }
};
void DefaultsAndValidation() {
    auto source = std::make_shared<FakeSource>(); auto transport = std::make_shared<FakeTransport>();
    Service service(source, transport, "stream", Small());
    CHECK(!source->enabled); CHECK(source->epoch == 1); CHECK(service.Context().epoch == 1);
    CHECK(!service.Publish(Message(), 1, 1)); CHECK(transport->Count() == 0);
    CHECK(service.Status()["enabled"] == false); CHECK(service.Status()["callback_configured"] == false);
    for (const auto& config : std::vector<Json>{nullptr, false, 12, "x", Json::array()}) CHECK(service.Configure(config).status == 400);
    for (const auto& key : {"self_id", "callback_url", "callback_token"})
        for (const auto& value : std::vector<Json>{nullptr, false, 12, Json::array()}) CHECK(service.Configure({{key, value}}).status == 400);
    for (const auto& value : std::vector<Json>{nullptr, "true", 1, Json::array()}) CHECK(service.Configure({{"enabled", value}}).status == 400);
    for (const auto& value : std::vector<Json>{nullptr, true, "3", -1, 0, 11, 1.5, (std::numeric_limits<uint64_t>::max)()})
        CHECK(service.Configure({{"max_attempts", value}}).status == 400);
    for (const auto& url : {"https://127.0.0.1/hook", "http://example.com/hook", "http://127.0.0.2/hook", "http://127.0.0.1.evil/", "http://localhost@evil/",
        "http://evil@localhost/", "http://localhost:/", "http://localhost:0/", "http://localhost:65536/", "http://[::1]evil/", "http://[::1]:/",
        "http://[::1]:999999999999999999999999999/", "http://localhost/#frag", "http://localhost/\r\n", "file:///tmp/", "HTTP://localhost/", "http://localhost\\evil/"})
        CHECK(service.Configure({{"callback_url", url}}).status == 400);
    CHECK(service.Configure({{"callback_url", "https://localhost/"}}).body["error"] == "https_unsupported");
    for (const auto& url : {"http://localhost/", "http://localhost:1/a?x=1", "http://[::1]:65535/hook", "http://127.0.0.1"})
        CHECK(service.Configure({{"callback_url", url}}).status == 200);
    CHECK(service.Configure({{"callback_url", ""}}).status == 200);
    CHECK(service.Configure({{"callback_token", "a b"}}).status == 400);
    CHECK(service.Configure({{"callback_token", std::string("a\0b", 3)}}).status == 400);
    CHECK(service.Configure({{"callback_token", std::string(4097, 'x')}}).status == 400);
    CHECK(service.Configure({{"self_id", "a b"}}).status == 400);
    CHECK(service.Configure({{"self_id", std::string(1025, 'x')}}).status == 400);
    CHECK(service.Configure({{"typo", true}}).status == 400);
    source->gate = false;
    const auto failed = service.Configure({{"enabled", true}, {"self_id", "bad"}, {"callback_token", "SECRET-current"}});
    CHECK(failed.status == 409); CHECK(failed.body.dump().find("SECRET-current") == std::string::npos);
    CHECK(service.Context().self_id.empty()); CHECK(service.Context().epoch == 1); CHECK(source->epoch == 1);
    CHECK(service.Status()["enabled"] == false); CHECK(service.Status()["source"]["version_ready"] == false);
    source->gate = true;
    Enable(service); CHECK(service.Publish(Message(), 2, service.Context().epoch)); CHECK(transport->Count() == 0);
    auto event = Event(service); CHECK(event["delivery"]["state"] == "not_configured");
    CHECK(event["event_id"] == "stream:2:1"); CHECK(event["self_id"] == "self");
    CHECK(event["direction"] == "incoming"); CHECK(event["msgsvrid"].is_null());
    source->on_enable = [&] { const auto context = service.Context(); CHECK(context.epoch >= 1); };
    CHECK(service.Configure({{"enabled", false}}).status == 200);
    source->on_enable = {};
    source->status_throws = true; CHECK(service.Status()["source"]["error"] == "source_status_failed");
    Service polling(std::make_shared<FakeSource>(), nullptr, "polling", Small());
    CHECK(polling.Configure({{"callback_url", "http://localhost/"}}).status == 409);
    Enable(polling); CHECK(polling.Publish(Message(), 1, polling.Context().epoch));
}
void DedupAndCursors() {
    auto source = std::make_shared<FakeSource>(); auto transport = std::make_shared<FakeTransport>();
    auto options = Small(); options.max_events = 3; options.max_dedup = 2;
    Service service(source, transport, "bounded", options); Enable(service);
    const auto epoch = service.Context().epoch;
    CHECK(service.Publish(Message(9007199254740993ULL), 1, epoch));
    CHECK(Event(service)["msgsvrid"] == "9007199254740993");
    CHECK(!service.Publish(Message(9007199254740993ULL), 2, epoch));
    CHECK(service.Publish(Message(9007199254740993ULL, "other"), 4, epoch));
    CHECK(Event(service, 1)["capture_gap"] == true);
    CHECK(service.Publish(Message(9007199254740993ULL, "peer", "other"), 5, epoch));
    CHECK(service.Publish(Message(9007199254740993ULL), 6, epoch)); // FIFO dedup eviction
    CHECK(service.Publish(Message(), 7, epoch)); CHECK(service.Publish(Message(), 8, epoch));
    const auto page = service.Events(0, 2);
    CHECK(page.status == 200); CHECK(page.body["gap"] == true); CHECK(page.body["cache_gap"] == true);
    CHECK(page.body["events"].size() == 2); CHECK(page.body["events"][0]["sequence"] == 4);
    CHECK(page.body["next_after"] == 5); CHECK(page.body["has_more"] == true);
    CHECK(service.Events(5, 2).body["events"].size() == 1); CHECK(service.Events(3, 512).body["gap"] == false);
    CHECK(service.Events(6, 2).body["events"].empty()); CHECK(service.Events(7, 2).status == 400);
    CHECK(service.Events(0, 0).status == 400); CHECK(service.Events(0, 513).status == 400);
    CHECK(service.Status()["events_retained"] == 3); CHECK(service.Status()["dedup_size"] == 2);
    CHECK(service.Status()["counters"]["deduplicated"] == 1); CHECK(service.Status()["counters"]["cache_evicted"] == 3);
    CHECK(service.Status()["counters"]["capture_gaps"] == 1);
    auto invalid = Message(); invalid.content = std::string("\xff", 1);
    CHECK(!service.Publish(invalid, 9, epoch)); CHECK(service.Status()["counters"]["invalid_input"] == 1);
    Enable(service, "new-self"); const auto next = service.Context();
    CHECK(next.epoch == epoch + 1); CHECK(source->epoch == next.epoch);
    CHECK(service.Events(0, 512).body["events"].empty()); CHECK(service.Status()["dedup_size"] == 0);
    CHECK(service.Events(0, 512).body["account_reset_gap"] == true);
    CHECK(service.Events(0, 512).body["next_after"] == 6);
    CHECK(!service.Publish(Message(9), 9, epoch)); CHECK(service.Status()["counters"]["stale_epoch"] == 1);
    auto input = Message(9007199254740993ULL, "peer", "new-self"); input.self_wxid = "wrong-old-self";
    CHECK(service.Publish(input, 1, next.epoch));
    CHECK(Event(service)["self_id"] == "new-self"); CHECK(Event(service)["event_id"] == "bounded:3:7");
    CHECK(Event(service)["capture_gap"] == false);
}
void DeliveryOutcomes() {
    const std::vector<std::vector<int>> cases{{204}, {0, 503, 200}, {408, 429, 201}, {500, 500, 500}, {400}, {302}, {401}, {404}};
    for (const auto& replies : cases) {
        auto source = std::make_shared<FakeSource>(); auto transport = std::make_shared<FakeTransport>(); transport->replies = replies;
        Service service(source, transport, "delivery", Small()); Enable(service, "self", true);
        CHECK(service.Publish(Message(1), 1, service.Context().epoch));
        const auto last = replies.back();
        const std::string state = last >= 200 && last < 300 ? "transport_acknowledged" : last == 500 ? "retry_exhausted" : "permanent_error";
        WaitState(service, state); CHECK(transport->Count() == replies.size());
        const auto first = transport->At(0);
        CHECK(first.thread != std::this_thread::get_id()); CHECK(first.token == "SECRET-current"); CHECK(first.payload["event_id"] == first.id);
        CHECK(first.payload["msgsvrid"] == "1"); CHECK(!first.payload.contains("delivery"));
        for (size_t i = 1; i < replies.size(); ++i) { CHECK(transport->At(i).id == first.id); CHECK(transport->At(i).payload == first.payload); }
        const auto diagnostic = service.Status().dump() + service.Events(0, 512).body.dump();
        CHECK(diagnostic.find("SECRET-current") == std::string::npos); CHECK(diagnostic.find("private transport error") == std::string::npos);
        CHECK(!service.Status()["source"].contains("callback_token"));
        CHECK(Event(service)["delivery"]["attempts"] == replies.size()); CHECK(service.Status()["outbox_size"] == 0);
    }
    auto source = std::make_shared<FakeSource>(); auto transport = std::make_shared<FakeTransport>(); transport->throw_delivery = true;
    Service service(source, transport, "throws", Small()); Enable(service, "self", true);
    CHECK(service.Configure({{"max_attempts", 1}}).status == 200);
    CHECK(service.Publish(Message(), 1, service.Context().epoch)); WaitState(service, "retry_exhausted");
    CHECK(transport->Count() == 1); CHECK(service.Status()["counters"]["network_failures"] == 1);
    CHECK(service.Status().dump().find("SECRET-current") == std::string::npos);
}
void QueueAndDestinationPinning() {
    auto source = std::make_shared<FakeSource>(); auto transport = std::make_shared<FakeTransport>(); transport->hold = true;
    auto options = Small(); options.max_outbox = 2;
    Service service(source, transport, "queue", options); Enable(service, "self", true);
    const auto epoch = service.Context().epoch;
    CHECK(service.Publish(Message(1), 1, epoch)); Until([&] { return transport->Count() == 1; });
    CHECK(service.Publish(Message(2), 2, epoch));
    CHECK(service.Publish(Message(3), 3, epoch)); // Polling survives callback overflow.
    CHECK(Event(service, 2)["delivery"]["state"] == "queue_overflow");
    CHECK(service.Status()["outbox_size"] == 2); CHECK(service.Status()["counters"]["outbox_overflow"] == 1);
    CHECK(service.Events(0, 512).body["events"].size() == 3);
    const auto config = service.Configure({{"callback_url", "http://localhost:8182/new"}, {"callback_token", "SECRET-next"}});
    CHECK(config.status == 200); CHECK(config.body.dump().find("SECRET-next") == std::string::npos);
    CHECK(service.Context().epoch == epoch);
    transport->Release(); WaitState(service, "transport_acknowledged", 1);
    CHECK(transport->At(0).url == "http://127.0.0.1:8181/old"); CHECK(transport->At(1).url == transport->At(0).url);
    CHECK(transport->At(1).token == "SECRET-current");
    CHECK(service.Publish(Message(4), 4, epoch)); WaitState(service, "transport_acknowledged", 3);
    CHECK(transport->At(2).url == "http://localhost:8182/new"); CHECK(transport->At(2).token == "SECRET-next");
    CHECK(service.Configure({{"callback_url", ""}}).status == 200);
    CHECK(service.Publish(Message(5), 5, epoch)); CHECK(Event(service, 4)["delivery"]["state"] == "not_configured");
    CHECK(transport->Count() == 3);
}
void AccountInFlightAndStop() {
    auto source = std::make_shared<FakeSource>(); auto transport = std::make_shared<FakeTransport>();
    transport->hold = true; transport->replies = {503, 204};
    auto options = Small(); options.retry_initial = std::chrono::milliseconds(100); options.retry_max = options.retry_initial;
    auto service = std::make_shared<Service>(source, transport, "account", options); Enable(*service, "self", true);
    const auto old = service->Context(); CHECK(service->Publish(Message(1), 1, old.epoch));
    Until([&] { return transport->Count() == 1; }); CHECK(service->Publish(Message(2), 2, old.epoch));
    CHECK(service->Configure({{"self_id", "second"}, {"callback_url", "http://localhost/new"}, {"callback_token", "second-secret"}}).status == 200);
    const auto current = service->Context(); CHECK(current.epoch == old.epoch + 1);
    CHECK(service->Events(0, 512).body["events"].empty()); CHECK(service->Status()["outbox_size"] == 0);
    CHECK(!service->Publish(Message(3), 3, old.epoch));
    CHECK(service->Publish(Message(1, "peer", "second"), 1, current.epoch));
    transport->Release(); WaitState(*service, "transport_acknowledged");
    CHECK(transport->Count() == 2); CHECK(transport->At(1).url == "http://localhost/new");
    CHECK(transport->At(0).token == "SECRET-current"); CHECK(transport->At(1).token == "second-secret");
    CHECK(service->Status()["counters"]["account_discarded"] == 2);
    CHECK(service->Status()["counters"]["old_epoch_in_flight_completed"] == 1);
    service->Stop(); service->Stop(); CHECK(!source->enabled); CHECK(service->Status()["stopped"] == true);
    CHECK(!service->Publish(Message(), 2, current.epoch)); CHECK(service->Configure({{"enabled", true}}).status == 503);
    CHECK(service->Events(0, 512).body["events"].size() == 1);

    // Stop wakes a long retry wait rather than sleeping until its next due time.
    auto retry_transport = std::make_shared<FakeTransport>(); retry_transport->replies = {503};
    options.retry_initial = std::chrono::milliseconds(60000); options.retry_max = options.retry_initial;
    Service retry(std::make_shared<FakeSource>(), retry_transport, "stop-retry", options); Enable(retry, "self", true);
    CHECK(retry.Publish(Message(), 1, retry.Context().epoch)); WaitState(retry, "retry_wait");
    const auto start = std::chrono::steady_clock::now(); retry.Stop();
    CHECK(std::chrono::steady_clock::now() - start < std::chrono::seconds(1));
    CHECK(retry_transport->Count() == 1); CHECK(Event(retry)["delivery"]["state"] == "stopped");
    CHECK(retry.Status()["outbox_size"] == 0);
}
void StopInFlight() {
    auto source = std::make_shared<FakeSource>(); auto transport = std::make_shared<FakeTransport>(); transport->hold = true;
    Service service(source, transport, "stop-flight", Small()); Enable(service, "self", true);
    CHECK(service.Publish(Message(), 1, service.Context().epoch)); Until([&] { return transport->Count() == 1; });
    CHECK(service.Publish(Message(), 2, service.Context().epoch));
    std::thread stop([&] { service.Stop(); });
    Until([&] { return !source->enabled; }); transport->Release(); stop.join();
    CHECK(Event(service)["delivery"]["state"] == "transport_acknowledged");
    CHECK(Event(service, 1)["delivery"]["state"] == "stopped");
    CHECK(transport->Count() == 1); CHECK(service.Status()["outbox_size"] == 0);
}
void Routes() {
    auto service = std::make_shared<Service>(std::make_shared<FakeSource>(), std::make_shared<FakeTransport>(), "http", Small());
    MemoryServer server; RegisterRoutes(server, service);
    CHECK(server.Call("GET", "/wxcx/messages/status").body["enabled"] == false);
    CHECK(server.Call("GET", "/wxcx/messages/config").status == 200);
    CHECK(server.Call("POST", "/wxcx/messages/config", R"({"enabled":true,"self_id":"self","callback_token":"SECRET-current"})").status == 200);
    CHECK(server.Call("GET", "/wxcx/messages/config").body.dump().find("SECRET-current") == std::string::npos);
    CHECK(service->Publish(Message(), 1, service->Context().epoch));
    CHECK(server.Call("GET", "/wxcx/messages/events?after=0&limit=1").body["events"].size() == 1);
    CHECK(server.Call("GET", "/wxcx/messages/events").status == 200);
    for (const auto& suffix : {"after=-1", "after=+1", "after=1.0", "after=", "after=18446744073709551616", "after=2", "after=0&after=1",
        "limit=0", "limit=513", "limit=-1", "limit=x", "limit=1&limit=2", "limit=18446744073709551615", "unknown=1", "after=%00"})
        CHECK(server.Call("GET", std::string("/wxcx/messages/events?") + suffix).status == 400);
    for (const auto& body : {"", "{", "[]", "null", R"({"enabled":true,"enabled":false})", R"({"max_attempts":1e100})"})
        CHECK(server.Call("POST", "/wxcx/messages/config", body).status == 400);
    CHECK(server.Call("POST", "/wxcx/messages/config", std::string(16385, ' ')).status == 413);
    CHECK(server.Call("POST", "/wxcx/messages/events", "{}").status == 404);
    CHECK(server.Call("POST", "/wxcx/messages/stop", "garbage").status == 400);
    CHECK(server.Call("POST", "/wxcx/messages/stop", "{}").body["stopped"] == true);
    CHECK(server.Call("POST", "/wxcx/messages/stop").status == 200);
    CHECK(server.Call("POST", "/wxcx/messages/config", R"({"enabled":true})").status == 503);
    CHECK(server.Call("GET", "/wxcx/messages/events?after=1").status == 200);
}
void OptionBounds() {
    for (int mode = 0; mode < 9; ++mode) {
        auto options = Small(); auto source = std::make_shared<FakeSource>();
        if (mode == 0) options.max_events = 0;
        if (mode == 1) options.max_events = 513;
        if (mode == 2) options.max_outbox = 0;
        if (mode == 3) options.max_outbox = 129;
        if (mode == 4) options.max_dedup = 0;
        if (mode == 5) options.max_dedup = 4097;
        if (mode == 6) options.retry_initial = std::chrono::milliseconds(0);
        if (mode == 7) options.retry_max = std::chrono::milliseconds(0);
        if (mode == 8) options.retry_max = std::chrono::milliseconds(60001);
        bool threw = false;
        try { Service invalid(source, nullptr, "bounds", options); } catch (const std::invalid_argument&) { threw = true; }
        CHECK(threw);
    }
}
void StructuredPayloadDelivery() {
    auto source = std::make_shared<FakeSource>(); auto transport = std::make_shared<FakeTransport>();
    Service service(source, transport, "structured", Small());
    Enable(service, "self", true); auto input = Message(9007199254740993ULL, "r@chatroom"); input.type = 49;
    input.content = "peer:\n<msg><appmsg><type>57</type><title>new reply</title><refermsg><type>1</type>"
        "<svrid>18446744073709551615</svrid><content>quoted body</content></refermsg></appmsg></msg>";
    CHECK(service.Publish(input, 1, service.Context().epoch)); WaitState(service, "transport_acknowledged");
    auto event = Event(service); CHECK(event["message_kind"] == "quote");
    CHECK(event["quote"]["reply_text"] == "new reply");
    CHECK(event["quote"]["msgsvrid"] == "18446744073709551615");
    auto sent = transport->At(0).payload;
    CHECK(sent["quote"] == event["quote"]); CHECK(sent["raw_content"] == input.content);
    MemoryServer server; auto shared = std::make_shared<Service>(std::make_shared<FakeSource>(), nullptr, "poll");
    Enable(*shared, "self", false); RegisterRoutes(server, shared);
    input.server_id++; input.content = "peer:\n<appmsg><type>5</type><title>card title</title><url>https://example.test/</url></appmsg>";
    CHECK(shared->Publish(input, 2, shared->Context().epoch));
    auto result = server.Call("GET", "/wxcx/messages/events?after=0&limit=1");
    CHECK(result.status == 200); CHECK(result.body["events"][0]["card"]["title"] == "card title");
    CHECK(result.body["events"][0]["message_kind"] == "link_card");
    input.server_id++;input.content="peer:\n<msg><appmsg><type>74</type><title>sample.log</title><appattach><status>0</status><totallen>97</totallen></appattach></appmsg></msg>";
    CHECK(shared->Publish(input,3,shared->Context().epoch));
    input.server_id++;input.content="peer:\n<msg><appmsg><type>6</type><title>sample.log</title><appattach><overwrite_newmsgid>9007199254740995</overwrite_newmsgid></appattach></appmsg></msg>";
    CHECK(shared->Publish(input,4,shared->Context().epoch));
    auto pair=server.Call("GET","/wxcx/messages/events?after=1&limit=2");
    CHECK(pair.status==200 && pair.body["events"].size()==2);
    CHECK(pair.body["events"][0]["event_type"]=="file_transfer");
    CHECK(pair.body["events"][1]["event_type"]=="message");
    CHECK(pair.body["events"][1]["file_transfer"]["replaces_msgsvrid"]=="9007199254740995");
}
} // namespace
int main() {
    try {
        DefaultsAndValidation(); DedupAndCursors(); DeliveryOutcomes(); QueueAndDestinationPinning();
        AccountInFlightAndStop(); StopInFlight(); Routes(); OptionBounds(); StructuredPayloadDelivery();
        std::cout << "message service: " << checks << " checks passed (offline, no sockets)\n"; return 0;
    } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
