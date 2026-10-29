#include "wxcx_message_service.h"
#include "httplib.h"
#include <algorithm>
#include <condition_variable>
#include <deque>
#include <limits>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <unordered_set>

namespace wxcx::messages {
namespace {
using Clock = std::chrono::steady_clock;
Reply Fail(int status, const char* code, const char* message) {
    return {status, {{"error", code}, {"message", message}}};
}
bool Decimal(const std::string& text, uint64_t& out) {
    if (text.empty() || text.size() > 20) return false;
    out = 0;
    for (unsigned char c : text) {
        if (c < '0' || c > '9' || out > ((std::numeric_limits<uint64_t>::max)() - (c - '0')) / 10) return false;
        out = out * 10 + (c - '0');
    }
    return true;
}
bool Identifier(const std::string& s, size_t bound, bool empty = false) {
    if (s.empty()) return empty;
    if (s.size() > bound) return false;
    return std::all_of(s.begin(), s.end(), [](unsigned char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.' || c == '@';
    });
}
bool LocalUrl(const std::string& url) {
    if (url.empty()) return true;
    if (url.size() > 2048 || url.compare(0, 7, "http://") != 0) return false;
    for (unsigned char c : url) if (c <= 32 || c >= 127 || c == '\\' || c == '#') return false;
    const auto end = url.find_first_of("/?", 7);
    const auto authority = url.substr(7, end == std::string::npos ? end : end - 7);
    std::string host, port;
    if (authority.compare(0, 5, "[::1]") == 0) {
        host = "[::1]";
        if (authority.size() > 5) {
            if (authority[5] != ':') return false;
            port = authority.substr(6);
            if (port.empty()) return false;
        }
    } else {
        const auto colon = authority.find(':');
        host = authority.substr(0, colon);
        if (colon != std::string::npos) {
            port = authority.substr(colon + 1);
            if (port.empty()) return false;
        }
    }
    if (host != "localhost" && host != "127.0.0.1" && host != "[::1]") return false;
    uint64_t number = 0;
    return port.empty() || (Decimal(port, number) && number > 0 && number <= 65535);
}
bool Token(const std::string& value) {
    if (value.size() > 4096) return false;
    return std::all_of(value.begin(), value.end(), [](unsigned char c) { return c >= 33 && c <= 126; });
}
// Source status is diagnostic data. Never surface token-shaped fields or the
// configured secret through its diagnostics. Transport error text is never used.
void Scrub(Json& value, const std::string& secret) {
    if (value.is_object()) {
        for (auto it = value.begin(); it != value.end();) {
            auto key = it.key();
            std::transform(key.begin(), key.end(), key.begin(), [](unsigned char c) {
                return c >= 'A' && c <= 'Z' ? static_cast<char>(c + 'a' - 'A') : static_cast<char>(c);
            });
            if (key.find("token") != std::string::npos || key.find("authorization") != std::string::npos ||
                key.find("secret") != std::string::npos) it = value.erase(it);
            else { Scrub(it.value(), secret); ++it; }
        }
    } else if (value.is_array()) {
        for (auto& item : value) Scrub(item, secret);
    } else if (value.is_string() && !secret.empty()) {
        auto text = value.get<std::string>();
        size_t p = 0;
        while ((p = text.find(secret, p)) != std::string::npos) {
            text.replace(p, secret.size(), "[redacted]"); p += 10;
        }
        value = std::move(text);
    }
}
} // namespace

struct Service::Impl {
    struct Event { uint64_t sequence; Json view; };
    struct Delivery {
        std::shared_ptr<Event> event;
        Json payload;
        std::string url, token;
        uint64_t epoch;
        unsigned attempts = 0, max_attempts;
        Clock::time_point due = Clock::now();
        bool in_flight = false;
    };
    std::shared_ptr<Source> source;
    std::shared_ptr<Transport> transport;
    std::string stream, self, url, token;
    Options options;
    mutable std::mutex mutex, control;
    std::condition_variable changed;
    std::thread worker;
    bool enabled = false, stopping = false, source_disable_failed = false;
    uint64_t epoch = 1, sequence = 0, evicted_through = 0, reset_through = 0, last_capture = 0;
    unsigned max_attempts = 3;
    std::deque<std::shared_ptr<Event>> events;
    std::deque<std::shared_ptr<Delivery>> outbox;
    std::deque<std::string> dedup_order;
    std::unordered_set<std::string> dedup;
    uint64_t accepted = 0, duplicates = 0, stale = 0, disabled = 0, invalid = 0,
        evictions = 0, overflow = 0, attempts = 0, acknowledged = 0,
        permanent = 0, exhausted = 0, network_failures = 0, cancelled = 0,
        account_discarded = 0, old_completions = 0, capture_gaps = 0;

    Json View() const { // mutex held
        size_t in_flight = 0;
        for (const auto& d : outbox) if (d->in_flight) ++in_flight;
        return {{"enabled", enabled}, {"stopped", stopping}, {"self_id", self}, {"epoch", epoch},
            {"process_stream_id", stream}, {"latest_sequence", sequence}, {"events_retained", events.size()},
            {"outbox_size", outbox.size()}, {"in_flight", in_flight}, {"dedup_size", dedup.size()},
            {"max_events", options.max_events}, {"max_outbox", options.max_outbox}, {"max_dedup", options.max_dedup},
            {"max_attempts", max_attempts}, {"callback_configured", !url.empty()},
            {"callback_transport_available", static_cast<bool>(transport)}, {"callback_token_configured", !token.empty()},
            {"callback_policy", "loopback_http_only"}, {"callback_acknowledgement", "HTTP 2xx receipt only; no AI or message-send confirmation"},
            {"callback_reconfiguration", "queued deliveries keep their original destination and token"},
            {"in_flight_limitation", "an in-flight HTTP delivery cannot be retracted by account change or stop"},
            {"source_disable_failed", source_disable_failed},
            {"counters", {{"accepted", accepted}, {"deduplicated", duplicates}, {"stale_epoch", stale},
                {"rejected_disabled", disabled}, {"invalid_input", invalid}, {"cache_evicted", evictions},
                {"outbox_overflow", overflow}, {"delivery_attempts", attempts}, {"transport_acknowledged", acknowledged},
                {"permanent_failures", permanent}, {"retry_exhausted", exhausted}, {"network_failures", network_failures},
                {"cancelled", cancelled}, {"account_discarded", account_discarded},
                {"old_epoch_in_flight_completed", old_completions}, {"capture_gaps", capture_gaps}}}};
    }
    void State(const std::shared_ptr<Delivery>& d, const char* state, int status = 0) {
        d->event->view["delivery"] = {{"state", state}, {"attempts", d->attempts},
            {"http_status", status > 0 ? Json(status) : Json(nullptr)}};
    }
    void Run() {
        std::unique_lock<std::mutex> lock(mutex);
        while (!stopping) {
            if (outbox.empty()) { changed.wait(lock, [&] { return stopping || !outbox.empty(); }); continue; }
            const auto first = std::min_element(outbox.begin(), outbox.end(), [](const auto& a, const auto& b) { return a->due < b->due; });
            auto d = *first;
            if (Clock::now() < d->due) { changed.wait_until(lock, d->due); continue; }
            d->in_flight = true; ++d->attempts; ++attempts; State(d, "in_flight");
            lock.unlock();
            DeliveryResult result;
            try { result = transport->Deliver(d->url, d->token, d->payload.at("event_id").get<std::string>(), d->payload); }
            catch (...) { result.status = 0; }
            lock.lock();
            d->in_flight = false;
            // Epoch changes discard the queue. An old in-flight call may finish,
            // but cannot update the new account or enqueue another attempt.
            if (d->epoch != epoch) { ++old_completions; continue; }
            const bool ok = result.status >= 200 && result.status < 300;
            const bool retryable = result.status <= 0 || result.status == 408 || result.status == 429 ||
                (result.status >= 500 && result.status < 600);
            if (result.status <= 0) ++network_failures;
            if (ok) { ++acknowledged; State(d, "transport_acknowledged", result.status); }
            else if (stopping) { ++cancelled; State(d, "stopped", result.status); }
            else if (!retryable) { ++permanent; State(d, "permanent_error", result.status); }
            else if (d->attempts >= d->max_attempts) { ++exhausted; State(d, "retry_exhausted", result.status); }
            else {
                auto delay = options.retry_initial;
                for (unsigned i = 1; i < d->attempts && delay < options.retry_max; ++i)
                    delay = (std::min)(delay * 2, options.retry_max);
                d->due = Clock::now() + delay; State(d, "retry_wait", result.status); continue;
            }
            const auto found = std::find(outbox.begin(), outbox.end(), d);
            if (found != outbox.end()) outbox.erase(found);
        }
    }
};

Service::Service(std::shared_ptr<Source> source, std::shared_ptr<Transport> transport,
    std::string processStreamId, Options options) : impl_(std::make_unique<Impl>()) {
    if (!source || !Identifier(processStreamId, 128) || options.max_events < 1 || options.max_events > 512 ||
        options.max_outbox < 1 || options.max_outbox > 128 || options.max_dedup < 1 || options.max_dedup > 4096 ||
        options.retry_initial.count() < 1 || options.retry_max < options.retry_initial || options.retry_max.count() > 60000)
        throw std::invalid_argument("Invalid bounded message service options, source, or stream id");
    impl_->source = std::move(source); impl_->transport = std::move(transport);
    impl_->stream = std::move(processStreamId); impl_->options = options;
    // Explicitly fence a reused source. Construction never enables observation.
    std::string error;
    if (!impl_->source->SetEnabled(false, error)) throw std::runtime_error("Unable to disable receive source");
    impl_->source->SetEpoch(impl_->epoch);
    impl_->worker = std::thread([this] { impl_->Run(); });
}
Service::~Service() { Stop(); }
ContextSnapshot Service::Context() const {
    std::lock_guard<std::mutex> lock(impl_->mutex); return {impl_->self, impl_->epoch};
}
Json Service::Status() const {
    std::lock_guard<std::mutex> control(impl_->control);
    Json view; std::string secret;
    { std::lock_guard<std::mutex> lock(impl_->mutex); view = impl_->View(); secret = impl_->token; }
    try { view["source"] = impl_->source->Status(); Scrub(view["source"], secret); }
    catch (...) { view["source"] = {{"error", "source_status_failed"}}; }
    return view;
}

Reply Service::Configure(const Json& config) {
    if (!config.is_object()) return Fail(400, "invalid_config", "JSON object required.");
    for (auto it = config.begin(); it != config.end(); ++it)
        if (it.key() != "enabled" && it.key() != "self_id" && it.key() != "callback_url" &&
            it.key() != "callback_token" && it.key() != "max_attempts")
            return Fail(400, "unknown_field", "Unknown configuration field.");
    std::lock_guard<std::mutex> control(impl_->control);
    std::string self, url, token;
    bool enabled; unsigned max_attempts; uint64_t epoch;
    {
        std::lock_guard<std::mutex> lock(impl_->mutex);
        if (impl_->stopping) return Fail(503, "service_stopped", "Service has stopped permanently.");
        self = impl_->self; url = impl_->url; token = impl_->token;
        enabled = impl_->enabled; max_attempts = impl_->max_attempts; epoch = impl_->epoch;
    }
    for (const auto key : {"self_id", "callback_url", "callback_token"}) {
        if (config.contains(key) && !config[key].is_string()) return Fail(400, "invalid_type", "Configuration strings must be strings.");
    }
    if (config.contains("self_id")) self = config["self_id"].get<std::string>();
    if (config.contains("callback_url")) url = config["callback_url"].get<std::string>();
    if (config.contains("callback_token")) token = config["callback_token"].get<std::string>();
    if (!Identifier(self, 1024, true)) return Fail(400, "invalid_self_id", "self_id must be empty or a bounded ASCII identity.");
    if (url.compare(0, 8, "https://") == 0) return Fail(400, "https_unsupported", "HTTPS callbacks are unsupported in this beta; use loopback HTTP.");
    if (!LocalUrl(url)) return Fail(400, "invalid_callback_url", "Only http://127.0.0.1, http://localhost or http://[::1] callbacks are supported.");
    if (!Token(token)) return Fail(400, "invalid_callback_token", "Token must be at most 4096 printable non-space ASCII bytes.");
    if (!url.empty() && !impl_->transport) return Fail(409, "callback_transport_unavailable", "No callback transport was installed.");
    if (config.contains("enabled")) {
        if (!config["enabled"].is_boolean()) return Fail(400, "invalid_enabled", "enabled must be a boolean.");
        enabled = config["enabled"].get<bool>();
    }
    if (config.contains("max_attempts")) {
        const auto& n = config["max_attempts"];
        if (!n.is_number_integer() || (n.is_number_integer() && !n.is_number_unsigned() && n.get<int64_t>() < 1) ||
            n.get<uint64_t>() < 1 || n.get<uint64_t>() > 10)
            return Fail(400, "invalid_max_attempts", "max_attempts must be an integer from 1 to 10.");
        max_attempts = n.get<unsigned>();
    }
    bool old_enabled, switch_account;
    {
        std::lock_guard<std::mutex> lock(impl_->mutex);
        old_enabled = impl_->enabled; switch_account = self != impl_->self;
        if (switch_account && epoch == (std::numeric_limits<uint64_t>::max)())
            return Fail(409, "epoch_exhausted", "Account epoch exhausted; start a new process stream.");
        // Source calls run outside the event mutex: a capture drainer may call
        // Context/Publish while native activation or quiescing is in progress.
        impl_->enabled = false;
    }
    bool source_ok = true;
    try {
        std::string error;
        if (switch_account) {
            source_ok = impl_->source->SetEnabled(false, error);
            if (source_ok) impl_->source->SetEpoch(epoch + 1);
        }
        if (source_ok) source_ok = impl_->source->SetEnabled(enabled, error);
    } catch (...) { source_ok = false; }
    if (!source_ok) {
        // Roll back config, but fail closed if restoring native state fails.
        bool restored = false;
        try {
            impl_->source->SetEpoch(epoch);
            std::string error; restored = impl_->source->SetEnabled(old_enabled, error);
        } catch (...) {}
        std::lock_guard<std::mutex> lock(impl_->mutex);
        impl_->enabled = restored && old_enabled;
        return Fail(409, "source_configuration_failed", "Source rejected configuration or failed its native/version gate; configuration was not committed.");
    }
    std::lock_guard<std::mutex> lock(impl_->mutex);
    if (switch_account) {
        ++impl_->epoch;
        impl_->reset_through = impl_->sequence;
        impl_->evicted_through = impl_->sequence;
        impl_->account_discarded += impl_->outbox.size();
        impl_->events.clear(); impl_->outbox.clear(); impl_->dedup.clear(); impl_->dedup_order.clear(); impl_->last_capture = 0;
    }
    impl_->self = std::move(self); impl_->url = std::move(url); impl_->token = std::move(token);
    impl_->enabled = enabled; impl_->max_attempts = max_attempts;
    impl_->changed.notify_all();
    return {200, impl_->View()};
}

bool Service::Publish(Input input, uint64_t captureSeq, uint64_t epoch) {
    {
        std::lock_guard<std::mutex> lock(impl_->mutex);
        if (epoch != impl_->epoch) { ++impl_->stale; return false; }
        if (!impl_->enabled || impl_->stopping) { ++impl_->disabled; return false; }
        // Configuration is the account authority; never let caller-supplied self
        // label a new account's event as an old account.
        input.self_wxid = impl_->self;
    }
    Json normalized;
    try { normalized = Normalize(input); }
    catch (...) { std::lock_guard<std::mutex> lock(impl_->mutex); ++impl_->invalid; return false; }
    std::lock_guard<std::mutex> lock(impl_->mutex);
    if (epoch != impl_->epoch) { ++impl_->stale; return false; }
    if (!impl_->enabled || impl_->stopping) { ++impl_->disabled; return false; }
    const bool capture_gap = impl_->last_capture && captureSeq > impl_->last_capture && captureSeq - impl_->last_capture > 1;
    if (capture_gap) ++impl_->capture_gaps;
    impl_->last_capture = (std::max)(impl_->last_capture, captureSeq);
    std::string key;
    if (input.server_id) {
        key = Json::array({impl_->self, input.from, input.to, normalized.at("conversation_id"), std::to_string(input.server_id)}).dump();
        if (impl_->dedup.count(key)) { ++impl_->duplicates; return false; }
    }
    if (impl_->sequence == (std::numeric_limits<uint64_t>::max)()) { ++impl_->invalid; return false; }
    const uint64_t seq = ++impl_->sequence;
    normalized["event_id"] = impl_->stream + ':' + std::to_string(epoch) + ':' + std::to_string(seq);
    normalized["epoch"] = epoch; normalized["sequence"] = seq; normalized["capture_seq"] = captureSeq;
    normalized["capture_gap"] = capture_gap;
    auto event = std::make_shared<Impl::Event>(Impl::Event{seq, normalized});
    event->view["delivery"] = {{"state", "not_configured"}, {"attempts", 0}, {"http_status", nullptr}};
    if (!impl_->url.empty()) {
        if (impl_->outbox.size() >= impl_->options.max_outbox) {
            ++impl_->overflow; event->view["delivery"]["state"] = "queue_overflow";
        } else {
            auto delivery = std::make_shared<Impl::Delivery>();
            delivery->event = event; delivery->payload = std::move(normalized);
            delivery->url = impl_->url; delivery->token = impl_->token; delivery->epoch = epoch;
            delivery->max_attempts = impl_->max_attempts;
            impl_->State(delivery, "queued"); impl_->outbox.push_back(std::move(delivery));
        }
    }
    if (!key.empty()) {
        if (impl_->dedup_order.size() == impl_->options.max_dedup) {
            impl_->dedup.erase(impl_->dedup_order.front()); impl_->dedup_order.pop_front();
        }
        impl_->dedup.insert(key); impl_->dedup_order.push_back(std::move(key));
    }
    if (impl_->events.size() == impl_->options.max_events) {
        impl_->evicted_through = impl_->events.front()->sequence; impl_->events.pop_front(); ++impl_->evictions;
    }
    impl_->events.push_back(std::move(event)); ++impl_->accepted; impl_->changed.notify_one(); return true;
}

Reply Service::Events(uint64_t after, size_t limit) const {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    if (limit < 1 || limit > 512) return Fail(400, "invalid_limit", "limit must be from 1 to 512.");
    if (after > impl_->sequence) return Fail(400, "invalid_after", "after is ahead of this process stream; reset to zero after a process restart.");
    Json result = Json::array(); uint64_t next = after;
    for (const auto& event : impl_->events) {
        if (event->sequence <= after) continue;
        result.push_back(event->view); next = event->sequence;
        if (result.size() == limit) break;
    }
    // An empty cache after account reset still advances the caller's cursor.
    if (result.empty()) next = (std::max)(after, impl_->evicted_through);
    return {200, {{"events", result}, {"after", after}, {"next_after", next}, {"latest_sequence", impl_->sequence},
        {"oldest_sequence", impl_->events.empty() ? Json(nullptr) : Json(impl_->events.front()->sequence)},
        {"has_more", next < impl_->sequence}, {"gap", after < impl_->evicted_through},
        {"cache_gap", after < impl_->evicted_through}, {"account_reset_gap", after < impl_->reset_through},
        {"evicted_through", impl_->evicted_through}, {"process_stream_id", impl_->stream}, {"epoch", impl_->epoch},
        {"stopped", impl_->stopping}}};
}

void Service::Stop() {
    std::lock_guard<std::mutex> control(impl_->control);
    {
        std::lock_guard<std::mutex> lock(impl_->mutex);
        if (impl_->stopping) return;
        impl_->stopping = true; impl_->enabled = false;
        for (const auto& d : impl_->outbox) if (!d->in_flight) { impl_->State(d, "stopped"); ++impl_->cancelled; }
        impl_->outbox.erase(std::remove_if(impl_->outbox.begin(), impl_->outbox.end(),
            [](const auto& d) { return !d->in_flight; }), impl_->outbox.end());
    }
    impl_->changed.notify_all();
    bool disabled = false;
    try { std::string error; disabled = impl_->source->SetEnabled(false, error); } catch (...) {}
    { std::lock_guard<std::mutex> lock(impl_->mutex); impl_->source_disable_failed = !disabled; }
    if (impl_->worker.joinable()) impl_->worker.join();
}

void RegisterRoutes(httplib::Server& server, std::shared_ptr<Service> service) {
    if (!service) throw std::invalid_argument("Null message service");
    auto send = [](httplib::Response& res, const Reply& reply) {
        res.status = reply.status; res.set_content(reply.body.dump(), "application/json");
    };
    server.Get("/wxcx/messages/status", [service](const httplib::Request&, httplib::Response& res) {
        res.set_content(service->Status().dump(), "application/json");
    });
    server.Get("/wxcx/messages/config", [service](const httplib::Request&, httplib::Response& res) {
        res.set_content(service->Status().dump(), "application/json");
    });
    server.Get("/wxcx/messages/events", [service, send](const httplib::Request& req, httplib::Response& res) {
        uint64_t after = 0, limit = 100;
        for (const auto& param : req.params) {
            if (param.first != "after" && param.first != "limit") {
                send(res, Fail(400, "invalid_query", "Only after and limit query arguments are supported.")); return;
            }
        }
        if (req.get_param_value_count("after") > 1 || req.get_param_value_count("limit") > 1 ||
            (req.has_param("after") && !Decimal(req.get_param_value("after"), after)) ||
            (req.has_param("limit") && !Decimal(req.get_param_value("limit"), limit)) || limit < 1 || limit > 512) {
            send(res, Fail(400, "invalid_cursor", "after must be an unsigned decimal uint64; limit must be a decimal from 1 to 512.")); return;
        }
        send(res, service->Events(after, static_cast<size_t>(limit)));
    });
    server.Post("/wxcx/messages/config", [service, send](const httplib::Request& req, httplib::Response& res) {
        if (req.body.size() > 16384) { send(res, Fail(413, "config_too_large", "Configuration exceeds 16384 bytes.")); return; }
        try {
            bool duplicate = false;
            std::unordered_set<std::string> keys;
            const auto parsed = Json::parse(req.body, [&](int, Json::parse_event_t event, Json& item) {
                if (event == Json::parse_event_t::key && !keys.insert(item.get<std::string>()).second) duplicate = true;
                return true;
            });
            if (duplicate) { send(res, Fail(400, "duplicate_field", "Duplicate configuration keys are not permitted.")); return; }
            send(res, service->Configure(parsed));
        } catch (const Json::exception&) { send(res, Fail(400, "invalid_json", "Malformed JSON or UTF-8.")); }
    });
    server.Post("/wxcx/messages/stop", [service, send](const httplib::Request& req, httplib::Response& res) {
        if (!req.body.empty() && req.body != "{}") { send(res, Fail(400, "invalid_stop", "Stop accepts an empty body or {}.")); return; }
        service->Stop(); send(res, {200, {{"stopped", true}, {"enabled", false}}});
    });
}
} // namespace wxcx::messages
