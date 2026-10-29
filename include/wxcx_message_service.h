#pragma once
#include "wxcx_message_model.h"
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

namespace httplib { class Server; }
namespace wxcx::messages {
struct Reply { int status; Json body; };
struct ContextSnapshot { std::string self_id; uint64_t epoch; };
class Source {
public:
    virtual ~Source() = default;
    virtual Json Status() = 0;
    // Performs native/version readiness checks. Must return within bounded time.
    virtual bool SetEnabled(bool, std::string& error) = 0;
    virtual void SetEpoch(uint64_t) {}
};
struct DeliveryResult { int status = 0; std::string error; };
class Transport {
public:
    virtual ~Transport() = default;
    // Worker only. Implementations MUST impose bounded connect/read/write times,
    // disable redirects, and return status=0 for network failure. A 2xx response
    // acknowledges HTTP receipt only. Do not log the token or payload.
    virtual DeliveryResult Deliver(const std::string& url, const std::string& token,
        const std::string& event_id, const Json& payload) = 0;
};
struct Options {
    size_t max_events = 512, max_outbox = 128, max_dedup = 1024;
    std::chrono::milliseconds retry_initial{250}, retry_max{30000};
};
class Service {
public:
    Service(std::shared_ptr<Source>, std::shared_ptr<Transport>,
        std::string processStreamId, Options = {});
    ~Service();
    Service(const Service&) = delete;
    Service& operator=(const Service&) = delete;
    // Call from the native capture-drain worker, NEVER from the native hook.
    // Owns/copies input, normalizes synchronously; false means no event retained.
    bool Publish(Input, uint64_t captureSeq, uint64_t epoch);
    Json Status() const;
    Reply Configure(const Json&);
    Reply Events(uint64_t after, size_t limit) const;
    ContextSnapshot Context() const;
    // Cooperative join may wait for one bounded Deliver. Main must retain/pin
    // the singleton and call Stop outside DllMain/loader lock; never detach it.
    void Stop();
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
void RegisterRoutes(httplib::Server&, std::shared_ptr<Service>);
} // namespace wxcx::messages
