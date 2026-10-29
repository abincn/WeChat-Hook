// Native boundary for the AI bridge. The hook only validates/copies bounded
// POD records; normalization, HTTP, retries and sends run on separate workers.
#include "httplib.h"
#include "wxcx_ai.h"
#include "wxcx.h"
#include "wxcx_addmsg.h"
#include "wxcx_message_service.h"
#include "wxcx_text_tasks.h"
#include "wxcx_probe_ring.h"
#include "wxcx_identity.h"
#include "wxcx_media_diagnostics.h"
#include "wxcx_media_tasks.h"
#include "wxcx_media_native.h"
#include "global.h"
#include <MinHook.h>
#include <windows.h>
#include <atomic>
#include <cstring>
#include <memory>
#include <mutex>
#include <algorithm>
#include <stdexcept>

namespace wxcx::ai {
namespace {
using Json = nlohmann::json;
constexpr uintptr_t kReceiveRva = 0x16D5180;
constexpr unsigned char kEntry[] = {0x55,0x41,0x57,0x41,0x56,0x41,0x55,0x41,0x54,0x56,0x57,0x53,0x48,0x81,0xEC,0xD8};
using SyncFn = char(__fastcall*)(void*, uintptr_t*, unsigned char, char);
SyncFn g_original = nullptr;
std::atomic<bool> g_enabled{false};
std::atomic<uint64_t> g_epoch{1}, g_calls{0}, g_invalid{0}, g_batchSkipped{0}, g_publishFailed{0};
probe::RecordRing<messages::RawMessage, 64> g_raw;

bool ReadMemory(uintptr_t address, void* output, size_t size, void*) {
    __try { std::memcpy(output, reinterpret_cast<const void*>(address), size); return true; }
    __except(EXCEPTION_EXECUTE_HANDLER) { return false; }
}
bool Verified() {
    try { const auto identity = RuntimeIdentity(); return identity.at("weixin").value("verified", false); }
    catch (...) { return false; }
}
bool Pin() {
    HMODULE module = nullptr;
    return GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
        reinterpret_cast<LPCWSTR>(&Pin), &module) != FALSE;
}
void Capture(uintptr_t* vector, uint64_t epoch) {
    uintptr_t bounds[2]{};
    if (!ReadMemory(reinterpret_cast<uintptr_t>(vector), bounds, sizeof(bounds), nullptr) ||
        !bounds[0] || bounds[1] < bounds[0] || (bounds[1] - bounds[0]) % 0x78 ||
        (bounds[1] - bounds[0]) / 0x78 > 1024) { ++g_invalid; return; }
    const size_t total = (bounds[1] - bounds[0]) / 0x78;
    const size_t count = (std::min)(total, size_t(64));
    if (total > count) g_batchSkipped.fetch_add(total - count);
    for (size_t i = 0; i < count; ++i) {
        messages::RawMessage record{};
        record.epoch = epoch;
        record.received_tick = GetTickCount64();
        if (messages::DecodeAddMsg(bounds[0] + i * 0x78, reinterpret_cast<uintptr_t>(g_hWeixinDll), ReadMemory, nullptr, record))
            g_raw.TryPush(record);
        else ++g_invalid;
    }
}
char __fastcall HookSync(void* context, uintptr_t* vector, unsigned char a3, char a4) {
    ++g_calls;
    const auto epoch = g_epoch.load(std::memory_order_acquire);
    if (g_enabled.load(std::memory_order_acquire)) Capture(vector, epoch);
    return g_original(context, vector, a3, a4);
}
// Preserve only complete UTF-8 code points when a fixed native buffer ends
// inside a character. Invalid bytes also make the corresponding field partial.
std::string Text(const char* data, size_t size, bool& complete) {
    size_t i = 0;
    while (i < size) {
        const size_t start = i;
        const unsigned char first = static_cast<unsigned char>(data[i++]);
        uint32_t value = first, minimum = 0; unsigned extra = 0;
        if (first >= 0xC2 && first <= 0xDF) { value &= 31; extra = 1; minimum = 0x80; }
        else if (first >= 0xE0 && first <= 0xEF) { value &= 15; extra = 2; minimum = 0x800; }
        else if (first >= 0xF0 && first <= 0xF4) { value &= 7; extra = 3; minimum = 0x10000; }
        else if (first >= 0x80) { complete = false; return std::string(data, start); }
        if (extra > size - i) { complete = false; return std::string(data, start); }
        while (extra--) {
            const auto next = static_cast<unsigned char>(data[i++]);
            if ((next & 0xC0) != 0x80) { complete = false; return std::string(data, start); }
            value = (value << 6) | (next & 63);
        }
        if (value < minimum || value > 0x10FFFF || (value >= 0xD800 && value <= 0xDFFF)) {
            complete = false; return std::string(data, start);
        }
    }
    return std::string(data, size);
}
class NativeSource final : public messages::Source {
    std::mutex mutex_;
    bool installed_ = false, consumerStarted_ = false;
    std::weak_ptr<messages::Service> service_;
    static DWORD WINAPI Drain(LPVOID context) {
        auto& self = *static_cast<NativeSource*>(context);
        // Drain the whole ring into heap storage without skipping queued records.
        auto records = std::make_unique<messages::RawMessage[]>(64);
        for (;;) {
            const auto batch = g_raw.TryDrain(records.get(), 64);
            for (size_t i = 0; i < batch.count; ++i) {
                auto service = self.service_.lock();
                if (!service) continue;
                const auto& raw = records[i];
                messages::Input input;
                bool fromComplete = true, toComplete = true;
                input.from = Text(raw.from, raw.from_size, fromComplete);
                input.to = Text(raw.to, raw.to_size, toComplete);
                if (!fromComplete || !toComplete) { ++g_invalid; continue; }
                input.content_complete = raw.content_complete;
                input.msgsource_complete = raw.msgsource_complete;
                input.content = Text(raw.content, raw.content_size, input.content_complete);
                input.msgsource = Text(raw.msgsource, raw.source_size, input.msgsource_complete);
                input.msgsource_known = raw.msgsource_known;
                input.type = raw.type; input.server_id = raw.server_id; input.create_time = raw.create_time;
                try {
                    if (!service->Publish(std::move(input), raw.sequence, raw.epoch)) ++g_publishFailed;
                    else g_IsLogin = 1; // a validated sync record, not a data-directory heuristic
                } catch (...) { ++g_publishFailed; }
            }
            Sleep(batch.count ? 1 : 20);
        }
    }
public:
    void Bind(const std::shared_ptr<messages::Service>& service) { service_ = service; }
    void SetEpoch(uint64_t epoch) override { g_epoch.store(epoch, std::memory_order_release); }
    Json Status() override {
        std::lock_guard<std::mutex> lock(mutex_);
        return {{"kind", "validated_addmsg"}, {"rva", "0x16D5180"}, {"enabled", g_enabled.load()},
            {"hook_installed", installed_}, {"runtime_acceptance", "pending"}, {"calls", g_calls.load()},
            {"invalid_records", g_invalid.load()}, {"batch_skipped", g_batchSkipped.load()},
            {"raw_dropped", g_raw.Dropped()}, {"raw_skipped", g_raw.Skipped()}, {"publish_failed", g_publishFailed.load()},
            {"content_limit_bytes", 16384}, {"metadata_limit_bytes", 8192}, {"persistence", "process_memory_only"}};
    }
    bool SetEnabled(bool enable, std::string& error) override {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!enable) { g_enabled.store(false, std::memory_order_release); return true; }
        if (!Verified()) { error = "version_mismatch"; return false; }
        if (!Pin()) { error = "module_pin_failed"; return false; }
        if (!consumerStarted_) {
            HANDLE thread = CreateThread(nullptr, 0, &Drain, this, 0, nullptr);
            if (!thread) { error = "capture_worker_start_failed"; return false; }
            CloseHandle(thread); consumerStarted_ = true;
        }
        if (!installed_) {
            auto* target = reinterpret_cast<unsigned char*>(reinterpret_cast<uintptr_t>(g_hWeixinDll) + kReceiveRva);
            unsigned char bytes[sizeof(kEntry)]{};
            if (!ReadMemory(reinterpret_cast<uintptr_t>(target), bytes, sizeof(bytes), nullptr) ||
                std::memcmp(bytes, kEntry, sizeof(bytes)) != 0) { error = "receive_prologue_mismatch"; return false; }
            const auto init = MH_Initialize();
            if (init != MH_OK && init != MH_ERROR_ALREADY_INITIALIZED) { error = "hook_engine_unavailable"; return false; }
            if (MH_CreateHook(target, reinterpret_cast<void*>(&HookSync), reinterpret_cast<void**>(&g_original)) != MH_OK || !g_original) {
                error = "receive_hook_create_failed"; return false;
            }
            if (MH_EnableHook(target) != MH_OK) {
                MH_RemoveHook(target); g_original = nullptr; error = "receive_hook_enable_failed"; return false;
            }
            installed_ = true;
        }
        g_enabled.store(true, std::memory_order_release); return true;
    }
};
class HttpTransport final : public messages::Transport {
public:
    messages::DeliveryResult Deliver(const std::string& url, const std::string& token,
        const std::string& eventId, const Json& payload) override {
        try {
            const auto end = url.find_first_of("/?#", 7);
            const auto base = url.substr(0, end);
            std::string path = end == std::string::npos ? "/" : url.substr(end);
            if (!path.empty() && path.front() == '?') path.insert(path.begin(), '/');
            httplib::Client client(base);
            client.set_connection_timeout(0, 500000); client.set_read_timeout(2, 0); client.set_write_timeout(2, 0);
            client.set_follow_location(false);
            httplib::Headers headers{{"X-Wxcx-Event-Id", eventId}};
            if (!token.empty()) headers.emplace("X-Wxcx-Token", token);
            httplib::Request request;
            request.method = "POST"; request.path = path;
            request.headers = std::move(headers);
            request.headers.emplace("Content-Type", "application/json");
            request.body = payload.dump();
            const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
            size_t responseBytes = 0;
            request.response_handler = [deadline](const httplib::Response&) {
                return std::chrono::steady_clock::now() < deadline;
            };
            request.content_receiver = [&responseBytes, deadline](const char*, size_t size, uint64_t, uint64_t) {
                if (size > 65536 - responseBytes || std::chrono::steady_clock::now() >= deadline) return false;
                responseBytes += size; return true;
            };
            const auto response = client.send(request);
            return response ? messages::DeliveryResult{response->status, {}} : messages::DeliveryResult{0, "transport_failed"};
        } catch (...) { return {0, "transport_exception"}; }
    }
};
bool SubmitText(const text::Request* request, bool& fault) {
    __try { return SendTextEx(request->toid, request->msg, request->atlist); }
    __except(EXCEPTION_EXECUTE_HANDLER) { fault = true; return false; }
}
class NativeText final : public text::Backend {
public:
    bool LoginReady() override { return g_IsLogin == 1; }
    bool VersionReady() override { return Verified(); }
    text::Submission Submit(const text::Request& request) override {
        bool fault = false; const bool submitted = SubmitText(&request, fault);
        if (fault) return {text::SubmissionState::Unknown, {"native_exception", "Submission outcome is unknown; do not retry automatically."}};
        if (!submitted) return {text::SubmissionState::Rejected, {"native_prepare_failed", "Could not prepare native text submission."}};
        return {text::SubmissionState::Submitted, {}};
    }
};
}
void RegisterRoutes(httplib::Server& server) {
    // The existing HTTP server outlives route registration and has a detached
    // listener. Retain/pin these process singletons; never join in DllMain.
    static auto* source = new std::shared_ptr<NativeSource>(std::make_shared<NativeSource>());
    static auto* received = new std::shared_ptr<messages::Service>([] {
        if (!Pin()) throw std::runtime_error("Cannot pin AI bridge module");
        const auto identity = RuntimeIdentity();
        const std::string stream = std::to_string(GetCurrentProcessId()) + "-" + identity.value("process_start_filetime", std::string("unknown"));
        return std::make_shared<messages::Service>(*source, std::make_shared<HttpTransport>(), stream);
    }());
    static const bool bound = ((*source)->Bind(*received), true);
    (void)bound;
    static auto* textTasks = new std::shared_ptr<text::Service>(std::make_shared<text::Service>(std::make_shared<NativeText>()));
    static auto* mediaTasks = new std::shared_ptr<media::Service>(std::make_shared<media::Service>(media::CreateNativeBackend(),
        std::to_string(GetCurrentProcessId())+"-"+RuntimeIdentity().value("process_start_filetime",std::string("unknown"))));
    messages::RegisterRoutes(server, *received);
    text::RegisterRoutes(server, *textTasks);
    media::RegisterRoutes(server, *mediaTasks);
    native::RegisterSchedulerProbeRoutes(server);
    native::RegisterCoroutineProbeRoutes(server);
    server.Get("/wxcx/ai/status", [](const httplib::Request&, httplib::Response& response) {
        Json out{{"build_id", "AI-HOOK-20261029-07"}, {"messages", (*received)->Status()}, {"text", (*textTasks)->Status()},
            {"runtime_identity", RuntimeIdentity()}, {"live_acceptance", "pending"}, {"automatic_ai_replies", false}};
        out["receive_payloads"] = {{"revision", 3}, {"live_acceptance", "pending"}, {"file_transfer_notice_subtype",74},
            {"appmsg_subtypes", {5,6,33,36,57}}, {"contact_card_type", 42},
            {"quote_send_supported", false}, {"card_send_supported", false}};
        out["media"]={{"download_available",false},{"scheduler_diagnostic_id",native::kSchedulerDiagnosticId},
            {"task_api_implemented",true},{"native_pipeline_live_verified",false},
            {"image_quality",{{"default","full"},{"supported",{"full","original"}},{"thumbnail_fallback",false}}},
            {"task_status_url","/wxcx/media/status"},{"artifact_validation","actual_file_sha256_and_image_decode_or_video_sample"},
            {"coroutine_diagnostic_id",native::kCoroutineDiagnosticId},
            {"native_scheduler_verified",false},{"image_decryption_live_verified",false}};
        response.set_content(out.dump(), "application/json");
    });
}
}
