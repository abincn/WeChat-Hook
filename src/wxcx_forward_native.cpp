#include "httplib.h"
#include "wxcx_forward.h"
#include "wxcx_identity.h"
#include "wxcx_msgloc.h"
#include <windows.h>
#include <stdexcept>

namespace wxcx { namespace forward { namespace {
// Deliberately no function-pointer casts or historical heap pointers here.
// Bindings may be added only with source acquisition, scheduler, lifetime and
// media completion evidence for this exact binary and each message kind.
class NativeBackend final : public Backend {
public:
    Resolution Resolve(const Request& request, const Context& context) override {
        const auto identity = RuntimeIdentity();
        if (!identity["weixin"].value("verified", false))
            return {{}, {"version_mismatch", "The module file and mapped headers do not match the verified 4.1.10.27 binary."}};
        if (context.Cancelled() || context.Expired()) return {{}, {"timeout", "Source lookup cancelled before submission."}};
        const auto found = msgloc::LocateUnique(request.msg_svr_id, request.source_talker,
            [&context] { return context.Cancelled() || context.Expired(); });
        auto evidence = std::make_shared<Message>();
        evidence->evidence = {{"lookup_status", found.status}, {"complete", found.complete}, {"matches", Json::array()}};
        for (const auto& match : found.matches) evidence->evidence["matches"].push_back({{"db", match.db}, {"table", match.table},
            {"local_id_decimal", std::to_string(match.local_id)}, {"msg_svr_id_decimal", std::to_string(match.msg_svr_id)},
            {"talker", match.talker}, {"raw_type", match.raw_type}});
        if (found.status != "found") {
            const char* code = found.status == "ambiguous" ? "source_ambiguous" : found.status == "not_found" ? "source_not_found" :
                found.status == "database_unavailable" ? "database_unavailable" : "source_lookup_incomplete";
            return {evidence, {code, found.detail}};
        }
        return {evidence, {"native_abi_unverified", "Database evidence is unique, but native source loading, scheduler ownership and per-type transfer completion are not verified. No native forwarding call was made."}};
    }
    Error PrepareMedia(const Request&, const std::shared_ptr<Message>&, const Context&) override {
        return {"resource_unavailable", "Native media acquisition has not been verified for this binary."};
    }
    Submission Submit(const Request&, const std::shared_ptr<Message>&, const Context&) override {
        return {SubmissionState::Rejected, {"native_abi_unverified", "Native Forward bindings are not enabled."}};
    }
    Json Capabilities() override {
        const auto identity = RuntimeIdentity();
        Json types = Json::object();
        for (const char* kind : {"text", "link", "image", "file"}) types[kind] = {
            {"available", false}, {"native_abi_verified", false}, {"runtime_acceptance", "not_performed"},
            {"reason", "native_source_loader_scheduler_and_completion_unverified"}};
        return {{"binary_identity", identity["weixin"]}, {"runtime_identity", identity}, {"native_adapter_state", "unverified"},
            {"native_abi_verified", false}, {"types", types}, {"native_media_download", false}};
    }
};
} // namespace
void RegisterRoutes(httplib::Server& svr) {
    // Existing HTTP server uses a detached process-lifetime thread. Keep one
    // bounded registry for that lifetime, rather than joining a worker from
    // static destruction under the Windows loader lock. Pin this module because
    // its routes/worker (and future native callbacks) cannot survive FreeLibrary.
    // /wxcx/forward/stop cooperatively stops work; replacement uses process restart.
    static const auto* lifetime = [] {
        HMODULE module = nullptr;
        if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
                reinterpret_cast<LPCWSTR>(&RegisterRoutes), &module))
            throw std::runtime_error("Unable to retain forward module lifetime");
        return new std::shared_ptr<Service>(std::make_shared<Service>(std::make_shared<NativeBackend>()));
    }();
    RegisterTaskRoutes(svr, *lifetime);
}
} }
