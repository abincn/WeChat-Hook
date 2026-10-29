#include "wxcx_identity.h"
#include "global.h"
#include <iostream>
HMODULE g_hModule = nullptr;
HMODULE g_hWeixinDll = nullptr;
int main(int argc, char**) {
    // Only fingerprint this test executable. Never LoadLibrary the target.
    g_hModule = GetModuleHandleW(nullptr);
    if (argc == 1) g_hWeixinDll = g_hModule;
    const auto identity = wxcx::RuntimeIdentity();
    if (identity.value("process_id", 0u) != GetCurrentProcessId() || identity.value("process_start_filetime", "").empty()) return 4;
    if (identity["weixin"].value("verified", true)) return 1;
    if (identity["probe"]["status"] != "hashed" || identity["probe"]["mapped_headers_match"] != true) return 2;
    if (argc > 1 && identity["weixin"]["status"] != "unavailable") return 3;
    std::cout << identity.dump() << '\n';
    return 0;
}
