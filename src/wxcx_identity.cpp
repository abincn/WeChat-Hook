#include "wxcx_identity.h"
#include "global.h"
#include <windows.h>
#include <bcrypt.h>
#include <vector>
#include <string>
#include <array>
#pragma comment(lib, "bcrypt.lib")
namespace wxcx { namespace {
constexpr const char* kExpected = "f487e4f56930456a25fb0d7b058c77e2dcd364e268d49bdfff4dc0e3be26ba36";
struct File { HANDLE value = INVALID_HANDLE_VALUE; ~File() { if (value != INVALID_HANDLE_VALUE) CloseHandle(value); } };
struct Crypto {
    BCRYPT_ALG_HANDLE algorithm = nullptr; BCRYPT_HASH_HANDLE hash = nullptr;
    std::vector<BYTE> object;
    ~Crypto() { if (hash) BCryptDestroyHash(hash); if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0); }
};
bool MappedHeader(HMODULE module, DWORD& imageSize, DWORD& timestamp) {
    __try {
        auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(module);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0 || dos->e_lfanew > 0x100000) return false;
        auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(reinterpret_cast<const BYTE*>(module) + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return false;
        imageSize = nt->OptionalHeader.SizeOfImage; timestamp = nt->FileHeader.TimeDateStamp; return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
nlohmann::json Fingerprint(HMODULE module) {
    using nlohmann::json;
    json out = {{"status", "unavailable"}, {"actual_sha256", nullptr}, {"hash_scope", "module_file_not_runtime_memory"}};
    if (!module) return out;
    std::vector<wchar_t> path(32768);
    const DWORD count = GetModuleFileNameW(module, path.data(), static_cast<DWORD>(path.size()));
    if (!count || count >= path.size()) return out;
    const int bytes = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, path.data(), count, nullptr, 0, nullptr, nullptr);
    if (bytes <= 0) return out;
    std::string utf8(bytes, '\0'); WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, path.data(), count, utf8.data(), bytes, nullptr, nullptr);
    out["path"] = utf8;
    File file; file.value = CreateFileW(path.data(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file.value == INVALID_HANDLE_VALUE) { out["status"] = "file_unavailable"; return out; }
    LARGE_INTEGER length{}; if (!GetFileSizeEx(file.value, &length)) return out;
    out["file_bytes"] = length.QuadPart;
    IMAGE_DOS_HEADER dos{}; IMAGE_NT_HEADERS64 nt{}; DWORD got = 0;
    if (!ReadFile(file.value, &dos, sizeof(dos), &got, nullptr) || got != sizeof(dos) || dos.e_magic != IMAGE_DOS_SIGNATURE ||
        dos.e_lfanew < 0 || dos.e_lfanew > 0x100000) return out;
    LARGE_INTEGER offset{}; offset.QuadPart = dos.e_lfanew;
    if (!SetFilePointerEx(file.value, offset, nullptr, FILE_BEGIN) || !ReadFile(file.value, &nt, sizeof(nt), &got, nullptr) ||
        got != sizeof(nt) || nt.Signature != IMAGE_NT_SIGNATURE || nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return out;
    DWORD imageSize = 0, timestamp = 0;
    const bool headerMatches = MappedHeader(module, imageSize, timestamp) && imageSize == nt.OptionalHeader.SizeOfImage && timestamp == nt.FileHeader.TimeDateStamp;
    out["mapped_headers_match"] = headerMatches; out["mapped_image_size"] = imageSize;
    offset.QuadPart = 0; if (!SetFilePointerEx(file.value, offset, nullptr, FILE_BEGIN)) return out;
    Crypto crypto; DWORD objectSize = 0, hashSize = 0, returned = 0;
    if (BCryptOpenAlgorithmProvider(&crypto.algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0 ||
        BCryptGetProperty(crypto.algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectSize), sizeof(objectSize), &returned, 0) < 0 ||
        BCryptGetProperty(crypto.algorithm, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hashSize), sizeof(hashSize), &returned, 0) < 0 || hashSize != 32) return out;
    crypto.object.resize(objectSize);
    std::vector<BYTE> buffer(1024 * 1024), digest(hashSize);
    if (BCryptCreateHash(crypto.algorithm, &crypto.hash, crypto.object.data(), objectSize, nullptr, 0, 0) < 0) return out;
    uint64_t total = 0;
    for (;;) {
        if (!ReadFile(file.value, buffer.data(), static_cast<DWORD>(buffer.size()), &got, nullptr)) return out;
        if (!got) break;
        total += got; if (BCryptHashData(crypto.hash, buffer.data(), got, 0) < 0) return out;
    }
    if (total != static_cast<uint64_t>(length.QuadPart) || BCryptFinishHash(crypto.hash, digest.data(), hashSize, 0) < 0) return out;
    const char* hex = "0123456789abcdef"; std::string sha;
    for (BYTE b : digest) { sha += hex[b >> 4]; sha += hex[b & 15]; }
    out["actual_sha256"] = sha; out["status"] = headerMatches ? "hashed" : "mapped_headers_mismatch";
    return out;
}
} // namespace
nlohmann::json RuntimeIdentity() {
    static const nlohmann::json cached = [] {
        auto weixin = Fingerprint(g_hWeixinDll);
        weixin["expected_sha256"] = kExpected;
        weixin["verified"] = weixin.value("status", "") == "hashed" && weixin["actual_sha256"] == kExpected && weixin.value("file_bytes", uint64_t(0)) == 183094832;
        FILETIME created{}, exited{}, kernel{}, user{};
        std::string start;
        if (GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user)) {
            const uint64_t value = (static_cast<uint64_t>(created.dwHighDateTime) << 32) | created.dwLowDateTime;
            start = std::to_string(value);
        }
        return nlohmann::json{{"probe_build_id", "AI-HOOK-20261029-07"}, {"process_id", GetCurrentProcessId()},
            {"process_start_filetime", start}, {"weixin", weixin}, {"probe", Fingerprint(g_hModule)}};
    }();
    return cached;
}
}
