// wxcx_client.cpp - 客户端函数表：运行时解析 + prologue 校验 + 安全调用
//
// 为什么需要这一层：
//   4.1.10.27 里这些高层函数（SendPat / Forward / SendFile / SendXml …）无法靠静态
//   字符串或调用图定位（这个 build 的字符串走自定义池、pb 走虚表、mars 无 RTTI）。
//   地址可以作为调查数据保存；地址校验不能替代本版本 ABI 和对象布局验证。

#include "wxcx_client.h"
#include "wxcx_sample.h"

#include "httplib.h"
#include "json.hpp"

#include <windows.h>
#include <psapi.h>

#include <cstdio>
#include <cstring>
#include <fstream>
#include <mutex>
#include <string>
#include <vector>

#include "global.h"

using json = nlohmann::json;

#pragma comment(lib, "psapi.lib")

namespace wxcx
{
namespace client
{
namespace
{
    struct Entry
    {
        const char* name;
        const char* desc;
        const char* sig;        // 文档用途，便于人肉核对
        uint64_t    rva;        // 0 = 未解析
        std::string prologue;   // 期望的首字节（hex，可空）
        void*       fn;
    };

    // 表：地址留空，运行时填
    Entry g_table[] = {
        { "send_pat",   "拍一拍",              "int64(WxString* roomid, WxString* wxid)",            0, "", nullptr },
        { "forward",    "转发消息",            "unverified 4.x native adapter; /wxcx/forward/capabilities", 0, "", nullptr },
        { "send_file",  "发任意文件",          "int64(appMgr, msg, WxString* to, WxString* path, …)", 0, "", nullptr },
        { "send_xml",   "发卡片/视频号 XML",   "int64(b1, WxString* from, to, xml, thumb, …)",       0, "", nullptr },
        { "send_text",  "发文本(高层)",        "int64(mgr, msg, WxString* to, WxString* msg, …)",    0, "", nullptr },
        { "send_image", "发图片(高层)",        "int64(mgr, msg, WxString* to, WxString* path, …)",   0, "", nullptr },
        { "send_emotion", "发表情",            "int64(emotionMgr, WxString* path, buff, to, …)",     0, "", nullptr },
        { "recv_call",  "接收消息回调",        "void(msgStruct*)",                                   0, "", nullptr },
        { "download_attach", "下载附件/语音",  "int64(...)",                                         0, "", nullptr },
        { "revoke",     "撤回消息",            "int64(uint64 localId)",                              0, "", nullptr },
    };

    std::mutex g_mtx;

    uint8_t* ImageBase(uint64_t* sizeOut = nullptr)
    {
        if (!g_hWeixinDll) return nullptr;
        MODULEINFO mi{};
        if (!::GetModuleInformation(::GetCurrentProcess(), g_hWeixinDll, &mi, sizeof(mi)))
            return nullptr;
        if (sizeOut) *sizeOut = (uint64_t)mi.SizeOfImage;
        return (uint8_t*)mi.lpBaseOfDll;
    }

    Entry* Find(const std::string& name)
    {
        for (auto& e : g_table)
            if (name == e.name) return &e;
        return nullptr;
    }

    bool ParseHex(const std::string& hex, std::string& out)
    {
        out.clear();
        auto nib = [](char c) -> int
        {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        if (hex.size() % 2) return false;
        for (size_t i = 0; i + 1 < hex.size(); i += 2)
        {
            int a = nib(hex[i]), b = nib(hex[i + 1]);
            if (a < 0 || b < 0) return false;
            out.push_back((char)((a << 4) | b));
        }
        return true;
    }

    // ---------- POD-only SEH 助手（含 std::string 的函数不能用 __try）----------
    bool PodMemEq(const void* a, const void* b, size_t n)
    {
        __try { return memcmp(a, b, n) == 0; }
        __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
    }

    constexpr long long kCallFailed = (long long)0x8000000000000000ULL;

    long long PodCall2(void* fn, void* a, void* b)
    {
        __try { return ((long long(__fastcall*)(void*, void*))fn)(a, b); }
        __except (EXCEPTION_EXECUTE_HANDLER) { return kCallFailed; }
    }

    long long PodCall4(void* fn, void* a, unsigned long long b, int c, int d)
    {
        __try { return ((long long(__fastcall*)(void*, unsigned long long, int, int))fn)(a, b, c, d); }
        __except (EXCEPTION_EXECUTE_HANDLER) { return kCallFailed; }
    }
    // 校验 prologue（为空则只检查可读）
    bool Verify(Entry& e, uint8_t* base, uint64_t size, std::string& why)
    {
        e.fn = nullptr;
        if (!base) { why = "weixin module not loaded"; return false; }
        if (e.rva == 0) { why = "unresolved"; return false; }
        if (e.rva >= size || size - e.rva < 16) { why = "rva out of image"; return false; }
        if (!wxcx::sample::IsFunctionStart(e.rva)) { why = "not a verified function entry"; return false; }

        uint8_t* p = base + e.rva;
        if (!e.prologue.empty())
        {
            std::string want;
            if (!ParseHex(e.prologue, want)) { why = "bad prologue hex"; return false; }
            if (want.size() > size - e.rva) { why = "prologue out of image"; return false; }
            if (!PodMemEq(p, want.data(), want.size())) { why = "prologue mismatch"; return false; }
        }
        e.fn = (void*)p;
        why = "ok";
        return true;
    }

    std::string DiskPath()
    {
        char path[MAX_PATH] = { 0 };
        HMODULE self = nullptr;
        ::GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                             GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                             (LPCWSTR)&DiskPath, &self);
        ::GetModuleFileNameA(self, path, MAX_PATH);
        std::string s(path);
        size_t pos = s.find_last_of("\\/");
        if (pos != std::string::npos) s.resize(pos + 1);
        return s + "wxcx_client.json";
    }

    void* Require(const char* name, std::string& why)
    {
        Entry* e = Find(name);
        if (!e) { why = "unknown function"; return nullptr; }
        uint64_t size = 0;
        uint8_t* base = ImageBase(&size);
        if (!Verify(*e, base, size, why)) return nullptr;
        return e->fn;
    }

    // -------- WxString 构造（布局：len@+0x10, cap@+0x18，<16 字节内联）--------
    struct WxStr
    {
        uint64_t buf[4] = { 0, 0, 0, 0 };   // 0x20 字节：内联区 + len + cap
        std::string heap;
    };

    void MakeWx(WxStr& out, const std::string& utf8)
    {
        // UTF-8 → UTF-16
        int n = ::MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), (int)utf8.size(), nullptr, 0);
        std::wstring w(n > 0 ? n : 0, L'\0');
        if (n > 0)
            ::MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), (int)utf8.size(), &w[0], n);

        size_t bytes = w.size() * sizeof(wchar_t);
        if (bytes < 16)
        {
            memcpy(&out.buf[0], w.data(), bytes);
            out.buf[2] = w.size();          // +0x10 len
            out.buf[3] = 15;                // +0x18 cap
        }
        else
        {
            out.heap.assign((const char*)w.data(), bytes);
            out.buf[0] = (uint64_t)(uintptr_t)out.heap.data();
            out.buf[2] = w.size();
            out.buf[3] = w.size() + 1;
        }
    }

    bool InImage(uint64_t v, uint64_t base, uint64_t size)
    {
        return v >= base && v < base + size;
    }
}

    bool SetRva(const std::string& name, uint64_t rva, const std::string& prologueHex)
    {
        std::lock_guard<std::mutex> lk(g_mtx);
        Entry* e = Find(name);
        if (!e) return false;

        e->rva = rva;
        e->prologue = prologueHex;
        e->fn = nullptr;

        if (e->rva == 0) return SaveToDisk();

        uint64_t size = 0;
        uint8_t* base = ImageBase(&size);
        std::string why;
        if (!Verify(*e, base, size, why)) return false;
        SaveToDisk();
        return true;
    }

    json Status()
    {
        std::lock_guard<std::mutex> lk(g_mtx);
        uint64_t size = 0;
        uint8_t* base = ImageBase(&size);

        json arr = json::array();
        int resolved = 0, unresolved = 0, bad = 0;
        for (auto& e : g_table)
        {
            json j;
            j["name"] = e.name;
            j["desc"] = e.desc;
            j["sig"] = e.sig;
            j["rva"] = e.rva;

            std::string why;
            bool ok = (e.rva != 0) && Verify(e, base, size, why);
            const bool forwardUnverified = std::string(e.name) == "forward";
            j["address_valid"] = ok;
            j["ok"] = ok && !forwardUnverified;
            if (forwardUnverified)
            {
                j["native_abi_verified"] = false;
                j["callable"] = false;
                j["blocked_by"] = "4.1.10.27 forward ABI and native message reference remain unverified";
            }
            j["why"] = why;
            if (e.rva == 0) unresolved++;
            else if (ok) resolved++;
            else bad++;
            arr.push_back(j);
        }

        json out;
        out["resolved"] = resolved;
        out["unresolved"] = unresolved;
        out["invalid"] = bad;
        out["note"] = "地址/首字节校验不证明调用约定；Forward 在 4.1.10.27 ABI 确认前禁用";
        out["items"] = arr;
        return out;
    }

    void LoadFromDisk()
    {
        std::ifstream in(DiskPath());
        if (!in) return;
        try
        {
            json j;
            in >> j;
            std::lock_guard<std::mutex> lk(g_mtx);
            for (auto& e : g_table)
            {
                if (!j.contains(e.name)) continue;
                const json& v = j[e.name];
                if (v.is_object())
                {
                    if (v.contains("rva") && v["rva"].is_number_unsigned())
                        e.rva = v["rva"].get<uint64_t>();
                    if (v.contains("prologue") && v["prologue"].is_string())
                        e.prologue = v["prologue"].get<std::string>();
                }
            }
        }
        catch (...) {}
    }

    bool SaveToDisk()
    {
        json j = json::object();
        for (auto& e : g_table)
        {
            if (e.rva == 0) continue;
            json v;
            v["rva"] = e.rva;
            v["prologue"] = e.prologue;
            j[e.name] = v;
        }
        try
        {
            std::ofstream out(DiskPath(), std::ios::trunc);
            if (!out) return false;
            out << j.dump(2);
            return true;
        }
        catch (...) { return false; }
    }

    CallResult SendPat(const std::string& roomid, const std::string& wxid)
    {
        CallResult r;
        std::string why;
        void* fn = Require("send_pat", why);
        if (!fn) { r.reason = "unresolved: send_pat (" + why + ")"; return r; }

        WxStr room, target;
        MakeWx(room, roomid);
        MakeWx(target, wxid);

        long long rc = PodCall2(fn, &room, &target);
        if (rc == kCallFailed) { r.reason = "exception while calling send_pat"; return r; }
        r.status = (long)rc;
        r.ok = true;
        return r;
    }

    CallResult Forward(const std::string& toid, uint64_t quad)
    {
        CallResult r;
        // 0x2161FC0 uses (out, selection-context, source-object, options, callbacks).
        // The historical 3.9.x (WxString*, quad, 4, 0) adapter cannot call it.
        // An in-range address or matching prologue cannot establish this ABI.
        (void)toid; (void)quad;
        r.reason = "unverified_abi: 4.1.10.27 native Forward and message reference encoding are not validated";
        return r;
    }

    void RegisterRoutes(httplib::Server& svr)
    {
        svr.Get("/wxcx/client/status", [](const httplib::Request&, httplib::Response& res)
        {
            res.set_content(Status().dump(2), "application/json");
        });

        // {"name":"send_pat","rva":"0x2CCDDC0","prologue":"56 57 53"}
        svr.Post("/wxcx/client/set", [](const httplib::Request& req, httplib::Response& res)
        {
            json out;
            if (req.body.empty())
            {
                out["ok"] = false;
                out["msg"] = "body required: {\"name\":\"...\",\"rva\":\"0x...\"}";
                res.set_content(out.dump(), "application/json");
                return;
            }
            try
            {
                json in = json::parse(req.body);
                std::string name = in.value("name", std::string());
                std::string rvaS = in.value("rva", std::string());

                uint64_t rva = 0;
                if (!rvaS.empty())
                {
                    const char* p = rvaS.c_str();
                    if (rvaS.rfind("0x", 0) == 0 || rvaS.rfind("0X", 0) == 0) p += 2;
                    rva = std::strtoull(p, nullptr, 16);
                }
                std::string prologue = in.value("prologue", std::string());

                out["ok"] = SetRva(name, rva, prologue);
                out["name"] = name;
                out["rva"] = rva;
                if (!out["ok"].get<bool>())
                    out["msg"] = "name 不存在，或 rva 越界/prologue 不匹配";
            }
            catch (const std::exception& ex)
            {
                out["ok"] = false;
                out["msg"] = ex.what();
            }
            res.set_content(out.dump(), "application/json");
        });

        // 拍一拍（地址就绪即生效）
        svr.Post("/SendPatMsg", [](const httplib::Request& req, httplib::Response& res)
        {
            json in;
            try { if (!req.body.empty()) in = json::parse(req.body); } catch (...) {}
            std::string room = in.value("roomid", std::string());
            std::string wxid = in.value("wxid", std::string());
            if (room.empty() || wxid.empty())
            {
                res.status = 400;
                res.set_content("{\"code\":\"-1\",\"msg\":\"roomid 和 wxid 必填\"}", "application/json");
                return;
            }
            auto r = SendPat(room, wxid);
            json out;
            out["code"] = r.ok ? "0" : "-1";
            out["status"] = r.status;
            if (!r.ok) out["msg"] = r.reason;
            res.set_content(out.dump(), "application/json");
        });

        // /ForwardMsg is owned by wxcx::forward's asynchronous task protocol.
    }

} // namespace client
} // namespace wxcx
