// wxcx_recv.cpp - inbound sysmsg probe (INT3 + VEH) with producer/consumer split
//
// Target: Weixin.dll+0x22D07C0 (4.1.10.27)
//
// Two hard rules for the hot path (runs on WeChat's own threads):
//   1) no allocation, no JSON, no file/network IO
//   2) bounded work only: a few hundred bytes of memcpy into a ring slot
// Formatting, string decoding and HTTP exposure all happen on our consumer
// thread, so a slow reader can never stall WeChat.
//
// Hook mechanism: single-byte INT3 at the function entry (atomic write), VEH
// catches the breakpoint, restores the byte, single-steps the original
// instruction, then re-arms. No thread is ever suspended.

#include "wxcx.h"

#include "httplib.h"
#include "json.hpp"

#include <windows.h>
#include <psapi.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <deque>
#include <mutex>
#include <string>

#include "global.h"
#include "wxcx_guard.h"
#include "Hook_Method.h"
#include "requests.h"
#include <ctime>

using json = nlohmann::json;

#pragma comment(lib, "psapi.lib")

namespace wxcx
{
namespace recv
{
    constexpr uint64_t kSysmsgHandlerRva = 0x22D07C0;

    namespace
    {
        // ---------------------------------------------------- hot path records
        constexpr size_t kArgBytes = 128;    // 每个入参最多抓这么多字节
        constexpr size_t kRingSize = 64;     // 必须是 2 的幂
        constexpr size_t kKeepEvents = 64;

        struct RawArg
        {
            uint64_t ptr;
            uint32_t hint;                   // 猜测的字符串长度（0 = 未知）
            uint8_t  bytes[kArgBytes];
        };

        struct RawEvent
        {
            uint64_t tick;
            RawArg   a[3];
        };

        RawEvent                g_ring[kRingSize];
        std::atomic<uint32_t>   g_head{ 0 };      // 生产者写
        std::atomic<uint32_t>   g_tail{ 0 };      // 消费者读
        std::atomic<uint64_t>   g_dropped{ 0 };

        // ---------------------------------------------------- consumer state
        std::mutex        g_mtx;
        std::deque<json>  g_events;
        std::atomic<bool> g_consumerStarted{ false };

        // ---------------------------------------------------- hook state
        std::atomic<bool>     g_armed{ false };
        std::atomic<uint64_t> g_deadlineMs{ 0 };
        std::atomic<long>     g_hits{ 0 };
        std::atomic<long>     g_armCount{ 0 };
        std::atomic<long>     g_traps{ 0 };
        std::atomic<long>     g_steps{ 0 };

        PVOID  g_veh = nullptr;
        thread_local bool t_inSingleStep = false;

        constexpr uint8_t kOriginalByte = 0x55;
        constexpr uint8_t kInt3 = 0xCC;

        // ---------------------------------------------------------- memory
        bool SafeRead(const void* p, void* dst, size_t n)
        {
            if (!p || n == 0) return false;
            __try
            {
                memcpy(dst, p, n);
                return true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                return false;
            }
        }

        bool WriteByte(void* p, uint8_t v)
        {
            DWORD old = 0;
            if (!::VirtualProtect(p, 1, PAGE_EXECUTE_READWRITE, &old)) return false;
            __try
            {
                *(volatile uint8_t*)p = v;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                ::VirtualProtect(p, 1, old, &old);
                return false;
            }
            ::VirtualProtect(p, 1, old, &old);
            ::FlushInstructionCache(::GetCurrentProcess(), p, 1);
            return true;
        }

        // 只做"读指针 + 拷贝"，不做任何解析
        void CaptureArg(RawArg& out, uint64_t value)
        {
            out.ptr = value;
            out.hint = 0;

            if (value < 0x10000) return;      // 小整数，不读

            // WxString 布局: len @ +0x10, cap @ +0x18
            uint64_t lenV = 0, capV = 0;
            if (SafeRead((void*)(value + 0x10), &lenV, 8) &&
                SafeRead((void*)(value + 0x18), &capV, 8) &&
                lenV > 0 && lenV <= kArgBytes && capV >= lenV && capV <= 65536)
            {
                uint64_t src = 0;
                if (lenV < 16)
                {
                    src = value;              // SSO: 数据就在结构体里
                }
                else
                {
                    SafeRead((void*)value, &src, 8);
                }
                if (src >= 0x10000 && SafeRead((void*)src, out.bytes, (size_t)lenV))
                {
                    out.hint = (uint32_t)lenV;
                    return;
                }
            }

            SafeRead((void*)value, out.bytes, kArgBytes);   // 兜底：抓 128 字节原文
        }

        // ---------------------------------------------------------- producer
        void OnSysmsg(const CALL_CONTEXT* ctx)
        {
            uint32_t head = g_head.load(std::memory_order_relaxed);
            uint32_t next = (head + 1) & (kRingSize - 1);

            if (next == g_tail.load(std::memory_order_acquire))
            {
                g_dropped++;                  // 环形缓冲满，丢弃（绝不阻塞微信线程）
                return;
            }

            RawEvent& e = g_ring[head];
            e.tick = ::GetTickCount64();
            CaptureArg(e.a[0], ctx->rcx);
            CaptureArg(e.a[1], ctx->rdx);
            CaptureArg(e.a[2], ctx->r8);

            g_head.store(next, std::memory_order_release);
        }

        // ---------------------------------------------------------- consumer
        bool LooksLikeText(const uint8_t* p, size_t n)
        {
            if (n < 4) return false;
            size_t printable = 0;
            for (size_t i = 0; i < n; ++i)
            {
                uint8_t c = p[i];
                if (c == 0) break;
                if (c == '\t' || c == '\r' || c == '\n' || (c >= 0x20 && c < 0x7F) || c >= 0x80)
                    printable++;
            }
            return printable * 100 / n >= 90;
        }

        json DescribeCaptured(const RawArg& a)
        {
            json j;
            j["raw"] = a.ptr;

            if (a.ptr < 0x10000)
            {
                j["kind"] = "small-int";
                return j;
            }

            if (a.hint > 0)
            {
                j["kind"] = "wx-string";
                j["len"] = a.hint;
                j["text"] = std::string((const char*)a.bytes,
                                        a.hint > kArgBytes ? kArgBytes : a.hint);
                return j;
            }

            size_t nz = 0;
            while (nz < kArgBytes && a.bytes[nz] != 0) nz++;
            j["kind"] = LooksLikeText(a.bytes, nz ? nz : 8) ? "text?" : "memory";

            static const char* kHex = "0123456789ABCDEF";
            std::string hex;
            size_t hn = nz > 64 ? 64 : (nz ? nz : 32);
            for (size_t i = 0; i < hn; ++i)
            {
                hex.push_back(kHex[a.bytes[i] >> 4]);
                hex.push_back(kHex[a.bytes[i] & 0xF]);
            }
            j["hex"] = hex;
            if (nz) j["ascii"] = std::string((const char*)a.bytes, nz > 96 ? 96 : nz);
            return j;
        }

        void CommitEvent(json ev)
        {
            std::lock_guard<std::mutex> lk(g_mtx);
            if (g_events.size() >= kKeepEvents) g_events.pop_front();
            g_events.push_back(std::move(ev));
        }

        void PushCallback(const json& ev);   // 前置声明

        DWORD WINAPI ConsumerThread(LPVOID)
        {
            for (;;)
            {
                ::Sleep(50);

                uint32_t tail = g_tail.load(std::memory_order_relaxed);
                while (tail != g_head.load(std::memory_order_acquire))
                {
                    const RawEvent& e = g_ring[tail];

                    json ev;
                    ev["t"] = e.tick;
                    ev["a1"] = DescribeCaptured(e.a[0]);
                    ev["a2"] = DescribeCaptured(e.a[1]);
                    ev["a3"] = DescribeCaptured(e.a[2]);
                    PushCallback(ev);          // 先推给 CallBackURL（阻塞在本线程，不影响微信）
                    CommitEvent(std::move(ev));

                    g_hits++;
                    tail = (tail + 1) & (kRingSize - 1);
                    g_tail.store(tail, std::memory_order_release);
                }
            }
            return 0;
        }

        // ------------------------------------------------- 回调推送（文档 016/019 结构）
        std::mutex  g_cbMtx;
        std::string g_cbUrl;             // 运行时可改
        std::string g_cbLastErr;
        std::atomic<long> g_cbOk{ 0 };
        std::atomic<long> g_cbFail{ 0 };

        std::string NowString()
        {
            SYSTEMTIME st{};
            ::GetLocalTime(&st);
            char b[32] = { 0 };
            snprintf(b, sizeof(b), "%04d-%02d-%02d %02d:%02d:%02d",
                     st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
            return std::string(b);
        }

        // 从三个入参里挑一个最像 XML/文本的
        const json* PickPayload(const json& ev)
        {
            const json* best = nullptr;
            for (const char* k : { "a2", "a3", "a1" })
            {
                if (!ev.contains(k)) continue;
                const json& a = ev[k];
                if (a.value("kind", std::string()) == "wx-string")
                {
                    std::string t = a.value("text", std::string());
                    if (!t.empty() && (t[0] == '<' || t.find('<') != std::string::npos))
                        return &a;
                    if (!best) best = &a;
                }
            }
            return best;
        }

        // 简易 XML 属性提取：<tag a="1" b="2" ...>
        // 只做"找 tag → 在其结束的 '>' 之前扫 key=\"value\""，不建树、不校验。
        bool ParseTagAttrs(const std::string& xml, const char* tag,
                           std::initializer_list<const char*> keys, json& out)
        {
            std::string open = "<";
            open += tag;
            size_t p = xml.find(open);
            if (p == std::string::npos) return false;
            size_t end = xml.find('>', p);
            if (end == std::string::npos) end = xml.size();
            std::string seg = xml.substr(p, end - p);

            bool any = false;
            for (const char* k : keys)
            {
                std::string pat = std::string(k) + "=\"";
                size_t q = seg.find(pat);
                if (q == std::string::npos) continue;
                q += pat.size();
                size_t e = seg.find('"', q);
                if (e == std::string::npos) continue;
                out[k] = seg.substr(q, e - q);
                any = true;
            }
            return any;
        }

        // 从原始 XML 推断 msgtype（对齐 showdoc 019/020/017 的取值）
        int InferMsgType(const std::string& xml)
        {
            if (xml.find("<sysmsg") != std::string::npos) return 10002;
            if (xml.find("<voicemsg") != std::string::npos) return 34;
            if (xml.find("<img") != std::string::npos) return 3;
            if (xml.find("<videomsg") != std::string::npos) return 43;
            if (xml.find("<emoji") != std::string::npos) return 47;
            if (xml.find("<appmsg") != std::string::npos) return 49;
            if (xml.find("<location") != std::string::npos) return 48;
            return 1;
        }

        void PushCallback(const json& ev)
        {
            std::string url;
            {
                std::lock_guard<std::mutex> lk(g_cbMtx);
                url = g_cbUrl;
            }
            if (url.empty() && !g_CallBack_Url.empty())
            {
                std::lock_guard<std::mutex> lk(g_cbMtx);
                g_cbUrl = g_CallBack_Url;
                url = g_cbUrl;
            }
            if (url.empty()) return;

            const json* payload = PickPayload(ev);
            std::string msgText = payload ? payload->value("text", std::string()) : std::string();

            int msgtype = InferMsgType(msgText);

            json item;
            item["cmdId"] = 5;
            item["fromid"] = "";
            item["fromtype"] = "1";
            item["index"] = 0;
            item["msg"] = msgText;
            item["msgsource"] = "";
            item["msgsvrid"] = 0;
            item["msgtype"] = msgtype;
            item["time"] = NowString();
            item["toid"] = "";

            // showdoc 020：语音消息把 XML 里的属性摊平，客户端不用再解析一遍
            if (msgtype == 34)
            {
                json voice;
                if (ParseTagAttrs(msgText, "voicemsg",
                                  { "voicelength", "length", "aeskey", "voiceurl",
                                    "voiceformat", "endflag", "clientmsgid", "fromusername" },
                                  voice))
                {
                    item["voice"] = voice;
                    if (voice.contains("fromusername"))
                        item["fromid"] = voice["fromusername"];
                    if (voice.contains("voicelength"))
                        item["voice_len"] = voice["voicelength"];
                }
            }
            else if (msgtype == 10002)
            {
                json at;
                if (ParseTagAttrs(msgText, "sysmsg", { "type" }, at))
                    item["sysmsg_type"] = at["type"];
            }

            json body;
            body["ServerPort"] = g_StartPort;
            body["msglist"] = json::array({ item });
            body["msgnumber"] = 1;
            body["selfwxid"] = SelfInfo.wxid;
            body["sendorrecv"] = 2;

            try
            {
                auto r = requests::post(url, httplib::Headers(), body.dump(), "application/json");
                if (r && r->status >= 200 && r->status < 300)
                {
                    g_cbOk++;
                    return;
                }
                g_cbFail++;
                std::lock_guard<std::mutex> lk(g_cbMtx);
                g_cbLastErr = r ? ("http " + std::to_string(r->status)) : "no response";
            }
            catch (...)
            {
                g_cbFail++;
                std::lock_guard<std::mutex> lk(g_cbMtx);
                g_cbLastErr = "exception";
            }
        }

        void StartConsumerOnce()
        {
            if (g_consumerStarted.exchange(true)) return;
            HANDLE h = ::CreateThread(nullptr, 0, &ConsumerThread, nullptr, 0, nullptr);
            if (h)
            {
                ::SetThreadPriority(h, THREAD_PRIORITY_BELOW_NORMAL);
                ::CloseHandle(h);
            }
        }

        // ---------------------------------------------- 好友切换 / 登录态变化 (showdoc 018)
        std::atomic<bool> g_switchWatcher{ false };

        void EmitSwitchEvent(const std::string& toWxid, int status)
        {
            json item;
            item["cmdid"] = 0;
            item["fromid"] = "";
            item["fromtype"] = 1;
            item["index"] = "0";
            item["msg"] = "\u8054\u7cfb\u4eba\u5207\u6362";     // 联系人切换
            item["msgsource"] = "";
            item["msgsvrid"] = 0;
            item["msgtype"] = 999;
            item["time"] = NowString();
            item["toid"] = "";

            json outinfo;
            outinfo["status"] = status;
            outinfo["switch_to_wxid"] = toWxid;

            json body;
            body["MsgNumber"] = 1;
            body["SelfWxid"] = SelfInfo.wxid;
            body["SendOrRecv"] = 2;
            body["ServerPort"] = g_StartPort;
            body["msglist"] = json::array({ item });
            body["outinfo"] = outinfo;

            // 1) 进本地事件表
            json ev;
            ev["t"] = (uint64_t)::GetTickCount64();
            ev["kind"] = "switch";
            ev["switch_to_wxid"] = toWxid;
            ev["onlinestatus"] = status;
            CommitEvent(std::move(ev));

            // 2) 推回调
            std::string url;
            {
                std::lock_guard<std::mutex> lk(g_cbMtx);
                url = g_cbUrl;
                if (url.empty() && !g_CallBack_Url.empty()) url = g_CallBack_Url;
            }
            if (url.empty()) return;

            try
            {
                auto r = requests::post(url, httplib::Headers(), body.dump(), "application/json");
                if (r && r->status >= 200 && r->status < 300) g_cbOk++;
                else
                {
                    g_cbFail++;
                    std::lock_guard<std::mutex> lk(g_cbMtx);
                    g_cbLastErr = r ? ("http " + std::to_string(r->status)) : "no response";
                }
            }
            catch (...)
            {
                g_cbFail++;
            }
        }

        DWORD WINAPI SwitchWatcher(LPVOID)
        {
            std::string lastWxid;
            uint64_t lastLogin = 0;
            bool first = true;

            for (;;)
            {
                ::Sleep(1000);

                std::string wxid = SelfInfo.wxid;
                uint64_t login = g_IsLogin;

                if (!first)
                {
                    bool changed = (!wxid.empty() && wxid != lastWxid) || (login != lastLogin && lastLogin != 0);
                    if (changed)
                        EmitSwitchEvent(wxid, (int)login);
                }

                if (!wxid.empty()) lastWxid = wxid;
                lastLogin = login;
                first = false;
            }
            return 0;
        }

        void StartSwitchWatcherOnce()
        {
            if (g_switchWatcher.exchange(true)) return;
            HANDLE h = ::CreateThread(nullptr, 0, &SwitchWatcher, nullptr, 0, nullptr);
            if (h)
            {
                ::SetThreadPriority(h, THREAD_PRIORITY_LOWEST);
                ::CloseHandle(h);
            }
        }

        // ------------------------------------------------------------- hook
        bool TargetInRange()
        {
            if (!g_hWeixinDll) return false;
            MODULEINFO mi{};
            if (!::GetModuleInformation(::GetCurrentProcess(), g_hWeixinDll, &mi, sizeof(mi)))
                return false;
            return kSysmsgHandlerRva + 16 <= (uint64_t)mi.SizeOfImage;
        }

        uint8_t* Target()
        {
            if (!g_hWeixinDll || !TargetInRange()) return nullptr;
            return (uint8_t*)((uintptr_t)g_hWeixinDll + kSysmsgHandlerRva);
        }

        bool PrologueIsPristine()
        {
            uint8_t* t = Target();
            if (!t) return false;
            uint8_t b = 0;
            if (!SafeRead(t, &b, 1)) return false;
            return b == kOriginalByte;
        }

        LONG CALLBACK VehHandler(EXCEPTION_POINTERS* ep)
        {
            uint8_t* target = Target();
            if (!target || !ep || !ep->ExceptionRecord || !ep->ContextRecord)
                return EXCEPTION_CONTINUE_SEARCH;

            auto* rec = ep->ExceptionRecord;
            auto* ctx = ep->ContextRecord;

            if (rec->ExceptionCode == EXCEPTION_BREAKPOINT &&
                (uintptr_t)rec->ExceptionAddress == (uintptr_t)target)
            {
                g_traps++;

                CALL_CONTEXT cc{};
                cc.rcx = ctx->Rcx;
                cc.rdx = ctx->Rdx;
                cc.r8 = ctx->R8;
                OnSysmsg(&cc);                 // 只拷贝，不做解析

                WriteByte(target, kOriginalByte);
                ctx->Rip = (DWORD64)target;
                ctx->EFlags |= 0x100;          // TF
                t_inSingleStep = true;
                return EXCEPTION_CONTINUE_EXECUTION;
            }

            if (rec->ExceptionCode == EXCEPTION_SINGLE_STEP && t_inSingleStep)
            {
                t_inSingleStep = false;
                ctx->EFlags &= ~0x100;
                g_steps++;
                if (g_armed) WriteByte(target, kInt3);
                return EXCEPTION_CONTINUE_EXECUTION;
            }

            return EXCEPTION_CONTINUE_SEARCH;
        }

        void EnsureVeh()
        {
            if (g_veh) return;
            g_veh = ::AddVectoredExceptionHandler(1, &VehHandler);
        }

        DWORD WINAPI Watchdog(LPVOID)
        {
            for (;;)
            {
                ::Sleep(200);
                if (g_armed && ::GetTickCount64() >= g_deadlineMs)
                {
                    uint8_t* t = Target();
                    if (t) WriteByte(t, kOriginalByte);
                    g_armed = false;
                }
            }
            return 0;
        }

        void StartWatchdogOnce()
        {
            static bool started = false;
            if (started) return;
            started = true;
            HANDLE h = ::CreateThread(nullptr, 0, &Watchdog, nullptr, 0, nullptr);
            if (h) ::CloseHandle(h);
        }
    } // namespace

    bool Arm(uint32_t windowMs)
    {
        if (windowMs == 0) windowMs = 60000;
        if (windowMs > 3600000) windowMs = 3600000;

        StartConsumerOnce();
        StartWatchdogOnce();
        EnsureVeh();
        wxcx::guard::SetProbeReadHandler([]() { wxcx::recv::Disarm(); });

        if (g_armed)
        {
            g_deadlineMs = ::GetTickCount64() + windowMs;
            return true;
        }

        uint8_t* t = Target();
        if (!t || !PrologueIsPristine()) return false;
        if (!WriteByte(t, kInt3)) return false;

        g_armed = true;
        g_deadlineMs = ::GetTickCount64() + windowMs;
        g_armCount++;
        return true;
    }

    bool Disarm()
    {
        if (!g_armed) return true;
        uint8_t* t = Target();
        if (!t) return false;
        if (!WriteByte(t, kOriginalByte)) return false;
        g_armed = false;
        return true;
    }

    bool IsArmed() { return g_armed; }
    long Hits() { return g_hits; }

    json Snapshot(size_t limit)
    {
        std::lock_guard<std::mutex> lk(g_mtx);
        json arr = json::array();
        size_t start = g_events.size() > limit ? g_events.size() - limit : 0;
        for (size_t i = start; i < g_events.size(); ++i) arr.push_back(g_events[i]);
        return arr;
    }

    void Clear()
    {
        std::lock_guard<std::mutex> lk(g_mtx);
        g_events.clear();
    }

    void RegisterRoutes(httplib::Server& svr)
    {
        StartSwitchWatcherOnce();
        svr.Get("/wxcx/recv/status", [](const httplib::Request&, httplib::Response& res)
        {
            json j;
            j["armed"] = IsArmed();
            j["hits"] = Hits();
            j["arm_count"] = (long)g_armCount;
            j["traps"] = (long)g_traps;
            j["single_steps"] = (long)g_steps;
            j["ring_dropped"] = (uint64_t)g_dropped;
            j["target_rva"] = "0x22D07C0";
            j["mode"] = "int3-veh + producer/consumer";   // 热路径只做拷贝
            j["veh_installed"] = (g_veh != nullptr);
            j["switch_watcher"] = (bool)g_switchWatcher;
            if (IsArmed())
            {
                uint64_t now = ::GetTickCount64();
                j["remaining_ms"] = g_deadlineMs > now ? (g_deadlineMs - now) : 0;
            }
            else
            {
                j["prologue_pristine"] = PrologueIsPristine();
            }
            res.set_content(j.dump(), "application/json");
        });

        svr.Post("/wxcx/recv/arm", [](const httplib::Request& req, httplib::Response& res)
        {
            uint32_t ms = 60000;
            if (!req.body.empty())
            {
                try
                {
                    json j = json::parse(req.body);
                    if (j.contains("ms") && j["ms"].is_number_integer())
                        ms = (uint32_t)j["ms"].get<long long>();
                }
                catch (...) {}
            }
            bool ok = Arm(ms);
            json j;
            j["ok"] = ok;
            j["armed"] = IsArmed();
            if (!ok) j["reason"] = "hook failed or prologue not pristine";
            res.set_content(j.dump(), "application/json");
        });

        svr.Post("/wxcx/recv/disarm", [](const httplib::Request&, httplib::Response& res)
        {
            bool ok = Disarm();
            json j;
            j["ok"] = ok;
            j["armed"] = IsArmed();
            j["prologue_pristine"] = PrologueIsPristine();
            res.set_content(j.dump(), "application/json");
        });

        svr.Get("/wxcx/recv/events", [](const httplib::Request& req, httplib::Response& res)
        {
            size_t limit = 20;
            if (req.has_param("limit"))
            {
                try { limit = (size_t)std::stoul(req.get_param_value("limit")); } catch (...) {}
                if (limit == 0 || limit > 64) limit = 20;
            }
            json out;
            out["armed"] = IsArmed();
            out["hits"] = Hits();
            out["events"] = Snapshot(limit);
            res.set_content(out.dump(), "application/json");
        });

        svr.Get("/wxcx/callback/status", [](const httplib::Request&, httplib::Response& res)
        {
            json j;
            {
                std::lock_guard<std::mutex> lk(g_cbMtx);
                j["url"] = g_cbUrl;
                j["last_error"] = g_cbLastErr;
            }
            j["ok"] = (long)g_cbOk;
            j["fail"] = (long)g_cbFail;
            j["mode"] = "same-process POST from consumer thread";
            res.set_content(j.dump(), "application/json");
        });

        svr.Post("/wxcx/callback/config", [](const httplib::Request& req, httplib::Response& res)
        {
            json j;
            if (!req.body.empty())
            {
                try
                {
                    json in = json::parse(req.body);
                    std::string url = in.value("url", std::string());
                    std::lock_guard<std::mutex> lk(g_cbMtx);
                    g_cbUrl = url;
                }
                catch (...) {}
            }
            {
                std::lock_guard<std::mutex> lk(g_cbMtx);
                j["url"] = g_cbUrl;
            }
            j["ok"] = true;
            res.set_content(j.dump(), "application/json");
        });

        svr.Post("/wxcx/recv/clear", [](const httplib::Request&, httplib::Response& res)
        {
            Clear();
            json j; j["ok"] = true;
            res.set_content(j.dump(), "application/json");
        });
    }

} // namespace recv
} // namespace wxcx
