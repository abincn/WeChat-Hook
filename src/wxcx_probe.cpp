// wxcx_probe.cpp - generic function probe (INT3 + VEH), arbitrary RVA
//
// Same mechanism as wxcx::recv (one-byte INT3, atomic write, VEH restores the
// byte, single-steps the original instruction, then re-arms), but:
//   * N independent targets instead of one fixed address
//   * captures rcx/rdx/r8 plus a caller-chosen dump of the rcx object
//   * producers never allocate or wait: bounded, non-waiting record publication
//
// Typical use: arm 0x2C6C550 (MicroMsgRequestNew serializer) with dump=0x60 to
// read the envelope's varint fields (cmdId/seq/...) straight out of the object.

#include "wxcx_probe.h"
#include "wxcx_probe_ring.h"
#include "wxcx_sample.h"
#include "wxcx_identity.h"

#include <fstream>
#include <string>

#include "httplib.h"
#include "json.hpp"

#include <windows.h>
#include <psapi.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <limits>
#include <string>

#include "global.h"

using json = nlohmann::json;

#pragma comment(lib, "psapi.lib")

namespace wxcx
{
namespace probe
{
namespace
{
    constexpr int    kMaxProbes = 4;
    constexpr size_t kMaxDump = 256;
    constexpr size_t kStack = 256;   // 抓 [rsp, rsp+256) 的原始字节
    constexpr size_t kRing = 64;
    constexpr size_t kKeep = 32;

    struct Slot
    {
        std::atomic<uint64_t> rva{ 0 };
        std::atomic<uint32_t> dump{ 0 };
        std::atomic<uint32_t> dumpReg{ 1 };    // 1=rcx 2=rdx 3=r8 4=r9
        std::atomic<bool> functionEntry{ false };
        std::atomic<uint32_t> followOff{ 0 };   // 从 rcx 对象里读出的指针偏移（0 = 不跟随）
        std::atomic<uint32_t> followLen{ 0 };   // 跟随后再 dump 多少字节
        std::atomic<uint32_t> follow2Off{ 0 };  // 第二跳：从 follow 结果再读一个指针
        std::atomic<uint32_t> followReadOffset{ 0 }; // 最终指针的读取偏移；用于读取大对象尾部
        std::atomic<uint32_t> strReg{ 0 };      // 0=关闭 1=rcx 2=rdx 3=r8 4=rsi 5=rdi 6=rax
        std::atomic<uint32_t> strOff{ 0 };      // 字符串对象相对寄存器基址的偏移
        std::atomic<uint32_t> strMax{ 0 };      // 最多抓多少字节
        std::atomic<bool>     armed{ false };
        std::atomic<uint64_t> deadline{ 0 };
        uint8_t               orig = 0;
        std::atomic<long>     traps{ 0 };
    };

    struct Record
    {
        uint64_t sequence;
        uint64_t tick;
        uint64_t rva;
        uint64_t a1, a2, a3, a4;
        uint64_t rip, rsp, object;
        uint32_t objectReg;
        bool functionEntry, retValid;
        uint32_t dumpLen;
        uint8_t  dump[kMaxDump];
        uint32_t stackLen;                  // 栈上原始字节（用于离线还原调用链）
        uint8_t  stack[kStack];
        uint32_t followLen;
        uint32_t followReadOffset;
        uint8_t  follow[kMaxDump];
        uint32_t tid;
        uint64_t ret;                       // 栈顶 [rsp]，直接调用者返回地址
        uint32_t strLen;                    // 逻辑长度
        uint32_t strCap;                    // 容量
        uint64_t strBuf;                    // 实际缓冲区地址
        uint32_t strGot;                    // 实际抓到的字节数
        uint8_t  strData[kMaxDump];
    };

    Slot    g_slots[kMaxProbes];
    RecordRing<Record, kRing> g_records;

    PVOID g_veh = nullptr;
    thread_local int t_pending = -1;       // 单步回填用的待处理槽位

    // ------------------------------------------------------------ 内存工具
    bool SafeRead(const void* p, void* dst, size_t n)
    {
        if (!p || !n) return false;
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

    // 解析已加载模块的 .text 范围（只用 PE 头，不分配）
    bool TextRange(uint64_t& lo, uint64_t& hi)
    {
        if (!g_hWeixinDll) return false;
        uint8_t* base = (uint8_t*)g_hWeixinDll;
        auto* dos = (IMAGE_DOS_HEADER*)base;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
        auto* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
        auto* sec = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i)
        {
            if (memcmp(sec[i].Name, ".text", 5) == 0)
            {
                uint64_t va = (uint64_t)base + sec[i].VirtualAddress;
                uint64_t sz = sec[i].Misc.VirtualSize;
                if (sec[i].SizeOfRawData > sz) sz = sec[i].SizeOfRawData;
                lo = va;
                hi = va + sz;
                return true;
            }
        }
        return false;
    }

    uint8_t* TargetOf(uint64_t rva)
    {
        if (!g_hWeixinDll) return nullptr;
        MODULEINFO mi{};
        if (!::GetModuleInformation(::GetCurrentProcess(), g_hWeixinDll, &mi, sizeof(mi)))
            return nullptr;
        if (rva >= (uint64_t)mi.SizeOfImage || (uint64_t)mi.SizeOfImage - rva < 16) return nullptr;
        return (uint8_t*)((uintptr_t)g_hWeixinDll + rva);
    }

    // ---------------------------------------------------------- 抓取与入队
    void Capture(int idx, const void* ctxRegs)
    {
        // All fields are private until TryPush publishes the complete record.
        auto* c = (const CONTEXT*)ctxRegs;
        Record r{};
        r.tick = ::GetTickCount64();
        r.rva = g_slots[idx].rva.load(std::memory_order_relaxed);
        r.a1 = c->Rcx;
        r.a2 = c->Rdx;
        r.a3 = c->R8;
        r.a4 = c->R9;
        r.rip = (uint64_t)g_hWeixinDll + r.rva;
        r.rsp = c->Rsp;
        r.functionEntry = g_slots[idx].functionEntry.load(std::memory_order_relaxed);
        r.objectReg = g_slots[idx].dumpReg.load(std::memory_order_relaxed);
        switch (r.objectReg)
        {
            case 2: r.object = c->Rdx; break;
            case 3: r.object = c->R8; break;
            case 4: r.object = c->R9; break;
            default: r.object = c->Rcx; break;
        }

        uint32_t dump = g_slots[idx].dump.load(std::memory_order_relaxed);
        if (dump > kMaxDump) dump = (uint32_t)kMaxDump;
        r.dumpLen = dump;
        if (dump && r.object >= 0x10000)
        {
            if (!SafeRead((const void*)r.object, r.dump, dump))
                r.dumpLen = 0;
        }
        else
        {
            r.dumpLen = 0;
        }

        // [rsp] is a return address only at a verified function entry.
        r.tid = (uint32_t)::GetCurrentThreadId();
        r.ret = 0;
        r.retValid = r.functionEntry && c->Rsp >= 0x10000 &&
            SafeRead((const void*)c->Rsp, &r.ret, 8);

        // Raw stack bytes; scanning them is not stack unwinding.
        r.stackLen = 0;
        if (c->Rsp >= 0x10000 && SafeRead((const void*)c->Rsp, r.stack, kStack))
            r.stackLen = (uint32_t)kStack;

        // 字符串采集：reg + off 指向 std::string/wstring（len@+0x10 cap@+0x18）
        r.strLen = r.strCap = r.strGot = 0;
        r.strBuf = 0;
        uint32_t sr = g_slots[idx].strReg.load(std::memory_order_relaxed);
        if (sr)
        {
            uint64_t regv = 0;
            switch (sr)
            {
                case 1: regv = c->Rcx; break;
                case 2: regv = c->Rdx; break;
                case 3: regv = c->R8;  break;
                case 4: regv = c->Rsi; break;
                case 5: regv = c->Rdi; break;
                case 6: regv = c->Rax; break;
                default: break;
            }
            uint32_t soff = g_slots[idx].strOff.load(std::memory_order_relaxed);
            uint32_t smax = g_slots[idx].strMax.load(std::memory_order_relaxed);
            if (smax == 0 || smax > kMaxDump) smax = kMaxDump;
            if (regv >= 0x10000)
            {
                uint64_t fieldAddr = regv + soff;
                uint64_t lenv = 0, capv = 0;
                if (SafeRead((const void*)(fieldAddr + 0x10), &lenv, 8) &&
                    SafeRead((const void*)(fieldAddr + 0x18), &capv, 8))
                {
                    r.strLen = (uint32_t)(lenv > 0xFFFFFFFFull ? 0xFFFFFFFFull : lenv);
                    r.strCap = (uint32_t)(capv > 0xFFFFFFFFull ? 0xFFFFFFFFull : capv);
                    uint64_t bufp = fieldAddr;
                    if (capv >= 0x10)
                    {
                        uint64_t deref = 0;
                        if (SafeRead((const void*)fieldAddr, &deref, 8)) bufp = deref;
                        else bufp = 0;
                    }
                    if (bufp >= 0x10000 && lenv > 0 && lenv < 0x10000)
                    {
                        uint32_t take = (uint32_t)(lenv > smax ? smax : lenv);
                        if (SafeRead((const void*)bufp, r.strData, take))
                        {
                            r.strBuf = bufp;
                            r.strGot = take;
                        }
                    }
                }
            }
        }

        // 指针跟随：rcx+followOff → (可选再一跳 follow2Off) → dump
        r.followLen = 0;
        uint32_t foff  = g_slots[idx].followOff.load(std::memory_order_relaxed);
        uint32_t flen  = g_slots[idx].followLen.load(std::memory_order_relaxed);
        uint32_t f2off = g_slots[idx].follow2Off.load(std::memory_order_relaxed);
        r.followReadOffset = g_slots[idx].followReadOffset.load(std::memory_order_relaxed);
        constexpr uint64_t kUint64Max = (std::numeric_limits<uint64_t>::max)();
        if (flen && r.object >= 0x10000 && r.object <= kUint64Max - foff)
        {
            uint64_t target = 0;
            if (SafeRead((const void*)(r.object + foff), &target, 8) && target >= 0x10000)
            {
                bool followOk = true;
                if (f2off != 0xFFFFFFFFu)
                {
                    uint64_t target2 = 0;
                    if (target <= kUint64Max - f2off &&
                        SafeRead((const void*)(target + f2off), &target2, 8) && target2 >= 0x10000)
                        target = target2;
                    else followOk = false;
                }
                if (flen > kMaxDump) flen = (uint32_t)kMaxDump;
                if (followOk && target <= kUint64Max - r.followReadOffset &&
                    SafeRead((const void*)(target + r.followReadOffset), r.follow, flen))
                    r.followLen = flen;
            }
        }

        g_slots[idx].traps++;
        g_records.TryPush(r);
    }

    // --------------------------------------------------------------- VEH
    LONG CALLBACK Veh(EXCEPTION_POINTERS* ep)
    {
        if (!ep || !ep->ExceptionRecord || !ep->ContextRecord)
            return EXCEPTION_CONTINUE_SEARCH;

        auto* rec = ep->ExceptionRecord;
        auto* ctx = ep->ContextRecord;

        if (rec->ExceptionCode == EXCEPTION_BREAKPOINT)
        {
            for (int i = 0; i < kMaxProbes; ++i)
            {
                if (!g_slots[i].armed.load(std::memory_order_relaxed)) continue;
                uint8_t* t = TargetOf(g_slots[i].rva.load(std::memory_order_relaxed));
                if (!t || (uintptr_t)rec->ExceptionAddress != (uintptr_t)t) continue;

                Capture(i, ctx);

                WriteByte(t, g_slots[i].orig);
                ctx->Rip = (DWORD64)t;
                ctx->EFlags |= 0x100;      // TF
                t_pending = i;
                return EXCEPTION_CONTINUE_EXECUTION;
            }
            return EXCEPTION_CONTINUE_SEARCH;
        }

        if (rec->ExceptionCode == EXCEPTION_SINGLE_STEP && t_pending >= 0)
        {
            int i = t_pending;
            t_pending = -1;
            ctx->EFlags &= ~0x100;

            if (g_slots[i].armed.load(std::memory_order_relaxed))
            {
                uint8_t* t = TargetOf(g_slots[i].rva.load(std::memory_order_relaxed));
                if (t) WriteByte(t, 0xCC);
            }
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        return EXCEPTION_CONTINUE_SEARCH;
    }

    void EnsureVeh()
    {
        if (!g_veh) g_veh = ::AddVectoredExceptionHandler(1, &Veh);
    }

    DWORD WINAPI Watchdog(LPVOID)
    {
        for (;;)
        {
            ::Sleep(250);
            uint64_t now = ::GetTickCount64();
            for (int i = 0; i < kMaxProbes; ++i)
            {
                if (!g_slots[i].armed.load(std::memory_order_relaxed)) continue;
                if (now >= g_slots[i].deadline.load(std::memory_order_relaxed))
                {
                    uint8_t* t = TargetOf(g_slots[i].rva.load(std::memory_order_relaxed));
                    if (t && WriteByte(t, g_slots[i].orig)) g_slots[i].armed = false;
                }
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

    std::string HexOf(const uint8_t* p, size_t n)
    {
        static const char* kH = "0123456789ABCDEF";
        std::string s;
        s.reserve(n * 2);
        for (size_t i = 0; i < n; ++i)
        {
            s.push_back(kH[p[i] >> 4]);
            s.push_back(kH[p[i] & 0xF]);
        }
        return s;
    }
}

    bool ArmEx(uint64_t rva, uint32_t windowMs, uint32_t dumpBytes, uint32_t followOff, uint32_t followLen);
    bool ArmEx(uint64_t rva, uint32_t windowMs, uint32_t dumpBytes, uint32_t followOff, uint32_t followLen, uint32_t follow2Off);
    bool ArmConfigured(uint64_t rva, uint32_t windowMs, uint32_t dumpBytes,
                       uint32_t followOff, uint32_t followLen, uint32_t follow2Off, uint32_t followReadOffset,
                       uint32_t dumpReg, uint32_t strReg, uint32_t strOff, uint32_t strMax);
    bool Arm(uint64_t rva, uint32_t windowMs, uint32_t dumpBytes)
    {
        return ArmEx(rva, windowMs, dumpBytes, 0, 0);
    }

    bool ArmEx(uint64_t rva, uint32_t windowMs, uint32_t dumpBytes, uint32_t followOff, uint32_t followLen)
    {
        return ArmEx(rva, windowMs, dumpBytes, followOff, followLen, 0xFFFFFFFFu);
    }

    bool ArmEx(uint64_t rva, uint32_t windowMs, uint32_t dumpBytes, uint32_t followOff, uint32_t followLen, uint32_t follow2Off)
    {
        return ArmConfigured(rva, windowMs, dumpBytes, followOff, followLen,
                             follow2Off, 0, 1, 0, 0, 0);
    }

    bool ArmConfigured(uint64_t rva, uint32_t windowMs, uint32_t dumpBytes,
                       uint32_t followOff, uint32_t followLen, uint32_t follow2Off, uint32_t followReadOffset,
                       uint32_t dumpReg, uint32_t strReg, uint32_t strOff, uint32_t strMax)
    {
        if (dumpReg < 1 || dumpReg > 4 || strReg > 6 || followReadOffset > 1048576u) return false;
        if (windowMs == 0) windowMs = 60000;
        if (windowMs > 3600000) windowMs = 3600000;
        if (dumpBytes > kMaxDump) dumpBytes = (uint32_t)kMaxDump;

        StartWatchdogOnce();
        EnsureVeh();

        uint8_t* t = TargetOf(rva);
        if (!t) return false;

        // 已在此 RVA 上布防 → 续期
        for (int i = 0; i < kMaxProbes; ++i)
        {
            if (g_slots[i].armed && g_slots[i].rva.load() == rva)
            {
                g_slots[i].dump = dumpBytes;
                g_slots[i].dumpReg = dumpReg;
                g_slots[i].strReg = strReg;
                g_slots[i].strOff = strOff;
                g_slots[i].strMax = strMax;
                g_slots[i].followOff = followOff;
                g_slots[i].followLen = followLen;
                g_slots[i].follow2Off = follow2Off;
                g_slots[i].followReadOffset = followReadOffset;
                g_slots[i].deadline = ::GetTickCount64() + windowMs;
                return true;
            }
        }

        for (int i = 0; i < kMaxProbes; ++i)
        {
            if (g_slots[i].armed) continue;

            uint8_t orig = 0;
            if (!SafeRead(t, &orig, 1)) return false;
            if (orig == 0xCC) return false;           // 已被别人的断点占着

            g_slots[i].rva = rva;
            g_slots[i].dump = dumpBytes;
            g_slots[i].dumpReg = dumpReg;
            g_slots[i].functionEntry = wxcx::sample::IsFunctionStart(rva);
            g_slots[i].strReg = strReg;
            g_slots[i].strOff = strOff;
            g_slots[i].strMax = strMax;
            g_slots[i].followOff = followOff;
            g_slots[i].followLen = followLen;
            g_slots[i].follow2Off = follow2Off;
            g_slots[i].followReadOffset = followReadOffset;
            g_slots[i].orig = orig;
            g_slots[i].deadline = ::GetTickCount64() + windowMs;

            // Publish ownership before the patched byte can be executed.
            g_slots[i].armed = true;
            if (!WriteByte(t, 0xCC)) { g_slots[i].armed = false; return false; }
            return true;
        }
        return false;   // 槽位用满
    }


    // 布防并在命中时采集"某寄存器 + 偏移"处的字符串（std::string/wstring 布局）
    bool ArmStr(uint64_t rva, uint32_t windowMs, uint32_t dumpBytes,
                uint32_t strReg, uint32_t strOff, uint32_t strMax)
    {
        return ArmConfigured(rva, windowMs, dumpBytes, 0, 0, 0xFFFFFFFFu,
                             0, 1, strReg, strOff, strMax);
    }

    bool Disarm(uint64_t rva)
    {
        for (int i = 0; i < kMaxProbes; ++i)
        {
            if (g_slots[i].armed && g_slots[i].rva.load() == rva)
            {
                uint8_t* t = TargetOf(rva);
                if (!t || !WriteByte(t, g_slots[i].orig)) return false;
                g_slots[i].armed = false;
                return true;
            }
        }
        return false;
    }

    void DisarmAll()
    {
        for (int i = 0; i < kMaxProbes; ++i)
        {
            if (!g_slots[i].armed) continue;
            uint8_t* t = TargetOf(g_slots[i].rva.load());
            if (t && WriteByte(t, g_slots[i].orig)) g_slots[i].armed = false;
        }
    }

    std::string StatusJson()
    {
        json j;
        json arr = json::array();
        for (int i = 0; i < kMaxProbes; ++i)
        {
            json p;
            p["slot"] = i;
            p["rva"] = "0x" + [](uint64_t v) {
                char b[32]; snprintf(b, sizeof(b), "%llX", (unsigned long long)v); return std::string(b);
            }(g_slots[i].rva.load());
            p["armed"] = (bool)g_slots[i].armed;
            p["dump_bytes"] = (uint32_t)g_slots[i].dump.load();
            p["dump_reg"] = (uint32_t)g_slots[i].dumpReg.load();
            p["capture_site"] = g_slots[i].functionEntry.load() ? "function_entry" : "instruction";
            p["traps"] = (long)g_slots[i].traps.load();
            if (g_slots[i].armed)
            {
                uint64_t now = ::GetTickCount64();
                uint64_t dl = g_slots[i].deadline.load();
                p["remaining_ms"] = dl > now ? (dl - now) : 0;
            }
            arr.push_back(p);
        }
        j["probes"] = arr;
        j["schema_version"] = 2;
        j["features"] = {{"follow_read_offset", true}};
        j["probe_build_id"] = "AI-HOOK-20261029-07";
        j["runtime_identity"] = wxcx::RuntimeIdentity();
        j["ring_dropped"] = g_records.Dropped();
        j["reader_skipped"] = g_records.Skipped();
        j["veh"] = (g_veh != nullptr);
        return j.dump();
    }

    static std::string HexValue(uint64_t value)
    {
        char text[32];
        snprintf(text, sizeof(text), "0x%llX", (unsigned long long)value);
        return text;
    }

    static json RecordJson(const Record& r)
    {
        json e;
        e["seq"] = r.sequence;
        e["t"] = r.tick;
        e["rva"] = r.rva;
        e["rva_hex"] = HexValue(r.rva);
        e["a1"] = r.a1; e["a2"] = r.a2; e["a3"] = r.a3; e["a4"] = r.a4;
        e["registers_hex"] = {{"rcx", HexValue(r.a1)}, {"rdx", HexValue(r.a2)},
                              {"r8", HexValue(r.a3)}, {"r9", HexValue(r.a4)}};
        e["register_scope"] = "probe_site";
        e["capture_site"] = r.functionEntry ? "function_entry" : "instruction";
        e["rip_hex"] = HexValue(r.rip); e["rsp_hex"] = HexValue(r.rsp);
        e["object_reg"] = r.objectReg; e["object_hex"] = HexValue(r.object);
        e["dump_len"] = r.dumpLen;
        e["dump_hex"] = HexOf(r.dump, r.dumpLen);
        e["tid"] = r.tid;
        e["ret_valid"] = r.retValid;
        e["ret"] = r.retValid ? json(r.ret) : json(nullptr);
        e["ret_hex"] = r.retValid ? json(HexValue(r.ret)) : json(nullptr);
        e["str_len"] = r.strLen; e["str_cap"] = r.strCap;
        e["str_buf"] = r.strBuf; e["str_got"] = r.strGot;
        e["str_hex"] = HexOf(r.strData, r.strGot);
        e["stack_hex"] = HexOf(r.stack, r.stackLen);
        e["stack_kind"] = "raw_stack_scan_not_unwind";
        e["follow_len"] = r.followLen;
        e["follow_read_offset"] = r.followReadOffset;
        e["follow_hex"] = HexOf(r.follow, r.followLen);
        return e;
    }

    static void BatchJson(json& out, const RecordRing<Record, kRing>::Batch& batch)
    {
        out["schema_version"] = 2;
        out["busy"] = batch.busy;
        out["consuming"] = true;
        out["dropped"] = g_records.Dropped();
        out["skipped"] = batch.skipped;
        out["reader_skipped_total"] = g_records.Skipped();
        out["published"] = batch.published;
        out["note"] = "entry-only return addresses; raw stack scan is not an unwound call stack";
    }

    std::string EventsJson(size_t limit)
    {
        if (limit == 0 || limit > kKeep) limit = 10;
        Record records[kKeep];
        const auto batch = g_records.TryDrain(records, limit);
        json arr = json::array();
        for (size_t i = 0; i < batch.count; ++i)
        {
            json e = RecordJson(records[i]);
            e["rva"] = HexValue(records[i].rva); // preserve the legacy events format
            arr.push_back(e);
        }
        json out;
        BatchJson(out, batch);
        out["events"] = arr;
        return out.dump();
    }


namespace
{
    // 外挂配置文件：与 DLL 同目录的 wxcx_probe.json
    // 结构：
    // {
    //   "presets": {
    //     "名字": [ {"rva": "0x1677F10", "dump": 64}, ... ],
    //     "带跟随": [ {"rva": "0x1677A30", "dump": 32, "follow_off": 8, "follow_len": 64} ],
    //     "带字符串": [ {"rva": "0xA63F45", "dump": 32, "str_reg": 4, "str_off": 384, "str_max": 256} ]
    //   }
    // }
    static std::string ProbeCfgPath()
    {
        char path[MAX_PATH]{};
        HMODULE hm = nullptr;
        if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                (LPCSTR)&ProbeCfgPath, &hm))
            return {};
        DWORD n = GetModuleFileNameA(hm, path, (DWORD)sizeof(path));
        if (!n || n >= sizeof(path)) return {};
        std::string p(path, n);
        size_t pos = p.find_last_of("\\/");
        if (pos != std::string::npos) p.erase(pos + 1);
        return p + "wxcx_probe.json";
    }

    static bool ReadProbeCfg(json& out, std::string& err)
    {
        std::string path = ProbeCfgPath();
        if (path.empty()) { err = "module path unavailable"; return false; }
        std::ifstream f(path.c_str(), std::ios::binary);
        if (!f) { err = "config not found: " + path; return false; }
        std::string text((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        if (text.size() >= 3 && (unsigned char)text[0] == 0xEF &&
            (unsigned char)text[1] == 0xBB && (unsigned char)text[2] == 0xBF)
            text.erase(0, 3);
        try { out = json::parse(text); }
        catch (const std::exception& e) { err = std::string("parse error: ") + e.what(); return false; }
        return true;
    }

    static uint64_t RvaFromJson(const json& v)
    {
        if (v.is_number_unsigned()) return v.get<uint64_t>();
        if (v.is_number_integer())  return (uint64_t)v.get<long long>();
        if (v.is_string())
        {
            std::string t = v.get<std::string>();
            const char* p = t.c_str();
            if (t.rfind("0x", 0) == 0 || t.rfind("0X", 0) == 0) p += 2;
            return std::strtoull(p, nullptr, 16);
        }
        return 0;
    }
}

    void RegisterRoutes(httplib::Server& svr)
    {
        svr.Get("/wxcx/probe/status", [](const httplib::Request&, httplib::Response& res)
        {
            res.set_content(StatusJson(), "application/json");
        });

        // {"rva":"0x2C6C550","ms":60000,"dump":96}
        svr.Post("/wxcx/probe/arm", [](const httplib::Request& req, httplib::Response& res)
        {
            uint64_t rva = 0;
            uint32_t ms = 60000, dump = 96, foff = 0, flen = 0, fread = 0;
            uint32_t sreg = 0, soff = 0, smax = 0, dreg = 1, f2off = 0xFFFFFFFFu;
            if (!req.body.empty())
            {
                try
                {
                    json j = json::parse(req.body);
                    std::string s = j.value("rva", std::string());
                    if (!s.empty()) rva = std::strtoull(s.c_str(), nullptr, 16);
                    if (j.contains("ms") && j["ms"].is_number_integer()) ms = (uint32_t)j["ms"].get<long long>();
                    if (j.contains("dump") && j["dump"].is_number_integer()) dump = (uint32_t)j["dump"].get<long long>();
                    dreg = j.value("dump_reg", 1u);
                    f2off = j.value("follow2_off", 0xFFFFFFFFu);
                    if (j.contains("str_reg") && j["str_reg"].is_number_integer())
                        sreg = (uint32_t)j["str_reg"].get<long long>();
                    if (j.contains("str_off") && j["str_off"].is_number_integer())
                        soff = (uint32_t)j["str_off"].get<long long>();
                    if (j.contains("str_max") && j["str_max"].is_number_integer())
                        smax = (uint32_t)j["str_max"].get<long long>();
                    if (j.contains("follow_off") && j["follow_off"].is_number_integer())
                        foff = (uint32_t)j["follow_off"].get<long long>();
                    if (j.contains("follow_len") && j["follow_len"].is_number_integer())
                        flen = (uint32_t)j["follow_len"].get<long long>();
                    if (j.contains("follow_read_offset") && j["follow_read_offset"].is_number_integer())
                        fread = (uint32_t)j["follow_read_offset"].get<long long>();
                }
                catch (...) {}
            }
            bool ok = (rva != 0) && ArmConfigured(rva, ms, dump, foff, flen, f2off, fread,
                                                 dreg, sreg, soff, smax);
            json out;
            out["ok"] = ok;
            out["rva"] = rva;
            out["follow_read_offset"] = fread;
            if (!ok) out["reason"] = "invalid rva / not mapped / already int3 / slots full";
            res.set_content(out.dump(), "application/json");
        });

        svr.Post("/wxcx/probe/disarm", [](const httplib::Request& req, httplib::Response& res)
        {
            bool ok = true;
            uint64_t requested = 0;
            if (!req.body.empty())
            {
                try
                {
                    json j = json::parse(req.body);
                    std::string s = j.value("rva", std::string());
                    if (!s.empty()) { requested = std::strtoull(s.c_str(), nullptr, 16); ok = Disarm(requested); }
                    else DisarmAll();
                }
                catch (...) { DisarmAll(); }
            }
            else
            {
                DisarmAll();
            }
            json out;
            for (const auto& slot : g_slots)
                if (slot.armed.load() && (!requested || slot.rva.load() == requested)) ok = false;
            out["ok"] = ok;
            res.set_content(out.dump(), "application/json");
        });

        // 预置组合：一次布防多个关键点（避免手工记 RVA）
        //   envelope  : 0x2C6C550  MicroMsgRequestNew 序列化（dump 96 → cmdId/seq 候选）
        //   messages  : envelope + 0x64A950 文本消息工厂（dump 32 → wrapper 头）

        // GET /wxcx/probe/presets → 外挂文件里可用的预置名 + 内置名
        svr.Get("/wxcx/probe/presets", [](const httplib::Request&, httplib::Response& res)
        {
            json out;
            out["builtin"] = json::array({"envelope", "messages", "sendpath", "forwardprobe",
                                          "forwardprobe2", "forwardprobe3", "appmsg49",
                                          "toxml", "parsexml", "body_dump", "toxml2"});
            json fromFile = json::array();
            json cfg; std::string err;
            out["config_path"] = ProbeCfgPath();
            if (ReadProbeCfg(cfg, err) && cfg.contains("presets") && cfg["presets"].is_object())
            {
                for (auto it = cfg["presets"].begin(); it != cfg["presets"].end(); ++it)
                {
                    json e;
                    e["name"] = it.key();
                    e["count"] = it.value().is_array() ? it.value().size() : 0;
                    fromFile.push_back(e);
                }
                out["ok"] = true;
            }
            else
            {
                out["ok"] = false;
                out["msg"] = err;
            }
            out["file"] = fromFile;
            res.set_content(out.dump(), "application/json");
        });

        svr.Post("/wxcx/probe/preset", [](const httplib::Request& req, httplib::Response& res)
        {
            std::string name = "messages";
            uint32_t ms = 120000;
            if (!req.body.empty())
            {
                try
                {
                    json j = json::parse(req.body);
                    name = j.value("name", name);
                    if (j.contains("ms") && j["ms"].is_number_integer())
                        ms = (uint32_t)j["ms"].get<long long>();
                }
                catch (...) {}
            }

            json out;
            out["name"] = name;
            json armed = json::array();

            // ---- 优先使用外挂 wxcx_probe.json（改地址不必重编 DLL）----
            {
                json cfg; std::string err;
                if (ReadProbeCfg(cfg, err) && cfg.contains("presets") &&
                    cfg["presets"].is_object() && cfg["presets"].contains(name) &&
                    cfg["presets"][name].is_array())
                {
                    for (const auto& item : cfg["presets"][name])
                    {
                        json a;
                        uint64_t rva = item.contains("rva") ? RvaFromJson(item["rva"]) : 0;
                        uint32_t dump = item.value("dump", 64u);
                        uint32_t foff = item.value("follow_off", 0u);
                        uint32_t flen = item.value("follow_len", 0u);
                        uint32_t f2   = item.value("follow2_off", 0xFFFFFFFFu);
                        uint32_t fread = item.value("follow_read_offset", 0u);
                        uint32_t sreg = item.value("str_reg", 0u);
                        uint32_t soff = item.value("str_off", 0u);
                        uint32_t smax = item.value("str_max", 0u);
                        uint32_t dreg = item.value("dump_reg", 1u);
                        a["rva"]  = rva;
                        a["dump"] = dump;
                        a["src"]  = "file";
                        bool ok = (rva != 0) && ArmConfigured(rva, ms, dump, foff, flen, f2, fread,
                                                             dreg, sreg, soff, smax);
                        a["ok"] = ok;
                        armed.push_back(a);
                    }
                    out["source"] = "wxcx_probe.json";
                    out["armed"] = armed;
                    res.set_content(out.dump(), "application/json");
                    return;
                }
            }


            auto armOne = [&](uint64_t rva, uint32_t dump, uint32_t foff = 0, uint32_t flen = 0, uint32_t f2 = 0xFFFFFFFFu)
            {
                json a;
                a["rva"] = rva;
                a["dump"] = dump;
                if (foff) { a["follow_off"] = foff; a["follow_len"] = flen; }
                a["ok"] = ArmEx(rva, ms, dump, foff, flen, f2);
                armed.push_back(a);
            };

            // 0x2C6C550(msg, writer)：dump 96 字节 + 跟随 field1 子消息(+0x08) 160 字节
            if (name == "envelope" || name == "messages")
                armOne(0x2C6C550, 96, 0x08, 160);

            if (name == "messages")
                armOne(0x64A950, 32);

            // sendpath：挂已知的底层提交点 send_message(0x1677A30)，
            // 抓它的调用栈 → 任何一次真实发送（文本/图片/文件/卡片）都会暴露上层函数
            // forwardprobe3：提交服务的同族虚表槽位
            //   vtable 0x84EC9C8 = { 0x16778E0, 0x0A820, 0x1677A30, 0x1677F00, 0x1677F10 }
            //   A/B 只命中 0x1677A30；转发可能走同一对象的其它槽位。
            //   同时挂 0x1676B20（A/B 中调用提交包装的函数）。
            if (name == "forwardprobe3")
            {
                armOne(0x16778E0, 64);
                armOne(0x1677F00, 64);
                armOne(0x1677F10, 64);
                armOne(0x1676B20, 64);
            }

            // forwardprobe：转发路径候选（C 组未命中提交层时用这一组）
            //   0x229F220  按类型分派的转换器（调用 0x22A59D0 / 0x22A3200 / 0x22A9D30）
            //   0x22A59D0  媒体对象 → 消息对象转换（case 8 = appmsg）
            //   0x22A92B0  AppMsg 工厂
            //   0x510E940  AppMsg 组装（写 +0xB0/+0xE0/+0x168）
            if (name == "forwardprobe")
            {
                armOne(0x229F220, 64);
                armOne(0x22A59D0, 64);
                armOne(0x22A92B0, 64);
                armOne(0x510E940, 64);
            }

            // forwardprobe2：转发可能直接送到序列化/提交层
            if (name == "forwardprobe2")
            {
                armOne(0xA21550, 64);   // 触发 ToXml 的上层
                armOne(0xA63B40, 64);   // ToXml
                armOne(0x1676DD0, 64);  // 提交包装（A/B 命中过）
                armOne(0xA1FB00, 64);   // 惰性建 XML 模型
            }

            // appmsg49：挂"就地写 type=49"的三个候选，用于找出 4.1.10.27 的 SendXml 等价物
            //   0x510E940  已知的 appmsg 构造（a1=out, a2=字符串, a3=字符串对象）
            //   0x51F7DF0  3 参数小包装（被 0x3576DF0 调用）
            //   0x51FE8D0  无直接调用者（虚表/回调）
            if (name == "appmsg49")
            {
                armOne(0x510E940, 64);
                armOne(0x51F7DF0, 64);
                armOne(0x51FE8D0, 64);
            }

            // toxml2：双断点关联采集
            //   A: 0xA63B40  ToXml 入口 → rcx=模型, rdx=序列化上下文, [rsp]=调用者
            //   B: 0xA63F45  串写入完成 → rsi=上下文, rsi+0x180 是 std::string 输出字段
            if (name == "toxml2")
            {
                armOne(0xA63B40, 32);
                armOne(0xA63F45, 32);
                ArmStr(0xA63F45, 300000, 32, 4 /*rsi*/, 0x180, 256);
            }

            // toxml：挂 AppMsg XML 序列化入口 0xA63B40（ToXml）
            //   命中时 stack 直接给出"谁要求把消息序列化成 XML"，
            //   这是静态扫描最难拿的一环。
            if (name == "toxml")
                armOne(0xA63B40, 64);

            // parsexml：挂 AppMsg XML 解析入口 0xA66280，用于区分收发方向
            if (name == "parsexml")
                armOne(0xA66280, 64);

            // body_dump：挂 send_message，两跳取消息体并 dump
            //   arg1[+8] -> data，data[0] -> body
            if (name == "body_dump")
                armOne(0x1677A30, 256, 0x08, 256, 0x00);

            if (name == "sendpath")
                armOne(0x1677A30, 32);

            out["armed"] = armed;
            out["window_ms"] = ms;
            out["note"] = "sysmsg 观测点用 /wxcx/recv/arm 单独布防（同一个字节不能被两套 INT3 共用）";
            res.set_content(out.dump(), "application/json");
        });
        // 解析后的调用栈：把 stack_hex 里的 qword 直接映射成镜像内 RVA，
        // 避免控制台截断导致看不到关键信息。
        svr.Get("/wxcx/probe/trace", [](const httplib::Request& req, httplib::Response& res)
        {
            size_t limit = 5;
            if (req.has_param("limit"))
            {
                try { limit = (size_t)std::stoul(req.get_param_value("limit")); } catch (...) {}
                if (limit == 0 || limit > 20) limit = 5;
            }

            uint64_t base = 0, size = 0;
            if (g_hWeixinDll)
            {
                MODULEINFO mi{};
                if (::GetModuleInformation(::GetCurrentProcess(), g_hWeixinDll, &mi, sizeof(mi)))
                {
                    base = (uint64_t)mi.lpBaseOfDll;
                    size = (uint64_t)mi.SizeOfImage;
                }
            }

            Record records[kKeep];
            const auto batch = g_records.TryDrain(records, limit);

            json arr = json::array();
            for (size_t i = 0; i < batch.count; ++i)
            {
                const Record& r = records[i];
                json e = RecordJson(r);

                // dump 里的前 8 个 qword（便于人工判断是栈对象还是堆对象）
                json q = json::array();
                for (size_t k = 0; k + 8 <= r.dumpLen && k < 64; k += 8)
                {
                    uint64_t v = 0;
                    memcpy(&v, r.dump + k, 8);
                    json item;
                    item["off"] = k;
                    item["v"] = v;
                    if (base && v >= base && v < base + size) item["rva"] = v - base;
                    q.push_back(item);
                }
                e["dump_qwords"] = q;
                e["tid"] = r.tid;
                {
                    uint64_t rv = 0;
                    if (base && r.ret >= base && r.ret < base + size) rv = r.ret - base;
                    e["ret_rva"] = r.retValid ? json(rv) : json(nullptr);
                }
                e["str_len"] = r.strLen;
                e["str_cap"] = r.strCap;
                e["str_buf"] = r.strBuf;
                e["str_got"] = r.strGot;
                if (r.strGot)
                {
                    std::string ascii;
                    for (size_t k = 0; k < r.strGot && k < 200; ++k)
                        ascii.push_back(r.strData[k] >= 32 && r.strData[k] < 127 ? (char)r.strData[k] : '.');
                    e["str_ascii"] = ascii;
                }
                e["str_hex"] = HexOf(r.strData, r.strGot);

                // Heuristic raw-stack scan, not an unwound call stack.
                json sv = json::array();
                std::vector<uint64_t> seen2;
                uint64_t tlo = 0, thi = 0;
                bool haveText = TextRange(tlo, thi);
                for (size_t k = 0; k + 8 <= r.stackLen; k += 8)
                {
                    uint64_t v = 0;
                    memcpy(&v, r.stack + k, 8);
                    if (!base || v < base || v >= base + size) continue;
                    // 只要落在 .text 的地址（排除 vtable 等数据指针）
                    if (haveText && (v < tlo || v >= thi)) continue;
                    uint64_t rva = v - base;
                    if (rva < 0x1000) continue;
                    bool dup = false;
                    for (auto s : seen2) if (s == rva) { dup = true; break; }
                    if (dup) continue;
                    seen2.push_back(rva);
                    sv.push_back(rva);
                    if (sv.size() >= 16) break;
                }
                e["stack_rvas"] = sv;
                e["stack_scan_rvas"] = sv;
                arr.push_back(e);
            }

            json out;
            BatchJson(out, batch);
            out["image_base"] = base;
            out["image_size"] = size;
            out["count"] = arr.size();
            out["events"] = arr;
            res.set_content(out.dump(2), "application/json");
        });
        svr.Get("/wxcx/probe/events", [](const httplib::Request& req, httplib::Response& res)
        {
            size_t limit = 10;
            if (req.has_param("limit"))
            {
                try { limit = (size_t)std::stoul(req.get_param_value("limit")); } catch (...) {}
            }
            res.set_content(EventsJson(limit), "application/json");
        });
    }

} // namespace probe
} // namespace wxcx
