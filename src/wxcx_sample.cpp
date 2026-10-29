// wxcx_sample.cpp - 执行采样器：找"做了什么动作 → 命中了哪个函数"
#include "wxcx_sample.h"

#include "httplib.h"
#include "json.hpp"

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>

#include <atomic>
#include <cstdio>
#include <cstring>
#include <string>

#include "global.h"

using json = nlohmann::json;

#pragma comment(lib, "psapi.lib")

namespace wxcx
{
namespace sample
{
namespace
{
    constexpr size_t kSlots = 8192;     // 定长哈希表，采样线程内不分配
    constexpr size_t kMaxThreads = 96;

    uint64_t          g_keys[kSlots]   = { 0 };
    uint32_t          g_counts[kSlots] = { 0 };
    std::atomic<size_t> g_used{ 0 };

    std::atomic<bool>     g_running{ false };
    std::atomic<uint32_t> g_interval{ 2 };
    std::atomic<uint64_t> g_deadline{ 0 };
    std::atomic<uint64_t> g_samples{ 0 };
    std::atomic<uint64_t> g_suspendFail{ 0 };
    std::atomic<uint64_t> g_resumeFail{ 0 };
    std::atomic<uint64_t> g_threadsSeen{ 0 };
    std::atomic<uint64_t> g_passes{ 0 };
    std::atomic<uint64_t> g_openFail{ 0 };
    std::atomic<uint64_t> g_contextFail{ 0 };
    std::atomic<uint64_t> g_outside{ 0 };
    std::atomic<uint64_t> g_skipped{ 0 };
    size_t                g_cursor = 0;
    volatile uint64_t     g_base = 0;
    volatile uint64_t     g_size = 0;

    // 采样线程内使用：不分配、不加锁
    void Record(uint64_t rva)
    {
        size_t idx = (size_t)((rva * 0x9E3779B97F4A7C15ULL) >> 20) & (kSlots - 1);
        for (size_t i = 0; i < 8; ++i)
        {
            size_t s = (idx + i) & (kSlots - 1);
            uint64_t k = g_keys[s];
            if (k == rva)
            {
                g_counts[s]++;
                return;
            }
            if (k == 0)
            {
                g_keys[s] = rva;
                g_counts[s] = 1;
                g_used++;
                return;
            }
        }
        // 局部 8 槽都冲突：丢弃（统计里由 samples 与 sum 的差值体现）
    }

    void SampleOnce()
    {
        DWORD self = ::GetCurrentThreadId();

        HANDLE snap = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap == INVALID_HANDLE_VALUE) return;

        THREADENTRY32 te{};
        te.dwSize = sizeof(te);
        if (!::Thread32First(snap, &te))
        {
            ::CloseHandle(snap);
            return;
        }

        // 先收集本进程线程 ID，按游标轮转取样：每趟只碰 kBatch 个线程。
        static DWORD tids[kMaxThreads];
        int total = 0;
        do
        {
            if (te.th32OwnerProcessID != ::GetCurrentProcessId()) continue;
            if (te.th32ThreadID == self) continue;
            if (total < (int)kMaxThreads) tids[total++] = te.th32ThreadID;
        } while (::Thread32Next(snap, &te));
        ::CloseHandle(snap);

        if (total == 0) return;
        g_threadsSeen += (uint64_t)total;

        const int kBatch = 12;
        for (int k = 0; k < kBatch && k < total; ++k)
        {
            DWORD tid = tids[(g_cursor + (size_t)k) % (size_t)total];

            HANDLE h = ::OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
                                    FALSE, tid);
            if (!h) { g_openFail++; continue; }

            // 只采"起始地址在 Weixin.dll 内"的线程：UI/逻辑线程，
            // 平台线程（ntdll/win32u 起）几乎不会给出有意义的样本。
            {
                typedef NTSTATUS(NTAPI* NtQIT_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);
                static NtQIT_t pNtQIT = (NtQIT_t)::GetProcAddress(::GetModuleHandleW(L"ntdll.dll"),
                                                                  "NtQueryInformationThread");
                if (pNtQIT)
                {
                    uint64_t start = 0;
                    if (pNtQIT(h, 9 /*ThreadQuerySetWin32StartAddress*/, &start, sizeof(start), nullptr) == 0 &&
                        start != 0 && (start < g_base || start >= g_base + g_size))
                    {
                        g_skipped++;
                        ::CloseHandle(h);
                        continue;
                    }
                }
            }

            if (::SuspendThread(h) == (DWORD)-1)
            {
                g_suspendFail++;
                ::CloseHandle(h);
                continue;
            }

            CONTEXT ctx{};
            ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
            if (::GetThreadContext(h, &ctx))
            {
                uint64_t rip = (uint64_t)ctx.Rip;
                if (rip >= g_base && rip < g_base + g_size)
                {
                    Record(rip - g_base);
                    g_samples++;
                }
                else
                {
                    g_outside++;
                }
            }
            else
            {
                g_contextFail++;
            }

            if (::ResumeThread(h) == (DWORD)-1) g_resumeFail++;
            ::CloseHandle(h);
        }

        g_cursor = (g_cursor + (size_t)kBatch) % (size_t)total;
        g_passes++;
    }

    DWORD WINAPI Worker(LPVOID)
    {
        while (g_running)
        {
            if (g_deadline && ::GetTickCount64() >= g_deadline)
            {
                g_running = false;
                break;
            }
            SampleOnce();
            ::Sleep(g_interval.load());
        }
        return 0;
    }
}

    bool Start(uint32_t intervalMs, uint32_t maxSeconds)
    {
        if (g_running) return true;
        if (!g_hWeixinDll) return false;

        MODULEINFO mi{};
        if (!::GetModuleInformation(::GetCurrentProcess(), g_hWeixinDll, &mi, sizeof(mi)))
            return false;

        g_base = (uint64_t)mi.lpBaseOfDll;
        g_size = (uint64_t)mi.SizeOfImage;

        if (intervalMs < 1) intervalMs = 1;
        if (intervalMs > 50) intervalMs = 50;
        if (maxSeconds < 1) maxSeconds = 1;
        if (maxSeconds > 120) maxSeconds = 120;

        g_interval = intervalMs;
        g_deadline = ::GetTickCount64() + (uint64_t)maxSeconds * 1000;
        g_samples = 0;
        g_suspendFail = 0;
        g_resumeFail = 0;
        g_threadsSeen = 0;
        g_passes = 0;
        g_openFail = 0;
        g_contextFail = 0;
        g_outside = 0;
        g_skipped = 0;
        g_cursor = 0;

        // 清表（在启动时清，不在采样中清）
        memset(g_keys, 0, sizeof(g_keys));
        memset(g_counts, 0, sizeof(g_counts));
        g_used = 0;

        g_running = true;
        HANDLE h = ::CreateThread(nullptr, 0, &Worker, nullptr, 0, nullptr);
        if (!h)
        {
            g_running = false;
            return false;
        }
        ::SetThreadPriority(h, THREAD_PRIORITY_ABOVE_NORMAL);
        ::CloseHandle(h);
        return true;
    }

    void Stop() { g_running = false; }

    json Status()
    {
        json j;
        j["running"] = (bool)g_running;
        j["interval_ms"] = (uint32_t)g_interval;
        j["samples"] = (uint64_t)g_samples;
        j["distinct_rvas"] = (size_t)g_used;
        j["threads_seen"] = (uint64_t)g_threadsSeen;
        j["passes"]         = (uint64_t)g_passes;
        j["open_fail"]      = (uint64_t)g_openFail;
        j["context_fail"]   = (uint64_t)g_contextFail;
        j["outside_module"] = (uint64_t)g_outside;
        j["skipped_foreign_threads"] = (uint64_t)g_skipped;
        j["suspend_fail"] = (uint64_t)g_suspendFail;
        j["resume_fail"] = (uint64_t)g_resumeFail;
        if (g_running && g_deadline)
        {
            uint64_t now = ::GetTickCount64();
            j["remaining_ms"] = g_deadline > now ? (g_deadline - now) : 0;
        }
        return j;
    }

    json Dump(size_t topN)
    {
        if (topN == 0 || topN > 500) topN = 100;

        struct Row { uint64_t rva; uint32_t n; };
        static Row rows[kSlots];       // HTTP 线程调用，非采样线程，可接受静态缓冲
        size_t m = 0;
        for (size_t i = 0; i < kSlots && m < kSlots; ++i)
        {
            if (!g_counts[i]) continue;
            rows[m].rva = g_keys[i];
            rows[m].n = g_counts[i];
            m++;
        }
        // 部分排序：简单选择前 topN
        for (size_t i = 0; i < m && i < topN; ++i)
        {
            size_t best = i;
            for (size_t k = i + 1; k < m; ++k)
                if (rows[k].n > rows[best].n) best = k;
            if (best != i) { Row t = rows[i]; rows[i] = rows[best]; rows[best] = t; }
        }

        json arr = json::array();
        char buf[32];
        for (size_t i = 0; i < m && i < topN; ++i)
        {
            snprintf(buf, sizeof(buf), "0x%llX", (unsigned long long)rows[i].rva);
            json e;
            e["rva"] = buf;
            e["hits"] = rows[i].n;
            arr.push_back(e);
        }

        json out;
        out["total_samples"] = (uint64_t)g_samples;
        out["distinct"] = m;
        out["top"] = arr;
        return out;
    }


    // ---------------- .pdata 函数表（从自身镜像解析，不读文件） ----------------
    struct FuncRange { uint32_t begin; uint32_t end; };
    FuncRange* g_funcs = nullptr;
    size_t     g_funcCount = 0;

    void BuildFuncTable()
    {
        if (g_funcs || !g_hWeixinDll) return;
        uint8_t* base = (uint8_t*)g_hWeixinDll;
        auto* dos = (IMAGE_DOS_HEADER*)base;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
        auto* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return;

        auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if (!dir.VirtualAddress || !dir.Size) return;

        auto* pdata = (IMAGE_RUNTIME_FUNCTION_ENTRY*)(base + dir.VirtualAddress);
        size_t n = dir.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);
        if (!n || n > 2000000) return;

        auto* arr = (FuncRange*)::VirtualAlloc(nullptr, n * sizeof(FuncRange),
                                               MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!arr) return;

        size_t m = 0;
        for (size_t i = 0; i < n; ++i)
        {
            uint32_t b = pdata[i].BeginAddress, e = pdata[i].EndAddress;
            if (b && e > b) { arr[m].begin = b; arr[m].end = e; m++; }
        }
        g_funcs = arr;
        g_funcCount = m;
    }

    // 线性扫描代价太高，采样结果数量小，用"区间包含"直接找（二分需排序，这里原地排序一次）
    static int CompareFunc(const void* a, const void* b)
    {
        uint32_t x = ((const FuncRange*)a)->begin, y = ((const FuncRange*)b)->begin;
        return (x < y) ? -1 : (x > y ? 1 : 0);
    }

    void EnsureSorted()
    {
        static bool sorted = false;
        if (sorted || !g_funcs) return;
        qsort(g_funcs, g_funcCount, sizeof(FuncRange), &CompareFunc);
        sorted = true;
    }

    bool FindFunc(uint64_t rva, FuncRange& out)
    {
        if (!g_funcs) return false;
        EnsureSorted();
        size_t lo = 0, hi = g_funcCount;
        while (lo < hi)
        {
            size_t mid = (lo + hi) / 2;
            if (g_funcs[mid].begin <= rva) lo = mid + 1;
            else hi = mid;
        }
        if (lo == 0) return false;
        size_t i = lo - 1;
        if (rva >= g_funcs[i].begin && rva < g_funcs[i].end) { out = g_funcs[i]; return true; }
        return false;
    }

    nlohmann::json DumpByFunc(size_t topN)
    {
        if (topN == 0 || topN > 200) topN = 40;
        BuildFuncTable();

        struct Row { uint32_t func; uint32_t size; uint32_t hits; };
        const size_t kMax = 2048;
        static Row rows[kMax];
        size_t m = 0;

        size_t unmapped = 0;
        for (size_t i = 0; i < kSlots; ++i)
        {
            if (!g_counts[i]) continue;
            FuncRange fr{};
            if (!FindFunc(g_keys[i], fr)) { unmapped += g_counts[i]; continue; }

            size_t k = 0;
            for (; k < m; ++k) if (rows[k].func == fr.begin) break;
            if (k == m)
            {
                if (m >= kMax) continue;
                rows[m].func = fr.begin;
                rows[m].size = fr.end - fr.begin;
                rows[m].hits = 0;
                m++;
            }
            rows[k].hits += g_counts[i];
        }

        for (size_t i = 0; i < m && i < topN; ++i)
        {
            size_t best = i;
            for (size_t k = i + 1; k < m; ++k) if (rows[k].hits > rows[best].hits) best = k;
            if (best != i) { Row t = rows[i]; rows[i] = rows[best]; rows[best] = t; }
        }

        json arr = json::array();
        char buf[32];
        for (size_t i = 0; i < m && i < topN; ++i)
        {
            snprintf(buf, sizeof(buf), "0x%llX", (unsigned long long)rows[i].func);
            json e;
            e["func"] = buf;
            e["size"] = rows[i].size;
            e["hits"] = rows[i].hits;
            arr.push_back(e);
        }

        json out;
        out["mode"] = "by_func";
        out["total_samples"] = (uint64_t)g_samples;
        out["distinct_funcs"] = m;
        out["unmapped_hits"] = unmapped;
        out["func_table"] = g_funcCount;
        out["top"] = arr;
        return out;
    }


    bool IsFunctionStart(uint64_t rva)
    {
        BuildFuncTable();
        FuncRange fr{};
        if (!FindFunc(rva, fr)) return false;
        return fr.begin == (uint32_t)rva;
    }


    bool Describe(uint64_t rva, uint64_t& start, uint64_t& end, bool& is_entry)
    {
        BuildFuncTable();
        FuncRange fr{};
        if (!FindFunc(rva, fr)) return false;
        start = fr.begin;
        end = fr.end;
        is_entry = (fr.begin == (uint32_t)rva);
        return true;
    }

    void RegisterRoutes(httplib::Server& svr)
    {
        // {"interval_ms":2,"seconds":20}
        svr.Post("/wxcx/sample/start", [](const httplib::Request& req, httplib::Response& res)
        {
            uint32_t iv = 2, sec = 20;
            try
            {
                if (!req.body.empty())
                {
                    json j = json::parse(req.body);
                    if (j.contains("interval_ms") && j["interval_ms"].is_number_integer())
                        iv = (uint32_t)j["interval_ms"].get<long long>();
                    if (j.contains("seconds") && j["seconds"].is_number_integer())
                        sec = (uint32_t)j["seconds"].get<long long>();
                }
            }
            catch (...) {}

            bool ok = Start(iv, sec);
            json out;
            out["ok"] = ok;
            out["interval_ms"] = iv;
            out["seconds"] = sec;
            if (!ok) out["msg"] = "weixin module not loaded or already running";
            res.set_content(out.dump(), "application/json");
        });

        svr.Post("/wxcx/sample/stop", [](const httplib::Request&, httplib::Response& res)
        {
            Stop();
            json out;
            out["ok"] = true;
            out["samples"] = (uint64_t)g_samples;
            res.set_content(out.dump(), "application/json");
        });


        // GET /wxcx/sym/where?rva=0xA63B40  → 所属函数区间
        svr.Get("/wxcx/sym/where", [](const httplib::Request& req, httplib::Response& res)
        {
            uint64_t rva = 0;
            if (req.has_param("rva"))
            {
                std::string v = req.get_param_value("rva");
                const char* p = v.c_str();
                if (v.rfind("0x", 0) == 0 || v.rfind("0X", 0) == 0) p += 2;
                rva = std::strtoull(p, nullptr, 16);
            }

            json out;
            out["rva"] = rva;
            uint64_t st = 0, en = 0;
            bool entry = false;
            if (rva && Describe(rva, st, en, entry))
            {
                out["ok"] = true;
                out["func_start"] = st;
                out["func_end"] = en;
                out["is_entry"] = entry;
            }
            else
            {
                out["ok"] = false;
                out["msg"] = "rva not in any .pdata function";
            }
            res.set_content(out.dump(), "application/json");
        });

        svr.Get("/wxcx/sample/status", [](const httplib::Request&, httplib::Response& res)
        {
            res.set_content(Status().dump(), "application/json");
        });

        svr.Get("/wxcx/sample/dump", [](const httplib::Request& req, httplib::Response& res)
        {
            size_t n = 100;
            if (req.has_param("top"))
            {
                try { n = (size_t)std::stoul(req.get_param_value("top")); } catch (...) {}
            }
            if (req.has_param("by") && req.get_param_value("by") == "func")
                res.set_content(DumpByFunc(n).dump(2), "application/json");
            else
                res.set_content(Dump(n).dump(2), "application/json");
        });
    }

}
}
