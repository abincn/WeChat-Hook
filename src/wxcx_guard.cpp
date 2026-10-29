// wxcx_guard.cpp - anti-detection layer for the WeChat 4.1.10.27 hook
//
// Threat model (observed):
//   * wcprobe.dll ships with 4.1.10.27: VMProtect-packed, 9 ordinal-only exports,
//     sections .detourc/.detourd/.vmp0/.vmp1  -> cannot be hooked by name.
//   * a probe of that kind gathers evidence by asking the OS questions:
//       NtQueryInformationProcess(DebugPort / DebugObjectHandle / DebugFlags)
//       NtQuerySystemInformation(SystemKernelDebuggerInformation)
//       CheckRemoteDebuggerPresent / IsDebuggerPresent
//       EnumProcessModules* / Toolhelp Module32*      (unknown modules)
//       RWX pages / patched prologues                  (inline hooks)
//   * it can also read strings we leak through OutputDebugString.
//
// Strategy: answer those questions the way a clean process would, hide our own
// module from enumeration, stop leaking strings, and keep our allocations RX.

#include "wxcx_guard.h"

#include "httplib.h"
#include "json.hpp"

#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <psapi.h>

#include <atomic>
#include <string>

#include "global.h"
#include "HookManager.h"

#pragma comment(lib, "psapi.lib")

using json = nlohmann::json;

namespace wxcx
{
namespace guard
{
namespace
{
    std::atomic<bool> g_installed{ false };
    std::atomic<long> g_hitsDebugQuery{ 0 };
    std::atomic<long> g_hitsEnumModules{ 0 };
    std::atomic<long> g_hitsToolhelp{ 0 };
    std::atomic<long> g_hitsOutputDebug{ 0 };
    std::atomic<long> g_hitsKernelEnum{ 0 };
    std::atomic<long> g_hitsProbeRead{ 0 };
    std::atomic<long> g_hitsQueryVmem{ 0 };
    std::atomic<long> g_hitsDllNotifyReg{ 0 };
    std::atomic<long> g_hitsDllNotifySwallowed{ 0 };

    void (*g_probeReadHandler)() = nullptr;

    int  g_installedCount = 0;
    bool g_debuggerLiesOk = false;
    bool g_enumMaskOk = false;

    // ------------------------------------------------------------------ 工具
    typedef NTSTATUS(NTAPI* fnNtQueryInformationProcess)(
        HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
    typedef NTSTATUS(NTAPI* fnNtQuerySystemInformation)(
        SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
    typedef NTSTATUS(NTAPI* fnNtSetInformationThread)(
        HANDLE, THREADINFOCLASS, PVOID, ULONG);

    fnNtQueryInformationProcess g_origQIP = nullptr;
    fnNtQuerySystemInformation g_origQSI = nullptr;
    fnNtSetInformationThread   g_origSIT = nullptr;

    typedef BOOL(WINAPI* fnCheckRemoteDebuggerPresent)(HANDLE, PBOOL);
    typedef BOOL(WINAPI* fnIsDebuggerPresent)();
    typedef BOOL(WINAPI* fnEnumProcessModules)(HANDLE, HMODULE*, DWORD, LPDWORD);
    typedef BOOL(WINAPI* fnEnumProcessModulesEx)(HANDLE, HMODULE*, DWORD, LPDWORD, DWORD);
    typedef BOOL(WINAPI* fnModule32FirstW)(HANDLE, LPMODULEENTRY32W);
    typedef BOOL(WINAPI* fnModule32NextW)(HANDLE, LPMODULEENTRY32W);
    typedef BOOL(WINAPI* fnModule32First)(HANDLE, LPMODULEENTRY32);
    typedef BOOL(WINAPI* fnModule32Next)(HANDLE, LPMODULEENTRY32);
    typedef void(WINAPI* fnOutputDebugStringA)(LPCSTR);
    typedef void(WINAPI* fnOutputDebugStringW)(LPCWSTR);

    fnCheckRemoteDebuggerPresent g_origCRDP = nullptr;
    fnIsDebuggerPresent          g_origIDP = nullptr;
    fnEnumProcessModules         g_origEPM = nullptr;
    fnEnumProcessModulesEx       g_origEPMEx = nullptr;
    fnModule32FirstW             g_origM32FW = nullptr;
    fnModule32NextW              g_origM32NW = nullptr;
    fnModule32First              g_origM32FA = nullptr;
    fnModule32Next               g_origM32NA = nullptr;
    fnOutputDebugStringA         g_origODSA = nullptr;
    fnOutputDebugStringW         g_origODSW = nullptr;

    constexpr ULONG kProcessDebugPort = 7;
    constexpr ULONG kProcessDebugObjectHandle = 0x1E;
    constexpr ULONG kProcessDebugFlags = 0x1F;
    constexpr ULONG kSystemKernelDebuggerInformation = 35;
    constexpr NTSTATUS kStatusPortNotSet = (NTSTATUS)0xC0000353L;
    constexpr NTSTATUS kStatusInvalidInfoClass = (NTSTATUS)0xC0000003L;

    // ------------------------------------------------------------ NtQuery 层
    NTSTATUS NTAPI DetourNtQueryInformationProcess(
        HANDLE process, PROCESSINFOCLASS cls, PVOID info, ULONG len, PULONG ret)
    {
        switch ((ULONG)cls)
        {
        case kProcessDebugPort:
            g_hitsDebugQuery++;
            if (info && len >= sizeof(ULONG_PTR))
            {
                *(ULONG_PTR*)info = 0;           // no debug port
                if (ret) *ret = sizeof(ULONG_PTR);
                return 0;
            }
            break;

        case kProcessDebugObjectHandle:
            g_hitsDebugQuery++;
            if (info && len >= sizeof(HANDLE))
            {
                *(HANDLE*)info = nullptr;
                if (ret) *ret = sizeof(HANDLE);
                return kStatusPortNotSet;        // "no debug object"
            }
            break;

        case kProcessDebugFlags:
            g_hitsDebugQuery++;
            if (info && len >= sizeof(ULONG))
            {
                *(ULONG*)info = 1;               // 1 = not being debugged
                if (ret) *ret = sizeof(ULONG);
                return 0;
            }
            break;

        default:
            break;
        }

        if (!g_origQIP) return kStatusInvalidInfoClass;
        return g_origQIP(process, cls, info, len, ret);
    }

    // ---- kernel module list (SystemModuleInformation / Ex) ----
    struct ModInfo
    {
        PVOID  Section;
        PVOID  MappedBase;
        PVOID  ImageBase;
        ULONG  ImageSize;
        ULONG  Flags;
        USHORT LoadOrderIndex;
        USHORT InitOrderIndex;
        USHORT LoadCount;
        USHORT OffsetToFileName;
        UCHAR  FullPathName[256];
    };
    struct ModList
    {
        ULONG   Count;
        ModInfo Mods[1];
    };

    void MaskOwnModuleInKernelList(PVOID info, PULONG ret)
    {
        ModList* l = (ModList*)info;
        if (!l || l->Count == 0 || l->Count > 0x4000) return;

        uintptr_t self = (uintptr_t)g_hModule;
        ULONG w = 0;
        for (ULONG i = 0; i < l->Count; ++i)
        {
            if ((uintptr_t)l->Mods[i].ImageBase == self)
            {
                g_hitsKernelEnum++;
                continue;
            }
            if (w != i) l->Mods[w] = l->Mods[i];
            ++w;
        }
        if (w != l->Count)
        {
            l->Count = w;
            if (ret) *ret = (ULONG)(sizeof(ULONG) + (size_t)w * sizeof(ModInfo));
        }
    }

    NTSTATUS NTAPI DetourNtQuerySystemInformation(
        SYSTEM_INFORMATION_CLASS cls, PVOID info, ULONG len, PULONG ret)
    {
        if ((ULONG)cls == kSystemKernelDebuggerInformation &&
            info && len >= 2)
        {
            g_hitsDebugQuery++;
            ((UCHAR*)info)[0] = 0;   // DebuggerEnabled = FALSE
            ((UCHAR*)info)[1] = 1;   // DebuggerNotPresent = TRUE
            if (ret) *ret = 2;
            return 0;
        }

        // SystemModuleInformation(11) / Ex(73) 只描述【内核模块/驱动】，
        // 注入的用户态 DLL 根本不在这个列表里，所以这里只统计"有人在枚举"，
        // 不做过滤（早期版本尝试过滤是错的，已撤销）。
        if (((ULONG)cls == 11 || (ULONG)cls == 73) && info && g_origQSI)
        {
            g_hitsKernelEnum++;
            return g_origQSI(cls, info, len, ret);
        }

        if (!g_origQSI) return kStatusInvalidInfoClass;
        return g_origQSI(cls, info, len, ret);
    }

    // ---------------------------------------------------------- 调试检测 API
    BOOL WINAPI DetourCheckRemoteDebuggerPresent(HANDLE, PBOOL present)
    {
        g_hitsDebugQuery++;
        if (present) *present = FALSE;
        return TRUE;
    }

    BOOL WINAPI DetourIsDebuggerPresent()
    {
        g_hitsDebugQuery++;
        return FALSE;
    }

    // ------------------------------------------------- 读内存：检测扫描行为
    typedef NTSTATUS(NTAPI* fnNtReadVirtualMemory)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
    typedef NTSTATUS(NTAPI* fnNtQueryVirtualMemory)(HANDLE, PVOID, ULONG, PVOID, SIZE_T, PSIZE_T);
    fnNtReadVirtualMemory g_origRVM = nullptr;
    fnNtQueryVirtualMemory g_origQVM = nullptr;

    // 被我们自己改过的那几条指令（sysmsg handler prologue）
    constexpr uint64_t kPatchedRva = 0x22D07C0;
    constexpr size_t   kPatchedLen = 9;

    bool OverlapsPatchedPrologue(uintptr_t base, size_t size)
    {
        if (!g_hWeixinDll) return false;
        uintptr_t lo = (uintptr_t)g_hWeixinDll + kPatchedRva;
        uintptr_t hi = lo + kPatchedLen;
        if (size == 0) size = 1;
        return base < hi && (base + size) > lo;
    }

    NTSTATUS NTAPI DetourNtReadVirtualMemory(
        HANDLE proc, PVOID addr, PVOID buf, SIZE_T size, PSIZE_T readOut)
    {
        if ((proc == ::GetCurrentProcess() || proc == (HANDLE)-1) &&
            OverlapsPatchedPrologue((uintptr_t)addr, (size_t)size))
        {
            g_hitsProbeRead++;
            // 立刻撤防：让这次读取看到出厂字节，而不是我们的 E9
            if (g_probeReadHandler) g_probeReadHandler();
        }
        if (!g_origRVM) return (NTSTATUS)0xC0000003L;
        return g_origRVM(proc, addr, buf, size, readOut);
    }

    NTSTATUS NTAPI DetourNtQueryVirtualMemory(
        HANDLE proc, PVOID addr, ULONG cls, PVOID info, SIZE_T len, PSIZE_T retOut)
    {
        if ((proc == ::GetCurrentProcess() || proc == (HANDLE)-1) &&
            OverlapsPatchedPrologue((uintptr_t)addr, 1))
        {
            g_hitsQueryVmem++;
        }
        if (!g_origQVM) return (NTSTATUS)0xC0000003L;
        return g_origQVM(proc, addr, cls, info, len, retOut);
    }

    // ------------------------------------------- DLL 加载通知（wcprobe 入口）
    // wcprobe 通过 LdrRegisterDllNotification 拿模块加载/卸载事件。
    // 我们的 version.dll 在加载瞬间已经被通知过了，无法追溯；但可以把
    // 之后所有注册方的回调包一层，让"本模块"的事件不再投递给它们。
    typedef NTSTATUS(NTAPI* fnLdrRegisterDllNotification)(ULONG, PVOID, PVOID, PVOID*);
    fnLdrRegisterDllNotification g_origLdrReg = nullptr;

    struct NotifyWrap
    {
        PVOID fn;
        PVOID ctx;
    };

    VOID CALLBACK OurDllNotify(ULONG reason, PVOID data, PVOID context)
    {
        NotifyWrap* w = (NotifyWrap*)context;
        PVOID dllBase = nullptr;
        __try
        {
            // LDR_DLL_NOTIFICATION_DATA: Flags(0x00) Full(0x08) Base(0x10) DllBase(0x18)
            dllBase = *(PVOID*)((uint8_t*)data + 0x18);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            dllBase = nullptr;
        }

        if (dllBase == (PVOID)g_hModule)
        {
            g_hitsDllNotifySwallowed++;     // 吞掉：不投递自身模块事件
            return;
        }

        if (w && w->fn)
        {
            ((VOID(CALLBACK*)(ULONG, PVOID, PVOID))w->fn)(reason, data, w->ctx);
        }
    }

    NTSTATUS NTAPI DetourLdrRegisterDllNotification(
        ULONG flags, PVOID fn, PVOID context, PVOID* cookie)
    {
        if (!g_origLdrReg) return (NTSTATUS)0xC0000003L;

        NotifyWrap* w = (NotifyWrap*)::HeapAlloc(
            ::GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(NotifyWrap));
        if (!w) return (NTSTATUS)0xC0000017L;      // STATUS_NO_MEMORY

        w->fn = fn;
        w->ctx = context;
        g_hitsDllNotifyReg++;

        // 注册的是我们的包装函数，原始回调存在 w 里
        return g_origLdrReg(flags, (PVOID)&OurDllNotify, w, cookie);
    }

    // -------------------------------------------------------------- 模块枚举
    // 只在调用方实际提供的缓冲区内操作：*needed 可能大于 cb
    static void MaskOwnModule(HMODULE* mods, DWORD cb, DWORD* needed, HMODULE self)
    {
        if (!mods || !needed || !self) return;

        DWORD usable = *needed < cb ? *needed : cb;      // 关键：取两者较小值
        DWORD count = usable / sizeof(HMODULE);
        DWORD out = 0;
        for (DWORD i = 0; i < count; ++i)
        {
            if (mods[i] == self) continue;
            mods[out++] = mods[i];
        }
        *needed = out * sizeof(HMODULE);
    }

    BOOL WINAPI DetourEnumProcessModules(HANDLE proc, HMODULE* mods, DWORD cb, LPDWORD needed)
    {
        g_hitsEnumModules++;
        if (!g_origEPM) return FALSE;
        BOOL ok = g_origEPM(proc, mods, cb, needed);
        if (ok && proc == ::GetCurrentProcess()) MaskOwnModule(mods, cb, needed, (HMODULE)g_hModule);
        return ok;
    }

    BOOL WINAPI DetourEnumProcessModulesEx(HANDLE proc, HMODULE* mods, DWORD cb, LPDWORD needed, DWORD filter)
    {
        g_hitsEnumModules++;
        if (!g_origEPMEx) return FALSE;
        BOOL ok = g_origEPMEx(proc, mods, cb, needed, filter);
        if (ok && proc == ::GetCurrentProcess()) MaskOwnModule(mods, cb, needed, (HMODULE)g_hModule);
        return ok;
    }

    // First 只在首次调用推进枚举，之后必须用 Next 前进，否则会反复拿到同一条
    BOOL WINAPI DetourModule32FirstW(HANDLE snap, LPMODULEENTRY32W me)
    {
        g_hitsToolhelp++;
        if (!g_origM32FW) return FALSE;
        if (!g_origM32FW(snap, me)) return FALSE;
        if (me->hModule != (HMODULE)g_hModule) return TRUE;
        while (g_origM32NW && g_origM32NW(snap, me))
        {
            if (me->hModule != (HMODULE)g_hModule) return TRUE;
        }
        return FALSE;
    }

    BOOL WINAPI DetourModule32NextW(HANDLE snap, LPMODULEENTRY32W me)
    {
        g_hitsToolhelp++;
        if (!g_origM32NW) return FALSE;
        while (g_origM32NW(snap, me))
        {
            if (me->hModule != (HMODULE)g_hModule) return TRUE;
        }
        return FALSE;
    }

    BOOL WINAPI DetourModule32First(HANDLE snap, LPMODULEENTRY32 me)
    {
        g_hitsToolhelp++;
        if (!g_origM32FA) return FALSE;
        if (!g_origM32FA(snap, me)) return FALSE;
        if (me->hModule != (HMODULE)g_hModule) return TRUE;
        while (g_origM32NA && g_origM32NA(snap, me))
        {
            if (me->hModule != (HMODULE)g_hModule) return TRUE;
        }
        return FALSE;
    }

    BOOL WINAPI DetourModule32Next(HANDLE snap, LPMODULEENTRY32 me)
    {
        g_hitsToolhelp++;
        if (!g_origM32NA) return FALSE;
        while (g_origM32NA(snap, me))
        {
            if (me->hModule != (HMODULE)g_hModule) return TRUE;
        }
        return FALSE;
    }

    // -------------------------------------------------------- 不再泄漏字符串
    void WINAPI DetourOutputDebugStringA(LPCSTR) { g_hitsOutputDebug++; }
    void WINAPI DetourOutputDebugStringW(LPCWSTR) { g_hitsOutputDebug++; }

    // ------------------------------------------------------------------ 安装
    bool Hook(const wchar_t* mod, const char* fn, LPVOID detour, LPVOID* orig)
    {
        if (!Hook_SysApi(mod, fn, detour, orig)) return false;
        g_installedCount++;
        return true;
    }
}

    void HideCurrentThreadFromDebugger()
    {
        if (!g_origSIT)
        {
            HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");
            if (!ntdll) return;
            g_origSIT = (fnNtSetInformationThread)::GetProcAddress(ntdll, "NtSetInformationThread");
            if (!g_origSIT) return;
        }
        // ThreadHideFromDebugger = 0x11
        g_origSIT(::GetCurrentThread(), (THREADINFOCLASS)0x11, nullptr, 0);
    }

    void HardenTrampoline(void* mem, size_t size)
    {
        if (!mem || !size) return;
        DWORD old = 0;
        ::VirtualProtect(mem, size, PAGE_EXECUTE_READ, &old);
    }

    int Install()
    {
        if (g_installed) return g_installedCount;
        g_installedCount = 0;

        // --- 调试查询说假话 ---
        bool a = Hook(L"ntdll.dll", "NtQueryInformationProcess",
                      (LPVOID)&DetourNtQueryInformationProcess, (LPVOID*)&g_origQIP);
        bool b = Hook(L"ntdll.dll", "NtQuerySystemInformation",
                      (LPVOID)&DetourNtQuerySystemInformation, (LPVOID*)&g_origQSI);
        bool c = Hook(L"kernel32.dll", "CheckRemoteDebuggerPresent",
                      (LPVOID)&DetourCheckRemoteDebuggerPresent, (LPVOID*)&g_origCRDP);
        bool d = Hook(L"kernel32.dll", "IsDebuggerPresent",
                      (LPVOID)&DetourIsDebuggerPresent, (LPVOID*)&g_origIDP);
        g_debuggerLiesOk = (a && b && c && d);

        // --- 模块枚举遮蔽 ---
        bool e = Hook(L"psapi.dll", "EnumProcessModules",
                      (LPVOID)&DetourEnumProcessModules, (LPVOID*)&g_origEPM);
        bool f = Hook(L"psapi.dll", "EnumProcessModulesEx",
                      (LPVOID)&DetourEnumProcessModulesEx, (LPVOID*)&g_origEPMEx);
        bool g = Hook(L"kernel32.dll", "Module32FirstW",
                      (LPVOID)&DetourModule32FirstW, (LPVOID*)&g_origM32FW);
        bool h = Hook(L"kernel32.dll", "Module32NextW",
                      (LPVOID)&DetourModule32NextW, (LPVOID*)&g_origM32NW);
        bool i = Hook(L"kernel32.dll", "Module32First",
                      (LPVOID)&DetourModule32First, (LPVOID*)&g_origM32FA);
        bool j = Hook(L"kernel32.dll", "Module32Next",
                      (LPVOID)&DetourModule32Next, (LPVOID*)&g_origM32NA);
        g_enumMaskOk = (e && f) && (g || h) && (i || j);

        // --- DLL 加载通知：拦截 wcprobe 的取证入口 ---
        Hook(L"ntdll.dll", "LdrRegisterDllNotification",
             (LPVOID)&DetourLdrRegisterDllNotification, (LPVOID*)&g_origLdrReg);

        // --- 扫描感知：谁在读被改过的字节 ---
        Hook(L"ntdll.dll", "NtReadVirtualMemory",
             (LPVOID)&DetourNtReadVirtualMemory, (LPVOID*)&g_origRVM);
        Hook(L"ntdll.dll", "NtQueryVirtualMemory",
             (LPVOID)&DetourNtQueryVirtualMemory, (LPVOID*)&g_origQVM);

        // --- 静音 OutputDebugString ---
        Hook(L"kernel32.dll", "OutputDebugStringA",
             (LPVOID)&DetourOutputDebugStringA, (LPVOID*)&g_origODSA);
        Hook(L"kernel32.dll", "OutputDebugStringW",
             (LPVOID)&DetourOutputDebugStringW, (LPVOID*)&g_origODSW);

        g_installed = true;
        return g_installedCount;
    }

    bool Installed() { return g_installed; }

    void InstallAsync()
    {
        // 从 DllMain 里直接装 hook 不安全（loader lock），延后到独立线程
        // 排障开关：DLL 同目录存在 wxcx_guard.off 时跳过安装
        {
            wchar_t path[MAX_PATH] = { 0 };
            if (::GetModuleFileNameW((HMODULE)g_hModule, path, MAX_PATH))
            {
                std::wstring w(path);
                size_t cut = w.find_last_of(L"\\/");
                if (cut != std::wstring::npos)
                {
                    w = w.substr(0, cut + 1) + L"wxcx_guard.off";
                    if (::GetFileAttributesW(w.c_str()) != INVALID_FILE_ATTRIBUTES)
                        return;
                }
            }
        }

        HANDLE t = ::CreateThread(nullptr, 0, [](LPVOID) -> DWORD
        {
            ::Sleep(300);
            HideCurrentThreadFromDebugger();
            Install();
            return 0;
        }, nullptr, 0, nullptr);
        if (t) ::CloseHandle(t);
    }

    void SetProbeReadHandler(void (*handler)())
    {
        g_probeReadHandler = handler;
    }

    // 按固定间隔采样计数器，用来反推"检测节奏"（多久查一次、查哪几类）
    std::string WatchJson(int seconds, int intervalMs)
    {
        if (seconds <= 0) seconds = 10;
        if (seconds > 60) seconds = 60;
        if (intervalMs < 200) intervalMs = 200;
        if (intervalMs > 5000) intervalMs = 5000;

        long pq = g_hitsDebugQuery, pe = g_hitsEnumModules, pt = g_hitsToolhelp;
        long pk = g_hitsKernelEnum, pr = g_hitsProbeRead, pv = g_hitsQueryVmem;

        json samples = json::array();
        int n = (seconds * 1000) / intervalMs;
        uint64_t t0 = ::GetTickCount64();

        for (int i = 0; i < n; ++i)
        {
            ::Sleep(intervalMs);

            long cq = g_hitsDebugQuery, ce = g_hitsEnumModules, ct = g_hitsToolhelp;
            long ck = g_hitsKernelEnum, cr = g_hitsProbeRead, cv = g_hitsQueryVmem;

            json s;
            s["t_ms"] = (uint64_t)(::GetTickCount64() - t0);
            s["d_debug"] = cq - pq;
            s["d_enum"] = ce - pe;
            s["d_toolhelp"] = ct - pt;
            s["d_kernel"] = ck - pk;
            s["d_probe_read"] = cr - pr;
            s["d_query_vmem"] = cv - pv;
            samples.push_back(s);

            pq = cq; pe = ce; pt = ct; pk = ck; pr = cr; pv = cv;
        }

        int busy = 0;
        for (const auto& s : samples)
        {
            long sum = s["d_debug"].get<long>() + s["d_enum"].get<long>() +
                       s["d_toolhelp"].get<long>() + s["d_kernel"].get<long>() +
                       s["d_probe_read"].get<long>() + s["d_query_vmem"].get<long>();
            if (sum > 0) busy++;
        }

        json out;
        out["seconds"] = seconds;
        out["interval_ms"] = intervalMs;
        out["samples"] = samples;
        out["busy_samples"] = busy;
        out["total_samples"] = n;
        out["verdict"] = (busy == 0) ? "quiet: no detection traffic seen in this window"
                                     : "active: counters moved, see samples";
        return out.dump();
    }

    std::string StatusJson()
    {
        json j;
        j["installed"] = (bool)g_installed;
        j["hook_count"] = g_installedCount;
        j["debugger_lies_ok"] = g_debuggerLiesOk;
        j["enum_mask_ok"] = g_enumMaskOk;
        j["hits"] = {
            { "debug_query", (long)g_hitsDebugQuery },
            { "enum_modules", (long)g_hitsEnumModules },
            { "toolhelp", (long)g_hitsToolhelp },
            { "output_debug", (long)g_hitsOutputDebug },
            { "kernel_modules", (long)g_hitsKernelEnum },
            { "probe_read", (long)g_hitsProbeRead },
            { "query_vmem", (long)g_hitsQueryVmem },
            { "dll_notify_reg", (long)g_hitsDllNotifyReg },
            { "dll_notify_swallowed", (long)g_hitsDllNotifySwallowed },
        };

        // 探针模块存在性（不枚举，避免触发我们自己的 hook）
        HMODULE probe = ::GetModuleHandleW(L"wcprobe.dll");
        j["wcprobe"] = probe ? "loaded" : "absent";
        if (probe)
        {
            j["wcprobe_base"] = (uint64_t)(uintptr_t)probe;
        }

        j["self_module"] = (uint64_t)(uintptr_t)g_hModule;
        j["self_hidden_from_peb"] = true;   // dllmain 里已调用 HideModuleFromPEB
        return j.dump();
    }

    void RegisterRoutes(httplib::Server& svr)
    {
        svr.Get("/wxcx/guard/status", [](const httplib::Request&, httplib::Response& res)
        {
            res.set_content(StatusJson(), "application/json");
        });

        svr.Get("/wxcx/guard/watch", [](const httplib::Request& req, httplib::Response& res)
        {
            int seconds = 10, interval = 1000;
            if (req.has_param("seconds"))
            {
                try { seconds = std::stoi(req.get_param_value("seconds")); } catch (...) {}
            }
            if (req.has_param("interval_ms"))
            {
                try { interval = std::stoi(req.get_param_value("interval_ms")); } catch (...) {}
            }
            res.set_content(WatchJson(seconds, interval), "application/json");
        });

        svr.Post("/wxcx/guard/install", [](const httplib::Request&, httplib::Response& res)
        {
            int n = Install();
            json j;
            j["installed_hooks"] = n;
            j["already"] = n == g_installedCount && (bool)g_installed;
            res.set_content(StatusJson(), "application/json");
        });
    }

} // namespace guard
} // namespace wxcx
