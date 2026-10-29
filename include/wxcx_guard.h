#pragma once
// wxcx_guard - 反检测 / 反调试 守卫层
//
// 目标：让 wcprobe.dll（VMP 加壳，9 个序号导出，无法按名 hook）拿不到可用证据，
// 而不是去改它内部。做法分三类：
//   1) 调试相关查询说谎（NtQueryInformationProcess / NtQuerySystemInformation /
//      CheckRemoteDebuggerPresent / IsDebuggerPresent）
//   2) 模块枚举遮蔽（EnumProcessModules* / Module32First* / Module32Next*）
//   3) 自身痕迹收敛（OutputDebugString 静音 / trampoline 降权 / 线程隐藏）
//
// 全部通过 MinHook（仓库已有 Hook_SysApi 封装）安装，失败逐项上报，不抛异常。

#include <string>

namespace httplib { class Server; }

namespace wxcx
{
namespace guard
{
    // 在后台线程里安装（不要放在 DllMain 的 loader lock 里做）
    void InstallAsync();

    // 同步安装；返回成功安装的项数
    int Install();

    bool Installed();

    // 供其它模块调用的工具
    void HideCurrentThreadFromDebugger();
    void HardenTrampoline(void* mem, size_t size);   // RWX -> RX

    // 有人在读 Weixin.dll 里被我们改过的那 9 个字节时先回调（用于立刻撤防）
    // 返回 true 表示"已处理"，仍会继续执行原始读取
    void SetProbeReadHandler(void (*handler)());

    // 按秒采样各计数器的增量，用于判断检测节奏
    std::string WatchJson(int seconds, int intervalMs);

    std::string StatusJson();

    void RegisterRoutes(httplib::Server& svr);
}
}
