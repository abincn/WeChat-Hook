#pragma once
// wxcx_sample - 无锚点的执行采样器（找函数地址用）
//
// 为什么需要：INT3 探针只能挂在**已知** RVA 上，栈回溯只能拿到"经过已知点"的上层函数。
// 拍一拍/撤回/下载语音/表情这些可能完全不经过 send_message 或信封序列化，探针抓不到。
//
// 采样器不需要任何先验地址：定时短暂挂起其它线程读 RIP，统计落在 Weixin.dll 内的地址直方图。
// 用户执行一次目标动作 → 直方图里的热点就是该动作的实现函数（再由离线 .pdata 映射成函数边界）。
//
// 安全约束：采样循环内不分配内存、不加锁、不调用可能依赖堆/加载器的 API；
//           每个线程 Suspend 后必定 Resume，配对失败即计数上报。

#include <cstdint>
#include <string>

#include "json.hpp"

namespace httplib { class Server; }

namespace wxcx
{
namespace sample
{
    void RegisterRoutes(httplib::Server& svr);

    // intervalMs: 采样间隔（1~50）；maxSeconds: 最长运行时间（1~120）
    bool Start(uint32_t intervalMs, uint32_t maxSeconds);
    void Stop();

    nlohmann::json Status();

    // 该 RVA 是否为 .pdata 记录的函数入口（调用裸 RVA 前的安全检查）
    bool IsFunctionStart(uint64_t rva);

    // 查询某 RVA 所属函数（基于 .pdata）：start/end/is_entry
    bool Describe(uint64_t rva, uint64_t& start, uint64_t& end, bool& is_entry);
    nlohmann::json Dump(size_t topN);
}
}
