#pragma once
// wxcx_probe - 通用函数探针（INT3 + VEH），用于抓取指定 RVA 的入参与对象内存
//
// 用途：像信封序列化函数 0x2C6C550(msg, writer) 这样的点，一挂上就能把
//       msg 对象的前 N 字节 dump 出来，从而直接读到 cmdId / seq 等 varint 字段。
//
// 与 wxcx::recv 的区别：
//   recv 是固定的 sysmsg 观测点（带 XML 解析与回调推送）；
//   probe 是"任意函数 + 任意 dump 长度"的通用抓取器，结果只进内存队列。

#include <cstdint>
#include <string>

namespace httplib { class Server; }

namespace wxcx
{
namespace probe
{
    void RegisterRoutes(httplib::Server& svr);

    // rva: 相对 Weixin.dll 的偏移；dumpBytes: 从 arg1(rcx) 指向的对象里拷多少字节（<=256）
    bool Arm(uint64_t rva, uint32_t windowMs, uint32_t dumpBytes);

    // followOff>0 时，从 arg1 对象的该偏移读出指针并再 dump followLen 字节
    bool ArmEx(uint64_t rva, uint32_t windowMs, uint32_t dumpBytes, uint32_t followOff, uint32_t followLen);
    bool Disarm(uint64_t rva);
    void DisarmAll();

    std::string StatusJson();
    std::string EventsJson(size_t limit);
}
}
