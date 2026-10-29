#pragma once
// wxcx_verify - 运行时内存完整性自检
//
// 目的：把"撤防后 .text 与出厂一致"从口号变成可复现的证据，同时能发现
// 任何第三方对我们代码段的修改（wcprobe / 其它注入者）。
//
// 做法：
//   POST /wxcx/verify/baseline   记录当前可执行节的 4KB 块 CRC 基线
//   GET  /wxcx/verify/check      重算并列出发生变化的块（带 RVA）
//   同时报告 sysmsg prologue 的 9 字节当前是"出厂"还是"被我们打了补丁"

#include <string>

namespace httplib { class Server; }

namespace wxcx
{
namespace verify
{
    void RegisterRoutes(httplib::Server& svr);
    std::string StatusJson();
}
}
