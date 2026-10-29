#pragma once
// wxcx_client - 客户端函数表的运行时解析与安全调用
//
// 设计目标：让"补齐功能"变成**填地址**而不是**改代码**。
//   * 每个高层客户端函数（SendPat / Forward / SendFile / SendXml …）在表里占一行；
//   * 地址可通过 POST /wxcx/client/set 在运行时填入（带 prologue 校验）；
//   * 填好后对应接口立刻可用，无需重新编译；
//   * 未填/校验失败时，接口返回明确的 {ok:false, reason:"unresolved"}，绝不乱跳。

#include <cstdint>
#include <string>

#include "json.hpp"

namespace httplib { class Server; }

namespace wxcx
{
namespace client
{
    void RegisterRoutes(httplib::Server& svr);

    // 运行时设置某个函数的 RVA（0 表示清除）。prologue 非空时按字节校验。
    bool SetRva(const std::string& name, uint64_t rva, const std::string& prologueHex);

    // 当前表状态
    nlohmann::json Status();

    // 载入/保存到 DLL 同目录的 wxcx_client.json（重启后不用重填）
    void LoadFromDisk();
    bool SaveToDisk();

    // ---- 已实现的受保护调用（地址未就绪时返回 false + reason）----
    struct CallResult
    {
        bool   ok = false;
        long   status = 0;
        std::string reason;
    };

    // int64 SendPat(WxString* roomid, WxString* wxid)
    CallResult SendPat(const std::string& roomid, const std::string& wxid);

    // Disabled legacy compatibility wrapper. New callers use /ForwardMsg with
    // msgsvrid and query /wxcx/forward/tasks/{task_id}; quad is not a native ID.
    CallResult Forward(const std::string& toid, uint64_t quadLocalId);
}
}
