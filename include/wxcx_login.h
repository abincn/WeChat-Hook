#pragma once
// wxcx_login - 登录状态探测
//
// 起因：g_IsLogin 在原工程里只被读取、从未被赋值，导致登录后仍报未登录，
//       且 DatabaseMgr::searchDatabases() 被 g_IsLogin 挡住 → 联系人为 0、MSG 表读不到。
//
// 这里用两条不依赖任何内部偏移的证据链：
//   1) 强制触发一次 DB 扫描（微信只在登录后才打开 sqlite 句柄）→ 扫到即已登录；
//   2) 兜底看数据目录（%USERPROFILE%\Documents\xwechat_files\<wxid>\db_storage）。

#include <string>

#include "json.hpp"

namespace httplib { class Server; }

namespace wxcx
{
namespace login
{
    // 探测并缓存结果到 g_IsLogin；forceRefresh 时忽略缓存重新探测
    bool Detect(bool forceRefresh = false);

    // 仅探测，不改全局状态
    struct Probe
    {
        bool        ok = false;
        int         dbCount = 0;
        std::string wxid;
        std::string dataDir;
        std::string source;      // "db" / "datadir" / "none"
        std::string detail;
    };
    Probe RunProbe();

    void RegisterRoutes(httplib::Server& svr);
}
}
