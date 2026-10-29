#pragma once
// wxcx = WeChat eXtension (chat / group-chat API surface)
// 目标版本: PC 微信 4.1.10.27 (Weixin.dll)
// 说明: 本模块只做"接口层 + 消息对象构造", 不修改上游 hook 逻辑。

#include <string>
#include <cstdint>

namespace httplib { class Server; }

namespace wxcx
{
    // 注册全部聊天 / 群聊 路由
    void RegisterRoutes(httplib::Server& svr);

    // ---- 发送层 (消息对象 + Weixin.dll+send_message) ----
    // toid: 好友 wxid 或 群 gid(@chatroom)
    // atlist: 群 @ 的 wxid 列表, 逗号分隔; 空 = 普通文本
    bool SendTextEx(const std::string& toid, const std::string& msg, const std::string& atlist);

    // 按扩展名分派: 图片走已有图片对象; 其他类型暂未实现(返回 false + reason)
    bool SendFileAuto(const std::string& toid, const std::string& path, std::string& reason);
    // 卡片/视频号（appmsg type=49）：mode=1 写 XML 到 ChatMsg+0x180；mode=2 走原生模型(未实现)
    bool SendAppMsgObject(const std::string& toid, const std::string& xml,
                          int mode, std::string& reason);

    // ---- 诊断 ----
    // 返回 offset 表自检结果 (是否落在 Weixin.dll 映像范围内)
    std::string OffsetsJson();

    // ---- 入站 sysmsg 探针 (群事件 / 通知类消息) ----
    namespace recv
    {
        void RegisterRoutes(httplib::Server& svr);
        bool Arm(uint32_t windowMs);   // 热补丁窗口：打 prologue，到时自动恢复
        bool Disarm();                 // 立即恢复原始字节
        bool IsArmed();
        long Hits();
    }
}
