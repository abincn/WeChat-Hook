#pragma once
// wxcx_voice - 语音数据读取（DB 路线，借鉴 WeChatFerry）
//
// WCF 的 get_audio_data: SELECT Buf FROM Media WHERE Reserved0=<id>，跨 MediaMSG<N>.db，
// 去掉首字节 0x02 混淆位，得到 silk 字节，再用自带 codec 转 pcm/mp3。
// 这里先提供"拿到 silk 原始字节"这一段（showdoc 的 voice_hex 就是它）。

#include <cstdint>
#include <string>

namespace httplib { class Server; }

namespace wxcx
{
namespace voice
{
    void RegisterRoutes(httplib::Server& svr);

    // 按 msgid（MSG 表 localId 或 msgsvrid）读取语音 silk 数据
    bool ReadByMsgId(uint64_t msgId, std::string& silk, std::string& usedDb, std::string& detail);
}
}
