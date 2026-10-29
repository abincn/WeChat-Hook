// wxcx_voice.cpp - 语音数据读取（借鉴 WeChatFerry 的 DB 路线）
//
// WeChatFerry 的做法（spy/database_executor.cpp::get_audio_data）：
//   1) 在 MediaMSG<N>.db 里执行  SELECT Buf FROM Media WHERE Reserved0=<msgid>
//   2) 结果首字节若是 0x02 则去掉（混淆字节）
//   3) 得到 silk 数据，再用自带 codec 转 pcm/mp3
//
// 它不发起任何网络请求——语音只有在本地已下载后才读得到；未下载的消息需要
// 先触发微信自己的下载（PushAttachTask）。
//
// 我们这一步先拿到 silk 原始字节（showdoc 的 voice_hex 就是这些字节），
// 解码成 mp3/pcm 需要 silk 解码器，另行接入。

#include "wxcx_voice.h"

#include "httplib.h"
#include "json.hpp"

#include <string>
#include <vector>

using json = nlohmann::json;

#include "../xdb/db_mgr.h"

namespace
{
    // 直接走 DatabaseMgr，避免跨编译单元依赖（DbQueryOn 在匿名命名空间内）
    bool QueryOn(const std::string& dbName, const std::string& sql, nlohmann::json& out)
    {
        try
        {
            out = nlohmann::json::parse(xmgr::DatabaseMgr::getInstance().execute(dbName, sql).dump());
            return out.value("status", -1) == 0;
        }
        catch (...)
        {
            out = nlohmann::json::object();
            return false;
        }
    }
}

namespace wxcx
{
namespace voice
{
namespace
{
    std::string ToHex(const std::string& s)
    {
        static const char* kH = "0123456789ABCDEF";
        std::string r;
        r.reserve(s.size() * 2);
        for (unsigned char c : s)
        {
            r.push_back(kH[c >> 4]);
            r.push_back(kH[c & 0xF]);
        }
        return r;
    }

    std::string ToBase64(const std::string& in)
    {
        static const char* kT = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string out;
        size_t i = 0;
        while (i + 2 < in.size())
        {
            unsigned v = ((unsigned char)in[i] << 16) | ((unsigned char)in[i + 1] << 8) | (unsigned char)in[i + 2];
            out.push_back(kT[(v >> 18) & 0x3F]);
            out.push_back(kT[(v >> 12) & 0x3F]);
            out.push_back(kT[(v >> 6) & 0x3F]);
            out.push_back(kT[v & 0x3F]);
            i += 3;
        }
        if (i < in.size())
        {
            unsigned v = ((unsigned char)in[i] << 16) | (i + 1 < in.size() ? ((unsigned char)in[i + 1] << 8) : 0);
            out.push_back(kT[(v >> 18) & 0x3F]);
            out.push_back(kT[(v >> 12) & 0x3F]);
            out.push_back(i + 1 < in.size() ? kT[(v >> 6) & 0x3F] : '=');
            out.push_back('=');
        }
        return out;
    }

    // Buf 可能是 blob（走 db 层会转成 hex 或字符串），这里做兼容提取
    bool ExtractBuf(const json& row, std::string& out)
    {
        if (!row.is_object()) return false;
        for (auto it = row.begin(); it != row.end(); ++it)
        {
            std::string col = it.key();
            if (col != "Buf" && col != "buf") continue;
            if (it.value().is_string())
            {
                out = it.value().get<std::string>();
                return true;
            }
        }
        return false;
    }
}

    bool ReadByMsgId(uint64_t msgId, std::string& silk, std::string& usedDb, std::string& detail)
    {
        std::string sql = "SELECT Buf FROM Media WHERE Reserved0=" + std::to_string(msgId) + ";";

        for (int i = 0; i < 32; ++i)
        {
            std::string db = "MediaMSG" + std::to_string(i) + ".db";
            json r;
            if (!QueryOn(db, sql, r)) continue;
            if (!r.contains("data") || !r["data"].is_array() || r["data"].empty()) continue;

            std::string buf;
            if (!ExtractBuf(r["data"][0], buf) || buf.empty()) continue;

            // 首字节 0x02 为混淆前缀，去掉
            if (!buf.empty() && (unsigned char)buf[0] == 0x02)
                buf.erase(buf.begin());

            silk = buf;
            usedDb = db;
            detail = "row found";
            return true;
        }

        detail = "no Buf found in MediaMSG*.db (voice may not be downloaded yet)";
        return false;
    }

    void RegisterRoutes(httplib::Server& svr)
    {
        // 语音消息列表：给客户端"先列再取"的能力（不依赖解码器）
        // {"limit":20}
        svr.Post("/wxcx/voice/recent", [](const httplib::Request& req, httplib::Response& res)
        {
            int limit = 20;
            try
            {
                if (!req.body.empty())
                {
                    json j = json::parse(req.body);
                    if (j.contains("limit") && j["limit"].is_number_integer())
                        limit = j["limit"].get<int>();
                }
            }
            catch (...) {}
            if (limit <= 0) limit = 20;
            if (limit > 200) limit = 200;

            // 4.x 的列名不完全统一，按候选依次尝试
            const char* cands[] = {
                "SELECT localId, StrTalker, CreateTime, IsSender, MsgSvrID FROM MSG "
                "WHERE Type=34 ORDER BY CreateTime DESC LIMIT %d",
                "SELECT localId, strTalker, CreateTime, IsSender, MsgSvrID FROM MSG "
                "WHERE MsgType=34 ORDER BY CreateTime DESC LIMIT %d",
                "SELECT rowid AS localId, strTalker, CreateTime, IsSender, MsgSvrID FROM MSG "
                "WHERE Type=34 ORDER BY CreateTime DESC LIMIT %d",
                "SELECT rowid AS localId, strTalker, CreateTime, IsSender, MsgSvrID FROM Message "
                "WHERE Type=34 ORDER BY CreateTime DESC LIMIT %d",
            };

            char sql[512];
            json r;
            bool ok = false;
            for (const char* c : cands)
            {
                snprintf(sql, sizeof(sql), c, limit);
                if (QueryOn("MicroMsg.db", sql, r) &&
                    r.contains("data") && r["data"].is_array())
                {
                    ok = true;
                    break;
                }
            }

            json out;
            out["code"] = ok ? "0" : "-1";
            if (!ok)
            {
                out["msg"] = "MSG 表结构不匹配（尝试了 Type/MsgType、localId/rowid 多种组合）";
                out["hint"] = "POST /wxcx/schema {\"db\":\"MicroMsg.db\",\"table\":\"MSG\"} 看真实列名";
                res.set_content(out.dump(), "application/json");
                return;
            }

            out["count"] = r["data"].size();
            out["items"] = r["data"];
            out["next_step"] = "用 items[].localId 调 POST /DownloadVoice {\"msgid\": ...} 取 silk";
            res.set_content(out.dump(), "application/json");
        });

        // {"msgid": 1234567890123, "format":"hex"|"base64"|"none"}
        svr.Post("/DownloadVoice", [](const httplib::Request& req, httplib::Response& res)
        {
            json in;
            try { if (!req.body.empty()) in = json::parse(req.body); } catch (...) {}

            uint64_t msgId = 0;
            if (in.contains("msgid") && in["msgid"].is_number_unsigned())
                msgId = in["msgid"].get<uint64_t>();
            else if (in.contains("msgsvrid") && in["msgsvrid"].is_number_unsigned())
                msgId = in["msgsvrid"].get<uint64_t>();

            if (msgId == 0)
            {
                res.status = 400;
                res.set_content("{\"code\":\"-1\",\"msg\":\"需要 msgid（MSG 表的 localId 或 msgsvrid）\"}",
                                "application/json");
                return;
            }

            std::string silk, usedDb, detail;
            bool ok = ReadByMsgId(msgId, silk, usedDb, detail);

            std::string fmt = in.value("format", std::string("hex"));
            json out;
            out["code"] = ok ? "0" : "-1";
            out["msgid"] = msgId;
            out["db"] = usedDb;
            out["detail"] = detail;
            out["len"] = silk.size();
            if (ok)
            {
                if (fmt == "hex") out["voice_hex"] = ToHex(silk);
                else if (fmt == "base64") out["voice_base64"] = ToBase64(silk);
                out["note"] = "silk 原始数据；解码 mp3/pcm 需 silk 解码器";
            }
            res.set_content(out.dump(), "application/json");
        });
    }
}
}
