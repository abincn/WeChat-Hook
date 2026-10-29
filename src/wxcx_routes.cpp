// wxcx_routes.cpp - chat / group-chat HTTP surface for WeChat 4.1.10.27
//
// httplib pulls in winsock2.h, so it must be included before windows.h.

#include "wxcx.h"
#include "wxcx_guard.h"
#include "wxcx_verify.h"
#include "wxcx_probe.h"
#include "wxcx_pb.h"
#include "wxcx_client.h"
#include "wxcx_login.h"
#include "wxcx_sample.h"
#include "wxcx_voice.h"
#include "wxcx_msgloc.h"
#include "wxcx_forward.h"
#include "wxcx_ai.h"

#include "httplib.h"
#include "json.hpp"

#include <windows.h>
#include <psapi.h>
#include <cwchar>

#include <cstdint>
#include <string>
#include <vector>

#include "global.h"
#include "wx_send.h"
#include "wx_send_xml.h"
#include "db_mgr.h"

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "ole32.lib")

using json = nlohmann::json;

namespace
{
    // ---------------------------------------------------------------- helpers
    std::vector<std::string> Split(const std::string& s, char sep)
    {
        std::vector<std::string> out;
        std::string cur;
        for (char c : s)
        {
            if (c == sep) { out.push_back(cur); cur.clear(); }
            else cur += c;
        }
        out.push_back(cur);
        return out;
    }

    bool HexToBytes(const std::string& hex, std::vector<unsigned char>& out)
    {
        out.clear();
        if (hex.empty() || (hex.size() % 2) != 0) return false;

        auto nibble = [](char c) -> int
        {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };

        out.reserve(hex.size() / 2);
        for (size_t i = 0; i < hex.size(); i += 2)
        {
            int hi = nibble(hex[i]);
            int lo = nibble(hex[i + 1]);
            if (hi < 0 || lo < 0) { out.clear(); return false; }
            out.push_back((unsigned char)((hi << 4) | lo));
        }
        return true;
    }

    std::string SqlEscape(const std::string& s)
    {
        std::string out;
        out.reserve(s.size() + 8);
        for (char c : s)
        {
            if (c == '\'') out += "''";
            else out += c;
        }
        return out;
    }

    bool ReadJson(const httplib::Request& req, json& out, httplib::Response& res)
    {
        if (req.body.empty())
        {
            out = json::object();
            return true;
        }
        try
        {
            out = json::parse(req.body);
            return true;
        }
        catch (...)
        {
            json e;
            e["code"] = "-1";
            e["status"] = 0;
            e["msg"] = "invalid json";
            res.set_content(e.dump(), "application/json");
            return false;
        }
    }

    json Ok(const std::string& msg = "success")
    {
        json j;
        j["code"] = "0";
        j["status"] = 1;
        j["msg"] = msg;
        return j;
    }

    json Fail(const std::string& msg, const std::string& reason = "")
    {
        json j;
        j["code"] = "-1";
        j["status"] = 0;
        j["msg"] = msg;
        if (!reason.empty()) j["reason"] = reason;
        return j;
    }

    std::string PickString(const json& req, const char* key)
    {
        if (req.contains(key) && req[key].is_string()) return req[key].get<std::string>();
        return std::string();
    }

    std::string PickStringAny(const json& req, std::initializer_list<const char*> keys)
    {
        for (const char* k : keys)
        {
            if (req.contains(k) && req[k].is_string())
            {
                std::string v = req[k].get<std::string>();
                if (!v.empty()) return v;
            }
        }
        return std::string();
    }

    std::string PickToId(const json& req)
    {
        return PickStringAny(req, { "toid", "to_wxid", "wxidorgid", "wxid", "gid", "username" });
    }

    std::string PickMsg(const json& req)
    {
        return PickStringAny(req, { "msg", "content", "text", "xml" });
    }

    bool LoginGuard(httplib::Response& res)
    {
        if (wxcx::login::Detect()) return true;
        res.set_content(Fail("not logged in", "g_IsLogin=0").dump(), "application/json");
        return false;
    }

    bool IsChatRoom(const std::string& wxid)
    {
        static const std::string suffix = "@chatroom";
        return wxid.size() > suffix.size() &&
               wxid.compare(wxid.size() - suffix.size(), suffix.size(), suffix) == 0;
    }

    // db query helper; converts ordered_json to plain json at the boundary.
    bool DbQueryOn(const std::string& dbName, const std::string& sql, json& out)
    {
        try
        {
            xmgr::DatabaseMgr& db = xmgr::DatabaseMgr::getInstance();
            out = json::parse(db.execute(dbName, sql).dump());
            return out.value("status", -1) == 0;
        }
        catch (...)
        {
            out = json::object();
            return false;
        }
    }

    bool DbQuery(const std::string& sql, json& out)
    {
        return DbQueryOn("MicroMsg.db", sql, out);
    }

    json QueryContactRow(const std::string& wxid, bool& found)
    {
        found = false;
        json r;

        if (wxid.empty()) return json::object();
        if (!DbQuery("SELECT * FROM Contact WHERE UserName='" + SqlEscape(wxid) + "' LIMIT 1", r))
            return json::object();

        if (!r.contains("data") || !r["data"].is_array() || r["data"].empty())
            return json::object();

        found = true;
        return r["data"][0];
    }

    json QueryChatRoomMembers(const std::string& gid, std::string& source)
    {
        json members = json::array();
        source = "unavailable";

        if (gid.empty()) return members;

        json r;
        if (!DbQuery("SELECT UserNameList, DisplayNameList FROM ChatRoom WHERE ChatRoomName='"
                     + SqlEscape(gid) + "' LIMIT 1", r))
            return members;

        if (!r.contains("data") || !r["data"].is_array() || r["data"].empty())
            return members;

        json row = r["data"][0];
        std::string names = row.value("UserNameList", std::string());
        std::string display = row.value("DisplayNameList", std::string());

        std::vector<std::string> ids = Split(names, ';');
        std::vector<std::string> nicks = Split(display, ';');

        for (size_t i = 0; i < ids.size(); ++i)
        {
            if (ids[i].empty()) continue;
            json m;
            m["wxid"] = ids[i];
            m["nickname"] = (i < nicks.size()) ? nicks[i] : std::string();
            m["role"] = 0;
            m["flag8"] = 0;
            m["flag16"] = 0;
            members.push_back(m);
        }

        source = "ChatRoom.UserNameList";
        return members;
    }

    void NotImplemented(httplib::Response& res, const std::string& route, const std::string& note)
    {
        json j;
        j["code"] = "-1";
        j["status"] = 0;
        j["msg"] = "not implemented";
        j["route"] = route;
        j["reason"] = note;
        res.status = 200;
        res.set_content(j.dump(), "application/json");
    }

    std::string Hex(uint64_t v)
    {
        char b[32] = { 0 };
        snprintf(b, sizeof(b), "0x%llX", (unsigned long long)v);
        return std::string(b);
    }
}

// ---------------------------------------------------------------- routes
void wxcx::RegisterRoutes(httplib::Server& svr)
{
    wxcx::ai::RegisterRoutes(svr);

    // ---------- image ----------
    svr.Post("/SendImgMsg", [](const httplib::Request& req, httplib::Response& res)
    {
        json j;
        if (!ReadJson(req, j, res)) return;
        if (!LoginGuard(res)) return;

        std::string toid = PickToId(j);
        std::string path = PickStringAny(j, { "path", "imgPath", "filepath" });

        if (toid.empty() || path.empty())
        {
            json r; r["ret"] = 1; r["retmsg"] = "toid/path required";
            res.set_content(r.dump(), "application/json");
            return;
        }

        std::string reason;
        bool ok = wxcx::SendFileAuto(toid, path, reason);

        json r;
        r["ret"] = ok ? 0 : 1;
        r["retmsg"] = ok ? "success" : reason;
        res.set_content(r.dump(), "application/json");
    });

    // ---------- file (path, or fileData + fileName) ----------
    svr.Post("/SendFileMsg", [](const httplib::Request& req, httplib::Response& res)
    {
        json j;
        if (!ReadJson(req, j, res)) return;
        if (!LoginGuard(res)) return;

        std::string toid = PickToId(j);
        std::string path = PickStringAny(j, { "path", "filePath", "filepath" });
        std::string fileData = PickString(j, "fileData");
        std::string fileName = PickString(j, "fileName");

        if (toid.empty())
        {
            json r; r["code"] = 0; r["msg"] = "toid required"; r["data"] = json::object();
            res.set_content(r.dump(), "application/json");
            return;
        }

        if (path.empty() && !fileData.empty())
        {
            if (fileName.empty())
            {
                json r; r["code"] = 0; r["msg"] = "fileName required with fileData";
                r["data"] = json::object();
                res.set_content(r.dump(), "application/json");
                return;
            }

            std::vector<unsigned char> bytes;
            if (!HexToBytes(fileData, bytes) || bytes.empty())
            {
                json r; r["code"] = 0; r["msg"] = "invalid hex fileData"; r["data"] = json::object();
                res.set_content(r.dump(), "application/json");
                return;
            }

            wchar_t tmpDir[MAX_PATH] = { 0 };
            ::GetTempPathW(MAX_PATH, tmpDir);

            GUID g{};
            ::CoCreateGuid(&g);
            wchar_t prefix[512] = { 0 };
            swprintf_s(prefix, L"%s wxcx_%08x%04x%04x_", tmpDir, g.Data1, g.Data2, g.Data3);

            int wlen = ::MultiByteToWideChar(CP_UTF8, 0, fileName.c_str(), -1, nullptr, 0);
            std::wstring wname(wlen > 0 ? (size_t)wlen : 1, L'\0');
            if (wlen > 0) ::MultiByteToWideChar(CP_UTF8, 0, fileName.c_str(), -1, &wname[0], wlen);

            std::wstring wpath = std::wstring(prefix) + wname.c_str();

            HANDLE h = ::CreateFileW(wpath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                                     FILE_ATTRIBUTE_TEMPORARY, nullptr);
            if (h == INVALID_HANDLE_VALUE)
            {
                json r; r["code"] = 0; r["msg"] = "temp write failed"; r["data"] = json::object();
                res.set_content(r.dump(), "application/json");
                return;
            }
            DWORD written = 0;
            ::WriteFile(h, bytes.data(), (DWORD)bytes.size(), &written, nullptr);
            ::CloseHandle(h);

            int plen = ::WideCharToMultiByte(CP_UTF8, 0, wpath.c_str(), -1, nullptr, 0, nullptr, nullptr);
            std::string utf8Path(plen > 0 ? (size_t)plen : 0, '\0');
            if (plen > 0)
                ::WideCharToMultiByte(CP_UTF8, 0, wpath.c_str(), -1, &utf8Path[0], plen, nullptr, nullptr);
            while (!utf8Path.empty() && utf8Path.back() == '\0') utf8Path.pop_back();

            std::string reason;
            bool ok = wxcx::SendFileAuto(toid, utf8Path, reason);
            ::DeleteFileW(wpath.c_str());

            json r;
            r["code"] = ok ? 1 : 0;
            r["msg"] = ok ? "success" : reason;
            r["data"] = json::object();
            res.set_content(r.dump(), "application/json");
            return;
        }

        if (path.empty())
        {
            json r; r["code"] = 0; r["msg"] = "path or fileData required"; r["data"] = json::object();
            res.set_content(r.dump(), "application/json");
            return;
        }

        std::string reason;
        bool ok = wxcx::SendFileAuto(toid, path, reason);

        json r;
        r["code"] = ok ? 1 : 0;
        r["msg"] = ok ? "success" : reason;
        r["data"] = json::object();
        res.set_content(r.dump(), "application/json");
    });

    // ---------- forward XML (image / video / gif) ----------
    svr.Post("/ForwardXMLMsg", [](const httplib::Request& req, httplib::Response& res)
    {
        json j;
        if (!ReadJson(req, j, res)) return;
        if (!LoginGuard(res)) return;

        std::string toid = PickToId(j);
        std::string xml = PickStringAny(j, { "content", "xml", "msg" });

        if (toid.empty() || xml.empty())
        {
            json r; r["ret"] = 1; r["retmsg"] = "toid/content required";
            res.set_content(r.dump(), "application/json");
            return;
        }

        WeixinSendXML::Initialize();
        bool ok = WeixinSendXML::ForwardXmlMessage(toid, xml);

        json r;
        r["ret"] = ok ? 0 : 1;
        r["retmsg"] = ok ? "success" : "fail";
        res.set_content(r.dump(), "application/json");
    });

    // ---------- decrypt dat image ----------
    svr.Post("/Decode_Pic", [](const httplib::Request& req, httplib::Response& res)
    {
        json j;
        if (!ReadJson(req, j, res)) return;

        std::string src = PickString(j, "src_path");
        std::string dst = PickString(j, "dst_path");

        if (src.empty() || dst.empty())
        {
            json r; r["ret"] = 1; r["retmsg"] = "src_path/dst_path required";
            res.set_content(r.dump(), "application/json");
            return;
        }

        // The legacy void native wrapper cannot establish decode success and
        // has no verified HTTP-thread context. Keep it off until the new file
        // decoder/key lifecycle has completed live validation.
        res.status = 501;
        json r; r["ret"] = -3; r["retmsg"] = "image_decoder_unverified";
        r["output_written"] = false;
        res.set_content(r.dump(), "application/json");
    });

    // ---------- contact / chatroom info ----------
    svr.Post("/GetContact", [](const httplib::Request& req, httplib::Response& res)
    {
        json j;
        if (!ReadJson(req, j, res)) return;

        std::string wxid = PickStringAny(j, { "wxid", "wxidorgid", "username", "gid" });
        if (wxid.empty())
        {
            res.status = 400;
            res.set_content(Fail("wxid required").dump(), "application/json");
            return;
        }

        bool found = false;
        json row = QueryContactRow(wxid, found);

        if (!found)
        {
            res.status = 404;
            json r;
            r["code"] = "-1";
            r["status"] = 0;
            r["msg"] = "contact not found";
            r["wxid"] = wxid;
            res.set_content(r.dump(), "application/json");
            return;
        }

        row["wxid"] = wxid;

        if (IsChatRoom(wxid))
        {
            std::string source;
            row["members"] = QueryChatRoomMembers(wxid, source);
            row["members_source"] = source;
            if (row.contains("MemberTotal")) row["member_total"] = row["MemberTotal"];
        }

        res.set_content(row.dump(), "application/json");
    });

    svr.Post("/GetContacts", [](const httplib::Request& req, httplib::Response& res)
    {
        json j;
        if (!ReadJson(req, j, res)) return;

        int offset = 0;
        int limit = 4096;
        if (j.contains("offset") && j["offset"].is_number_integer()) offset = j["offset"].get<int>();
        if (j.contains("limit") && j["limit"].is_number_integer()) limit = j["limit"].get<int>();
        if (offset < 0) offset = 0;
        if (limit <= 0) limit = 4096;
        if (limit > 4096) limit = 4096;

        json r;
        if (!DbQuery("SELECT * FROM Contact LIMIT " + std::to_string(limit) +
                     " OFFSET " + std::to_string(offset), r))
        {
            res.set_content(Fail("db query failed").dump(), "application/json");
            return;
        }

        json out;
        out["status"] = 0;
        out["offset"] = offset;
        out["limit"] = limit;
        out["contacts"] = r.contains("data") ? r["data"] : json::array();
        size_t count = out["contacts"].is_array() ? out["contacts"].size() : 0;
        out["count"] = count;
        out["complete"] = count < (size_t)limit;
        out["source"] = "MicroMsg.db/Contact";

        res.set_content(out.dump(), "application/json");
    });

    // ---------- chatroom member count (DB: Contact.MemberTotal) ----------
    svr.Post("/QueryChatRoomMemberCount", [](const httplib::Request& req, httplib::Response& res)
    {
        json j;
        if (!ReadJson(req, j, res)) return;

        std::string gid = PickStringAny(j, { "gid", "wxid", "toid" });
        bool found = false;
        json row = QueryContactRow(gid, found);

        if (!found)
        {
            res.set_content(Fail("chatroom not found", "contact_miss").dump(), "application/json");
            return;
        }

        json r;
        r["code"] = "0";
        r["status"] = 1;
        r["gid"] = gid;
        r["MemberTotal"] = row.contains("MemberTotal") ? row["MemberTotal"] : json(0);
        res.set_content(r.dump(), "application/json");
    });

    // ---------- documented but not implemented in this hook ----------
    struct StubRoute { const char* path; const char* note; };
    static const StubRoute stubs[] = {
        { "/SendImgMsg_NoSrc",      "needs PB: upload fileid/authkey/crc32 then NetScene" },
        { "/SendFileMsg_NoSrc",     "needs PB: CDN upload + attach NetScene" },
        { "/SendVoiceMsg",          "needs PB: silk encode + CDN upload" },
        { "/ForwardVoiceMsg",       "needs PB: forward voice NetScene" },
        { "/RevokeMsg",             "needs PB: revoke NetScene(10002)" },

        { "/Voice2Text",            "needs PB: voice2text NetScene" },
        { "/AddtoEmoji",            "needs PB: emoji add NetScene" },
        { "/ChatRoomTopMsg",        "needs PB: chatroom top message NetScene" },
        { "/ChatRoomUnTopMsg",      "needs PB: chatroom top message NetScene" },
        { "/GetTransText",          "needs PB: translate NetScene" },
        { "/GetFavList",            "needs PB: favorite NetScene" },
        { "/Batchgetfavitem",       "needs PB: favorite NetScene" },
        { "/AddFavitem",            "needs PB: favorite NetScene" },
        { "/CreateChatRoom",        "needs PB: create chatroom NetScene" },
        { "/AddFriendToChatRoom",   "needs PB: add member NetScene" },
        { "/InviteFriendToChatRoom","needs PB: invite NetScene" },
        { "/ChatRoomEditMark",      "needs PB: chatroom remark NetScene" },
        { "/QueryChatRoomOwnerWxid","needs PB: owner query NetScene" },
        { "/GetChatroomMemberDetailInfo", "needs PB: member detail NetScene" },
        { "/GetChatrooMmemberDetail",     "needs PB: member detail NetScene" },
        { "/BatchGetChatRoomMemberWxid",  "needs PB: member wxid list NetScene" },
        { "/QueryChatRoomMemberNickName", "needs PB: member nickname NetScene" },
        { "/ChatRoomMemberBatchDelete",   "needs PB: kick member NetScene" },
        { "/ChatRoomInviteCfg",     "needs PB: invite config NetScene" },
        { "/GetChatRoomQRCode",     "needs PB: qrcode NetScene" },
        { "/AddChatRoomAdmin",      "needs PB: set admin NetScene" },
        { "/DelChatRoomAdmin",      "needs PB: del admin NetScene" },
        { "/TransferChatRoomOwner", "needs PB: transfer owner NetScene" },
        { "/GetFriendOrChatroomDetailInfo", "needs PB: detail fetch NetScene" },
        { "/GetHeadIMG",            "needs PB: head image (Contact.BigHeadImgUrl available)" },
        { "/GetOpenIMContact",      "needs PB: OpenIM" },
        { "/GetA8Key",              "needs PB: A8Key" },
        { "/oplog/edit_chatroom_name",    "needs oplog/PB: rename chatroom" },
        { "/setchatroomannouncement",     "needs oplog/PB: set announcement" },
        { "/delchatroomannouncement",     "needs oplog/PB: clear announcement" },
    };

    for (const auto& s : stubs)
    {
        std::string path = s.path;
        std::string note = s.note;
        svr.Post(path, [path, note](const httplib::Request&, httplib::Response& res)
        {
            NotImplemented(res, path, note);
        });
    }

    // ---------- DB self-inspection (needed to finish group reads) ----------
    // GET  /wxcx/tables?db=MicroMsg.db
    // POST /wxcx/schema {"db":"MicroMsg.db","table":"Contact"}
    svr.Get("/wxcx/tables", [](const httplib::Request& req, httplib::Response& res)
    {
        std::string db = req.has_param("db") ? req.get_param_value("db") : "MicroMsg.db";

        json r;
        if (!DbQueryOn(db, "SELECT name, sql FROM sqlite_master WHERE type IN ('table','view') ORDER BY name", r))
        {
            res.set_content(Fail("db query failed", "cannot read sqlite_master: " + db).dump(),
                            "application/json");
            return;
        }

        json out;
        out["db"] = db;
        out["status"] = 0;
        out["objects"] = r.contains("data") ? r["data"] : json::array();
        out["count"] = out["objects"].is_array() ? out["objects"].size() : 0;
        res.set_content(out.dump(), "application/json");
    });

    svr.Post("/wxcx/schema", [](const httplib::Request& req, httplib::Response& res)
    {
        json j;
        if (!ReadJson(req, j, res)) return;

        std::string db = PickString(j, "db");
        if (db.empty()) db = "MicroMsg.db";
        std::string table = PickStringAny(j, { "table", "name" });

        if (table.empty())
        {
            res.status = 400;
            res.set_content(Fail("table required").dump(), "application/json");
            return;
        }

        json cols;
        bool okCols = DbQueryOn(db, "PRAGMA table_info('" + SqlEscape(table) + "')", cols);

        json ddl;
        bool okDdl = DbQueryOn(db, "SELECT sql FROM sqlite_master WHERE name='" + SqlEscape(table) + "'", ddl);

        json out;
        out["db"] = db;
        out["table"] = table;
        out["columns_ok"] = okCols;
        out["columns"] = (okCols && cols.contains("data")) ? cols["data"] : json::array();
        out["ddl"] = (okDdl && ddl.contains("data") && !ddl["data"].empty()) ? ddl["data"][0] : json(nullptr);
        res.set_content(out.dump(), "application/json");
    });

    // ---------- login status (showdoc 002 /IsLoginStatus) ----------
    svr.Post("/IsLoginStatus", [](const httplib::Request&, httplib::Response& res)
    {
        json j;
        bool online = wxcx::login::Detect();
        j["onlinestatus"] = online ? "3" : "1";
        j["msg"] = online ? "\u767b\u9646\u5b8c\u6210\uff01" : "\u5c1a\u672a\u767b\u9646";
        res.set_content(j.dump(), "application/json");
    });

    // ---------- integrity self check ----------
    wxcx::verify::RegisterRoutes(svr);

    // ---------- client function table ----------
    wxcx::client::RegisterRoutes(svr);
    wxcx::login::RegisterRoutes(svr);
    wxcx::sample::RegisterRoutes(svr);
    wxcx::voice::RegisterRoutes(svr);
    wxcx::msgloc::RegisterRoutes(svr);
    wxcx::forward::RegisterRoutes(svr);

    // ---------- protobuf builders / decoder ----------
    wxcx::pb::RegisterRoutes(svr);

    // ---------- generic function probe ----------
    wxcx::probe::RegisterRoutes(svr);

    // ---------- anti-detection guard ----------
    wxcx::guard::RegisterRoutes(svr);

    // ---------- inbound sysmsg probe ----------
    wxcx::recv::RegisterRoutes(svr);

    // Quote/card send routes are registered once by the text service and return 501.

    // ---------- 消息表读取（showdoc 019 的历史面）----------
    // POST 别名：部分客户端习惯 POST，行为与 GET /wxcx/tables?db= 一致
    svr.Post("/wxcx/tables", [](const httplib::Request& req, httplib::Response& res)
    {
        std::string db = "MicroMsg.db";
        if (req.has_param("db")) db = req.get_param_value("db");
        else if (!req.body.empty())
        {
            try
            {
                json j = json::parse(req.body);
                if (j.contains("db") && j["db"].is_string()) db = j["db"].get<std::string>();
            }
            catch (...) {}
        }

        json r;
        if (!DbQueryOn(db, "SELECT name, sql FROM sqlite_master WHERE type IN ('table','view') ORDER BY name", r))
        {
            res.set_content(Fail("db query failed", "cannot read sqlite_master: " + db).dump(), "application/json");
            return;
        }
        json out;
        out["db"] = db;
        out["status"] = 0;
        out["data"] = r.contains("data") ? r["data"] : json::array();
        res.set_content(out.dump(), "application/json");
    });

    // 4.x 的消息记录字段（来自二进制里的列名串）：
    //   talkerId / strTalker / MsgSvrID / CreateTime / strContent / Status / IsSender / bytesExtra
    svr.Post("/wxcx/msg/recent", [](const httplib::Request& req, httplib::Response& res)
    {
        json j;
        if (!ReadJson(req, j, res)) return;

        int limit = 20;
        if (j.contains("limit") && j["limit"].is_number_integer()) limit = j["limit"].get<int>();
        if (limit <= 0) limit = 20;
        if (limit > 200) limit = 200;

        std::string table = PickString(j, "table");

        // 常见候选表名，按顺序尝试
        std::vector<std::string> candidates;
        if (!table.empty()) candidates.push_back(table);
        else candidates = { "MSG", "Message", "ChatMsg" };

        json attempts = json::array();
        for (const auto& t : candidates)
        {
            json r;
            if (!DbQuery("SELECT * FROM " + t + " ORDER BY createTime DESC LIMIT " + std::to_string(limit), r))
            {
                // 列名可能是 CreateTime；换一种大小写再试
                if (!DbQuery("SELECT * FROM " + t + " ORDER BY CreateTime DESC LIMIT " + std::to_string(limit), r))
                {
                    json a;
                    a["table"] = t;
                    a["ok"] = false;
                    attempts.push_back(a);
                    continue;
                }
            }

            json out;
            out["status"] = 0;
            out["table"] = t;
            out["count"] = r.contains("data") && r["data"].is_array() ? r["data"].size() : 0;
            out["rows"] = r.contains("data") ? r["data"] : json::array();
            res.set_content(out.dump(), "application/json");
            return;
        }

        json out;
        out["status"] = -1;
        out["msg"] = "no message table matched";
        out["attempts"] = attempts;
        out["hint"] = "GET /wxcx/tables?db=MicroMsg.db to list actual table names";
        res.set_content(out.dump(), "application/json");
    });

    // ---------- 批量联系人简要信息（showdoc 084，纯 DB 实现）----------
    svr.Post("/BatchGetContactBriefInfo", [](const httplib::Request& req, httplib::Response& res)
    {
        json j;
        if (!ReadJson(req, j, res)) return;

        std::vector<std::string> ids;
        if (j.contains("wxidlist") && j["wxidlist"].is_array())
            for (const auto& v : j["wxidlist"])
                if (v.is_string()) ids.push_back(v.get<std::string>());

        if (ids.empty())
        {
            res.status = 400;
            res.set_content(Fail("wxidlist required").dump(), "application/json");
            return;
        }
        if (ids.size() > 200) ids.resize(200);

        std::string in;
        for (size_t i = 0; i < ids.size(); ++i)
        {
            if (i) in += ",";
            in += "'" + SqlEscape(ids[i]) + "'";
        }

        json r;
        json out;
        out["status"] = 0;
        out["requested"] = ids.size();

        if (DbQuery("SELECT UserName, NickName, Alias, BigHeadImgUrl, SmallHeadImgUrl, "
                    "Remark, MemberTotal FROM Contact WHERE UserName IN (" + in + ")", r))
        {
            out["contacts"] = r.contains("data") ? r["data"] : json::array();
            out["count"] = out["contacts"].is_array() ? out["contacts"].size() : 0;
        }
        else
        {
            out["contacts"] = json::array();
            out["count"] = 0;
            out["error"] = "db query failed";
        }
        res.set_content(out.dump(), "application/json");
    });

    // ---------- 批量检测好友状态（showdoc 035，本地视角）----------
    // 说明：真实的"是否被对方删除"需要服务端校验（PB），本地只能给出通讯录里的存在性与标志位。
    svr.Post("/CheckFriendStatus", [](const httplib::Request& req, httplib::Response& res)
    {
        json j;
        if (!ReadJson(req, j, res)) return;

        std::vector<std::string> ids;
        if (j.contains("wxidlist") && j["wxidlist"].is_array())
            for (const auto& v : j["wxidlist"])
                if (v.is_string()) ids.push_back(v.get<std::string>());

        if (ids.empty())
        {
            res.status = 400;
            res.set_content(Fail("wxidlist required").dump(), "application/json");
            return;
        }
        if (ids.size() > 200) ids.resize(200);

        std::string in;
        for (size_t i = 0; i < ids.size(); ++i)
        {
            if (i) in += ",";
            in += "'" + SqlEscape(ids[i]) + "'";
        }

        json r;
        bool ok = DbQuery("SELECT UserName, NickName, BitVal, ContactType, VerifyFlag, DeleteFlag "
                          "FROM Contact WHERE UserName IN (" + in + ")", r);
        if (!ok)
        {
            // 部分版本没有 DeleteFlag 列，退回基础列
            ok = DbQuery("SELECT UserName, NickName, BitVal, ContactType, VerifyFlag "
                         "FROM Contact WHERE UserName IN (" + in + ")", r);
        }
        if (!ok)
        {
            res.set_content(Fail("db query failed", "Contact table schema unexpected").dump(),
                            "application/json");
            return;
        }

        json rows = (r.contains("data") && r["data"].is_array()) ? r["data"] : json::array();

        json out;
        out["status"] = 0;
        out["local_only"] = true;
        out["note"] = "本地通讯录视角；判定'被对方删除'需要服务端校验，当前不具备";
        out["results"] = rows;
        out["count"] = rows.size();

        // 不在通讯录里的（可能是陌生人/已删除）
        json missing = json::array();
        for (const auto& id : ids)
        {
            bool found = false;
            for (const auto& row : rows)
            {
                if (row.contains("UserName") && row["UserName"].is_string() &&
                    row["UserName"].get<std::string>() == id)
                {
                    found = true;
                    break;
                }
            }
            if (!found) missing.push_back(id);
        }
        out["not_in_contact"] = missing;
        res.set_content(out.dump(), "application/json");
    });

    // ---------- 能力矩阵（单一事实来源，便于客户端决策）----------
    svr.Get("/wxcx/capabilities", [](const httplib::Request&, httplib::Response& res)
    {
        struct Cap { const char* route; const char* name; const char* status; const char* note; };
        static const Cap caps[] = {
            { "/wxcx/messages/events", "结构化私聊/群消息", "partial", "文本/群@基础通过；引用/卡片解析待真机" },
            { "/wxcx/messages/config", "接收与本机回调配置", "partial", "self_id显式配置；有限重试/缺口可见" },
            { "/wxcx/text/tasks/{task_id}", "文本任务状态", "partial", "已提交不等于对端收到" },
            { "/SendTextMsg",              "发送文本消息",         "partial", "异步任务/去重；原生收件与稳定性待验收" },
            { "/SendTextMsg_NoSrc",        "发送文本消息_无源",     "partial", "同上，返回202/task_id" },
            { "/SendAtMsg_NoSrc",          "发送群@文本消息_无源",  "partial", "异步群@文本；真实收件待验收" },
            { "/SendImgMsg",               "发送图片消息",         "ok",      "png/jpg/bmp/webp/gif" },
            { "/SendFileMsg",              "发送文件消息",         "partial", "GIF/图片可用；mp4 与普通文件需 PB(CDN 上传)" },
            { "/SendImgMsg_NoSrc",         "发送图片消息_无源",     "blocked", "需 PB: CDN fileid/authkey" },
            { "/SendFileMsg_NoSrc",        "无源发送文件",         "blocked", "需 PB: CDN 上传" },
            { "/ForwardXMLMsg",            "转发XML消息_图片/视频/GIF", "blocked", "旧 RVA 为函数中段，调用已禁用；需恢复本版本业务入口" },
            { "/SendCardMsg_NoSrc",        "发送卡片XML",          "blocked", "unsafe_disabled：body+0x180 是容量字段，需恢复正确对象布局" },
            { "/SendFinderMsg_NoSrc",      "发送视频号XML",        "blocked", "同上：XML 字段与调用约定尚未确认" },
            { "/ForwardMsg",              "转发现有消息",         "blocked", "异步任务接口已接入；各消息类型原生适配尚未验证，任务不会执行旧四参数调用" },
            { "/SendPatMsg",               "发送拍一拍",           "ready",   "客户端函数 send_pat：地址可经 /wxcx/client/set 运行时填入" },
            { "/SendVoiceMsg",             "发送语音",             "blocked", "需 PB + silk 编码" },
            { "/ForwardVoiceMsg",          "转发语音",             "blocked", "需 PB 或 voicemsg 对象" },
            { "/RevokeMsg",                "撤回指定消息",         "ready",   "字段表已备(RevokeMsgRequest)，缺 cmdId" },
            { "/DownloadVoice",            "下载语音数据",         "ready",   "字段表已备(DownloadVoiceRequest)，缺 cmdId" },
            { "/Voice2Text",               "语音转文字",           "blocked", "需 PB: GetVoiceTransResRequest" },
            { "/GetTransText",             "翻译文本",             "blocked", "需 PB: Translate*" },
            { "/AddtoEmoji",               "添加表情",             "blocked", "需 PB: EmojiUpload*" },
            { "/ChatRoomTopMsg",           "设置群置顶消息",       "ready",   "字段表已备(ChatRoomTopMsgRequest)，缺 cmdId" },
            { "/ChatRoomUnTopMsg",         "取消群置顶消息",       "ready",   "同上" },
            { "/Decode_Pic",               "解密dat图片",          "blocked", "HTTP 501 until decoder/key lifecycle is verified; no native call or success claim" },
            { "/wxcx/recv/*",              "接收回调/通知类/收文本/收语音", "ok", "INT3+VEH 探针 + 回调推送" },
            { "/wxcx/callback/*",          "回调配置与状态",       "ok",      "" },
            { "/wxcx/msg/recent",          "消息历史(MSG 表)",     "ok",      "只读，表名自动探测" },
            { "/IsLoginStatus",            "检查登录状态",         "ok",      "showdoc 002" },
            { "/GetContact",               "取群聊/好友信息",      "ok",      "Contact 表 + 成员(若 ChatRoom 表存在)" },
            { "/GetContacts",              "通讯录分页",           "ok",      "" },
            { "/QueryChatRoomMemberCount", "查询群成员数量",       "ok",      "Contact.MemberTotal" },
            { "/BatchGetContactBriefInfo", "批量获取联系人简要信息", "ok",     "showdoc 084" },
            { "/CheckFriendStatus",        "批量检测好友状态",     "partial", "local_only：被删判定需服务端" },
            { "/CreateChatRoom",           "创建群聊",             "ready",   "字段表已备，缺 cmdId + 提交入口" },
            { "/AddFriendToChatRoom",      "拉好友进群",           "ready",   "同上" },
            { "/ChatRoomMemberBatchDelete","批量移除群成员",       "ready",   "同上" },
            { "/setchatroomannouncement",  "发布群公告",           "ready",   "同上" },
            { "/wxcx/pb/*",                "PB 编解码 + dry-run",  "ok",      "8 种请求可编码；decode 可解任意报文" },
            { "/wxcx/probe/*",             "通用函数探针",         "partial", "schema 2：四寄存器、完整原始快照、丢弃计数；单步窗口可能漏命中" },
            { "/wxcx/verify/*",            "内存完整性自检",       "ok",      "4KB 块 CRC + 差异定位" },
            { "/wxcx/guard/*",             "反检测层",             "ok",      "API 层说谎 + 枚举遮蔽 + 通知过滤" },
        };

        json arr = json::array();
        int ok = 0, partial = 0, ready = 0, blocked = 0;
        for (const auto& c : caps)
        {
            json e;
            e["route"] = c.route;
            e["name"] = c.name;
            e["status"] = c.status;
            e["note"] = c.note;
            arr.push_back(e);

            std::string s = c.status;
            if (s == "ok") ok++;
            else if (s == "partial") partial++;
            else if (s == "ready") ready++;
            else if (s == "blocked") blocked++;
        }

        json out;
        out["total"] = (int)sizeof(caps) / (int)sizeof(caps[0]);
        json summary;
        summary["ok"] = ok;
        summary["partial"] = partial;
        summary["ready"] = ready;
        summary["blocked"] = blocked;
        out["summary"] = summary;
        out["blocker"] = "各接口依赖不同：PB 传输、CDN、对象布局和原生 ABI 均可能未完成；地址或 cmdId 不能单独证明可调用";
        out["how_to_unblock"] = "Forward 使用 capture_forward_suite.ps1 关联四类源消息、目标、身份尾部和版本证据；对象加载、调度与媒体路径确认后逐类型验收";
        out["items"] = arr;
        res.set_content(out.dump(2), "application/json");
    });

    // ---------- self check ----------
    svr.Get("/wxcx/health", [](const httplib::Request&, httplib::Response& res)
    {
        json j;
        j["login"] = (uint64_t)(wxcx::login::Detect() ? 1 : 0);
        j["weixin_dll"] = (uint64_t)(uintptr_t)g_hWeixinDll;
        j["start_port"] = g_StartPort;
        j["offset_check"] = json::parse(wxcx::OffsetsJson());
        res.set_content(j.dump(4), "application/json");
    });
}

// ---------------------------------------------------------------- offsets
std::string wxcx::OffsetsJson()
{
    json out;
    out["note"] = "in_range only proves the RVA lies inside the image, not that it is semantically right";

    if (!g_hWeixinDll)
    {
        out["status"] = "weixin_dll_not_loaded";
        return out.dump();
    }

    MODULEINFO mi{};
    ::GetModuleInformation(::GetCurrentProcess(), g_hWeixinDll, &mi, sizeof(mi));
    size_t imgSize = mi.SizeOfImage;
    out["image_size"] = (uint64_t)imgSize;

    struct Entry { const char* name; uint64_t rva; };
    static const Entry entries[] = {
        { "offset::send_message",        offset::send_message },
        { "offset::create_param2",       offset::create_param2 },
        { "offset::txt_message_ctr",     offset::txt_message_ctr },
        { "offset::txt_message_vtbl",    offset::txt_message_vtbl },
        { "offset::param1_vtable",       offset::param1_vtable },
        { "offset::param2",              offset::param2 },
        { "offset::param2_1",            offset::param2_1 },
        { "offset::param2_2",            offset::param2_2 },
        { "offset::param2_3",            offset::param2_3 },
        { "offset::img_msg_vtbl",        offset::img_msg_vtbl },
        { "offset::img_msg_vtb2",        offset::img_msg_vtb2 },
        { "offset::dec_pic_call",        offset::dec_pic_call },
    };

    json rows = json::array();
    bool all = true;
    for (const auto& e : entries)
    {
        json r;
        r["name"] = e.name;
        r["rva"] = Hex(e.rva);
        r["in_range"] = e.rva < imgSize;
        if (!r["in_range"].get<bool>()) all = false;
        rows.push_back(r);
    }

    out["entries"] = rows;
    out["status"] = all ? "all_in_range" : "some_out_of_range";
    return out.dump();
}
