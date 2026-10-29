// wxcx_pb.cpp - minimal protobuf wire codec + request builders
//
// Purpose: turn the field tables recovered statically (docs/STATIC_ANALYSIS.md §6)
// into something usable:
//   * build CreateChatRoom / AddChatRoomMember / DelChatRoomMember request bodies
//     before we know the transport (cmdId + mars Task) — the bytes are correct
//     independently of how they are sent;
//   * decode any captured protobuf body back into a field tree, so a single
//     dynamic capture can be turned into a field list without hand tools.
//
// No dependency on WeChat internals: pure wire format.

#include "wxcx_pb.h"

#include "httplib.h"
#include "json.hpp"

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

using json = nlohmann::json;

namespace wxcx
{
namespace pb
{
namespace
{
    constexpr size_t kMaxDepth = 8;
    constexpr size_t kMaxItems = 512;

    // ------------------------------------------------------------ writer
    struct Writer
    {
        std::string out;

        void Varint(uint64_t v)
        {
            while (v >= 0x80)
            {
                out.push_back((char)((v & 0x7F) | 0x80));
                v >>= 7;
            }
            out.push_back((char)v);
        }

        void Tag(uint32_t field, uint32_t wire)
        {
            Varint(((uint64_t)field << 3) | wire);
        }

        void UInt(uint32_t field, uint64_t v)
        {
            Tag(field, 0);
            Varint(v);
        }

        void Fixed64(uint32_t field, uint64_t v)
        {
            Tag(field, 1);
            for (int i = 0; i < 8; ++i) out.push_back((char)((v >> (8 * i)) & 0xFF));
        }

        void Fixed32(uint32_t field, uint32_t v)
        {
            Tag(field, 5);
            for (int i = 0; i < 4; ++i) out.push_back((char)((v >> (8 * i)) & 0xFF));
        }

        void Bytes(uint32_t field, const std::string& s)
        {
            Tag(field, 2);
            Varint(s.size());
            out.append(s);
        }
    };

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

    bool FromHex(const std::string& hex, std::string& out)
    {
        auto nib = [](char c) -> int
        {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        out.clear();
        if (hex.size() % 2) return false;
        for (size_t i = 0; i + 1 < hex.size(); i += 2)
        {
            int a = nib(hex[i]), b = nib(hex[i + 1]);
            if (a < 0 || b < 0) return false;
            out.push_back((char)((a << 4) | b));
        }
        return true;
    }

    // ------------------------------------------------------------ reader
    struct Reader
    {
        const std::string& d;
        size_t i = 0;
        bool ok = true;

        explicit Reader(const std::string& s) : d(s) {}

        bool Eof() const { return i >= d.size(); }

        uint64_t Varint()
        {
            uint64_t v = 0;
            int shift = 0;
            while (i < d.size() && shift < 64)
            {
                uint8_t b = (uint8_t)d[i++];
                v |= (uint64_t)(b & 0x7F) << shift;
                if (!(b & 0x80)) return v;
                shift += 7;
            }
            ok = false;
            return 0;
        }

        bool Bytes(std::string& out, size_t n)
        {
            if (i + n > d.size()) { ok = false; return false; }
            out.assign(d, i, n);
            i += n;
            return true;
        }
    };

    bool LooksTextual(const std::string& s)
    {
        if (s.empty()) return false;
        size_t printable = 0;
        for (unsigned char c : s)
        {
            if (c >= 0x20 && c < 0x7F) printable++;
            else if (c == '\n' || c == '\r' || c == '\t') printable++;
            else if (c >= 0x80) printable++;          // UTF-8 中文
            else return false;
        }
        return printable * 100 / s.size() >= 90;
    }

    json DecodeFields(const std::string& body, size_t depth, size_t& budget);

    // 尝试把 length-delimited 内容当作子消息解析；失败则当字符串
    json DecodeNested(const std::string& s, size_t depth, size_t& budget)
    {
        if (depth < kMaxDepth && !s.empty())
        {
            json sub = DecodeFields(s, depth + 1, budget);
            if (sub.is_array() && sub.size() > 0 && budget > 0)
            {
                json wrapped;
                wrapped["nested"] = sub;
                return wrapped;
            }
        }
        if (LooksTextual(s))
        {
            json j;
            j["str"] = s.size() > 512 ? s.substr(0, 512) : s;
            if (s.size() > 512) j["truncated"] = true;
            return j;
        }
        json j;
        j["hex"] = ToHex(s.size() > 128 ? s.substr(0, 128) : s);
        j["size"] = s.size();
        return j;
    }

    json DecodeFields(const std::string& body, size_t depth, size_t& budget)
    {
        json arr = json::array();
        Reader r(body);
        if (!r.ok) return json();

        while (!r.Eof() && r.ok && budget > 0 && arr.size() < kMaxItems)
        {
            uint64_t key = r.Varint();
            if (!r.ok) break;
            uint32_t field = (uint32_t)(key >> 3);
            uint32_t wire = (uint32_t)(key & 7);
            if (field == 0) { r.ok = false; break; }

            json e;
            e["f"] = field;

            switch (wire)
            {
            case 0:
                e["varint"] = r.Varint();
                break;
            case 1:
            {
                std::string b;
                if (!r.Bytes(b, 8)) return json();
                uint64_t v = 0;
                for (int k = 0; k < 8; ++k) v |= (uint64_t)(uint8_t)b[k] << (8 * k);
                e["fixed64"] = v;
                break;
            }
            case 2:
            {
                uint64_t len = r.Varint();
                if (!r.ok || len > body.size()) return json();
                std::string b;
                if (!r.Bytes(b, (size_t)len)) return json();
                e["len"] = len;
                e["value"] = DecodeNested(b, depth, budget);
                break;
            }
            case 5:
            {
                std::string b;
                if (!r.Bytes(b, 4)) return json();
                uint32_t v = 0;
                for (int k = 0; k < 4; ++k) v |= (uint32_t)(uint8_t)b[k] << (8 * k);
                e["fixed32"] = v;
                break;
            }
            default:
                e["wire"] = wire;
                e["unsupported"] = true;
                r.ok = false;
                break;
            }
            arr.push_back(e);
            budget--;
        }
        if (!r.ok) return json();
        return arr;
    }

    // ------------------------------------------------------- 通用构造器
    // 字段表来源：docs/STATIC_ANALYSIS.md §6 / §10（序列化函数立即数）
    enum Kind { K_VARINT = 0, K_BYTES = 1, K_FIXED64 = 2 };

    struct FieldSpec
    {
        int  no;
        Kind kind;
        bool repeated;
    };

    // 从 {"f1":"..","f2":123,...} 或 {"f7":["a","b"]} 构造
    std::string BuildBySpec(const json& in, const std::vector<FieldSpec>& spec)
    {
        Writer w;
        for (const auto& s : spec)
        {
            std::string key = "f" + std::to_string(s.no);
            if (!in.contains(key)) continue;
            const json& v = in[key];

            if (s.repeated && v.is_array())
            {
                for (const auto& e : v)
                {
                    if (e.is_string()) w.Bytes((uint32_t)s.no, e.get<std::string>());
                    else if (e.is_number_unsigned()) w.UInt((uint32_t)s.no, e.get<uint64_t>());
                    else if (e.is_number_integer())
                    {
                        auto n = e.get<long long>();
                        if (n >= 0) w.UInt((uint32_t)s.no, (uint64_t)n);
                    }
                }
                continue;
            }

            switch (s.kind)
            {
            case K_BYTES:
                if (v.is_string()) w.Bytes((uint32_t)s.no, v.get<std::string>());
                break;
            case K_VARINT:
                if (v.is_number_unsigned()) w.UInt((uint32_t)s.no, v.get<uint64_t>());
                else if (v.is_number_integer())
                {
                    auto n = v.get<long long>();
                    if (n >= 0) w.UInt((uint32_t)s.no, (uint64_t)n);
                }
                break;
            case K_FIXED64:
                if (v.is_number_unsigned()) w.Fixed64((uint32_t)s.no, v.get<uint64_t>());
                else if (v.is_number_integer())
                {
                    auto n = v.get<long long>();
                    if (n >= 0) w.Fixed64((uint32_t)s.no, (uint64_t)n);
                }
                break;
            }
        }
        return w.out;
    }

    const std::vector<FieldSpec>& SpecAnnouncement()
    {
        static const std::vector<FieldSpec> s = {
            { 1, K_BYTES, false }, { 2, K_FIXED64, false }, { 3, K_FIXED64, false },
            { 4, K_VARINT, false }, { 5, K_FIXED64, false }, { 6, K_VARINT, false },
            { 7, K_BYTES, true },   { 8, K_VARINT, false },
        };
        return s;
    }

    const std::vector<FieldSpec>& SpecTopMsg()
    {
        static const std::vector<FieldSpec> s = {
            { 1, K_BYTES, false }, { 2, K_FIXED64, false }, { 3, K_VARINT, false },
            { 5, K_VARINT, false }, { 6, K_FIXED64, false }, { 7, K_FIXED64, false },
            { 8, K_BYTES, false },
        };
        return s;
    }

    const std::vector<FieldSpec>& SpecRevoke()
    {
        static const std::vector<FieldSpec> s = {
            { 1, K_BYTES, false }, { 2, K_FIXED64, false }, { 3, K_VARINT, false },
            { 4, K_VARINT, false }, { 5, K_VARINT, false }, { 6, K_FIXED64, false },
            { 7, K_FIXED64, false }, { 8, K_VARINT, false },
        };
        return s;
    }

    const std::vector<FieldSpec>& SpecPat()
    {
        static const std::vector<FieldSpec> s = {
            { 1, K_BYTES, false }, { 2, K_FIXED64, false }, { 3, K_FIXED64, false },
            { 4, K_FIXED64, false }, { 5, K_FIXED64, false }, { 6, K_VARINT, false },
        };
        return s;
    }

    const std::vector<FieldSpec>& SpecDownloadVoice()
    {
        static const std::vector<FieldSpec> s = {
            { 1, K_VARINT, false }, { 2, K_VARINT, false }, { 3, K_VARINT, false },
            { 4, K_FIXED64, false }, { 5, K_BYTES, false }, { 7, K_FIXED64, false },
        };
        return s;
    }

    std::string GetStr(const json& j, const char* k)
    {
        return (j.contains(k) && j[k].is_string()) ? j[k].get<std::string>() : std::string();
    }

    std::vector<std::string> GetStrList(const json& j, const char* k)
    {
        std::vector<std::string> out;
        if (j.contains(k) && j[k].is_array())
            for (const auto& v : j[k])
                if (v.is_string()) out.push_back(v.get<std::string>());
        return out;
    }

    uint64_t GetU64(const json& j, const char* k, uint64_t def = 0)
    {
        if (j.contains(k) && j[k].is_number_unsigned()) return j[k].get<uint64_t>();
        if (j.contains(k) && j[k].is_number_integer())
        {
            auto v = j[k].get<long long>();
            return v < 0 ? 0 : (uint64_t)v;
        }
        return def;
    }
}

    // CreateChatRoomRequest: 1=LEN, 2=LEN, 3=VARINT, 4=repeated LEN
    std::string BuildCreateChatRoom(const json& in)
    {
        Writer w;
        std::string f1 = GetStr(in, "gname");
        std::string f2 = GetStr(in, "field2");
        uint64_t f3 = GetU64(in, "field3", 0);
        auto members = GetStrList(in, "wxidlist");

        if (!f1.empty()) w.Bytes(1, f1);
        if (!f2.empty()) w.Bytes(2, f2);
        if (f3) w.UInt(3, f3);
        for (const auto& m : members) w.Bytes(4, m);
        return w.out;
    }

    // AddChatRoomMemberRequest: 1=LEN 2=VARINT 3=rep LEN 4=LEN 5=VARINT 6=64bit 7=LEN
    std::string BuildAddChatRoomMember(const json& in)
    {
        Writer w;
        std::string gid = GetStr(in, "gid");
        auto members = GetStrList(in, "wxidlist");
        uint64_t f2 = GetU64(in, "field2", 0);
        std::string f4 = GetStr(in, "field4");
        uint64_t f5 = GetU64(in, "field5", 0);
        uint64_t f6 = GetU64(in, "field6", 0);
        std::string f7 = GetStr(in, "field7");

        if (!gid.empty()) w.Bytes(1, gid);
        if (f2) w.UInt(2, f2);
        for (const auto& m : members) w.Bytes(3, m);
        if (!f4.empty()) w.Bytes(4, f4);
        if (f5) w.UInt(5, f5);
        if (f6) w.Fixed64(6, f6);
        if (!f7.empty()) w.Bytes(7, f7);
        return w.out;
    }

    std::string BuildSetChatRoomAnnouncement(const json& in)
    {
        return BuildBySpec(in, SpecAnnouncement());
    }

    std::string BuildChatRoomTopMsg(const json& in)
    {
        return BuildBySpec(in, SpecTopMsg());
    }

    std::string BuildRevokeMsg(const json& in)
    {
        return BuildBySpec(in, SpecRevoke());
    }

    std::string BuildSendPat(const json& in)
    {
        return BuildBySpec(in, SpecPat());
    }

    std::string BuildDownloadVoice(const json& in)
    {
        return BuildBySpec(in, SpecDownloadVoice());
    }
    // DelChatRoomMemberRequest: 1=LEN 2=VARINT 3=rep LEN 4=64bit 5=VARINT
    std::string BuildDelChatRoomMember(const json& in)
    {
        Writer w;
        std::string gid = GetStr(in, "gid");
        auto members = GetStrList(in, "wxidlist");
        uint64_t f2 = GetU64(in, "field2", 0);
        uint64_t f4 = GetU64(in, "field4", 0);
        uint64_t f5 = GetU64(in, "field5", 0);

        if (!gid.empty()) w.Bytes(1, gid);
        if (f2) w.UInt(2, f2);
        for (const auto& m : members) w.Bytes(3, m);
        if (f4) w.Fixed64(4, f4);
        if (f5) w.UInt(5, f5);
        return w.out;
    }

    void RegisterRoutes(httplib::Server& svr)
    {
        auto readJson = [](const httplib::Request& req, json& out, httplib::Response& res) -> bool
        {
            if (req.body.empty()) { out = json::object(); return true; }
            try { out = json::parse(req.body); return true; }
            catch (...)
            {
                res.status = 400;
                res.set_content("{\"code\":\"-1\",\"msg\":\"invalid json\"}", "application/json");
                return false;
            }
        };

        auto emit = [](httplib::Response& res, const std::string& body)
        {
            json j;
            j["hex"] = ToHex(body);
            j["len"] = body.size();
            res.set_content(j.dump(), "application/json");
        };

        svr.Post("/wxcx/pb/CreateChatRoomRequest", [readJson, emit](const httplib::Request& req, httplib::Response& res)
        {
            json in;
            if (!readJson(req, in, res)) return;
            emit(res, BuildCreateChatRoom(in));
        });

        svr.Post("/wxcx/pb/AddChatRoomMemberRequest", [readJson, emit](const httplib::Request& req, httplib::Response& res)
        {
            json in;
            if (!readJson(req, in, res)) return;
            emit(res, BuildAddChatRoomMember(in));
        });

        svr.Post("/wxcx/pb/DelChatRoomMemberRequest", [readJson, emit](const httplib::Request& req, httplib::Response& res)
        {
            json in;
            if (!readJson(req, in, res)) return;
            emit(res, BuildDelChatRoomMember(in));
        });

        svr.Post("/wxcx/pb/SetChatRoomAnnouncementRequest", [readJson, emit](const httplib::Request& req, httplib::Response& res)
        {
            json in; if (!readJson(req, in, res)) return;
            emit(res, BuildSetChatRoomAnnouncement(in));
        });

        svr.Post("/wxcx/pb/ChatRoomTopMsgRequest", [readJson, emit](const httplib::Request& req, httplib::Response& res)
        {
            json in; if (!readJson(req, in, res)) return;
            emit(res, BuildChatRoomTopMsg(in));
        });

        svr.Post("/wxcx/pb/RevokeMsgRequest", [readJson, emit](const httplib::Request& req, httplib::Response& res)
        {
            json in; if (!readJson(req, in, res)) return;
            emit(res, BuildRevokeMsg(in));
        });

        svr.Post("/wxcx/pb/SendPatRequest", [readJson, emit](const httplib::Request& req, httplib::Response& res)
        {
            json in; if (!readJson(req, in, res)) return;
            emit(res, BuildSendPat(in));
        });

        svr.Post("/wxcx/pb/DownloadVoiceRequest", [readJson, emit](const httplib::Request& req, httplib::Response& res)
        {
            json in; if (!readJson(req, in, res)) return;
            emit(res, BuildDownloadVoice(in));
        });
        // 半成品发送：默认 dry-run，只回显将发送的 body 与 cmdId 占位。
        // 拿到 cmdId 与 mars 提交入口后，把这里替换成真实提交即可。
        svr.Post("/wxcx/pb/send", [readJson, emit](const httplib::Request& req, httplib::Response& res)
        {
            json in;
            if (!readJson(req, in, res)) return;

            std::string type = in.value("type", std::string());
            json params = (in.contains("params") && in["params"].is_object())
                              ? in["params"] : json::object();

            std::string body;
            if (type == "CreateChatRoom")               body = BuildCreateChatRoom(params);
            else if (type == "AddChatRoomMember")       body = BuildAddChatRoomMember(params);
            else if (type == "DelChatRoomMember")       body = BuildDelChatRoomMember(params);
            else if (type == "SetChatRoomAnnouncement") body = BuildSetChatRoomAnnouncement(params);
            else if (type == "ChatRoomTopMsg")          body = BuildChatRoomTopMsg(params);
            else if (type == "RevokeMsg")               body = BuildRevokeMsg(params);
            else if (type == "SendPat")                 body = BuildSendPat(params);
            else if (type == "DownloadVoice")           body = BuildDownloadVoice(params);

            json out;
            out["dry_run"] = true;
            out["type"] = type;
            out["body_len"] = body.size();
            out["body_hex"] = ToHex(body);
            out["cmd_id"] = nullptr;                 // 未知：等 probe 抓取
            out["blocked_by"] = "cmdId + mars Task submit address";
            if (type.empty()) out["error"] = "type required";
            else if (body.empty()) out["warning"] = "empty body: check params";
            res.set_content(out.dump(), "application/json");
        });

        // 自检：用固定样例编码再解码，返回两侧结果（无需真机即可验证实现）
        svr.Get("/wxcx/pb/selftest", [](const httplib::Request&, httplib::Response& res)
        {
            json sample;
            sample["gname"] = "A";
            sample["wxidlist"] = json::array({ "B" });

            std::string body = BuildCreateChatRoom(sample);

            size_t budget = kMaxItems;
            json fields = DecodeFields(body, 0, budget);

            json out;
            out["sample"] = sample;
            out["hex"] = ToHex(body);
            out["expected_hex"] = "0A0141220142";   // field1="A", field4="B"
            out["match_expected"] = (ToHex(body) == "0A0141220142");
            out["decoded"] = fields.is_null() ? json::array() : fields;
            out["roundtrip_ok"] = fields.is_array() && fields.size() == 2;
            res.set_content(out.dump(), "application/json");
        });

        // 解码任意 protobuf 报文：{"hex":"0A03..."} → 字段树
        svr.Post("/wxcx/pb/decode", [](const httplib::Request& req, httplib::Response& res)
        {
            json in;
            if (!req.body.empty())
            {
                try { in = json::parse(req.body); }
                catch (...)
                {
                    res.status = 400;
                    res.set_content("{\"code\":\"-1\",\"msg\":\"invalid json\"}", "application/json");
                    return;
                }
            }
            std::string body;
            if (!FromHex(in.value("hex", std::string()), body))
            {
                res.status = 400;
                res.set_content("{\"code\":\"-1\",\"msg\":\"invalid hex\"}", "application/json");
                return;
            }
            size_t budget = kMaxItems;
            json fields = DecodeFields(body, 0, budget);
            json out;
            out["ok"] = !fields.is_null();
            out["size"] = body.size();
            out["fields"] = fields.is_null() ? json::array() : fields;
            out["budget_left"] = budget;
            res.set_content(out.dump(), "application/json");
        });
    }

} // namespace pb
} // namespace wxcx
