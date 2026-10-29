// Database lookup evidence, not a verified WeChat 4.x forwarding identifier.
#include "wxcx_msgloc.h"
#include "wxcx_ids.h"
#include "httplib.h"
#include "json.hpp"
#include "../xdb/db_mgr.h"

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

using json = nlohmann::json;

namespace wxcx { namespace msgloc {
namespace {
bool QueryOn(const std::string& db, const std::string& sql, json& out)
{
    try
    {
        out = json::parse(xmgr::DatabaseMgr::getInstance().execute(db, sql).dump());
        return out.is_object() && out.contains("status") &&
               out["status"].is_number_integer() && out["status"] == 0;
    }
    catch (...) { return false; }
}

std::string Lower(std::string_view text)
{
    std::string s(text);
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

// Database table-name convention only, not a native message identifier.
std::string TalkerTable(const std::string& talker)
{
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_MD5_ALGORITHM, nullptr, 0) < 0) return {};
    unsigned char digest[16]{};
    const auto status = BCryptHash(algorithm, nullptr, 0,
        reinterpret_cast<PUCHAR>(const_cast<char*>(talker.data())), static_cast<ULONG>(talker.size()),
        digest, sizeof(digest));
    BCryptCloseAlgorithmProvider(algorithm, 0);
    if (status < 0) return {};
    std::string table = "msg_";
    constexpr char hex[] = "0123456789abcdef";
    for (auto value : digest) { table += hex[value >> 4]; table += hex[value & 15]; }
    return table;
}

bool HashedMessageTable(const std::string& table)
{
    return table.size() == 36 && table.rfind("msg_", 0) == 0 &&
        std::all_of(table.begin() + 4, table.end(), [](unsigned char c) { return std::isxdigit(c) != 0; });
}

std::vector<std::string> CandidateDbs(bool includeMedia)
{
    std::vector<std::string> out;
    try
    {
        for (const auto& kv : xmgr::DatabaseMgr::getInstance().searchDatabases())
        {
            const auto name = Lower(ids::Basename(kv.first));
            if (name.find("msg") == std::string::npos) continue;
            if (!includeMedia && name.find("mediamsg") != std::string::npos) continue;
            out.push_back(kv.first);
        }
    }
    catch (...) {}
    if (std::find(out.begin(), out.end(), "MicroMsg.db") == out.end())
        out.push_back("MicroMsg.db");
    return out;
}

std::string Hex(uint64_t value)
{
    std::ostringstream stream;
    stream << "0x" << std::hex << std::uppercase << std::setfill('0')
           << std::setw(16) << value;
    return stream.str();
}
}

Result Locate(uint64_t msgSvrId, bool includeMedia)
{
    Result r;
    r.msg_svr_id = msgSvrId;
    if (msgSvrId == 0)
    {
        r.detail = "invalid MsgSvrID: must be positive";
        return r;
    }
    const char* tables[] = { "MSG", "Message" };
    const char* idCols[] = { "localId", "rowid" };
    const char* svrCols[] = { "MsgSvrID", "msgSvrId" };
    bool invalidRow = false;
    for (const auto& db : CandidateDbs(includeMedia))
    for (const char* tbl : tables)
    for (const char* idc : idCols)
    for (const char* svc : svrCols)
    {
        // SQLite can compare an out-of-int64 numeric literal as REAL. Re-read
        // the server ID so a rounded or different ID can never count as a match.
        const std::string sql = "SELECT " + std::string(idc) +
            " AS wxcx_local_id, " + svc + " AS wxcx_msg_svr_id FROM " + tbl +
            " WHERE " + svc + "='" + std::to_string(msgSvrId) + "' LIMIT 1";
        json q;
        if (!QueryOn(db, sql, q) || !q.contains("data") ||
            !q["data"].is_array() || q["data"].empty()) continue;
        const auto& row = q["data"][0];
        uint64_t localId = 0, returnedSvrId = 0;
        if (!row.is_object() || !row.contains("wxcx_local_id") ||
            !ids::ParseLocalId(row["wxcx_local_id"], localId) ||
            !row.contains("wxcx_msg_svr_id") ||
            !ids::ParseUint64(row["wxcx_msg_svr_id"], returnedSvrId) ||
            returnedSvrId != msgSvrId)
        {
            invalidRow = true;
            continue;
        }
        r.found = true;
        r.db = db;
        r.table = tbl;
        r.id_col = idc;
        r.svr_col = svc;
        r.local_id = localId;
        uint32_t index = 0;
        if (ids::ParseDbIndexCandidate(db, index))
        {
            r.db_index_candidate = index;
            r.candidate_quad = (static_cast<uint64_t>(index) << 32) | localId;
            r.detail = "located database row; db_index_candidate is a filename-only hypothesis; "
                "candidate_quad is research-only (candidate << 32 | local_id). "
                "WeChat 4.x native ABI is unverified; db_idx and quad are null; "
                "candidate values must not be used for native calls";
        }
        else
        {
            r.detail = "located database row; basename is not an exact bounded MSG<number>.db; "
                "db_index_candidate and candidate_quad are null (unknown/ambiguous). "
                "WeChat 4.x native ABI is unverified; db_idx and quad are null";
        }
        return r;
    }
    r.detail = invalidRow
        ? "no valid match: rejected row with invalid/mismatched MsgSvrID or localId/rowid outside 1..UINT32_MAX"
        : "not found in any candidate db/table/column combination";
    return r;
}

UniqueResult LocateUnique(uint64_t msgSvrId, const std::string& sourceTalker, const std::function<bool()>& cancelled)
{
    UniqueResult result;
    if (!msgSvrId) { result.status = "invalid_message_id"; result.detail = "MsgSvrID must be positive"; return result; }
    auto quote = [](const std::string& value, char delimiter) {
        std::string out(1, delimiter);
        for (char c : value) { out += c; if (c == delimiter) out += c; }
        return out + delimiter;
    };
    std::vector<std::string> dbs;
    try {
        for (const auto& db : xmgr::DatabaseMgr::getInstance().searchDatabases()) dbs.push_back(db.first);
    } catch (...) { result.status = "database_unavailable"; result.detail = "Database discovery failed"; return result; }
    if (dbs.empty()) { result.status = "database_unavailable"; result.detail = "No message database is registered"; return result; }
    bool incomplete = dbs.size() > 128, recognized = false;
    const auto requestedTable = sourceTalker.empty() ? std::string{} : TalkerTable(sourceTalker);
    if (!sourceTalker.empty() && requestedTable.empty()) {
        result.status = "lookup_incomplete"; result.detail = "Cannot verify conversation table digest"; return result;
    }
    size_t inspected = 0;
    for (size_t d = 0; d < dbs.size() && d < 128; ++d) {
        if (cancelled && cancelled()) { result.status = "lookup_incomplete"; result.detail = "Source lookup cancelled between database operations"; return result; }
        const auto& db = dbs[d];
        json tables;
        if (!QueryOn(db, "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name", tables) ||
            !tables.contains("data") || !tables["data"].is_array()) { incomplete = true; continue; }
        bool hasNameIndex = false, checkedNameIndex = false, validNameIndex = false;
        for (const auto& item : tables["data"])
            if (item.is_object() && item.contains("name") && item["name"].is_string() &&
                Lower(item["name"].get<std::string>()) == "name2id") hasNameIndex = true;
        for (const auto& item : tables["data"]) {
            if (cancelled && cancelled()) { result.status = "lookup_incomplete"; result.detail = "Source lookup cancelled between schema operations"; return result; }
            if (!item.is_object() || !item.contains("name") || !item["name"].is_string()) { incomplete = true; continue; }
            const auto table = item["name"].get<std::string>();
            const auto lowerTable = Lower(table);
            if (++inspected > 4096 || table.find('\0') != std::string::npos) { incomplete = true; continue; }
            // Favorite and unread-index tables also contain server_id. Their
            // IDs belong to other namespaces and cannot establish source
            // message uniqueness or make a message lookup incomplete.
            if (lowerTable != "msg" && lowerTable != "message" && lowerTable.rfind("msg_", 0) != 0) continue;
            const bool scopedHashTable = !sourceTalker.empty() && HashedMessageTable(lowerTable);
            if (scopedHashTable && lowerTable != requestedTable) continue;
            if (scopedHashTable && !checkedNameIndex) {
                checkedNameIndex = true;
                json names;
                const auto sql = "SELECT user_name FROM Name2Id WHERE user_name=" + quote(sourceTalker, '\'') + " LIMIT 2";
                validNameIndex = hasNameIndex && QueryOn(db, sql, names) && names.contains("data") &&
                    names["data"].is_array() && names["data"].size() == 1 && names["data"][0].is_object() &&
                    names["data"][0].contains("user_name") && names["data"][0]["user_name"].is_string() &&
                    names["data"][0]["user_name"].get<std::string>() == sourceTalker;
            }
            if (scopedHashTable && !validNameIndex) { incomplete = true; continue; }
            json schema;
            if (!QueryOn(db, "PRAGMA table_info(" + quote(table, '"') + ")", schema) ||
                !schema.contains("data") || !schema["data"].is_array()) { incomplete = true; continue; }
            std::vector<std::string> columns;
            if (schema["data"].empty()) incomplete = true;
            for (const auto& c : schema["data"]) {
                if (c.is_object() && c.contains("name") && c["name"].is_string() && c["name"].get<std::string>().find('\0') == std::string::npos)
                    columns.push_back(c["name"].get<std::string>());
                else incomplete = true;
            }
            auto pick = [&](std::initializer_list<const char*> names) -> std::string {
                for (const auto* name : names) for (const auto& col : columns)
                    if (Lower(col) == Lower(name)) return col;
                return {};
            };
            const auto server = pick({"MsgSvrID", "server_id"});
            if (server.empty()) {
                // A recognizable message table with an unknown ID schema is
                // not evidence that the requested source is absent/unique.
                if (lowerTable == "msg" || lowerTable == "message" || lowerTable.rfind("msg_", 0) == 0) incomplete = true;
                continue;
            }
            recognized = true;
            auto local = pick({"localId", "local_id"});
            // rowid is a query fallback, not a verified native identifier.
            if (local.empty() && (lowerTable == "msg" || lowerTable == "message")) local = "rowid";
            const auto talker = pick({"strTalker", "talker"});
            const auto type = pick({"Type", "local_type"});
            const bool derivedTalker = talker.empty() && scopedHashTable && validNameIndex;
            if (server.empty() || local.empty() || (!sourceTalker.empty() && talker.empty() && !derivedTalker)) { incomplete = true; continue; }
            const std::string sql = "SELECT " + quote(local, '"') + " AS wxcx_local_id, " + quote(server, '"') +
                " AS wxcx_msg_svr_id, " + (derivedTalker ? quote(sourceTalker, '\'') : talker.empty() ? "NULL" : quote(talker, '"')) +
                " AS wxcx_talker, " + (type.empty() ? "NULL" : quote(type, '"')) +
                " AS wxcx_raw_type FROM " + quote(table, '"') + " WHERE " + quote(server, '"') +
                "=" + quote(std::to_string(msgSvrId), '\'') + (sourceTalker.empty() || derivedTalker ? "" : " AND " + quote(talker, '"') + "=" + quote(sourceTalker, '\'')) + " LIMIT 2";
            json rows;
            if (!QueryOn(db, sql, rows) || !rows.contains("data") || !rows["data"].is_array()) { incomplete = true; continue; }
            for (const auto& row : rows["data"]) {
                UniqueMatch match; match.db = db; match.table = table;
                if (!row.is_object() || !row.contains("wxcx_local_id") || !row.contains("wxcx_msg_svr_id") ||
                    !ids::ParseUint64(row["wxcx_local_id"], match.local_id) || !match.local_id ||
                    !ids::ParseUint64(row["wxcx_msg_svr_id"], match.msg_svr_id) || match.msg_svr_id != msgSvrId) { incomplete = true; continue; }
                if (row.contains("wxcx_talker") && row["wxcx_talker"].is_string()) match.talker = row["wxcx_talker"].get<std::string>();
                if (!sourceTalker.empty() && match.talker != sourceTalker) { incomplete = true; continue; }
                if (row.contains("wxcx_raw_type") && !row["wxcx_raw_type"].is_null())
                    match.raw_type = row["wxcx_raw_type"].is_string() ? row["wxcx_raw_type"].get<std::string>() : row["wxcx_raw_type"].dump();
                if (result.matches.size() < 128) result.matches.push_back(std::move(match));
                else incomplete = true;
            }
        }
    }
    result.complete = !incomplete && recognized;
    result.status = result.matches.size() > 1 ? "ambiguous" : !result.complete ? "lookup_incomplete" :
        result.matches.empty() ? "not_found" : "found";
    result.detail = result.status == "found" ? "Unique database evidence; native object loading remains unverified" :
        result.status == "ambiguous" ? "Multiple records match; provide source_talker or resolve duplicated database evidence" :
        result.status == "not_found" ? "No matching record in inspected message tables" : "Not all message schemas/rows could be verified";
    return result;
}

void RegisterRoutes(httplib::Server& svr)
{
    svr.Post("/wxcx/db/locate_unique", [](const httplib::Request& req, httplib::Response& res) {
        json input; uint64_t id = 0; std::string talker;
        try {
            input = json::parse(req.body);
            if (!input.is_object() || !input.contains("msgsvrid") || !ids::ParseUint64(input["msgsvrid"], id) || !id)
                throw std::invalid_argument("msgsvrid must be a positive uint64 decimal string or JSON integer");
            if (input.contains("source_talker")) {
                if (!input["source_talker"].is_string()) throw std::invalid_argument("source_talker must be a string");
                talker = input["source_talker"].get<std::string>();
                if (talker.empty() || talker.size() > 256 || talker.find('\0') != std::string::npos)
                    throw std::invalid_argument("invalid source_talker");
                for (unsigned char c : talker) if (c < 32 || c == 127) throw std::invalid_argument("invalid source_talker");
            }
        } catch (const std::exception& e) {
            res.status = 400; res.set_content(json({{"code", "-1"}, {"msg", e.what()}}).dump(), "application/json"); return;
        }
        const auto found = LocateUnique(id, talker);
        json matches = json::array();
        for (const auto& m : found.matches) matches.push_back({{"db", m.db}, {"table", m.table},
            {"local_id_decimal", std::to_string(m.local_id)}, {"msg_svr_id_decimal", std::to_string(m.msg_svr_id)},
            {"talker", m.talker}, {"raw_type", m.raw_type}});
        res.set_content(json({{"code", found.status == "found" ? "0" : "-1"}, {"status", found.status},
            {"complete", found.complete}, {"matches", matches}, {"detail", found.detail}, {"native_abi_verified", false}}).dump(), "application/json");
    });
    svr.Post("/wxcx/db/locate", [](const httplib::Request& req, httplib::Response& res)
    {
        auto badRequest = [&](const char* detail)
        {
            res.status = 400;
            res.set_content(json({{"code", "-1"}, {"msg", detail}}).dump(), "application/json");
        };
        json in;
        try { in = json::parse(req.body); }
        catch (const json::exception&) { badRequest("malformed JSON"); return; }
        if (!in.is_object()) { badRequest("request must be a JSON object"); return; }
        uint64_t id = 0;
        bool hasId = false;
        // Validate both aliases if supplied, rejecting conflicting values.
        for (const char* key : { "msgid", "msgsvrid" })
        {
            if (!in.contains(key)) continue;
            uint64_t parsed = 0;
            if (!ids::ParseUint64(in[key], parsed) || parsed == 0 || (hasId && parsed != id))
            {
                badRequest("msgid/msgsvrid must be matching positive uint64 decimal strings or JSON integers");
                return;
            }
            id = parsed;
            hasId = true;
        }
        if (!hasId) { badRequest("msgid or msgsvrid is required"); return; }
        bool includeMedia = false;
        if (in.contains("include_media"))
        {
            if (!in["include_media"].is_boolean())
            { badRequest("include_media must be a boolean"); return; }
            includeMedia = in["include_media"].get<bool>();
        }

        const Result r = Locate(id, includeMedia);
        json out = {
            {"code", r.found ? "0" : "-1"}, {"found", r.found},
            {"msg_svr_id", r.msg_svr_id}, {"msg_svr_id_decimal", std::to_string(r.msg_svr_id)},
            {"detail", r.detail}, {"quad_verified", r.quad_verified},
            {"native_abi_verified", r.native_abi_verified},
            {"db_idx", nullptr}, {"quad", nullptr}, {"db_index_candidate", nullptr},
            {"candidate_quad_hex", nullptr}, {"candidate_quad_decimal", nullptr}
        };
        if (r.found)
        {
            out["db"] = r.db;
            out["table"] = r.table;
            out["id_column"] = r.id_col;
            out["svr_column"] = r.svr_col;
            out["local_id"] = r.local_id;
            out["local_id_decimal"] = std::to_string(r.local_id);
            if (r.db_index_candidate) out["db_index_candidate"] = *r.db_index_candidate;
            if (r.candidate_quad)
            {
                out["candidate_quad_hex"] = Hex(*r.candidate_quad);
                out["candidate_quad_decimal"] = std::to_string(*r.candidate_quad);
            }
        }
        res.set_content(out.dump(), "application/json");
    });
}
} }
