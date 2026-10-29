// Offline tests: actual locator + actual HTTP route, in-memory HTTP transport
// and a DB adapter with DatabaseMgr's real string-valued-row representation.
// No sockets, WeChat process, native ABI, sqlite runtime or network are used.
#include "httplib.h"
#include "json.hpp"
#include "wxcx_ids.h"
#include "wxcx_msgloc.h"
#include "../xdb/db_mgr.h"
#include <iostream>
#include <stdexcept>
#include <utility>
#include <algorithm>

using json = nlohmann::json;
using ordered_json = nlohmann::ordered_json;
namespace {
int checks = 0;
void Check(bool ok, const char* expression, int line)
{
    ++checks;
    if (!ok) throw std::runtime_error(std::string("line ") + std::to_string(line) + ": " + expression);
}
#define CHECK(...) Check((__VA_ARGS__), #__VA_ARGS__, __LINE__)

std::map<std::string, LPVOID> databases;
std::vector<std::pair<std::string, std::string>> queries;
std::function<ordered_json(const std::string&, const std::string&)> execute;

ordered_json Empty() { return {{"status", 0}, {"data", ordered_json::array()}}; }
ordered_json Row(const json& local, const json& server)
{
    return {{"status", 0}, {"data", ordered_json::array({
        {{"wxcx_local_id", local}, {"wxcx_msg_svr_id", server}}
    })}};
}
void Fixture(const std::string& db, const json& local, const json& server,
             const std::string& column = "localId")
{
    databases = {{db, nullptr}};
    queries.clear();
    execute = [=](const std::string& name, const std::string& sql)
    {
        if (name != db || sql.find("SELECT " + column + " AS ") != 0) return Empty();
        return Row(local, server);
    };
}

class OfflineServer : public httplib::Server
{
public:
    std::pair<int, json> PostBody(const std::string& body, const std::string& path = "/wxcx/db/locate")
    {
        const std::string request = "POST " + path + " HTTP/1.1\r\nHost: offline\r\n"
            "Content-Type: application/json\r\nContent-Length: " + std::to_string(body.size()) +
            "\r\nConnection: close\r\n\r\n" + body;
        httplib::detail::BufferStream stream;
        stream.write(request.data(), request.size());
        bool closed = false;
        CHECK(process_request(stream, true, closed, {}));
        const auto response = stream.get_buffer().substr(request.size());
        CHECK(response.find("HTTP/1.1 ") == 0);
        const int status = std::stoi(response.substr(9, 3));
        const auto split = response.find("\r\n\r\n");
        CHECK(split != std::string::npos);
        return {status, json::parse(response.substr(split + 4))};
    }
};

void TestNumbers()
{
    const auto max = (std::numeric_limits<uint64_t>::max)();
    for (const auto& item : std::vector<std::pair<json, uint64_t>>{
        {"0", 0}, {"00042", 42}, {"9007199254740993", 9007199254740993ULL},
        {"18446744073709551615", max}, {json(uint64_t(max)), max},
        {json::parse("18446744073709551615"), max},
        {json::parse("9007199254740993"), 9007199254740993ULL},
        {json(int64_t(17)), 17}, {json(uint64_t(0)), 0}})
    {
        uint64_t out = 99;
        CHECK(wxcx::ids::ParseUint64(item.first, out));
        CHECK(out == item.second);
    }
    for (const auto& value : std::vector<json>{
        "", " ", " 1", "1 ", "+1", "-1", "-0", "1x", "0x10", "1.0", "1e3",
        "18446744073709551616", "9999999999999999999999999999999999999",
        std::string("12\0junk", 7), json(-1), json(int64_t(-9223372036854775807LL - 1)),
        json(1.0), json(-0.0), json(1e20), json::parse("18446744073709551616"),
        true, nullptr, json::array({1}), json::object({{"x", 1}})})
    {
        uint64_t out = 77;
        CHECK(!wxcx::ids::ParseUint64(value, out));
        CHECK(out == 77);
    }
    uint64_t out = 0;
    CHECK(wxcx::ids::ParseUint64(ordered_json("18446744073709551615"), out));
    CHECK(out == max);
    CHECK(wxcx::ids::ParseLocalId(json("4294967295"), out));
    CHECK(out == 4294967295ULL);
    for (const auto& value : std::vector<json>{"0", 0, -1, 1.0, "4294967296", "18446744073709551615"})
        CHECK(!wxcx::ids::ParseLocalId(value, out));
}

void TestNames()
{
    for (const auto& item : std::vector<std::pair<std::string, uint32_t>>{
        {"MSG0.db", 0}, {"MSG12.db", 12}, {"MSG4294967295.db", 4294967295U},
        {R"(F:\weixin_4.1.10.27\user123\MSG12.db)", 12},
        {"/v4.1.10.27/user123/MSG0.db", 0}})
    {
        uint32_t index = 99;
        CHECK(wxcx::ids::ParseDbIndexCandidate(item.first, index));
        CHECK(index == item.second);
    }
    for (const auto& name : {"MSG.db", "MicroMsg.db", "MediaMSG0.db", "MSG-1.db",
        "MSG+1.db", "MSG12.db.bak", "prefixMSG12.db", "MSG12x.db", "MSG4294967296.db",
        "MSG999999999999999999999999.db", "MSG00000000000.db", "MSG1.2.db",
        R"(F:\weixin_4.1.10.27\MSG.db)", R"(F:\weixin_4.1.10.27\MediaMSG12.db)",
        R"(F:\MSG12.db\MicroMsg.db)", "MSG12.db/"})
    {
        uint32_t index = 77;
        CHECK(!wxcx::ids::ParseDbIndexCandidate(name, index));
        CHECK(index == 77);
    }
}

void TestLocator()
{
    constexpr uint64_t server = 9007199254740993ULL;
    // All returned columns are strings, matching xdb/db_mgr.cpp execute.
    Fixture("MSG12.db", "12345", "9007199254740993");
    auto r = wxcx::msgloc::Locate(server);
    CHECK(r.found && r.local_id == 12345 && r.msg_svr_id == server);
    CHECK(r.db_index_candidate && *r.db_index_candidate == 12);
    CHECK(r.candidate_quad && *r.candidate_quad == ((12ULL << 32) | 12345));
    CHECK(!r.db_idx && !r.quad && !r.quad_verified && !r.native_abi_verified);
    CHECK(queries.front().second.find("='9007199254740993' LIMIT 1") != std::string::npos);

    Fixture("MSG0.db", "4294967295", "18446744073709551615", "rowid");
    r = wxcx::msgloc::Locate((std::numeric_limits<uint64_t>::max)());
    CHECK(r.found && r.local_id == 4294967295ULL && r.id_col == "rowid");
    CHECK(r.db_index_candidate && *r.db_index_candidate == 0);
    CHECK(r.candidate_quad && *r.candidate_quad == 4294967295ULL);

    Fixture("MSG4294967295.db", "4294967295", "1");
    r = wxcx::msgloc::Locate(1);
    CHECK(r.candidate_quad && *r.candidate_quad == (std::numeric_limits<uint64_t>::max)());

    for (const char* column : {"localId", "rowid"})
    for (const auto& value : std::vector<json>{"0", 0, "-1", -1, "1.0", 1.0,
        "4294967296", "18446744073709551615", "18446744073709551616", "42junk", nullptr})
    {
        Fixture("MSG0.db", value, "1", column);
        r = wxcx::msgloc::Locate(1);
        CHECK(!r.found && r.local_id == 0 && !r.candidate_quad);
        CHECK(r.detail.find("rejected row") != std::string::npos);
    }
    for (const auto& value : std::vector<json>{"9007199254740992", "18446744073709551616",
        -1, 9007199254740992.0, nullptr})
    {
        Fixture("MSG0.db", "17", value);
        CHECK(!wxcx::msgloc::Locate(server).found);
    }
    Fixture("MSG12.db", json(int64_t(42)), json(uint64_t(server)));
    CHECK(wxcx::msgloc::Locate(server).local_id == 42);

    Fixture(R"(F:\weixin_4.1.10.27\123\MSG12.db)", "42", "1");
    r = wxcx::msgloc::Locate(1);
    CHECK(r.db_index_candidate && *r.db_index_candidate == 12);
    for (const auto& name : {"MSG.db", "MicroMsg.db", "MSG4294967296.db"})
    {
        Fixture(name, "42", "1");
        r = wxcx::msgloc::Locate(1);
        CHECK(r.found && !r.db_index_candidate && !r.candidate_quad);
        CHECK(r.detail.find("unknown/ambiguous") != std::string::npos);
    }

    Fixture(R"(F:\weixin_4.1.10.27\MediaMSG12.db)", "42", "1");
    CHECK(!wxcx::msgloc::Locate(1).found);
    for (const auto& q : queries) CHECK(q.first.find("MediaMSG") == std::string::npos);
    r = wxcx::msgloc::Locate(1, true);
    CHECK(r.found && !r.db_index_candidate && !r.candidate_quad && !r.quad_verified);
    queries.clear();
    CHECK(!wxcx::msgloc::Locate(0).found);
    CHECK(queries.empty());

    for (const auto& invalid : std::vector<ordered_json>{nullptr, ordered_json::array(),
        {{"status", "0"}}, {{"status", true}}, {{"status", 0}, {"data", "bad"}},
        {{"status", 0}, {"data", ordered_json::array({nullptr})}},
        {{"status", 0}, {"data", ordered_json::array({{{"wxcx_msg_svr_id", "1"}}})}}})
    {
        execute = [=](const std::string&, const std::string&) { return invalid; };
        CHECK(!wxcx::msgloc::Locate(1, true).found);
    }
    execute = [](const std::string&, const std::string&) -> ordered_json
        { throw std::runtime_error("offline DB failure"); };
    CHECK(!wxcx::msgloc::Locate(1, true).found);
}

void TestRoutes()
{
    OfflineServer server;
    wxcx::msgloc::RegisterRoutes(server);
    Fixture("MSG12.db", "12345", "9007199254740993");
    for (const auto& body : {R"({"msgid":"9007199254740993"})",
                             R"({"msgsvrid":9007199254740993})"})
    {
        const auto [status, out] = server.PostBody(body);
        CHECK(status == 200 && out["found"] == true && out["local_id"] == 12345);
        CHECK(out["msg_svr_id_decimal"] == "9007199254740993");
        CHECK(out["db_idx"].is_null() && out["quad"].is_null());
        CHECK(out["quad_verified"] == false && out["native_abi_verified"] == false);
        CHECK(out["db_index_candidate"] == 12);
        CHECK(out["candidate_quad_hex"] == "0x0000000C00003039");
        CHECK(out["candidate_quad_decimal"] == "51539619897");
        CHECK(!out.contains("next_step") && !out.contains("quad_id"));
        CHECK(out.dump().find("ForwardMsg") == std::string::npos);
    }
    Fixture("MSG4294967295.db", "4294967295", "18446744073709551615");
    for (const auto& body : {R"({"msgid":"18446744073709551615"})",
                             R"({"msgid":18446744073709551615})"})
    {
        const auto [status, out] = server.PostBody(body);
        CHECK(status == 200 && out["found"] == true);
        CHECK(out["msg_svr_id_decimal"] == "18446744073709551615");
        CHECK(out["candidate_quad_decimal"] == "18446744073709551615");
        CHECK(out["candidate_quad_hex"] == "0xFFFFFFFFFFFFFFFF");
    }

    Fixture("MediaMSG12.db", "42", "1");
    CHECK(server.PostBody(R"({"msgid":"1"})").second["found"] == false);
    CHECK(server.PostBody(R"({"msgid":"1","include_media":false})").second["found"] == false);
    const auto media = server.PostBody(R"({"msgid":"1","include_media":true})");
    CHECK(media.first == 200 && media.second["found"] == true);
    CHECK(media.second["db_index_candidate"].is_null());
    CHECK(media.second["candidate_quad_decimal"].is_null());
    CHECK(media.second["candidate_quad_hex"].is_null());
    CHECK(media.second["detail"].get<std::string>().find("unknown/ambiguous") != std::string::npos);

    for (const auto& body : {"", "{", "{\"msgid\":1}junk", "[]", "null", "true", "123", "\"text\"", "{}",
        R"({"msgid":""})", R"({"msgid":"1x"})", R"({"msgid":"-1"})", R"({"msgid":-1})",
        R"({"msgid":0})", R"({"msgid":"0"})", R"({"msgid":1.0})", R"({"msgid":1e0})",
        R"({"msgid":true})", R"({"msgid":null})", R"({"msgid":[]})", R"({"msgid":{}})",
        R"({"msgid":"18446744073709551616"})", R"({"msgid":18446744073709551616})",
        R"({"msgid":"1","msgsvrid":"2"})", R"({"msgid":"1","msgsvrid":null})",
        R"({"msgid":"1","include_media":"true"})", R"({"msgid":"1","include_media":1})",
        R"({"msgid":"1","include_media":null})", R"({"msgid":"1","include_media":[]})",
        R"({"msgid":"1","include_media":{}})"})
    {
        queries.clear();
        const auto [status, out] = server.PostBody(body);
        CHECK(status == 400 && out["code"] == "-1");
        CHECK(queries.empty());
    }
    Fixture("MSG0.db", "42", "1");
    CHECK(server.PostBody(R"({"msgid":1,"msgsvrid":"1"})").second["found"] == true);
    Fixture("MSG0.db", "0", "1", "rowid");
    const auto invalidRow = server.PostBody(R"({"msgid":"1"})").second;
    CHECK(invalidRow["found"] == false && invalidRow["code"] == "-1");
    CHECK(invalidRow["candidate_quad_decimal"].is_null() && invalidRow["quad"].is_null());
}
}

// Link-time DB substitute: no production singleton constructor/patching code.
namespace xmgr {
DatabaseMgr::DatabaseMgr() = default;
DatabaseMgr::~DatabaseMgr() = default;
const std::map<std::string, LPVOID>& DatabaseMgr::searchDatabases() { return databases; }
ordered_json DatabaseMgr::execute(const std::string& db, const std::string& sql)
{
    queries.emplace_back(db, sql);
    return ::execute(db, sql);
}
}

namespace {
void TestConversationTableLocator() {
    const std::string table = "Msg_9e20f478899dc29eb19741386f9343c8";
    auto install = [&](int mode) {
        databases = {{"message_0.db", nullptr}}; queries.clear();
        execute = [=](const std::string&, const std::string& sql) -> ordered_json {
            if (sql.find("sqlite_master") != std::string::npos) {
                auto tables = ordered_json::array({{{"name", table}}, {{"name", "Msg_4854e361501ed01e50d68adff5f8bc85"}},
                    {{"name", "fav_db_item"}}, {{"name", "SessionUnreadListTable_1"}}});
                if (mode != 1) tables.push_back({{"name", "Name2Id"}});
                return {{"status", 0}, {"data", tables}};
            }
            if (sql.find("SELECT user_name FROM Name2Id") == 0) {
                CHECK(sql.find("user_name='filehelper' LIMIT 2") != std::string::npos);
                if (mode == 2) return {{"status", -1}};
                auto names = ordered_json::array();
                if (mode != 3) names.push_back({{"user_name", mode == 4 ? "wrong" : "filehelper"}});
                if (mode == 5) names.push_back({{"user_name", "filehelper"}});
                return {{"status", 0}, {"data", names}};
            }
            if (sql.find("PRAGMA") == 0) {
                if (sql.find("Name2Id") != std::string::npos)
                    return {{"status", 0}, {"data", ordered_json::array({{{"name", "user_name"}}})}};
                CHECK(sql.find("4854e361") == std::string::npos);
                return {{"status", 0}, {"data", ordered_json::array({{{"name", "local_id"}}, {{"name", "server_id"}}, {{"name", "local_type"}}})}};
            }
            CHECK(sql.find("'filehelper' AS wxcx_talker") != std::string::npos);
            CHECK(sql.find("FROM \"" + table + "\"") != std::string::npos);
            CHECK(sql.find(" AND ") == std::string::npos);
            auto rows = ordered_json::array();
            if (mode != 6) rows.push_back({{"wxcx_local_id", "7"}, {"wxcx_msg_svr_id", "9007199254740993"},
                {"wxcx_talker", mode == 8 ? "wrong" : "filehelper"}, {"wxcx_raw_type", "21474836529"}});
            if (mode == 7) rows.push_back(rows[0]);
            return {{"status", 0}, {"data", rows}};
        };
    };
    install(0);
    auto found = wxcx::msgloc::LocateUnique(9007199254740993ULL, "filehelper");
    CHECK(found.status == "found" && found.complete && found.matches.size() == 1);
    CHECK(found.matches[0].table == table && found.matches[0].talker == "filehelper");
    CHECK(found.matches[0].local_id == 7 && found.matches[0].raw_type == "21474836529");
    CHECK(std::none_of(queries.begin(), queries.end(), [](const auto& query) {
        return query.second.find("fav_db_item") != std::string::npos || query.second.find("SessionUnreadListTable_1") != std::string::npos;
    }));
    for (int mode : {1,2,3,4,5,8}) {
        install(mode); auto rejected = wxcx::msgloc::LocateUnique(9007199254740993ULL, "filehelper");
        CHECK(rejected.status == "lookup_incomplete" && !rejected.complete);
    }
    install(6); CHECK(wxcx::msgloc::LocateUnique(9007199254740993ULL, "filehelper").status == "not_found");
    install(7); CHECK(wxcx::msgloc::LocateUnique(9007199254740993ULL, "filehelper").status == "ambiguous");
}

void TestUniqueLocator() {
    const std::string server = "18446744073709551615";
    auto row = [&] (std::string talker = "source") -> ordered_json {
        return {{"wxcx_local_id", "4294967297"}, {"wxcx_msg_svr_id", server}, {"wxcx_talker", talker}, {"wxcx_raw_type", "49"}};
    };
    auto install = [&](ordered_json rows, bool hasTalker = true, bool failure = false) {
        databases = {{"not-named-message.db", nullptr}}; queries.clear();
        execute = [=](const std::string&, const std::string& sql) -> ordered_json {
            if (sql.find("sqlite_master") != std::string::npos)
                return {{"status", 0}, {"data", ordered_json::array({{{"name", "Msg_hash"}}, {{"name", "Other"}}})}};
            if (sql.find("PRAGMA") == 0) {
                if (failure) return {{"status", -1}};
                ordered_json columns = ordered_json::array();
                if (sql.find("Other") == std::string::npos) {
                    for (const char* name : {"local_id", "server_id", "local_type"}) columns.push_back({{"name", name}});
                    if (hasTalker) columns.push_back({{"name", "talker"}});
                } else columns.push_back({{"name", "key"}});
                return {{"status", 0}, {"data", columns}};
            }
            CHECK(sql.find("LIMIT 2") != std::string::npos);
            return {{"status", 0}, {"data", rows}};
        };
    };
    const auto max = (std::numeric_limits<uint64_t>::max)();
    install(ordered_json::array({row()}));
    CHECK(wxcx::msgloc::LocateUnique(max, {}, [] { return true; }).status == "lookup_incomplete");
    CHECK(queries.empty());
    auto one = wxcx::msgloc::LocateUnique(max, "source");
    CHECK(one.status == "found" && one.complete && one.matches.size() == 1);
    CHECK(one.matches[0].local_id == 4294967297ULL); CHECK(one.matches[0].msg_svr_id == max);
    CHECK(one.matches[0].raw_type == "49");
    CHECK(std::any_of(queries.begin(), queries.end(), [](const auto& q) { return q.second.find("\"talker\"='source'") != std::string::npos; }));
    install(ordered_json::array({row("a'b")}));
    CHECK(wxcx::msgloc::LocateUnique(max, "a'b").status == "found");
    CHECK(std::any_of(queries.begin(), queries.end(), [](const auto& q) { return q.second.find("'a''b'") != std::string::npos; }));
    install(ordered_json::array({row(), row("another")}));
    CHECK(wxcx::msgloc::LocateUnique(max).status == "ambiguous");
    install(ordered_json::array()); CHECK(wxcx::msgloc::LocateUnique(max).status == "not_found");
    install(ordered_json::array({row()}), false); CHECK(wxcx::msgloc::LocateUnique(max, "source").status == "lookup_incomplete");
    install(ordered_json::array({row()}), true, true); CHECK(wxcx::msgloc::LocateUnique(max).status == "lookup_incomplete");
    auto wrong = row(); wrong["wxcx_msg_svr_id"] = "18446744073709551614";
    install(ordered_json::array({wrong})); CHECK(wxcx::msgloc::LocateUnique(max).status == "lookup_incomplete");
    install(ordered_json::array({row()}));
    databases["second.db"] = nullptr;
    CHECK(wxcx::msgloc::LocateUnique(max).status == "ambiguous");
    install(ordered_json::array({row()}));
    databases["second.db"] = nullptr;
    auto original = execute;
    execute = [=](const std::string& db, const std::string& sql) -> ordered_json {
        if (db == "second.db") return {{"status", -1}};
        return original(db, sql);
    };
    auto incomplete = wxcx::msgloc::LocateUnique(max);
    CHECK(incomplete.status == "lookup_incomplete" && !incomplete.complete && incomplete.matches.size() == 1);
    install(ordered_json::array({row()}));
    auto knownSchema = execute;
    execute = [=](const std::string& db, const std::string& sql) -> ordered_json {
        if (sql.find("sqlite_master") != std::string::npos)
            return {{"status", 0}, {"data", ordered_json::array({{{"name", "Msg_hash"}}, {{"name", "Msg_unknown"}}})}};
        if (sql.find("PRAGMA") == 0 && sql.find("Msg_unknown") != std::string::npos)
            return {{"status", 0}, {"data", ordered_json::array({{{"name", "opaque_id"}}})}};
        return knownSchema(db, sql);
    };
    CHECK(wxcx::msgloc::LocateUnique(max).status == "lookup_incomplete");
    databases.clear(); CHECK(wxcx::msgloc::LocateUnique(max).status == "database_unavailable");
    CHECK(wxcx::msgloc::LocateUnique(0).status == "invalid_message_id");
    install(ordered_json::array({row()}));
    OfflineServer service; wxcx::msgloc::RegisterRoutes(service);
    auto route = service.PostBody(R"({"msgsvrid":"18446744073709551615","source_talker":"source"})", "/wxcx/db/locate_unique");
    CHECK(route.first == 200 && route.second["status"] == "found");
    CHECK(route.second["matches"][0]["local_id_decimal"] == "4294967297");
    CHECK(route.second["native_abi_verified"] == false);
    CHECK(service.PostBody(R"({"msgsvrid":1.0})", "/wxcx/db/locate_unique").first == 400);
}
}

int main()
{
    try
    {
        TestNumbers(); std::cout << "PASS lossless uint64 and local ID parsing\n";
        TestNames(); std::cout << "PASS bounded basename shard candidates\n";
        TestLocator(); std::cout << "PASS real locator with offline string-row DB substitute\n";
        TestRoutes(); std::cout << "PASS registered HTTP route using memory transport only\n";
        TestUniqueLocator(); std::cout << "PASS schema-bound unique lookup and ambiguity/incomplete rejection\n";
        TestConversationTableLocator(); std::cout << "PASS indexed conversation table lookup and incomplete-index rejection\n";
        std::cout << "PASS " << checks << " checks; no sockets or WeChat runtime\n";
        return 0;
    }
    catch (const std::exception& e)
    {
        std::cerr << "FAIL after " << checks << " checks: " << e.what() << '\n';
        return 1;
    }
}
