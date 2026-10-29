#pragma once
// Database lookup only. Filename shard numbers and composed quad values are
// research candidates; neither establishes the WeChat 4.x native ABI.

#include <cstdint>
#include <optional>
#include <string>
#include <vector>
#include <functional>

namespace httplib { class Server; }

namespace wxcx
{
namespace msgloc
{
    struct Result
    {
        bool        found = false;
        uint64_t    msg_svr_id = 0;
        std::string db;
        std::string table;
        std::string id_col;
        std::string svr_col;
        uint64_t    local_id = 0;
        // Compatibility names denote VERIFIED values; absent without ABI
        // evidence. Candidates must not be passed to native functions.
        std::optional<uint32_t> db_idx;
        std::optional<uint64_t> quad;
        std::optional<uint32_t> db_index_candidate;
        std::optional<uint64_t> candidate_quad;
        bool quad_verified = false;
        bool native_abi_verified = false;
        std::string detail;
    };

    Result Locate(uint64_t msgSvrId, bool includeMedia = false);
    struct UniqueMatch {
        std::string db, table, talker, raw_type;
        uint64_t local_id = 0, msg_svr_id = 0;
    };
    struct UniqueResult {
        std::string status, detail;
        bool complete = false;
        std::vector<UniqueMatch> matches;
    };
    // Schema-bound evidence only; never a native object or composed identifier.
    UniqueResult LocateUnique(uint64_t msgSvrId, const std::string& sourceTalker = {},
        const std::function<bool()>& cancelled = {});
    void RegisterRoutes(httplib::Server& svr);
}
}
