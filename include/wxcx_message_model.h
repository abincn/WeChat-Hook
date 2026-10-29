#pragma once

#include <cstdint>
#include <string>
#include "json.hpp"

namespace wxcx::messages {
using Json = nlohmann::json;

struct Input {
    std::string from, to, content, msgsource, self_wxid;
    uint64_t server_id = 0;
    uint32_t type = 0, create_time = 0;
    bool msgsource_known = false, content_complete = true, msgsource_complete = true;
};

// Pure, bounded normalization; no native calls or I/O. Empty identity strings
// become null. Unknown self suppresses direction and direct-peer inference.
// Throws std::length_error above 1 MiB content, 64 KiB msgsource, or 1024 bytes
// per identity, and std::invalid_argument for invalid UTF-8 in any input string.
// Accepted strings are preserved byte-for-byte (except the documented group
// member prefix in content). XML parsing is limited to depth 32, 4096 elements,
// 1024 unique mentions and 256 bytes per mention; unsupported XML is invalid.
// Only an unqualified msgsource root and one direct atuserlist are recognized.
// DTDs, processing instructions (including XML declarations), and custom
// entities are rejected. @all is retained as a token, never treated as self.
// Additive payload projection: message_kind, payload_status, quote/card. Native
// type49 bodies support reference(57), link(5), file(6), mini program(33/36);
// type42 supports contact-card attributes. Body XML allows a bounded UTF-8 XML
// declaration, retains original content, never fetches URLs or expands entities.
// Invalid/incomplete body XML exposes no structured quote/card. Unknown appmsg
// subtypes retain common fields but are explicitly unsupported. Referenced
// content is raw data, not recursively interpreted or looked up in a database.
// Image/video references additionally project one bounded img/videomsg XML
// layer into quote.media hints. Resource readiness remains unknown; no media
// download, decryption, path fabrication or recursive quote execution occurs.
// file_transfer is null except file74 notices / file6 content. A 74 notice uses
// event_type=file_transfer (not a content message). Later file6 content exposes
// the exact overwrite_newmsgid as replaces_msgsvrid; it never implies the local
// file has downloaded. AI consumers trigger on event_type=message plus their
// own type/completeness/account/allowlist policy, not upload notices.
Json Normalize(const Input& input);
// Strict source XML projection for native file/video integrity verification.
// Uses the same bounded XML reader; no native access, URL fetch or path output.
Json SourceResourceMetadata(uint32_t type,const std::string& content);
} // namespace wxcx::messages
