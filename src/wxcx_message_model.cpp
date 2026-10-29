#include "wxcx_message_model.h"

#include <algorithm>
#include <stdexcept>
#include <string_view>
#include <unordered_set>
#include <vector>
#include <map>
#include <limits>

namespace wxcx::messages {
namespace {
constexpr size_t kContentLimit = 1024 * 1024, kMetadataLimit = 64 * 1024;
bool Space(char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; }
bool XmlChar(uint32_t c) {
    return c == 9 || c == 10 || c == 13 || (c >= 32 && c <= 0xD7FF) ||
        (c >= 0xE000 && c <= 0xFFFD) || (c >= 0x10000 && c <= 0x10FFFF);
}
bool Utf8(std::string_view s, bool xml = false) {
    for (size_t i = 0; i < s.size();) {
        uint32_t c = static_cast<unsigned char>(s[i++]);
        unsigned n = 0; uint32_t min = 0;
        if (c >= 0xC2 && c <= 0xDF) { c &= 31; n = 1; min = 0x80; }
        else if (c >= 0xE0 && c <= 0xEF) { c &= 15; n = 2; min = 0x800; }
        else if (c >= 0xF0 && c <= 0xF4) { c &= 7; n = 3; min = 0x10000; }
        else if (c >= 0x80) return false;
        if (n > s.size() - i) return false;
        while (n--) {
            const auto b = static_cast<unsigned char>(s[i++]);
            if ((b & 0xC0) != 0x80) return false;
            c = (c << 6) | (b & 63);
        }
        if (c < min || c > 0x10FFFF || (c >= 0xD800 && c <= 0xDFFF) ||
            (xml && !XmlChar(c))) return false;
    }
    return true;
}
void AppendUtf8(std::string& out, uint32_t c) {
    if (c < 0x80) out += static_cast<char>(c);
    else if (c < 0x800) {
        out += static_cast<char>(0xC0 | (c >> 6)); out += static_cast<char>(0x80 | (c & 63));
    } else if (c < 0x10000) {
        out += static_cast<char>(0xE0 | (c >> 12));
        out += static_cast<char>(0x80 | ((c >> 6) & 63)); out += static_cast<char>(0x80 | (c & 63));
    } else {
        out += static_cast<char>(0xF0 | (c >> 18)); out += static_cast<char>(0x80 | ((c >> 12) & 63));
        out += static_cast<char>(0x80 | ((c >> 6) & 63)); out += static_cast<char>(0x80 | (c & 63));
    }
}
bool NameStart(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || c == ':';
}
bool NameChar(char c) { return NameStart(c) || (c >= '0' && c <= '9') || c == '-' || c == '.'; }

// A deliberately restricted XML reader. Every byte of the document is validated
// before any mention is trusted; no recovery, external resolution or expansion.
class Metadata {
public:
    struct Node {
        std::string name, text;
        std::map<std::string, std::string> attributes;
        std::vector<size_t> children;
    };
    explicit Metadata(std::string_view s, bool body = false, bool media = false) : s_(s), body_(body), media_(media) {}
    bool Parse() {
        if (!Utf8(s_, true)) return false;
        // UTF-8 BOM is permitted only at the beginning of the XML document.
        if (s_.substr(0, 3) == "\xEF\xBB\xBF") p_ = 3;
        if (body_ && At("<?xml") && !Declaration()) return false;
        if (!Misc() || !Element(0) || !Misc() || p_ != s_.size()) return false;
        if (body_) return true;
        if (!found_) return true;
        size_t begin = 0;
        std::unordered_set<std::string> seen;
        while (begin <= list_.size()) {
            size_t end = list_.find(',', begin);
            if (end == std::string::npos) end = list_.size();
            auto token = std::string_view(list_).substr(begin, end - begin);
            while (!token.empty() && Space(token.front())) token.remove_prefix(1);
            while (!token.empty() && Space(token.back())) token.remove_suffix(1);
            if (!token.empty()) {
                if (token.size() > 256 || std::any_of(token.begin(), token.end(), [](char c) {
                    return Space(c) || static_cast<unsigned char>(c) < 32 || c == '<' || c == '>';
                })) return false;
                if (seen.emplace(token).second) {
                    if (mentions.size() == 1024) return false;
                    mentions.emplace_back(token);
                }
            }
            if (end == list_.size()) break;
            begin = end + 1;
        }
        return true;
    }
    std::vector<std::string> mentions;
    std::vector<Node> tree;
private:
    std::string_view s_;
    size_t p_ = 0, nodes_ = 0;
    bool found_ = false;
    bool body_ = false;
    bool media_ = false;
    std::string list_;
    bool At(std::string_view value) const { return s_.substr(p_, value.size()) == value; }
    void Ws() { while (p_ < s_.size() && Space(s_[p_])) ++p_; }
    std::string_view Name() {
        size_t begin = p_;
        if (p_ == s_.size() || !NameStart(s_[p_])) return {};
        while (p_ < s_.size() && NameChar(s_[p_])) ++p_;
        return s_.substr(begin, p_ - begin);
    }
    bool Comment() {
        if (!At("<!--")) return false;
        const auto end = s_.find("--", p_ + 4);
        if (end == std::string_view::npos || s_.substr(end, 3) != "-->") return false;
        p_ = end + 3; return true;
    }
    bool Misc() {
        Ws();
        while (At("<!--")) { if (!Comment()) return false; Ws(); }
        return true;
    }
    bool Declaration() {
        p_ += 5;
        std::vector<std::pair<std::string, std::string>> attrs;
        while (p_ < s_.size() && p_ < 256) {
            const auto before = p_; Ws();
            if (At("?>")) {
                p_ += 2;
                if (attrs.empty() || attrs[0] != std::make_pair(std::string("version"), std::string("1.0"))) return false;
                size_t i = 1;
                if (i < attrs.size() && attrs[i].first == "encoding") {
                    if (attrs[i].second != "utf-8" && attrs[i].second != "UTF-8") return false;
                    ++i;
                }
                if (i < attrs.size() && attrs[i].first == "standalone") {
                    if (attrs[i].second != "yes" && attrs[i].second != "no") return false;
                    ++i;
                }
                return i == attrs.size();
            }
            if (p_ == before || attrs.size() == 3) return false;
            const auto name = Name(); if (name.empty()) return false;
            Ws(); if (!At("=")) return false; ++p_; Ws();
            if (p_ == s_.size() || (s_[p_] != '\'' && s_[p_] != '"')) return false;
            const char quote = s_[p_++]; const auto start = p_;
            while (p_ < s_.size() && s_[p_] != quote && s_[p_] != '<' && s_[p_] != '&') ++p_;
            if (p_ == s_.size() || s_[p_] != quote) return false;
            attrs.emplace_back(std::string(name), std::string(s_.substr(start, p_ - start))); ++p_;
        }
        return false;
    }
    bool Decode(std::string_view in, std::string& out) {
        for (size_t i = 0; i < in.size();) {
            if (in[i] != '&') { out += in[i++]; continue; }
            const auto end = in.find(';', i + 1);
            if (end == std::string_view::npos || end - i > 16) return false;
            auto e = in.substr(i + 1, end - i - 1);
            if (e == "amp") out += '&';
            else if (e == "lt") out += '<';
            else if (e == "gt") out += '>';
            else if (e == "quot") out += '"';
            else if (e == "apos") out += '\'';
            else {
                if (e.empty() || e.front() != '#') return false;
                e.remove_prefix(1); unsigned base = 10;
                if (!e.empty() && e.front() == 'x') { base = 16; e.remove_prefix(1); }
                if (e.empty()) return false;
                uint32_t value = 0;
                for (char c : e) {
                    unsigned digit;
                    if (c >= '0' && c <= '9') digit = c - '0';
                    else if (c >= 'a' && c <= 'f') digit = c - 'a' + 10;
                    else if (c >= 'A' && c <= 'F') digit = c - 'A' + 10;
                    else return false;
                    if (digit >= base || value > (0x10FFFF - digit) / base) return false;
                    value = value * base + digit;
                }
                if (!XmlChar(value)) return false;
                AppendUtf8(out, value);
            }
            i = end + 1;
        }
        return true;
    }
    bool Element(size_t depth) {
        if (depth >= 32 || ++nodes_ > 4096 || !At("<")) return false;
        ++p_; const auto name = Name();
        const bool rootAllowed = body_ ? (name == "msg" || name == "appmsg" ||
            (media_ && (name == "img" || name == "videomsg"))) : name == "msgsource";
        if (name.empty() || (depth == 0 && !rootAllowed)) return false;
        const auto node = tree.size();
        if (body_) tree.push_back({std::string(name), {}, {}, {}});
        const bool target = !body_ && name == "atuserlist";
        if (target && (depth != 1 || found_)) return false;
        if (target) found_ = true;
        std::unordered_set<std::string_view> attrs;
        while (true) {
            const size_t before = p_; Ws();
            if (At("/>")) { p_ += 2; return true; }
            if (At(">")) { ++p_; break; }
            if (p_ == before) return false;
            auto attr = Name();
            if (attr.empty() || !attrs.insert(attr).second) return false;
            Ws(); if (!At("=")) return false; ++p_; Ws();
            if (p_ == s_.size() || (s_[p_] != '\'' && s_[p_] != '"')) return false;
            const char quote = s_[p_++]; const size_t start = p_;
            while (p_ < s_.size() && s_[p_] != quote && s_[p_] != '<') ++p_;
            if (p_ == s_.size() || s_[p_] != quote) return false;
            std::string decoded;
            if (!Decode(s_.substr(start, p_ - start), decoded)) return false;
            if (body_) {
                if (attr == "xmlns" || attr.substr(0, 6) == "xmlns:") return false;
                tree[node].attributes.emplace(std::string(attr), std::move(decoded));
            }
            ++p_;
        }
        while (p_ < s_.size()) {
            if (At("</")) {
                p_ += 2; if (Name() != name) return false;
                Ws(); if (!At(">")) return false; ++p_; return true;
            }
            if (At("<!--")) { if (!Comment()) return false; continue; }
            if (At("<![CDATA[")) {
                const size_t start = p_ + 9, end = s_.find("]]>", start);
                if (end == std::string_view::npos) return false;
                if (target) list_.append(s_.substr(start, end - start));
                if (body_) tree[node].text.append(s_.substr(start, end - start));
                p_ = end + 3; continue;
            }
            if (At("<")) {
                if (body_) tree[node].children.push_back(tree.size());
                if (target || !Element(depth + 1)) return false;
                continue;
            }
            const size_t start = p_;
            while (p_ < s_.size() && s_[p_] != '<') ++p_;
            const auto text = s_.substr(start, p_ - start);
            if (text.find("]]>") != std::string_view::npos) return false;
            std::string decoded;
            if (!Decode(text, decoded)) return false;
            if (target) list_ += decoded;
            if (body_) tree[node].text += decoded;
        }
        return false;
    }
};
bool Room(std::string_view id) {
    constexpr std::string_view suffix = "@chatroom";
    return id.size() > suffix.size() && id.substr(id.size() - suffix.size()) == suffix;
}
size_t MemberPrefix(std::string_view text) {
    // Bounded ASCII identifier followed immediately by colon + LF; never split
    // ordinary prose, a URL, a CRLF prefix, or an arbitrary colon occurrence.
    for (size_t i = 0; i < text.size() && i <= 256; ++i) {
        if (text[i] == ':') return i && i + 1 < text.size() && text[i + 1] == '\n' ? i + 2 : 0;
        const char c = text[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.' || c == '@')) return 0;
    }
    return 0;
}
Json Identity(const std::string& id) { return id.empty() ? Json(nullptr) : Json(id); }
void Check(const std::string& value, size_t limit) {
    if (value.size() > limit) throw std::length_error("message normalization input exceeds bound");
    if (!Utf8(value)) throw std::invalid_argument("message normalization input is not UTF-8");
}
// Read direct children only. A duplicate recognized field or mixed scalar is
// ambiguous: reject the structured projection, retaining the original body.
class BodyFields {
    const std::vector<Metadata::Node>& tree_;
public:
    explicit BodyFields(const Metadata& xml) : tree_(xml.tree) {}
    size_t Child(size_t parent, std::string_view name) const {
        size_t result = SIZE_MAX;
        if (parent == SIZE_MAX) return result;
        for (auto index : tree_[parent].children) if (tree_[index].name == name) {
            if (result != SIZE_MAX) throw std::invalid_argument("duplicate field");
            result = index;
        }
        return result;
    }
    std::string Text(size_t parent, std::string_view name) const {
        const auto child = Child(parent, name);
        if (child == SIZE_MAX) return {};
        if (!tree_[child].children.empty()) throw std::invalid_argument("mixed field");
        return tree_[child].text;
    }
    std::string Attribute(size_t index, const char* name) const {
        const auto found = tree_[index].attributes.find(name);
        return found == tree_[index].attributes.end() ? "" : found->second;
    }
};
std::string Trim(std::string value) {
    const auto begin = value.find_first_not_of(" \t\r\n");
    if (begin == std::string::npos) return {};
    const auto end = value.find_last_not_of(" \t\r\n");
    return value.substr(begin, end - begin + 1);
}
uint64_t Number(const std::string& value, uint64_t maximum = UINT64_MAX) {
    if (value.empty() || value.size() > 20) throw std::invalid_argument("missing number");
    uint64_t result = 0;
    for (unsigned char c : value) {
        if (c < '0' || c > '9' || c - '0' > maximum || result > (maximum - (c - '0')) / 10)
            throw std::invalid_argument("invalid number");
        result = result * 10 + (c - '0');
    }
    return result;
}
Json OptionalNumber(std::string value, bool string, uint64_t maximum = UINT64_MAX) {
    value = Trim(std::move(value));
    if (value.empty()) return nullptr;
    const auto n = Number(value, maximum);
    return string ? Json(std::to_string(n)) : Json(n);
}
Json QuotedMedia(const Json& type, const std::string& content) {
    if (type.is_null()) return nullptr;
    const auto value = type.get<uint64_t>();
    if (value != 3 && value != 43 && value != 62) return nullptr;
    const bool image = value == 3;
    Json out{{"kind", image ? "image" : "video"}, {"metadata_status", "unavailable"},
        {"resource_status", "not_resolved"}, {"resource_ready", nullptr}, {"download_supported", false},
        {"attributes", Json::object()}};
    const auto trimmed = Trim(content);
    if (trimmed.empty() || (trimmed.front() != '<' && trimmed.compare(0, 3, "\xEF\xBB\xBF") != 0)) return out;
    out["metadata_status"] = "invalid";
    Metadata xml(trimmed, true, true);
    if (!xml.Parse()) return out;
    try {
        BodyFields fields(xml);
        const auto tag = image ? "img" : "videomsg";
        const auto other = image ? "videomsg" : "img";
        const auto media = xml.tree[0].name == tag ? size_t(0) :
            xml.tree[0].name == "msg" ? fields.Child(0, tag) : SIZE_MAX;
        if (media == SIZE_MAX || fields.Child(0, other) != SIZE_MAX) return out;
        Json attributes = Json::object();
        for (const char* key : {"md5", "length", "hdlength", "cdnthumbwidth", "cdnthumbheight", "cdnthumblength",
            "playlength", "cdnmidimgurl", "cdnbigimgurl", "cdnthumburl", "cdnvideourl"}) {
            auto text = fields.Attribute(media, key);
            if (text.empty()) continue;
            const std::string_view name(key);
            if (name == "length" || name == "hdlength" || name == "cdnthumbwidth" || name == "cdnthumbheight" ||
                name == "cdnthumblength" || name == "playlength")
                text = std::to_string(Number(Trim(std::move(text))));
            attributes[key] = std::move(text);
        }
        out["attributes"] = std::move(attributes); out["metadata_status"] = "parsed";
    } catch (const std::invalid_argument&) { /* reference identity/reply remain valid; optional media does not */ }
    return out;
}
Json Body(uint32_t type, const std::string& content, bool complete) {
    Json out{{"message_kind", type == 1 ? "text" : "unknown"}, {"payload_status", "not_applicable"},
        {"quote", nullptr}, {"card", nullptr}, {"file_transfer", nullptr}};
    if (type != 49 && type != 42) return out;
    out["payload_status"] = complete ? "invalid" : "incomplete";
    if (!complete) return out;
    Metadata xml(content, true);
    if (!xml.Parse()) return out;
    try {
        BodyFields fields(xml);
        if (type == 42) {
            if (xml.tree[0].name != "msg") return out;
            auto username = fields.Attribute(0, "username");
            if (username.empty()) return out;
            out["card"] = {{"username", username}, {"nickname", fields.Attribute(0, "nickname")},
                {"alias", fields.Attribute(0, "alias")}, {"avatar_url", fields.Attribute(0, "bigheadimgurl")}};
            out["message_kind"] = "contact_card"; out["payload_status"] = "parsed"; return out;
        }
        const auto app = xml.tree[0].name == "appmsg" ? size_t(0) : fields.Child(0, "appmsg");
        if (app == SIZE_MAX) return out;
        const auto subtype = Number(Trim(fields.Text(app, "type")), UINT32_MAX);
        const auto title = fields.Text(app, "title");
        if (subtype == 57) {
            const auto reference = fields.Child(app, "refermsg");
            if (reference == SIZE_MAX) return out;
            auto id = OptionalNumber(fields.Text(reference, "svrid"), true);
            if (id == "0") id = nullptr;
            Json quote{{"reply_text", title}, {"msgsvrid", id},
                {"message_type", OptionalNumber(fields.Text(reference, "type"), false, UINT32_MAX)},
                {"sender_id", Identity(fields.Text(reference, "fromusr"))},
                {"conversation_id", Identity(fields.Text(reference, "chatusr"))},
                {"display_name", fields.Text(reference, "displayname")},
                {"content", fields.Text(reference, "content")},
                {"message_time", OptionalNumber(fields.Text(reference, "createtime"), false, UINT32_MAX)},
                {"content_is_raw", true}};
            quote["media"] = QuotedMedia(quote["message_type"], quote["content"].get_ref<const std::string&>());
            out["quote"] = std::move(quote); out["message_kind"] = "quote";
        } else {
            Json card{{"app_type", subtype}, {"title", title}, {"description", fields.Text(app, "des")},
                {"url", fields.Text(app, "url")}, {"thumb_url", fields.Text(app, "thumburl")},
                {"attachment", nullptr}, {"mini_program", nullptr}};
            if (subtype == 6 || subtype == 74) {
                const auto attachment = fields.Child(app, "appattach");
                card["attachment"] = {{"file_extension", fields.Text(attachment, "fileext")},
                    {"total_bytes", OptionalNumber(fields.Text(attachment, "totallen"), true)}};
                auto previous = OptionalNumber(fields.Text(attachment, "overwrite_newmsgid"), true);
                if (previous == "0") previous = nullptr;
                out["file_transfer"] = {{"phase", subtype == 74 ? "notice" : "content"},
                    {"status_code", OptionalNumber(fields.Text(attachment, "status"), false, UINT32_MAX)},
                    {"replaces_msgsvrid", std::move(previous)}};
            }
            if (subtype == 33 || subtype == 36) {
                const auto weapp = fields.Child(app, "weappinfo");
                card["mini_program"] = {{"app_id", fields.Text(weapp, "appid")},
                    {"username", fields.Text(weapp, "username")}, {"page_path", fields.Text(weapp, "pagepath")}};
            }
            out["card"] = std::move(card);
            out["message_kind"] = subtype == 5 ? "link_card" : subtype == 6 ? "file_card" : subtype == 74 ? "file_transfer_notice" :
                (subtype == 33 || subtype == 36) ? "mini_program_card" : "app_message";
            // Observed 74 notices are explicitly replaced by later subtype6
            // overwrite_newmsgid. Preserve both events; distinguish the notice
            // so an AI consumer can trigger only on event_type=message.
            if (subtype == 74) out["event_type"] = "file_transfer";
            if (subtype != 5 && subtype != 6 && subtype != 33 && subtype != 36 && subtype != 74) {
                out["payload_status"] = "unsupported"; return out;
            }
        }
        out["payload_status"] = "parsed";
    } catch (const std::invalid_argument&) {
        out["quote"] = nullptr; out["card"] = nullptr; out["message_kind"] = "unknown";
        out["file_transfer"] = nullptr; out.erase("event_type");
        out["payload_status"] = "invalid";
    }
    return out;
}
} // namespace

Json SourceResourceMetadata(uint32_t type,const std::string& content){
    Json out{{"status","invalid"},{"total_bytes",nullptr},{"md5",nullptr},{"extension",nullptr}};
    try{
        Check(content,kContentLimit);auto body=content;const auto prefix=MemberPrefix(body);if(prefix)body.erase(0,prefix);
        body=Trim(std::move(body));Metadata xml(body,true,true);if(!xml.Parse())return out;BodyFields fields(xml);std::string length,digest;
        if(type==43){
            const auto node=xml.tree[0].name=="videomsg"?size_t(0):xml.tree[0].name=="msg"?fields.Child(0,"videomsg"):SIZE_MAX;
            if(node==SIZE_MAX)return out;length=fields.Attribute(node,"length");digest=fields.Attribute(node,"md5");
        }else if(type==49){
            const auto app=xml.tree[0].name=="appmsg"?size_t(0):xml.tree[0].name=="msg"?fields.Child(0,"appmsg"):SIZE_MAX;
            if(app==SIZE_MAX||Number(Trim(fields.Text(app,"type")),UINT32_MAX)!=6)return out;
            const auto attachment=fields.Child(app,"appattach");if(attachment==SIZE_MAX)return out;
            length=fields.Text(attachment,"totallen");digest=fields.Text(app,"md5");if(digest.empty())digest=fields.Text(attachment,"md5");
            auto extension=Trim(fields.Text(attachment,"fileext"));if(!extension.empty()&&extension.front()=='.')extension.erase(0,1);
            if(!extension.empty()&&extension.size()<=12&&std::all_of(extension.begin(),extension.end(),[](char c){return (c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9');}))out["extension"]=extension;
        }else return out;
        length=Trim(std::move(length));if(length.empty())return out;const auto bytes=Number(length);if(type==43&&!bytes)return out;
        digest=Trim(std::move(digest));if(!digest.empty()){
            if(digest.size()!=32||!std::all_of(digest.begin(),digest.end(),[](char c){return (c>='0'&&c<='9')||(c>='a'&&c<='f')||(c>='A'&&c<='F');}))return out;
            for(char& c:digest)if(c>='A'&&c<='F')c=static_cast<char>(c-'A'+'a');out["md5"]=digest;
        }
        out["total_bytes"]=std::to_string(bytes);out["status"]="parsed";
    }catch(const std::exception&){}return out;
}

Json Normalize(const Input& in) {
    Check(in.from, 1024); Check(in.to, 1024); Check(in.self_wxid, 1024);
    Check(in.content, kContentLimit); Check(in.msgsource, kMetadataLimit);
    const bool from_room = Room(in.from), to_room = Room(in.to);
    const bool group = from_room || to_room;
    const bool ambiguous_room = from_room && to_room && in.from != in.to;
    const std::string room = ambiguous_room ? "" : from_room ? in.from : to_room ? in.to : "";
    std::string sender = group ? "" : in.from;
    std::string content = in.content;
    if (group && !ambiguous_room) {
        const size_t prefix = MemberPrefix(content);
        if (prefix) {
            auto member = content.substr(0, prefix - 2);
            if (!Room(member)) { sender = member; content.erase(0, prefix); }
        }
        if (sender.empty() && !from_room) sender = in.from;
    }
    std::string direction = "unknown", conversation = room;
    if (!in.self_wxid.empty() && !ambiguous_room) {
        if (in.from == in.self_wxid || sender == in.self_wxid) direction = "outgoing";
        else if (in.to == in.self_wxid && !in.from.empty()) direction = "incoming";
        if (!group) {
            if (direction == "outgoing") conversation = in.to;
            else if (direction == "incoming") conversation = in.from;
        }
    }
    Json mentions = Json::array(), at_me = nullptr;
    std::string status = "unknown";
    if (in.msgsource_known && in.msgsource_complete) {
        if (in.msgsource.empty()) status = "absent";
        else {
            Metadata metadata(in.msgsource);
            if (!metadata.Parse()) status = "invalid";
            else {
                mentions = metadata.mentions;
                status = metadata.mentions.empty() ? "absent" : "parsed";
            }
        }
        if ((status == "absent" || status == "parsed") && !in.self_wxid.empty()) {
            at_me = std::find(mentions.begin(), mentions.end(), Json(in.self_wxid)) != mentions.end();
        }
    }
    Json result{
        {"schema_version", 1}, {"event_type", "message"},
        {"from_id", Identity(in.from)}, {"to_id", Identity(in.to)}, {"self_id", Identity(in.self_wxid)},
        {"conversation_id", Identity(conversation)}, {"room_id", Identity(room)}, {"sender_id", Identity(sender)},
        {"is_group", group}, {"direction", direction}, {"content", content}, {"raw_content", in.content},
        {"msgsource", in.msgsource_known ? Json(in.msgsource) : Json(nullptr)},
        {"msgsvrid", in.server_id ? Json(std::to_string(in.server_id)) : Json(nullptr)},
        {"message_time", in.create_time ? Json(in.create_time) : Json(nullptr)},
        {"mentions", mentions}, {"is_at_me", at_me}, {"mention_status", status},
        {"content_complete", in.content_complete}, {"msgsource_complete", in.msgsource_complete}, {"type", in.type}
    };
    result.update(Body(in.type, content, in.content_complete));
    return result;
}
} // namespace wxcx::messages
