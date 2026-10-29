#include "wxcx_message_model.h"

#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

using wxcx::messages::Input;
using wxcx::messages::Json;
using wxcx::messages::Normalize;
namespace {
size_t checks = 0;
void Expect(bool value, const char* description) {
    ++checks;
    if (!value) throw std::runtime_error(description);
}
Input Message() {
    Input in;
    in.from = "alice"; in.to = "wxid_self"; in.self_wxid = "wxid_self";
    in.content = "hello"; in.type = 1;
    return in;
}
Json Metadata(const std::string& xml, const std::string& self = "wxid_self") {
    auto in = Message(); in.msgsource = xml; in.msgsource_known = true; in.self_wxid = self;
    return Normalize(in);
}
void Invalid(const std::string& xml) {
    auto j = Metadata(xml);
    Expect(j["mention_status"] == "invalid", "malformed/unsupported XML must be invalid");
    Expect(j["is_at_me"].is_null(), "invalid metadata must not assert no mention");
    Expect(j["mentions"].empty(), "invalid metadata must not expose partially trusted mentions");
}
template<class Exception, class F> void Throws(F action) {
    bool caught = false;
    try { action(); } catch (const Exception&) { caught = true; }
    Expect(caught, "expected documented input rejection");
}
void IdentityTests() {
    auto in = Message(); auto j = Normalize(in);
    Expect(j["schema_version"] == 1 && j["event_type"] == "message", "schema");
    Expect(j.size() == 26, "additive structured payload fields");
    Expect(j["from_id"] == "alice" && j["to_id"] == "wxid_self" && j["self_id"] == "wxid_self", "identities");
    Expect(j["sender_id"] == "alice" && j["conversation_id"] == "alice", "incoming peer");
    Expect(j["direction"] == "incoming" && j["is_group"] == false && j["room_id"].is_null(), "direct direction");
    Expect(j["msgsvrid"].is_null() && j["message_time"].is_null(), "unknown numeric fields");
    Expect(j["msgsource"].is_null() && j["is_at_me"].is_null() && j["mention_status"] == "unknown", "missing raw metadata");
    in.server_id = std::numeric_limits<uint64_t>::max(); in.create_time = 4294967295U;
    j = Normalize(in);
    Expect(j["msgsvrid"] == "18446744073709551615", "uint64 represented exactly as decimal string");
    Expect(j["message_time"].get<uint64_t>() == 4294967295ULL, "numeric timestamp unsigned range");
    in.server_id = 9007199254740993ULL;
    Expect(Json::parse(Normalize(in).dump())["msgsvrid"] == "9007199254740993", "server ID above double precision survives wire");
    in.from = "wxid_self"; in.to = "bob"; j = Normalize(in);
    Expect(j["direction"] == "outgoing" && j["conversation_id"] == "bob" && j["sender_id"] == "wxid_self", "outgoing direct");
    in.self_wxid.clear(); j = Normalize(in);
    Expect(j["direction"] == "unknown" && j["conversation_id"].is_null() && j["self_id"].is_null(), "unknown self suppresses inference");
    in = Input{}; j = Normalize(in);
    Expect(j["direction"] == "unknown" && j["sender_id"].is_null() && j["from_id"].is_null() && j["to_id"].is_null(), "empty identifiers cannot imply outgoing");
    in = Message(); in.to = "bob";
    Expect(Normalize(in)["conversation_id"].is_null(), "unrelated endpoints have unknown peer");
    in = Message(); in.from = "r@chatroom"; in.content = "wxid_member:\nhello: world";
    j = Normalize(in);
    Expect(j["is_group"] == true && j["room_id"] == "r@chatroom" && j["conversation_id"] == "r@chatroom", "exact room suffix");
    Expect(j["sender_id"] == "wxid_member" && j["content"] == "hello: world" && j["raw_content"] == in.content, "group member prefix and raw preservation");
    Expect(j["direction"] == "incoming", "incoming room");
    in.content = "wxid_self:\nown message"; j = Normalize(in);
    Expect(j["direction"] == "outgoing" && j["sender_id"] == "wxid_self", "own room message");
    in.self_wxid.clear(); j = Normalize(in);
    Expect(j["direction"] == "unknown" && j["sender_id"] == "wxid_self", "prefix does not discover unknown self");
    in = Message(); in.from = "wxid_self"; in.to = "r@chatroom"; j = Normalize(in);
    Expect(j["direction"] == "outgoing" && j["sender_id"] == "wxid_self" && j["conversation_id"] == "r@chatroom", "outgoing room endpoint");
    in = Message(); in.from = "r@chatroom";
    for (const std::string text : {"hello: world", "hello:\r\nworld", "a b:\nworld", ":\nworld", "https://host/x", "a:\nx:\nremaining"}) {
        in.content = text; j = Normalize(in);
        if (text == "a:\nx:\nremaining") Expect(j["content"] == "x:\nremaining", "strip only first exact member prefix");
        else Expect(j["content"] == text && j["sender_id"].is_null(), "do not arbitrarily split colons");
    }
    in.content = std::string(257, 'x') + ":\nbody";
    Expect(Normalize(in)["content"] == in.content, "member prefix bound");
    in.content = std::string(256, 'x') + ":\nbody";
    Expect(Normalize(in)["content"] == "body", "maximum member prefix accepted");
    in = Message(); in.content = "wxid_member:\nbody";
    Expect(Normalize(in)["content"] == in.content, "direct message never strips prefix");
    for (const std::string id : {"@chatroom", "r@chatroom.spoof", "r@chatroom\n", "r@CHATROOM"}) {
        in.from = id; Expect(Normalize(in)["is_group"] == false, "room classification must be exact");
    }
    in.from = "a@chatroom"; in.to = "b@chatroom"; j = Normalize(in);
    Expect(j["room_id"].is_null() && j["direction"] == "unknown", "ambiguous room endpoints");
}
void MentionTests() {
    auto j = Metadata("<msgsource><atuserlist><![CDATA[ alice, wxid_self,alice, \n bob \t ]]></atuserlist></msgsource>");
    Expect(j["mentions"] == Json::array({"alice", "wxid_self", "bob"}), "CDATA trimming and stable deduplication");
    Expect(j["is_at_me"] == true && j["mention_status"] == "parsed", "actual self mention");
    j = Metadata("<msgsource a='&quot;'><atuserlist>alice&#44;wxid_&#x73;elf,a&amp;b,a&amp;b</atuserlist><other x='1'>ok</other></msgsource>");
    Expect(j["mentions"] == Json::array({"alice", "wxid_self", "a&b"}) && j["is_at_me"] == true, "predefined and numeric entities");
    j = Metadata("<msgsource><atuserlist><![CDATA[wxid_]]>self,<![CDATA[alice]]></atuserlist></msgsource>");
    Expect(j["mentions"] == Json::array({"wxid_self", "alice"}), "adjacent text and CDATA");
    j = Metadata(" \n<!--before--><msgsource><!--ok--><atuserlist>alice</atuserlist></msgsource><!--after-->\t");
    Expect(j["mention_status"] == "parsed" && j["is_at_me"] == false, "valid comments and complete document");
    j = Metadata("\xEF\xBB\xBF<msgsource/>");
    Expect(j["mention_status"] == "absent", "UTF8 BOM");
    for (const std::string xml : {"", "<msgsource/>", "<msgsource></msgsource>", "<msgsource><atuserlist/></msgsource>", "<msgsource><atuserlist> , \n, </atuserlist></msgsource>"}) {
        j = Metadata(xml); Expect(j["mention_status"] == "absent" && j["is_at_me"] == false, "known complete empty mentions");
        Expect(Metadata(xml, "")["is_at_me"].is_null(), "unknown self stays null even with complete metadata");
    }
    j = Metadata("<msgsource><atuserlist>wxid_self</atuserlist></msgsource>", "");
    Expect(j["is_at_me"].is_null() && j["mention_status"] == "parsed", "unknown self retains parsed mentions");
    j = Metadata("<msgsource><atuserlist>@all</atuserlist></msgsource>");
    Expect(j["mentions"] == Json::array({"@all"}) && j["is_at_me"] == false && !j.contains("is_at_all"), "no invented @all semantics");
    auto in = Message(); in.content = "@wxid_self @nickname @all"; in.msgsource_known = true;
    j = Normalize(in);
    Expect(j["is_at_me"] == false && j["mentions"].empty(), "display text is not mention evidence");
    in.msgsource = "<msgsource><atuserlist>wxid_self</atuserlist></msgsource>";
    in.msgsource_complete = false; j = Normalize(in);
    Expect(j["is_at_me"].is_null() && j["mention_status"] == "unknown" && j["msgsource_complete"] == false, "truncation flag overrides apparently valid XML");
    in.msgsource_known = false; in.msgsource_complete = true; j = Normalize(in);
    Expect(j["is_at_me"].is_null() && j["msgsource"].is_null() && j["mentions"].empty(), "unknown raw field cannot be trusted");
    in.msgsource.clear(); Expect(Normalize(in)["mention_status"] == "unknown", "empty unknown metadata");
    for (const std::string xml : {
        "<msgsource><atuserlist>wxid_self</atuserlist>",
        "<msgsource><atuserlist>wxid_self</atuserlist></msgsource>junk",
        "<msgsource/><msgsource/>", "<other><atuserlist>wxid_self</atuserlist></other>",
        "<msgsource><atuserlist>a</atuserlist><atuserlist>b</atuserlist></msgsource>",
        "<msgsource><atuserlist/><atuserlist/></msgsource>",
        "<msgsource><x><atuserlist>wxid_self</atuserlist></x></msgsource>",
        "<msgsource><atuserlist><x/>wxid_self</atuserlist></msgsource>",
        "<msgsource><atuserlist><![CDATA[wxid_self</atuserlist></msgsource>",
        "<!DOCTYPE msgsource [<!ENTITY x 'wxid_self'>]><msgsource><atuserlist>&x;</atuserlist></msgsource>",
        "<!DOCTYPE msgsource SYSTEM 'file:///unread'><msgsource/>",
        "<?xml version='1.0'?><msgsource/>", "<msgsource><?pi x?></msgsource>",
        "<msgsource><atuserlist>&unknown;</atuserlist></msgsource>",
        "<msgsource><atuserlist>&#0;</atuserlist></msgsource>",
        "<msgsource><atuserlist>&#xD800;</atuserlist></msgsource>",
        "<msgsource><atuserlist>&#x110000;</atuserlist></msgsource>",
        "<msgsource><atuserlist>&#999999999999999;</atuserlist></msgsource>",
        "<msgsource><atuserlist>&#x;</atuserlist></msgsource>",
        "<msgsource><atuserlist>&#12a;</atuserlist></msgsource>",
        "<msgsource><atuserlist>wxid_self &</atuserlist></msgsource>",
        "<msgsource><atuserlist>wxid self</atuserlist></msgsource>",
        "<msgsource><atuserlist>&lt;fake&gt;</atuserlist></msgsource>",
        "<msgsource a='1' a='2'/>", "<msgsource a='1'b='2'/>", "<msgsource a='<'/>",
        "<msgsource a='&x;'/>", "<msgsource><!--a--b--></msgsource>",
        "<msgsource>]]></msgsource>", "<msgsource><x></msgsource>",
        "<msgsource></msgsource x>", "<msgsource / >", "<msgsource><!bogus/></msgsource>"
    }) Invalid(xml);
    Invalid(std::string("<msgsource>\0</msgsource>", 24));
    const std::string full = "<msgsource><atuserlist><![CDATA[wxid_self]]></atuserlist></msgsource>";
    for (size_t n = 1; n < full.size(); ++n) Invalid(full.substr(0, n));
    std::string deep = "<msgsource>";
    for (int i = 0; i < 32; ++i) deep += "<x>";
    for (int i = 0; i < 32; ++i) deep += "</x>";
    Invalid(deep + "</msgsource>");
    std::string wide = "<msgsource>";
    for (int i = 0; i < 4096; ++i) wide += "<x/>";
    Invalid(wide + "</msgsource>");
    std::string many;
    for (int i = 0; i < 1025; ++i) many += "id" + std::to_string(i) + ",";
    Invalid("<msgsource><atuserlist>" + many + "</atuserlist></msgsource>");
    Invalid("<msgsource><atuserlist>" + std::string(257, 'a') + "</atuserlist></msgsource>");
}
void EncodingAndBoundsTests() {
    auto in = Message();
    in.content = std::string("quote\" slash\\ line\n tab\t nul\0 tail", 34) + u8"中文😀";
    in.content_complete = false;
    auto j = Normalize(in); auto wire = Json::parse(j.dump());
    Expect(wire["raw_content"] == in.content && wire["content"] == in.content, "lossless JSON escaping and UTF8");
    Expect(wire["content_complete"] == false && wire["type"] == 1, "preserve completeness and type");
    for (const std::string bad : {std::string("\x80"), std::string("\xC0\xAF"), std::string("\xED\xA0\x80"), std::string("\xF4\x90\x80\x80"), std::string("\xE2\x82")}) {
        for (int field = 0; field < 5; ++field) {
            auto invalid = Message();
            std::string* fields[] = {&invalid.from, &invalid.to, &invalid.self_wxid, &invalid.content, &invalid.msgsource};
            *fields[field] = bad;
            Throws<std::invalid_argument>([&] { Normalize(invalid); });
        }
    }
    in = Message(); in.content.assign(1024 * 1024, 'a');
    Expect(Normalize(in)["raw_content"].get_ref<const std::string&>().size() == in.content.size(), "content maximum accepted");
    in.content += 'a'; Throws<std::length_error>([&] { Normalize(in); });
    in = Message(); in.msgsource.assign(64 * 1024 + 1, 'a');
    Throws<std::length_error>([&] { Normalize(in); });
    in = Message(); in.from.assign(1025, 'a');
    Throws<std::length_error>([&] { Normalize(in); });
}
void BodyTests() {
    auto in = Message();
    auto j = Normalize(in);
    Expect(j["message_kind"] == "text" && j["payload_status"] == "not_applicable", "plain text unchanged");
    Expect(j["quote"].is_null() && j["card"].is_null(), "plain text has no fabricated payload");
    const std::string quote = "<msg><appmsg appid=''><title><![CDATA[本次回复 & 不执行引用]]></title><type>57</type>"
        "<refermsg><type>1</type><svrid>18446744073709551615</svrid><fromusr>alice</fromusr>"
        "<chatusr>r@chatroom</chatusr><displayname>甲&amp;乙</displayname><content><![CDATA[原文 <hello>]]></content>"
        "<createtime>1793236672</createtime></refermsg></appmsg></msg>";
    const std::string link = "<msg><appmsg><title>A&amp;B</title><des><![CDATA[description]]></des><type>5</type>"
        "<url>https://example.test/a?x=1&amp;y=2</url><thumburl>https://example.test/image</thumburl></appmsg></msg>";
    for (bool group : {false, true}) {
        in = Message(); in.type = 49;
        if (group) in.from = "r@chatroom";
        in.content = (group ? "alice:\n" : "") + quote;
        in.msgsource_known = true; in.msgsource = "<msgsource><atuserlist>wxid_self</atuserlist></msgsource>";
        j = Normalize(in);
        Expect(j["payload_status"] == "parsed" && j["message_kind"] == "quote", "private/group reference parsed");
        Expect(j["quote"]["reply_text"] == "本次回复 & 不执行引用", "reply separated from quote");
        Expect(j["quote"]["content"] == "原文 <hello>" && j["quote"]["content_is_raw"] == true, "quoted content retained as data");
        Expect(j["quote"]["msgsvrid"] == "18446744073709551615", "full reference uint64 identity");
        Expect(j["quote"]["sender_id"] == "alice" && j["quote"]["display_name"] == "甲&乙", "reference author");
        Expect(j["quote"]["conversation_id"] == "r@chatroom" && j["quote"]["message_time"] == 1793236672, "reference context");
        Expect(j["raw_content"] == in.content && j["content"] == quote, "raw XML preserved independently");
        Expect(j["is_at_me"] == true && j["is_group"] == group, "mention normalization remains independent");
        in.content = (group ? "alice:\n" : "") + link; j = Normalize(in);
        Expect(j["message_kind"] == "link_card" && j["payload_status"] == "parsed", "private/group link card");
        Expect(j["card"]["title"] == "A&B" && j["card"]["description"] == "description", "card decoded text");
        Expect(j["card"]["url"] == "https://example.test/a?x=1&y=2" && j["quote"].is_null(), "card URL is data");
    }
    auto body = [&](const std::string& xml) { auto value = Message(); value.type = 49; value.content = xml; return Normalize(value); };
    j = body("<appmsg><title>file</title><type>6</type><appattach><fileext>pdf</fileext><totallen>9007199254740993</totallen></appattach></appmsg>");
    Expect(j["message_kind"] == "file_card" && j["card"]["attachment"]["total_bytes"] == "9007199254740993", "file size preserves precision");
    Expect(j["card"]["attachment"]["file_extension"] == "pdf" && !j["card"].contains("local_path"), "no invented downloaded path");
    for (auto type : {33,36}) {
        j = body("<appmsg><type>"+std::to_string(type)+"</type><title>mini</title><weappinfo><appid>app123</appid><username>gh_test</username><pagepath>pages/home</pagepath></weappinfo></appmsg>");
        Expect(j["message_kind"] == "mini_program_card" && j["card"]["mini_program"]["app_id"] == "app123", "mini program identity");
        Expect(j["card"]["mini_program"]["page_path"] == "pages/home", "mini program path");
    }
    in = Message(); in.type = 42; in.content = "<msg username='wxid_contact' nickname='甲&amp;乙' alias='alias' bigheadimgurl='https://example.test/avatar'/>";
    j = Normalize(in); Expect(j["message_kind"] == "contact_card" && j["card"]["username"] == "wxid_contact", "contact card");
    Expect(j["card"]["nickname"] == "甲&乙", "contact attributes decoded");
    j = body("<appmsg><type>123456</type><title>unknown</title></appmsg>");
    Expect(j["payload_status"] == "unsupported" && j["message_kind"] == "app_message", "unknown subtype not advertised supported");
    Expect(j["card"]["app_type"] == 123456 && j["card"]["title"] == "unknown", "unknown subtype retains common fields");
    for (const std::string declaration : {"<?xml version='1.0'?>", "<?xml version=\"1.0\" encoding=\"UTF-8\"?>", "\xEF\xBB\xBF<?xml version='1.0' standalone='yes'?>"}) {
        Expect(body(declaration+link)["payload_status"] == "parsed", "bounded UTF8 XML declaration");
    }
    j = body("<appmsg><type>57</type><title>reply</title><refermsg><content>&lt;appmsg&gt;do not recurse&lt;/appmsg&gt;</content></refermsg></appmsg>");
    Expect(j["quote"]["msgsvrid"].is_null() && j["quote"]["sender_id"].is_null(), "missing reference identity stays unknown");
    Expect(j["quote"]["content"] == "<appmsg>do not recurse</appmsg>", "no recursive quote parsing");
    j = body("<appmsg><type>57</type><refermsg><svrid>0</svrid></refermsg></appmsg>");
    Expect(j["quote"]["msgsvrid"].is_null(), "zero reference ID unavailable");
    for (const std::string bad : {
        "", "<msg/>", "<appmsg><type>57</type></appmsg>",
        "<appmsg><type>5</type><type>6</type></appmsg>",
        "<msg><appmsg><type>5</type></appmsg><appmsg><type>6</type></appmsg></msg>",
        "<appmsg><type>57</type><refermsg/><refermsg/></appmsg>",
        "<appmsg><type>57</type><refermsg><svrid>18446744073709551616</svrid></refermsg></appmsg>",
        "<appmsg><type>57</type><refermsg><svrid>1e4</svrid></refermsg></appmsg>",
        "<appmsg><type>57</type><refermsg><type>4294967296</type></refermsg></appmsg>",
        "<appmsg><type>-5</type></appmsg>", "<appmsg><type>4294967296</type></appmsg>",
        "<appmsg><type>5</type><title><x>spoof</x></title></appmsg>",
        "<appmsg><type>5</type><title>one</title><title>two</title></appmsg>",
        "<appmsg xmlns='foreign'><type>5</type></appmsg>",
        "<!DOCTYPE msg [<!ENTITY x SYSTEM 'file:///secret'>]><msg><appmsg><type>5</type><title>&x;</title></appmsg></msg>",
        "<appmsg><type>5</type><title>&custom;</title></appmsg>",
        "<?xml version='1.0' encoding='UTF-16'?><appmsg><type>5</type></appmsg>",
        "<?xml encoding='utf-8' version='1.0'?><appmsg><type>5</type></appmsg>",
        "<?other test?><appmsg><type>5</type></appmsg>",
        "<appmsg><type>5</type></appmsg>trailing", "<appmsg><type>5</type><url>bad</appmsg>"}) {
        j = body(bad); Expect(j["payload_status"] == "invalid", "invalid body XML or ambiguous fields rejected");
        Expect(j["quote"].is_null() && j["card"].is_null(), "failed parse never exposes partial trusted payload");
        Expect(j["raw_content"] == bad, "failed parse preserves original");
    }
    in = Message(); in.type = 49; in.content = link; in.content_complete = false;
    j = Normalize(in); Expect(j["payload_status"] == "incomplete" && j["card"].is_null(), "truncated valid-looking body untrusted");
    in = Message(); in.content = quote; j = Normalize(in);
    Expect(j["message_kind"] == "text" && j["quote"].is_null(), "XML text cannot spoof native message type");
    std::string deep = "<msg><appmsg><type>5</type>";
    for(int i=0;i<32;++i) deep += "<n>";
    for(int i=0;i<32;++i) deep += "</n>";
    deep += "</appmsg></msg>";
    Expect(body(deep)["payload_status"] == "invalid", "body XML depth bounded");
    std::string many = "<msg><appmsg><type>5</type>";
    for(int i=0;i<4096;++i) many += "<n/>";
    many += "</appmsg></msg>";
    Expect(body(many)["payload_status"] == "invalid", "body XML element count bounded");
    const auto mediaQuote = [](int type, const std::string& media, bool group = false) {
        auto message = Message(); message.type = 49;
        if (group) message.from = "r@chatroom";
        message.msgsource_known = true;
        message.content = (group ? "alice:\n" : "") + std::string("<msg><appmsg><type>57</type><title>media reply</title><refermsg><type>") +
            std::to_string(type) + "</type><svrid>9007199254740993</svrid><content><![CDATA[" + media +
            "]]></content></refermsg></appmsg></msg>";
        return Normalize(message);
    };
    for (bool group : {false,true}) {
        for (int type : {3,43,62}) {
            const bool image = type == 3;
            const auto xml = image ? "<msg><img md5='abcd' length='9007199254740993' cdnthumbwidth='320' cdnthumbheight='240' cdnmidimgurl='opaque-image-locator' aeskey='not-projected'/></msg>" :
                "<msg><videomsg md5='abcd' length='9007199254740993' playlength='12' cdnthumbwidth='320' cdnthumburl='opaque-thumb-locator' cdnvideourl='opaque-video-locator' aeskey='not-projected'/></msg>";
            j = mediaQuote(type,xml,group);
            Expect(j["message_kind"] == "quote" && j["payload_status"] == "parsed", "private/group media quote");
            Expect(j["quote"]["reply_text"] == "media reply" && j["quote"]["msgsvrid"] == "9007199254740993", "media quote identity and new reply retained");
            auto media = j["quote"]["media"];
            Expect(media["kind"] == (image ? "image" : "video") && media["metadata_status"] == "parsed", "image/video reference type");
            Expect(media["attributes"]["length"] == "9007199254740993", "media length hint precision");
            Expect(media["resource_status"] == "not_resolved" && media["resource_ready"].is_null() && media["download_supported"] == false, "hints never imply available media");
            Expect(!media["attributes"].contains("aeskey") && !media.contains("local_path"), "no fabricated media path or duplicated secret");
            Expect(j["is_at_me"] == false, "quoted metadata does not create an actual mention");
            Expect(media["attributes"][image ? "cdnmidimgurl" : "cdnvideourl"] == (image ? "opaque-image-locator" : "opaque-video-locator"), "opaque media locator retained without fetching");
            if (!image) Expect(media["attributes"]["playlength"] == "12", "raw playlength hint retained without invented unit conversion");
        }
    }
    for (const auto xml : {"<img length='1'/>", "<?xml version='1.0'?><msg><img length='1'/></msg>"})
        Expect(mediaQuote(3,xml)["quote"]["media"]["metadata_status"] == "parsed", "direct/wrapped media XML");
    for (const auto xml : {"[图片]", ""}) {
        j = mediaQuote(3,xml);
        Expect(j["payload_status"] == "parsed" && j["quote"]["media"]["metadata_status"] == "unavailable", "missing XML media hints do not destroy reference");
    }
    for (const auto xml : {"<msg><img", "<msg><img/><img/></msg>", "<msg><videomsg/></msg>",
        "<msg><img length='18446744073709551616'/></msg>", "<msg><img cdnthumbwidth='-1'/></msg>",
        "<!DOCTYPE msg SYSTEM 'https://example.test/evil'><msg><img/></msg>"}) {
        j = mediaQuote(3,xml);
        Expect(j["payload_status"] == "parsed" && j["quote"]["reply_text"] == "media reply", "invalid optional media does not discard valid quote");
        Expect(j["quote"]["media"]["metadata_status"] == "invalid", "malformed media hints explicit");
        Expect(j["quote"]["media"]["attributes"].empty(), "invalid media hints not partially exposed");
    }
    Expect(mediaQuote(1,"text")["quote"]["media"].is_null(), "text quote has no media projection");
    const std::string notice = "<msg><appmsg><title>sample.log</title><type>74</type><appattach><totallen>97</totallen><fileext>log</fileext>"
        "<fileuploadtoken>opaque-secret</fileuploadtoken><status>0</status></appattach><md5>abc</md5><laninfo/></appmsg></msg>";
    j=body(notice);
    Expect(j["event_type"]=="file_transfer" && j["message_kind"]=="file_transfer_notice", "74 notice is not ordinary content");
    Expect(j["payload_status"]=="parsed" && j["file_transfer"]["phase"]=="notice" && j["file_transfer"]["status_code"]==0, "74 raw notice state");
    Expect(j["card"]["attachment"]["total_bytes"]=="97" && !j["card"].contains("fileuploadtoken"), "notice metadata without duplicated token");
    j=body("<msg><appmsg><type>6</type><title>sample.log</title><appattach><totallen>97</totallen><fileext>log</fileext>"
        "<overwrite_newmsgid>18446744073709551615</overwrite_newmsgid></appattach></appmsg></msg>");
    Expect(j["event_type"]=="message" && j["message_kind"]=="file_card", "final6 remains content");
    Expect(j["file_transfer"]["phase"]=="content" && j["file_transfer"]["replaces_msgsvrid"]=="18446744073709551615", "exact64 overwrite relation");
    j=body("<appmsg><type>74</type><appattach><status>9</status></appattach></appmsg>");
    Expect(j["event_type"]=="file_transfer" && j["file_transfer"]["status_code"]==9, "unknown notice status is raw, never guessed complete");
    j=body("<appmsg><type>6</type><appattach><overwrite_newmsgid>18446744073709551616</overwrite_newmsgid></appattach></appmsg>");
    Expect(j["payload_status"]=="invalid" && j["file_transfer"].is_null(), "invalid overwrite identity fails atomically");
    j=body("<appmsg><type>74</type><appattach><status>-1</status></appattach></appmsg>");
    Expect(j["payload_status"]=="invalid" && j["event_type"]=="message", "malformed notice rejected without partial event projection");
}
} // namespace
int main() {
    try {
        IdentityTests(); MentionTests(); EncodingAndBoundsTests(); BodyTests();
        std::cout << "message_model: " << checks << " checks passed\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "message_model failed after " << checks << " checks: " << e.what() << '\n';
        return 1;
    }
}
