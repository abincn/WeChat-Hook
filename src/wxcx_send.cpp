#include "wxcx.h"

#include <windows.h>
#include <objbase.h>

#include <cstdint>
#include <cstring>
#include <cstdio>
#include <string>
#include <vector>

#include "global.h"
#include "wx_send.h"

// ---------------------------------------------------------------------------
// 说明
//   本文件是"消息对象"构造层: 直接按 4.1.10.27 的内存布局拼一个 WeChat 的
//   消息结构, 再调 Weixin.dll+offset::send_message 入队。
//   与 src/wx_send.cpp 的区别:
//     1) 文本支持 atlist (群 @);
//     2) 图片按扩展名区分 filetype (3=png/jpg, 47=gif);
//   偏移来源见 include/wxcx_offsets.h。
// ---------------------------------------------------------------------------

using WeixinCall = __int64(*)(...);


namespace WeixinSend
{
    bool SendAppMsgObject(const std::string& toid, const std::string& xml,
                          int mode, std::string& reason);
}

namespace wxcx
{
namespace detail
{
#pragma pack(push, 1)
    struct WxString
    {
        union
        {
            char  inline_buf[16];
            char* heap_buf;
        };
        uint64_t length;
        uint64_t cap;
    };

    struct WxStringU
    {
        union
        {
            wchar_t  inline_buf[8];
            wchar_t* heap_buf;
        };
        uint64_t length;
        uint64_t cap;
    };

    // 4.1.10.27 文本消息体 (相对消息块 +0x10)
    struct TextMessage
    {
        uint64_t      pad0[22];     // 0x000
        WxString      receiver;     // 0x0B0
        uint64_t      pad1[1];      // 0x0D0
        uint64_t      type;         // 0x0D8  1 = 文本
        uint64_t      pad2[21];     // 0x0E0
        uint64_t      msg_len;      // 0x188
        uint64_t      pad3[163];    // 0x190
        WxString      uuid;         // 0x6A8
        uint64_t      pad4[8];      // 0x6C8
        WxString      content;      // 0x708
        WxString      atlist;       // 0x728  群 @ 的 wxid 列表
    };
#pragma pack(pop)

    static_assert(sizeof(WxString) == 0x20, "WxString layout");
    static_assert(offsetof(TextMessage, receiver) == 0x0B0, "receiver");
    static_assert(offsetof(TextMessage, type) == 0x0D8, "type");
    static_assert(offsetof(TextMessage, uuid) == 0x6A8, "uuid");
    static_assert(offsetof(TextMessage, content) == 0x708, "content");
    static_assert(offsetof(TextMessage, atlist) == 0x728, "atlist");

    inline void* HeapZero(size_t bytes)
    {
        return ::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, bytes);
    }

    inline uint64_t WxCapacity(uint64_t len)
    {
        uint64_t need = len + 1;
        uint64_t cap = (need + 0xF) & ~0xFULL;
        return cap - 1;
    }

    inline void SetWxString(WxString* dst, const std::string& src)
    {
        if (!dst) return;
        memset(dst, 0, sizeof(WxString));

        dst->length = src.size();

        if (src.size() < 16)
        {
            memcpy(dst->inline_buf, src.data(), src.size());
            dst->cap = 0xF;
            return;
        }

        char* buf = (char*)::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, src.size() + 1);
        if (!buf) return;

        memcpy(buf, src.data(), src.size());
        buf[src.size()] = '\0';
        dst->heap_buf = buf;
        dst->cap = WxCapacity(src.size());
    }

    inline void SetWxStringU(WxStringU* dst, const std::string& utf8)
    {
        if (!dst) return;
        memset(dst, 0, sizeof(WxStringU));

        int need = ::MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, nullptr, 0);
        if (need <= 0) return;

        std::wstring w(need - 1, L'\0');
        ::MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, &w[0], need);

        dst->length = w.size();
        if (w.size() < 8)
        {
            memcpy(dst->inline_buf, w.data(), w.size() * sizeof(wchar_t));
            dst->inline_buf[w.size()] = L'\0';
            dst->cap = 0xF;
            return;
        }

        wchar_t* buf = (wchar_t*)::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY,
                                             (w.size() + 1) * sizeof(wchar_t));
        if (!buf) return;

        memcpy(buf, w.data(), (w.size() + 1) * sizeof(wchar_t));
        dst->heap_buf = buf;
        dst->cap = WxCapacity(w.size());
    }

    inline std::string NewGuid()
    {
        GUID g{};
        ::CoCreateGuid(&g);

        char buf[64] = { 0 };
        snprintf(buf, sizeof(buf),
                 "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                 g.Data1, g.Data2, g.Data3,
                 g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3],
                 g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7]);
        return std::string(buf);
    }

    inline uint64_t FileSizeOf(const std::string& path)
    {
        int wlen = ::MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, nullptr, 0);
        if (wlen <= 0) return 0;

        std::wstring w(wlen, L'\0');
        ::MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, &w[0], wlen);

        HANDLE h = ::CreateFileW(w.c_str(), GENERIC_READ,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                 OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) return 0;

        LARGE_INTEGER sz{};
        ::GetFileSizeEx(h, &sz);
        ::CloseHandle(h);
        return (uint64_t)sz.QuadPart;
    }

    inline std::string ToLower(std::string s)
    {
        for (char& c : s) c = (char)::tolower((unsigned char)c);
        return s;
    }

    inline std::string ExtOf(const std::string& path)
    {
        size_t dot = path.find_last_of('.');
        if (dot == std::string::npos) return std::string();
        std::string ext = path.substr(dot + 1);
        size_t q = ext.find_first_of("?#");
        if (q != std::string::npos) ext = ext.substr(0, q);
        return ToLower(ext);
    }
} // namespace detail

// ---------------------------------------------------------------------------
// 文本 (可选 atlist)
// ---------------------------------------------------------------------------
bool SendTextEx(const std::string& toid, const std::string& msg, const std::string& atlist)
{
    using namespace detail;

    if (!g_hWeixinDll || toid.empty()) return false;

    uintptr_t base = (uintptr_t)g_hWeixinDll;

    // 与 src/wx_send.cpp 保持一致: 0x768 * 8 字节消息块
    uint64_t* msgBuf = (uint64_t*)HeapZero(0x768 * sizeof(uint64_t));
    if (!msgBuf) return false;

    msgBuf[0] = base + offset::txt_message_vtbl;
    msgBuf[1] = 0x200000005LL;

    TextMessage* m = reinterpret_cast<TextMessage*>(msgBuf + 2);
    WeixinCall ctor = (WeixinCall)(base + offset::txt_message_ctr);
    ctor((uint64_t)m);

    SetWxString(&m->receiver, toid);
    SetWxString(&m->content, msg);
    m->msg_len = msg.size();
    m->type = 1;

    if (!atlist.empty())
    {
        SetWxString(&m->atlist, atlist);
    }

    uint64_t* data = (uint64_t*)HeapZero(0x20);
    if (!data) return false;
    data[0] = (uint64_t)(msgBuf + 2);
    data[1] = (uint64_t)msgBuf;
    data[2] = 0;

    uint64_t* arg1 = (uint64_t*)HeapZero(0x28);
    if (!arg1) return false;
    arg1[0] = base + offset::param1_vtable;
    arg1[1] = (uint64_t)data;
    arg1[2] = (uint64_t)data + 0x10;
    arg1[3] = (uint64_t)data + 0x10;
    arg1[4] = 1;

    uint64_t* arg2 = (uint64_t*)HeapZero(0xE8);
    if (!arg2) return false;

    // ===== param2 构造 (照抄 wx_send.cpp 的 BuildSendParam2_Text) =====
    {
        WeixinCall build = (WeixinCall)(base + offset::create_param2);
        uint64_t* buf = (uint64_t*)HeapZero(16 * sizeof(uint64_t));

        struct Block { uint64_t vtable; uint64_t temp[6]; uint64_t self; };
        Block* p2 = (Block*)HeapZero(sizeof(Block));
        Block* p3 = (Block*)HeapZero(sizeof(Block));
        Block* p4 = (Block*)HeapZero(sizeof(Block));
        if (!buf || !p2 || !p3 || !p4) return false;

        p2->vtable = base + offset::param2_1; p2->self = (uint64_t)p2;
        p3->vtable = base + offset::param2_2; p3->self = (uint64_t)p3;
        p4->vtable = base + offset::param2_3; p4->self = (uint64_t)p4;

        build((uint64_t)arg2, (uint64_t)p2, (uint64_t)p3, (uint64_t)p4,
              (uint64_t)buf, *(uint64_t*)(base + offset::param2));
    }

    WeixinCall send = (WeixinCall)(base + offset::send_message);
    send((uint64_t)arg1, (uint64_t)arg2);
    return true;
}

// ---------------------------------------------------------------------------
// 图片对象 (fileType: 3=png/jpg, 47=gif)
// ---------------------------------------------------------------------------
static bool SendImageObject(const std::string& toid, const std::string& path, uint64_t fileType)
{
    using namespace detail;

    if (!g_hWeixinDll || toid.empty() || path.empty()) return false;

    uintptr_t base = (uintptr_t)g_hWeixinDll;
    uint64_t fileSize = FileSizeOf(path);
    if (fileSize == 0) return false;

    uint64_t* msg = (uint64_t*)HeapZero(0x7C0);
    if (!msg) return false;

    std::string guid = NewGuid();

    msg[0] = base + offset::img_msg_vtbl;
    msg[1] = 0x200000006;
    msg[2] = base + offset::img_msg_vtb2;

    *(uint64_t*)(msg + 0x40 / 8) = 0xF;
    *(uint64_t*)(msg + 0x60 / 8) = 0xF;
    *(uint64_t*)(msg + 0x80 / 8) = 0xF;
    *(uint64_t*)(msg + 0xA0 / 8) = 0xF;
    *(uint64_t*)(msg + 0xA8 / 8) = 0x0000000100000000;
    *(uint64_t*)(msg + 0xB0 / 8) = 0x0000000700000000;

    SetWxString((WxString*)(msg + 0xC0 / 8), toid);
    *(uint64_t*)(msg + 0xD0 / 8) = toid.size();
    *(uint64_t*)(msg + 0xD8 / 8) = WxCapacity(toid.size());

    *(uint64_t*)(msg + 0xE8 / 8) = fileType;

    SetWxStringU((WxStringU*)(msg + 0xF0 / 8), path);
    *(uint64_t*)(msg + 0x100 / 8) = path.size();
    *(uint64_t*)(msg + 0x108 / 8) = WxCapacity(path.size());

    *(uint64_t*)(msg + 0x130 / 8) = 0xF;
    *(uint64_t*)(msg + 0x150 / 8) = 7;
    *(uint64_t*)(msg + 0x170 / 8) = 0xF;

    *(uint64_t*)(msg + 0x198 / 8) = fileSize;
    *(uint64_t*)(msg + 0x1B8 / 8) = 0xF;

    *(uint64_t*)(msg + 0x668 / 8) = 0xF;
    *(uint64_t*)(msg + 0x688 / 8) = 0xF;
    *(uint64_t*)(msg + 0x6B0 / 8) = 0xF;
    SetWxString((WxString*)(msg + 0x6B8 / 8), guid);
    *(uint64_t*)(msg + 0x6C8 / 8) = guid.size();
    *(uint64_t*)(msg + 0x6D0 / 8) = WxCapacity(guid.size());

    *(uint64_t*)(msg + 0x6F0 / 8) = 0xF;
    *(uint64_t*)(msg + 0x710 / 8) = 0xF;
    *(uint64_t*)(msg + 0x738 / 8) = 0xF;
    *(uint64_t*)(msg + 0x760 / 8) = 0xF;
    *(uint64_t*)(msg + 0x780 / 8) = 0xF;
    *(uint64_t*)(msg + 0x7A0 / 8) = 0xF;

    // param1
    struct Inner1 { void* p1; void* p2; void* p3; uint64_t count; };
    struct Inner2 { void* vtable; void* p1; uint64_t d1; uint64_t d2; uint64_t f1; };

    Inner1* s1 = (Inner1*)HeapZero(sizeof(Inner1));
    Inner2* s2 = (Inner2*)HeapZero(sizeof(Inner2));
    if (!s1 || !s2) return false;

    s1->p1 = (void*)((uint64_t)msg + 0x10);
    s1->p2 = (void*)msg;
    s1->p3 = nullptr;
    s1->count = 0;

    s2->vtable = (void*)(base + offset::param1_vtable);
    s2->p1 = s1;
    s2->d1 = (uint64_t)s1 + 0x10;
    s2->d2 = (uint64_t)s1 + 0x10;
    s2->f1 = 1;

    // param2
    uint64_t* arg2 = (uint64_t*)HeapZero(0xE8);
    if (!arg2) return false;

    {
        WeixinCall build = (WeixinCall)(base + offset::create_param2);
        uint64_t* buf = (uint64_t*)HeapZero(0x10);

        struct Block { uint64_t vtable; uint64_t temp[6]; uint64_t self; };
        Block* p2 = (Block*)HeapZero(sizeof(Block));
        Block* p3 = (Block*)HeapZero(sizeof(Block));
        Block* p4 = (Block*)HeapZero(sizeof(Block));
        if (!buf || !p2 || !p3 || !p4) return false;

        p2->vtable = base + offset::param2_1; p2->self = (uint64_t)p2;
        p3->vtable = base + offset::param2_2; p3->self = (uint64_t)p3;
        p4->vtable = base + offset::param2_3; p4->self = (uint64_t)p4;

        build((uint64_t)arg2, (uint64_t)p2, (uint64_t)p3, (uint64_t)p4,
              (uint64_t)buf, *(uint64_t*)(base + offset::param2));
    }

    WeixinCall send = (WeixinCall)(base + offset::send_message);
    send((uint64_t)s2, (uint64_t)arg2);
    return true;
}

bool SendFileAuto(const std::string& toid, const std::string& path, std::string& reason)
{
    std::string ext = detail::ExtOf(path);

    // 图片: png/jpg/jpeg/bmp/webp 走 filetype 3; gif 走 47
    if (ext == "png" || ext == "jpg" || ext == "jpeg" || ext == "bmp" || ext == "webp")
    {
        if (SendImageObject(toid, path, 3)) return true;
        reason = "send_image_object_failed";
        return false;
    }

    if (ext == "gif")
    {
        if (SendImageObject(toid, path, 47)) return true;
        reason = "send_gif_object_failed";
        return false;
    }

    // 视频 / 普通文件: 需要 4.1.10.27 对应的 video / attach 消息对象偏移,
    // 当前未定位到, 不能拿图片对象硬发 (会崩客户端)。
    reason = "unsupported_file_kind:" + (ext.empty() ? std::string("<none>") : ext);
    return false;
}


    // ---- appmsg（卡片/视频号）薄封装：转发到 wx_send.cpp 的 WeixinSend 实现 ----
    bool SendAppMsgObject(const std::string& toid, const std::string& xml,
                          int mode, std::string& reason)
    {
        return WeixinSend::SendAppMsgObject(toid, xml, mode, reason);
    }

} // namespace wxcx
