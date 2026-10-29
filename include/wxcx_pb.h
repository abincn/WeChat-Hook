#pragma once
// wxcx_pb - 极简 protobuf 线格式编解码 + 群操作请求构造
//
// 字段号来源：docs/STATIC_ANALYSIS.md §6（从序列化函数的立即数静态确认）
// 目前只覆盖三个群操作请求；decode 端点可解任意 protobuf 报文。

#include <string>

#include "json.hpp"

namespace httplib { class Server; }

namespace wxcx
{
namespace pb
{
    void RegisterRoutes(httplib::Server& svr);

    std::string BuildCreateChatRoom(const nlohmann::json& in);
    std::string BuildAddChatRoomMember(const nlohmann::json& in);
    std::string BuildDelChatRoomMember(const nlohmann::json& in);
}
}
