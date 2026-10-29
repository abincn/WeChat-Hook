#pragma once
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
namespace wxcx { namespace forward {
enum class ResponseParseState { Parsed, Missing, Invalid };
struct ResponseStatus {
    ResponseParseState state = ResponseParseState::Missing;
    std::optional<int32_t> server_return;
    std::string detail;
};
// SendAppMsgResponse field1 = BaseResponse, whose field1 is int32 ret.
// Requires an explicit, unambiguous ret. Unknown/malformed bytes never mean 0.
ResponseStatus ParseSendAppMsgResponse(const uint8_t* bytes, size_t size);
} }
