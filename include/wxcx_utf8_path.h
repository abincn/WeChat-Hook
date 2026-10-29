#pragma once
#include <filesystem>
#include <string>
#include <string_view>
namespace wxcx::media {
inline std::filesystem::path Utf8Path(std::string_view text){
#if defined(__cpp_char8_t)
 const auto* begin=reinterpret_cast<const char8_t*>(text.data());return std::filesystem::path(begin,begin+text.size());
#else
 return std::filesystem::u8path(text.begin(),text.end());
#endif
}
inline std::string PathUtf8(const std::filesystem::path& path){auto value=path.u8string();return {reinterpret_cast<const char*>(value.data()),value.size()};}
}
