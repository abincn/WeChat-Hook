#pragma once
#include "wxcx_media_tasks.h"
#include "wxcx_image_container.h"
#include <filesystem>
namespace wxcx::media {
struct ExpectedResource {bool present=false;uint64_t bytes=0;std::string md5,extension;};
// Only copies a native-derived source file. Never accepts output paths from HTTP.
// Output names are generated internally, immutable, and do not overwrite originals.
Outcome PrepareArtifact(const std::filesystem::path& source,const std::string& kind,
 const std::filesystem::path& outputRoot,const std::function<bool(ImageKeys&,std::string&)>& keys,
 const std::function<bool()>& current,const std::function<ImageDecode(const Bytes&)>& wxgf={},const ExpectedResource& expected={});
std::string Sha256(const unsigned char*,size_t);
bool IsThumbnailPath(const std::filesystem::path&);
bool MatchesNativeImagePath(const std::filesystem::path&,const std::string& quality);
}
