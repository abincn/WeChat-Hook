#pragma once
#include "wxcx_media_tasks.h"
namespace wxcx::media {
// Release candidate only. Each call rechecks exact native identity and entry
// bytes. General availability remains false until image/video live acceptance.
std::shared_ptr<Backend> CreateNativeBackend();
// Image 1 is a thumbnail; 2 is the full image, 3 is the separate HD original.
uint32_t NativeResourceKind(const Request&,uint32_t type,uint32_t subtype) noexcept;
}
