#pragma once
#include "wxcx_image_container.h"
#include <array>
namespace wxcx::media {
namespace wxgf {
using Info=int(*)(const unsigned char*,uint32_t,int*);
using Convert=int(*)(const unsigned char*,uint32_t,unsigned char*,int*,const int*);
// ABI observed in native 7B9F40: 44-byte info, 32-byte options and -206
// output-resize contract. Output is independently decoded before publication.
ImageDecode ConvertWith(const Bytes&,Info,Convert);
// A delay slot may still point at its exact native resolver stub. We never
// execute that stub or modify the IAT; calls use separately verified exports.
bool ImportTargetMatches(uintptr_t observed,uintptr_t resolved,uintptr_t base,
 uintptr_t thunk,const std::array<unsigned char,12>& observedCode,const std::array<unsigned char,12>& expectedCode) noexcept;
}
ImageDecode DecodeLiveWxgf(const Bytes&);
}
