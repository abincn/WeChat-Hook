#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace wxcx::media {
using Bytes = std::vector<unsigned char>;
constexpr size_t kMaxImageContainerBytes = 200 * 1024 * 1024;
struct ImageKeys { std::array<unsigned char, 16> aes{}; unsigned char xor_byte = 0; };
void EraseImageKeys(ImageKeys&) noexcept;
struct ImageLayout {
    size_t aes_plain = 0, aes_cipher = 0, middle = 0, xor_tail = 0;
};
struct ImageDecode {
    bool decoded = false;
    std::string error, format;
    Bytes content;
};
// Format scope: the V2 writer in this exact 4.1.10.27 binary. Reject malformed
// lengths; never clamp header values. Does not access WeChat or the filesystem.
bool InspectImageV2(const Bytes&, ImageLayout&, std::string& error);
// AES-128-ECB prefix / unchanged middle / XOR tail, verified PKCS7. A decoded
// wxgf/unknown result does NOT imply an image is displayable or ready for AI.
ImageDecode DecodeImageV2(const Bytes&, const ImageKeys&);
// Native keys: explicit gate, verified prologues and native string destruction.
// Caller must erase the keys; no logging, caching or hardcoded account keys.
bool DeriveLiveImageKeys(ImageKeys&, std::string& error);
}
