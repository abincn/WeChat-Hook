#include "wxcx_image_container.h"
#include <windows.h>
#include <bcrypt.h>
#include <algorithm>
#include <cstring>
#pragma comment(lib, "bcrypt.lib")
namespace wxcx::media {
namespace {
uint32_t U32(const unsigned char* p) {
    return uint32_t(p[0]) | uint32_t(p[1]) << 8 | uint32_t(p[2]) << 16 | uint32_t(p[3]) << 24;
}
std::string Format(const Bytes& bytes) {
    auto starts = [&](const char* text, size_t size) { return bytes.size() >= size && std::memcmp(bytes.data(), text, size) == 0; };
    if (starts("\x89PNG\r\n\x1a\n",8)) return "png";
    if (starts("\xff\xd8\xff",3)) return "jpeg";
    if (starts("GIF87a",6) || starts("GIF89a",6)) return "gif";
    if (starts("RIFF",4) && bytes.size() >= 12 && std::memcmp(bytes.data()+8,"WEBP",4)==0) return "webp";
    if (starts("wxgf",4)) return "wxgf";
    return "unknown";
}
struct Cipher {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_KEY_HANDLE key = nullptr;
    Bytes object;
    ~Cipher() {
        if (key) BCryptDestroyKey(key);
        if (!object.empty()) SecureZeroMemory(object.data(), object.size());
        if (algorithm) BCryptCloseAlgorithmProvider(algorithm,0);
    }
};
bool Decrypt(const unsigned char* input, size_t count, const ImageKeys& keys, Bytes& out) {
    Cipher cipher; ULONG size=0, returned=0;
    if (BCryptOpenAlgorithmProvider(&cipher.algorithm,BCRYPT_AES_ALGORITHM,nullptr,0)<0 ||
        BCryptSetProperty(cipher.algorithm,BCRYPT_CHAINING_MODE,reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_ECB)),sizeof(BCRYPT_CHAIN_MODE_ECB),0)<0 ||
        BCryptGetProperty(cipher.algorithm,BCRYPT_OBJECT_LENGTH,reinterpret_cast<PUCHAR>(&size),sizeof(size),&returned,0)<0 ||
        !size || size>1024*1024) return false;
    cipher.object.resize(size);
    if (BCryptGenerateSymmetricKey(cipher.algorithm,&cipher.key,cipher.object.data(),size,
        const_cast<PUCHAR>(keys.aes.data()),static_cast<ULONG>(keys.aes.size()),0)<0) return false;
    out.resize(count);
    return BCryptDecrypt(cipher.key,const_cast<PUCHAR>(input),static_cast<ULONG>(count),nullptr,nullptr,0,
        out.data(),static_cast<ULONG>(out.size()),&returned,0)>=0 && returned==count;
}
}
void EraseImageKeys(ImageKeys& keys) noexcept { SecureZeroMemory(&keys,sizeof(keys)); }
bool InspectImageV2(const Bytes& bytes, ImageLayout& layout, std::string& error) {
    layout={};error.clear();
    auto fail=[&](const char* message){error=message;return false;};
    if(bytes.size()>kMaxImageContainerBytes) return fail("image_too_large");
    if(bytes.size()<15) return fail("image_header_incomplete");
    constexpr unsigned char header[]={7,8,0x56,0x32,8,7};
    if(std::memcmp(bytes.data(),header,sizeof(header))!=0 || bytes[14]!=1) return fail("unsupported_image_container");
    const size_t plain=U32(bytes.data()+6), tail=U32(bytes.data()+10);
    if(!plain || plain>1024 || tail>1024*1024) return fail("image_lengths_invalid");
    const size_t cipher=(plain/16+1)*16;
    if(cipher>bytes.size()-15 || tail>bytes.size()-15-cipher) return fail("image_payload_incomplete");
    const size_t middle=bytes.size()-15-cipher-tail;
    if(middle && (plain!=1024 || tail!=1024*1024)) return fail("image_lengths_invalid");
    layout={plain,cipher,middle,tail};return true;
}
ImageDecode DecodeImageV2(const Bytes& bytes, const ImageKeys& keys) {
    ImageDecode result; ImageLayout layout;
    if(!InspectImageV2(bytes,layout,result.error)) return result;
    Bytes prefix;
    if(!Decrypt(bytes.data()+15,layout.aes_cipher,keys,prefix)) {result.error="image_crypto_failed";return result;}
    const auto padding=static_cast<unsigned char>(layout.aes_cipher-layout.aes_plain);
    if(!std::all_of(prefix.begin()+layout.aes_plain,prefix.end(),[&](unsigned char c){return c==padding;})) {
        result.error="image_key_or_padding_invalid";return result;
    }
    result.content.reserve(layout.aes_plain+layout.middle+layout.xor_tail);
    result.content.insert(result.content.end(),prefix.begin(),prefix.begin()+layout.aes_plain);
    const auto middle=bytes.begin()+15+layout.aes_cipher;
    result.content.insert(result.content.end(),middle,middle+layout.middle);
    const auto tail=middle+layout.middle;
    for(size_t i=0;i<layout.xor_tail;++i) result.content.push_back(tail[i]^keys.xor_byte);
    result.format=Format(result.content);result.decoded=true;return result;
}
}
