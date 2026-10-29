#include "wxcx_image_container.h"
#include "wxcx_identity.h"
#include "global.h"
#include <windows.h>
#include <cstring>
#include <mutex>

namespace wxcx::media {
namespace {
constexpr unsigned char kAesEntry[]={0x55,0x41,0x56,0x56,0x57,0x53,0x48,0x83,0xec,0x40,0x48,0x8d,0x6c,0x24,0x40,0x48};
constexpr unsigned char kXorEntry[]={0x55,0x56,0x53,0x48,0x83,0xec,0x40,0x48,0x8d,0x6c,0x24,0x40,0x48,0xc7,0x45,0xf8};
constexpr unsigned char kDestroyEntry[]={0x56,0x48,0x83,0xec,0x20,0x48,0x89,0xce,0x48,0x8b,0x41,0x18,0x48,0x83,0xf8,0x10};
bool Entry(uintptr_t address,const unsigned char* expected) {
    __try {return std::memcmp(reinterpret_cast<const void*>(address),expected,16)==0;}
    __except(EXCEPTION_EXECUTE_HANDLER){return false;}
}
// Native encoder 0x9BA970 frees the same derived std::string through 0x20C0.
// Keep its ABI buffer POD; never invoke this DLL's std::string destructor/free.
bool NativeKeys(uintptr_t base,unsigned char* aes,unsigned char* xorByte) {
    unsigned char storage[32]{};
    bool made=false, shape=false, valid=false;
    __try {
        __try {
            using Derive=void*(__fastcall*)(void*,unsigned int);
            reinterpret_cast<Derive>(base+0x9B1FD0)(storage,2);
            made=true;
            const auto length=*reinterpret_cast<const uint64_t*>(storage+16);
            const auto capacity=*reinterpret_cast<const uint64_t*>(storage+24);
            shape=capacity>=15 && capacity<4096 && length<=capacity;
            valid=shape && length==32;
            if(valid){
                auto* data=capacity>=16?*reinterpret_cast<unsigned char**>(storage):storage;
                std::memcpy(aes,data,16);
            }
        } __finally {
            if(made && shape){
                const auto length=*reinterpret_cast<const uint64_t*>(storage+16);
                const auto capacity=*reinterpret_cast<const uint64_t*>(storage+24);
                auto* data=capacity>=16?*reinterpret_cast<unsigned char**>(storage):storage;
                SecureZeroMemory(data,static_cast<size_t>(length));
                using Destroy=void(__fastcall*)(void*);
                reinterpret_cast<Destroy>(base+0x20C0)(storage);
            }
            SecureZeroMemory(storage,sizeof(storage));
        }
        if(!valid)return false;
        using Xor=uint64_t(__fastcall*)();
        *xorByte=static_cast<unsigned char>(reinterpret_cast<Xor>(base+0x9B1F20)());
        return true;
    } __except(EXCEPTION_EXECUTE_HANDLER){return false;}
}
}
bool DeriveLiveImageKeys(ImageKeys& keys,std::string& error) {
    static std::mutex mutex;
    std::lock_guard<std::mutex> lock(mutex);
    EraseImageKeys(keys);error.clear();
    try {
        const auto identity=RuntimeIdentity().at("weixin");
        if(!identity.value("verified",false)||!identity.value("mapped_headers_match",false)){error="version_unverified";return false;}
    }catch(...){error="version_unverified";return false;}
    if(g_IsLogin!=1 || !g_hWeixinDll){error="login_not_ready";return false;}
    const auto base=reinterpret_cast<uintptr_t>(g_hWeixinDll);
    if(!Entry(base+0x9B1FD0,kAesEntry)||!Entry(base+0x9B1F20,kXorEntry)||!Entry(base+0x20C0,kDestroyEntry)){
        error="image_key_prologue_mismatch";return false;
    }
    if(!NativeKeys(base,keys.aes.data(),&keys.xor_byte)){
        EraseImageKeys(keys);error="image_key_derivation_failed";return false;
    }
    return true;
}
}
