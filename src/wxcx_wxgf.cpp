#include "wxcx_wxgf.h"
#include "wxcx_media_files.h"
#include "wxcx_identity.h"
#include "global.h"
#include <windows.h>
#include <fstream>
#include <filesystem>
#include <cstring>
#include <mutex>
#include <algorithm>

namespace wxcx::media {
namespace wxgf {
bool ImportTargetMatches(uintptr_t observed,uintptr_t resolved,uintptr_t base,uintptr_t thunk,
 const std::array<unsigned char,12>& observedCode,const std::array<unsigned char,12>& expectedCode) noexcept {
 if(!observed||!resolved||!base)return false;
 return observed==resolved||(observed==base+thunk&&observedCode==expectedCode);
}
ImageDecode ConvertWith(const Bytes& source,Info info,Convert convert){
 ImageDecode out;auto fail=[&](const char* error){out.error=error;out.content.clear();return out;};
 if(!info||!convert)return fail("wxgf_codec_unverified");
 if(source.size()<4||source.size()>kMaxImageContainerBytes||memcmp(source.data(),"wxgf",4))return fail("unsupported_image_format");
 int meta[11]{};if(info(source.data(),static_cast<uint32_t>(source.size()),meta)!=0)return fail("wxgf_invalid");
 uint64_t product=1;
 for(unsigned i=0;i<3;++i){if(meta[i]<=0||meta[i]>32*1024*1024)return fail("wxgf_dimensions_invalid");product*=static_cast<unsigned>(meta[i]);if(product>32*1024*1024)return fail("wxgf_dimensions_invalid");}
 constexpr int max=50*1024*1024;
 int capacity=static_cast<int>((std::min)(uint64_t(max),product*3));out.content.resize(capacity);
 int options[8]{};int actual=capacity;
 int status=convert(source.data(),static_cast<uint32_t>(source.size()),out.content.data(),&actual,options);
 if(status==-206){
  if(actual<=capacity||actual>max)return fail("wxgf_output_invalid");
  capacity=actual;out.content.assign(static_cast<size_t>(capacity),0);actual=capacity;
  status=convert(source.data(),static_cast<uint32_t>(source.size()),out.content.data(),&actual,options);
 }
 if(status||actual<=0||actual>capacity)return fail("wxgf_conversion_failed");
 out.content.resize(static_cast<size_t>(actual));out.decoded=true;out.format="unverified_image";return out;
}
}
namespace {
bool HeaderMatches(HMODULE module,const unsigned char* file,size_t size)noexcept{
 __try{if(size<sizeof(IMAGE_DOS_HEADER)+sizeof(IMAGE_NT_HEADERS64))return false;auto* disk=reinterpret_cast<const IMAGE_DOS_HEADER*>(file);auto* live=reinterpret_cast<const IMAGE_DOS_HEADER*>(module);
 if(disk->e_magic!=IMAGE_DOS_SIGNATURE||disk->e_lfanew<0||static_cast<size_t>(disk->e_lfanew)>size-sizeof(IMAGE_NT_HEADERS64)||live->e_magic!=disk->e_magic||live->e_lfanew!=disk->e_lfanew)return false;
 auto* a=reinterpret_cast<const IMAGE_NT_HEADERS64*>(file+disk->e_lfanew);auto* b=reinterpret_cast<const IMAGE_NT_HEADERS64*>(reinterpret_cast<const unsigned char*>(module)+live->e_lfanew);
 return a->Signature==IMAGE_NT_SIGNATURE&&b->Signature==a->Signature&&a->OptionalHeader.Magic==IMAGE_NT_OPTIONAL_HDR64_MAGIC&&a->OptionalHeader.Magic==b->OptionalHeader.Magic&&a->OptionalHeader.SizeOfImage==b->OptionalHeader.SizeOfImage&&a->FileHeader.TimeDateStamp==b->FileHeader.TimeDateStamp;
 }__except(EXCEPTION_EXECUTE_HANDLER){return false;}
}
struct Codec {wxgf::Info info=nullptr;wxgf::Convert convert=nullptr;const char* error="wxgf_codec_unverified";};
bool ReadCode(uintptr_t address,std::array<unsigned char,12>& code) noexcept {
 __try{memcpy(code.data(),reinterpret_cast<const void*>(address),code.size());return true;}__except(EXCEPTION_EXECUTE_HANDLER){return false;}
}
bool ReadSlots(uintptr_t base,uintptr_t& info,uintptr_t& convert) noexcept {
 __try{info=*reinterpret_cast<const uintptr_t*>(base+0xA839F78);convert=*reinterpret_cast<const uintptr_t*>(base+0xA839FA8);return true;}__except(EXCEPTION_EXECUTE_HANDLER){return false;}
}
Codec Resolve(){
 Codec codec;wchar_t nativePath[32768]{};auto length=GetModuleFileNameW(g_hWeixinDll,nativePath,32768);
 if(!length||length>=32768)return codec;
 const auto path=std::filesystem::path(nativePath).parent_path()/L"VoipEngine.dll";
 // The dependency is delay-loaded by WeChat. Verify the exact sibling file
 // before loading it; never use PATH/current-directory DLL resolution.
 std::ifstream input(path,std::ios::binary|std::ios::ate);
 codec.error="wxgf_component_identity_mismatch";
 if(!input||input.tellg()!=19704360)return codec;Bytes bytes(19704360);input.seekg(0);if(!input.read(reinterpret_cast<char*>(bytes.data()),bytes.size()))return codec;
 if(Sha256(bytes.data(),bytes.size())!="adcf791169b3894f01bfe441a2aab62a94522e3fdd99ff6aa2e6aa27e612501f")return codec;
 HMODULE module=LoadLibraryExW(path.c_str(),nullptr,LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|LOAD_LIBRARY_SEARCH_SYSTEM32);
 codec.error="wxgf_component_load_failed";if(!module)return codec;
 struct Release{HMODULE module;~Release(){FreeLibrary(module);}} release{module};
 codec.error="wxgf_component_identity_mismatch";
 wchar_t loadedPath[32768]{};length=GetModuleFileNameW(module,loadedPath,32768);
 std::error_code pathError;
 if(!length||length>=32768||!std::filesystem::equivalent(path,std::filesystem::path(loadedPath),pathError)||pathError||!HeaderMatches(module,bytes.data(),bytes.size()))return codec;
 auto info=GetProcAddress(module,"wxam_dec_getWXGFInfo_5"),convert=GetProcAddress(module,"wxam_dec_wxam2pic_5");
 // These are direct exports, not forwarded exports, in the pinned component.
 const auto codecBase=reinterpret_cast<uintptr_t>(module);codec.error="wxgf_export_unverified";
 if(reinterpret_cast<uintptr_t>(info)!=codecBase+0x9224C0||reinterpret_cast<uintptr_t>(convert)!=codecBase+0x918280)return codec;
 // Accept either resolved exports or the exact known unresolved delay thunks.
 // Unknown redirects still fail. Direct calls do not touch WeChat's IAT.
 const auto base=reinterpret_cast<uintptr_t>(g_hWeixinDll);
 constexpr std::array<unsigned char,12> infoStub{0x48,0x8d,0x05,0xfc,0xd6,0xf9,0x03,0xe9,0x9c,0,0,0},convertStub{0x48,0x8d,0x05,0xe4,0xd6,0xf9,0x03,0xe9,0x54,0,0,0};
 uintptr_t infoSlot=0,convertSlot=0;std::array<unsigned char,12> infoCode{},convertCode{};codec.error="wxgf_import_unverified";
 if(!ReadSlots(base,infoSlot,convertSlot))return codec;
 if(infoSlot!=reinterpret_cast<uintptr_t>(info)&&!ReadCode(infoSlot,infoCode))return codec;
 if(convertSlot!=reinterpret_cast<uintptr_t>(convert)&&!ReadCode(convertSlot,convertCode))return codec;
 if(!wxgf::ImportTargetMatches(infoSlot,reinterpret_cast<uintptr_t>(info),base,0x689C875,infoCode,infoStub)||
 !wxgf::ImportTargetMatches(convertSlot,reinterpret_cast<uintptr_t>(convert),base,0x689C8BD,convertCode,convertStub))return codec;
 codec.error="wxgf_component_retention_failed";
 HMODULE pinned=nullptr;if(!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN,reinterpret_cast<LPCWSTR>(info),&pinned)||pinned!=module)return codec;
 codec.info=reinterpret_cast<wxgf::Info>(info);codec.convert=reinterpret_cast<wxgf::Convert>(convert);codec.error="";return codec;
}
}
ImageDecode DecodeLiveWxgf(const Bytes& bytes){
 ImageDecode failed;failed.error="wxgf_codec_unverified";
 try{const auto identity=RuntimeIdentity().at("weixin");if(!identity.value("verified",false)||!identity.value("mapped_headers_match",false)||g_IsLogin!=1||!g_hWeixinDll)return failed;}catch(...){return failed;}
 static std::mutex mutex;std::lock_guard<std::mutex> lock(mutex);
 // Resolve only after a valid process gate; a transient pre-login call cannot
 // poison a permanent negative cache. Do not print keys, buffers or addresses.
 static Codec codec;if(!codec.info)codec=Resolve();
 if(!codec.info){failed.error=codec.error;return failed;}
 return wxgf::ConvertWith(bytes,codec.info,codec.convert);
}
}
