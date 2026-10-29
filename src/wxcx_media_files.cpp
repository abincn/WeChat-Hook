#include "wxcx_media_files.h"
#include "wxcx_utf8_path.h"
#include <windows.h>
#include <bcrypt.h>
#include <wincodec.h>
#include <mfapi.h>
#include <mfidl.h>
#include <mfreadwrite.h>
#include <mferror.h>
#include <wrl/client.h>
#include <fstream>
#include <algorithm>
#include <limits>
#pragma comment(lib,"bcrypt.lib")
#pragma comment(lib,"ole32.lib")
#pragma comment(lib,"windowscodecs.lib")
#pragma comment(lib,"mfplat.lib")
#pragma comment(lib,"mfreadwrite.lib")
#pragma comment(lib,"mfuuid.lib")
namespace wxcx::media {
namespace {
using Microsoft::WRL::ComPtr;
struct Com {HRESULT hr=CoInitializeEx(nullptr,COINIT_MULTITHREADED);~Com(){if(SUCCEEDED(hr))CoUninitialize();}};
bool ImageReadable(const Bytes& bytes){
 if(bytes.size()>MAXDWORD||bytes.empty())return false;Com com;
 ComPtr<IWICImagingFactory> factory;ComPtr<IWICStream> stream;ComPtr<IWICBitmapDecoder> decoder;ComPtr<IWICBitmapFrameDecode> frame;ComPtr<IWICFormatConverter> converted;
 if(FAILED(CoCreateInstance(CLSID_WICImagingFactory,nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(&factory)))||
 FAILED(factory->CreateStream(&stream))||FAILED(stream->InitializeFromMemory(const_cast<BYTE*>(bytes.data()),static_cast<DWORD>(bytes.size())))||
 FAILED(factory->CreateDecoderFromStream(stream.Get(),nullptr,WICDecodeMetadataCacheOnLoad,&decoder))||FAILED(decoder->GetFrame(0,&frame)))return false;
 UINT width=0,height=0;if(FAILED(frame->GetSize(&width,&height))||!width||!height||uint64_t(width)*height>32*1024*1024)return false;
 if(FAILED(factory->CreateFormatConverter(&converted))||FAILED(converted->Initialize(frame.Get(),GUID_WICPixelFormat32bppBGRA,WICBitmapDitherTypeNone,nullptr,0,WICBitmapPaletteTypeCustom)))return false;
 Bytes row(static_cast<size_t>(width)*4);
 for(UINT y=0;y<height;++y){WICRect rect{0,static_cast<INT>(y),static_cast<INT>(width),1};if(FAILED(converted->CopyPixels(&rect,width*4,static_cast<UINT>(row.size()),row.data())))return false;}return true;
}
bool VideoReadable(const std::filesystem::path& path){
 Com com;if(FAILED(MFStartup(MF_VERSION,MFSTARTUP_NOSOCKET)))return false;
 struct Shutdown{~Shutdown(){MFShutdown();}} shutdown;
 ComPtr<IMFSourceReader> reader;ComPtr<IMFMediaType> type;
 if(FAILED(MFCreateSourceReaderFromURL(path.c_str(),nullptr,&reader))||FAILED(reader->GetNativeMediaType(static_cast<DWORD>(MF_SOURCE_READER_FIRST_VIDEO_STREAM),0,&type)))return false;
 GUID major{};if(FAILED(type->GetGUID(MF_MT_MAJOR_TYPE,&major))||major!=MFMediaType_Video)return false;
 ComPtr<IMFSample> sample;DWORD flags=0;LONGLONG timestamp=0;
 for(unsigned i=0;i<32;++i){if(FAILED(reader->ReadSample(static_cast<DWORD>(MF_SOURCE_READER_FIRST_VIDEO_STREAM),0,nullptr,&flags,&timestamp,&sample)))return false;
 if(sample){DWORD bytes=0;return SUCCEEDED(sample->GetTotalLength(&bytes))&&bytes>0;}
 if(flags&(MF_SOURCE_READERF_ENDOFSTREAM|MF_SOURCE_READERF_ERROR))return false;}return false;
}
std::string ImageFormat(const Bytes& b){
 auto starts=[&](const char* s,size_t n){return b.size()>=n&&memcmp(b.data(),s,n)==0;};
 if(starts("\xff\xd8\xff",3))return "jpeg";if(starts("\x89PNG\r\n\x1a\n",8))return "png";
 if(starts("GIF87a",6)||starts("GIF89a",6))return "gif";
 if(starts("RIFF",4)&&b.size()>=12&&memcmp(b.data()+8,"WEBP",4)==0)return "webp";return {};
}
}
static std::string Digest(const unsigned char* data,size_t size,const wchar_t* algorithm,ULONG digestSize){
 if(size>(std::numeric_limits<ULONG>::max)())return {};BCRYPT_ALG_HANDLE alg=nullptr;
 if(BCryptOpenAlgorithmProvider(&alg,algorithm,nullptr,0)<0)return {};
 unsigned char digest[32]{};unsigned char empty=0;const auto status=BCryptHash(alg,nullptr,0,size?const_cast<PUCHAR>(data):&empty,static_cast<ULONG>(size),digest,digestSize);BCryptCloseAlgorithmProvider(alg,0);
 if(status<0)return {};std::string value;constexpr char hex[]="0123456789abcdef";for(ULONG i=0;i<digestSize;++i){value+=hex[digest[i]>>4];value+=hex[digest[i]&15];}return value;
}
std::string Sha256(const unsigned char* data,size_t size){return Digest(data,size,BCRYPT_SHA256_ALGORITHM,32);}
namespace {
std::wstring LowerFilename(const std::filesystem::path& path){auto name=path.filename().wstring();for(auto& c:name)if(c>=L'A'&&c<=L'Z')c+=L'a'-L'A';return name;}
bool Ends(const std::wstring& name,const wchar_t* suffix){auto length=wcslen(suffix);return name.size()>=length&&name.compare(name.size()-length,length,suffix)==0;}
}
bool IsThumbnailPath(const std::filesystem::path& path){const auto name=LowerFilename(path);return Ends(name,L"_t.dat")||Ends(name,L"_thumb.jpg")||Ends(name,L"_thumb.jpeg");}
bool MatchesNativeImagePath(const std::filesystem::path& path,const std::string& quality){
 const auto name=LowerFilename(path);if(IsThumbnailPath(path))return false;
 if(quality=="original")return Ends(name,L"_h.dat");
 return quality=="full"&&Ends(name,L".dat")&&!Ends(name,L"_h.dat");
}
Outcome PrepareArtifact(const std::filesystem::path& source,const std::string& kind,const std::filesystem::path& root,
 const std::function<bool(ImageKeys&,std::string&)>& derive,const std::function<bool()>& current,const std::function<ImageDecode(const Bytes&)>& wxgf,const ExpectedResource& expected){
 Outcome result;auto fail=[&](const char* code){result.error=code;return result;};
 if(kind!="image"&&kind!="video"&&kind!="file")return fail("type_unsupported");
 if(!current||!current())return fail("account_changed");
 if(kind=="image"&&IsThumbnailPath(source))return fail("image_thumbnail_rejected");
 // Deny directories/reparse files. Open the actual file for stable read while
 // retaining its handle: a path string or database status is insufficient.
 HANDLE handle=CreateFileW(source.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
 if(handle==INVALID_HANDLE_VALUE)return fail("resource_missing");
 struct Close{HANDLE h;~Close(){CloseHandle(h);}} close{handle};
 BY_HANDLE_FILE_INFORMATION info{};LARGE_INTEGER length{};
 if(!GetFileInformationByHandle(handle,&info)||info.dwFileAttributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT)||!GetFileSizeEx(handle,&length)||length.QuadPart<0||(!length.QuadPart&&kind!="file"))return fail("file_invalid");
 if(static_cast<uint64_t>(length.QuadPart)>kMaxImageContainerBytes)return fail("file_too_large");
 Bytes bytes(static_cast<size_t>(length.QuadPart));DWORD read=0;
 if(!ReadFile(handle,bytes.data(),static_cast<DWORD>(bytes.size()),&read,nullptr)||read!=bytes.size())return fail("file_invalid");
 if(expected.present&&(static_cast<uint64_t>(length.QuadPart)!=expected.bytes||(!expected.md5.empty()&&Digest(bytes.data(),bytes.size(),BCRYPT_MD5_ALGORITHM,16)!=expected.md5)))return fail("resource_integrity_mismatch");
 std::string format=kind=="video"?"video":kind=="file"?"file":ImageFormat(bytes);
 const auto isWxgf=[](const Bytes& value){return value.size()>=4&&!memcmp(value.data(),"wxgf",4);};
 if(kind=="image"&&format.empty()&&!isWxgf(bytes)){
  ImageLayout layout;std::string error;if(!InspectImageV2(bytes,layout,error)){result.error=error;return result;}
  ImageKeys keys;struct Erase{ImageKeys& keys;~Erase(){EraseImageKeys(keys);}} erase{keys};
  if(!derive||!derive(keys,error)){result.error=error.empty()?"image_key_derivation_failed":error;return result;}
  auto decoded=DecodeImageV2(bytes,keys);if(!decoded.decoded){result.error=decoded.error;return result;}
  format=ImageFormat(decoded.content);bytes=std::move(decoded.content);
 }
 if(kind=="image"&&format.empty()&&isWxgf(bytes)){
  if(!wxgf)return fail("unsupported_image_format");auto converted=wxgf(bytes);if(!converted.decoded){result.error=converted.error;return result;}
  format=ImageFormat(converted.content);bytes=std::move(converted.content);
 }
 if(kind=="image"&&format.empty())return fail("unsupported_image_format");
 if(kind=="image"&&!ImageReadable(bytes))return fail("file_invalid");
 if(kind=="video"&&!VideoReadable(source))return fail("file_invalid");
 if(!current())return fail("account_changed");
 const auto sha=Sha256(bytes.data(),bytes.size());if(sha.empty())return fail("output_failed");
 std::error_code ec;std::filesystem::create_directories(root,ec);if(ec)return fail("output_failed");
 unsigned char random[16]{};if(BCryptGenRandom(nullptr,random,sizeof(random),BCRYPT_USE_SYSTEM_PREFERRED_RNG)<0)return fail("output_failed");
 std::string name;constexpr char hex[]="0123456789abcdef";for(auto b:random){name+=hex[b>>4];name+=hex[b&15];}
 auto extension=format=="video"?std::string("mp4"):format=="file"?expected.extension:format;
 if(extension.empty()||extension.size()>12||extension.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")!=std::string::npos)extension="bin";
 const auto output=root/Utf8Path(name+"."+extension);
 HANDLE out=CreateFileW(output.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);if(out==INVALID_HANDLE_VALUE)return fail("output_failed");
 DWORD written=0;const bool okay=WriteFile(out,bytes.data(),static_cast<DWORD>(bytes.size()),&written,nullptr)&&written==bytes.size()&&FlushFileBuffers(out);CloseHandle(out);
 if(!okay||!current()){DeleteFileW(output.c_str());return fail(okay?"account_changed":"output_failed");}
 result.artifact={PathUtf8(output),format,sha,bytes.size(),extension};return result;
}
}
