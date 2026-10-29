#include "wxcx_media_native.h"
#include "wxcx_native_coroutine.h"
#include "wxcx_identity.h"
#include "wxcx_msgloc.h"
#include "wxcx_media_files.h"
#include "wxcx_wxgf.h"
#include "wxcx_utf8_path.h"
#include "wxcx_message_model.h"
#include "wxcx_ids.h"
#include "global.h"
#include <windows.h>
#include <filesystem>
#include <cstring>
#include <mutex>
#include <stdexcept>
#include <atomic>

namespace wxcx::media {
uint32_t NativeResourceKind(const Request& request,uint32_t type,uint32_t subtype) noexcept {
 if(request.kind=="image"&&type==3)return request.image_quality=="full"?2:request.image_quality=="original"?3:0;
 if(request.kind=="video"&&type==43)return 32;
 if(request.kind=="file"&&type==49&&subtype==6)return 103;
 return 0;
}
namespace {
using Pair=native::coroutine::detail::SharedPair;
struct String {alignas(8) unsigned char bytes[16]{};uint64_t size=0,capacity=15;};
struct Wide {alignas(8) wchar_t bytes[8]{};uint64_t size=0,capacity=7;};
struct Future {Pair owner;uint64_t options=0;};
struct DownloadOptions {uint32_t flags=1,pad=0;Wide first,second;};
struct DownloadResult {int code=0,detail=0;String message;Pair data;};
static_assert(sizeof(String)==32&&sizeof(Wide)==32&&sizeof(Future)==24&&sizeof(DownloadOptions)==72&&sizeof(DownloadResult)==56);
template<class T> T Function(uintptr_t base,uintptr_t rva){return reinterpret_cast<T>(base+rva);}
struct Owner {
 Pair pair{};uintptr_t base;
 explicit Owner(uintptr_t b):base(b){};Owner(const Owner&)=delete;Owner& operator=(const Owner&)=delete;
 ~Owner(){if(pair.control)Function<void(*)(Pair*)>(base,0x2130)(&pair);}
};
struct NativeString {
 String value;uintptr_t base;
 NativeString(uintptr_t b,const std::string& text):base(b){
  if(text.size()<=15){memcpy(value.bytes,text.data(),text.size());value.size=text.size();}
  else Function<void*(*)(String*,uint64_t,uintptr_t,const char*)>(base,0x54470)(&value,text.size(),0,text.data());
 }
 ~NativeString(){Function<void(*)(String*)>(base,0x20C0)(&value);}
};
bool CopyString(uintptr_t address,std::string& out,size_t max=4096){
 // Keep SEH out of scopes that own C++ objects.
 if(max>1024*1024)return false;std::vector<unsigned char> buffer(max);size_t length=0;
 const auto read=[](uintptr_t p,unsigned char* dst,size_t* size,size_t bound)noexcept{
  __try{const auto* s=reinterpret_cast<const String*>(p);if(s->size>bound||s->size>s->capacity||s->capacity<15)return false;
   const auto* data=s->capacity>=16?*reinterpret_cast<unsigned char* const*>(s->bytes):s->bytes;
   if(s->size&&reinterpret_cast<uintptr_t>(data)<0x10000)return false;memcpy(dst,data,static_cast<size_t>(s->size));*size=static_cast<size_t>(s->size);return true;
  }__except(EXCEPTION_EXECUTE_HANDLER){return false;}
 };
 if(!read(address,buffer.data(),&length,max))return false;out.assign(reinterpret_cast<const char*>(buffer.data()),length);return out.find('\0')==std::string::npos;
}
bool Read(uintptr_t address,void* target,size_t size)noexcept{__try{memcpy(target,reinterpret_cast<const void*>(address),size);return true;}__except(EXCEPTION_EXECUTE_HANDLER){return false;}}
struct Entry {uintptr_t rva;unsigned char bytes[16];};
constexpr Entry kEntries[]={
 {0x16E1510,{0x55,0x41,0x57,0x41,0x56,0x41,0x54,0x56,0x57,0x53,0x48,0x81,0xec,0x80,0x02,0}},
 {0x1D3FC0,{0x56,0x57,0x48,0x83,0xec,0x28,0x48,0x89,0xce,0x48,0x8d,0x05,0x88,0xe4,0xff,0x07}},
 {0xA1DD50,{0x56,0x57,0x48,0x83,0xec,0x28,0x48,0x89,0xce,0x81,0x79,0x0c,0x10,0x27,0,0}},
 {0xA234B0,{0x55,0x41,0x57,0x41,0x56,0x41,0x55,0x41,0x54,0x56,0x57,0x53,0x48,0x81,0xec,0x98}},
 {0x410C0,{0x48,0x8b,0x05,0x59,0x9a,0x7f,0x0a,0xc3,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc}},
 {0x425C0,{0x56,0x48,0x83,0xec,0x40,0x48,0x89,0xce,0x48,0x8b,0x05,0xf1,0xba,0x08,0x0a,0x48}},
 {0x32C900,{0x48,0x89,0xd0,0x0f,0x57,0xc0,0x0f,0x11,0x02,0x48,0x8b,0x51,0x30,0x48,0x85,0xd2}},
 {0x64AA70,{0x55,0x56,0x57,0x48,0x81,0xec,0x90,0,0,0,0x48,0x8d,0xac,0x24,0x80,0}},
 {0x35D33A0,{0x55,0x41,0x57,0x41,0x56,0x41,0x55,0x41,0x54,0x56,0x57,0x53,0x48,0x81,0xec,0xa8}},
 {0x16E41E0,{0x55,0x56,0x57,0x48,0x83,0xec,0x60,0x48,0x8d,0x6c,0x24,0x60,0x48,0xc7,0x45,0xf8}},
 {0xA21B40,{0x55,0x56,0x57,0x53,0x48,0x83,0xec,0x38,0x48,0x8d,0x6c,0x24,0x30,0x48,0xc7,0x45}},
 {0x9FE580,{0x55,0x41,0x57,0x41,0x56,0x41,0x54,0x56,0x57,0x53,0x48,0x81,0xec,0x90,0x01,0}},
 {0x171BFF0,{0x55,0x41,0x57,0x41,0x56,0x41,0x55,0x41,0x54,0x56,0x57,0x53,0x48,0x81,0xec,0x58}},
 {0x3C9F70,{0x55,0x41,0x57,0x41,0x56,0x56,0x57,0x53,0x48,0x81,0xec,0x08,0x02,0,0,0x48}},
 {0x34B0C0,{0x8b,0x81,0xc4,0,0,0,0xc3,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc}},
 {0xA2BF30,{0x55,0x41,0x57,0x41,0x56,0x56,0x57,0x53,0x48,0x83,0xec,0x68,0x48,0x8d,0x6c,0x24}},
 {0x55900,{0x56,0x57,0x48,0x83,0xec,0x28,0x48,0x89,0xce,0x48,0x8b,0x79,0x30,0x48,0x85,0xff}},
 {0x54470,{0x41,0x57,0x41,0x56,0x41,0x54,0x56,0x57,0x53,0x48,0x83,0xec,0x28,0x48,0x85,0xd2}},
 {0x2130,{0x56,0x48,0x83,0xec,0x20,0x48,0x8b,0x71,0x08,0x48,0x85,0xf6,0x74,0x23,0xf0,0xff}},
 {0x7980,{0x56,0x48,0x83,0xec,0x20,0x48,0x89,0xce,0x48,0x8b,0x41,0x18,0x48,0x83,0xf8,0x08}},
 {0x20C0,{0x56,0x48,0x83,0xec,0x20,0x48,0x89,0xce,0x48,0x8b,0x41,0x18,0x48,0x83,0xf8,0x10}}
};
uintptr_t Binding(){
 if(g_IsLogin!=1||!g_hWeixinDll)return 0;
 try{auto id=RuntimeIdentity().at("weixin");if(!id.value("verified",false)||!id.value("mapped_headers_match",false))return 0;}catch(...){return 0;}
 auto base=reinterpret_cast<uintptr_t>(g_hWeixinDll);unsigned char observed[16];
 for(const auto& e:kEntries)if(!Read(base+e.rva,observed,16)||memcmp(e.bytes,observed,16))return 0;return base;
}
std::string CurrentAccount(uintptr_t base){
 // Same virtual account-string getter used by native A1DD50. Borrow/copy only.
 const auto address=[](uintptr_t b)noexcept->uintptr_t{
  __try{const auto app=Function<uintptr_t(*)()>(b,0x410C0)();if(app<0x10000)return 0;
   const auto table=*reinterpret_cast<const uintptr_t*>(app);return reinterpret_cast<uintptr_t(*)(uintptr_t)>(*reinterpret_cast<const uintptr_t*>(table+32))(app);
  }__except(EXCEPTION_EXECUTE_HANDLER){return 0;}
 }(base);
 std::string value;if(!address||!CopyString(address,value,256))return {};return value;
}
std::string AccountStamp(uintptr_t base){
 auto account=CurrentAccount(base);if(account.empty())return {};
 Owner root(base),scope(base);
 Function<void*(*)(Pair*)>(base,0x425C0)(&root.pair);if(!root.pair.object||!root.pair.control)return {};
 Function<void*(*)(void*,Pair*)>(base,0x32C900)(root.pair.object,&scope.pair);if(!scope.pair.object||!scope.pair.control)return {};
 // Account-owned scope identity prevents a logout/login of the same wxid
 // from making an older task current again. This stamp is never exposed.
 return account+":"+std::to_string(reinterpret_cast<uintptr_t>(scope.pair.control));
}
bool Wait(uintptr_t base,Future& future,bool& unknown){
 unknown=false;if(!future.owner.object||!future.owner.control){unknown=true;return false;}
 // await_noexcept handles cooperative resume/cancellation. Check rejection
 // before entering native typed unwrap, whose await rejects fatally on state 2.
 if(Function<int64_t(*)(Future*)>(base,0x3C9F70)(&future)<0){unknown=true;return false;}
 const auto state=Function<uint32_t(*)(void*)>(base,0x34B0C0)(future.owner.object);unknown=state!=1&&state!=2;return state==1;
}
std::filesystem::path ResourcePath(uintptr_t base,void* record,uint32_t kind){
 Wide wide;Function<void*(*)(Wide*,void*,uint32_t*,uint32_t)>(base,0x9FE580)(&wide,record,&kind,1);
 struct Destroy{uintptr_t base;Wide& wide;~Destroy(){Function<void(*)(Wide*)>(base,0x7980)(&wide);}} destroy{base,wide};
 if(wide.size>32760||wide.size>wide.capacity||wide.capacity<7)return {};
 const auto* data=wide.capacity>=8?*reinterpret_cast<const wchar_t* const*>(wide.bytes):wide.bytes;
 std::wstring result(data,static_cast<size_t>(wide.size));if(result.find(L'\0')!=std::wstring::npos)return {};return result;
}
class NativeBackend final:public Backend {
public:
 std::string Account()override{const auto base=Binding();return base?AccountStamp(base):std::string();}
 void Discard(const Artifact& artifact)noexcept override{
  if(artifact.path.empty())return;try{wchar_t temp[MAX_PATH]{};if(!GetTempPathW(MAX_PATH,temp))return;
   auto file=Utf8Path(artifact.path);auto stem=file.stem().wstring();
   if(file.parent_path()!=std::filesystem::path(temp)/L"wxcx-media"||stem.size()!=32||stem.find_first_not_of(L"0123456789abcdef")!=std::wstring::npos)return;
   DeleteFileW(file.c_str());
  }catch(...){}
 }
 StartResult Start(const Request& request,const std::string& account,Progress progress,Complete finish)override{
  const auto preparedBase=Binding();if(!preparedBase)return {"native_binding_unverified",false};
  auto heldScope=std::make_shared<Owner>(preparedBase);
  try{
   Owner root(preparedBase);Function<void*(*)(Pair*)>(preparedBase,0x425C0)(&root.pair);
   if(!root.pair.object)return {"account_changed",false};
   Function<void*(*)(void*,Pair*)>(preparedBase,0x32C900)(root.pair.object,&heldScope->pair);
   if(!heldScope->pair.object||!heldScope->pair.control||CurrentAccount(preparedBase)+":"+std::to_string(reinterpret_cast<uintptr_t>(heldScope->pair.control))!=account)return {"account_changed",false};
  }catch(...){return {"native_exception",false};}
  // Retaining the account control block before queueing also prevents pointer
  // reuse from turning a same-wxid logout/login into a false stamp match.
  struct Ticket {std::atomic<bool> entered{false};Complete finish;explicit Ticket(Complete f):finish(std::move(f)){}~Ticket(){if(!entered.load()){try{finish(Outcome{"native_task_discarded"});}catch(...){}}}};
  auto ticket=std::make_shared<Ticket>(finish);
  auto result=native::coroutine::StartTask([request,account,ticket,heldScope,progress=std::move(progress),finish=std::move(finish)](native::ContextState context,uint32_t){
   ticket->entered.store(true);
   Outcome out;bool downloadSubmitted=false,downloadFinished=false;
   try{
    if(context!=native::ContextState::Present){out.error="coroutine_context_missing";finish(std::move(out));return;}
    const auto base=Binding();if(!base){out.error="native_binding_unverified";finish(std::move(out));return;}
    const auto current=[base,account]{return g_IsLogin==1&&AccountStamp(base)==account;};
    if(!current()||!progress("locating")){out.error="account_changed";finish(std::move(out));return;}
    auto found=msgloc::LocateUnique(request.msgsvrid,request.source_talker,[&]{return !current();});
    if(!found.complete||found.status!="found"||found.matches.size()!=1){
     out.error=!found.complete?"source_lookup_incomplete":found.matches.empty()?"source_not_found":"source_ambiguous";finish(std::move(out));return;}
    const auto& match=found.matches[0];if(match.talker.empty()){out.error="source_lookup_incomplete";finish(std::move(out));return;}
    if(!progress("querying")){out.error="account_changed";finish(std::move(out));return;}
    Owner service(base),record(base);
    Function<void*(*)(void*,Pair*)>(base,0x64AA70)(heldScope->pair.object,&service.pair);
    if(!service.pair.object)throw std::runtime_error("service");
    NativeString session(base,match.talker);
    alignas(8) unsigned char optional[736]{};
    struct RecordCleanup{uintptr_t base;unsigned char* data;~RecordCleanup(){if(data[728]==1)Function<void(*)(void*)>(base,0x1D3FC0)(data);}} recordCleanup{base,optional};
    // Full business loader: unlike the repository-only future, this hydrates
    // attachment metadata and resource state before returning the native record.
    Function<void*(*)(void*,void*,String*,uint64_t,uint32_t)>(base,0x16E1510)(service.pair.object,optional,&session.value,request.msgsvrid,0);
    alignas(8) unsigned char ignored[24]{};
    if(optional[728]!=1){out.error="source_not_found";finish(std::move(out));return;}
    // Clone an actual queried native record, never a fabricated database DTO.
    Function<void*(*)(void*,Pair*)>(base,0xA21B40)(optional,&record.pair);
    if(!record.pair.object||!record.pair.control)throw std::runtime_error("record");
    const auto rec=reinterpret_cast<uintptr_t>(record.pair.object);
    const auto svrid=*reinterpret_cast<const uint64_t*>(rec+328);
    const auto type=*reinterpret_cast<const uint32_t*>(rec+12);
    const auto subtype=*reinterpret_cast<const uint32_t*>(rec+16);
    auto* talker=Function<void*(*)(void*)>(base,0xA1DD50)(record.pair.object);std::string returnedTalker;
    if(svrid!=request.msgsvrid||!CopyString(reinterpret_cast<uintptr_t>(talker),returnedTalker,256)||returnedTalker!=match.talker){out.error="source_identity_mismatch";finish(std::move(out));return;}
    // A12970 establishes _t.dat / .dat / _h.dat for image 1 / 2 / 3.
    const uint32_t resource=NativeResourceKind(request,type,subtype);
    if(!resource){out.error="type_unsupported";finish(std::move(out));return;}
    ExpectedResource expected;
    if(request.kind!="image"){
     // A234B0 is the native body getter (video/file body at record+384).
     // record+88 is source metadata, not message XML.
     NativeString body(base,"");Function<void*(*)(void*,String*)>(base,0xA234B0)(record.pair.object,&body.value);
     std::string xml;if(!CopyString(reinterpret_cast<uintptr_t>(&body.value),xml,1024*1024)){out.error="source_metadata_invalid";finish(std::move(out));return;}
     auto metadata=messages::SourceResourceMetadata(type,xml);
     if(metadata.at("status")!="parsed"||!ids::ParseUint64(metadata.at("total_bytes"),expected.bytes)){out.error="source_metadata_invalid";finish(std::move(out));return;}
     expected.present=true;if(!metadata.at("md5").is_null())expected.md5=metadata.at("md5").get<std::string>();
     if(!metadata.at("extension").is_null())expected.extension=metadata.at("extension").get<std::string>();
    }
    if(!current()||!progress("checking")){out.error="account_changed";finish(std::move(out));return;}
    auto path=ResourcePath(base,record.pair.object,resource);std::error_code ec;
    if(request.kind=="image"&&!path.empty()&&!MatchesNativeImagePath(path,request.image_quality)){out.error="image_resource_kind_mismatch";finish(std::move(out));return;}
    bool exists=!path.empty()&&std::filesystem::is_regular_file(path,ec)&&!ec;
    if(exists){const auto size=std::filesystem::file_size(path,ec);exists=!ec&&(size>0||request.kind=="file");if(expected.present&&size!=expected.bytes)exists=false;}
    if(!exists){
     if(!request.download){out.error="resource_missing";finish(std::move(out));return;}
     if(!progress("downloading")){out.error="account_changed";finish(std::move(out));return;}
     Future future;DownloadOptions options;
     struct FutureCleanup{uintptr_t base;Future& value;~FutureCleanup(){if(value.owner.control)Function<void(*)(Pair*)>(base,0x2130)(&value.owner);}} futureCleanup{base,future};
     // 171BFF0 consumes this separate strong reference on every native exit.
     Pair passed=record.pair;InterlockedIncrement(reinterpret_cast<volatile long*>(reinterpret_cast<uintptr_t>(passed.control)+8));
     downloadSubmitted=true;
     Function<void*(*)(void*,Pair*,Pair*,uint32_t,uint32_t,DownloadOptions*)>(base,0x171BFF0)(service.pair.object,&future.owner,&passed,resource,0,&options);
     if(!Wait(base,future,out.result_unknown)){out.error="resource_failed";finish(std::move(out));return;}
     downloadFinished=true;
     DownloadResult result;bool made=false;
     struct Cleanup{uintptr_t base;DownloadResult& result;bool& made;~Cleanup(){if(made)Function<void(*)(DownloadResult*)>(base,0x55900)(&result);}} cleanup{base,result,made};
     Function<void*(*)(void*,DownloadResult*,Pair*)>(base,0xA2BF30)(ignored,&result,&future.owner);made=true;
     out.native_code=result.code;out.native_detail=result.detail;
     if(result.code||result.detail){out.error="resource_failed";finish(std::move(out));return;}
     if(!current()){out.error="account_changed";finish(std::move(out));return;}
     path=ResourcePath(base,record.pair.object,resource);
     if(request.kind=="image"&&!path.empty()&&!MatchesNativeImagePath(path,request.image_quality)){out.error="image_resource_kind_mismatch";finish(std::move(out));return;}
    }
    if(!progress(request.kind=="image"?"decoding":"verifying")){out.error="account_changed";finish(std::move(out));return;}
    wchar_t temp[MAX_PATH]{};if(!GetTempPathW(MAX_PATH,temp)){out.error="output_failed";finish(std::move(out));return;}
    out=PrepareArtifact(path,request.kind,std::filesystem::path(temp)/L"wxcx-media",DeriveLiveImageKeys,current,DecodeLiveWxgf,expected);
    if(out.error.empty()&&request.kind=="image")out.artifact.image_quality=request.image_quality;
   }catch(...){out.error="native_exception";out.result_unknown=downloadSubmitted&&!downloadFinished;}
   finish(std::move(out));
  });
  return {result.error,static_cast<bool>(result.probe)||result.error=="coroutine_launch_exception"};
 }
};
}
std::shared_ptr<Backend> CreateNativeBackend(){return std::make_shared<NativeBackend>();}
}
