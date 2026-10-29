#include "httplib.h"
#include "wxcx_media_tasks.h"
#include "wxcx_media_native.h"
#include "wxcx_media_files.h"
#include "wxcx_wxgf.h"
#include "wxcx_utf8_path.h"
#include "wxcx_message_model.h"
#include "wxcx_msgloc.h"
#include "wxcx_identity.h"
#include "global.h"
#include <windows.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <vector>
#include <future>
HMODULE g_hWeixinDll=nullptr;volatile uint64_t g_IsLogin=0;
namespace wxcx {nlohmann::json RuntimeIdentity(){return {{"weixin",{{"verified",false}}}};}}
namespace wxcx::msgloc {UniqueResult LocateUnique(uint64_t,const std::string&,const std::function<bool()>&){throw std::runtime_error("native lookup must not execute in offline test");}}
namespace wxcx::media {bool DeriveLiveImageKeys(ImageKeys&,std::string& error){error="version_unverified";return false;}}
using namespace wxcx::media;
int checks=0;
void Check(bool value){++checks;if(!value)throw std::runtime_error("media check "+std::to_string(checks));}
struct Fake:Backend {
 std::string account="a";unsigned starts=0,discarded=0;bool fail=false,unknown=false,sync=false;Progress progress;Complete complete;
 std::string Account()override{return account;}
 void Discard(const Artifact& a)noexcept override{if(!a.path.empty())++discarded;}
 StartResult Start(const Request&,const std::string& owner,Progress p,Complete c)override{++starts;Check(owner==account);progress=p;complete=c;if(sync)c(Good());return {fail?"unsafe private error":"",unknown};}
 static Outcome Good(){return {"",{"fake-file","file",std::string(64,'a'),3}};}
};
Json RequestJson(const std::string& id="r"){return {{"msgsvrid","18446744073709551615"},{"kind","image"},{"request_id",id},{"source_talker","group@chatroom"}};}
class MemoryServer:public httplib::Server {
public:
 Reply Call(const std::string& method,const std::string& path,const std::string& body={}){
 auto request=method+" "+path+" HTTP/1.1\r\nHost: offline\r\nContent-Type: application/json\r\nContent-Length: "+std::to_string(body.size())+"\r\nConnection: close\r\n\r\n"+body;
 httplib::detail::BufferStream stream;stream.write(request.data(),request.size());bool closed=false;Check(process_request(stream,true,closed,{}));
 auto response=stream.get_buffer().substr(request.size());auto payload=response.substr(response.find("\r\n\r\n")+4);auto value=Json::parse(payload,nullptr,false);return {std::stoi(response.substr(9,3)),value.is_discarded()?Json(payload):value};
 }
};
int codecMode=0,codecCalls=0;
int Info(const unsigned char*,uint32_t,int* meta){meta[0]=1;meta[1]=1;meta[2]=1;if(codecMode==1)return -1;if(codecMode==2)meta[1]=0;if(codecMode==3){meta[0]=32*1024*1024;meta[1]=32*1024*1024;}return 0;}
const unsigned char kGif[]={71,73,70,56,57,97,1,0,1,0,128,0,0,0,0,0,255,255,255,33,249,4,1,0,0,0,0,44,0,0,0,0,1,0,1,0,0,2,1,68,0,59};
int Convert(const unsigned char*,uint32_t,unsigned char* target,int* length,const int* options){
 ++codecCalls;for(unsigned i=0;i<8;++i)Check(options[i]==0);
 if(codecMode==4)return -206;if(codecMode==5){*length=51*1024*1024;return -206;}
 if(codecMode==6){*length=*length+1;return 0;}if(codecMode==7)return -9;
 if(*length<static_cast<int>(sizeof(kGif))){*length=sizeof(kGif);return -206;}memcpy(target,kGif,sizeof(kGif));*length=sizeof(kGif);return 0;
}
int main(){try{
 std::array<unsigned char,12> validStub{0x48,0x8d,0x05,0xfc,0xd6,0xf9,0x03,0xe9,0x9c,0,0,0};auto changedStub=validStub;changedStub[3]^=1;
 Check(wxgf::ImportTargetMatches(0x200000,0x200000,0x100000,0x875,{},validStub));
 Check(wxgf::ImportTargetMatches(0x100875,0x200000,0x100000,0x875,validStub,validStub));
 Check(!wxgf::ImportTargetMatches(0x100875,0x200000,0x100000,0x875,changedStub,validStub));
 Check(!wxgf::ImportTargetMatches(0x100876,0x200000,0x100000,0x875,validStub,validStub));
 Check(!wxgf::ImportTargetMatches(0,0x200000,0x100000,0x875,validStub,validStub));
 Request imageRequest;imageRequest.kind="image";
 Check(NativeResourceKind(imageRequest,3,0)==2);
 imageRequest.image_quality="original";Check(NativeResourceKind(imageRequest,3,0)==3);
 imageRequest.image_quality="thumbnail";Check(NativeResourceKind(imageRequest,3,0)==0);
 imageRequest.kind="video";Check(NativeResourceKind(imageRequest,43,0)==32);Check(NativeResourceKind(imageRequest,3,0)==0);
 imageRequest.kind="file";Check(NativeResourceKind(imageRequest,49,6)==103);Check(NativeResourceKind(imageRequest,49,74)==0);
 Check(!MatchesNativeImagePath(L"abc_t.dat","full"));Check(!MatchesNativeImagePath(L"abc_T.DAT","original"));
 Check(!MatchesNativeImagePath(L"abc_thumb.jpg","full"));Check(MatchesNativeImagePath(L"abc.dat","full"));
 Check(!MatchesNativeImagePath(L"abc_h.dat","full"));Check(MatchesNativeImagePath(L"abc_H.DAT","original"));
 Check(!MatchesNativeImagePath(L"abc.dat","original"));Check(!MatchesNativeImagePath(L"abc.jpeg","full"));
 auto native=CreateNativeBackend();Check(native->Account().empty());
 auto metadata=wxcx::messages::SourceResourceMetadata(49,"<msg><appmsg><type>6</type><md5>900150983CD24FB0D6963F7D28E17F72</md5><appattach><totallen>3</totallen></appattach></appmsg></msg>");Check(metadata.at("status")=="parsed");Check(metadata.at("total_bytes")=="3");Check(metadata.at("md5")=="900150983cd24fb0d6963f7d28e17f72");
 Check(wxcx::messages::SourceResourceMetadata(43,"<msg><videomsg length='3' md5='900150983cd24fb0d6963f7d28e17f72'/></msg>").at("status")=="parsed");
 for(const auto& xml:{"<msg><videomsg length='0'/></msg>","<msg><videomsg length='-1'/></msg>","<!DOCTYPE msg><msg><videomsg length='3'/></msg>","<msg><videomsg length='3' md5='bad'/></msg>","<msg><videomsg length='3'/><videomsg length='4'/></msg>"})Check(wxcx::messages::SourceResourceMetadata(43,xml).at("status")=="invalid");
 Check(wxcx::messages::SourceResourceMetadata(49,"<msg><appmsg><type>74</type><appattach><totallen>3</totallen></appattach></appmsg></msg>").at("status")=="invalid");
 Bytes privateImage{'w','x','g','f'};Check(!DecodeLiveWxgf(privateImage).decoded);
 Check(wxgf::ConvertWith(privateImage,nullptr,&Convert).error=="wxgf_codec_unverified");Check(wxgf::ConvertWith(Bytes{'x'},&Info,&Convert).error=="unsupported_image_format");
 for(int mode=1;mode<=7;++mode){codecMode=mode;Check(!wxgf::ConvertWith(privateImage,&Info,&Convert).decoded);}
 codecMode=0;codecCalls=0;auto converted=wxgf::ConvertWith(privateImage,&Info,&Convert);Check(converted.decoded&&converted.content.size()==sizeof(kGif));Check(codecCalls==2);
 auto f=std::make_shared<Fake>();auto now=Service::Clock::now();Service service(f,"test",{16,2,std::chrono::milliseconds(100)},[&]{return now;});
 for(Json bad:{Json::array(),Json{{"msgsvrid",-1},{"kind","image"}},Json{{"msgsvrid",1.0},{"kind","image"}},Json{{"msgsvrid","18446744073709551616"},{"kind","image"}},Json{{"msgsvrid",0},{"kind","image"}},Json{{"msgsvrid",1},{"kind","voice"}},Json{{"msgsvrid",1},{"kind","image"},{"path","c:/arbitrary"}},Json{{"msgsvrid",1},{"kind","image"},{"download",1}}})Check(service.Submit(bad).status==400);
 auto reply=service.Submit(RequestJson());Check(reply.status==202);auto id=reply.body.at("task_id").get<std::string>();Check(f->starts==1);Check(service.Submit(RequestJson()).status==200);Check(f->starts==1);
 Check(reply.body.at("image_quality")=="full");auto explicitFull=RequestJson();explicitFull["image_quality"]="full";Check(service.Submit(explicitFull).status==200);
 auto original=RequestJson();original["image_quality"]="original";Check(service.Submit(original).status==409);
 for(const Json& quality:{Json("thumbnail"),Json(""),Json(1),Json(nullptr)}){auto bad=RequestJson("bad-quality");bad["image_quality"]=quality;Check(service.Submit(bad).status==400);}
 auto videoQuality=RequestJson("bad-video-quality");videoQuality["kind"]="video";videoQuality["image_quality"]="full";Check(service.Submit(videoQuality).status==400);
 auto changed=RequestJson();changed["kind"]="video";Check(service.Submit(changed).status==409);Check(service.Content(id).status==409);
 Check(f->progress("locating"));Check(f->progress("downloading"));auto done=f->complete;
 Check(service.Get(id).body.at("last_stage")=="downloading");Check(service.Get(id).body.at("download_started")==true);
 now+=std::chrono::milliseconds(101);Check(service.Get(id).body.at("state")=="result_unknown");Check(service.Get(id).body.at("native_pending")==true);
 done(Fake::Good());Check(f->discarded==1);Check(service.Get(id).body.at("state")=="result_unknown");Check(service.Get(id).body.at("native_pending")==false);Check(service.Content(id).status==409);Check(service.Submit(RequestJson()).status==200);Check(f->starts==1);
 reply=service.Submit(RequestJson("r2"));auto id2=reply.body.at("task_id").get<std::string>();done=f->complete;f->account="b";Check(service.Get(id2).status==404);done(Fake::Good());f->account="a";Check(service.Get(id2).body.at("state")=="account_changed");Check(service.Content(id2).status==409);
 f->sync=true;reply=service.Submit(RequestJson("r3"));Check(reply.body.at("state")=="ready");Check(service.Content(reply.body.at("task_id")).status==200);Check(reply.body.dump().find("fake-file")==std::string::npos);
 auto fail=std::make_shared<Fake>();fail->fail=true;Service failure(fail,"fail");reply=failure.Submit(RequestJson());Check(reply.body.at("state")=="failed");Check(reply.body.at("error")=="native_failed");Check(reply.body.dump().find("private")==std::string::npos);
 auto released=reply.body.at("task_id").get<std::string>();Check(failure.Release(released).status==200);Check(failure.Get(released).status==404);Check(failure.Submit(RequestJson()).status==410);Check(fail->starts==1);
 auto queue=std::make_shared<Fake>();Service limited(queue,"limit",{4,1,std::chrono::milliseconds(100)},[&]{return now;});reply=limited.Submit(RequestJson());Check(reply.status==202);Check(limited.Submit(RequestJson("second")).status==429);now+=std::chrono::seconds(1);Check(limited.Get(reply.body.at("task_id")).body.at("state")=="timed_out");Check(limited.Submit(RequestJson("second")).status==429);queue->complete({"resource_failed"});Check(limited.Status().at("active")==0);
 reply=limited.Submit(RequestJson("second"));Check(reply.status==202);Check(queue->progress("downloading"));limited.Stop();Check(limited.Get(reply.body.at("task_id")).body.at("state")=="result_unknown");queue->complete(Fake::Good());Check(limited.Submit(RequestJson("third")).status==503);
 auto timeout=std::make_shared<Fake>();timeout->fail=true;timeout->unknown=true;Service unknown(timeout,"unknown");reply=unknown.Submit(RequestJson());Check(reply.body.at("state")=="result_unknown");Check(reply.body.at("native_pending")==true);Check(unknown.Submit(RequestJson()).status==200);Check(timeout->starts==1);timeout->complete({"resource_failed"});Check(unknown.Status().at("active")==0);
 auto uncertain=std::make_shared<Fake>();Service uncertainService(uncertain,"uncertain");auto uncertainTask=uncertainService.Submit(RequestJson());Outcome uncertainOutcome;uncertainOutcome.error="native_exception";uncertainOutcome.result_unknown=true;uncertain->complete(uncertainOutcome);Check(uncertainService.Get(uncertainTask.body.at("task_id")).body.at("state")=="result_unknown");Check(uncertainService.Submit(RequestJson()).status==200);Check(uncertain->starts==1);
 auto httpBackend=std::make_shared<Fake>();auto http=std::make_shared<Service>(httpBackend,"http");MemoryServer server;RegisterRoutes(server,http);
 Check(server.Call("POST","/wxcx/media/tasks","broken").status==400);Check(server.Call("POST","/wxcx/media/tasks",std::string(2049,'x')).status==400);
 auto h=server.Call("POST","/wxcx/media/tasks",RequestJson().dump());Check(h.status==202);auto httpId=h.body.at("task_id").get<std::string>();
 Check(server.Call("GET","/wxcx/media/tasks/"+httpId).body.at("state")=="queued");Check(server.Call("DELETE","/wxcx/media/tasks/"+httpId).status==409);
 httpBackend->complete({"resource_failed"});Check(server.Call("GET","/wxcx/media/tasks/"+httpId+"/content").status==409);Check(server.Call("DELETE","/wxcx/media/tasks/"+httpId).status==200);Check(server.Call("POST","/wxcx/media/tasks",RequestJson().dump()).status==410);
 Check(server.Call("GET","/wxcx/media/requests/r").status==410);Check(server.Call("GET","/wxcx/media/requests/unknown").status==404);
 Check(server.Call("POST","/wxcx/media/stop","{\"force\":true}").status==400);Check(server.Call("POST","/wxcx/media/stop","{}").body.at("stopped")==true);
 auto parallel=std::make_shared<Fake>();Service concurrent(parallel,"parallel");auto one=std::async(std::launch::async,[&]{return concurrent.Submit(RequestJson());});auto two=std::async(std::launch::async,[&]{return concurrent.Submit(RequestJson());});auto first=one.get(),other=two.get();Check(first.body.at("task_id")==other.body.at("task_id"));Check(parallel->starts==1);Check(first.status+other.status==402);parallel->complete({"resource_failed"});
 // Real filesystem/crypto and WIC checks; no native WeChat calls or network.
 auto root=std::filesystem::temp_directory_path()/(L"wxcx-媒体-offline-"+std::to_wstring(GetCurrentProcessId()));std::filesystem::create_directories(root);auto source=root/L"source.bin";auto output=root/L"out";
 {std::ofstream file(source,std::ios::binary);file<<"abc";}
 bool current=true;int derivations=0;auto account=[&]{return current;};auto keys=[&](ImageKeys&,std::string& error){++derivations;error="version_unverified";return false;};
 auto file=PrepareArtifact(source,"file",output,keys,account);Check(file.error.empty());Check(file.artifact.bytes==3);Check(file.artifact.sha256=="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");Check(std::filesystem::exists(Utf8Path(file.artifact.path)));Check(derivations==0);
 auto assetBackend=std::make_shared<Fake>();auto assets=std::make_shared<Service>(assetBackend,"asset");MemoryServer assetServer;RegisterRoutes(assetServer,assets);auto accepted=assetServer.Call("POST","/wxcx/media/tasks",RequestJson().dump());auto assetId=accepted.body.at("task_id").get<std::string>();assetBackend->complete(file);
 auto content=assetServer.Call("GET","/wxcx/media/tasks/"+assetId+"/content");Check(content.status==200&&content.body=="abc");
 {std::ofstream changedFile(Utf8Path(file.artifact.path),std::ios::binary|std::ios::trunc);changedFile<<"xyz";}
 Check(assetServer.Call("GET","/wxcx/media/tasks/"+assetId+"/content").body.at("error")=="artifact_changed");
 Check(PrepareArtifact(root/L"missing","file",output,keys,account).error=="resource_missing");Check(PrepareArtifact(root,"file",output,keys,account).error.size()>0);
 Check(!PrepareArtifact(source,"image",output,keys,account).error.empty());Check(!PrepareArtifact(source,"video",output,keys,account).error.empty());
 current=false;Check(PrepareArtifact(source,"file",output,keys,account).error=="account_changed");current=true;
 auto second=PrepareArtifact(source,"file",output,keys,account);Check(second.error.empty());Check(second.artifact.path!=file.artifact.path);Check(second.artifact.sha256==file.artifact.sha256);
 auto named=PrepareArtifact(source,"file",output,keys,account,{},ExpectedResource{true,3,"900150983cd24fb0d6963f7d28e17f72","log"});Check(named.error.empty());Check(Utf8Path(named.artifact.path).extension()==L".log");
 Check(PrepareArtifact(source,"file",output,keys,account,{},ExpectedResource{true,4,{}}).error=="resource_integrity_mismatch");
 Check(PrepareArtifact(source,"file",output,keys,account,{},ExpectedResource{true,3,std::string(32,'0')}).error=="resource_integrity_mismatch");
 {std::ofstream empty(source,std::ios::binary|std::ios::trunc);}
 auto empty=PrepareArtifact(source,"file",output,keys,account,{},ExpectedResource{true,0,"d41d8cd98f00b204e9800998ecf8427e"});Check(empty.error.empty());Check(empty.artifact.bytes==0);Check(empty.artifact.sha256=="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
 auto gif=root/L"image.bin";const unsigned char image[]={71,73,70,56,57,97,1,0,1,0,128,0,0,0,0,0,255,255,255,33,249,4,1,0,0,0,0,44,0,0,0,0,1,0,1,0,0,2,1,68,0,59};
 {std::ofstream stream(gif,std::ios::binary);stream.write(reinterpret_cast<const char*>(image),sizeof(image));}
 auto decoded=PrepareArtifact(gif,"image",output,keys,account);Check(decoded.error.empty());Check(decoded.artifact.format=="gif");Check(derivations==0);
 auto thumbnail=root/L"image_t.dat";std::filesystem::copy_file(gif,thumbnail);
 Check(PrepareArtifact(thumbnail,"image",output,keys,account).error=="image_thumbnail_rejected");std::filesystem::remove(thumbnail);
 {std::ofstream stream(gif,std::ios::binary|std::ios::trunc);stream.write("wxgf",4);}
 Check(PrepareArtifact(gif,"image",output,keys,account).error=="unsupported_image_format");
 auto privateDecoded=PrepareArtifact(gif,"image",output,keys,account,[](const Bytes& b){return wxgf::ConvertWith(b,&Info,&Convert);});Check(privateDecoded.error.empty());Check(privateDecoded.artifact.format=="gif");Check(privateDecoded.artifact.sha256==decoded.artifact.sha256);
 for(const auto& entry:std::filesystem::directory_iterator(output))std::filesystem::remove(entry.path());std::filesystem::remove(output);std::filesystem::remove(source);std::filesystem::remove(gif);std::filesystem::remove(root);
 std::cout<<checks<<" media lifecycle/file checks passed; no WeChat native calls/network\n";return 0;
 }catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}}
