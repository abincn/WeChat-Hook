#include "wxcx_addmsg.h"
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <vector>
#include <string>
using namespace wxcx::messages;
namespace {
constexpr uintptr_t base=0x100000, module=0x180000000;
struct Memory {
    std::vector<unsigned char> bytes=std::vector<unsigned char>(131072);
    template<class T> void Put(size_t at,T value) { std::memcpy(bytes.data()+at,&value,sizeof(value)); }
    static bool Read(uintptr_t at,void* out,size_t size,void* context) {
        auto& m=*static_cast<Memory*>(context);
        if(at<base || at-base>m.bytes.size() || size>m.bytes.size()-(at-base))return false;
        std::memcpy(out,m.bytes.data()+(at-base),size);return true;
    }
    void String(size_t at,const std::string& text,size_t heap) {
        Put<uint64_t>(at+16,text.size());Put<uint64_t>(at+24,text.size()<16?15:text.size());
        if(text.size()<16)std::memcpy(bytes.data()+at,text.data(),text.size());
        else {Put<uintptr_t>(at,base+heap);std::memcpy(bytes.data()+heap,text.data(),text.size());}
    }
    void Arena(size_t field,size_t wrapper,size_t rep,const std::string& text,size_t heap) {
        Put<uintptr_t>(field,base+wrapper);Put<uintptr_t>(wrapper,module+0x82643A8);
        Put<uintptr_t>(wrapper+8,base+rep);String(rep,text,heap);
    }
    Memory() {
        Put<uintptr_t>(0,module+0x83DF408);Put<uint32_t>(0x6c,0xb1e);
        Put<uint32_t>(0x14,1);Put<uint32_t>(0x48,1793232000);
        Put<uint64_t>(0x50,18446744073709551614ULL);
        Arena(8,0x100,0x200,"room@chatroom",0x2000);
        Arena(0x18,0x300,0x400,"wxid_self",0x3000);
        Arena(0x20,0x500,0x600,"wxid_sender:\nhello",0x4000);
        Put<uintptr_t>(0x38,base+0x700);String(0x700,"<msgsource><atuserlist>wxid_self</atuserlist></msgsource>",0x5000);
    }
    bool Decode(RawMessage& out) {return DecodeAddMsg(base,module,Read,this,out);}
};
int checks=0;
void Check(bool value) {++checks;if(!value)throw std::runtime_error("check "+std::to_string(checks));}
}
int main() {
    try {
        Memory m;RawMessage out{};Check(m.Decode(out));Check(out.server_id==18446744073709551614ULL);
        Check(out.create_time==1793232000);Check(out.msgsource_known && out.msgsource_complete);
        Check(std::string(out.content,out.content_size)=="wxid_sender:\nhello");
        Check(std::string(out.msgsource,out.source_size).find("wxid_self")!=std::string::npos);
        m.Put<uint32_t>(0x6c,0x1e);out={};Check(m.Decode(out));Check(out.server_id==0 && out.create_time==0);
        Check(out.msgsource_known && out.source_size==0);
        m.Put<uint32_t>(0x6c,0x21e);m.Put<uintptr_t>(0x38,0x42);out={};Check(m.Decode(out));Check(!out.msgsource_known && !out.msgsource_complete);
        m.Put<uintptr_t>(0,module);Check(!m.Decode(out));m.Put<uintptr_t>(0,module+0x83DF408);
        m.Put<uint32_t>(0x6c,0x1c);Check(!m.Decode(out));m.Put<uint32_t>(0x6c,0x1e);
        m.Put<uintptr_t>(0x100,module);Check(!m.Decode(out));m.Put<uintptr_t>(0x100,module+0x82643A8);
        m.Arena(0x20,0x500,0x600,std::string(20000,'x'),0x8000);out={};Check(m.Decode(out));Check(out.content_size==16384 && !out.content_complete);
        m.Put<uint64_t>(0x618,1);Check(!m.Decode(out));
        Check(!DecodeAddMsg(base,module,nullptr,nullptr,out));
        Check(!DecodeAddMsg(UINTPTR_MAX-2,module,Memory::Read,&m,out));
        Check(!DecodeAddMsg(base,UINTPTR_MAX-2,Memory::Read,&m,out));
        std::cout<<checks<<" AddMsg decoder checks passed\n";return 0;
    }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
}
