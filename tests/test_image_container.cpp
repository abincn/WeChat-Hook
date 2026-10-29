#include "wxcx_image_container.h"
#include <windows.h>
#include <bcrypt.h>
#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <cstring>
#pragma comment(lib,"bcrypt.lib")
using namespace wxcx::media;
namespace {
int checks=0;
void Check(bool value){++checks;if(!value)throw std::runtime_error("check "+std::to_string(checks));}
Bytes Encrypt(const Bytes& plain,const ImageKeys& keys){
    BCRYPT_ALG_HANDLE alg=nullptr;BCRYPT_KEY_HANDLE key=nullptr;ULONG objectSize=0,n=0;Bytes object,out;
    auto cleanup=[&]{if(key)BCryptDestroyKey(key);if(alg)BCryptCloseAlgorithmProvider(alg,0);};
    try{
        Check(BCryptOpenAlgorithmProvider(&alg,BCRYPT_AES_ALGORITHM,nullptr,0)>=0);
        Check(BCryptSetProperty(alg,BCRYPT_CHAINING_MODE,reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_ECB)),sizeof(BCRYPT_CHAIN_MODE_ECB),0)>=0);
        Check(BCryptGetProperty(alg,BCRYPT_OBJECT_LENGTH,reinterpret_cast<PUCHAR>(&objectSize),sizeof(objectSize),&n,0)>=0);
        object.resize(objectSize);
        Check(BCryptGenerateSymmetricKey(alg,&key,object.data(),objectSize,const_cast<PUCHAR>(keys.aes.data()),16,0)>=0);
        out.resize((plain.size()/16+1)*16);
        Check(BCryptEncrypt(key,const_cast<PUCHAR>(plain.data()),static_cast<ULONG>(plain.size()),nullptr,nullptr,0,out.data(),static_cast<ULONG>(out.size()),&n,BCRYPT_BLOCK_PADDING)>=0);
        out.resize(n);cleanup();return out;
    }catch(...){cleanup();throw;}
}
void Put(Bytes& bytes,size_t at,uint32_t n){for(int i=0;i<4;++i)bytes[at+i]=static_cast<unsigned char>(n>>(i*8));}
Bytes Fixture(const Bytes& plain,const ImageKeys& keys){
    const size_t head=(std::min)(plain.size(),size_t(1024));
    const size_t tail=(std::min)(plain.size()-head,size_t(1024*1024));
    auto encrypted=Encrypt(Bytes(plain.begin(),plain.begin()+head),keys);
    Bytes out(15);out[0]=7;out[1]=8;out[2]=0x56;out[3]=0x32;out[4]=8;out[5]=7;out[14]=1;
    Put(out,6,static_cast<uint32_t>(head));Put(out,10,static_cast<uint32_t>(tail));
    out.insert(out.end(),encrypted.begin(),encrypted.end());
    out.insert(out.end(),plain.begin()+head,plain.end()-tail);
    for(auto i=plain.end()-tail;i!=plain.end();++i)out.push_back(*i^keys.xor_byte);
    return out;
}
}
int main(){try{
    ImageKeys keys;for(size_t i=0;i<16;++i)keys.aes[i]=static_cast<unsigned char>(i);keys.xor_byte=0x5a;
    // AES prefix block: NIST SP800-38A F.1.1 known-answer vector.
    ImageKeys nist;const unsigned char key[]={0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
    std::copy(std::begin(key),std::end(key),nist.aes.begin());
    const Bytes original={0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a};
    const Bytes cipher={0x3a,0xd7,0x7b,0xb4,0x0d,0x7a,0x36,0x60,0xa8,0x9e,0xca,0xf3,0x24,0x66,0xef,0x97};
    auto known=Fixture(original,nist);Check(std::equal(cipher.begin(),cipher.end(),known.begin()+15));
    auto result=DecodeImageV2(known,nist);Check(result.decoded && result.content==original && result.format=="unknown");
    for(size_t length:{size_t(3),size_t(15),size_t(16),size_t(17),size_t(1023),size_t(1024),size_t(1025),size_t(1024*1024+1024),size_t(1024*1024+1024+4097)}){
        Bytes plain(length);for(size_t i=0;i<length;++i)plain[i]=static_cast<unsigned char>(i*17);
        plain[0]=0xff;plain[1]=0xd8;plain[2]=0xff;
        auto encrypted=Fixture(plain,keys);ImageLayout layout;std::string error;
        Check(InspectImageV2(encrypted,layout,error));Check(layout.aes_plain==(std::min)(length,size_t(1024)));
        auto decoded=DecodeImageV2(encrypted,keys);Check(decoded.decoded);Check(decoded.error.empty());Check(decoded.content==plain);Check(decoded.format=="jpeg");
        if(length>1024*1024+1024)Check(layout.middle==4097);
    }
    for(const auto header: {std::string("\x89PNG\r\n\x1a\n",8),std::string("GIF89a"),std::string("RIFFxxxxWEBP"),std::string("wxgf"),std::string("other")}){
        const Bytes plain(header.begin(),header.end());auto result=DecodeImageV2(Fixture(plain,keys),keys);Check(result.decoded);
        const auto expected=header[0]=='\x89'?"png":header.substr(0,3)=="GIF"?"gif":header.substr(0,4)=="RIFF"?"webp":header=="wxgf"?"wxgf":"unknown";
        Check(result.format==expected);
    }
    auto good=Fixture(Bytes(1025,0x41),keys);
    for(size_t at:{size_t(0),size_t(1),size_t(2),size_t(3),size_t(4),size_t(5),size_t(14)}){auto bad=good;bad[at]^=1;auto result=DecodeImageV2(bad,keys);Check(!result.decoded && result.content.empty());}
    for(size_t n=0;n<15;++n){Check(!DecodeImageV2(Bytes(n),keys).decoded);}
    for(uint32_t value:{0U,1025U,UINT32_MAX}){auto bad=good;Put(bad,6,value);Check(!DecodeImageV2(bad,keys).decoded);}
    for(uint32_t value:{1048577U,UINT32_MAX}){auto bad=good;Put(bad,10,value);Check(!DecodeImageV2(bad,keys).decoded);}
    auto truncated=good;truncated.resize(15+1024);Check(!DecodeImageV2(truncated,keys).decoded);
    auto corrupt=good;corrupt[15+1039]^=0x80;auto failed=DecodeImageV2(corrupt,keys);Check(!failed.decoded && failed.content.empty());
    ImageKeys wrong=keys;wrong.aes[0]^=1;failed=DecodeImageV2(good,wrong);Check(!failed.decoded && failed.error=="image_key_or_padding_invalid");
    auto inconsistent=good;inconsistent.insert(inconsistent.begin()+15+1040,0);Check(!DecodeImageV2(inconsistent,keys).decoded);
    EraseImageKeys(keys);Check(std::all_of(keys.aes.begin(),keys.aes.end(),[](auto c){return c==0;}) && keys.xor_byte==0);
    std::cout<<checks<<" image container checks passed; no native calls/network/filesystem decryption\n";return 0;
}catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}}
