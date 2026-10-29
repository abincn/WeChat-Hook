#include "wxcx_image_container.h"
#include "wxcx_identity.h"
#include "global.h"
#include <iostream>
#include <stdexcept>
#include <algorithm>
HMODULE g_hWeixinDll=nullptr;
volatile uint64_t g_IsLogin=0;
namespace { bool ready=false, broken=false,mapped=true; int checks=0;
void Check(bool condition){++checks;if(!condition)throw std::runtime_error("key gate check "+std::to_string(checks));}
}
namespace wxcx { nlohmann::json RuntimeIdentity(){if(broken) return nlohmann::json::object();return {{"weixin",{{"verified",ready},{"mapped_headers_match",mapped}}}};} }
int main(){try{
    using namespace wxcx::media;
    ImageKeys keys;std::string error;
    auto zero=[&]{Check(keys.xor_byte==0 && std::all_of(keys.aes.begin(),keys.aes.end(),[](auto x){return x==0;}));};
    keys.aes.fill(7);keys.xor_byte=9;Check(!DeriveLiveImageKeys(keys,error));Check(error=="version_unverified");zero();
    broken=true;Check(!DeriveLiveImageKeys(keys,error));Check(error=="version_unverified");zero();broken=false;
    ready=true;mapped=false;Check(!DeriveLiveImageKeys(keys,error));Check(error=="version_unverified");zero();mapped=true;
    Check(!DeriveLiveImageKeys(keys,error));Check(error=="login_not_ready");zero();
    g_IsLogin=1;Check(!DeriveLiveImageKeys(keys,error));Check(error=="login_not_ready");zero();
    // Intentionally unmapped fake module. SEH prologue validation must reject
    // it before any indirect native call; no real WeChat process is involved.
    g_hWeixinDll=reinterpret_cast<HMODULE>(0x10000);keys.aes.fill(3);
    Check(!DeriveLiveImageKeys(keys,error));Check(error=="image_key_prologue_mismatch");zero();
    std::cout<<checks<<" native image key gate checks passed (no native calls)\n";return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
