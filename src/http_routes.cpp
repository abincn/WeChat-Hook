#include "httplib.h"
#include "http_routes.h"
#include "SendTextMsg.h"
#include "GetSelfProfile.h"
#include "ForwardXMLMsg.h"
#include "SendImageMsg.h"
#include "QueryDB.h"
#include "wxcx.h"

void RegisterRoutes(httplib::Server& svr)
{
    RegisterGetSelfProfile(svr);
    Route_QueryDB(svr);

    // 聊天 / 群聊 扩展接口 (见 docs/ 与 showdoc PCWeixinHook)
    wxcx::RegisterRoutes(svr);
}
