# 当前API使用说明

源码版本AI-HOOK-20261029-07，限定已校验的Windows微信4.1.10.27 x64。已验收范围和未完成项见[完整报告](PROJECT_COMPLETION_REPORT_20261029.md)。此仓库不包含微信DLL、IDA文件、真实聊天采集及构建产物。

## 构建与配置

在Visual Studio开发命令行构建：

```powershell
msbuild x64_Version_dll.vcxproj /p:Configuration=Release /p:Platform=x64 /p:PlatformToolset=v143
```

使用本机已安装的兼容工具链与Windows SDK。复制tools/wxcx.config.example.json为tools/wxcx.config.json，配置自己的微信安装路径和Token；默认仅监听127.0.0.1:30001。配置文件已排除提交。通用部署/启动脚本为tools/deploy.ps1、tools/run_wechat.ps1，安装前先正常退出测试微信并保留备份。

以下示例只说明接口，不会自动执行。请求鉴权使用X-Wxcx-Token。示例账号和消息ID必须替换为自己的真实值。

## 接收消息

先GET /wxcx/ai/status核对身份。接收默认关闭，配置真实自身账号后显式启用：

```http
POST /wxcx/messages/config
Content-Type: application/json

{"enabled":true,"self_id":"wxid_your_account","callback_url":"","callback_token":""}
```

GET /wxcx/messages/events?after=0&limit=128增量轮询，后续保留返回的游标；GET /wxcx/messages/status查看计数、丢失/缓存缺口和当前流。服务器ID使用十进制字符串，不转成有精度损失的浮点数。群会话与发言人分离；is_at_me来自真实@元数据，正文出现@昵称不足以证明真正@。

私聊和群聊的引用文字/图片/视频、独立链接/文件卡片已有结构验收。引用内的原消息ID与当前回复ID不同；取原媒体时应使用对应原消息ID，且原记录必须在本机存在。

需要短暂停用时配置enabled=false；POST /wxcx/messages/stop停止当前进程服务。重启后使用新的进程流和游标，不保证持久续传。

## 本机回调

接收服务允许配置本机HTTP回调，仅支持127.0.0.1、localhost、[::1]。有有限重试和event_id，接收端应据此去重；HTTP2xx只说明回调接收，不说明AI处理或消息发送成功。真实网络失败恢复及完整AI闭环尚未验收。模型调用应放在独立业务服务中，勿放入Hook原生回调。

## 发送文本

```http
POST /SendTextMsg
Content-Type: application/json

{"toid":"filehelper","msg":"your test text","request_id":"example-text-1"}
```

HTTP202返回task_id，用GET /wxcx/text/tasks/{task_id}查询。同号同参数返回原任务，同号异参冲突；去重限当前进程。submitted是本地原生提交状态，不自动代表对端收到。结果未知时不得自动重发。

/SendTextMsg_NoSrc和/SendAtMsg_NoSrc进入同一文本任务服务。当前只有文件助手单条文本有实际收件确认；好友/群文本和发出真正群@仍待验收。/SendQuoteMsg、/SendCardMsg_NoSrc、/SendFinderMsg_NoSrc明确返回501。

## 取回媒体

```http
POST /wxcx/media/tasks
Content-Type: application/json

{"msgsvrid":"123456789012345678","source_talker":"wxid_source_account","kind":"image","image_quality":"full","download":true,"request_id":"example-image-1"}
```

msgsvrid是示例，必须替换。kind支持image/video/file。image_quality仅用于图片：full为微信完整图片资源，original为独立高清资源；不回退缩略图。高清资源当前未验收，不保证存在。

- GET /wxcx/media/tasks/{task_id}：任务状态、最后阶段、下载阶段标记、失败类别或artifact。
- GET /wxcx/media/requests/{request_id}：响应丢失后找回原任务，避免重投。
- GET /wxcx/media/tasks/{task_id}/content：仅在ready后取任务产物，按返回大小/SHA复核。
- DELETE /wxcx/media/tasks/{task_id}：释放已结束任务的副本。
- GET /wxcx/media/status；POST /wxcx/media/stop：查看或停止受理。

默认观察上限300秒。原生调用完成状态不确定时不自动重试。只允许取任务生成的自有文件，不接受任意本机读取路径；不会为测试自动删除微信缓存。

已人工验收文件助手/群完整图、私聊/群视频和文件；缺失私聊视频的原生下载通过。私聊入站图、高清原图、缺失图片/文件下载及通用格式仍未完成验收。取得文件不等于AI已经理解其内容。

## 原生转发和其他功能

/ForwardMsg及/wxcx/forward/tasks/{task_id}有异步任务框架，但四类原生提交能力均未启用；/wxcx/forward/capabilities返回逐类型状态。人工UI转发证据不能算接口成功，当前自动转发矩阵仍为0/12。

群管理、语音、撤回、翻译、收藏等大量旧接口只是占位/编码基础；不要仅按路由名称或旧ok标记认定可用。当前没有完整AI模型调用、上下文、自动回复、防自循环及持久恢复闭环。

## 离线测试

tests包含C++服务/消息模型/媒体/协程测试及Python采集合约测试。合成测试不调用真实微信；未公开的真实采集fixture测试应跳过。使用本机Python和v143工具链，测试工程可单独构建；本地路径、真实账号配置和测试数据不应提交。
