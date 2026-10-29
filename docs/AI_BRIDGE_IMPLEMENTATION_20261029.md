> 公开脱敏副本：真实账号、会话、消息标识和机器地址不公开。采集原件、IDA分析及验收明细仅本地保留；文中的相关路径不代表仓库包含这些文件。

# AI-HOOK-20261029-01

本版补齐结构化消息入口、群成员与 @ 元数据解析、有界缓存/本机回调、异步文本任务。默认关闭消息观察，不连接 AI、不自动回复。2026-10-29已完成五项基础真机用例：私聊、群普通消息、真@自己、正文@昵称对照、filehelper单条文本实际收件。完整范围与限制见[真机记录](AI01_LIVE_TEST_20261029.md)。

## 接口

| 接口 | 用途 |
| --- | --- |
| GET /wxcx/ai/status | 编号、二进制身份、接收/文本任务状态 |
| POST /wxcx/messages/config | enabled、self_id、callback_url、callback_token、max_attempts |
| GET /wxcx/messages/status | 丢失、去重、缓存、回调计数 |
| GET /wxcx/messages/events?after=0&limit=128 | 进程内增量轮询，保存 next_after |
| POST /wxcx/messages/stop | 永久停止本进程接收服务；短暂停用请配置 enabled=false |
| POST /SendTextMsg、/SendTextMsg_NoSrc、/SendAtMsg_NoSrc | 文本任务，接受返回 HTTP 202/task_id |
| GET /wxcx/text/tasks/{task_id} | 查看排队、失败、提交或结果未知 |

接收配置示例：`{"enabled":true,"self_id":"wxid_真实账号","callback_url":"","callback_token":""}`。self_id 是账号身份依据，缺失时 direction/@我保持未知。切换账号必须先停观察、修改 self_id 后再启用；本版没有自动识别账号退出或切换的保证。

事件包含 conversation_id、room_id、sender_id、direction、完整十进制字符串 msgsvrid、message_time、content/raw_content、msgsource、mentions/is_at_me/mention_status、完整性标记。仅元数据中确实存在自己的账号才判为 @我；正文出现 @昵称不足以证明，@all 仅保留原始标记。XML 不完整或不支持时返回未知/无效，不能当作未@。

服务 sequence 是轮询游标，capture_seq 是采集顺序；event_id 为进程流/账号 epoch/服务序号。重启需按 process_stream_id 重建游标。默认最多缓存512事件、128待回调、1024去重键；缓存覆盖、原生丢失及回调队满都有计数，不能视作持久消息队列。

服务核心只依赖调用者注入 Transport；DLL 注入本机 HTTP 传输，连接0.5秒、读写各2秒、禁重定向，保留路径和查询串。仅允许 127.0.0.1、localhost、[::1]；配置和状态不返回地址/令牌。网络/5xx/408/429有限重试，保持 event_id，接收端按此去重。HTTP 2xx 只证明回调收到。外部 AI 应由独立本机程序接入，先过滤 direction=incoming、完整性、允许会话及 is_at_me，再由显式规则调用文本接口；本包不提供现成 AI 程序。

文本支持 request_id 进程内去重；同号不同参数409。超时或异常后结果未知，不自动重发。原生发送仍复用项目 SendTextEx，其线程要求、对象释放、接收及连续运行稳定性尚待真机确认；本版不能宣称可靠自动回复已验收。任务资源上限1024，达到上限明确拒绝新任务。

## 原生依据与限制

限定 Weixin.dll SHA-256 f487e4f56930456a25fb0d7b058c77e2dcd364e268d49bdfff4dc0e3be26ba36。接收 RVA 0x16D5180、原始返回 char，启用前核对函数头。AddMsg 步长0x78/vtable RVA0x83DF408；字段证据见 docs/evidence/ai-AddMsgParse.c、ai-addmsg-fields-A19E90.c、ai-addmsg-copy-A1B9C0.c。

from+8、to+18、content+20 为字符串包装，包装 vtable RVA0x82643A8；msgsource+38 为直接 std::string 指针。hasbits+6C 验证字段存在；type+14、秒时间+48、64位服务器ID+50。禁止使用旧32位消息ID或运行时间冒充消息时间。

Hook 仅安全读取有界POD，64条环形；每批超过64条会报告跳过。正文16KiB、元数据8KiB，截断有标记，UTF-8只保留完整字符。JSON、网络、文本发送均在其他工作线程。DLL和单例固定到进程退出；停观察后Hook透传，固定消费者仍驻留，不支持热卸载。旧接收探针独立保留，未自动启用。

## 验证与真机用例

VS2022 v143 Release x64 整包构建成功。离线检查：消息模型405、消息服务383、文本任务2351、原生字段读取20。前三组覆盖各模块及内存HTTP，不使用真实微信/网络；不能证明原生布局及发送已验收。

使用 tools/start_ai_01.ps1 核对 DLL 哈希与编号；tools/test_ai_01.ps1 默认 Status，不发送。Enable需真实SelfId；Poll保存每页、初末状态，中文提示一次完成多种消息。

| 用例 | 预期 | 当前结果 |
| --- | --- | --- |
| 私聊文本 | 身份/源ID/时间/正文对应真实消息 | 基础通过，字面编号未使用，关联限制见真机记录 |
| 群普通文本 | 群ID、群成员ID正确，@我=false | 基础通过 |
| 群内真正@自己 | 元数据可解析，@我=true | 基础通过 |
| 仅正文输入@昵称 | 不能误判成@我 | 基础通过 |
| 超长内容、重复观察、停止后重启 | 截断/去重/丢失明确，进程稳定 | 待真机 |
| 文件传输助手单条文本 | 任务可查，实际收到相同识别号 | 用户已确认实际收到且内容一致 |

先把新DLL、脚本及清单备齐，正常退出微信后备份两处旧DLL再替换并重启。安装与发送需一次集中确认。回退需先停新任务、记录未知结果、退出后恢复旧DLL，不重放任务。04的人工四类转发证据不构成本版消息接收或自动发送的验收。
