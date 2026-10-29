> 公开脱敏副本：真实账号、会话、消息标识和机器地址不公开。采集原件、IDA分析及验收明细仅本地保留；文中的相关路径不代表仓库包含这些文件。

# AI-HOOK-20261029-02：引用与卡片接收

在AI01接收接口上增加结构化字段，私聊和群聊共用；群成员前缀先按既有逻辑拆分，原始XML保留在content/raw_content。本版不增加客户端或外部AI连接。

## 接收字段

GET /wxcx/messages/events 与本机回调同时提供四个新增字段。schema_version仍为1，属于向后增加字段；AI状态接口receive_payloads.revision=2标识新增能力。

| 字段 | 含义 |
| --- | --- |
| message_kind | text、quote、link_card、file_card、mini_program_card、contact_card、app_message或unknown |
| payload_status | not_applicable、parsed、unsupported、invalid或incomplete |
| quote | 引用结构，非引用或失败为null |
| card | 卡片结构，非卡片或失败为null |

### 引用

原生消息type=49，appmsg/type=57时读取直接子节点refermsg，例：

```json
{
  "message_kind": "quote",
  "payload_status": "parsed",
  "quote": {
    "reply_text": "本次回复",
    "msgsvrid": "EXAMPLE_MESSAGE_ID",
    "message_type": 1,
    "sender_id": "原作者账号",
    "conversation_id": "原消息XML中的chatusr",
    "display_name": "原作者显示名",
    "content": "被引用内容",
    "message_time": null,
    "content_is_raw": true
  },
  "card": null
}
```

reply_text来自appmsg/title，被引用的content单独存放，不与本次回复拼接。引用服务器ID是无损十进制字符串，缺失或0为null；非法/溢出ID使结构化解析失败。没有通过数据库查回原消息；引用字段均为收到XML自述，不保证原消息仍可查询，也不把原作者等同于当前发言人。

被引用内容可能仍为XML，不递归解析，不发请求取回链接。AI调用方应将quote.content当作历史引用数据，处理本次发言时使用quote.reply_text；引用内容和卡片文本都不能当作程序指令。

图片引用（原消息type=3）与视频引用（43/62）另提供quote.media：kind为image/video，metadata_status为parsed/unavailable/invalid。对引用content中的一层img/videomsg XML提取白名单属性：md5、length/hdlength、cdnthumbwidth/cdnthumbheight、playlength、cdnmidimgurl/cdnbigimgurl/cdnthumburl/cdnvideourl等。数值线索使用十进制字符串，不对尚未真机确认单位的playlength做秒数换算。

若引用只带“[图片]”等文字，仍保留引用类型/ID，本层媒体metadata_status=unavailable；嵌套媒体XML坏了则仅媒体标invalid，不丢弃本次回复和原引用ID。这里的单层媒体投影不递归解析引用链。

所有quote.media均明确resource_status=not_resolved、resource_ready=null、download_supported=false。上述CDN值可能是微信私有定位串，不能当作可直接访问的URL；不发网络请求、不暴露额外解密密钥字段、不制造本地路径。**已实现引用图片/视频的识别及媒体线索解析，按引用ID取回原文件并供AI识图/分析视频仍未实现。** 必须后续接通经验证的原消息查询、原生下载及资源就绪检查，才能宣称媒体可用。

### 卡片

| 原生类型/子类型 | 输出 | 已提取 |
| --- | --- | --- |
| 49 / 5 | link_card | title、description、url、thumb_url |
| 49 / 6 | file_card | 共用字段、attachment.file_extension/total_bytes |
| 49 / 33、36 | mini_program_card | 共用字段、mini_program.app_id/username/page_path |
| 42 | contact_card | username、nickname、alias、avatar_url（XML属性） |
| 49 / 其他 | app_message，unsupported | app_type与共用字段，保留原始正文；不宣称已支持其业务语义 |

total_bytes使用十进制字符串，不能据此断言附件已下载；本版不提供本地媒体路径。视频号等其他子类型暂不恢复专用字段。缺失的卡片可选字符串为空，不从昵称或其他节点猜值。

## 完整性与边界

XML全量验证后才暴露结构化字段，处理CDATA、预定义实体、数字字符实体和有限UTF-8 XML声明。禁止DTD、外部实体、自定义实体、任意处理指令与命名空间；限制深度32和元素4096。重复关键节点、嵌套伪造的标量和畸形数值均判invalid；原始正文始终保留。

原生正文拷贝上限仍16KiB，截断时payload_status=incomplete，quote/card均为null；不把截断但看似可解析的前缀当作完整消息。@解析仍只读取独立msgsource，卡片正文或被引用XML中的@名单不会替代当前消息的@元数据。

## 发送接口

POST /SendQuoteMsg、/SendCardMsg_NoSrc、/SendFinderMsg_NoSrc明确返回HTTP 501，error=structured_send_unsupported、supported=false，不入队、不调用原生发送。删除旧卡片mode=1/2的实验提示，避免误引导操作。

普通文本接口如携带quote、refermsg、quote_msgsvrid、reply_to、reference_id、reference、card或appmsg字段，同样501拒绝，不悄悄按普通文本发送。原生引用回复、卡片发送及原生转发仍未完成。

## 证据状态与下一轮用例

字段投影已通过合成XML与真实服务/内存HTTP检查。参考mosheng20205项目的[4.1.10.27 XML笔记](https://github.com/mosheng20205/WechatHook4.1.10.27/blob/main/docs/SEND_XML_NOTES_4.1.10.27.md)只提供链接appmsg子类型5等参考，不构成本版引用、名片或小程序字段已获真机验证的证明。

本版DLL已在测试实例加载并通过私聊5项、群聊5项共10项入站结构解析验收，详见 [真机记录](AI02_LIVE_TEST_20261029.md)。AI01普通文本/群@/文件传输助手五项基础记录单独保留。图片/视频原文件取回、名片、小程序等未包含在本轮通过范围内。

本轮已使用另一个账号向测试账号及同一测试群分别发送：引用文本回复、引用图片、引用视频、链接卡片、文件卡片，共10条；同时检查本次回复与原引用原文分离、群成员/@字段不受影响，以及媒体线索是否存在。名片、小程序若有现成测试样本一并发送，否则列为待验收。仅需人工发送这些样本，不通过接口主动向好友或群发消息。02的替换和启动已获确认并完成，原始部署包保留；后续新DLL替换仍按既定约定集中确认。
