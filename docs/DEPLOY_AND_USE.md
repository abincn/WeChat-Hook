> 公开脱敏副本：真实账号、会话、消息标识和机器地址不公开。采集原件、IDA分析及验收明细仅本地保留；文中的相关路径不代表仓库包含这些文件。

# 真机使用手册（微信 4.1.10.27）

面向：`C:\Program Files\Tencent\Weixin\4.1.10.27` 这套安装。

---

## 0. 前提

| 项 | 要求 |
| --- | --- |
| 微信版本 | 4.1.10.27（`Weixin.dll` 约 183 MB，imageBase `0x180000000`） |
| 系统 | Windows x64 |
| 产物 | `repo\x64\Release\version.dll`（当前 881,664 字节） |
| 端口 | 默认 `30001`，仅监听 `127.0.0.1` |
| 前提机制 | `Weixin.exe` 延迟导入 `VERSION.dll`，同目录 `version.dll` 会被优先加载 |

---

## 0.5 真机不是本机：目录单独配置 + 打包

三个脚本都支持 `wxcx.config.json`（参数 > 配置文件 > 自动探测）：

```json
{
  "VersionDir":  "D:\\Program Files\\Tencent\\Weixin\\4.1.10.27",
  "InstallRoot": "D:\\Program Files\\Tencent\\Weixin",
  "Port": 30001, "BindAddr": "127.0.0.1", "Token": "",
  "ExpectedVersion": "4.1.10.27"
}
```

- `VersionDir`：含 `Weixin.dll` 的版本子目录
- `InstallRoot`：含 `Weixin.exe` 的安装根（启动器在这一层）
- 自动探测顺序：运行中的进程 → `WXCX_VERSION_DIR` 环境变量 → 注册表 `InstallPath` → 常见目录（并展开一层版本子目录，按「版本号/体积」打分选最匹配的）

**版本校验**：`deploy.ps1` 会校验 `Weixin.dll` 的文件版本，识别不到时退化为体积比对（183,094,832 ±5%）。
不匹配直接中止——偏移只对 4.1.10.27 有效，装错版本会崩。确认无误才用 `-Force`。

打包给真机：

```powershell
.\tools\package.ps1
# → dist\wxcx-4.1.10.27-<时间戳>\ 和同名 .zip（含 dll、脚本、docs、README.txt）
```

真机上解压后：改 `wxcx.config.json` → `deploy.ps1 -WhatIfOnly` 干跑 → `deploy.ps1` → `run_wechat.ps1` → `smoke_test.ps1`。

## 1. 部署（1 步）

```powershell
cd LOCAL_PROJECT
.\tools\deploy.ps1
```

它会：

1. 把 `x64\Release\version.dll` 复制到安装目录；
2. 若目标已存在同名文件，先备份成 `version.dll.bak_wxcx`（不会覆盖已有备份）。

先完全退出微信，否则文件被占用会复制失败（脚本会明确报错）。

只看会做什么不加 `-Launch`：

```powershell
.\tools\deploy.ps1 -WhatIfOnly
```

---

## 2. 启动（带参数）

参数由 DLL 从**进程命令行**解析，可选：

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `StartPort=` | `30001` | HTTP 端口，1–65535 |
| `BindAddr=` | `127.0.0.1` | 监听地址；改 `0.0.0.0` 才可局域网访问 |
| `Token=` | 空 | 非空时所有请求必须带 `X-Wxcx-Token` 头或 `?token=` |
| `RecvType=` | `1` | 接收类型开关 |
| `CallBackURL=` | 空 | 收到事件时把 JSON POST 到这里 |

```powershell
# 本机
.\tools\run_wechat.ps1

# 指定端口 + 令牌
.\tools\run_wechat.ps1 -Port 30002 -Token abc123

# 局域网（必须设 Token，否则等于把控制接口暴露出去）
.\tools\run_wechat.ps1 -BindAddr 0.0.0.0 -Token abc123
```

启动后扫码登录。

---

## 3. 验活（登录后）

```powershell
$port = 30001
Invoke-RestMethod "http://127.0.0.1:$port/wxcx/health"
Invoke-RestMethod "http://127.0.0.1:$port/IsLoginStatus" -Method Post -ContentType 'application/json' -Body '{}'
```

`/IsLoginStatus` 返回 `{"onlinestatus":"3","msg":"登陆完成！"}` 即已登录（`"1"` 为未登录）。

带 Token 时统一加头：

```powershell
$h = @{ 'X-Wxcx-Token' = 'abc123' }
Invoke-RestMethod "http://127.0.0.1:$port/wxcx/health" -Headers $h
```

---

## 4. 常用调用

### 4.1 发文本 / 群@

```powershell
Invoke-RestMethod "http://127.0.0.1:$port/SendTextMsg" -Method Post -ContentType 'application/json' -Body (@{
  toid = 'filehelper'; msg = 'hello'
} | ConvertTo-Json)

# 群内 @（toid 为 xxx@chatroom）
Invoke-RestMethod "http://127.0.0.1:$port/SendAtMsg_NoSrc" -Method Post -ContentType 'application/json' -Body (@{
  toid = 'example_group@chatroom'; msg = '开会了'; atlist = @('wxid_example','wxid_example')
} | ConvertTo-Json)
```

### 4.2 发图片 / 解密 dat

```powershell
Invoke-RestMethod "http://127.0.0.1:$port/SendImgMsg" -Method Post -ContentType 'application/json' -Body (@{
  toid = 'filehelper'; path = 'C:\pics\a.png'
} | ConvertTo-Json)

Invoke-RestMethod "http://127.0.0.1:$port/Decode_Pic" -Method Post -ContentType 'application/json' -Body (@{
  path = 'C:\pics\a.dat'
} | ConvertTo-Json)
```

### 4.3 联系人 / 群成员数 / 消息历史

```powershell
Invoke-RestMethod "http://127.0.0.1:$port/GetContacts"   -Method Post -ContentType 'application/json' -Body '{}'
Invoke-RestMethod "http://127.0.0.1:$port/QueryChatRoomMemberCount" -Method Post -ContentType 'application/json' -Body '{"gid":"example_group@chatroom"}'
Invoke-RestMethod "http://127.0.0.1:$port/wxcx/msg/recent" -Method Post -ContentType 'application/json' -Body '{"limit":20}'
Invoke-RestMethod "http://127.0.0.1:$port/BatchGetContactBriefInfo" -Method Post -ContentType 'application/json' -Body '{"wxidlist":["filehelper"]}'
```

### 4.4 接收事件（回调或轮询）

```powershell
# 方式一：运行时设置回调地址
Invoke-RestMethod "http://127.0.0.1:$port/wxcx/callback/config" -Method Post -ContentType 'application/json' -Body (@{
  url = 'http://127.0.0.1:8000/recv'
} | ConvertTo-Json)

# 方式二：轮询本地事件表
Invoke-RestMethod "http://127.0.0.1:$port/wxcx/recv/arm" -Method Post -ContentType 'application/json' -Body '{"ms":600000}'
Invoke-RestMethod "http://127.0.0.1:$port/wxcx/recv/events?limit=10"
```

事件里 `msgtype` 会自动推断（`<sysmsg>`=10002、`<voicemsg>`=34、`<img>`=3 …），
语音消息还会把 `aeskey/voiceurl/length` 摊平到 `voice` 字段。

---

## 5. 探针（抓函数地址 / 调用栈）

```powershell
# 抓"发送"整条路径：挂 send_message(0x1677A30)，记录 dump + stack
Invoke-RestMethod "http://127.0.0.1:$port/wxcx/probe/preset" -Method Post -ContentType 'application/json' -Body '{"name":"sendpath","ms":120000}'

# 然后在微信里发一条文本、发一个文件，再取事件：
Invoke-RestMethod "http://127.0.0.1:$port/wxcx/probe/events?limit=10"

# 撤防
Invoke-RestMethod "http://127.0.0.1:$port/wxcx/probe/disarm" -Method Post -ContentType 'application/json' -Body '{}'
```

`events[].stack_hex` 是调用栈原始字节，脚本 `tools\capture_cmdid.ps1` 会自动解析成 RVA 列表。

---

## 6. 完整性自检（确认补丁可撤销）

```powershell
# 1) 未布防时建基线
Invoke-RestMethod "http://127.0.0.1:$port/wxcx/verify/baseline" -Method Post -ContentType 'application/json' -Body '{}'

# 2) 布防探针
Invoke-RestMethod "http://127.0.0.1:$port/wxcx/recv/arm" -Method Post -ContentType 'application/json' -Body '{"ms":60000}'

# 3) 检查差异：应只有 1 块，prologue = patched(int3)
Invoke-RestMethod "http://127.0.0.1:$port/wxcx/verify/check?max=20"

# 4) 撤防后再检查：应 equal=true、prologue=pristine
Invoke-RestMethod "http://127.0.0.1:$port/wxcx/recv/disarm" -Method Post -ContentType 'application/json' -Body '{}'
Invoke-RestMethod "http://127.0.0.1:$port/wxcx/verify/check?max=20"
```

---

## 7. 反检测层（可选）

```powershell
Invoke-RestMethod "http://127.0.0.1:$port/wxcx/guard/install" -Method Post -ContentType 'application/json' -Body '{}'
Invoke-RestMethod "http://127.0.0.1:$port/wxcx/guard/status"
```

- 立即关闭：在安装目录放一个空文件 `wxcx_guard.off`，DLL 会跳过安装。
- 状态里的计数器（`d_debug/d_enum/d_toolhelp/d_probe_read`）含义是"这些路径被调用过多少次"，
  **计数为 0 只能说明没走这些路径**，不能证明没被检测到。

---

## 8. 故障排查

| 现象 | 原因 / 处理 |
| --- | --- |
| 端口连不上 | 微信没起来 / DLL 没加载 / 端口被占用。先看 `netstat -ano \| findstr 30001` |
| 复制 version.dll 失败 | 微信还在运行，完全退出后再部署 |
| `/IsLoginStatus` 返回 `"1"` | 未登录或会话未建立，扫码后再试 |
| 发送返回 `code=-1` | 目标 `toid` 不存在；先用 `/GetContacts` 确认真实 wxid |
| 探针 `ok=false` | 该 RVA 未映射 / 首字节已是 `0xCC`（被别的断点占用）/ 4 个槽位已满 |
| `traps` 一直为 0 | 目标函数没被调用；或 VEH 被更早的处理器抢占 |
| 微信崩溃 | 删除 `version.dll` 恢复，或用 `version.dll.bak_wxcx` 覆盖回来 |

---

## 9. 卸载

```powershell
cd C:\Program Files\Tencent\Weixin\4.1.10.27
if (Test-Path version.dll.bak_wxcx) { Move-Item version.dll.bak_wxcx version.dll -Force }
else { Remove-Item version.dll -Force }
```

---

## 10. 能力边界（务必知道）

| 状态 | 端点 |
| --- | --- |
| 可用 | 发文本/无源文本/群@/图片/XML转发、解密dat、收事件与回调、MSG 历史、联系人、登录状态 |
| 部分 | 发文件（图片/GIF 可用；mp4/普通文件未实现）、好友状态（本地视角） |
| 仅有编码器 | 建群/拉人/踢人/公告/置顶/撤回/拍一拍/下载语音（报文能生成，缺函数地址，**不会真的发出去**） |

实时状态查 `GET /wxcx/capabilities`。
