# guided_capture.ps1 - 引导式抓取：脚本提示动作，你操作，脚本自动收数据并出报告
#
# 用法：
#   .\guided_capture.ps1                     # 全流程（约 5~8 分钟）
#   .\guided_capture.ps1 -Skip send_pat,revoke   # 跳过某些步骤
#   .\guided_capture.ps1 -Only send_file         # 只跑某几步
#   .\guided_capture.ps1 -DryRun                 # 只打印计划，不联网
#
# 每一步：
#   1) 布防探针（信封序列化 0x2C6C550 + send_message 0x1677A30，最多 4 槽）
#   2) 屏幕提示具体操作（照着点即可）
#   3) 轮询 traps 计数，检测到新事件即自动进入下一步（也可回车跳过/强制继续）
#   4) 取 /wxcx/probe/trace，提取 stack_rvas，写入报告
param(
    [string]$Config,
    [int]$Port = 0,
    [string]$Token,
    [int]$TimeoutSec = 180,
    [string[]]$Skip = @(),
    [string[]]$Only = @(),
    [string]$OutDir,
    [switch]$DryRun
)

# -File 调用时逗号不会被自动拆分，这里手动拆，允许 -Only send_file,send_pat
$Only = @($Only | ForEach-Object { $_ -split ',' } | Where-Object { $_ })
$Skip = @($Skip | ForEach-Object { $_ -split ',' } | Where-Object { $_ })

$ErrorActionPreference = 'Continue'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $here 'wxcx-common.ps1')

if (-not $Config) {
    foreach ($c in @((Join-Path $here 'wxcx.config.json'), (Join-Path (Split-Path -Parent $here) 'wxcx.config.json'))) {
        if (Test-Path $c) { $Config = $c; break }
    }
}
$cfg = Read-WxcxConfig -Path $Config
if ($Port -eq 0)      { $Port = if ($cfg['Port']) { [int]$cfg['Port'] } else { 30001 } }
if ($null -eq $Token) { $Token = [string]$cfg['Token'] }
if (-not $OutDir)     { $OutDir = Join-Path (Split-Path -Parent $here) 'capture' }

$base = "http://127.0.0.1:$Port"
$headers = @{}
if ($Token) { $headers['X-Wxcx-Token'] = $Token }

# ---------------- 动作清单（顺序 = 价值顺序）----------------
$actions = @(
    @{ id='send_text';  title='发送一条文本';
       how='打开任意聊天（建议"文件传输助手"），输入一行字并发送'; hook='send_message' },
    @{ id='send_file';  title='发送一个文件';
       how='打开"文件传输助手" → 点 + 或拖拽 → 发送任意一个文件（pdf/mp4/zip 都行）'; hook='send_message' },
    @{ id='send_image'; title='发送一张图片';
       how='打开"文件传输助手" → 发送一张本地图片'; hook='send_message' },
    @{ id='send_card';  title='发送一个卡片/链接';
       how='把任意公众号文章或网页链接粘贴到"文件传输助手"发送（生成卡片）'; hook='envelope' },
    @{ id='send_pat';   title='拍一拍';
       how='进入任意群 → 双击别人的头像两次（触发"拍了拍"）'; hook='envelope' },
    @{ id='revoke';     title='撤回一条消息';
       how='在刚发过消息的聊天里，右键那条消息 → 撤回'; hook='envelope' },
    @{ id='forward';    title='转发一条消息';
       how='右键任意一条历史消息 → 转发 → 选"文件传输助手" → 发送'; hook='envelope' },
    @{ id='voice_send'; title='发送一条语音';
       how='打开"文件传输助手" → 点语音按钮 → 按住说 1 秒 → 发送'; hook='envelope' },
    @{ id='voice_dl';   title='点开一条收到的语音';
       how='找一条别人发来的语音消息，点一下播放（会触发下载/解码）'; hook='envelope' },
    @{ id='emoji';      title='发送一个表情';
       how='打开"文件传输助手" → 表情面板 → 发一个收藏表情'; hook='envelope' }
)

if ($Only.Count -gt 0) { $actions = $actions | Where-Object { $Only -contains $_.id } }
if ($Skip.Count -gt 0) { $actions = $actions | Where-Object { $Skip -notcontains $_.id } }

Write-Host '================ 引导式抓取 ================' -ForegroundColor Cyan
Write-Host ("端口 {0}   共 {1} 步   单步超时 {2}s" -f $Port, $actions.Count, $TimeoutSec)
foreach ($a in $actions) { Write-Host ("  - {0,-12} {1}" -f $a.id, $a.title) }
Write-Host ''

if ($DryRun) { Write-Host '[dry] 仅打印计划，不联网 / 不布防'; return }

function Get-Json($path, $timeout = 10) {
    Invoke-RestMethod "$base$path" -Headers $headers -TimeoutSec $timeout
}
function Post-Json($path, $body, $timeout = 20) {
    Invoke-RestMethod "$base$path" -Method Post -Headers $headers `
        -ContentType 'application/json' -Body $body -TimeoutSec $timeout
}
function Get-TrapTotal {
    try { ($(Get-Json '/wxcx/probe/status').probes | Measure-Object -Property traps -Sum).Sum } catch { 0 }
}

# 0) 前置检查
try { $h = Get-Json '/wxcx/health'; Write-Host ("[i] 服务在线，start_port={0}" -f $h.start_port) -ForegroundColor Green }
catch {
    Write-Host '[-] 服务不可达：确认微信已启动、version.dll 已部署、端口正确' -ForegroundColor Red
    exit 1
}
try {
    $lg = Post-Json '/wxcx/login/detect' '{}'
    if ($lg.onlinestatus -ne '3') {
        Write-Host '[!] 当前判定为未登录，抓到的数据可能不完整；建议先登录再跑' -ForegroundColor Yellow
    } else {
        Write-Host ("[i] 已登录，wxid={0}" -f $lg.wxid) -ForegroundColor Green
    }
} catch { Write-Host '[!] 登录探测失败（继续）' -ForegroundColor Yellow }

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$report = [ordered]@{
    generated_at = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    port = $Port
    steps = @()
}

# 1) 逐步执行
$idx = 0
foreach ($a in $actions) {
    $idx++
    Write-Host ''
    Write-Host ('──────── 第 {0}/{1} 步：{2} ────────' -f $idx, $actions.Count, $a.title) -ForegroundColor Cyan
    Write-Host ('  操作：{0}' -f $a.how) -ForegroundColor Yellow

    # 布防：信封序列化 + send_message（两个点，覆盖消息类与请求类）
    try {
        Post-Json '/wxcx/probe/preset' '{"name":"envelope","ms":300000}' | Out-Null
        Post-Json '/wxcx/probe/arm' ('{"rva":"0x1677A30","ms":300000,"dump":32}') | Out-Null
    } catch { Write-Host ('  [!] 布防失败: {0}' -f $_.Exception.Message) -ForegroundColor Yellow }

    # 同时启动执行采样器：不依赖任何锚点，能发现"根本不经过已知探针"的功能
    $sampling = $false
    try {
        $sr = Post-Json '/wxcx/sample/start' ('{"interval_ms":2,"seconds":' + ($TimeoutSec + 10) + '}')
        if ($sr.ok) { $sampling = $true; Write-Host '  [i] 采样器已启动（自动发现任意执行到的函数）' -ForegroundColor DarkGray }
    } catch { Write-Host '  [!] 采样器启动失败（继续用探针）' -ForegroundColor Yellow }

    $before = Get-TrapTotal
    Write-Host '  …… 现在请到微信里完成上面的操作（完成后自动继续）' -ForegroundColor Gray

    $detected = $false
    $elapsed = 0
    while ($elapsed -lt $TimeoutSec) {
        Start-Sleep -Seconds 2
        $elapsed += 2
        $now = Get-TrapTotal
        if ($now -gt $before) { $detected = $true; break }
        if ($elapsed % 20 -eq 0) { Write-Host ('  …… 已等待 {0}s / {1}s' -f $elapsed, $TimeoutSec) -ForegroundColor DarkGray }
    }

    $step = [ordered]@{ id = $a.id; title = $a.title; how = $a.how; detected = $detected; events = @() }

    if (-not $detected) {
        Write-Host '  [!] 超时未检测到事件（可能该操作不走这两个点），继续下一步' -ForegroundColor Yellow
    }

    try {
        $tr = Get-Json '/wxcx/probe/trace?limit=8'
        foreach ($e in @($tr.events)) {
            $step.events += [ordered]@{
                hook_rva   = $e.rva
                a1 = $e.a1; a2 = $e.a2; a3 = $e.a3
                stack_rvas = @($e.stack_rvas)
                dump_qwords = @($e.dump_qwords | ForEach-Object { [ordered]@{ off = $_.off; v = $_.v; rva = $_.rva } })
            }
        }
        $first = @($step.events | ForEach-Object { ($_.stack_rvas | Select-Object -First 1) }) | Where-Object { $_ }
        if ($first) { Write-Host ('  [+] 抓到 {0} 条，首帧候选 RVA: {1}' -f $step.events.Count, (($first | Select-Object -First 4) -join ', ')) -ForegroundColor Green }
        elseif ($detected) { Write-Host ('  [+] 抓到 {0} 条（栈内无镜像地址）' -f $step.events.Count) -ForegroundColor Green }
    } catch { Write-Host ('  [!] 取 trace 失败: {0}' -f $_.Exception.Message) -ForegroundColor Yellow }

    # 收采样结果：这是"无锚点发现函数"的关键
    if ($sampling) {
        # 尾部窗口：动作刚完成时还有收尾代码在跑，多采 3 秒能显著提高样本量
        Start-Sleep -Seconds 3
        try {
            $st = Get-Json '/wxcx/sample/status'
            $step.sample_stats = [ordered]@{
                samples = $st.samples; passes = $st.passes
                outside = $st.outside_module; skipped = $st.skipped_foreign_threads
                open_fail = $st.open_fail; context_fail = $st.context_fail
                suspend_fail = $st.suspend_fail; resume_fail = $st.resume_fail
            }
            Write-Host ('  [采样器] 样本={0} 趟数={1} 模块外={2} 跳过外来线程={3} 打开失败={4}' -f `
                $st.samples, $st.passes, $st.outside_module, $st.skipped_foreign_threads, $st.open_fail) -ForegroundColor DarkGray
        } catch {}
        try { Post-Json '/wxcx/sample/stop' '{}' | Out-Null } catch {}
        try {
            $d = Get-Json '/wxcx/sample/dump?top=20&by=func'
            $step.hotspots = @($d.top | ForEach-Object { [ordered]@{ func = $_.func; size = $_.size; hits = $_.hits } })
            $step.samples = $d.total_samples
            $step.unmapped_hits = $d.unmapped_hits
            $top3 = @($d.top | Select-Object -First 3 | ForEach-Object { '{0}({1})' -f $_.func, $_.hits })
            if ($top3.Count) { Write-Host ('  [采样] {0} 个样本，热点函数: {1}' -f $d.total_samples, ($top3 -join ' ')) -ForegroundColor Green }
        } catch { Write-Host ('  [!] 取采样结果失败: {0}' -f $_.Exception.Message) -ForegroundColor Yellow }
    }

    $report.steps += $step

    try { Post-Json '/wxcx/probe/disarm' '{}' | Out-Null } catch {}
}

# 2) 汇总：跨步骤出现的候选地址
$all = @()
foreach ($s in $report.steps) {
    foreach ($e in $s.events) {
        foreach ($r in $e.stack_rvas) { $all += [pscustomobject]@{ step = $s.id; rva = $r } }
    }
}
$cand = $all | Group-Object rva | Sort-Object Count -Descending |
        Select-Object -First 15 @{n='rva';e={ '0x{0:X}' -f [int]$_.Name }}, Count, @{n='steps';e={ ($_.Group.step | Select-Object -Unique) -join ',' }}

$jsonPath = Join-Path $OutDir ("capture-$stamp.json")
$mdPath   = Join-Path $OutDir ("capture-$stamp.md")

$report | ConvertTo-Json -Depth 8 | Set-Content $jsonPath -Encoding UTF8

$md = New-Object System.Text.StringBuilder
[void]$md.AppendLine("# 抓取报告 $stamp")
[void]$md.AppendLine('')
[void]$md.AppendLine('| 步骤 | 检测 | 事件 | 首帧 RVA | 采样样本 | 热点函数前3 |')
[void]$md.AppendLine('| --- | --- | --- | --- | --- | --- |')
foreach ($s in $report.steps) {
    $firsts = @($s.events | ForEach-Object { ($_.stack_rvas | Select-Object -First 1) }) |
              Where-Object { $_ } | Select-Object -Unique -First 3
    $fs = if ($firsts) { ($firsts | ForEach-Object { '0x{0:X}' -f $_ }) -join ' / ' } else { '-' }
    $hs = '-'
    if ($s.hotspots) {
        $hs = (@($s.hotspots | Select-Object -First 3 | ForEach-Object { '{0}({1})' -f $_.func, $_.hits })) -join ' '
    }
    [void]$md.AppendLine(('| {0} | {1} | {2} | {3} | {4} | {5} |' -f $s.title, $s.detected, $s.events.Count, $fs, $s.samples, $hs))
}
[void]$md.AppendLine('')
[void]$md.AppendLine('## 跨步骤出现的候选地址')
[void]$md.AppendLine('')
[void]$md.AppendLine('| RVA | 出现次数 | 出现在哪些步骤 |')
[void]$md.AppendLine('| --- | --- | --- |')
foreach ($c in $cand) { [void]$md.AppendLine(('| {0} | {1} | {2} |' -f $c.rva, $c.Count, $c.steps)) }
[void]$md.AppendLine('')
[void]$md.AppendLine('> 首帧 = send_message / 信封序列化的直接调用方，通常就是该功能的实现函数。')
$md | Set-Content $mdPath -Encoding UTF8

Write-Host ''
Write-Host '================ 完成 ================' -ForegroundColor Cyan
$report.steps | Format-Table @{n='步骤';e={$_.title}}, @{n='检测到';e={$_.detected}}, @{n='事件';e={$_.events.Count}} -AutoSize |
    Out-String -Width 120 | Write-Host
Write-Host ''
$cand | Format-Table -AutoSize | Out-String -Width 120 | Write-Host
Write-Host ("[+] 报告: {0}" -f $jsonPath)
Write-Host ("[+] 报告: {0}" -f $mdPath)
Write-Host '把 .md 或 .json 发我，我据此填 /wxcx/client/set 并点亮对应接口。' -ForegroundColor Green
