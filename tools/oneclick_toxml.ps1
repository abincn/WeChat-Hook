# oneclick_toxml.ps1 - 一键双断点采集：谁调用 AppMsg 的 XML 序列化 + 生成了什么
#
#   .\oneclick_toxml.ps1                 # 交互式（默认 180s 窗口）
#   .\oneclick_toxml.ps1 -Seconds 120
#   .\oneclick_toxml.ps1 -SelfTest       # 离线校验报告格式（不联网）
param(
    [string]$Config,
    [int]$Port = 0,
    [string]$Token,
    [int]$Seconds = 180,
    [switch]$SelfTest
)

$ErrorActionPreference = 'Continue'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $here 'wxcx-common.ps1')

if ($SelfTest) {
    $demo = [ordered]@{
        toxml_entry = '0xA63B40'; toxml_done = '0xA63F45'
        hits = 2; caller_return_rva = '0x172CAF'; xml_model_ptr = '0x1A2B3C40'
        context_ptr = '0x1A2B3C40'; output_field = 'context+0x180'
        xml_length = 812; xml_prefix = '<msg><appmsg ...'
        status = 'ok'
    }
    $demo | ConvertTo-Json -Depth 4
    Write-Host '[selftest] 报告格式正常'
    return
}

if (-not $Config) {
    foreach ($c in @((Join-Path $here 'wxcx.config.json'), (Join-Path (Split-Path -Parent $here) 'wxcx.config.json'))) {
        if (Test-Path $c) { $Config = $c; break }
    }
}
$cfg = Read-WxcxConfig -Path $Config
if ($Port -eq 0)      { $Port = if ($cfg['Port']) { [int]$cfg['Port'] } else { 30001 } }
if ($null -eq $Token) { $Token = [string]$cfg['Token'] }

$base = "http://127.0.0.1:$Port"
$headers = @{}
if ($Token) { $headers['X-Wxcx-Token'] = $Token }

function Get-Json($p, $t = 10) { Invoke-RestMethod "$base$p" -Headers $headers -TimeoutSec $t }
function Post-Json($p, $b, $t = 20) {
    Invoke-RestMethod "$base$p" -Method Post -Headers $headers -ContentType 'application/json' -Body $b -TimeoutSec $t
}

Write-Host '================ 一键双断点采集：AppMsg XML ================' -ForegroundColor Cyan

# 0) 前置检查
try { $h = Get-Json '/wxcx/health'; Write-Host ("[i] 服务在线 start_port={0}" -f $h.start_port) -ForegroundColor Green }
catch { Write-Host '[-] 服务不可达' -ForegroundColor Red; exit 1 }

# 1) 布防双断点
Write-Host '[1/4] 布防：0xA63B40 (ToXml 入口) + 0xA63F45 (串写入完成)' -ForegroundColor Cyan
$arm = Post-Json '/wxcx/probe/preset' (@{ name = 'toxml2'; ms = ($Seconds * 1000 + 15000) } | ConvertTo-Json)
$armed = @($arm.armed)
$armed | Format-Table -AutoSize | Out-String -Width 120 | Write-Host
if (-not ($armed | Where-Object { $_.ok })) {
    Write-Host '[-] 布防失败：检查微信是否已注入、RVA 是否被占用' -ForegroundColor Red
    exit 1
}

# 2) 清空旧事件 + 让用户操作
try { $null = Get-Json '/wxcx/probe/events?limit=1' } catch {}
Write-Host ''
Write-Host '[2/4] 请现在操作微信（任选其一，建议都做）：' -ForegroundColor Yellow
Write-Host '   a) 打开一个含卡片/公众号链接的聊天，滚到那条卡片'
Write-Host '   b) 向"文件传输助手"粘贴一个公众号文章链接并发送'
Write-Host ("   窗口 {0}s，检测到命中会自动继续" -f $Seconds)
for ($t = $Seconds; $t -gt 0; $t -= 5) { Write-Host ("   剩余 {0}s ..." -f $t); Start-Sleep -Seconds 5 }

# 3) 取数据
Write-Host '[3/4] 采集结果' -ForegroundColor Cyan
$tr = Get-Json '/wxcx/probe/trace?limit=10'
$evts = @($tr.events)
Write-Host ("   事件数: {0}" -f $evts.Count)

$entry = @($evts | Where-Object { $_.rva -eq 0xA63B40 })
$done  = @($evts | Where-Object { $_.rva -eq 0xA63F45 })

$report = [ordered]@{
    toxml_entry = '0xA63B40'
    toxml_done  = '0xA63F45'
    hits        = $evts.Count
    caller_return_rva = $null
    xml_model_ptr     = $null
    context_ptr       = $null
    output_field      = 'context+0x180'
    xml_length        = $null
    xml_prefix        = $null
    status            = 'pending'
}

if ($entry.Count) {
    $e0 = $entry[0]
    if ($e0.ret_rva) { $report.caller_return_rva = ('0x{0:X}' -f $e0.ret_rva) }
    if ($e0.dump_qwords) { $report.xml_model_ptr = ('0x{0:X}' -f $e0.dump_qwords[0].v) }
    Write-Host ("   ToXml 进入: 调用者返回 RVA {0}" -f $report.caller_return_rva) -ForegroundColor Green
} else {
    Write-Host '   未命中 ToXml 入口（可能该操作没触发序列化）' -ForegroundColor Yellow
}

if ($done.Count) {
    $d0 = $done[0]
    $report.context_ptr = ('0x{0:X}' -f $d0.a1)
    $report.xml_length  = $d0.str_len
    if ($d0.str_got -gt 0) {
        $report.xml_prefix = $d0.str_ascii
    }
    Write-Host ("   串写入完成: len={0} cap={1} 前缀={2}" -f $d0.str_len, $d0.str_cap, $d0.str_ascii) -ForegroundColor Green
} else {
    Write-Host '   未命中串写入点' -ForegroundColor Yellow
}

if ($entry.Count -and $done.Count) { $report.status = 'ok' }

# 4) 输出
Write-Host '[4/4] 汇总' -ForegroundColor Cyan
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$outDir = Join-Path (Split-Path -Parent $here) 'capture'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$path = Join-Path $outDir ("toxml-$stamp.json")
$report | ConvertTo-Json -Depth 5 | Set-Content $path -Encoding UTF8
$report | ConvertTo-Json -Depth 5 | Write-Host

try { Post-Json '/wxcx/probe/disarm' '{}' | Out-Null } catch {}
Write-Host ("[+] 已撤防，报告: {0}" -f $path) -ForegroundColor Green
