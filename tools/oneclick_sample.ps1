# oneclick_sample.ps1 - 采样差分：找出"只在某个操作期间活跃"的函数
#
# 用途：不依赖任何地址假设，直接对比两次采样的函数命中分布。
#   1) 基线采样（什么都不做）
#   2) 操作采样（执行目标操作，例如"转发一张卡片"）
#   3) 差分：只出现在操作期间的函数 → 候选业务函数
#
#   .\wxcx-run.cmd oneclick_sample.ps1 -Label forward -Seconds 20
#   .\wxcx-run.cmd oneclick_sample.ps1 -Label forward -Seconds 20 -Hub http://127.0.0.1:30001
param(
    [string]$Config,
    [int]$Port = 0,
    [string]$Token,
    [string]$Label = 'action',
    [int]$Seconds = 20,
    [int]$Interval = 2,
    [int]$Top = 150,
    [switch]$SkipBaseline,
    [switch]$SelfTest
)

$ErrorActionPreference = 'Continue'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $here 'wxcx-common.ps1')

if ($SelfTest) {
    [ordered]@{
        label = 'forward'; baseline_funcs = 2; action_funcs = 2
        only_in_action = @('0x1FADD10')
        files = @('sample-diff.json')
    } | ConvertTo-Json -Depth 4
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

function Get-Json($p, $t = 20) { Invoke-RestMethod "$base$p" -Headers $headers -TimeoutSec $t }
function Post-Json($p, $b, $t = 30) {
    Invoke-RestMethod "$base$p" -Method Post -Headers $headers -ContentType 'application/json' -Body $b -TimeoutSec $t
}

function Run-Phase([string]$name, [int]$sec) {
    Write-Host ("---- {0}（{1}s）----" -f $name, $sec) -ForegroundColor Yellow
    try { $null = Post-Json '/wxcx/sample/stop' '{}' } catch {}
    Start-Sleep -Milliseconds 300
    $st = Post-Json '/wxcx/sample/start' (@{ interval_ms = $Interval; seconds = ($sec + 3) } | ConvertTo-Json)
    Write-Host ("   采样启动: ok={0}" -f $st.ok)
    if (-not $st.ok) { throw '采样器启动失败（微信未加载或已在运行）' }
    for ($t = $sec; $t -gt 0; $t -= 5) { Write-Host ("   剩余 {0}s" -f $t); Start-Sleep -Seconds 5 }
    $null = Post-Json '/wxcx/sample/stop' '{}'
    Start-Sleep -Milliseconds 400
    try {
        $dump = Get-Json ("/wxcx/sample/dump?by=func&top=" + $Top)
        Write-Host ("   采样统计: samples={0} distinct_funcs={1} unmapped_hits={2} func_table={3}" -f `
            $dump.total_samples, $dump.distinct_funcs, $dump.unmapped_hits, $dump.func_table)
        $rows = @($dump.top)
        if ($rows.Count -eq 0) {
            Write-Host '   [!] dump 为空：采样期间没有抓到样本（检查 interval_ms 是否过大 / 微信是否在前台）' -ForegroundColor Yellow
        }
        return $rows
    } catch {
        Write-Host ("   [!] dump 失败: {0}" -f $_.Exception.Message) -ForegroundColor Red
        return @()
    }
}

Write-Host '=========== 采样差分 ===========' -ForegroundColor Cyan
try { $h = Get-Json '/wxcx/health'; Write-Host ("[i] 服务在线 port={0}" -f $Port) -ForegroundColor Green }
catch { Write-Host '[-] 服务不可达' -ForegroundColor Red; exit 1 }

$actionRows = @()
if (-not $SkipBaseline) {
    Write-Host '请保持微信空闲（不要发消息、不要切窗口）。'
    $baselineRows = Run-Phase '基线采样' $Seconds
} else {
    $baselineRows = @()
}

Write-Host ''
Write-Host '现在执行目标操作（例如：右键卡片 → 转发 → 文件传输助手 → 发送）' -ForegroundColor Yellow
$actionRows = Run-Phase ("操作采样: " + $Label) $Seconds

# 归一化：func -> count
function ToMap($rows) {
    $m = @{}
    foreach ($r in $rows) {
        if ($null -eq $r) { continue }
        $fv = $r.func
        if ($null -eq $fv) { continue }
        $k = ('0x{0:X}' -f [int64]$fv)
        $c = 0
        try { $c = [int64]$r.hits } catch { $c = 0 }
        if ($m.ContainsKey($k)) { $m[$k] += $c } else { $m[$k] = $c }
    }
    return $m
}

$bMap = ToMap $baselineRows
$aMap = ToMap $actionRows

$only = @()
$grown = @()
foreach ($k in $aMap.Keys) {
    $av = $aMap[$k]
    if (-not $bMap.ContainsKey($k)) {
        $only += [ordered]@{ func = $k; action = $av; baseline = 0 }
    } else {
        $bv = $bMap[$k]
        if ($av -ge ($bv * 3) -and $av -ge 5) {
            $grown += [ordered]@{ func = $k; action = $av; baseline = $bv }
        }
    }
}
$only  = @($only  | Sort-Object { -$_.action })
$grown = @($grown | Sort-Object { -$_.action })

Write-Host ''
Write-Host ("[结果] 操作期间函数数={0}  基线={1}  仅操作出现={2}  显著增长={3}" -f $aMap.Count, $bMap.Count, $only.Count, $grown.Count) -ForegroundColor Cyan

# 对只出现的函数查所属区间（辅助定位）
foreach ($o in $only) {
    if ($o.func -match '^0x') {
        try {
            $w = Get-Json ("/wxcx/sym/where?rva=" + $o.func)
            if ($w.ok) { $o.func_start = ('0x{0:X}' -f [int64]$w.func_start); $o.is_entry = [bool]$w.is_entry }
        } catch {}
    }
}

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$outDir = Join-Path (Split-Path -Parent $here) 'capture'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$path = Join-Path $outDir ("sample-diff-$Label-$stamp.json")

$report = [ordered]@{
    label = $Label
    started_at = (Get-Date).ToString('s')
    seconds = $Seconds
    interval_ms = $Interval
    baseline_funcs = $bMap.Count
    action_funcs = $aMap.Count
    only_in_action = $only
    grown = $grown
    baseline_top = @($baselineRows | Select-Object -First 40)
    action_top = @($actionRows | Select-Object -First 40)
}
$report | ConvertTo-Json -Depth 6 | Set-Content $path -Encoding UTF8

Write-Host ''
Write-Host '仅操作期间出现（前 15）:'
$only | Select-Object -First 15 | ForEach-Object { "   {0,-12} count={1,-6} start={2}" -f $_.func, $_.action, $_.func_start }
Write-Host '显著增长（前 10）:'
$grown | Select-Object -First 10 | ForEach-Object { "   {0,-12} action={1,-6} baseline={2}" -f $_.func, $_.action, $_.baseline }

Write-Host ''
Write-Host ("[+] 报告: {0}" -f $path) -ForegroundColor Green
