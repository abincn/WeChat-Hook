# smoke_test.ps1 - 部署后一键自检（默认只做只读检查，不改变微信状态）
#
# 用法：
#   .\smoke_test.ps1                          # 读 wxcx.config.json（若存在）
#   .\smoke_test.ps1 -Port 30001
#   .\smoke_test.ps1 -Token abc123
#   .\smoke_test.ps1 -IncludeSend             # 额外发一条文本给 filehelper
param(
    [string]$Config,
    [int]$Port = 0,
    [string]$Token,
    [switch]$IncludeSend
)

$ErrorActionPreference = 'Continue'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $here 'wxcx-common.ps1')

if (-not $Config) {
    foreach ($c in @((Join-Path $here 'wxcx.config.json'), (Join-Path (Split-Path -Parent $here) 'wxcx.config.json'))) {
        if (Test-Path $c) { $Config = $c; break }
    }
}
$cfg = Read-WxcxConfig -Path $Config
if ($Port -eq 0)    { $Port = if ($cfg['Port']) { [int]$cfg['Port'] } else { 30001 } }
if ($null -eq $Token) { $Token = [string]$cfg['Token'] }

$base = "http://127.0.0.1:$Port"
$headers = @{}
if ($Token) { $headers['X-Wxcx-Token'] = $Token }

$rows = @()

function Add-Row($name, $status, $detail) {
    $script:rows += [pscustomobject]@{ 检查 = $name; 结果 = $status; 说明 = $detail }
}

function Get-Json($path, $timeout = 10) {
    Invoke-RestMethod "$base$path" -Headers $headers -TimeoutSec $timeout
}

function Post-Json($path, $body, $timeout = 15) {
    Invoke-RestMethod "$base$path" -Method Post -Headers $headers `
        -ContentType 'application/json' -Body $body -TimeoutSec $timeout
}

# 0) 连通性
try {
    $h = Get-Json '/wxcx/health'
    Add-Row 'GET /wxcx/health' 'PASS' ("start_port={0}" -f $h.start_port)
} catch {
    Add-Row 'GET /wxcx/health' 'FAIL' $_.Exception.Message
    $rows | Format-Table -AutoSize | Out-String -Width 160 | Write-Host
    Write-Host '[-] 服务不可达：确认微信已启动、version.dll 已部署、端口未被占用' -ForegroundColor Red
    exit 1
}

# 1) 登录状态
try {
    $s = Post-Json '/IsLoginStatus' '{}'
    if ($s.onlinestatus -eq '3') { Add-Row 'POST /IsLoginStatus' 'PASS' $s.msg }
    else { Add-Row 'POST /IsLoginStatus' 'WARN' ("onlinestatus={0}（未登录，后续用例可能失败）" -f $s.onlinestatus) }
} catch { Add-Row 'POST /IsLoginStatus' 'FAIL' $_.Exception.Message }

# 2) 能力矩阵
try {
    $c = Get-Json '/wxcx/capabilities'
    Add-Row 'GET /wxcx/capabilities' 'PASS' ("ok={0} partial={1} ready={2} blocked={3}" -f `
        $c.summary.ok, $c.summary.partial, $c.summary.ready, $c.summary.blocked)
} catch { Add-Row 'GET /wxcx/capabilities' 'FAIL' $_.Exception.Message }

# 3) 数据库表清单
try {
    $t = Get-Json '/wxcx/tables?db=MicroMsg.db'
    $n = if ($t.data) { ($t.data | Measure-Object).Count } else { 0 }
    Add-Row 'POST /wxcx/tables' $(if ($n -gt 0) { 'PASS' } else { 'WARN' }) ("tables={0}" -f $n)
} catch { Add-Row 'POST /wxcx/tables' 'FAIL' $_.Exception.Message }

# 4) 消息历史
try {
    $m = Post-Json '/wxcx/msg/recent' '{"limit":5}'
    if ($m.status -eq 0) {
        Add-Row 'POST /wxcx/msg/recent' 'PASS' ("table={0} count={1}" -f $m.table, $m.count)
    } else {
        Add-Row 'POST /wxcx/msg/recent' 'WARN' ("status={0} {1}" -f $m.status, $m.msg)
    }
} catch { Add-Row 'POST /wxcx/msg/recent' 'FAIL' $_.Exception.Message }

# 5) 联系人
try {
    $ct = Post-Json '/GetContacts' '{"limit":3}'
    Add-Row 'POST /GetContacts' 'PASS' ("returned={0}" -f (($ct.data | Measure-Object).Count))
} catch { Add-Row 'POST /GetContacts' 'FAIL' $_.Exception.Message }

# 6) 探针/自检/防护 状态
foreach ($p in '/wxcx/probe/status', '/wxcx/verify/status', '/wxcx/guard/status', '/wxcx/callback/status') {
    try {
        $r = Get-Json $p
        Add-Row ("GET $p") 'PASS' 'ok'
    } catch { Add-Row ("GET $p") 'FAIL' $_.Exception.Message }
}

# 7) 可选：发一条文本
if ($IncludeSend) {
    try {
        $r = Post-Json '/SendTextMsg' '{"toid":"filehelper","msg":"wxcx smoke test"}'
        Add-Row 'POST /SendTextMsg(filehelper)' $(if ($r.code -eq '0' -or $r.code -eq 0) { 'PASS' } else { 'WARN' }) `
            ("code={0}" -f $r.code)
    } catch { Add-Row 'POST /SendTextMsg(filehelper)' 'FAIL' $_.Exception.Message }
}

# 汇总
$rows | Format-Table -AutoSize | Out-String -Width 160 | Write-Host
$fail = ($rows | Where-Object { $_.结果 -eq 'FAIL' } | Measure-Object).Count
$warn = ($rows | Where-Object { $_.结果 -eq 'WARN' } | Measure-Object).Count
Write-Host ("总计 {0} 项：PASS {1} / WARN {2} / FAIL {3}" -f `
    $rows.Count, ($rows.Count - $fail - $warn), $warn, $fail) -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })

exit $(if ($fail) { 1 } else { 0 })
