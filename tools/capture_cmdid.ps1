# capture_cmdid.ps1 - 一次性抓取并解析 envelope 的 varint 字段
#
# 用法：
#   .\tools\capture_cmdid.ps1                 # 交互式：布防 → 你操作微信 → 解析
#   .\tools\capture_cmdid.ps1 -Seconds 60     # 只等待 60 秒
#   .\tools\capture_cmdid.ps1 -SelfTest       # 离线自检（用合成数据验证解析逻辑）
#
# 原理：
#   /wxcx/probe/preset 在 0x2C6C550（MicroMsgRequestNew 序列化）下 INT3，
#   每次发请求都会把 msg 对象前 96 字节 dump 出来。
#   脚本把这 96 字节按 4 字节切成 dword，横向对比多条记录：
#     * 随请求类型变化 → cmdId 候选
#     * 单调递增         → seq 候选
#     * 恒定不变         → 版本号/会话等

param(
    [int]$Port = 30001,
    [int]$Seconds = 90,
    [int]$DumpBytes = 96,
    [switch]$SelfTest,
    [string]$HexOverride
)

$ErrorActionPreference = 'Stop'
$base = "http://127.0.0.1:$Port"

function Split-Dwords([string]$hex) {
    $bytes = for ($i = 0; $i + 1 -lt $hex.Length; $i += 2) {
        [Convert]::ToByte($hex.Substring($i, 2), 16)
    }
    $out = @()
    for ($o = 0; $o + 3 -lt $bytes.Count; $o += 4) {
        $out += [uint32]($bytes[$o] -bor ($bytes[$o+1] -shl 8) -bor ($bytes[$o+2] -shl 16) -bor ($bytes[$o+3] -shl 24))
    }
    return ,$out
}

function Analyze-Offsets($events, [int]$dumpLen) {
    $n = [int]($dumpLen / 4)
    $rows = @()

    for ($k = 0; $k -lt $n; $k++) {
        $vals = @()
        foreach ($e in $events) {
            $d = Split-Dwords $e.dump_hex
            if ($k -lt $d.Count) { $vals += $d[$k] }
        }
        if ($vals.Count -eq 0) { continue }

        $distinct = ($vals | Sort-Object -Unique).Count
        $monotonic = $true
        for ($i = 1; $i -lt $vals.Count; $i++) {
            if ($vals[$i] -le $vals[$i-1]) { $monotonic = $false; break }
        }

        $kind = if ($distinct -eq 1) { '常量' }
                elseif ($monotonic) { '递增(seq?)' }
                elseif ($distinct -le 8 -and ($vals | Measure-Object -Maximum).Maximum -lt 100000) { '变化(cmdId?)' }
                else { '其它' }

        $rows += [pscustomobject]@{
            offset = ('+0x{0:X2}' -f ($k * 4))
            kind   = $kind
            distinct = $distinct
            values = (($vals | Select-Object -First 6) -join ', ')
        }
    }
    return $rows
}

function Show-Table($rows) {
    $rows | Format-Table -AutoSize | Out-String -Width 160
}

# ---------------- 自检 ----------------
if ($SelfTest) {
    Write-Host '[selftest] 用合成 dump 验证解析与分类逻辑' -ForegroundColor Cyan
    # 造 3 条记录：+0x08 恒定, +0x14 递增, +0x1C 随类型变化
    function Make-Dump([uint32]$const, [uint32]$seq, [uint32]$cmd) {
        $dw = New-Object 'uint32[]' 24
        $dw[2] = $const
        $dw[5] = $seq
        $dw[7] = $cmd
        $hex = ''
        foreach ($v in $dw) {
            for ($b = 0; $b -lt 4; $b++) { $hex += '{0:X2}' -f (($v -shr (8*$b)) -band 0xFF) }
        }
        return $hex
    }
    $fake = @(
        @{ dump_hex = (Make-Dump 0xAABB 100 237) },
        @{ dump_hex = (Make-Dump 0xAABB 101 237) },
        @{ dump_hex = (Make-Dump 0xAABB 102 1200) }
    )
    $rows = Analyze-Offsets $fake 96
    Show-Table $rows
    $cmd = $rows | Where-Object { $_.kind -like '变化*' }
    $seq = $rows | Where-Object { $_.kind -like '递增*' }
    Write-Host ("[selftest] cmdId 候选: {0}" -f (($cmd | ForEach-Object { $_.offset }) -join ','))
    Write-Host ("[selftest] seq   候选: {0}" -f (($seq | ForEach-Object { $_.offset }) -join ','))
    $pass = (@($cmd).Count -eq 1 -and $cmd[0].offset -eq '+0x1C') -and (@($seq).Count -eq 1 -and $seq[0].offset -eq '+0x14')
    Write-Host ("[selftest] 结果: {0}" -f $(if ($pass) { 'PASS' } else { 'FAIL' })) -ForegroundColor $(if ($pass) { 'Green' } else { 'Red' })
    return
}

# ---------------- 实际抓取 ----------------
Write-Host "== 1/4 布防 envelope 探针 (dump=$DumpBytes) ==" -ForegroundColor Cyan
$arm = Invoke-RestMethod "$base/wxcx/probe/preset" -Method Post -ContentType 'application/json' `
        -Body (@{ name = 'messages'; ms = ($Seconds * 1000 + 15000) } | ConvertTo-Json)
$arm.armed | Format-Table -AutoSize | Out-String -Width 120 | Write-Host
if (-not ($arm.armed | Where-Object { $_.ok })) {
    Write-Host '布防失败：检查微信是否已注入、RVA 是否被占用' -ForegroundColor Red
    return
}

Write-Host "== 2/4 清空旧事件 ==" -ForegroundColor Cyan
try { Invoke-RestMethod "$base/wxcx/probe/events?limit=1" | Out-Null } catch {}

Write-Host ("== 3/4 请现在操作微信（{0} 秒内）：发 1 条消息 + 建 1 个群 ==" -f $Seconds) -ForegroundColor Yellow
for ($t = $Seconds; $t -gt 0; $t -= 5) {
    Write-Host ("   剩余 {0}s ..." -f $t)
    Start-Sleep -Seconds 5
}

Write-Host '== 4/4 拉取并解析 ==' -ForegroundColor Cyan
$ev = Invoke-RestMethod "$base/wxcx/probe/events?limit=20"
$events = @($ev.events)
Write-Host ("捕获 {0} 条记录" -f $events.Count)

if ($events.Count -lt 2) {
    Write-Host '记录太少：至少需要 2 次请求（一次发消息、一次建群）才能对比' -ForegroundColor Yellow
    return
}

$rows = Analyze-Offsets $events $DumpBytes
Show-Table $rows | Write-Host

# 子消息正文（follow_hex）与调用栈（stack_hex）
foreach ($e in $events | Select-Object -First 3) {
    if ($e.PSObject.Properties.Name -contains 'follow_hex' -and $e.follow_hex) {
        Write-Host ("follow 正文: {0}…" -f $e.follow_hex.Substring(0, [Math]::Min(80, $e.follow_hex.Length)))
    }
}
$stacks = $events | Where-Object { $_.PSObject.Properties.Name -contains 'stack_hex' -and $_.stack_hex }
if ($stacks) {
    Write-Host '调用栈候选（每 8 字节一个小端 qword，落在镜像内的即为返回地址）:' -ForegroundColor Cyan
    $d = Split-Dwords $stacks[0].stack_hex
    for ($i = 0; $i + 1 -lt $d.Count; $i += 2) {
        $q = ([uint64]$d[$i+1] -shl 32) -bor [uint64]$d[$i]
        if ($q -ge 0x180000000 -and $q -lt 0x18AF0E000) { Write-Host ('   rva 0x{0:X}' -f ($q - 0x180000000)) }
    }
}

$cmdCand = $rows | Where-Object { $_.kind -like '变化*' }
$seqCand = $rows | Where-Object { $_.kind -like '递增*' }

Write-Host ''
Write-Host '== 结论 ==' -ForegroundColor Cyan
Write-Host ("cmdId 候选: {0}" -f (($cmdCand | ForEach-Object { "$($_.offset) 值=$($_.values)" }) -join ' | '))
Write-Host ("seq   候选: {0}" -f (($seqCand | ForEach-Object { $_.offset }) -join ', '))
Write-Host ''
Write-Host '把上面两行发我，即可确定 cmdId 并点亮群操作接口。' -ForegroundColor Green
Write-Host '也可以用 /wxcx/pb/decode 对 dump_hex 里的 LEN 字段做进一步确认。'
