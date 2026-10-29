# wxcx-common.ps1 - 部署/启动脚本共用的路径解析与版本校验
# 被 deploy.ps1 / run_wechat.ps1 dot-source 引入，不单独执行。

$script:ExpectedDllSize = 183094832   # Weixin.dll 体积（4.1.10.27），用于版本兜底校验

function Read-WxcxConfig {
    param([string]$Path)
    if (-not $Path) { return @{} }
    if (-not (Test-Path $Path)) { return @{} }
    try {
        $j = Get-Content $Path -Raw -Encoding UTF8 | ConvertFrom-Json
        $h = @{}
        foreach ($p in $j.PSObject.Properties) {
            if ($p.Name -notlike '_*') { $h[$p.Name] = $p.Value }
        }
        return $h
    } catch {
        Write-Host ("[!] 配置文件解析失败，忽略: {0} — {1}" -f $Path, $_.Exception.Message) -ForegroundColor Yellow
        return @{}
    }
}

function Find-WeixinVersionDir {
    param([string]$Expected = '4.1.10.27')

    # 收集候选目录：进程 / 环境变量 / 注册表 / 常见根目录及其一层子目录
    $cands = New-Object System.Collections.Generic.List[string]

    $p = Get-Process Weixin -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($p -and $p.Path) { $cands.Add((Split-Path -Parent $p.Path)) }

    if ($env:WXCX_VERSION_DIR) { $cands.Add($env:WXCX_VERSION_DIR) }

    foreach ($k in @('HKCU:\Software\Tencent\Weixin',
                     'HKLM:\SOFTWARE\WOW6432Node\Tencent\Weixin',
                     'HKLM:\SOFTWARE\Tencent\Weixin')) {
        if (-not (Test-Path $k)) { continue }
        $v = (Get-ItemProperty $k -ErrorAction SilentlyContinue).InstallPath
        if ($v) { $cands.Add($v) }
    }

    foreach ($r in @((Join-Path $env:ProgramFiles 'Tencent\Weixin'),
                     (Join-Path ${env:ProgramFiles(x86)} 'Tencent\Weixin'),
                     'D:\net\Tencent\Weixin',
                     'D:\Program Files\Tencent\Weixin'
)) {
        $cands.Add($r)
    }

    # 展开一层子目录（版本子目录结构：<root>\4.1.10.27\Weixin.dll）
    $all = New-Object System.Collections.Generic.List[string]
    foreach ($c in $cands) {
        if (-not $c -or -not (Test-Path $c)) { continue }
        $all.Add($c)
        Get-ChildItem $c -Directory -ErrorAction SilentlyContinue | ForEach-Object { $all.Add($_.FullName) }
    }

    # 只保留真正含 Weixin.dll 的目录，并按"是否匹配期望版本"打分
    $best = $null
    $bestScore = -1
    foreach ($d in ($all | Select-Object -Unique)) {
        $dll = Join-Path $d 'Weixin.dll'
        if (-not (Test-Path $dll)) { continue }

        $score = 0
        $fi = Get-Item $dll
        if ($fi.VersionInfo.FileVersion -like "$Expected*") { $score += 100 }
        $lo = [int]($script:ExpectedDllSize * 0.95); $hi = [int]($script:ExpectedDllSize * 1.05)
        if ($fi.Length -ge $lo -and $fi.Length -le $hi) { $score += 50 }
        if (Test-Path (Join-Path $d 'Weixin.exe')) { $score += 5 }

        if ($score -gt $bestScore) { $bestScore = $score; $best = $d }
    }
    return $best
}

function Test-WeixinVersion {
    param(
        [Parameter(Mandatory)][string]$VersionDir,
        [string]$Expected = '4.1.10.27'
    )
    $dll = Join-Path $VersionDir 'Weixin.dll'
    if (-not (Test-Path $dll)) {
        return [pscustomobject]@{ Ok = $false; Reason = "找不到 Weixin.dll: $dll" }
    }
    $fi   = Get-Item $dll
    $fv   = $fi.VersionInfo.FileVersion
    $size = $fi.Length

    if ($fv -and $fv -like "$Expected*") {
        return [pscustomobject]@{ Ok = $true; Reason = "文件版本 $fv"; Size = $size }
    }
    # 版本字段不可用时用体积兜底（±5%）
    $lo = [int]($script:ExpectedDllSize * 0.95)
    $hi = [int]($script:ExpectedDllSize * 1.05)
    if ($size -ge $lo -and $size -le $hi) {
        return [pscustomobject]@{ Ok = $true; Reason = "按体积判定（$size 字节，期望 $($script:ExpectedDllSize)）"; Size = $size }
    }
    return [pscustomobject]@{
        Ok     = $false
        Reason = ("版本不匹配：文件版本='{0}'，Weixin.dll 体积={1}（期望约 {2}）" -f $fv, $size, $script:ExpectedDllSize)
        Size   = $size
    }
}
