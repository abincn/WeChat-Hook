# deploy.ps1 - 把 version.dll 部署到目标机器的微信目录（支持配置/自动探测/版本校验）
#
# 用法：
#   .\deploy.ps1                        # 读 wxcx.config.json（若存在），否则自动探测微信目录
#   .\deploy.ps1 -VersionDir "D:\...\4.1.10.27" -InstallRoot "D:\...\Weixin"
#   .\deploy.ps1 -WhatIfOnly            # 干跑
#   .\deploy.ps1 -Launch                # 部署后带参数启动
#   .\deploy.ps1 -Force                 # 版本不匹配也强行部署（不推荐）
param(
    [string]$Repo,
    [string]$Config,
    [string]$VersionDir,
    [string]$InstallRoot,
    [int]$Port = 0,
    [string]$BindAddr,
    [string]$Token,
    [string]$CallBackURL,
    [switch]$Launch,
    [switch]$WhatIfOnly,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $here 'wxcx-common.ps1')

if (-not $Repo) { $Repo = Split-Path -Parent $here }
if (-not $Config) {
    foreach ($c in @((Join-Path $here 'wxcx.config.json'), (Join-Path $Repo 'wxcx.config.json'))) {
        if (Test-Path $c) { $Config = $c; break }
    }
}
$cfg = Read-WxcxConfig -Path $Config

# 参数 > 配置文件 > 自动探测
if (-not $VersionDir) { $VersionDir = $cfg['VersionDir'] }
if (-not $VersionDir) { $VersionDir = Find-WeixinVersionDir -Expected $expected }
if (-not $VersionDir) {
    throw "找不到微信目录：请设置 -VersionDir，或在 wxcx.config.json 里填 VersionDir"
}
if (-not $InstallRoot) {
    if ($cfg['InstallRoot']) { $InstallRoot = $cfg['InstallRoot'] }
    else { $InstallRoot = Split-Path -Parent $VersionDir }
}
if ($Port -eq 0)      { $Port = if ($cfg['Port']) { [int]$cfg['Port'] } else { 30001 } }
if (-not $BindAddr)   { $BindAddr = if ($cfg['BindAddr']) { $cfg['BindAddr'] } else { '127.0.0.1' } }
if ($null -eq $Token)       { $Token = [string]$cfg['Token'] }
if (-not $CallBackURL)      { $CallBackURL = [string]$cfg['CallBackURL'] }
$expected = if ($cfg['ExpectedVersion']) { $cfg['ExpectedVersion'] } else { '4.1.10.27' }

Write-Host ("[i] 微信目录 : {0}" -f $VersionDir)
Write-Host ("[i] 安装根   : {0}" -f $InstallRoot)
Write-Host ("[i] 配置文件 : {0}" -f $(if ($Config) { $Config } else { '<未使用>' }))

$ver = Test-WeixinVersion -VersionDir $VersionDir -Expected $expected
if ($ver.Ok) {
    Write-Host ("[+] 版本校验通过: {0}" -f $ver.Reason)
} else {
    Write-Host ("[!] {0}" -f $ver.Reason) -ForegroundColor Red
    if (-not $Force) {
        throw "已中止：偏移只对 $expected 有效，装到其它版本会崩溃。确认无误可加 -Force"
    }
    Write-Host "[!] -Force 已指定，继续部署（后果自负）" -ForegroundColor Yellow
}

$built = Join-Path $Repo 'x64\Release\version.dll'
if (-not (Test-Path $built)) { $built = Join-Path $Repo 'version.dll' }
if (-not (Test-Path $built)) { throw "未找到构建产物 version.dll（先在仓库里构建）" }

$src = Get-Item $built
Write-Host ("[i] 产物     : {0}  {1:N0} 字节  {2}" -f $src.FullName, $src.Length, $src.LastWriteTime)

$targets = @($VersionDir, $InstallRoot) | Where-Object { Test-Path $_ } | Select-Object -Unique
foreach ($t in $targets) {
    $dst = Join-Path $t 'version.dll'
    if (Test-Path $dst) {
        $bak = "$dst.bak_wxcx"
        if (-not (Test-Path $bak)) {
            if (-not $WhatIfOnly) { Copy-Item $dst $bak -Force }
            Write-Host "[i] 备份 -> $bak"
        }
    }
    if ($WhatIfOnly) { Write-Host "[dry] 复制 -> $dst" }
    else {
        try { Copy-Item $built $dst -Force; Write-Host "[+] 已部署 -> $dst" }
        catch { throw "复制失败（微信可能正在运行）: $($_.Exception.Message)" }
    }
}

Write-Host ""
Write-Host "下一步："
Write-Host ("  启动: {0} -VersionDir `"{1}`" -Port {2} -BindAddr {3}" -f (Join-Path $here 'run_wechat.ps1'), $VersionDir, $Port, $BindAddr)
Write-Host ("  验活: Invoke-RestMethod http://127.0.0.1:{0}/wxcx/health" -f $Port)

if ($Launch -and -not $WhatIfOnly) {
    $exe = Join-Path $VersionDir 'Weixin.exe'
    $wd  = $VersionDir
    if (-not (Test-Path $exe)) {
        $p = Join-Path (Split-Path -Parent $VersionDir) 'Weixin.exe'
        if (Test-Path $p) { $exe = $p; $wd = Split-Path -Parent $VersionDir }
    }
    $args = @("StartPort=$Port", "BindAddr=$BindAddr")
    if ($Token)       { $args += "Token=$Token" }
    if ($CallBackURL) { $args += "CallBackURL=$CallBackURL" }
    Write-Host ("[i] 启动: {0} {1}" -f $exe, ($args -join ' '))
    Start-Process -FilePath $exe -ArgumentList $args -WorkingDirectory $wd
}
