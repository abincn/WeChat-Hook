# run_wechat.ps1 - 带 wxcx 参数启动微信（参数由 DLL 从进程命令行解析）
#
# 用法：
#   .\run_wechat.ps1                              # 读 wxcx.config.json / 自动探测目录
#   .\run_wechat.ps1 -VersionDir "D:\...\4.1.10.27" -Port 30002 -Token abc123
param(
    [string]$Config,
    [string]$VersionDir,
    [int]$Port = 0,
    [string]$BindAddr,
    [string]$Token,
    [string]$CallBackURL,
    [switch]$WhatIfOnly
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $here 'wxcx-common.ps1')

if (-not $Config) {
    foreach ($c in @((Join-Path $here 'wxcx.config.json'), (Join-Path (Split-Path -Parent $here) 'wxcx.config.json'))) {
        if (Test-Path $c) { $Config = $c; break }
    }
}
$cfg = Read-WxcxConfig -Path $Config

if (-not $VersionDir) { $VersionDir = $cfg['VersionDir'] }
if (-not $VersionDir) { $VersionDir = Find-WeixinVersionDir -Expected $(if ($cfg["ExpectedVersion"]) { $cfg["ExpectedVersion"] } else { "4.1.10.27" }) }
if (-not $VersionDir) { throw "找不到微信目录：设置 -VersionDir 或在 wxcx.config.json 里填 VersionDir" }

if ($Port -eq 0)    { $Port = if ($cfg['Port']) { [int]$cfg['Port'] } else { 30001 } }
if (-not $BindAddr) { $BindAddr = if ($cfg['BindAddr']) { $cfg['BindAddr'] } else { '127.0.0.1' } }
if ($null -eq $Token)      { $Token = [string]$cfg['Token'] }
if (-not $CallBackURL)     { $CallBackURL = [string]$cfg['CallBackURL'] }

# 启动器通常在安装根（含 Weixin.exe），版本子目录只有 Weixin.dll
$exe = Join-Path $VersionDir 'Weixin.exe'
$workDir = $VersionDir
if (-not (Test-Path $exe)) {
    $parent = Split-Path -Parent $VersionDir
    $cand = Join-Path $parent 'Weixin.exe'
    if (Test-Path $cand) { $exe = $cand; $workDir = $parent }
}
if (-not (Test-Path $exe)) { throw "找不到 Weixin.exe（已查 $VersionDir 与其父目录）" }

$proxy = Join-Path $VersionDir 'version.dll'
if (-not (Test-Path $proxy)) {
    Write-Host "[!] 目标目录没有 version.dll，先跑 deploy.ps1" -ForegroundColor Yellow
}

$args = @("StartPort=$Port", "BindAddr=$BindAddr")
if ($Token)       { $args += "Token=$Token" }
if ($CallBackURL) { $args += "CallBackURL=$CallBackURL" }

Write-Host ("[i] 启动器: {0}
[i] 工作目录: {1}" -f $exe, $workDir)
Write-Host ("[i] 参数: {0}" -f ($args -join ' '))
if ($WhatIfOnly) { Write-Host "[dry] 不实际启动"; return }
Start-Process -FilePath $exe -ArgumentList $args -WorkingDirectory $workDir

Write-Host '[i] 扫码登录后验活：'
Write-Host ("    Invoke-RestMethod http://127.0.0.1:{0}/wxcx/health" -f $Port)
