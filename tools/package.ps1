# package.ps1 - 打成可拷到真机的自包含目录（+ zip）
#
# 用法：
#   .\tools\package.ps1                       # 输出 dist\wxcx-4.1.10.27-<时间戳>\
#   .\tools\package.ps1 -ZipOnly              # 只留 zip
param(
    [string]$Repo,
    [string]$OutDir,
    [switch]$ZipOnly
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $Repo) { $Repo = Split-Path -Parent $here }

$dll = Join-Path $Repo 'x64\Release\version.dll'
if (-not (Test-Path $dll)) { throw "未找到构建产物: $dll" }

$stamp = Get-Date -Format 'yyyyMMdd-HHmm'
if (-not $OutDir) { $OutDir = Join-Path $Repo "dist\wxcx-4.1.10.27-$stamp" }
if (Test-Path $OutDir) { throw "输出目录已存在: $OutDir" }

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $OutDir 'docs') | Out-Null

Copy-Item $dll (Join-Path $OutDir 'version.dll') -Force

foreach ($f in 'deploy.ps1', 'run_wechat.ps1', 'wxcx-common.ps1', 'smoke_test.ps1', 'capture_cmdid.ps1', 'guided_capture.ps1', 'oneclick_toxml.ps1', 'oneclick_forward.ps1', 'forward-analysis-common.ps1', 'test_forward_analysis.ps1', 'capture_forward_source.ps1', 'forward-source-plan.json', 'test_forward_plan.ps1', 'wxcx.config.example.json', 'wxcx_probe.json') {
    $src = Join-Path $here $f
    if (Test-Path $src) { Copy-Item $src (Join-Path $OutDir $f) -Force }
}

foreach ($d in 'DEPLOY_AND_USE.md', 'CAPABILITY_MATRIX.md', 'FORWARD_HANDOFF.md') {
    $src = Join-Path $Repo "docs\$d"
    if (Test-Path $src) { Copy-Item $src (Join-Path $OutDir "docs\$d") -Force }
}

$readme = @"
wxcx for Weixin 4.1.10.27 —— 部署包
生成时间: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

一、准备
  1) 把整个目录拷到真机任意位置（例：C:\wxcx）
  2) 确认真机微信版本是 4.1.10.27（版本不符会被 deploy.ps1 拦下）
  3) 完全退出微信

二、配置目录（必须，真机路径与开发机不同）
  复制 wxcx.config.example.json 为 wxcx.config.json，改 VersionDir / InstallRoot：
    {
      "VersionDir":  "D:\Program Files\Tencent\Weixin\4.1.10.27",
      "InstallRoot": "D:\Program Files\Tencent\Weixin",
      "Port": 30001,
      "BindAddr": "127.0.0.1",
      "Token": "",
      "ExpectedVersion": "4.1.10.27"
    }
  说明：VersionDir 是含 Weixin.dll 的版本子目录；InstallRoot 是含 Weixin.exe 的安装根。
       不填也能自动探测（进程 > 环境变量 WXCX_VERSION_DIR > 注册表 > 常见目录）。

三、部署
  powershell -ExecutionPolicy Bypass -File .\deploy.ps1 -WhatIfOnly   # 先干跑确认路径
  powershell -ExecutionPolicy Bypass -File .\deploy.ps1               # 正式部署（自动备份）

四、启动
  powershell -ExecutionPolicy Bypass -File .\run_wechat.ps1 -Port 30001
  # 局域网访问改成： -BindAddr 0.0.0.0 -Token 你的口令

五、自检（扫码登录后）
  powershell -ExecutionPolicy Bypass -File .\smoke_test.ps1
  # 输出 PASS/WARN/FAIL 表；有 FAIL 时退出码为 1

六、常用
  Invoke-RestMethod http://127.0.0.1:30001/wxcx/health
  Invoke-RestMethod http://127.0.0.1:30001/IsLoginStatus -Method Post -ContentType 'application/json' -Body '{}'
  Invoke-RestMethod http://127.0.0.1:30001/SendTextMsg -Method Post -ContentType 'application/json' -Body '{"toid":"filehelper","msg":"hi"}'

七、卸载
  删除安装目录的 version.dll，或用同名 .bak_wxcx 备份覆盖回来。

详细说明见 docs\DEPLOY_AND_USE.md。
"@
$readmePath = Join-Path $OutDir 'README.txt'
[IO.File]::WriteAllText($readmePath, $readme, (New-Object System.Text.UTF8Encoding($true)))

$zip = "$OutDir.zip"
if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path (Join-Path $OutDir '*') -DestinationPath $zip -CompressionLevel Optimal

Write-Host ("[+] 目录: {0}" -f $OutDir)
Write-Host ("[+] 压缩: {0}  ({1:N0} 字节)" -f $zip, (Get-Item $zip).Length)
Get-ChildItem $OutDir -Recurse -File | ForEach-Object {
    "    {0,-42} {1,10:N0}" -f $_.FullName.Substring($OutDir.Length + 1), $_.Length
}

if ($ZipOnly) { Remove-Item $OutDir -Recurse -Force; Write-Host "[+] 已删除解包目录（-ZipOnly）" }
