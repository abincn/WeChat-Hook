@echo off
rem wxcx-run.cmd - 绕过 PowerShell 执行策略运行本目录脚本
rem
rem   wxcx-run.cmd oneclick_forward.ps1 -Preset forwardprobe4 -Only C_forward -Seconds 30
rem   wxcx-run.cmd deploy.ps1
rem   wxcx-run.cmd run_wechat.ps1
rem
rem 说明：只对本次调用的进程生效（-ExecutionPolicy Bypass），不修改系统策略。

setlocal
set "SCRIPT=%~1"
if "%SCRIPT%"=="" (
    echo 用法: wxcx-run.cmd ^<脚本名^> [参数...]
    echo 例:   wxcx-run.cmd oneclick_forward.ps1 -Preset forwardprobe4 -Only C_forward -Seconds 30
    exit /b 1
)
shift

set "HERE=%~dp0"
set "TARGET=%HERE%%SCRIPT%"
if not exist "%TARGET%" (
    echo [-] 找不到脚本: %TARGET%
    exit /b 1
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%TARGET%" %*
exit /b %ERRORLEVEL%
