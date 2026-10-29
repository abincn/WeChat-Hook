[CmdletBinding()]
param(
    [string]$Config,
    [ValidateRange(1,3590)][int]$Seconds = 45,
    [string]$OutputDirectory,
    [switch]$NoPrompt
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'wxcx-common.ps1')
if (-not $Config) { $Config = Join-Path $PSScriptRoot 'wxcx.config.json' }
if (-not (Test-Path -LiteralPath $Config -PathType Leaf)) { throw 'Existing test configuration is required.' }
$cfg = Read-WxcxConfig -Path $Config
Write-Host '[FWD-FILEHELPER-20261028-04-R3] 四类消息转发采集，所有发送操作由你在微信中完成。'
Write-Host '依次采集：文本、链接卡片、图片、文件；目标均为文件传输助手。'
Write-Host '每轮先找到提示时间对应的原消息，按回车后等待【开始采集】，再右键原消息 → 转发 → 文件传输助手 → 发送。'
Write-Host '等本轮结束，再按下一轮提示操作。'
$captureArgs = @{
    ManifestPath = Join-Path $PSScriptRoot 'forward-filehelper-04.json'
    Config = $Config; CollectOnly = $true; Seconds = $Seconds
    # WinPS converts an omitted [string] parameter to empty text, so the
    # suite's null-only fallback does not load Token. Pass it explicitly.
    Token = [string]$cfg['Token']
}
if ($cfg['Port']) { $captureArgs.Port = [int]$cfg['Port'] }
if ($PSBoundParameters.ContainsKey('OutputDirectory')) { $captureArgs.OutputDirectory = $OutputDirectory }
if ($NoPrompt) { $captureArgs.NoPrompt = $true }
# Never print captureArgs: the configured token is private.
& (Join-Path $PSScriptRoot 'capture_forward_suite.ps1') @captureArgs
