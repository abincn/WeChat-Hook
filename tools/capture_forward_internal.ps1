[CmdletBinding()]
param(
    [string]$Config, [int]$Port = 0, [string]$Token,
    [ValidateRange(1,3590)][int]$Seconds = 30,
    [string]$OutputDirectory, [switch]$NoPrompt
)
$ErrorActionPreference = 'Stop'
$CaptureScriptId = 'FWD-CAP-20261028-04-R3' # Bump this ID for every published script revision.
$CapturePlanPath = Join-Path $PSScriptRoot 'forward-internal-plan.json'
$CaptureScriptSha256 = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash
$CapturePlanSha256 = (Get-FileHash -LiteralPath $CapturePlanPath -Algorithm SHA256).Hash
$pipelineFiles = @('capture_forward_internal.ps1','oneclick_forward.ps1','forward-analysis-common.ps1','forward-internal-plan.json')
$pipelineText = ($pipelineFiles | ForEach-Object {
    $file = Join-Path $PSScriptRoot $_
    "{0}:{1}" -f $_, (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash
}) -join "`n"
$shaProvider = [Security.Cryptography.SHA256]::Create()
try { $CapturePipelineSha256 = ([BitConverter]::ToString($shaProvider.ComputeHash([Text.Encoding]::UTF8.GetBytes($pipelineText)))).Replace('-','') }
finally { $shaProvider.Dispose() }
$argsCapture = @{
    ProbePlanPath = $CapturePlanPath
    CaptureScriptId = $CaptureScriptId
    CaptureScriptSha256 = $CaptureScriptSha256
    CapturePipelineSha256 = $CapturePipelineSha256
    ProbePlanSha256 = $CapturePlanSha256
    Only = @('C_forward'); Seconds = $Seconds
}
foreach ($key in @('Config','Port','Token','OutputDirectory','NoPrompt')) {
    if ($PSBoundParameters.ContainsKey($key)) { $argsCapture[$key] = $PSBoundParameters[$key] }
}
# Support both repo/tools and repo/dist/<bundle> layouts.
$repoCandidates = @(
    (Split-Path -Parent $PSScriptRoot),
    (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
)
$repoCandidate = $repoCandidates | Where-Object {
    Test-Path -LiteralPath (Join-Path $_ 'tools\wxcx-common.ps1')
} | Select-Object -First 1
if ($repoCandidate) {
    if (-not $argsCapture.ContainsKey('OutputDirectory')) { $argsCapture.OutputDirectory = Join-Path $repoCandidate 'capture' }
    if (-not $argsCapture.ContainsKey('Config')) {
        foreach ($file in @('tools\wxcx.config.json','wxcx.config.json')) {
            $candidate = Join-Path $repoCandidate $file
            if (Test-Path -LiteralPath $candidate) { $argsCapture.Config = $candidate; break }
        }
    }
}
Write-Host ("CAPTURE_SCRIPT_ID={0}" -f $CaptureScriptId)
Write-Host ("SCRIPT_SHA256={0}" -f $CaptureScriptSha256)
Write-Host ("PIPELINE_SHA256={0}" -f $CapturePipelineSha256)
Write-Host ("PROBE_PLAN_SHA256={0}" -f $CapturePlanSha256)
Write-Host 'This capture only observes the existing WeChat process. It does not invoke forwarding functions or replace the DLL.'
& (Join-Path $PSScriptRoot 'oneclick_forward.ps1') @argsCapture
