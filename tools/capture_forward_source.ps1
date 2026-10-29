[CmdletBinding()]
param(
    [string]$Config, [int]$Port = 0, [string]$Token,
    [ValidateRange(1,3590)][int]$Seconds = 30,
    [string]$OutputDirectory, [switch]$NoPrompt
)
$ErrorActionPreference = 'Stop'
$argsCapture = @{
    ProbePlanPath = Join-Path $PSScriptRoot 'forward-source-plan.json'
    Only = @('C_forward'); Seconds = $Seconds
}
foreach ($key in @('Config','Port','Token','OutputDirectory','NoPrompt')) {
    if ($PSBoundParameters.ContainsKey($key)) { $argsCapture[$key] = $PSBoundParameters[$key] }
}
# Support both repo/tools and repo/dist/<bundle>. Reuse the existing project
# configuration and capture directory when either layout is present.
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
Write-Host 'Source-object capture uses the currently running schema-2 DLL. No DLL/config replacement or restart is needed.'
& (Join-Path $PSScriptRoot 'oneclick_forward.ps1') @argsCapture
