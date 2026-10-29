# Forward capture / offline analysis. All candidates remain unverified.
[CmdletBinding()]
param(
    [string]$Config, [int]$Port = 0, [string]$Token,
    [ValidateRange(1,3590)][int]$Seconds = 25,
    [string]$ProbeRva = '0x1677A30', [string]$Preset = 'forward_entry',
    [ValidateSet('A_text','B_card','C_forward')][string[]]$Only = @(),
    [string]$CapturePath, [string]$OutputDirectory, [switch]$SelfTest, [switch]$NoPrompt,
    [string]$ProbePlanPath, [string]$CaptureScriptId,
    [string]$CaptureScriptSha256, [string]$CapturePipelineSha256, [string]$ProbePlanSha256,
    $ScenarioContext, $ProbeStatusIdentity
)
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
. (Join-Path $here 'forward-analysis-common.ps1')
# Default: .\oneclick_forward.ps1 -Preset forward_entry
# Legacy single-point use: .\oneclick_forward.ps1 -ProbeRva 0x1677A30
# Offline: .\oneclick_forward.ps1 -CapturePath <capture.json>
# forward_entry observes complex native objects; it does not establish a callable four-argument ABI.
if ($PSBoundParameters.ContainsKey('ProbeRva') -and -not $PSBoundParameters.ContainsKey('Preset')) { $Preset = '' }

# Offline branches never read configuration/credentials or contact a service.
if ($SelfTest) { & (Join-Path $here 'test_forward_analysis.ps1'); return }
if ($CapturePath) {
    $capture = ConvertFrom-ForwardJson (Get-Content -LiteralPath $CapturePath -Raw -Encoding UTF8)
    $analysis = Get-ForwardAnalysis -Capture $capture
} else {
    $probePlan = $null; $probePlanRaw = $null
    if ($ProbePlanPath) {
        if ($PSBoundParameters.ContainsKey('ProbeRva') -or $PSBoundParameters.ContainsKey('Preset')) { throw 'Use ProbePlanPath alone, without ProbeRva/Preset.' }
        # Read a plain .NET string: WinPS 5.1 Get-Content adds provider metadata
        # whose PSDrive/Provider graph can explode during deep JSON serialization.
        $planFile = (Resolve-Path -LiteralPath $ProbePlanPath).ProviderPath
        $probePlanRaw = [IO.File]::ReadAllText($planFile, [Text.Encoding]::UTF8)
        $probePlan = ConvertFrom-ForwardJson $probePlanRaw
        $null = ConvertTo-ForwardProbePlan $probePlan
        $expectedScriptId = Get-ForwardField $probePlan 'capture_script_id'
        if ($CaptureScriptId -and $expectedScriptId -and $CaptureScriptId -ne $expectedScriptId) {
            throw ("Capture script/plan mismatch: script={0}, plan={1}. Use the matching package." -f $CaptureScriptId, $expectedScriptId)
        }
        $Preset = 'inline_plan'
    }
    . (Join-Path $here 'wxcx-common.ps1')
    if (-not $Config) {
        foreach ($path in @((Join-Path $here 'wxcx.config.json'), (Join-Path (Split-Path -Parent $here) 'wxcx.config.json'))) {
            if (Test-Path -LiteralPath $path) { $Config = $path; break }
        }
    }
    $cfg = Read-WxcxConfig -Path $Config
    if ($Port -eq 0) { $Port = if ($cfg['Port']) { [int]$cfg['Port'] } else { 30001 } }
    if (-not $PSBoundParameters.ContainsKey('Token')) { $Token = [string]$cfg['Token'] }
    $headers = @{}
    if ($Token) { $headers['X-Wxcx-Token'] = $Token }
    $base = "http://127.0.0.1:$Port"
    $request = {
        param($method, $endpoint, $body)
        $argsHttp = @{ Uri = "$base$endpoint"; Method = $method; Headers = $headers; TimeoutSec = 25; ErrorAction = 'Stop'; UseBasicParsing = $true }
        if ($method -eq 'POST') { $argsHttp.ContentType = 'application/json'; $argsHttp.Body = $body }
        $response = Invoke-WebRequest @argsHttp
        $raw = [string]$response.Content
        [pscustomobject]@{ raw_json = $raw }
    }.GetNewClosure()
    if ($probePlan) {
        $transport = $request
        $request = {
            param($method, $endpoint, $body)
            if ($method -eq 'POST' -and $endpoint -eq '/wxcx/probe/preset') {
                $options = ConvertFrom-ForwardJson $body
                return Invoke-ForwardArmPlan -Plan $probePlan -WindowMs ([int]$options.ms) -Request $transport
            }
            & $transport $method $endpoint $body
        }
        $requiredFeatures = @(Get-ForwardField $probePlan 'required_features' @())
        $requiredProbeBuild = Get-ForwardField $probePlan 'required_probe_build_id'
        if ($requiredFeatures.Count -or $requiredProbeBuild) {
            if ($ProbeStatusIdentity) {
                # A suite supplies this window's fresh pre-arm identity observation.
                if (-not $ScenarioContext -or $ProbeStatusIdentity.status -ne 'success' -or
                    $ProbeStatusIdentity.suite_id -ne $ScenarioContext.suite_id -or
                    $ProbeStatusIdentity.scenario_id -cne $ScenarioContext.id -or
                    $ProbeStatusIdentity.plan_sha256 -ne (Get-FileHash -LiteralPath $planFile -Algorithm SHA256).Hash -or
                    $ProbeStatusIdentity.endpoint -ne "$base/wxcx/probe/status") {
                    throw 'Suite preflight identity does not match this scenario, endpoint and plan.'
                }
                $statusHasher = [Security.Cryptography.SHA256]::Create()
                try { $statusHash = ([BitConverter]::ToString($statusHasher.ComputeHash([Text.Encoding]::UTF8.GetBytes([string]$ProbeStatusIdentity.raw_json)))).Replace('-','') }
                finally { $statusHasher.Dispose() }
                if ($statusHash -ne $ProbeStatusIdentity.sha256) { throw 'Suite preflight response hash mismatch.' }
                $statusResponse = [pscustomobject]@{ raw_json = $ProbeStatusIdentity.raw_json }
            } else { $statusResponse = & $transport 'GET' '/wxcx/probe/status' $null }
            $status = ConvertFrom-ForwardJson $statusResponse.raw_json
            if ($requiredProbeBuild -and (Get-ForwardField $status 'probe_build_id') -cne $requiredProbeBuild) {
                throw ("Loaded probe DLL build does not match required '{0}'; no probes were armed." -f $requiredProbeBuild)
            }
            if (-not $ProbeStatusIdentity) {
                $ProbeStatusIdentity = [pscustomobject]@{ status = 'success'; observed_at = [DateTimeOffset]::UtcNow.ToString('o')
                    endpoint = "$base/wxcx/probe/status"; raw_json = $statusResponse.raw_json; response = $status }
            }
            $features = Get-ForwardField $status 'features'
            foreach ($feature in $requiredFeatures) {
                if ((Get-ForwardField $features ([string]$feature)) -ne $true) {
                    throw ("Loaded probe DLL lacks required feature '{0}'; no probes were armed. Load the matching probe DLL and restart WeChat before collecting." -f $feature)
                }
            }
        }
    }
    $capture = [ordered]@{
        schema_version = 3; started_at = [DateTimeOffset]::UtcNow.ToString('o')
        probe_rva = $(if ($Preset) { 'preset:' + $Preset } else { $ProbeRva })
        requested_seconds = $Seconds; scenarios = @(); symbols = @{}
        limitations = @('Consumer API may lose events between reads; saturation and queue loss invalidate absence evidence.',
            'Raw stack scanning is not unwinding. Probe registers do not describe caller entry arguments. No call ABI validation.')
    }
    if ($CaptureScriptId) {
        $capture['capture_metadata'] = [ordered]@{
            script_id = $CaptureScriptId
            script_sha256 = $CaptureScriptSha256
            pipeline_sha256 = $CapturePipelineSha256
            probe_plan_sha256 = $ProbePlanSha256
        }
    }
    if ($ScenarioContext) {
        $capture['scenario_context'] = $ScenarioContext
        $capture['suite_id'] = $ScenarioContext.suite_id
        $capture['suite_script_id'] = $ScenarioContext.suite_script_id
    }
    if ($ProbeStatusIdentity) { $capture['probe_status_identity'] = $ProbeStatusIdentity }
    $plan = @(
        @{ id = 'A_text'; title = '普通文本'; hint = '向文件传输助手发送普通文本' },
        @{ id = 'B_card'; title = '链接卡片'; hint = '向文件传输助手发送链接卡片' },
        @{ id = 'C_forward'; title = '转发卡片'; hint = '将已收到的卡片转发给文件传输助手' }
    )
    if ($probePlan) { $capture.probe_plan_json = $probePlanRaw }
    if ($Only.Count) { $plan = @($plan | Where-Object { $Only -contains $_.id }) }
    if ($ScenarioContext) {
        if (-not $ScenarioContext.id -or -not $ScenarioContext.suite_id) { throw 'ScenarioContext needs id and suite_id.' }
        $plan = @(@{ id = [string]$ScenarioContext.id; title = [string]$ScenarioContext.label
            hint = ('本轮转发已有消息；类型={0}，源会话={1}，消息编号={2}，目标={3}，资源状态={4}。等待【开始采集】后操作一次。' -f
                $ScenarioContext.type, $ScenarioContext.source_talker, $ScenarioContext.source_msgsvrid,
                $ScenarioContext.toid, $ScenarioContext.downloaded) })
    }
    foreach ($step in $plan) {
        Write-Host ("{0}: {1}；采集 {2} 秒" -f $step.id, $step.hint, $Seconds)
        if (-not $NoPrompt) { $null = Read-Host '准备好对应操作后按 Enter，开始采集' }
        $rec = Invoke-ForwardScenario -Scenario $step.id -Title $step.title -Seconds $Seconds -ProbeRva $ProbeRva -Preset $Preset -Request $request
        if ($ScenarioContext) { $rec | Add-Member -NotePropertyName scenario_context -NotePropertyValue $ScenarioContext }
        $capture.scenarios += $rec
        Write-Host ("【本轮采集结束】状态={0}，布防={1}，记录数={2}，窗口完整={3}" -f $rec.capture_status, $rec.arm_status, $rec.events.Count, $rec.trace_complete)
        foreach ($warning in $rec.warnings) { Write-Warning $warning }
        foreach ($err in $rec.errors) { Write-Warning ("{0}: {1}" -f $err.stage, $err.message) }
    }
    $capture.ended_at = [DateTimeOffset]::UtcNow.ToString('o')
    $resolver = {
        param($rva)
        $response = & $request 'GET' ("/wxcx/sym/where?rva=$rva") $null
        ConvertFrom-ForwardJson $response.raw_json
    }
    Write-Verbose 'Normalizing captured events and function boundaries.'
    $analysis = Get-ForwardAnalysis -Capture $capture -Resolve $resolver
    Write-Verbose 'Event normalization complete.'
    $capture.symbols = $analysis.symbols
}
if (-not $OutputDirectory) { $OutputDirectory = Join-Path (Split-Path -Parent $here) 'capture' }
Write-Verbose 'Writing capture, candidates and report.'
$paths = Write-ForwardReport -Capture $capture -Analysis $analysis -OutputDirectory $OutputDirectory
Write-Verbose 'Report files saved.'
$paths | Format-List | Out-Host
if (@($capture.scenarios | Where-Object { $_.capture_status -eq 'failed' }).Count) {
    throw 'Capture failed in one or more scenarios. Evidence/errors were saved; collection failure is not zero hits.'
}
