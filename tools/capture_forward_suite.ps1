# Observation-only orchestration. Never installs a DLL or invokes a send/forward API.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ManifestPath,
    [string]$Config, [int]$Port = 0, [string]$Token,
    [ValidateRange(1,3590)][int]$Seconds = 30,
    [string]$OutputDirectory, [string]$PackageDirectory, [string]$PythonPath,
    [switch]$LookupSource = $true, [switch]$StructureOnly, [switch]$NoPrompt, [switch]$ValidateOnly, [switch]$CollectOnly
)
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$repo = Split-Path -Parent $here
. (Join-Path $here 'forward-analysis-common.ps1')
. (Join-Path $here 'wxcx-common.ps1')
$suiteScriptId = 'FWD-SUITE-20261028-04-R3'
$captureScriptId = 'FWD-CAP-20261028-04-R3'
$probeBuildId = 'FWD-PROBE-20261028-04'
$packageScriptNames = @('capture_forward_internal.ps1','oneclick_forward.ps1','forward-analysis-common.ps1',
    'forward-internal-plan.json','capture_forward_suite.ps1','analyze_forward_suite.py','wxcx-common.ps1')
$packageScriptHashes = @{}
if ($StructureOnly) { $LookupSource = $false }
function Get-SuiteTextHash([string]$Text) {
    $provider = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($provider.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text)))).Replace('-','') }
    finally { $provider.Dispose() }
}
function Get-SuiteFileHash([string]$Path) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash }
function Get-SuitePackageField([string]$Text, [string]$Name) {
    $matchesFound = [regex]::Matches($Text, '(?m)^' + [regex]::Escape($Name) + ': ([^\r\n]+)\s*$')
    if ($matchesFound.Count -ne 1) { throw "Package metadata requires exactly one $Name field." }
    $matchesFound[0].Groups[1].Value.Trim()
}
function Get-SuitePipelineHash([string]$Directory) {
    $lines = @('capture_forward_internal.ps1','oneclick_forward.ps1','forward-analysis-common.ps1','forward-internal-plan.json') | ForEach-Object {
        '{0}:{1}' -f $_, (Get-SuiteFileHash (Join-Path $Directory $_))
    }
    Get-SuiteTextHash ($lines -join "`n")
}
function Assert-SuiteDecimal($Value, [string]$Field) {
    if ($Value -isnot [string] -or $Value -notmatch '^[1-9][0-9]{0,19}$') { throw "$Field must be a POSITIVE decimal string (replace the example zero sentinel; never use a JSON number)." }
    $null = [UInt64]::Parse($Value, [Globalization.CultureInfo]::InvariantCulture)
}
function Save-Suite {
    $suite | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $suitePath -Encoding UTF8
}
function Invoke-SuiteRead([string]$Method, [string]$Endpoint, $Body) {
    $observation = [ordered]@{ endpoint = "$base$Endpoint"; method = $Method; observed_at = [DateTimeOffset]::UtcNow.ToString('o')
        status = 'failed'; request_json = $null; raw_json = $null; sha256 = $null; response = $null; error = $null }
    try {
        $http = @{ Uri = "$base$Endpoint"; Method = $Method; Headers = $headers; TimeoutSec = 25; UseBasicParsing = $true; ErrorAction = 'Stop' }
        if ($Method -eq 'POST') {
            $observation.request_json = $Body | ConvertTo-Json -Compress
            $http.ContentType = 'application/json'; $http.Body = $observation.request_json
        }
        $reply = Invoke-WebRequest @http
        $observation.raw_json = [string]$reply.Content
        $observation.sha256 = Get-SuiteTextHash $observation.raw_json
        $observation.response = ConvertFrom-ForwardJson $observation.raw_json
        $observation.status = 'success'
    } catch {
        $observation.error = $_.Exception.Message
        # HTTP error bodies often explain unavailable/ambiguous DB evidence.
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
            $observation['error_details'] = [string]$_.ErrorDetails.Message
        }
    }
    [pscustomobject]$observation
}
function Assert-SuiteScriptSet {
    foreach ($name in $packageScriptNames) {
        $currentHash = Get-SuiteFileHash (Join-Path $here $name)
        if ($currentHash -ne (Get-SuiteFileHash (Join-Path $packageTools $name)) -or
            ($packageScriptHashes.ContainsKey($name) -and $packageScriptHashes[$name] -ne $currentHash)) {
            throw "Current script differs from the 04 package: $name. No next window was armed."
        }
        $packageScriptHashes[$name] = $currentHash
    }
}
function Get-SuiteRuntimeKey($Runtime) {
    if ((Get-ForwardField $Runtime 'probe_build_id') -cne $probeBuildId) { throw 'Runtime probe build mismatch.' }
    $processIdValue = Get-ForwardField $Runtime 'process_id'
    if ($processIdValue -is [bool] -or [string]$processIdValue -notmatch '^[1-9][0-9]{0,9}$' -or
        [UInt64]$processIdValue -gt [UInt32]::MaxValue) { throw 'Missing or invalid runtime process_id.' }
    $processStart = Get-ForwardField $Runtime 'process_start_filetime'
    Assert-SuiteDecimal $processStart 'runtime process_start_filetime'
    $probe = Get-ForwardField $Runtime 'probe'
    $target = Get-ForwardField $Runtime 'weixin'
    if ((Get-ForwardField $probe 'status') -cne 'hashed' -or
        (Get-ForwardField $probe 'mapped_headers_match') -isnot [bool] -or $probe.mapped_headers_match -ne $true -or
        [string](Get-ForwardField $probe 'actual_sha256') -notmatch '^[A-Fa-f0-9]{64}$' -or
        $probe.actual_sha256 -ne $packageDllHash) { throw 'Loaded probe DLL does not match the 04 package DLL/hash/mapped headers.' }
    if ((Get-ForwardField $target 'status') -cne 'hashed' -or
        (Get-ForwardField $target 'verified') -isnot [bool] -or $target.verified -ne $true -or
        [string](Get-ForwardField $target 'actual_sha256') -notmatch '^[A-Fa-f0-9]{64}$' -or
        $target.actual_sha256 -ne (Get-ForwardField $target 'expected_sha256')) { throw 'Runtime target Weixin.dll identity is unverified.' }
    [ordered]@{ process_id = [string]$processIdValue; process_start_filetime = $processStart
        probe_build_id = $probeBuildId; probe_sha256 = ([string]$probe.actual_sha256).ToUpperInvariant()
        weixin_sha256 = ([string]$target.actual_sha256).ToUpperInvariant()
        probe_path = Get-ForwardField $probe 'path'; weixin_path = Get-ForwardField $target 'path' } | ConvertTo-Json -Compress
}
function Get-SuiteIdentityKey($Observation) {
    $status = $Observation.response
    $caps = $Observation.forward_capabilities
    $binary = Get-ForwardField $caps.response 'binary_identity'
    $feature = Get-ForwardField (Get-ForwardField $status 'features') 'follow_read_offset'
    $verified = Get-ForwardField $binary 'verified'
    if ($Observation.status -ne 'success' -or [int](Get-ForwardField $status 'schema_version' 0) -lt 2 -or
        $feature -isnot [bool] -or $feature -ne $true -or
        (Get-ForwardField $status 'probe_build_id') -cne $probeBuildId) { throw 'Probe schema/feature/build identity mismatch; no next window was armed.' }
    if ($caps.status -ne 'success' -or $verified -isnot [bool] -or $verified -ne $true -or
        (Get-ForwardField $binary 'status') -cne 'hashed' -or
        [string](Get-ForwardField $binary 'actual_sha256') -notmatch '^[A-Fa-f0-9]{64}$' -or
        $binary.expected_sha256 -ne $binary.actual_sha256) { throw 'Target Weixin.dll binary identity is missing or unverified.' }
    $statusKey = Get-SuiteRuntimeKey (Get-ForwardField $status 'runtime_identity')
    $capsRuntime = Get-ForwardField $caps.response 'runtime_identity'
    $capsKey = Get-SuiteRuntimeKey $capsRuntime
    if ($statusKey -cne $capsKey -or $binary.actual_sha256 -ne $capsRuntime.weixin.actual_sha256) {
        throw 'Probe status and forward capabilities refer to different process/runtime identities.'
    }
    $statusKey
}
function Get-SuiteFreshPreflight {
    $fresh = Invoke-SuiteRead 'GET' '/wxcx/probe/status' $null
    $fresh | Add-Member -NotePropertyMembers @{
        suite_id = $suiteId; plan_sha256 = $suite.provenance.plan_sha256
        forward_capabilities = (Invoke-SuiteRead 'GET' '/wxcx/forward/capabilities' $null)
    }
    $fresh
}

# All local validation happens before any network access or probe operation.
$manifestFile = (Resolve-Path -LiteralPath $ManifestPath).ProviderPath
$manifestRaw = [IO.File]::ReadAllText($manifestFile, [Text.Encoding]::UTF8)
# Do not stringify large numeric tokens here: MsgSvrID MUST be supplied as JSON text.
$manifest = ConvertFrom-Json -InputObject $manifestRaw -ErrorAction Stop
$scenes = @(Get-ForwardField $manifest 'scenarios' @())
if ($scenes.Count -lt 4) { throw 'Manifest needs 4+ labeled scenarios covering text, link, image and file.' }
$seen = @{}; $types = @{}
foreach ($scene in $scenes) {
    foreach ($reserved in @('suite_id','suite_script_id')) {
        if (Test-ForwardField $scene $reserved) { throw "Reserved scenario property: $reserved" }
    }
    if ($scene.id -isnot [string] -or $scene.id -notmatch '^[A-Za-z0-9][A-Za-z0-9_-]{0,79}$' -or $seen.ContainsKey($scene.id)) { throw 'Scenario IDs must be unique safe names, 1..80 characters.' }
    $seen[$scene.id] = $true
    if (@('text','link','image','file') -cnotcontains $scene.type) { throw "Invalid scenario type: $($scene.type)" }
    $types[$scene.type] = $true
    foreach ($key in @('label','source_talker','toid')) {
        $value = Get-ForwardField $scene $key
        if ($value -isnot [string] -or [string]::IsNullOrWhiteSpace($value)) { throw "Scenario $($scene.id) needs $key." }
    }
    Assert-SuiteDecimal $scene.source_msgsvrid "Scenario $($scene.id) source_msgsvrid"
    if (Test-ForwardField $scene 'db_msgsvrid') { Assert-SuiteDecimal $scene.db_msgsvrid "Scenario $($scene.id) db_msgsvrid" }
    $downloaded = Get-ForwardField $scene 'downloaded'
    if ($downloaded -isnot [bool] -and @('downloaded','not_downloaded','unknown','not_applicable') -cnotcontains $downloaded) { throw "Scenario $($scene.id) needs downloaded state (boolean or downloaded/not_downloaded/unknown/not_applicable)." }
}
foreach ($type in @('text','link','image','file')) { if (-not $types.ContainsKey($type)) { throw "Manifest is missing $type." } }
$planPath = Join-Path $here 'forward-internal-plan.json'
$plan = ConvertFrom-ForwardJson ([IO.File]::ReadAllText($planPath))
$points = ConvertTo-ForwardProbePlan $plan
if ($plan.capture_script_id -cne $captureScriptId -or $plan.target_version -ne '4.1.10.27' -or $points.Count -ne 4 -or
    @($plan.required_features) -notcontains 'follow_read_offset') { throw 'Expected the current 04 four-point plan for 4.1.10.27.' }
$servicePoint = @($points | Where-Object { $_.rva -eq '0x16BDF60' })
if ($servicePoint.Count -ne 1 -or $servicePoint[0].follow_read_offset -ne 400 -or $servicePoint[0].follow_len -ne 32) { throw 'Service identity tail must read 32 bytes at +0x190.' }
if (-not $PackageDirectory) {
    $PackageDirectory = if (Test-Path -LiteralPath (Join-Path $repo 'PACKAGE.txt')) { $repo }
        else { Join-Path $repo 'dist/wxcx-forward-codex-20261028-04-r3/bundle' }
}
$packageRoot = (Resolve-Path -LiteralPath $PackageDirectory).ProviderPath
$packageTextPath = Join-Path $packageRoot 'PACKAGE.txt'
$packageText = [IO.File]::ReadAllText($packageTextPath)
if ((Get-SuitePackageField $packageText 'Package') -cne 'wxcx-forward-codex-20261028-04-r3' -or
    (Get-SuitePackageField $packageText 'Capture script ID') -cne $captureScriptId -or
    (Get-SuitePackageField $packageText 'Suite script ID') -cne $suiteScriptId) { throw 'Wrong capture package version; expected the current 04 bundle.' }
$expectedDllHash = Get-SuitePackageField $packageText 'DLL SHA256'
$expectedPipelineHash = Get-SuitePackageField $packageText 'Pipeline SHA256'
$packageDllPath = Join-Path $packageRoot 'version.dll'
$packageDllHash = Get-SuiteFileHash $packageDllPath
$packageTools = Join-Path $packageRoot 'tools'
$packagePipelineHash = Get-SuitePipelineHash $packageTools
if ($expectedDllHash -notmatch '^[0-9A-Fa-f]{64}$' -or $packageDllHash -ne $expectedDllHash -or
    $expectedPipelineHash -notmatch '^[0-9A-Fa-f]{64}$' -or $packagePipelineHash -ne $expectedPipelineHash) {
    throw 'Package integrity/version mismatch; no probes were armed.'
}
Assert-SuiteScriptSet
if (-not $CollectOnly -and -not $ValidateOnly) {
if (-not $PythonPath) {
    $pythonCommand = Get-Command python.exe,python,python3 -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($pythonCommand) { $PythonPath = $pythonCommand.Source }
    else {
        $bundledPython = Join-Path $env:USERPROFILE '.cache/codex-runtimes/codex-primary-runtime/dependencies/python/python.exe'
        if (Test-Path -LiteralPath $bundledPython) { $PythonPath = $bundledPython }
    }
}
if (-not $PythonPath -or -not (Test-Path -LiteralPath $PythonPath)) { throw 'Python 3 is required for offline suite analysis. Supply -PythonPath.' }
}
$suiteId = 'forward-suite-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [Guid]::NewGuid().ToString('N').Substring(0,12)
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $repo 'capture' }
$null = New-Item -ItemType Directory -Force -Path $OutputDirectory
$outputRoot = (Resolve-Path -LiteralPath $OutputDirectory).ProviderPath
$suiteDirectory = Join-Path $outputRoot $suiteId
$null = New-Item -ItemType Directory -Path $suiteDirectory
$suitePath = Join-Path $suiteDirectory 'suite.json'
$manifestSnapshot = Join-Path $suiteDirectory 'manifest.json'
[IO.File]::WriteAllText($manifestSnapshot, $manifestRaw, (New-Object Text.UTF8Encoding($false)))
$provenanceDirectory = Join-Path $suiteDirectory 'provenance'
$null = New-Item -ItemType Directory -Path $provenanceDirectory
$archiveNames = @($packageScriptNames)
if (Test-Path -LiteralPath (Join-Path $here 'forward-suite.example.json')) { $archiveNames += 'forward-suite.example.json' }
$files = $archiveNames | ForEach-Object {
    $path = Join-Path $here $_
    $snapshot = Join-Path $provenanceDirectory $_
    Copy-Item -LiteralPath $path -Destination $snapshot
    [pscustomobject]@{ path = $snapshot; source_path = $path; sha256 = Get-SuiteFileHash $snapshot }
}
$suite = [ordered]@{
    schema_version = 1; suite_id = $suiteId; suite_script_id = $suiteScriptId
    started_at = [DateTimeOffset]::UtcNow.ToString('o'); ended_at = $null; status = 'validated'
    target_version = '4.1.10.27'; lookup_source = [bool]$LookupSource
    analysis_mode = $(if ($CollectOnly) { 'deferred' } elseif ($ValidateOnly) { 'not_requested' } else { 'inline' })
    manifest = $manifest; manifest_path = $manifestSnapshot; manifest_sha256 = Get-SuiteFileHash $manifestSnapshot
    package = [ordered]@{ expected_script_id = $captureScriptId; expected_probe_build_id = $probeBuildId; verified = $true; status = 'verified'
        expected_suite_script_id = $suiteScriptId; name = 'wxcx-forward-codex-20261028-04-r3'; directory = $packageRoot; metadata_path = $packageTextPath
        metadata_sha256 = Get-SuiteFileHash $packageTextPath; dll_path = $packageDllPath; dll_sha256 = $packageDllHash; pipeline_sha256 = $packagePipelineHash
        note = '04 package scripts and DLL must match current scripts and the runtime probe module file identity.' }
    provenance = [ordered]@{ plan_sha256 = Get-SuiteFileHash $planPath; pipeline_sha256 = Get-SuitePipelineHash $here; files = @($files) }
    preflight = $null; scenarios = @(); errors = @()
    limitations = @('Observation only; all forwarding actions are manual. No native sends, DLL installation or ABI validation.',
        'A matching byte window or integer candidate does not prove message-ID semantics.',
        'Identity observations bracket each window; unobserved transient changes and runtime-memory integrity remain outside this check.')
}
Save-Suite
if ($ValidateOnly) { Write-Host "Validated locally; no service contacted. $suitePath"; return }
if (-not $Config) {
    foreach ($file in @((Join-Path $here 'wxcx.config.json'), (Join-Path $repo 'wxcx.config.json'))) {
        if (Test-Path -LiteralPath $file) { $Config = $file; break }
    }
}
$cfg = Read-WxcxConfig -Path $Config
if ($Port -eq 0) { $Port = if ($cfg['Port']) { [int]$cfg['Port'] } else { 30001 } }
if (-not $PSBoundParameters.ContainsKey('Token')) { $Token = [string]$cfg['Token'] }
$headers = @{}
if ($Token) { $headers['X-Wxcx-Token'] = $Token }
$base = "http://127.0.0.1:$Port"
$failed = $false
try {
    # Establish the baseline, then refresh and compare identity for every window.
    $statusObservation = Get-SuiteFreshPreflight
    $suite.preflight = $statusObservation
    Save-Suite
    $baselineIdentity = Get-SuiteIdentityKey $statusObservation
    $suite.status = 'collecting'; Save-Suite
    $sceneNumber = 0
    foreach ($scene in $scenes) {
        $sceneNumber++
        Assert-SuiteScriptSet
        $context = [ordered]@{ suite_id = $suiteId; suite_script_id = $suiteScriptId }
        foreach ($p in $scene.PSObject.Properties) { if ($context.Contains($p.Name)) { throw "Reserved scenario property: $($p.Name)" }; $context[$p.Name] = $p.Value }
        $sceneDirectory = Join-Path $suiteDirectory $scene.id
        $null = New-Item -ItemType Directory -Path $sceneDirectory
        $entry = [pscustomobject]@{ id = $scene.id; context = $context; status = 'pending'; capture_path = $null; capture_sha256 = $null
            source_lookup = $null; preflight = $null; postflight = $null; error = $null; artifacts = @() }
        $suite.scenarios += $entry
        if ($LookupSource) {
            $entry.source_lookup = Invoke-SuiteRead 'POST' '/wxcx/db/locate_unique' @{ msgsvrid = $scene.source_msgsvrid; source_talker = $scene.source_talker }
        }
        $typeName = @{ text='文本'; link='链接卡片'; image='图片'; file='文件' }[$scene.type]
        Write-Host ("【第 {0}/{1} 轮：{2}】{3}" -f $sceneNumber, $scenes.Count, $typeName, $scene.label)
        Write-Host ("源会话：{0}；消息编号：{1}；目标会话：{2}" -f $scene.source_talker, $scene.source_msgsvrid, $scene.toid)
        Write-Host '先在聊天记录中找到这条原消息，停留在原消息处，等待开始采集。'
        Write-Host '看到【开始采集】后，再右键原消息 → 转发 → 文件传输助手 → 发送；每轮只操作一次。'
        if (-not $NoPrompt) { $null = Read-Host '找到原消息后按回车；脚本先核对版本，再显示【开始采集】' }
        $entry.preflight = Get-SuiteFreshPreflight
        $entry.preflight | Add-Member -NotePropertyName scenario_id -NotePropertyValue $scene.id
        Save-Suite
        try {
            Assert-SuiteScriptSet
            if ((Get-SuitePipelineHash $here) -ne $suite.provenance.pipeline_sha256) { throw 'Capture pipeline changed during the suite.' }
            if ((Get-SuiteIdentityKey $entry.preflight) -cne $baselineIdentity) { throw 'Process/runtime identity changed; no next window was armed.' }
        } catch {
            $entry.status = 'failed'; $entry.error = $_.Exception.Message; Save-Suite; throw
        }
        $captureArgs = @{
            ProbePlanPath = $planPath; CaptureScriptId = $captureScriptId
            CaptureScriptSha256 = Get-SuiteFileHash (Join-Path $here 'capture_forward_internal.ps1')
            CapturePipelineSha256 = $suite.provenance.pipeline_sha256; ProbePlanSha256 = $suite.provenance.plan_sha256
            ScenarioContext = $context; ProbeStatusIdentity = $entry.preflight
            Seconds = $Seconds; OutputDirectory = $sceneDirectory; NoPrompt = $true
            Port = $Port; Token = $Token
        }
        if ($Config) { $captureArgs.Config = $Config }
        try { & (Join-Path $here 'oneclick_forward.ps1') @captureArgs; $entry.status = 'captured' }
        catch { $entry.status = 'failed'; $entry.error = $_.Exception.Message; $failed = $true }
        # Bracket the window even if oneclick failed: a different process may
        # otherwise produce a clean-looking trace after a restart/replacement.
        $entry.postflight = Get-SuiteFreshPreflight
        $entry.postflight | Add-Member -NotePropertyMembers @{ scenario_id = $scene.id; phase = 'post_window' }
        Save-Suite
        try {
            Assert-SuiteScriptSet
            if ((Get-SuiteIdentityKey $entry.postflight) -cne $baselineIdentity) {
                throw 'Process/runtime identity changed after capture; this window is invalid.'
            }
        } catch {
            $entry.status = 'failed'; $failed = $true
            $entry.error = (@($entry.error, $_.Exception.Message) | Where-Object { $_ }) -join ' '
        }
        # Even failed captures can have valuable raw evidence saved by oneclick.
        $captures = @(Get-ChildItem -LiteralPath $sceneDirectory -Filter 'forward-capture-*.json' -File)
        if ($captures.Count -eq 1) { $entry.capture_path = $captures[0].FullName; $entry.capture_sha256 = Get-SuiteFileHash $entry.capture_path }
        else {
            $entry.status = 'failed'
            $entry.error = (@($entry.error, 'Expected exactly one saved capture.') | Where-Object { $_ }) -join ' '
            $failed = $true
        }
        $entry.artifacts = @(Get-ChildItem -LiteralPath $sceneDirectory -File | ForEach-Object { [pscustomobject]@{ path = $_.FullName; sha256 = Get-SuiteFileHash $_.FullName } })
        Save-Suite
        if ($entry.status -eq 'failed') { break }
    }
    $suite.status = if ($failed) { 'incomplete' } else { 'collected' }
} catch {
    $failed = $true; $suite.status = 'failed'; $suite.errors += $_.Exception.Message
} finally {
    $suite.ended_at = [DateTimeOffset]::UtcNow.ToString('o'); Save-Suite
    if ($CollectOnly) {
        Write-Warning '原始记录已保存，等待离线分析；保存完成不代表转发功能已验证成功。'
    } else {
        & $PythonPath -B (Join-Path $here 'analyze_forward_suite.py') --suite $suitePath --output-directory $suiteDirectory
        if ($LASTEXITCODE -ne 0) { $failed = $true; Write-Warning '离线分析发现证据不足或分析失败，原因已保存在记录目录。' }
    }
    Write-Host "采集记录：$suitePath"
}
if ($failed) { throw '采集未完整完成，错误及原始记录已保存到上述目录。' }
