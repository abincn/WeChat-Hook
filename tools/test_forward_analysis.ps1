# Dedicated offline regression suite. Fixed fixtures; no live process, config, or network.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'forward-analysis-common.ps1')
$script:ForwardTestCount = 0
function Assert-Forward($Condition, [string]$Message) {
    if (-not $Condition) { throw "ASSERT FAILED: $Message" }
    $script:ForwardTestCount++
}
function New-TestEvent($Point = '0x1000', $Ret = '0x4010') {
    [pscustomobject]@{
        schema_version = 2; rva = $Point; ret_rva = $Ret
        capture_site = 'function_entry'; ret_valid = $true; register_scope = 'probe_site'
        stack_kind = 'raw_stack_scan_not_unwind'; seq = 11; tid = 7
        a1 = '9007199254740993'; a2 = $null; a3 = 0; a4 = '18446744073709551615'
        stack_hex = '1020304050607080'; dump_hex = 'AABBCCDD'; follow_hex = 'DEADBEEF'
        stack_rvas = @(0x3010,0x4010); dump_qwords = @(@{ off = 0; v = '9007199254740993' })
        future_field = @{ retained = $true }
    }
}
function New-TestScenario([string]$Id, [object[]]$Events = @(), [string[]]$Points = @('0x1000','0x2000')) {
    [pscustomobject]@{
        scenario = $Id; capture_status = 'success'; arm_status = 'success'; trace_complete = $true; trace_schema_version = 2
        armed_detail = @($Points | ForEach-Object { [pscustomobject]@{ rva = $_; ok = $true } })
        events = $Events; hit_count = $Events.Count; errors = @()
    }
}
$fixtureSymbols = @{
    '0x1000' = @{ ok = $true; func_start = '0x1000'; is_entry = $true }
    '0x2000' = @{ ok = $true; func_start = '0x2000'; is_entry = $true }
    '0x3010' = @{ ok = $true; func_start = '0x3000'; is_entry = $false }
    '0x3020' = @{ ok = $true; func_start = '0x3000'; is_entry = $false }
    '0x4010' = @{ ok = $true; func_start = '0x4000'; is_entry = $false }
    '0x5010' = @{ ok = $true; func_start = '0x5000'; is_entry = $false }
    '0x1677F10' = @{ ok = $true; func_start = '0x1677F10'; is_entry = $true }
    '0x216272B' = @{ ok = $true; func_start = '0x2162600'; is_entry = $false }
}
function New-TestCapture([object[]]$Scenarios) { [pscustomobject]@{ scenarios = $Scenarios; symbols = $fixtureSymbols } }
function New-MockTransport {
    param([string]$Mode = 'success', [object[]]$Events = @(), [int]$Dropped = 0)
    $state = @{ calls = (New-Object 'System.Collections.Generic.List[string]'); trace_reads = 0; disarms = 0 }
    $published = if ($Events.Count) { $Events[-1].seq } else { 10 }
    $traceRaw = @{ schema_version = 2; consuming = $true; published = $published; reader_skipped_total = 0; image_base = '9007199254740993'; image_size = 1048576; dropped = $Dropped; skipped = 0; busy = $false; events = $Events } | ConvertTo-Json -Depth 30 -Compress
    if ($Mode -eq 'legacy') { $traceRaw = @{ events = $Events; dropped = $Dropped } | ConvertTo-Json -Depth 30 -Compress }
    $request = {
        param($method, $path, $body)
        [void]$state.calls.Add("$method $path")
        if ($path -eq '/wxcx/probe/disarm') {
            $state.disarms++
            if ($Mode -eq 'disarm_failure' -and $state.disarms -gt 1) { throw 'fixture disarm failure' }
            if ($Mode -eq 'reset_failure' -and $state.disarms -eq 1) { throw 'fixture reset failure' }
            $raw = '{"ok":true}'
        } elseif ($path -like '/wxcx/probe/trace*' -or $path -like '/wxcx/probe/events*') {
            $state.trace_reads++
            if ($state.trace_reads -eq 1) {
                if ($Mode -eq 'preflight_failure') { throw 'fixture preflight failure' }
                $raw = '{"schema_version":2,"published":10,"dropped":0,"reader_skipped_total":0,"busy":false,"image_base":9007199254740993,"image_size":1048576,"events":[]}'
                if ($Mode -eq 'legacy') { $raw = '{"image_base":9007199254740993,"image_size":1048576,"events":[]}' }
            } else {
                if ($Mode -eq 'trace_failure') { throw 'fixture trace failure' }
                if ($Mode -eq 'malformed_trace') { $raw = '{"ok":true}' }
                elseif ($Mode -eq 'invalid_json') { $raw = '{BROKEN' }
                else { $raw = $traceRaw }
            }
        } elseif ($path -eq '/wxcx/probe/preset' -or $path -eq '/wxcx/probe/arm') {
            if ($Mode -eq 'arm_throw') { throw 'fixture arm HTTP failure after possible arm' }
            if ($Mode -eq 'no_arm') { $raw = '{"armed":[{"rva":4096,"ok":false}]}' }
            elseif ($Mode -eq 'partial') { $raw = '{"armed":[{"rva":4096,"ok":true},{"rva":8192,"ok":false}]}' }
            elseif ($path -eq '/wxcx/probe/arm') { $raw = '{"ok":true,"rva":4096}' }
            else { $raw = '{"armed":[{"rva":4096,"ok":true},{"rva":8192,"ok":true}]}' }
        } else { throw "Unexpected offline request: $method $path" }
        [pscustomobject]@{ raw_json = $raw }
    }.GetNewClosure()
    [pscustomobject]@{ state = $state; request = $request; trace_raw = $traceRaw }
}
function Invoke-MockScenario($Mock, [string]$Scenario = 'A_text', [string]$Preset = '') {
    Invoke-ForwardScenario -Scenario $Scenario -Seconds 0 -ProbeRva '0x1000' -Preset $Preset -Request $Mock.request
}

# Exact addresses, preserved JSON strings, and rejection of already rounded values.
$largeJson = '{"n":9007199254740993,"max":18446744073709551615,"s":"literal 9007199254740993 with \"text\"","zero":0}'
$large = ConvertFrom-ForwardJson $largeJson
Assert-Forward ((ConvertTo-ForwardAddress $large.n) -eq '0x20000000000001') '>2^53 integer must not round'
Assert-Forward ((ConvertTo-ForwardAddress $large.max) -eq '0xFFFFFFFFFFFFFFFF') 'UInt64 max must survive'
Assert-Forward ($large.s -eq 'literal 9007199254740993 with "text"') 'JSON string contents must remain intact'
Assert-Forward ((ConvertTo-ForwardAddress '0x0020000000000001') -eq '0x20000000000001') 'hex canonicalization'
$thrown = $false
try { $null = ConvertTo-ForwardAddress ([double]9007199254740992) } catch { $thrown = $true }
Assert-Forward $thrown 'already imprecise float must be rejected'

$c = New-TestScenario 'C_forward' @((New-TestEvent))
$cOnly = Get-ForwardAnalysis (New-TestCapture @($c))
Assert-Forward ($cOnly.candidates[0].evidence -eq 'baseline_missing') 'C-only capture must not claim differential evidence'
Assert-Forward ($cOnly.candidates[0].baseline_missing.Count -eq 2) 'both missing baselines identified'
Assert-Forward ($cOnly.groups[0].samples[0].registers.rdx -eq $null) 'unknown register stays null'
Assert-Forward ($cOnly.groups[0].samples[0].registers.r8 -eq '0x0') 'known zero stays zero'
Assert-Forward ($cOnly.groups[0].samples[0].registers.r9 -eq '0xFFFFFFFFFFFFFFFF') 'new R9 exact'

$a = New-TestScenario 'A_text' @((New-TestEvent '0x1000' '0x3010'))
$b = New-TestScenario 'B_card' @((New-TestEvent '0x1000' '0x3010'))
$c = New-TestScenario 'C_forward' @(
    (New-TestEvent '0x1000' '0x3020'), (New-TestEvent '0x1000' '0x4010'),
    (New-TestEvent '0x2000' '0x4010'), (New-TestEvent '0x1000' '0x4010'),
    (New-TestEvent '0x2000' '0x5010'))
$capture = New-TestCapture @($a,$b,$c)
$multi = Get-ForwardAnalysis $capture
Assert-Forward ($multi.candidates.Count -eq 4) 'all events and point/return groups must contribute'
$shared = @($multi.candidates | Where-Object { $_.caller_function_rva -eq '0x3000' })[0]
Assert-Forward ($shared.evidence -eq 'shared-with-baseline') 'same function with different return address is shared'
$repeat = @($multi.candidates | Where-Object { $_.probe_rva -eq '0x1000' -and $_.ret_rva -eq '0x4010' })[0]
Assert-Forward ($repeat.count -eq 2 -and $repeat.event_indexes.Count -eq 2) 'duplicate observations preserved'
Assert-Forward (@($multi.candidates | Where-Object { $_.evidence -eq 'only-in-C' }).Count -eq 3) 'all fully covered differential groups found'
Assert-Forward ($repeat.ret_is_entry -eq $false -and -not (Test-ForwardField $repeat 'is_entry')) 'ret_is_entry is not candidate-entry status'
Assert-Forward ($repeat.abi_validation -eq 'not_performed' -and $repeat.register_scope -eq 'probe_site') 'no ABI/caller-register claim'
$sample = @($multi.groups | Where-Object { $_.scenario -eq 'C_forward' })[0].samples[0]
Assert-Forward ($sample.raw_event.stack_hex -eq '1020304050607080' -and $sample.raw_event.dump_hex -eq 'AABBCCDD' -and $sample.raw_event.follow_hex -eq 'DEADBEEF') 'raw stack/dump/follow preserved'
Assert-Forward ($sample.raw_event.future_field.retained -eq $true) 'unknown future fields preserved'

$failedB = New-TestScenario 'B_card'; $failedB.capture_status = 'failed'; $failedB.trace_complete = $false
$failedAnalysis = Get-ForwardAnalysis (New-TestCapture @($a,$failedB,$c))
Assert-Forward (@($failedAnalysis.candidates | Where-Object { $_.evidence -ne 'baseline_missing' }).Count -eq 0) 'failed baseline disables differential evidence'
$otherPointB = New-TestScenario 'B_card' @() @('0x2000')
$otherPointAnalysis = Get-ForwardAnalysis (New-TestCapture @($a,$otherPointB,$c))
Assert-Forward (@($otherPointAnalysis.candidates | Where-Object { $_.probe_rva -eq '0x1000' -and $_.evidence -ne 'baseline_missing' }).Count -eq 0) 'coverage must match actual probe'
$zeroAnalysis = Get-ForwardAnalysis (New-TestCapture @((New-TestScenario 'A_text'),(New-TestScenario 'B_card'),(New-TestScenario 'C_forward' @((New-TestEvent)))))
Assert-Forward ($zeroAnalysis.candidates[0].evidence -eq 'only-in-C') 'successful covered zero-hit baselines support window-limited absence'

$legacy = [pscustomobject]@{ scenario = 'C_forward'; probe_rva = 'preset:forwardprobe3'; armed = $true; traps = 1; ret_rva = '0x216272B'; caller_function_rva = '0x2162600'; caller_is_entry = $false; registers = @{ r9 = '0x0' } }
$historical = Get-ForwardAnalysis (New-TestCapture @($legacy))
Assert-Forward ($historical.candidates[0].probe_rva -eq 'unknown_point') 'missing event.rva in historical preset cannot be inferred'
Assert-Forward ($historical.candidates[0].evidence -eq 'baseline_missing') 'legacy summary cannot claim C-only'
Assert-Forward ($historical.groups[0].caller_function_rva -eq $null) 'legacy return not promoted to valid caller'
$oldEvent = [pscustomobject]@{ rva = '0x1677F10'; ret_rva = '0x216272B'; rcx = '0x123'; r9 = '0x0' }
$oldEvents = [pscustomobject]@{ scenario = 'C_forward'; events = @($oldEvent); armed = $true; traps = 1 }
$oldResult = Get-ForwardAnalysis (New-TestCapture @($oldEvents))
Assert-Forward ($oldResult.groups[0].probe_function_rva -eq '0x1677F10') 'destructor point must not be attributed to send_message'
Assert-Forward ($oldResult.groups[0].samples[0].registers.r9 -eq $null) 'historical zero R9 is invalid'
Assert-Forward ($oldResult.groups[0].samples[0].stack_kind -eq 'raw_stack_scan_not_unwind') 'raw stack scan is not unwind'
$instruction = New-TestEvent; $instruction.capture_site = 'instruction'; $instruction.ret_valid = $false
$instructionCapture = New-TestCapture @((New-TestScenario 'A_text'),(New-TestScenario 'B_card'),(New-TestScenario 'C_forward' @($instruction)))
$instructionAnalysis = Get-ForwardAnalysis $instructionCapture
Assert-Forward ($instructionAnalysis.groups[0].caller_function_rva -eq $null -and $instructionAnalysis.candidates[0].evidence -eq 'return_or_normalization_missing') 'instruction stack top cannot establish caller'
$invalidReturn = New-TestEvent; $invalidReturn.ret_valid = $false
$invalidAnalysis = Get-ForwardAnalysis (New-TestCapture @((New-TestScenario 'C_forward' @($invalidReturn))))
Assert-Forward ($invalidAnalysis.groups[0].caller_function_rva -eq $null) 'entry with invalid return cannot establish caller'
$unresolvedCapture = [pscustomobject]@{ scenarios = @((New-TestScenario 'C_forward' @((New-TestEvent)))) }
$resolveFailure = Get-ForwardAnalysis -Capture $unresolvedCapture -Resolve { throw 'fixture symbol failure' }
Assert-Forward ($resolveFailure.groups[0].samples[0].normalization_error -like '*fixture symbol failure*') 'symbol error is explicit'

# Actual collector code with injected in-memory responses, including finally cleanup.
$mock = New-MockTransport
$zero = Invoke-MockScenario $mock
Assert-Forward ($zero.capture_status -eq 'success' -and $zero.hit_count -eq 0 -and $zero.trace_complete) 'zero hits are distinct from collection failure'
Assert-Forward ($mock.state.disarms -eq 2) 'single-point /arm uses final disarm'
Assert-Forward ($zero.arm_status -eq 'success' -and $zero.armed_detail.Count -eq 1) 'single-point arm reply without armed array supported'
Assert-Forward ($zero.window_started_at -and $zero.window_ended_at -and $null -ne $zero.actual_window_ms) 'window metadata preserved'
Assert-Forward ($mock.state.calls[-2] -eq 'POST /wxcx/probe/disarm' -and $mock.state.calls[-1] -like 'GET /wxcx/probe/trace*') 'final drain occurs after disarm'
$mock = New-MockTransport -Events @((New-TestEvent))
$record = Invoke-MockScenario $mock 'C_forward'
Assert-Forward ($record.trace_batches[0].raw_json -ceq $mock.trace_raw) 'entire original trace JSON retained verbatim'
Assert-Forward ($record.requests.Count -eq 5 -and $record.events[0].dump_hex -eq 'AABBCCDD') 'all requests and original event evidence retained'
$batchResult = Get-ForwardAnalysis (New-TestCapture @($record))
Assert-Forward ($batchResult.groups[0].samples[0].batch_index -eq 0) 'analysis sample links to original trace batch'
$envelopeOnly = ConvertFrom-ForwardJson ($mock.trace_raw)
$envelopeOnly.events[0].PSObject.Properties.Remove('schema_version')
$envelopeOnly.events[0] | Add-Member -NotePropertyName registers_hex -NotePropertyValue @{ rcx = '0x20000000000001'; rdx = $null; r8 = '0x0'; r9 = '0xFFFFFFFFFFFFFFFF' }
$envelopeOnly.events[0].a1 = $null
$record.events = @($envelopeOnly.events)
$record.trace_batches[0].response = $envelopeOnly
$envelopeAnalysis = Get-ForwardAnalysis (New-TestCapture @($record))
Assert-Forward ($envelopeAnalysis.groups[0].caller_function_rva -eq '0x4000') 'actual v2 top-level schema enables entry attribution'
Assert-Forward ($envelopeAnalysis.groups[0].samples[0].registers.rcx -eq '0x20000000000001') 'registers_hex preferred without float conversion'
$record.events = @(ConvertFrom-ForwardJson $record.trace_batches[0].raw_json | ForEach-Object { $_.events })
$record.trace_batches[0].response = ConvertFrom-ForwardJson $record.trace_batches[0].raw_json
foreach ($mode in @('arm_throw','no_arm','trace_failure','malformed_trace','invalid_json','disarm_failure','reset_failure','preflight_failure')) {
    $mock = New-MockTransport -Mode $mode
    $failure = Invoke-MockScenario $mock
    Assert-Forward ($mock.state.disarms -eq 2) "finally disarm on $mode"
    Assert-Forward ($failure.capture_status -eq 'failed' -and $null -eq $failure.hit_count -and -not $failure.trace_complete -and $failure.errors.Count -gt 0) "explicit failure, not zero hits: $mode"
}
$mock = New-MockTransport
$waitFailure = Invoke-ForwardScenario -Scenario 'A_text' -Seconds 1 -ProbeRva '0x1000' -Request $mock.request -Wait { throw 'fixture interrupted wait' }
Assert-Forward ($mock.state.disarms -eq 2 -and $waitFailure.errors[0].stage -eq 'collect') 'interrupted collection still disarms'
$mock = New-MockTransport -Events @((New-TestEvent))
$waitState = @{ count = 0 }
$interruptAfterRead = { param($ms) $waitState.count++; if ($waitState.count -gt 1) { throw 'fixture later interruption' } }.GetNewClosure()
$partialWindow = Invoke-ForwardScenario -Scenario 'A_text' -Seconds 1 -ProbeRva '0x1000' -Request $mock.request -Wait $interruptAfterRead
Assert-Forward ($partialWindow.capture_status -eq 'failed' -and $partialWindow.events.Count -ge 1 -and $partialWindow.trace_batches.Count -ge 1 -and $null -eq $partialWindow.hit_count) 'failure after successful read preserves earlier raw evidence'
Assert-Forward ($mock.state.disarms -eq 2) 'late collection failure still disarms'
$mock = New-MockTransport -Mode 'partial'
$partial = Invoke-MockScenario $mock 'B_card' 'fixture'
Assert-Forward ($partial.arm_status -eq 'partial' -and $partial.warnings.Count -gt 0) 'partially armed preset called out'
$partialCapture = New-TestCapture @((New-TestScenario 'A_text'),$partial,(New-TestScenario 'C_forward' @((New-TestEvent '0x2000'))))
$partialAnalysis = Get-ForwardAnalysis $partialCapture
Assert-Forward ($partialAnalysis.candidates[0].evidence -eq 'baseline_missing') 'failed preset point is not baseline coverage'
$mock = New-MockTransport -Dropped 1
$loss = Invoke-MockScenario $mock
Assert-Forward ($loss.capture_status -eq 'success' -and -not $loss.trace_complete -and $loss.warnings.Count) 'queue loss explicitly disables absence'
Assert-Forward ($null -eq $loss.hit_count) 'lossy empty response is not reported as zero total hits'
$loss.scenario = 'B_card'
$lossAnalysis = Get-ForwardAnalysis (New-TestCapture @((New-TestScenario 'A_text'),$loss,(New-TestScenario 'C_forward' @((New-TestEvent)))))
Assert-Forward ($lossAnalysis.candidates[0].evidence -eq 'baseline_missing') 'lossy zero-hit window cannot be negative baseline'
$loss.trace_complete = $true
$lossReanalysis = Get-ForwardAnalysis (New-TestCapture @((New-TestScenario 'A_text'),$loss,(New-TestScenario 'C_forward' @((New-TestEvent)))))
Assert-Forward ($lossReanalysis.candidates[0].evidence -eq 'baseline_missing') 'offline analysis rechecks loss metadata instead of trusting completeness flag'
$integrityScenario = [pscustomobject]@{
    trace_schema_version = 2; preflight = @{ published = '9007199254740993'; dropped = 7; reader_skipped_total = 3 }
    trace_batches = @(@{ endpoint = '/wxcx/probe/trace?limit=20'; response = @{ schema_version = 2; published = '9007199254740995'; dropped = 7; reader_skipped_total = 3; busy = $false; skipped = 0; events = @(@{seq = '9007199254740994'}, @{seq = '9007199254740995'}) } })
}
Assert-Forward ((Get-ForwardTraceIntegrity $integrityScenario).complete) 'sequence arithmetic above 2^53 and unchanged cumulative loss are exact'
$integrityScenario.trace_batches[0].response.events = @(@{seq = '9007199254740995'})
Assert-Forward (-not (Get-ForwardTraceIntegrity $integrityScenario).complete) 'sequence gap disables absence evidence'
$integrityScenario.trace_batches[0].response.events = @()
Assert-Forward (-not (Get-ForwardTraceIntegrity $integrityScenario).complete) 'another reader consumption cannot masquerade as zero hits'
$integrityScenario.trace_batches[0].response.published = '9007199254740993'
$integrityScenario.trace_batches[0].response.busy = $true
Assert-Forward (-not (Get-ForwardTraceIntegrity $integrityScenario).complete) 'busy empty trace is not a zero-hit window'
$integrityScenario.trace_batches[0].response.busy = $false
$integrityScenario.trace_batches[0].response.skipped = 1
Assert-Forward (-not (Get-ForwardTraceIntegrity $integrityScenario).complete) 'reader skipped metadata invalidates baseline'
$integrityScenario.trace_batches[0].response.skipped = 0
$integrityScenario.trace_batches[0].response.reader_skipped_total = 4
Assert-Forward (-not (Get-ForwardTraceIntegrity $integrityScenario).complete) 'cumulative reader loss changed during window'
$integrityScenario.preflight.published = 10
$integrityScenario.preflight.dropped = 0
$integrityScenario.preflight.reader_skipped_total = 0
$integrityScenario.trace_batches = @(
    @{ endpoint = '/wxcx/probe/trace?limit=20'; response = @{ schema_version = 2; published = 11; dropped = 0; skipped = 0; reader_skipped_total = 0; events = @(@{seq = 11}) } },
    @{ endpoint = '/wxcx/probe/trace?limit=20'; response = @{ schema_version = 2; published = 12; dropped = 0; skipped = 0; reader_skipped_total = 0; events = @(@{seq = 12}) } })
Assert-Forward ((Get-ForwardTraceIntegrity $integrityScenario).complete) 'consecutive sequences across multiple batches accepted'
$integrityScenario.trace_batches[1].response.events[0].seq = 14
$integrityScenario.trace_batches[1].response.published = 14
Assert-Forward (-not (Get-ForwardTraceIntegrity $integrityScenario).complete) 'sequence gap between separate batches rejected'
$unknownBaseline = New-TestScenario 'B_card' @([pscustomobject]@{ ret_rva = '0x4010' })
$unknownAnalysis = Get-ForwardAnalysis (New-TestCapture @((New-TestScenario 'A_text'),$unknownBaseline,(New-TestScenario 'C_forward' @((New-TestEvent)))))
Assert-Forward ($unknownAnalysis.candidates[0].evidence -eq 'baseline_missing') 'baseline event without actual RVA cannot establish point absence'
$sameCallerOtherPoint = New-TestScenario 'B_card' @((New-TestEvent '0x2000' '0x4010'))
$pointIsolation = Get-ForwardAnalysis (New-TestCapture @((New-TestScenario 'A_text'),$sameCallerOtherPoint,(New-TestScenario 'C_forward' @((New-TestEvent '0x1000' '0x4010')))))
Assert-Forward ($pointIsolation.candidates[0].evidence -eq 'only-in-C') 'same caller on another probe does not erase actual point identity'
$saturatedEvents = @(1..20 | ForEach-Object { New-TestEvent })
$mock = New-MockTransport -Events $saturatedEvents
$saturated = Invoke-MockScenario $mock
Assert-Forward ($saturated.events.Count -eq 20 -and -not $saturated.trace_complete) 'saturated consumer response preserved and marked incomplete'
$mock = New-MockTransport -Mode 'legacy' -Events @([pscustomobject]@{ rva = 4096; ret = '9007199254757393'; a4 = 0; stack_hex = '0102'; dump_hex = '0304'; follow_hex = '0506' })
$legacyRecord = Invoke-MockScenario $mock 'C_forward'
Assert-Forward ($mock.state.calls[-1] -eq 'GET /wxcx/probe/events?limit=32' -and $legacyRecord.events[0].stack_hex -eq '0102') 'legacy raw-byte fallback consumes only /events during window'
$legacyDerived = Get-ForwardAnalysis (New-TestCapture @($legacyRecord))
Assert-Forward ($legacyDerived.groups[0].ret_rva -eq '0x4010' -and $legacyDerived.groups[0].samples[0].registers.r9 -eq $null) 'legacy image-base arithmetic exact above 2^53; R9 remains null'

# Export/reimport is part of the offline contract. Only a unique temporary directory is used.
$tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$testDir = Join-Path $tempRoot ('forward-offline-test-' + [Guid]::NewGuid().ToString('N'))
try {
    $paths = Write-ForwardReport -Capture $capture -Analysis $multi -OutputDirectory $testDir
    $roundtrip = ConvertFrom-ForwardJson (Get-Content -LiteralPath $paths.capture -Raw -Encoding UTF8)
    $reanalysis = Get-ForwardAnalysis $roundtrip
    Assert-Forward ($reanalysis.candidates.Count -eq 4) 'saved capture reanalyzed entirely offline'
    $markdown = Get-Content -LiteralPath $paths.report -Raw -Encoding UTF8
    Assert-Forward ($markdown -match 'ret_is_entry' -and $markdown -match 'not performed' -and $markdown -match 'raw_stack_scan_not_unwind') 'report semantics explicit'
    $rawPaths = Write-ForwardReport -Capture (New-TestCapture @($record)) -Analysis $batchResult -OutputDirectory $testDir
    $rawRoundtrip = ConvertFrom-ForwardJson (Get-Content -LiteralPath $rawPaths.capture -Raw -Encoding UTF8)
    Assert-Forward ($rawRoundtrip.scenarios[0].trace_batches[0].raw_json -ceq $record.trace_batches[0].raw_json) 'raw original JSON survives file serialization'
    & (Join-Path $PSScriptRoot 'oneclick_forward.ps1') -CapturePath $paths.capture -OutputDirectory $testDir | Out-Null
    Assert-Forward (@(Get-ChildItem -LiteralPath $testDir -Filter 'forward-analysis-*.md').Count -ge 3) 'offline command entry point produces reports without config/network'
} finally {
    $resolvedTestDir = [IO.Path]::GetFullPath($testDir)
    if (-not $resolvedTestDir.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase) -or (Split-Path -Leaf $resolvedTestDir) -notlike 'forward-offline-test-*') { throw 'Unsafe test cleanup path.' }
    if (Test-Path -LiteralPath $resolvedTestDir) { Remove-Item -LiteralPath $resolvedTestDir -Recurse -Force }
}
Write-Host ("PASS: {0} offline assertions; no WeChat, network, IDA, REA or credentials used." -f $script:ForwardTestCount)
