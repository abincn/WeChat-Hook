[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'forward-analysis-common.ps1')
$script:checks = 0
function Check($value, [string]$label) {
    $script:checks++
    if (-not $value) { throw ('FAIL: ' + $label) }
}
$plan = ConvertFrom-ForwardJson (Get-Content -LiteralPath (Join-Path $PSScriptRoot 'forward-source-plan.json') -Raw -Encoding UTF8)
$internalPlanPath = Join-Path $PSScriptRoot 'forward-internal-plan.json'
$internalPlanRaw = [IO.File]::ReadAllText($internalPlanPath, [Text.Encoding]::UTF8)
$internalPlan = ConvertFrom-ForwardJson $internalPlanRaw
$internalPoints = ConvertTo-ForwardProbePlan $internalPlan
Check ($internalPoints.Count -eq 4 -and $internalPoints[0].rva -eq '0x2161FC0' -and $internalPoints[2].rva -eq '0x3689B10') 'common source entry and request-wrapper points validated'
Check ($internalPoints[0].dump_reg -eq 3 -and $internalPoints[2].follow_off -eq 0 -and $internalPoints[2].follow_len -eq 256) 'internal plan captures source and descriptor within schema limits'
$state = @{ calls = @(); fail = ''; raised = '' }
$transport = {
    param($method, $endpoint, $body)
    $state.calls += [pscustomobject]@{ method=$method; endpoint=$endpoint; body=$body }
    if ($endpoint -eq '/wxcx/probe/arm') {
        $p = ConvertFrom-ForwardJson $body
        if ($p.rva -eq $state.raised) { throw 'synthetic transport error' }
        return [pscustomobject]@{ raw_json=(@{ ok=($p.rva -ne $state.fail); rva=$p.rva } | ConvertTo-Json -Compress) }
    }
    if ($endpoint -eq '/wxcx/probe/disarm') { return [pscustomobject]@{raw_json='{"ok":true}'} }
    if ($endpoint -like '/wxcx/probe/trace*') {
        return [pscustomobject]@{raw_json='{"schema_version":2,"events":[],"image_base":6442450944,"image_size":183558144,"count":0,"busy":false,"dropped":0,"skipped":0,"reader_skipped_total":0,"published":0}'}
    }
    throw ('unexpected endpoint ' + $endpoint)
}

$result = ConvertFrom-ForwardJson (Invoke-ForwardArmPlan -Plan $plan -WindowMs 40000 -Request $transport).raw_json
Check ($result.armed.Count -eq 4 -and @($result.armed | Where-Object {-not $_.ok}).Count -eq 0) 'four actual arm confirmations'
Check ($state.calls.Count -eq 4 -and @($state.calls | Where-Object {$_.endpoint -ne '/wxcx/probe/arm'}).Count -eq 0) 'no presets/config write or native call'
$first = ConvertFrom-ForwardJson $state.calls[0].body
Check ($first.rva -eq '0x2161FC0' -and $first.dump_reg -eq 3 -and $first.dump -eq 256) 'source DTO selected in r8'
Check ($first.str_reg -eq 3 -and $first.str_off -eq 16 -and $first.ms -eq 40000) 'string and window preserved'
$second = ConvertFrom-ForwardJson $state.calls[1].body
Check ($second.follow_off -eq 0 -and $second.follow2_off -eq 0) 'both zero offsets preserved'
Check ($result.armed[0].request_json -ceq $state.calls[0].body -and $result.armed[0].response_raw_json) 'actual requests and responses retained'

$state.calls = @(); $state.fail = '0x43ACC80'
$partial = ConvertFrom-ForwardJson (Invoke-ForwardArmPlan -Plan $plan -WindowMs 10000 -Request $transport).raw_json
Check (@($partial.armed | Where-Object {$_.ok}).Count -eq 3 -and $partial.armed[1].error) 'partial arm failure explicit'
$state.fail = ''; $state.raised = '0x1649E60' # not present: then fail an actual configured point
$state.raised = '0x1679340'
$partial = ConvertFrom-ForwardJson (Invoke-ForwardArmPlan -Plan $plan -WindowMs 10000 -Request $transport).raw_json
Check (-not $partial.armed[2].ok -and $partial.armed[2].error -like '*synthetic*') 'transport failure recorded per point'
$state.raised = ''

foreach ($bad in @(
    @{points=@()},
    @{points=@(@{rva='0x10'},@{rva='0X10'})},
    @{points=@(@{rva='0x10'; dump=257})},
    @{points=@(@{rva='0x10'; dump_reg=0})},
    @{points=@(@{rva='0x10'; dump_reg=1.0})},
    @{points=@(@{rva='0x10'; follow_off=-1})},
    @{points=@(@{rva='0x0'})},
    @{points=@(@{rva='0x10'; str_reg=7})},
    @{points=@(@{rva='0x10'; str_max=$true})}
)) {
    $state.calls = @(); $failed = $false
    try { $null = Invoke-ForwardArmPlan -Plan $bad -WindowMs 10000 -Request $transport } catch { $failed = $true }
    Check ($failed -and $state.calls.Count -eq 0) 'invalid complete plan rejected before effects'
}

$state.calls = @()
$wrapper = {
    param($method,$endpoint,$body)
    if ($endpoint -eq '/wxcx/probe/preset') {
        $opts = ConvertFrom-ForwardJson $body
        return Invoke-ForwardArmPlan -Plan $plan -WindowMs ([int]$opts.ms) -Request $transport
    }
    & $transport $method $endpoint $body
}
$scenario = Invoke-ForwardScenario -Scenario C_forward -Title test -Seconds 0 -Preset inline_plan -Request $wrapper
Check ($scenario.capture_status -eq 'success' -and $scenario.arm_status -eq 'success') 'integrated real collector with injected transport'
Check ($scenario.armed_detail.Count -eq 4 -and $scenario.trace_complete) 'coverage and integrity preserved'
Check ($state.calls[0].endpoint -eq '/wxcx/probe/disarm' -and $state.calls[-2].endpoint -eq '/wxcx/probe/disarm') 'disarm before and after observation'
Write-Host ("PASS: {0} inline-plan checks; no network or WeChat runtime" -f $script:checks)
