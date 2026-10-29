# Offline analysis and injectable collector. Import has no configuration/network side effects.
function ConvertTo-ForwardProbePlan {
    param([Parameter(Mandatory)]$Plan)
    $points = @(Get-ForwardField $Plan 'points' @())
    if ($points.Count -lt 1 -or $points.Count -gt 4) { throw 'Probe plan must contain 1..4 points.' }
    $limits = @{
        dump = @(0,256); dump_reg = @(1,4); follow_off = @(0,1048576)
        follow_read_offset = @(0,1048576)
        follow2_off = @(0,1048576); follow_len = @(0,256)
        str_reg = @(0,6); str_off = @(0,1048576); str_max = @(0,256)
    }
    $result = @(); $seen = @{}
    foreach ($point in $points) {
        $rva = ConvertTo-ForwardAddress (Get-ForwardField $point 'rva')
        if (-not $rva -or $rva -eq '0x0' -or $seen.ContainsKey($rva)) { throw 'Plan RVA must be nonzero and unique.' }
        $seen[$rva] = $true
        $out = [ordered]@{ rva = $rva }
        foreach ($field in $limits.Keys) {
            if (-not (Test-ForwardField $point $field)) { continue }
            $value = Get-ForwardField $point $field
            if ($null -eq $value -or $value -is [double] -or $value -is [single] -or $value -is [bool] -or [string]$value -notmatch '^[0-9]+$') {
                throw ("Plan {0} must be an integer." -f $field)
            }
            $number = [UInt64]::Parse([string]$value, [Globalization.CultureInfo]::InvariantCulture)
            if ($number -lt $limits[$field][0] -or $number -gt $limits[$field][1]) { throw ("Plan {0} out of range." -f $field) }
            $out[$field] = [uint32]$number
        }
        $result += [pscustomobject]$out
    }
    return ,$result
}

function Invoke-ForwardArmPlan {
    param([Parameter(Mandatory)]$Plan, [ValidateRange(1,3600000)][int]$WindowMs,
          [Parameter(Mandatory)][scriptblock]$Request)
    # Validate the entire plan before the first effectful request.
    $points = ConvertTo-ForwardProbePlan $Plan
    $armed = @()
    foreach ($point in $points) {
        $payload = [ordered]@{ ms = $WindowMs }
        foreach ($property in $point.PSObject.Properties) { $payload[$property.Name] = $property.Value }
        $rawRequest = $payload | ConvertTo-Json -Compress
        $item = [ordered]@{ rva = $point.rva; ok = $false; request_json = $rawRequest; response_raw_json = $null }
        try {
            $response = & $Request 'POST' '/wxcx/probe/arm' $rawRequest
            $item.response_raw_json = $response.raw_json
            $data = ConvertFrom-ForwardJson $response.raw_json
            $returned = ConvertTo-ForwardAddress (Get-ForwardField $data 'rva')
            $item.ok = (Get-ForwardField $data 'ok') -eq $true -and $returned -eq $point.rva
            if (Test-ForwardField $point 'follow_read_offset') {
                $returnedOffset = Get-ForwardField $data 'follow_read_offset'
                $item.ok = $item.ok -and $null -ne $returnedOffset -and
                    [uint64]$returnedOffset -eq [uint64]$point.follow_read_offset
            }
            if (-not $item.ok) { $item.error = 'Probe arm not confirmed for the requested RVA.' }
        } catch { $item.error = $_.Exception.Message }
        $armed += [pscustomobject]$item
    }
    [pscustomobject]@{ raw_json = ([ordered]@{ source = 'inline_plan'; name = Get-ForwardField $Plan 'name' 'inline_plan'; armed = $armed } | ConvertTo-Json -Depth 15 -Compress) }
}

function Get-ForwardField {
    param($Object, [string]$Name, $Default = $null)
    if ($null -eq $Object) { return $Default }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return $Object[$Name] }
    } elseif ($null -ne $Object.PSObject.Properties[$Name]) { return $Object.$Name }
    return $Default
}
function Test-ForwardField {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $false }
    if ($Object -is [System.Collections.IDictionary]) { return $Object.Contains($Name) }
    return $null -ne $Object.PSObject.Properties[$Name]
}
function ConvertFrom-ForwardJson {
    param([Parameter(Mandatory)][string]$Json)
    # Protect large integer tokens before parsing (also on Windows PowerShell 5.1).
    # JSON strings are matched first and never rewritten. Save original text separately.
    $pattern = '"(?:\\.|[^"\\])*"|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?'
    $safe = [regex]::Replace($Json, $pattern, [System.Text.RegularExpressions.MatchEvaluator]{
        param($m)
        $s = $m.Value
        if ($s[0] -ne '"' -and $s -notmatch '[.eE]' -and $s.TrimStart('-').Length -ge 16) { return '"' + $s + '"' }
        return $s
    })
    ConvertFrom-Json -InputObject $safe -ErrorAction Stop
}
function ConvertTo-ForwardAddress {
    param($Value)
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    if ($Value -is [double] -or $Value -is [single]) {
        if ([double]$Value -gt 9007199254740991 -or [double]$Value -lt 0 -or [math]::Truncate([double]$Value) -ne [double]$Value) {
            throw 'Imprecise floating point address; supply original JSON, decimal integer text, or hex text.'
        }
    }
    $s = ([string]$Value).Trim()
    if ($s -match '^0[xX]([0-9a-fA-F]+)$') {
        $n = [UInt64]::Parse($Matches[1], [Globalization.NumberStyles]::AllowHexSpecifier, [Globalization.CultureInfo]::InvariantCulture)
    } else { $n = [UInt64]::Parse($s, [Globalization.CultureInfo]::InvariantCulture) }
    return ('0x{0:X}' -f $n)
}
function Get-ForwardEventAddress {
    param($Event, [string]$Name, $Warnings)
    try { ConvertTo-ForwardAddress (Get-ForwardField $Event $Name) }
    catch { [void]$Warnings.Add(("Invalid {0}: {1}" -f $Name, $_.Exception.Message)); return $null }
}
function Get-ForwardArmedPoints {
    param($Arm)
    $list = Get-ForwardField $Arm 'armed'
    if ($null -ne $list -and $list -isnot [bool]) { return @($list) }
    if ($null -ne (Get-ForwardField $Arm 'rva')) { return @($Arm) }
    return @()
}

function Get-ForwardTraceIntegrity {
    param($Scenario)
    $complete = $true; $messages = @()
    $preflight = Get-ForwardField $Scenario 'preflight'
    $schema = [int](Get-ForwardField $Scenario 'trace_schema_version' 0)
    $previous = Get-ForwardField $preflight 'published'
    $batches = @(Get-ForwardField $Scenario 'trace_batches' @())
    if ($schema -ge 2 -and $batches.Count -and $null -eq $previous) {
        $complete = $false; $messages += 'Preflight published sequence missing: consumer coverage cannot be established.'
    }
    foreach ($batch in $batches) {
        $response = $batch.response
        $events = @($response.events)
        $limit = if ($batch.endpoint -like '*events*') { 32 } else { 20 }
        if ($events.Count -ge $limit) {
            $complete = $false; $messages += 'Trace page saturated: consuming API may have skipped older records.'
        }
        foreach ($container in @($response, (Get-ForwardField $response 'queue'))) {
            foreach ($key in @('skipped','busy')) {
                $value = Get-ForwardField $container $key
                if ($null -ne $value -and [decimal]$value -gt 0) {
                    $complete = $false; $messages += ("Queue {0}={1}; absence evidence disabled." -f $key, $value)
                }
            }
            foreach ($key in @('dropped','ring_dropped','reader_skipped_total')) {
                $value = Get-ForwardField $container $key
                $start = Get-ForwardField $preflight $key
                if ($null -ne $value -and (($null -eq $start -and [decimal]$value -gt 0) -or ($null -ne $start -and [decimal]$value -ne [decimal]$start))) {
                    $complete = $false; $messages += ("Queue {0} changed/unknown during window; absence evidence disabled." -f $key)
                }
            }
        }
        if ([int](Get-ForwardField $response 'schema_version' $schema) -ge 2) {
            foreach ($e in $events) {
                $seq = Get-ForwardField $e 'seq'
                if ($null -eq $seq -or $null -eq $previous -or ([decimal]$seq - [decimal]$previous) -ne 1) {
                    $complete = $false; $messages += 'Missing/nonconsecutive event sequence: possible loss or another consuming reader.'
                }
                $previous = $seq
            }
            $published = Get-ForwardField $response 'published'
            if ($null -eq $published -or $null -eq $previous -or [decimal]$published -ne [decimal]$previous) {
                $complete = $false; $messages += 'Published sequence not fully observed: empty response cannot establish zero hits.'
            }
            $previous = $published
        }
    }
    [pscustomobject]@{ complete = $complete; warnings = @($messages | Select-Object -Unique) }
}

function Invoke-ForwardScenario {
    [CmdletBinding()]
    param(
        [string]$Scenario, [string]$Title, [ValidateRange(0,3590)][int]$Seconds,
        [string]$ProbeRva, [string]$Preset, [Parameter(Mandatory)][scriptblock]$Request,
        [ValidateRange(1,5000)][int]$PollMilliseconds = 500,
        [scriptblock]$Wait = { param($ms) Start-Sleep -Milliseconds $ms }
    )
    $rec = [ordered]@{
        scenario = $Scenario; scenario_cn = $Title; capture_status = 'failed'; arm_status = 'unknown'
        probe_rva = $(if ($Preset) { 'preset:' + $Preset } else { $ProbeRva })
        requested_seconds = $Seconds; poll_ms = $PollMilliseconds
        started_at = [DateTimeOffset]::UtcNow.ToString('o'); window_started_at = $null; window_ended_at = $null
        ended_at = $null; actual_window_ms = $null; trace_complete = $false; armed_detail = @()
        events = @(); trace_batches = @(); requests = @(); errors = @(); warnings = @()
        image_base = $null; image_size = $null; trace_schema_version = $null; preflight = $null
        stack_kind = 'raw_stack_scan_not_unwind'; register_scope = 'probe_site'; hit_count = $null
    }
    $stage = 'reset'; $armAttempted = $false; $watch = $null
    $endpoint = '/wxcx/probe/trace?limit=20'
    $send = {
        param($method, $path, $body)
        $entry = [ordered]@{ method = $method; endpoint = $path; started_at = [DateTimeOffset]::UtcNow.ToString('o'); ended_at = $null; ok = $false; raw_json = $null }
        try {
            $response = & $Request $method $path $body
            $entry.raw_json = $response.raw_json
            $data = ConvertFrom-ForwardJson $response.raw_json
            $entry.ok = $true
            return $data
        } finally {
            $entry.ended_at = [DateTimeOffset]::UtcNow.ToString('o')
            $rec.requests += [pscustomobject]$entry
        }
    }
    $read = {
        $batch = & $send 'GET' $endpoint $null
        if (-not (Test-ForwardField $batch 'events') -or $batch.events -isnot [array]) { throw 'Trace response has no events array.' }
        if ((Get-ForwardField $batch 'ok') -eq $false) { throw 'Trace response reports ok=false.' }
        $rec.trace_batches += [pscustomobject]@{
            endpoint = $endpoint; received_at = [DateTimeOffset]::UtcNow.ToString('o')
            response = $batch; raw_json = $rec.requests[-1].raw_json
        }
        $rec.events += @($batch.events)
        return $batch
    }
    try {
        $reset = & $send 'POST' '/wxcx/probe/disarm' '{}'
        if ((Get-ForwardField $reset 'ok') -ne $true) { throw 'Initial disarm did not confirm success.' }
        $stage = 'preflight'
        # Flush stale records while disarmed; preserve as requests, not current-window events.
        $preflight = & $send 'GET' '/wxcx/probe/trace?limit=20' $null
        if (-not (Test-ForwardField $preflight 'events') -or $preflight.events -isnot [array]) { throw 'Preflight trace has no events array.' }
        $rec.preflight = $preflight
        if ((Get-ForwardField $preflight 'busy') -eq $true -or (Get-ForwardField $preflight 'ok') -eq $false) { throw 'Preflight queue could not be drained safely.' }
        $rec.image_base = Get-ForwardField $preflight 'image_base'
        $rec.image_size = Get-ForwardField $preflight 'image_size'
        $rec.trace_schema_version = Get-ForwardField $preflight 'schema_version'
        if ([int]$rec.trace_schema_version -lt 2) {
            $endpoint = '/wxcx/probe/events?limit=32'
            $rec.warnings += 'Legacy service: collecting /events for raw stack/dump bytes; return validity and R9 are unknown.'
        }
        $stage = 'arm'
        $body = @{ ms = ($Seconds * 1000 + 10000) }
        if ($Preset) { $path = '/wxcx/probe/preset'; $body.name = $Preset }
        else { $path = '/wxcx/probe/arm'; $body.rva = $ProbeRva; $body.dump = 64 }
        $rec.window_started_at = [DateTimeOffset]::UtcNow.ToString('o')
        $watch = [Diagnostics.Stopwatch]::StartNew()
        $armAttempted = $true
        $arm = & $send 'POST' $path ($body | ConvertTo-Json -Compress)
        $rec.armed_detail = @(Get-ForwardArmedPoints $arm)
        $okPoints = @($rec.armed_detail | Where-Object { (Get-ForwardField $_ 'ok') -eq $true })
        if (-not $okPoints.Count) { $rec.arm_status = 'failed'; throw 'No probe point confirmed armed.' }
        $rec.arm_status = if ($okPoints.Count -eq $rec.armed_detail.Count) { 'success' } else { 'partial' }
        if ($rec.arm_status -eq 'partial') { $rec.warnings += 'Preset only partially armed: failed points have no baseline coverage.' }
        Write-Host ("【开始采集】点位已就绪，计时 {0} 秒。现在执行上方提示的一次操作。" -f $Seconds)
        $stage = 'collect'
        while ($watch.Elapsed.TotalSeconds -lt $Seconds) {
            & $Wait ([int][math]::Min($PollMilliseconds, [math]::Max(1, ($Seconds * 1000 - $watch.ElapsedMilliseconds))))
            $null = & $read
        }
    } catch { $rec.errors += [pscustomobject]@{ stage = $stage; message = $_.Exception.Message } }
    finally {
        # Even an arm HTTP failure may have armed probes on the server.
        try {
            $disarm = & $send 'POST' '/wxcx/probe/disarm' '{}'
            if ((Get-ForwardField $disarm 'ok') -ne $true) { throw 'Final disarm did not confirm success.' }
        } catch { $rec.errors += [pscustomobject]@{ stage = 'disarm'; message = $_.Exception.Message } }
        $rec.window_ended_at = [DateTimeOffset]::UtcNow.ToString('o')
        if ($watch) { $watch.Stop(); $rec.actual_window_ms = $watch.ElapsedMilliseconds }
        if ($armAttempted) {
            try { $null = & $read }
            catch { $rec.errors += [pscustomobject]@{ stage = 'final_trace'; message = $_.Exception.Message } }
        }
        $rec.ended_at = [DateTimeOffset]::UtcNow.ToString('o')
    }
    try { $integrity = Get-ForwardTraceIntegrity $rec; $rec.warnings += $integrity.warnings }
    catch { $rec.errors += [pscustomobject]@{ stage = 'queue_metadata'; message = $_.Exception.Message } }
    if (-not $rec.errors.Count) {
        $rec.capture_status = 'success'; $rec.trace_complete = $integrity.complete
        if ($integrity.complete) { $rec.hit_count = $rec.events.Count }
    }
    return [pscustomobject]$rec
}

function Get-ForwardAnalysis {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Capture, [scriptblock]$Resolve)
    $warnings = New-Object 'System.Collections.Generic.List[string]'
    $symbols = @{}
    $savedSymbols = Get-ForwardField $Capture 'symbols'
    if ($savedSymbols) {
        if ($savedSymbols -is [System.Collections.IDictionary]) { foreach ($key in $savedSymbols.Keys) { $symbols[$key] = $savedSymbols[$key] } }
        else { foreach ($p in $savedSymbols.PSObject.Properties) { $symbols[$p.Name] = $p.Value } }
    }
    $lookup = {
        param($rva)
        if (-not $rva -or $rva -eq '0x0') { return $null }
        if (-not $symbols.ContainsKey($rva)) {
            try {
                if ($Resolve) { $symbols[$rva] = & $Resolve $rva }
                else { $symbols[$rva] = [pscustomobject]@{ ok = $false; error = 'offline_symbol_missing' } }
            } catch { $symbols[$rva] = [pscustomobject]@{ ok = $false; error = $_.Exception.Message } }
        }
        return $symbols[$rva]
    }
    $scenarios = @(); $groups = @(); $samples = @()
    foreach ($s in @(Get-ForwardField $Capture 'scenarios' @())) {
        $id = [string](Get-ForwardField $s 'scenario')
        $armDetail = @(Get-ForwardField $s 'armed_detail' @())
        $covered = @($armDetail | Where-Object { (Get-ForwardField $_ 'ok') -eq $true } | ForEach-Object {
            Get-ForwardEventAddress $_ 'rva' $warnings
        } | Where-Object { $_ } | Select-Object -Unique)
        $status = Get-ForwardField $s 'capture_status' 'unknown_legacy'
        $complete = (Get-ForwardField $s 'trace_complete') -eq $true
        try {
            $integrity = Get-ForwardTraceIntegrity $s
            $complete = $complete -and $integrity.complete
            foreach ($message in $integrity.warnings) { [void]$warnings.Add(("{0}: {1}" -f $id, $message)) }
        } catch { $complete = $false; [void]$warnings.Add(("{0}: invalid queue metadata: {1}" -f $id, $_.Exception.Message)) }
        $scenarios += [pscustomobject]@{
            scenario = $id; capture_status = $status; trace_complete = $complete; covered_points = $covered
            arm_status = Get-ForwardField $s 'arm_status' 'unknown_legacy'
            trace_schema_version = Get-ForwardField $s 'trace_schema_version' 0
            received_events = @(Get-ForwardField $s 'events' @()).Count
            hit_count = Get-ForwardField $s 'hit_count'; errors = @(Get-ForwardField $s 'errors' @())
        }
        $items = @(Get-ForwardField $s 'events' @())
        if (-not $items.Count -and (Get-ForwardField $s 'ret_rva')) {
            $items = @([pscustomobject]@{ ret_rva = $s.ret_rva; legacy_summary_only = $true })
        }
        $index = 0
        foreach ($e in $items) {
            $point = Get-ForwardEventAddress $e 'rva' $warnings
            if (-not $point -or $point -eq '0x0') { $point = 'unknown_point' }
            $schema = Get-ForwardField $e 'schema_version' (Get-ForwardField $s 'trace_schema_version' 0)
            $site = Get-ForwardField $e 'capture_site'; $retValid = Get-ForwardField $e 'ret_valid'
            $batchIndex = $null; $batches = @(Get-ForwardField $s 'trace_batches' @()); $offset = 0
            for ($b = 0; $b -lt $batches.Count; $b++) {
                $response = Get-ForwardField $batches[$b] 'response'
                $count = @(Get-ForwardField $response 'events' @()).Count
                if ($index -ge $offset -and $index -lt ($offset + $count)) {
                    $batchIndex = $b
                    $schema = Get-ForwardField $e 'schema_version' (Get-ForwardField $response 'schema_version' $schema)
                    $site = Get-ForwardField $e 'capture_site' (Get-ForwardField $response 'capture_site' $site)
                    $retValid = Get-ForwardField $e 'ret_valid' (Get-ForwardField $response 'ret_valid' $retValid)
                    break
                }
                $offset += $count
            }
            $ret = Get-ForwardEventAddress $e 'ret_rva' $warnings
            if (-not $ret -or $ret -eq '0x0') {
                $ret = $null
                $baseHex = Get-ForwardEventAddress $s 'image_base' $warnings
                $sizeHex = Get-ForwardEventAddress $s 'image_size' $warnings
                $vaHex = Get-ForwardEventAddress $e 'ret' $warnings
                if ($baseHex -and $sizeHex -and $vaHex) {
                    $baseN = [UInt64]::Parse($baseHex.Substring(2), [Globalization.NumberStyles]::HexNumber)
                    $sizeN = [UInt64]::Parse($sizeHex.Substring(2), [Globalization.NumberStyles]::HexNumber)
                    $vaN = [UInt64]::Parse($vaHex.Substring(2), [Globalization.NumberStyles]::HexNumber)
                    if ($vaN -ge $baseN -and ([decimal]$vaN - [decimal]$baseN) -lt [decimal]$sizeN) {
                        $ret = ConvertTo-ForwardAddress ([UInt64]([decimal]$vaN - [decimal]$baseN))
                    }
                }
            }
            $valid = [int]$schema -ge 2 -and $site -eq 'function_entry' -and $retValid -eq $true
            $pSym = if ($point -ne 'unknown_point') { & $lookup $point } else { $null }
            $rSym = if ($ret) { & $lookup $ret } else { $null }
            $probeFunction = $null; $caller = $null; $retEntry = $null
            if ((Get-ForwardField $pSym 'ok') -eq $true) { $probeFunction = Get-ForwardEventAddress $pSym 'func_start' $warnings }
            if ((Get-ForwardField $rSym 'ok') -eq $true) {
                $retEntry = Get-ForwardField $rSym 'is_entry'
                if ($valid) { $caller = Get-ForwardEventAddress $rSym 'func_start' $warnings }
            }
            $registers = [ordered]@{}
            foreach ($pair in @(@('rcx','a1'), @('rdx','a2'), @('r8','a3'), @('r9','a4'))) {
                $value = Get-ForwardField $e $pair[1] (Get-ForwardField $e $pair[0])
                if ([int]$schema -ge 2) { $value = Get-ForwardField (Get-ForwardField $e 'registers_hex') $pair[0] $value }
                if ($pair[0] -eq 'r9' -and [int]$schema -lt 2) { $value = $null }
                try { $registers[$pair[0]] = ConvertTo-ForwardAddress $value }
                catch { $registers[$pair[0]] = $null; [void]$warnings.Add($_.Exception.Message) }
            }
            $samples += [pscustomobject]@{
                scenario = $id; event_index = $index; batch_index = $batchIndex; probe_rva = $point
                ret_rva = $ret; ret_valid = $(if ([int]$schema -ge 2) { $valid } else { $null })
                ret_is_entry = $retEntry; caller_function_rva = $caller
                observed_ret_function_rva = $(if ((Get-ForwardField $rSym 'ok') -eq $true) { Get-ForwardEventAddress $rSym 'func_start' $warnings } else { $null })
                probe_function_rva = $probeFunction; probe_is_entry = Get-ForwardField $pSym 'is_entry'
                capture_site = $(if ($site) { $site } else { 'unknown_legacy' })
                register_scope = 'probe_site'; registers = [pscustomobject]$registers
                stack_kind = 'raw_stack_scan_not_unwind'; raw_event = $e
                normalization_error = Get-ForwardField $rSym 'error'
            }
            $index++
        }
    }
    foreach ($set in @($samples | Group-Object -Property { '{0}|{1}|{2}' -f $_.scenario, $_.probe_rva, $_.ret_rva })) {
        $first = $set.Group[0]
        $callers = @($set.Group | ForEach-Object { $_.caller_function_rva } | Where-Object { $_ } | Select-Object -Unique)
        $groups += [pscustomobject]@{
            scenario = $first.scenario; probe_rva = $first.probe_rva; ret_rva = $first.ret_rva
            probe_function_rva = $first.probe_function_rva
            caller_function_rva = $(if ($callers.Count -eq 1 -and @($set.Group | Where-Object { -not $_.caller_function_rva }).Count -eq 0) { $callers[0] } else { $null })
            ret_is_entry = $first.ret_is_entry; count = $set.Count
            event_indexes = @($set.Group | ForEach-Object { $_.event_index }); samples = @($set.Group)
        }
    }
    $candidates = @()
    foreach ($g in @($groups | Where-Object { $_.scenario -eq 'C_forward' })) {
        $missing = @(); $shared = @(); $exact = @()
        foreach ($id in @('A_text','B_card')) {
            $baseline = @($scenarios | Where-Object { $_.scenario -eq $id })
            if ($baseline.Count -ne 1 -or $baseline[0].capture_status -ne 'success' -or -not $baseline[0].trace_complete -or [int]$baseline[0].trace_schema_version -lt 2 -or $baseline[0].covered_points -notcontains $g.probe_rva) { $missing += $id }
            if (@($groups | Where-Object { $_.scenario -eq $id -and ($_.probe_rva -eq 'unknown_point' -or ($_.probe_rva -eq $g.probe_rva -and -not $_.caller_function_rva)) }).Count -and $missing -notcontains $id) { $missing += $id }
            if (@($groups | Where-Object { $_.scenario -eq $id -and $_.probe_rva -eq $g.probe_rva -and $_.caller_function_rva -eq $g.caller_function_rva -and $_.caller_function_rva }).Count) { $shared += $id }
            if (@($groups | Where-Object { $_.scenario -eq $id -and $_.probe_rva -eq $g.probe_rva -and $_.ret_rva -eq $g.ret_rva }).Count) { $exact += $id }
        }
        $c = @($scenarios | Where-Object { $_.scenario -eq 'C_forward' })
        $evidence = 'only-in-C'
        if ($missing.Count) { $evidence = 'baseline_missing' }
        elseif ($g.probe_rva -eq 'unknown_point') { $evidence = 'unknown_point' }
        elseif ($c.Count -ne 1 -or $c[0].capture_status -ne 'success' -or -not $c[0].trace_complete -or $c[0].covered_points -notcontains $g.probe_rva) { $evidence = 'capture_incomplete' }
        elseif (-not $g.caller_function_rva) { $evidence = 'return_or_normalization_missing' }
        elseif ($shared.Count) { $evidence = 'shared-with-baseline' }
        $candidates += [pscustomobject]@{
            probe_rva = $g.probe_rva; probe_function_rva = $g.probe_function_rva; ret_rva = $g.ret_rva
            caller_function_rva = $g.caller_function_rva; ret_is_entry = $g.ret_is_entry
            evidence = $evidence; baseline_missing = $missing; shared_with = $shared; exact_return_seen_in = $exact
            event_indexes = $g.event_indexes; count = $g.count; status = 'unverified'; abi_validation = 'not_performed'
            register_scope = 'probe_site'; note = 'Registers belong to the probed site/function, not caller entry. ret_is_entry describes only the return address. No call ABI validation.'
        }
    }
    [pscustomobject]@{ schema_version = 3; scenarios = $scenarios; groups = $groups; candidates = $candidates; warnings = $warnings.ToArray(); symbols = $symbols }
}

function Write-ForwardReport {
    param($Capture, $Analysis, [Parameter(Mandatory)][string]$OutputDirectory)
    $null = New-Item -ItemType Directory -Force -Path $OutputDirectory
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss-ffff'
    $capPath = Join-Path $OutputDirectory "forward-capture-$stamp.json"
    $candPath = Join-Path $OutputDirectory "forward-candidates-$stamp.json"
    $mdPath = Join-Path $OutputDirectory "forward-analysis-$stamp.md"
    Write-Verbose 'Serializing capture JSON.'
    $Capture | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $capPath -Encoding UTF8
    Write-Verbose 'Serializing analysis JSON.'
    $Analysis | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $candPath -Encoding UTF8
    Write-Verbose 'Rendering Markdown report.'
    $md = New-Object System.Text.StringBuilder
    [void]$md.AppendLine('# Forward capture analysis')
    $captureMeta = Get-ForwardField $Capture 'capture_metadata'
    $captureScriptId = Get-ForwardField $captureMeta 'script_id'
    if ($captureScriptId) {
        [void]$md.AppendLine(("Capture script ID: {0}" -f $captureScriptId))
        [void]$md.AppendLine(("Capture script SHA256: {0}" -f (Get-ForwardField $captureMeta 'script_sha256' 'unknown')))
        [void]$md.AppendLine(("Capture pipeline SHA256: {0}" -f (Get-ForwardField $captureMeta 'pipeline_sha256' 'unknown')))
        [void]$md.AppendLine(("Probe plan SHA256: {0}" -f (Get-ForwardField $captureMeta 'probe_plan_sha256' 'unknown')))
    } else {
        [void]$md.AppendLine('Capture script ID: not recorded (legacy capture or direct oneclick run).')
    }
    [void]$md.AppendLine('All candidates: unverified; call ABI validation: not performed.')
    [void]$md.AppendLine('Registers are snapshots at the probe site / probed function, not caller entry arguments. Historical R9 is unknown (null).')
    [void]$md.AppendLine('ret_is_entry describes the return address, not a candidate callable entry. Only schema >= 2 function_entry + ret_valid permits caller attribution.')
    [void]$md.AppendLine('stack_rvas / stack bytes are raw_stack_scan_not_unwind. Raw consumer responses, dump/stack/follow bytes and queue/window metadata are in the capture JSON; historical omissions cannot be recovered.')
    [void]$md.AppendLine('only-in-C means absent in observed successful A/B windows with the same actual probe covered; it does not establish Forward semantics.')
    [void]$md.AppendLine('Failed or lossy windows have unknown total hit counts. Compare received events separately; baseline_missing prevents negative baseline claims.')
    [void]$md.AppendLine('')
    [void]$md.AppendLine('| Scenario | Collection | Arm | Received events | Hit count (unknown on failure/loss) | Complete | Covered points |')
    [void]$md.AppendLine('| --- | --- | --- | --- | --- | --- | --- |')
    foreach ($s in $Analysis.scenarios) {
        [void]$md.AppendLine(('| {0} | {1} | {2} | {3} | {4} | {5} | {6} |' -f $s.scenario, $s.capture_status, $s.arm_status, $s.received_events, $s.hit_count, $s.trace_complete, ($s.covered_points -join ', ')))
    }
    [void]$md.AppendLine('')
    [void]$md.AppendLine('| Scenario | Actual point | Probe function | Return RVA | Caller function | ret_is_entry | Count |')
    [void]$md.AppendLine('| --- | --- | --- | --- | --- | --- | --- |')
    foreach ($g in $Analysis.groups) {
        [void]$md.AppendLine(('| {0} | {1} | {2} | {3} | {4} | {5} | {6} |' -f $g.scenario, $g.probe_rva, $g.probe_function_rva, $g.ret_rva, $g.caller_function_rva, $g.ret_is_entry, $g.count))
    }
    [void]$md.AppendLine('')
    foreach ($candidate in $Analysis.candidates) {
        [void]$md.AppendLine(('- point={0}; return={1}; caller={2}; evidence={3}; baseline_missing={4}; unverified' -f $candidate.probe_rva, $candidate.ret_rva, $candidate.caller_function_rva, $candidate.evidence, ($candidate.baseline_missing -join ',')))
    }
    if (-not $Analysis.candidates.Count) { [void]$md.AppendLine('No C event groups available; this does not prove Forward is absent.') }
    foreach ($s in @(Get-ForwardField $Capture 'scenarios' @())) {
        [void]$md.AppendLine(('- {0} window={1} .. {2}; requested_seconds={3}; actual_ms={4}' -f $s.scenario, (Get-ForwardField $s 'window_started_at'), (Get-ForwardField $s 'window_ended_at'), (Get-ForwardField $s 'requested_seconds'), (Get-ForwardField $s 'actual_window_ms')))
        foreach ($warning in @(Get-ForwardField $s 'warnings' @())) { [void]$md.AppendLine(('- WARNING: {0}' -f $warning)) }
        foreach ($point in @(Get-ForwardField $s 'armed_detail' @())) {
            if ((Get-ForwardField $point 'ok') -ne $true) { [void]$md.AppendLine(('- FAILED ARM point={0}; reason={1}' -f (Get-ForwardField $point 'rva'), (Get-ForwardField $point 'reason'))) }
        }
        foreach ($err in @(Get-ForwardField $s 'errors' @())) { [void]$md.AppendLine(('- ERROR {0}: {1}' -f $err.stage, $err.message)) }
    }
    foreach ($warning in $Analysis.warnings) { [void]$md.AppendLine(('- WARNING: {0}' -f $warning)) }
    Set-Content -LiteralPath $mdPath -Value $md.ToString() -Encoding UTF8
    [pscustomobject]@{ capture = $capPath; candidates = $candPath; report = $mdPath }
}
