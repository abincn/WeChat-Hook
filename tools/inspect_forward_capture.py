#!/usr/bin/env python3
"""Offline schema-3 / trace-2 Forward snapshot verifier (Python stdlib only).

Usage (no output files are created unless explicitly requested)::

    python -B tools/inspect_forward_capture.py CAPTURE.json
    python -B tools/inspect_forward_capture.py CAPTURE.json --json-out REPORT.json --md-out REPORT.md

Exit codes: 0 = this structural profile verified, 1 = rejected input/evidence,
2 = command-line or file I/O error. This is not a business-success check.
Snapshot addresses are integers only; they are NEVER dereferenced locally.
"""

import argparse
import json
import re
import sys
from pathlib import Path


U64_MAX = (1 << 64) - 1
POINTS = (0x2161FC0, 0x43ACC80, 0x1649E60)
# rva: (dump register, dump bytes, followed bytes)
PROFILE = {POINTS[0]: (2, 96, 128), POINTS[1]: (3, 64, 128),
           POINTS[2]: (3, 32, 256)}
REGISTERS = ("rcx", "rdx", "r8", "r9")
LIMITATIONS = [
    "Only observed snapshot structure is verified; business success is not established.",
    "Registers have probe_site scope, not caller-entry argument scope; no call ABI validation.",
    "Raw stack scanning is not an unwound call stack.",
    "Selection-context +0x38 == 0 describes this observation only; other paths are not excluded.",
    "Map sentinel bytes after the fixed 26-byte header are ignored, including allocator residue.",
    "Heap string payload and vector element pointer-pair bytes were not captured; no local pointer dereference.",
    "observed_u32 at body +0xE0 has no confirmed XML-type or other business meaning.",
    "Clean recorded counters do not prove that unobserved activity or other paths do not exist.",
]


class ValidationError(ValueError):
    """The input cannot support the requested structural claim."""


def require(condition, path, message):
    if not condition:
        raise ValidationError(f"{path}: {message}")


def uint(value, path, maximum=U64_MAX):
    """Accept exact JSON ints or canonical decimal/0x strings, never floats/bools."""
    if type(value) is int:
        result = value
    elif isinstance(value, str) and re.fullmatch(r"(?:0|[1-9][0-9]*|0[xX][0-9a-fA-F]+)", value):
        is_hex = value.lower().startswith("0x")
        require(len(value) <= (18 if is_hex else 20), path, "integer outside uint64 range")
        result = int(value, 16 if is_hex else 10)
    else:
        raise ValidationError(f"{path}: expected exact unsigned integer, not float/bool")
    require(0 <= result <= maximum, path, f"integer outside 0..{maximum}")
    return result


def address(value, path):
    require(isinstance(value, str) and re.fullmatch(r"0[xX][0-9a-fA-F]{1,16}", value),
            path, "expected 0x-prefixed uint64 hex address")
    return uint(value, path)


def hx(value):
    return f"0x{value:X}"


def object_at(value, path):
    require(isinstance(value, dict), path, "expected object")
    return value


def array_at(value, path):
    require(isinstance(value, list), path, "expected array")
    return value


def boolean(value, path):
    require(type(value) is bool, path, "expected boolean")
    return value


def _reject_float(value):
    raise ValidationError(f"JSON: floating-point/non-finite number is forbidden: {value}")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "JSON", f"duplicate key {key!r}")
        result[key] = value
    return result


def loads_exact(text):
    """Preserve >2**53 numbers in outer AND embedded raw_json documents."""
    try:
        return json.loads(text, parse_int=int, parse_float=_reject_float,
                          parse_constant=_reject_float, object_pairs_hook=_unique_object)
    except (ValueError, TypeError, RecursionError) as exc:
        raise ValidationError(f"JSON: {exc}") from exc


def hex_bytes(value, path, length=None, maximum=256):
    require(isinstance(value, str), path, "expected hex string")
    require(len(value) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]*", value) is not None,
            path, "expected even-length hex without spaces or prefix")
    require(len(value) <= maximum * 2, path, f"exceeds {maximum} bytes")
    if length is not None:
        require(len(value) == length * 2, path, f"expected exactly {length} bytes")
    return bytes.fromhex(value)


def word(data, offset, size=8):
    require(offset >= 0 and offset + size <= len(data), "snapshot", f"truncated field at {hx(offset)}")
    return int.from_bytes(data[offset:offset + size], "little")


def decode_string(data, offset, path):
    """Decode a 32-byte MSVC string object, using captured inline bytes only."""
    require(offset + 32 <= len(data), path, "truncated 32-byte std::string")
    length, capacity = word(data, offset + 16), word(data, offset + 24)
    require(length <= capacity, path, "string length exceeds capacity")
    result = {"offset": hx(offset), "length": length, "capacity": capacity}
    if capacity >= 16:
        pointer = word(data, offset)
        require(pointer != 0 and pointer + capacity <= U64_MAX, path, "invalid heap buffer range")
        result.update(storage="heap", pointer=hx(pointer), status="not_captured")
        return result
    require(data[offset + length] == 0, path, "inline string lacks terminator at length")
    try:
        value = data[offset:offset + length].decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValidationError(f"{path}: invalid UTF-8") from exc
    result.update(storage="inline", status="captured", value=value)
    return result


def decode_vector(data, path):
    begin, end, cap = (word(data, off) for off in (0, 8, 16))
    require(begin <= end <= cap, path, "vector requires begin <= end <= cap")
    require(begin != 0, path, "this profile requires one non-null vector element")
    require(begin % 8 == 0, path, "vector pointer is not qword aligned")
    require((end - begin) % 16 == 0 and (cap - begin) % 16 == 0,
            path, "vector span/capacity is not a multiple of stride 16")
    count = (end - begin) // 16
    require(count == 1, path, "this profile requires exactly one shared-ptr pair slot")
    return {"begin": hx(begin), "end": hx(end), "cap": hx(cap), "stride": 16,
            "count": count, "capacity": (cap - begin) // 16,
            "element_layout": "shared_ptr_pair", "element_bytes": "not_captured",
            "follow_interpretation": "profile follows begin then its first pointer to body; intermediate pair bytes unavailable"}


def decode_sentinel(data):
    # MSVC tree-node fixed header only: three pointers, color, is_nil.
    # The remainder is deliberately never decoded or searched for strings.
    return {"fixed_header_bytes": 26, "left": hx(word(data, 0)),
            "parent": hx(word(data, 8)), "right": hx(word(data, 16)),
            "color": data[24], "is_nil": data[25],
            "ignored_tail_bytes": len(data) - 26, "content": "not_interpreted"}


def validate_event(event, base, image_size, path):
    """Return a normalized event for exact comparison of redundant copies."""
    e = dict(object_at(event, path))
    for key in ("seq", "rva", "a1", "a2", "a3", "a4", "ret", "ret_rva",
                "object_reg", "dump_len", "follow_len", "str_buf", "str_cap",
                "str_got", "str_len", "t", "tid"):
        maximum = (1 << 32) - 1 if key in ("object_reg", "dump_len", "follow_len", "str_cap",
                                          "str_got", "str_len", "tid") else U64_MAX
        e[key] = uint(e.get(key), f"{path}.{key}", maximum)
    require(e["seq"] >= 1, path, "seq must be positive")
    require(e["rva"] in PROFILE, path, "point is outside the supported Forward profile")
    reg, dump_len, follow_len = PROFILE[e["rva"]]
    require(e.get("register_scope") == "probe_site", path, "register_scope must be probe_site")
    require(e.get("capture_site") == "function_entry", path, "point must be a function_entry probe")
    require(e["object_reg"] == reg, path, "object_reg does not match point/probe profile")
    for key in ("object_hex", "ret_hex", "rip_hex", "rsp_hex", "rva_hex"):
        e[key] = hx(address(e.get(key), f"{path}.{key}"))
    require(address(e["rva_hex"], path) == e["rva"], path, "rva/rva_hex disagree")
    require(e["rva"] < image_size and address(e["rip_hex"], path) == base + e["rva"],
            path, "rip does not match image_base + point RVA")
    regs = object_at(e.get("registers_hex"), f"{path}.registers_hex")
    normalized_regs = {}
    for i, name in enumerate(REGISTERS, 1):
        value = address(regs.get(name), f"{path}.registers_hex.{name}")
        require(value == e[f"a{i}"], path, f"{name}/a{i} disagree")
        normalized_regs[name] = hx(value)
    e["registers_hex"] = normalized_regs
    require(e["object_hex"] == normalized_regs[REGISTERS[reg - 1]], path,
            "object_hex does not match selected probe register")
    require(e["ret"] == address(e["ret_hex"], path), path, "ret/ret_hex disagree")
    require(boolean(e.get("ret_valid"), path) and e["ret_rva"] < image_size
            and e["ret"] == base + e["ret_rva"], path, "invalid entry return address")
    require(e["dump_len"] == dump_len and e["follow_len"] == follow_len, path,
            "dump/follow lengths do not match point profile (possibly truncated)")
    dump = hex_bytes(e.get("dump_hex"), path + ".dump_hex", e["dump_len"])
    follow = hex_bytes(e.get("follow_hex"), path + ".follow_hex", e["follow_len"])
    require(address(e["object_hex"], path) + len(dump) <= U64_MAX, path, "dump address range overflows")
    e["dump_hex"], e["follow_hex"] = dump.hex(), follow.hex()
    qwords, seen = [], set()
    for item in array_at(e.get("dump_qwords"), path + ".dump_qwords"):
        item = object_at(item, path + ".dump_qwords[]")
        off, value = uint(item.get("off"), path), uint(item.get("v"), path)
        require(off % 8 == 0 and off + 8 <= len(dump) and off not in seen,
                path, "invalid/duplicate dump_qwords offset")
        require(word(dump, off) == value, path, "dump_qwords disagrees with captured bytes")
        seen.add(off)
        qwords.append({"off": off, "v": value})
    require(seen == set(range(0, min(64, len(dump)), 8)), path, "missing dump_qwords")
    e["dump_qwords"] = sorted(qwords, key=lambda item: item["off"])
    require(e.get("stack_kind") == "raw_stack_scan_not_unwind", path, "invalid stack scope")
    stack = hex_bytes(e.get("stack_hex"), path + ".stack_hex", 256)
    require(word(stack, 0) == e["ret"], path, "stack-top return address disagrees")
    require(address(e["rsp_hex"], path) + len(stack) <= U64_MAX, path, "stack range overflows")
    e["stack_hex"] = stack.hex()
    for key in ("stack_rvas", "stack_scan_rvas"):
        e[key] = [uint(v, path) for v in array_at(e.get(key), path + "." + key)]
        require(all(v < image_size for v in e[key]), path, "stack RVA outside image")
    require(e["stack_rvas"] == e["stack_scan_rvas"], path, "stack scan copies disagree")
    require(e["str_len"] <= e["str_cap"] and e["str_got"] <= e["str_len"],
            path, "invalid auxiliary string length/capacity")
    e["str_hex"] = hex_bytes(e.get("str_hex"), path + ".str_hex", e["str_got"]).hex()
    return e


def normalize_preflight_event(event, path):
    """Compare stale transport copies without applying the current-window profile.

    These bytes are not decoded as Forward evidence. Validate any recorded numeric
    and snapshot fields, while allowing stale events from other probe presets.
    """
    e = dict(object_at(event, path))
    integer_fields = ("seq", "rva", "a1", "a2", "a3", "a4", "ret", "ret_rva",
                      "object_reg", "dump_len", "follow_len", "str_buf", "str_cap",
                      "str_got", "str_len", "t", "tid")
    for key in integer_fields:
        if key in e and not (key in ("ret", "ret_rva") and e[key] is None):
            e[key] = uint(e[key], f"{path}.{key}")
    require(uint(e.get("seq"), path + ".seq") >= 1, path, "stale seq must be positive")
    for key in ("object_hex", "ret_hex", "rip_hex", "rsp_hex", "rva_hex"):
        if key in e and e[key] is not None:
            e[key] = hx(address(e[key], f"{path}.{key}"))
    if "registers_hex" in e:
        e["registers_hex"] = {key: hx(address(value, path + ".registers_hex." + key))
                              for key, value in object_at(e["registers_hex"], path).items()}
    for name, length_key in (("dump", "dump_len"), ("follow", "follow_len"), ("str", "str_got")):
        if name + "_hex" in e or length_key in e:
            length = uint(e.get(length_key), path + "." + length_key, 256)
            e[name + "_hex"] = hex_bytes(e.get(name + "_hex"), path + "." + name, length).hex()
    if "stack_hex" in e:
        e["stack_hex"] = hex_bytes(e["stack_hex"], path + ".stack_hex").hex()
    if "dump_qwords" in e:
        normalized, seen = [], set()
        dump = hex_bytes(e.get("dump_hex"), path + ".dump_hex")
        for item in array_at(e["dump_qwords"], path + ".dump_qwords"):
            item = object_at(item, path + ".dump_qwords[]")
            off, value = uint(item.get("off"), path), uint(item.get("v"), path)
            require(off % 8 == 0 and off not in seen and off + 8 <= len(dump), path, "invalid stale qword offset")
            require(word(dump, off) == value, path, "stale qword disagrees with captured bytes")
            seen.add(off)
            normalized.append({"off": off, "v": value})
        e["dump_qwords"] = sorted(normalized, key=lambda item: item["off"])
    for key in ("stack_rvas", "stack_scan_rvas"):
        if key in e:
            e[key] = [uint(value, path + "." + key) for value in array_at(e[key], path)]
    return e


def verify_capture(capture, scenario_name="C_forward"):
    """Pure inspection: no I/O, no process access, no pointer dereference."""
    report = {"report_schema_version": 1, "status": "rejected", "errors": [],
              "scenario": scenario_name, "business_success": "not_established",
              "limitations": list(LIMITATIONS)}
    try:
        _verify(capture, scenario_name, report)
    except (ValidationError, RecursionError) as exc:
        report["errors"].append(str(exc))
    if not report["errors"]:
        report["status"] = "verified"
    return report


def _verify(capture, scenario_name, report):
    capture = object_at(capture, "capture")
    require(uint(capture.get("schema_version"), "schema_version") == 3, "capture", "expected schema 3")
    scenarios = array_at(capture.get("scenarios"), "scenarios")
    selected = [s for s in scenarios if object_at(s, "scenario").get("scenario") == scenario_name]
    require(len(selected) == 1, "scenarios", "expected exactly one matching scenario")
    s = selected[0]
    require(uint(s.get("trace_schema_version"), "trace_schema_version") == 2,
            "scenario", "expected trace schema 2")
    require(s.get("register_scope") == "probe_site", "scenario", "invalid register scope")
    require(s.get("stack_kind") == "raw_stack_scan_not_unwind", "scenario", "invalid stack scope")
    for key in ("capture_status", "arm_status"):
        require(s.get(key) == "success", "scenario." + key, "capture/arming metadata reports failure")
    require(boolean(s.get("trace_complete"), "trace_complete"), "scenario", "capture window incomplete")
    for key in ("errors", "warnings"):
        require(not array_at(s.get(key), "scenario." + key), "scenario." + key, "capture reports issues")
    base, size = uint(s.get("image_base"), "image_base"), uint(s.get("image_size"), "image_size")
    require(base > 0 and size > 0 and base + size <= U64_MAX, "image", "invalid image range")
    report.update(capture_schema_version=3, trace_schema_version=2,
                  image_base=hx(base), image_size=size, register_scope="probe_site")
    armed = {}
    for p in array_at(s.get("armed_detail"), "armed_detail"):
        p = object_at(p, "armed_detail[]")
        rva = uint(p.get("rva"), "armed.rva")
        require(rva not in armed and rva < size, "armed_detail", "duplicate/out-of-range point")
        require(boolean(p.get("ok"), "armed.ok"), "armed_detail", "probe not armed")
        armed[rva] = uint(p.get("dump"), "armed.dump", 256)
    for rva, (_, dump_size, _) in PROFILE.items():
        require(armed.get(rva) == dump_size, "armed_detail", f"missing/mismatched probe {hx(rva)}")
    events = [validate_event(e, base, size, f"events[{i}]")
              for i, e in enumerate(array_at(s.get("events"), "events"))]
    require(uint(s.get("hit_count"), "hit_count") == len(events), "scenario", "hit_count mismatch")
    seqs = [e["seq"] for e in events]
    require([e["rva"] for e in events] == list(POINTS), "events",
            "this structural profile requires the three ordered Forward points")
    integrity = {"sequences": seqs, "event_count": len(events), "trace_batch_count": 0,
                 "busy_observations": 0, "dropped_max": 0, "skipped_max": 0,
                 "reader_skipped_total_max": 0, "published_final": 0}
    report["integrity"] = integrity

    def trace(value, path, preflight_copy=False):
        r = object_at(value, path)
        require(uint(r.get("schema_version"), path) == 2, path, "expected trace schema 2")
        require(uint(r.get("image_base"), path) == base and uint(r.get("image_size"), path) == size,
                path, "trace image range disagrees")
        busy = boolean(r.get("busy"), path + ".busy")
        require(boolean(r.get("consuming"), path + ".consuming"), path, "trace not consuming")
        integrity["busy_observations"] += int(busy)
        for key in ("dropped", "skipped", "reader_skipped_total"):
            value = uint(r.get(key), path + "." + key)
            integrity[key + "_max"] = max(integrity[key + "_max"], value)
        normalized = dict(r)
        for key in ("schema_version", "image_base", "image_size", "count", "dropped",
                    "skipped", "reader_skipped_total", "published"):
            normalized[key] = uint(r.get(key), path + "." + key)
        normalized["events"] = [normalize_preflight_event(e, path + ".events[]") if preflight_copy
                                else validate_event(e, base, size, path + ".events[]")
                                for e in array_at(r.get("events"), path + ".events")]
        require(normalized["count"] == len(normalized["events"]), path, "trace count mismatch")
        require(all(e["seq"] <= normalized["published"] for e in normalized["events"]),
                path, "event seq exceeds published counter")
        return normalized

    preflight = trace(s.get("preflight"), "preflight", preflight_copy=True)
    start = preflight["published"]
    expected_final = start + len(events)
    require(expected_final <= U64_MAX, "sequence", "preflight published + event count exceeds uint64 range")
    if seqs != list(range(start + 1, expected_final + 1)):
        report["errors"].append(
            f"sequence: expected ordered contiguous seq {start + 1}..{expected_final} "
            f"after preflight published={start}; gap/duplicate/reorder observed")
    integrity.update(published_start=start, published_expected_final=expected_final,
                     preflight_stale_event_count=preflight["count"])
    batches, flattened = [], []
    published = start
    for i, batch in enumerate(array_at(s.get("trace_batches"), "trace_batches")):
        batch = object_at(batch, "trace_batches[]")
        path = f"trace_batches[{i}]"
        response = trace(batch.get("response"), path + ".response")
        raw = trace(loads_exact(batch.get("raw_json")), path + ".raw_json")
        require(response == raw, path, "raw_json and response disagree (including exact integers)")
        require(response["published"] >= published, path, "published counter decreased")
        published = response["published"]
        flattened.extend(response["events"])
        batches.append(response)
    require(batches and flattened == events, "trace_batches", "batch events disagree with scenario events")
    require(published == expected_final, "trace_batches",
            "final published count disagrees with preflight published + window event count")
    integrity.update(trace_batch_count=len(batches), published_final=published)
    # Request copies are another representation, not additional events or losses.
    request_traces = []
    for i, request in enumerate(array_at(s.get("requests"), "requests")):
        request = object_at(request, "requests[]")
        endpoint = request.get("endpoint")
        require(isinstance(endpoint, str), "requests.endpoint", "expected string")
        if endpoint.split("?", 1)[0] == "/wxcx/probe/trace":
            require(request.get("ok") is True and request.get("method") == "GET",
                    "requests", "trace request failed or has unexpected method")
            request_traces.append(trace(loads_exact(request.get("raw_json")), f"requests[{i}].raw_json",
                                        preflight_copy=not request_traces))
    require(request_traces == [preflight] + batches, "requests", "trace request copies disagree")
    integrity["counter_aggregation"] = "maxima across redundant representations, not sums; busy counts representations"
    for key in ("busy_observations", "dropped_max", "skipped_max", "reader_skipped_total_max"):
        if integrity[key]:
            report["errors"].append(f"trace integrity: {key}={integrity[key]}; loss/busy invalidates completeness")

    observations = []
    for e in events:
        dump, follow = bytes.fromhex(e["dump_hex"]), bytes.fromhex(e["follow_hex"])
        observation = {"seq": e["seq"], "point_rva": hx(e["rva"]),
                       "object_register": REGISTERS[e["object_reg"] - 1],
                       "object_address": e["object_hex"], "register_scope": "probe_site",
                       "capture_site": "function_entry", "dump_bytes": len(dump), "follow_bytes": len(follow)}
        if e["rva"] in POINTS[:2]:
            sentinel = decode_sentinel(follow)
            require(sentinel["color"] in (0, 1) and sentinel["is_nil"] == 1,
                    "map sentinel", "invalid fixed header flags")
            observation["map_sentinel"] = sentinel
            if e["rva"] == POINTS[0]:
                selection = word(dump, 0x38)
                observation["selection_context"] = {"offset": "0x38", "observed_qword": hx(selection),
                                                     "observed_zero": selection == 0,
                                                     "scope": "this captured branch observation only"}
        else:
            observation["vector"] = decode_vector(dump, "vector")
            vt, embedded_vt = word(follow, 0), word(follow, 0xD8)
            require(base <= vt < base + size and vt - base == 0x84ECF58,
                    "body.vtable", "expected RVA 0x84ECF58")
            require(base <= embedded_vt < base + size and embedded_vt - base == 0x81D14A8,
                    "body.embedded_vtable", "expected RVA 0x81D14A8 at +0xD8")
            recipient = decode_string(follow, 0xB0, "body.string_0xB0")
            require(recipient["storage"] == "inline", "body.string_0xB0", "profile requires inline capacity <16")
            observation["body"] = {"vtable": hx(vt), "vtable_rva": hx(vt - base),
                                   "string_0xB0": recipient,
                                   "string_0x38": decode_string(follow, 0x38, "body.string_0x38"),
                                   "embedded_vtable_offset": "0xD8", "embedded_vtable_rva": hx(embedded_vt - base),
                                   "observed_u32_offset": "0xE0", "observed_u32": word(follow, 0xE0, 4),
                                   "observed_u32_0xE4": word(follow, 0xE4, 4),
                                   "semantic_candidates": {
                                       "observed_message_type": {"offset": "0xE0", "value": word(follow, 0xE0, 4)},
                                       "observed_message_subtype": {"offset": "0xE4", "value": word(follow, 0xE4, 4)},
                                       "status": "candidates_only"},
                                   "source_dto": {
                                       "embedded_offset": "0xD8",
                                       "identity_body_offset": "0x190", "identity_status": "not_captured",
                                       "scalar_blocks_body_range": "0x190..0x1AF", "scalar_blocks_status": "not_captured"}}
        observations.append(observation)
    report["observations"] = observations
    report["static_context"] = {
        "provenance": "user-provided static findings; not independently verified by this offline tool",
        "vtable_plus_0x8_method_rva": "0x6F1210", "reads_body_offset": "0xE0",
        "vtable_plus_0x10_method_rva": "0x167A890", "reads_body_subtype_offset": "0xE4",
        "source_dto_copy_ctor_rva": "0x1B5920", "source_dto_vptr_rva": "0x81D14A8",
        "copy_operations": ["write source-DTO vptr", "copy source+0x8 qword",
                            "copy source+0xB8..0xD7 as two 16-byte scalar blocks"],
        "name_inference": "no business inference from the IDA SchedulerProxy label",
        "next_capture_candidate": "direct source dump256; not performed by this tool"}


def render_markdown(report):
    lines = ["# Forward offline structural evidence", "", f"Status: **{report['status']}**.",
             "Business success: **not established**.", ""]
    if "source" in report:
        lines.extend([f"Source: `{report['source']}`", ""])
    if report["errors"]:
        lines.extend(["## Rejections", ""] + [f"- {error}" for error in report["errors"]] + [""])
    if "integrity" in report:
        q = report["integrity"]
        lines.extend([f"Schema 3 / trace 2; {q['event_count']} events, seq {q['sequences']}; "
                      f"{q['trace_batch_count']} trace batches; published={q['published_final']}.",
                      f"Preflight published={q['published_start']}; expected window seq "
                      f"{q['published_start'] + 1}..{q['published_expected_final']}; "
                      f"{q['preflight_stale_event_count']} stale preflight events excluded from this window."
                      if "published_start" in q else "Preflight baseline could not be validated.",
                      f"Recorded busy={q['busy_observations']}, dropped(max)={q['dropped_max']}, "
                      f"skipped(max)={q['skipped_max']}, reader_skipped_total(max)={q['reader_skipped_total_max']}.",
                      "Counters use maxima across duplicate representations; events are counted once.", ""])
    for e in report.get("observations", []):
        lines.extend([f"## seq {e['seq']} — {e['point_rva']}", "",
                      f"Probe register `{e['object_register']}` = `{e['object_address']}`; "
                      f"scope `{e['register_scope']}`; dump {e['dump_bytes']} bytes, follow {e['follow_bytes']} bytes.", ""])
        if "map_sentinel" in e:
            m = e["map_sentinel"]
            lines.extend([f"Map sentinel fixed header (26 bytes): left `{m['left']}`, parent `{m['parent']}`, "
                          f"right `{m['right']}`, color={m['color']}, is_nil={m['is_nil']}. "
                          f"Remaining {m['ignored_tail_bytes']} bytes ignored; no map content inferred.", ""])
        if "selection_context" in e:
            c = e["selection_context"]
            lines.extend([f"Selection context dump +0x38 = `{c['observed_qword']}`; "
                          f"zero observation: {str(c['observed_zero']).lower()}. "
                          "This checks the captured branch context; other paths are not excluded.", ""])
        if "body" in e:
            v, b = e["vector"], e["body"]
            a, h = b["string_0xB0"], b["string_0x38"]
            lines.extend([f"Vector begin/end/cap: `{v['begin']}` / `{v['end']}` / `{v['cap']}`. "
                          f"Stride {v['stride']}; {v['count']} shared-ptr pair slot, capacity {v['capacity']}. "
                          "Intermediate element pointer/control pair bytes: not_captured; followed body interpreted under the capture profile.", "",
                          f"Body vtable − image_base = `{b['vtable_rva']}`. "
                          f"Embedded vtable +0xD8 RVA = `{b['embedded_vtable_rva']}`.", "",
                          f"+0xB0 std::string: UTF-8 inline {json.dumps(a['value'], ensure_ascii=True)}, "
                          f"len={a['length']}, cap={a['capacity']}.", "",
                          f"+0x38 std::string: {h['storage']}, len={h['length']}, cap={h['capacity']}, "
                          f"status={h['status']}" + (f", pointer `{h['pointer']}`." if "pointer" in h else f", value {json.dumps(h['value'], ensure_ascii=True)}.") + " No snapshot pointer is dereferenced.", "",
                          f"+0xE0 observed_u32 = {b['observed_u32']}; +0xE4 observed_u32 = {b['observed_u32_0xE4']}. "
                          "Only observed_message_type/subtype candidates; no XML-type confirmation or sending-success claim.", "",
                          "Source-DTO is embedded at +0xD8. Its identity at body +0x190 and scalar blocks "
                          "+0x190..0x1AF lie beyond follow256: not_captured, never assumed zero.", ""])
    if "static_context" in report:
        lines.extend(["## Supplied static context", "",
                      "Provenance: user-provided static findings, not independently verified by this offline tool. "
                      "Vtable +8 method RVA 0x6F1210 reads body +0xE0 u32; +0x10 method RVA 0x167A890 reads +0xE4 u32. "
                      "The IDA SchedulerProxy label does not establish business meaning. Source-DTO copy_ctor RVA 0x1B5920 "
                      "writes vptr RVA 0x81D14A8, copies source+8 qword and source+0xB8..0xD7 as two 16-byte scalar blocks. "
                      "Next capture candidate: direct source dump256 (not performed here).", ""])
    lines.extend(["## Evidence limits", ""] + [f"- {item}" for item in report["limitations"]])
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("capture", type=Path)
    parser.add_argument("--scenario", default="C_forward")
    parser.add_argument("--json-out", type=Path, help="explicit machine JSON output path; default: stdout")
    parser.add_argument("--md-out", type=Path, help="explicit human-readable Markdown output path")
    args = parser.parse_args(argv)
    try:
        paths = [p.resolve() for p in (args.capture, args.json_out, args.md_out) if p is not None]
        require(len(paths) == len(set(paths)), "output", "input and output paths must be distinct")
        # Catch existing hard-link aliases as well as resolved symlink aliases.
        for i, left in enumerate(paths):
            for right in paths[i + 1:]:
                require(not (left.exists() and right.exists() and left.samefile(right)),
                        "output", "input/output aliases must be distinct")
        try:
            capture = loads_exact(args.capture.read_text(encoding="utf-8-sig"))
            report = verify_capture(capture, args.scenario)
        except (ValidationError, UnicodeError) as exc:
            report = {"report_schema_version": 1, "status": "rejected", "errors": [str(exc)],
                      "business_success": "not_established", "limitations": list(LIMITATIONS)}
        report["source"] = args.capture.as_posix()
        machine = json.dumps(report, ensure_ascii=True, indent=2) + "\n"
        if args.json_out:
            args.json_out.write_text(machine, encoding="utf-8")
        else:
            sys.stdout.write(machine)
        if args.md_out:
            args.md_out.write_text(render_markdown(report), encoding="utf-8")
        return 0 if report["status"] == "verified" else 1
    except (OSError, ValidationError) as exc:
        print(f"inspect_forward_capture: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
