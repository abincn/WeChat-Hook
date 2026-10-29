#!/usr/bin/env python3
"""Offline Forward suite evidence analysis, using only the Python standard library.

CLI: --suite suite.json --output-directory DIR. Exit 0 means sufficient recorded
structural evidence, 1 insufficient evidence, 2 output/command-line I/O failure.
No snapshot address is dereferenced and no service or process is contacted.
analyze_suite(path) reads inputs without writing and returns a JSON-safe report.
Unknown input properties are retained in input_suite and capture_evidence.
"""

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime
from pathlib import Path


CAPTURE_ID = "FWD-CAP-20261028-04-R3"
SUITE_ID = "FWD-SUITE-20261028-04-R3"
BUILD_ID = "FWD-PROBE-20261028-04"
PIPELINE = ("capture_forward_internal.ps1", "oneclick_forward.ps1",
            "forward-analysis-common.ps1", "forward-internal-plan.json")
PACKAGE_TOOLS = PIPELINE + ("capture_forward_suite.ps1", "analyze_forward_suite.py", "wxcx-common.ps1")
POINTS = {0x2161FC0: (3, 256, 0), 0x16BDF60: (2, 32, 32),
          0x3689B10: (2, 32, 256), 0x2160460: (3, 96, 0)}
MAX64 = (1 << 64) - 1
LIMITATIONS = [
    "Exact byte equality and integer equality are observations, not proof of message-ID semantics.",
    "No send success, delivery, native ABI, or per-type forwarding availability is established.",
    "Matches require UI sequence before service sequence in one window and non-reversing ticks when both are present; temporal order is not causal proof.",
    "Missing legacy metadata, loss, partial arming and ambiguous pairs are insufficient evidence.",
    "A declared db_msgsvrid is user-supplied, not an independently verified database result.",
    "Fresh pre/post-window observations bind process/start, target and probe identities to the initial suite identity; unobserved transient changes remain possible.",
    "Capabilities binary_identity verifies the target Weixin.dll file. The runtime probe file digest must match package 04, with matching mapped headers; this is not runtime-memory attestation.",
    "Hashes establish recorded file consistency, not authenticity of the evidence producer.",
]


class EvidenceError(ValueError):
    pass


def need(condition, message):
    if not condition:
        raise EvidenceError(message)


def obj(value, name):
    need(isinstance(value, dict), name + ": expected object (missing legacy metadata is insufficient)")
    return value


def arr(value, name):
    need(isinstance(value, list), name + ": expected array")
    return value


def number(value, name):
    if type(value) is int:
        n = value
    elif isinstance(value, str) and len(value) <= 20 and re.fullmatch(r"(?:0|[1-9][0-9]*|0[xX][0-9a-fA-F]+)", value):
        n = int(value, 16 if value.lower().startswith("0x") else 10)
    else:
        raise EvidenceError(name + ": expected exact unsigned integer")
    need(0 <= n <= MAX64, name + ": outside uint64 range")
    return n


def decimal(value, name):
    need(isinstance(value, str) and len(value) <= 20 and
         re.fullmatch(r"(?:0|[1-9][0-9]*)", value), name + ": expected decimal STRING")
    number(value, name)
    return value


def positive_decimal(value, name):
    decimal(value, name)
    need(number(value, name) > 0, name + ": expected POSITIVE decimal STRING")
    return value


def timestamp(value, name):
    need(isinstance(value, str), name + ": missing timestamp")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        need(result.utcoffset() is not None, name + ": timezone required")
        return result
    except ValueError as exc:
        raise EvidenceError(name + ": invalid timestamp") from exc


def digest(data):
    return hashlib.sha256(data).hexdigest().upper()


def sha(value, name):
    need(isinstance(value, str) and re.fullmatch(r"[a-fA-F0-9]{64}", value), name + ": expected SHA256")
    return value.upper()


def same_hash(value, expected, name):
    need(sha(value, name) == sha(expected, name), name + ": SHA256 mismatch")


def _pairs(pairs):
    result = {}
    for k, v in pairs:
        need(k not in result, "JSON: duplicate key " + repr(k))
        result[k] = v
    return result


def _bad_float(value):
    raise EvidenceError("JSON: float/nonfinite value forbidden: " + value)


def loads(text):
    need(isinstance(text, str), "raw_json: expected string")
    try:
        return json.loads(text, object_pairs_hook=_pairs, parse_float=_bad_float,
                          parse_constant=_bad_float)
    except (ValueError, RecursionError) as exc:
        raise EvidenceError("JSON: " + str(exc)) from exc


def resolve(base, value):
    need(isinstance(value, str) and value.strip(), "path: expected nonempty string")
    p = Path(value)
    return (p if p.is_absolute() else base / p).resolve()


def read_json(path):
    raw = path.read_bytes()
    return obj(loads(raw.decode("utf-8-sig")), str(path)), digest(raw)


# PowerShell preserves large numeric tokens as decimal strings. Normalize only
# numeric transport fields, never scenario IDs, talkers or declared message IDs.
NUMERIC = set("schema_version seq rva a1 a2 a3 a4 ret ret_rva object_reg dump_len follow_len follow_read_offset str_buf str_cap str_got str_len t tid image_base image_size count published dropped skipped reader_skipped_total ring_dropped reader_skipped dump dump_reg follow_off follow2_off str_reg str_off str_max ms off v".split())


def normalized(value, key=""):
    if type(value) is bool:
        return ("json_boolean", value)
    if isinstance(value, dict):
        return {k: normalized(v, k) for k, v in value.items()}
    if isinstance(value, list):
        return [normalized(v, key) for v in value]
    if key in NUMERIC and value is not None and type(value) is not bool:
        return number(value, key)
    return value


def observation(value, name):
    o = obj(value, name)
    need(o.get("status") == "success" and not o.get("error"), name + ": observation failed or missing")
    raw = o.get("raw_json")
    data = obj(loads(raw), name + ".raw_json")
    same_hash(o.get("sha256"), digest(raw.encode("utf-8")), name)
    need(normalized(data) == normalized(obj(o.get("response"), name + ".response")),
         name + ": raw_json/response disagree")
    return data


def validate_context(c, name):
    obj(c, name)
    need(isinstance(c.get("id"), str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}", c["id"]), name + ": invalid scenario id")
    need(c.get("type") in ("text", "link", "image", "file"), name + ": invalid type")
    for key in ("label", "source_talker", "toid"):
        need(isinstance(c.get(key), str) and c[key].strip(), name + ": missing " + key)
    positive_decimal(c.get("source_msgsvrid"), name + ".source_msgsvrid")
    if "db_msgsvrid" in c:
        positive_decimal(c["db_msgsvrid"], name + ".db_msgsvrid")
    d = c.get("downloaded")
    need(type(d) is bool or (isinstance(d, str) and d in
         ("downloaded", "not_downloaded", "unknown", "not_applicable")), name + ": invalid downloaded state")


def provenance(suite, base, report):
    p = obj(suite.get("provenance"), "provenance")
    files = arr(p.get("files"), "provenance.files")
    by_name, seen = {}, set()
    for item in files:
        obj(item, "provenance.files[]")
        path = resolve(base, item.get("path"))
        need(path not in seen, "provenance: duplicate file path")
        seen.add(path)
        actual = digest(path.read_bytes())
        same_hash(item.get("sha256"), actual, "provenance " + str(path))
        if path.name in PACKAGE_TOOLS:
            need(path.name not in by_name, "provenance: duplicate pipeline filename")
            by_name[path.name] = (path, actual)
    need(set(by_name) == set(PACKAGE_TOOLS), "provenance: all seven package tool files required")
    pipeline = digest("\n".join(n + ":" + by_name[n][1] for n in PIPELINE).encode("utf-8"))
    same_hash(p.get("pipeline_sha256"), pipeline, "provenance.pipeline_sha256")
    same_hash(p.get("plan_sha256"), by_name[PIPELINE[-1]][1], "provenance.plan_sha256")
    plan, _ = read_json(by_name[PIPELINE[-1]][0])
    need(plan.get("capture_script_id") == CAPTURE_ID and plan.get("target_version") == "4.1.10.27", "plan: capture version mismatch")
    need("follow_read_offset" in arr(plan.get("required_features"), "plan.required_features"), "plan: feature missing")
    points = arr(plan.get("points"), "plan.points")
    need(len(points) == 4, "plan: expected four points")
    indexed = {number(obj(x, "plan.point").get("rva"), "plan.rva"): x for x in points}
    need(set(indexed) == set(POINTS), "plan: wrong or duplicate points")
    for rva, (reg, dump_len, follow_len) in POINTS.items():
        point = indexed[rva]
        need(number(point.get("dump_reg"), "plan.dump_reg") == reg and
             number(point.get("dump"), "plan.dump") == dump_len and
             number(point.get("follow_len", 0), "plan.follow_len") == follow_len, "plan: point profile mismatch")
    service = indexed[0x16BDF60]
    need(number(service.get("follow_read_offset"), "plan.follow_read_offset") == 400 and
         number(service.get("follow_off"), "plan.follow_off") == 0 and
         number(service.get("follow2_off"), "plan.follow2_off") == 0, "plan: service must follow descriptor +0x190")
    report["provenance_integrity"] = "verified"
    return p, by_name, plan, indexed


def preflight(suite, prov, value=None, name="preflight"):
    p = obj(suite.get("preflight") if value is None else value, name)
    need(p.get("suite_id") == suite["suite_id"], "preflight: suite_id mismatch")
    same_hash(p.get("plan_sha256"), prov.get("plan_sha256"), "preflight.plan_sha256")
    status = observation(p, "preflight")
    need(number(status.get("schema_version"), "preflight.schema_version") >= 2,
         "preflight: schema >=2 required")
    need(status.get("probe_build_id") == BUILD_ID, "preflight: wrong/missing canonical probe_build_id")
    need(obj(status.get("features"), "preflight.features").get("follow_read_offset") is True,
         "preflight: follow_read_offset unsupported")
    caps = observation(p.get("forward_capabilities"), "preflight.forward_capabilities")
    binary = obj(caps.get("binary_identity"), "binary_identity")
    need(binary.get("status") == "hashed" and binary.get("verified") is True,
         "binary_identity: target Weixin.dll file requires status=hashed and verified=true")
    same_hash(binary.get("actual_sha256"), binary.get("expected_sha256"), "binary_identity")
    runtime = obj(caps.get("runtime_identity"), name + ".capabilities.runtime_identity")
    status_runtime = obj(status.get("runtime_identity"), name + ".status.runtime_identity")
    for identity in (runtime, status_runtime):
        need(identity.get("probe_build_id") == BUILD_ID, name + ": runtime probe build mismatch")
        pid = number(identity.get("process_id"), name + ".runtime_identity.process_id")
        need(0 < pid <= (1 << 32) - 1, name + ": process_id must be positive uint32")
        positive_decimal(identity.get("process_start_filetime"), name + ".runtime_identity.process_start_filetime")
        need(normalized(identity.get("weixin")) == normalized(binary),
             name + ": runtime_identity.weixin disagrees with binary_identity")
        probe = obj(identity.get("probe"), name + ".runtime_identity.probe")
        need(probe.get("status") == "hashed" and probe.get("mapped_headers_match") is True,
             name + ": runtime probe requires hashed status and matching mapped headers")
        same_hash(probe.get("actual_sha256"), obj(suite.get("package"), "package").get("dll_sha256"),
                  name + ".runtime probe/package DLL")
    key = runtime_key(runtime)
    need(key == runtime_key(status_runtime), name + ": status/capabilities process/probe/target identities disagree")
    status_at = timestamp(p.get("observed_at"), name + ".observed_at")
    caps_at = timestamp(p["forward_capabilities"].get("observed_at"), name + ".forward_capabilities.observed_at")
    need(status_at <= caps_at, name + ": capabilities observation precedes status")
    return {"runtime_identity": runtime, "identity_key": key, "status_at": status_at, "caps_at": caps_at}


def runtime_key(identity):
    """Compare stable identities, allowing exact transport int/string PID copies."""
    result = {"process_id": str(number(identity.get("process_id"), "runtime.process_id")),
              "process_start_filetime": identity["process_start_filetime"],
              "probe_build_id": identity["probe_build_id"]}
    for module in ("probe", "weixin"):
        fingerprint = obj(identity.get(module), "runtime." + module)
        path = fingerprint.get("path")
        need(isinstance(path, str) and path.strip(), "runtime." + module + ": missing module path")
        result[module + "_sha256"] = sha(fingerprint.get("actual_sha256"), "runtime." + module)
        result[module + "_path"] = path
    return result


def validate_package(package, base):
    """Verify package 04 metadata, DLL and all seven tools without modifying it."""
    package = obj(package, "package")
    need(package.get("verified") is True and package.get("status") == "verified", "package: not verified")
    need(package.get("expected_script_id") == CAPTURE_ID and
         package.get("expected_probe_build_id") == BUILD_ID and
         package.get("expected_suite_script_id") == SUITE_ID,
         "package: expected capture/probe/suite IDs disagree")
    paths = {}
    for field, hash_field in (("metadata_path", "metadata_sha256"), ("dll_path", "dll_sha256")):
        path = resolve(base, package.get(field))
        same_hash(package.get(hash_field), digest(path.read_bytes()), "package." + field)
        paths[field] = path
    root = resolve(base, package.get("directory"))
    need(paths["metadata_path"] == (root / "PACKAGE.txt").resolve() and
         paths["dll_path"] == (root / "version.dll").resolve(), "package: paths disagree with package directory")
    metadata = paths["metadata_path"].read_text(encoding="utf-8-sig")
    expected = {"Package": "wxcx-forward-codex-20261028-04-r3", "Capture script ID": CAPTURE_ID,
                "Suite script ID": SUITE_ID,
                "DLL SHA256": sha(package.get("dll_sha256"), "package.dll_sha256"),
                "Pipeline SHA256": sha(package.get("pipeline_sha256"), "package.pipeline_sha256")}
    for label, value in expected.items():
        matches = re.findall(r"^" + re.escape(label) + r": ([^\r\n]+)\s*$", metadata, re.MULTILINE)
        need(len(matches) == 1 and matches[0].strip().upper() == value.upper(), "package metadata: mismatch/duplicate " + label)
    hashes = {n: digest((root / "tools" / n).read_bytes()) for n in PACKAGE_TOOLS}
    actual = digest("\n".join(n + ":" + hashes[n] for n in PIPELINE).encode("utf-8"))
    same_hash(package.get("pipeline_sha256"), actual, "package pipeline")
    return hashes


def package_correspondence(package, files, base):
    hashes = validate_package(package, base)
    need(set(PACKAGE_TOOLS) <= set(files), "package/provenance: seven archived tools required")
    for name in PACKAGE_TOOLS:
        same_hash(hashes[name], files[name][1], "package/provenance " + name)


def bytes_field(event, field):
    value = event.get(field + "_hex")
    need(isinstance(value, str) and len(value) <= 512 and len(value) % 2 == 0 and
         re.fullmatch(r"[0-9a-fA-F]*", value) is not None, field + ": invalid/truncated hex")
    data = bytes.fromhex(value)
    need(number(event.get(field + "_len"), field + "_len") == len(data), field + ": length mismatch")
    return data


def validate_trace(record, indexed):
    need(number(record.get("trace_schema_version"), "trace_schema_version") == 2, "trace: expected schema 2")
    for k in ("capture_status", "arm_status"):
        need(record.get(k) == "success", k + ": failed/partial/unknown")
    need(record.get("trace_complete") is True, "trace: incomplete window")
    need(number(record.get("actual_window_ms"), "actual_window_ms") > 0 and
         number(record.get("requested_seconds"), "requested_seconds") > 0, "trace: missing/empty window duration")
    try:
        start = datetime.fromisoformat(record["window_started_at"].replace("Z", "+00:00"))
        end = datetime.fromisoformat(record["window_ended_at"].replace("Z", "+00:00"))
        need(start.utcoffset() is not None and end.utcoffset() is not None and start <= end,
             "trace: invalid window timestamps")
    except (KeyError, AttributeError, ValueError, TypeError) as exc:
        raise EvidenceError("trace: missing/invalid window timestamps") from exc
    for k in ("errors", "warnings"):
        need(not arr(record.get(k), k), "capture reports " + k)
    base = number(record.get("image_base"), "image_base")
    size = number(record.get("image_size"), "image_size")
    need(base > 0 and size > 0 and base + size <= MAX64, "trace: invalid image range")
    armed = arr(record.get("armed_detail"), "armed_detail")
    need(len(armed) == 4, "arming: expected all four points")
    seen = set()
    for a in armed:
        obj(a, "armed_detail[]")
        rva = number(a.get("rva"), "armed.rva")
        need(rva in indexed and rva not in seen and a.get("ok") is True, "arming: wrong/duplicate/failed point")
        seen.add(rva)
        req = obj(loads(a.get("request_json")), "arm.request_json")
        reply = obj(loads(a.get("response_raw_json")), "arm.response_raw_json")
        for key, value in indexed[rva].items():
            if key in NUMERIC:
                need(number(req.get(key), "arm." + key) == number(value, "plan." + key), "arming: request disagrees with plan: " + key)
        need(reply.get("ok") is True and number(reply.get("rva"), "arm.reply.rva") == rva, "arming: reply failed")
        if rva == 0x16BDF60:
            need(number(reply.get("follow_read_offset"), "arm.reply.follow_read_offset") == 400,
                 "arming: service offset was not confirmed")
    events = arr(record.get("events"), "events")
    need(number(record.get("hit_count"), "hit_count") == len(events), "hit_count mismatch")
    for e in events:
        obj(e, "event")
        rva = number(e.get("rva"), "event.rva")
        need(rva in POINTS and rva < size, "event: unsupported point")
        reg, dl, fl = POINTS[rva]
        need(e.get("capture_site") == "function_entry" and e.get("register_scope") == "probe_site", "event: invalid capture scope")
        need(number(e.get("object_reg"), "object_reg") == reg, "event: wrong dump register")
        need(len(bytes_field(e, "dump")) == dl and len(bytes_field(e, "follow")) == fl, "event: partial dump/follow")
        if "rva_hex" in e:
            need(number(e["rva_hex"], "rva_hex") == rva, "event: rva_hex mismatch")
        if "rip_hex" in e:
            need(number(e["rip_hex"], "rip_hex") == base + rva, "event: rip/image mismatch")
        if rva == 0x16BDF60:
            need(number(e.get("follow_read_offset"), "event.follow_read_offset") == 400, "service: missing/wrong follow_read_offset (head256 is not identity tail)")

    def trace(value, name):
        t = obj(value, name)
        need(number(t.get("schema_version"), name + ".schema") == 2, name + ": trace version mismatch")
        need(number(t.get("image_base"), name) == base and number(t.get("image_size"), name) == size, name + ": image identity mismatch")
        need(t.get("busy") is False and t.get("consuming") is True and t.get("ok") is not False, name + ": busy/failed/nonconsuming")
        for container in (t, obj(t.get("queue", {}), name + ".queue")):
            for key in ("dropped", "skipped", "reader_skipped_total", "ring_dropped", "reader_skipped"):
                if container is t and key in ("dropped", "skipped", "reader_skipped_total") or key in container:
                    need(number(container.get(key), name + "." + key) == 0, name + ": loss counter " + key)
            if "busy" in container:
                need(container["busy"] is False or type(container["busy"]) is int and container["busy"] == 0, name + ": queue busy")
        ee = arr(t.get("events"), name + ".events")
        need(number(t.get("count"), name + ".count") == len(ee) and len(ee) < 20, name + ": count mismatch or saturated page")
        pub = number(t.get("published"), name + ".published")
        need(all(0 < number(obj(e, "trace.event").get("seq"), "trace.seq") <= pub for e in ee), name + ": seq outside published range")
        return normalized(t)

    baseline = trace(record.get("preflight"), "record.preflight")
    published = baseline["published"]
    seqs = [number(e.get("seq"), "event.seq") for e in events]
    need(published + len(events) <= MAX64 and seqs == list(range(published + 1, published + len(events) + 1)), "trace: missing/duplicate/reordered sequence")
    batches, flat = [], []
    for b in arr(record.get("trace_batches"), "trace_batches"):
        obj(b, "batch")
        t = trace(b.get("response"), "batch.response")
        need(t == trace(loads(b.get("raw_json")), "batch.raw_json"), "batch: raw/response disagree")
        flat.extend(t["events"])
        need(t["published"] == published + len(t["events"]), "trace: published sequence not fully observed")
        published = t["published"]
        batches.append(t)
    need(batches and flat == normalized(events), "trace: batch/window event copies disagree")
    copies = []
    for req in arr(record.get("requests"), "requests"):
        obj(req, "request")
        endpoint = req.get("endpoint")
        need(isinstance(endpoint, str), "request: missing endpoint")
        need(req.get("ok") is True, "request: failed transport")
        if endpoint.split("?", 1)[0] == "/wxcx/probe/trace":
            need(req.get("method") == "GET", "trace request: expected GET")
            copies.append(trace(loads(req.get("raw_json")), "request.raw_json"))
    need(copies == [baseline] + batches, "trace: request copies disagree")
    return {"event_count": len(events), "sequences": seqs, "published_start": baseline["published"],
            "published_final": published, "trace_batch_count": len(batches), "status": "verified"}


def lookup_targets(entry, context, result, required=True):
    targets = [{"source": "manifest.source_msgsvrid (user declared)", "decimal": context["source_msgsvrid"]}]
    if "db_msgsvrid" in context:
        targets.append({"source": "manifest.db_msgsvrid (user declared; not independently verified)", "decimal": context["db_msgsvrid"]})
    result["source_lookup"] = entry.get("source_lookup")
    result["source_lookup_status"] = "not_requested"
    lookup = entry.get("source_lookup")
    if lookup is None:
        if required:
            result["errors"].append("source_lookup required by default; set suite.lookup_source=false explicitly for structure-only analysis.")
        return targets
    try:
        response = observation(lookup, "source_lookup")
        code = response.get("code")
        need((type(code) is int and code == 0) or (type(code) is str and code == "0"),
             "source_lookup: missing/nonzero response code")
        status = response.get("status")
        need(status in ("found", "not_found", "ambiguous", "lookup_incomplete", "database_unavailable"), "source_lookup: unknown result status")
        need(type(response.get("complete")) is bool, "source_lookup: complete must be boolean")
        matches = arr(response.get("matches"), "source_lookup.matches")
        result["source_lookup_status"] = status
        if status != "found" or response["complete"] is not True or len(matches) != 1:
            result["lookup_notes"].append("No DB comparison: requires complete unique found result.")
            result["errors"].append("Requested source_lookup did not establish a complete unique source.")
            return targets
        match = obj(matches[0], "source_lookup.matches[0]")
        for key in ("local_id_decimal", "msg_svr_id_decimal"):
            decimal(match.get(key), "source_lookup." + key)
        need(match.get("talker") == context["source_talker"], "source_lookup: talker differs from declared source")
        need(match["msg_svr_id_decimal"] == context["source_msgsvrid"], "source_lookup: message ID differs from requested source")
        for key in ("local_id_decimal", "msg_svr_id_decimal"):
            targets.append({"source": "source_lookup.matches[0]." + key + " (complete unique DB result)", "decimal": match[key]})
    except (EvidenceError, ValueError, TypeError) as exc:
        result["source_lookup_status"] = "unusable"
        result["lookup_notes"].append(str(exc))
        result["errors"].append(str(exc))
    return targets


def candidates(block, targets):
    # Every byte-aligned position is shown explicitly; no preferred offset/meaning.
    out = []
    for width in (4, 8):
        for off in range(33 - width):
            value = str(int.from_bytes(block[off:off + width], "little"))
            out.append({"block_offset": "0x%X" % off, "ui_dump_offset": "0x%X" % (0xB8 + off),
                        "service_descriptor_offset": "0x%X" % (0x190 + off),
                        "encoding": "u%d_le" % (width * 8), "decimal": value,
                        "equal_to": [t["source"] for t in targets if t["decimal"] == value],
                        "semantic_status": "unproven_raw_offset_candidate"})
    return out


def analyze_scenario(entry, expected, suite, base, prov, files, plan, indexed, gate_errors,
                     initial_identity=None, previous_at=None):
    result = {"id": expected["id"], "type": expected["type"], "status": "insufficient",
              "context": expected, "errors": [], "lookup_notes": [],
              "matching": {"status": "not_evaluated", "pair_count": 0, "pairs": []},
              "candidates": [], "business_success": "not_established"}
    if entry is None:
        result["errors"].append("Missing suite scenario/capture.")
        return result
    targets = lookup_targets(entry, expected, result, required=suite.get("lookup_source", True))
    result["comparison_targets"] = targets
    try:
        need(normalized(entry.get("context")) == normalized(expected), "suite entry: context mismatch")
        need(entry.get("status") == "captured" and not entry.get("error"), "suite entry: failed/pending capture")
        # Re-read all archived/package inputs for each scene. Live source_path
        # properties are provenance only: archived path is the evidence source.
        current_prov, current_files, _, _ = provenance(suite, base, {})
        for name in PACKAGE_TOOLS:
            same_hash(current_files[name][1], files[name][1], "scene/initial provenance " + name)
        package_correspondence(suite.get("package"), current_files, base)
        fresh_value = obj(entry.get("preflight"), "scenario.preflight")
        need(fresh_value.get("scenario_id") == expected["id"], "scenario.preflight: missing/wrong scenario_id")
        fresh = preflight(suite, current_prov, fresh_value, "scenario.preflight")
        need(initial_identity is not None and fresh["identity_key"] == initial_identity["identity_key"],
             "scenario.preflight: process/start/probe/target identity changed from initial preflight")
        need(fresh["status_at"] >= initial_identity["caps_at"], "scenario.preflight: observation predates initial preflight")
        if previous_at is not None:
            need(fresh["status_at"] >= previous_at, "scenario.preflight: observations out of window order")
        result["preflight_integrity"] = "verified"
        result["runtime_identity_key"] = fresh["identity_key"]
        result["preflight_observed_at"] = fresh_value["forward_capabilities"]["observed_at"]
        post_value = obj(entry.get("postflight"), "scenario.postflight")
        need(post_value.get("scenario_id") == expected["id"] and post_value.get("phase") == "post_window",
             "scenario.postflight: missing/wrong scenario_id or phase")
        post = preflight(suite, current_prov, post_value, "scenario.postflight")
        need(post["identity_key"] == fresh["identity_key"],
             "scenario.postflight: process/start/probe/target identity changed during window")
        need(post["status_at"] >= fresh["caps_at"], "scenario.postflight: observation predates preflight")
        path = resolve(base, entry.get("capture_path"))
        result["capture_path"] = str(path)
        capture, actual = read_json(path)
        result["capture_evidence"] = capture
        same_hash(entry.get("capture_sha256"), actual, "capture")
        result["capture_sha256"] = actual
        for artifact in arr(entry.get("artifacts", []), "artifacts"):
            obj(artifact, "artifact")
            artifact_path = resolve(base, artifact.get("path"))
            same_hash(artifact.get("sha256"), digest(artifact_path.read_bytes()), "artifact " + str(artifact_path))
        need(type(capture.get("schema_version")) is int and capture["schema_version"] == 3, "capture: expected schema 3")
        need(capture.get("suite_id") == suite["suite_id"] and capture.get("suite_script_id") == SUITE_ID,
             "capture: suite/script identity mismatch or legacy omission")
        need(normalized(capture.get("scenario_context")) == normalized(expected), "capture: scenario_context mismatch")
        need(normalized(capture.get("probe_status_identity")) == normalized(fresh_value), "capture: probe_status_identity must equal this scenario's fresh preflight")
        meta = obj(capture.get("capture_metadata"), "capture_metadata")
        need(meta.get("script_id") == CAPTURE_ID, "capture_metadata: script version mismatch")
        for key, expected_value in (("suite_id", suite["suite_id"]), ("suite_script_id", SUITE_ID),
                                    ("scenario_context", expected)):
            if key in meta:
                need(normalized(meta[key]) == normalized(expected_value), "capture_metadata: conflicting " + key)
        same_hash(meta.get("script_sha256"), files[PIPELINE[0]][1], "capture_metadata.script_sha256")
        same_hash(meta.get("pipeline_sha256"), prov.get("pipeline_sha256"), "capture_metadata.pipeline_sha256")
        same_hash(meta.get("probe_plan_sha256"), prov.get("plan_sha256"), "capture_metadata.probe_plan_sha256")
        need(normalized(loads(capture.get("probe_plan_json"))) == normalized(plan), "capture: embedded plan disagrees with verified plan")
        records = arr(capture.get("scenarios"), "capture.scenarios")
        need(records, "capture: no records")
        pairs = []
        for i, rec in enumerate(records):
            obj(rec, "record")
            need(rec.get("scenario") == expected["id"], "record: scenario id mismatch/omission")
            need(normalized(rec.get("scenario_context")) == normalized(expected), "record: scenario_context mismatch/omission")
            need(timestamp(rec.get("window_started_at"), "window_started_at") >= fresh["caps_at"],
                 "scenario.preflight: observation occurs after capture window start")
            need(post["status_at"] >= timestamp(rec.get("window_ended_at"), "window_ended_at"),
                 "scenario.postflight: observation precedes capture window end")
            integrity = validate_trace(rec, indexed)
            result.setdefault("windows", []).append({"record_index": i, "integrity": integrity})
            ui = [e for e in rec["events"] if number(e["rva"], "rva") == 0x2161FC0]
            service = [e for e in rec["events"] if number(e["rva"], "rva") == 0x16BDF60]
            for u in ui:
                block = bytes_field(u, "dump")[0xB8:0xD8]
                for v in service:
                    if block == bytes_field(v, "follow"):
                        ui_seq = number(u["seq"], "seq")
                        service_seq = number(v["seq"], "seq")
                        order_errors = []
                        if ui_seq >= service_seq:
                            order_errors.append("UI sequence must precede service sequence")
                        ui_tick = number(u["t"], "UI.t") if "t" in u else None
                        service_tick = number(v["t"], "service.t") if "t" in v else None
                        if ui_tick is not None and service_tick is not None and ui_tick > service_tick:
                            order_errors.append("Service tick precedes UI tick")
                        pairs.append({"record_index": i, "ui_seq": ui_seq,
                                      "service_seq": service_seq, "hex": block.hex(),
                                      "ui_tick": str(ui_tick) if ui_tick is not None else None,
                                      "service_tick": str(service_tick) if service_tick is not None else None,
                                      "tick_check": "compared" if ui_tick is not None and service_tick is not None else "unavailable",
                                      "ordering_status": "insufficient" if order_errors else "ordered",
                                      "ordering_errors": order_errors,
                                      "ui_range": "0xB8..0xD7", "service_range": "0x190..0x1AF"})
        invalid_order = any(p["ordering_status"] != "ordered" for p in pairs)
        result["matching"] = {"status": "ordering_insufficient" if invalid_order else "unique_match" if len(pairs) == 1 else "multiple_matches" if pairs else "missing",
                              "pair_count": len(pairs), "pairs": pairs}
        need(not invalid_order, "matching: byte-equal pair violates UI-before-service sequence/tick order; cannot attribute it to this UI action")
        need(len(pairs) == 1, "matching: requires exactly one pair within a single record/window")
        result["candidates"] = candidates(bytes.fromhex(pairs[0]["hex"]), targets)
        block = bytes.fromhex(pairs[0]["hex"])
        if block in (bytes(32), b"\xff" * 32):
            result["matching"]["status"] = "weak_uniform_match"
            result["matching"]["identity_evidence"] = "insufficient"
            raise EvidenceError("matching: all-zero/all-FF identity block is weak evidence, not sufficient identity evidence")
        result["postflight_integrity"] = "verified"
        result["postflight_observed_at"] = post_value["forward_capabilities"]["observed_at"]
        need(not gate_errors, "suite integrity/preflight failed; see suite errors")
        if not result["errors"]:
            result["status"] = "sufficient"
    except (EvidenceError, OSError, UnicodeError, ValueError, TypeError, RecursionError) as exc:
        result["errors"].append(str(exc))
    return result


def analyze_suite(path):
    """Read a suite and its referenced evidence; return a report, never write files.

    Malformed or missing evidence returns status insufficient with diagnostics.
    Values of all ID candidates/comparison targets are decimal strings.
    """
    path = Path(path).resolve()
    report = {"report_schema_version": 1, "status": "insufficient", "source": str(path),
              "errors": [], "scenarios": [], "business_success": "not_established",
              "semantic_proof": "not_established", "limitations": list(LIMITATIONS)}
    try:
        suite, suite_hash = read_json(path)
        report.update(input_suite=suite, suite_sha256=suite_hash, suite_id=suite.get("suite_id"))
        need(type(suite.get("schema_version")) is int and suite["schema_version"] == 1, "suite: expected schema_version=1")
        need(isinstance(suite.get("suite_id"), str) and suite["suite_id"].strip(), "suite: missing suite_id")
        need(suite.get("suite_script_id") == SUITE_ID, "suite: script version mismatch")
        need(type(suite.get("lookup_source", True)) is bool, "suite.lookup_source: expected boolean")
        report["lookup_source"] = suite.get("lookup_source", True)
        if "target_version" in suite:
            need(suite["target_version"] == "4.1.10.27", "suite: target version mismatch")
        scenes = arr(obj(suite.get("manifest"), "manifest").get("scenarios"), "manifest.scenarios")
        ids, types = set(), set()
        for scene in scenes:
            validate_context(scene, "manifest.scenario")
            need(scene["id"] not in ids, "manifest: duplicate scenario id")
            need(not ({"suite_id", "suite_script_id"} & set(scene)), "manifest: reserved context keys")
            ids.add(scene["id"])
            types.add(scene["type"])
        need(types == {"text", "link", "image", "file"}, "manifest: all four types required")
        manifest, manifest_hash = read_json(resolve(path.parent, suite.get("manifest_path")))
        same_hash(suite.get("manifest_sha256"), manifest_hash, "manifest")
        need(normalized(manifest) == normalized(suite["manifest"]), "manifest snapshot disagrees with embedded manifest")
        entries = arr(suite.get("scenarios"), "suite.scenarios")
        mapped = {}
        for entry in entries:
            obj(entry, "suite.scenario")
            key = entry.get("id")
            need(isinstance(key, str) and key in ids and key not in mapped, "suite: unknown/duplicate scenario id")
            mapped[key] = entry
        prov = obj(suite.get("provenance"), "provenance")
        files, plan, indexed = {}, {}, {}
        initial_identity = None
        try:
            prov, files, plan, indexed = provenance(suite, path.parent, report)
        except (EvidenceError, OSError, UnicodeError, ValueError) as exc:
            report["errors"].append(str(exc))
        try:
            package_correspondence(suite.get("package"), files, path.parent)
            report["package_integrity"] = "verified"
            initial_identity = preflight(suite, prov)
            report["preflight_integrity"] = "verified"
            report["runtime_identity_key"] = initial_identity["identity_key"]
        except (EvidenceError, OSError, UnicodeError, ValueError) as exc:
            report["errors"].append(str(exc))
        if suite.get("errors"):
            report["errors"].append("Suite collection reports errors; see input_suite.errors.")
        if "status" in suite and suite["status"] != "collected":
            report["errors"].append("Suite was not fully collected: " + str(suite["status"]))
        previous_at = initial_identity["caps_at"] if initial_identity else None
        for scene in scenes:
            expected = dict(scene, suite_id=suite["suite_id"], suite_script_id=SUITE_ID)
            if not files:
                result = {"id": scene["id"], "type": scene["type"], "status": "insufficient",
                          "errors": ["Cannot validate capture without verified provenance."],
                          "matching": {"status": "not_evaluated", "pair_count": 0, "pairs": []}, "candidates": []}
            else:
                result = analyze_scenario(mapped.get(scene["id"]), expected, suite, path.parent,
                                          prov, files, plan, indexed, report["errors"], initial_identity, previous_at)
                if result.get("postflight_observed_at"):
                    previous_at = timestamp(result["postflight_observed_at"], "scenario.postflight.observed_at")
            report["scenarios"].append(result)
        if not report["errors"] and all(x["status"] == "sufficient" for x in report["scenarios"]):
            report["status"] = "sufficient"
    except (EvidenceError, OSError, UnicodeError, ValueError, TypeError, RecursionError) as exc:
        report["errors"].append(str(exc))
    report["summary"] = {"scenario_count": len(report["scenarios"]),
                         "sufficient_count": sum(s["status"] == "sufficient" for s in report["scenarios"])}
    return report


def render_markdown(report):
    def safe(value):
        return str(value).replace("\\", "\\\\").replace("|", "\\|").replace("`", "'").replace("\r", " ").replace("\n", " ")
    lines = ["# Forward suite offline analysis", "", "Evidence status: **" + report["status"] + "**.",
             "Business success and message-ID semantics: **not established**.", "",
             "Suite: `" + safe(report.get("suite_id", "unknown")) + "`", "",
             "Expected identities: capture script, suite script, probe build and package 04.",
             "Package validation: " + report.get("package_integrity", "not_established") +
             "; preflight validation: " + report.get("preflight_integrity", "not_established") + ".", "",
             "Capabilities binary_identity concerns the target Weixin.dll file. Runtime probe DLL file "
             "hashes must equal the package 04 DLL; mapped headers must match. Seven packaged tools "
             "must equal archived provenance. These checks do not attest runtime memory.", "",
             "Source lookup: " + ("required (default)" if report.get("lookup_source", True) else "explicit structure-only mode") + ".", ""]
    for error in report["errors"]:
        lines.append("- " + safe(error))
    for s in report["scenarios"]:
        lines.extend(["", "## " + safe(s["id"]), "", "Status: **" + s["status"] + "**.", "",
                      "Pair status: " + s["matching"]["status"] + "; pairs=" + str(s["matching"]["pair_count"]) + ".", ""])
        for error in s.get("errors", []) + s.get("lookup_notes", []):
            lines.append("- " + safe(error))
        if "source_lookup_status" in s:
            lines.extend(["", "Database lookup: " + safe(s["source_lookup_status"]) + "."])
        lines.extend(["", "Fresh scenario preflight: " + s.get("preflight_integrity", "not_established") + "."])
        lines.extend(["", "Post-window identity: " + s.get("postflight_integrity", "not_established") + "."])
        for pair in s["matching"]["pairs"]:
            lines.extend(["", "Record " + str(pair["record_index"]) + ", UI seq " + str(pair["ui_seq"]) +
                          " / service seq " + str(pair["service_seq"]) + ": `" + pair["hex"] + "`."])
            lines.append("Ordering: " + pair.get("ordering_status", "not_established") +
                         "; tick check: " + pair.get("tick_check", "unavailable") + ".")
            for error in pair.get("ordering_errors", []):
                lines.append("- " + safe(error))
        if s.get("candidates"):
            lines.extend(["", "All byte-aligned u32/u64 little-endian raw offset candidates; no semantic proof.", "",
                          "| UI dump offset | Service descriptor offset | Encoding | Decimal string | Equal to |",
                          "| --- | --- | --- | --- | --- |"])
            for c in s["candidates"]:
                lines.append("| " + " | ".join(safe(v) for v in (c["ui_dump_offset"], c["service_descriptor_offset"],
                             c["encoding"], c["decimal"], "; ".join(c["equal_to"]) or "none")) + " |")
    lines.extend(["", "## Evidence limits", ""] + ["- " + x for x in LIMITATIONS])
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", required=True, type=Path)
    parser.add_argument("--output-directory", required=True, type=Path)
    args = parser.parse_args(argv)
    report = analyze_suite(args.suite)
    try:
        outputs = [args.output_directory / ("forward-suite-analysis." + ext) for ext in ("json", "md")]
        inputs = {args.suite.resolve()}
        suite = report.get("input_suite", {})
        base = args.suite.resolve().parent
        if suite.get("manifest_path"):
            inputs.add(resolve(base, suite["manifest_path"]))
        package = suite.get("package", {})
        if isinstance(package, dict):
            for key in ("metadata_path", "dll_path"):
                if package.get(key):
                    inputs.add(resolve(base, package[key]))
            if package.get("directory"):
                inputs.update(resolve(base, package["directory"]) / "tools" / n for n in PACKAGE_TOOLS)
        prov = suite.get("provenance", {})
        refs = []
        for value in (prov.get("files") if isinstance(prov, dict) else None, suite.get("scenarios")):
            if isinstance(value, list):
                refs.extend(value)
        for item in refs:
            if isinstance(item, dict):
                for key in ("path", "capture_path"):
                    if item.get(key):
                        inputs.add(resolve(base, item[key]))
                for artifact in item.get("artifacts", []):
                    if isinstance(artifact, dict) and artifact.get("path"):
                        inputs.add(resolve(base, artifact["path"]))
        for out in outputs:
            need(out.resolve() not in inputs and not any(out.exists() and p.exists() and out.samefile(p) for p in inputs), "output would overwrite an input evidence file")
        need(outputs[0].resolve() != outputs[1].resolve() and not
             (outputs[0].exists() and outputs[1].exists() and outputs[0].samefile(outputs[1])),
             "report outputs must not alias one another")
        args.output_directory.mkdir(parents=True, exist_ok=True)
        outputs[0].write_text(json.dumps(report, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
        outputs[1].write_text(render_markdown(report), encoding="utf-8")
    except (OSError, EvidenceError, ValueError, TypeError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(json.dumps({"status": report["status"], "outputs": [str(p.resolve()) for p in outputs]}))
    return 0 if report["status"] == "sufficient" else 1


if __name__ == "__main__":
    sys.exit(main())
