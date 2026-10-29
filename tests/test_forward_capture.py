"""stdlib-only tests; run with python -B -m unittest discover -s tests -p test_forward_capture.py -v."""

import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import sys
import unittest
from unittest import mock


# Importing the verifier must not leave __pycache__ behind, even without -B.
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("inspect_forward_capture", ROOT / "tools" / "inspect_forward_capture.py")
inspector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(inspector)
FIXTURE = ROOT / "capture" / "20261028-155804" / "forward-capture-20261028-155804-4159.json"


def put(data, offset, value, size=8):
    data[offset:offset + size] = value.to_bytes(size, "little")


def qwords(data):
    return [{"off": off, "v": str(int.from_bytes(data[off:off + 8], "little"))}
            for off in range(0, min(len(data), 64), 8)]


def inline(data, offset, value=b"filehelper", capacity=15):
    data[offset:offset + 32] = bytes(32)
    data[offset:offset + len(value)] = value
    put(data, offset + 16, len(value))
    put(data, offset + 24, capacity)


def make_capture(base=0x7FFF1F8D0000, published_start=0, stale_events=False):
    size = 0xAF0E000
    events = []
    for i, rva in enumerate(inspector.POINTS):
        reg, dump_size, follow_size = inspector.PROFILE[rva]
        dump = bytearray(dump_size)
        follow = bytearray(follow_size)
        if i < 2:
            put(dump, 0, 0x230000)
            put(dump, 8, 1)
            for off in (0, 8, 16):
                put(follow, off, 0x240000)
            follow[24:26] = b"\x01\x01"
            # Intentional allocator residue, never map payload.
            follow[26:42] = b"RESIDUE_NOT_DATA"
            if i == 1:
                put(dump, 16, 4593315984810359949)
        else:
            for off, value in ((0, 0x250000), (8, 0x250010), (16, 0x250010)):
                put(dump, off, value)
            put(follow, 0, base + 0x84ECF58)
            put(follow, 0x38, 0x260000)
            put(follow, 0x48, 54)
            put(follow, 0x50, 70)
            inline(follow, 0xB0)
            put(follow, 0xD8, base + 0x81D14A8)
            put(follow, 0xE0, 49, 4)
            put(follow, 0xE4, 5, 4)
        arguments = [0x100000 + n * 0x100 for n in range(4)]
        ret_rva = 0x21626E7
        stack = bytearray(256)
        put(stack, 0, base + ret_rva)
        event = {"seq": published_start + i + 1, "rva": rva, "rva_hex": hex(rva),
                 "rip_hex": hex(base + rva), "rsp_hex": "0x10000",
                 "ret": base + ret_rva, "ret_hex": hex(base + ret_rva),
                 "ret_rva": ret_rva, "ret_valid": True,
                 "register_scope": "probe_site", "capture_site": "function_entry",
                 "object_reg": reg, "object_hex": hex(arguments[reg - 1]),
                 "registers_hex": {r: hex(v) for r, v in zip(inspector.REGISTERS, arguments)},
                 "dump_hex": dump.hex(), "dump_len": dump_size, "dump_qwords": qwords(dump),
                 "follow_hex": follow.hex(), "follow_len": follow_size,
                 "stack_hex": stack.hex(), "stack_kind": "raw_stack_scan_not_unwind",
                 "stack_rvas": [ret_rva], "stack_scan_rvas": [ret_rva],
                 "str_buf": 0, "str_cap": 0, "str_got": 0, "str_len": 0, "str_hex": "",
                 "tid": 10068, "t": 4226511359}
        event.update({f"a{n}": value for n, value in enumerate(arguments, 1)})
        events.append(event)
    scenario = {"scenario": "C_forward", "capture_status": "success", "arm_status": "success",
                "trace_complete": True, "errors": [], "warnings": [],
                "register_scope": "probe_site", "stack_kind": "raw_stack_scan_not_unwind",
                "trace_schema_version": 2, "image_base": base, "image_size": size,
                "hit_count": 3, "events": events,
                "armed_detail": [{"rva": rva, "ok": True, "dump": profile[1]}
                                 for rva, profile in inspector.PROFILE.items()]}
    capture = {"schema_version": 3, "scenarios": [scenario]}
    synchronize(capture, published_start=published_start)
    if stale_events:
        # Prior-window events may be from another preset; do not apply the
        # current Forward points/body profile or count these as window evidence.
        stale = copy.deepcopy(events[1])
        stale.update(seq=published_start, rva=0x60A0A0, rva_hex="0x60A0A0",
                     rip_hex=hex(base + 0x60A0A0))
        scenario["preflight"].update(count=1, events=[stale])
        sync_requests(capture)
    return capture


def synchronize(capture, published_start=None):
    """Regenerate redundant recording representations after intentional mutations."""
    s = capture["scenarios"][0]
    previous = s.get("preflight", {})
    if published_start is None:
        published_start = previous.get("published", 0)
    baseline = {"schema_version": 2, "image_base": s["image_base"], "image_size": s["image_size"],
                "busy": False, "consuming": True, "dropped": 0, "skipped": 0,
                "reader_skipped_total": 0, "count": 0, "events": [], "published": published_start}
    s["preflight"] = copy.deepcopy(baseline)
    s["preflight"]["events"] = copy.deepcopy(previous.get("events", []))
    s["preflight"]["count"] = len(s["preflight"]["events"])
    response = dict(copy.deepcopy(baseline), count=len(s["events"]), events=copy.deepcopy(s["events"]),
                    published=max(e["seq"] for e in s["events"]))
    s["trace_batches"] = [{"response": response, "raw_json": json.dumps(response)}]
    sync_requests(capture)


def sync_requests(capture):
    s = capture["scenarios"][0]
    s["requests"] = [{"method": "GET", "endpoint": "/wxcx/probe/trace?limit=20", "ok": True,
                      "raw_json": json.dumps(r)}
                     for r in [s["preflight"]] + [b["response"] for b in s["trace_batches"]]]


def mutate_bytes(capture, event_index, field, offset, value, size=8):
    event = capture["scenarios"][0]["events"][event_index]
    data = bytearray.fromhex(event[field + "_hex"])
    put(data, offset, value, size)
    event[field + "_hex"] = data.hex()
    if field == "dump":
        event["dump_qwords"] = qwords(data)
    synchronize(capture)


class ForwardCaptureTests(unittest.TestCase):
    def setUp(self):
        self.capture = make_capture()

    def rejected(self, fragment, capture=None):
        report = inspector.verify_capture(self.capture if capture is None else capture)
        self.assertEqual(report["status"], "rejected", report)
        self.assertIn(fragment, "\n".join(report["errors"]))
        return report

    def test_valid_structure_and_evidence_limits(self):
        before = copy.deepcopy(self.capture)
        r = inspector.verify_capture(self.capture)
        self.assertEqual(r["status"], "verified", r["errors"])
        self.assertEqual(self.capture, before)  # pure API
        self.assertEqual(r["business_success"], "not_established")
        self.assertEqual(r["integrity"]["sequences"], [1, 2, 3])
        e = r["observations"][2]
        self.assertEqual(e["vector"]["count"], 1)
        self.assertEqual(e["vector"]["element_bytes"], "not_captured")
        self.assertEqual(e["body"]["string_0xB0"]["value"], "filehelper")
        self.assertEqual(e["body"]["observed_u32"], 49)
        self.assertEqual(e["body"]["observed_u32_0xE4"], 5)
        self.assertEqual(e["body"]["semantic_candidates"]["status"], "candidates_only")
        self.assertEqual(e["body"]["source_dto"]["identity_status"], "not_captured")
        self.assertEqual(e["body"]["source_dto"]["identity_body_offset"], "0x190")
        self.assertEqual(r["observations"][0]["selection_context"]["observed_qword"], "0x0")

    def test_heap_payload_missing_is_not_captured_no_dereference(self):
        # A plausible host address or even an address inside the captured body
        # is never permission to read memory or infer the heap string value.
        mutate_bytes(self.capture, 2, "follow", 0x38, id(self))
        r = inspector.verify_capture(self.capture)
        self.assertEqual(r["status"], "verified", r["errors"])
        heap = r["observations"][2]["body"]["string_0x38"]
        self.assertEqual((heap["status"], heap["length"], heap["capacity"]), ("not_captured", 54, 70))
        self.assertNotIn("value", heap)

    def test_sentinel_residue_is_ignored(self):
        baseline = inspector.verify_capture(self.capture)
        for index in (0, 1):
            e = self.capture["scenarios"][0]["events"][index]
            data = bytearray.fromhex(e["follow_hex"])
            data[26:] = b"\xff" * (len(data) - 26)
            e["follow_hex"] = data.hex()
        synchronize(self.capture)
        changed = inspector.verify_capture(self.capture)
        self.assertEqual(changed, baseline)
        self.assertNotIn("RESIDUE", json.dumps(changed))
        self.assertNotIn("RESIDUE", inspector.render_markdown(changed))

    def test_nonzero_context_is_an_observation_not_other_path_proof(self):
        mutate_bytes(self.capture, 0, "dump", 0x38, 123)
        r = inspector.verify_capture(self.capture)
        self.assertEqual(r["status"], "verified", r["errors"])
        self.assertFalse(r["observations"][0]["selection_context"]["observed_zero"])

    def test_truncated_snapshots(self):
        for index in range(3):
            for field in ("dump", "follow", "stack"):
                with self.subTest(index=index, field=field):
                    c = make_capture()
                    e = c["scenarios"][0]["events"][index]
                    e[field + "_hex"] = e[field + "_hex"][:-2]
                    synchronize(c)
                    self.rejected("exactly", c)

    def test_truncation_with_adjusted_declared_length(self):
        e = self.capture["scenarios"][0]["events"][2]
        e["follow_hex"] = e["follow_hex"][:-2]
        e["follow_len"] = 255
        synchronize(self.capture)
        self.rejected("truncated")

    def test_wrong_body_vtable(self):
        mutate_bytes(self.capture, 2, "follow", 0, 0x7FFF1F8D0000 + 0x84ECF60)
        self.rejected("body.vtable")

    def test_wrong_embedded_vtable(self):
        mutate_bytes(self.capture, 2, "follow", 0xD8, 0)
        self.rejected("embedded_vtable")

    def test_invalid_utf8(self):
        mutate_bytes(self.capture, 2, "follow", 0xB0, 0xFF, 1)
        self.rejected("invalid UTF-8")

    def test_inline_length_exceeds_capacity(self):
        mutate_bytes(self.capture, 2, "follow", 0xC0, 16)
        self.rejected("length exceeds capacity")

    def test_heap_length_exceeds_capacity(self):
        mutate_bytes(self.capture, 2, "follow", 0x48, 71)
        self.rejected("length exceeds capacity")

    def test_heap_null_pointer(self):
        mutate_bytes(self.capture, 2, "follow", 0x38, 0)
        self.rejected("invalid heap buffer range")

    def test_inline_terminator(self):
        mutate_bytes(self.capture, 2, "follow", 0xBA, 65, 1)
        self.rejected("terminator")

    def test_utf8_length_is_bytes(self):
        e = self.capture["scenarios"][0]["events"][2]
        data = bytearray.fromhex(e["follow_hex"])
        inline(data, 0xB0, "助手".encode("utf-8"))
        e["follow_hex"] = data.hex()
        synchronize(self.capture)
        r = inspector.verify_capture(self.capture)
        self.assertEqual(r["status"], "verified", r["errors"])
        self.assertEqual(r["observations"][2]["body"]["string_0xB0"]["length"], 6)

    def test_wrong_vector_spans(self):
        for offset, value, message in ((8, 0x25000F, "stride 16"), (16, 0x250021, "stride 16"),
                                       (8, 0x24FFFF, "begin <= end <= cap"),
                                       (16, 0x24FFFF, "begin <= end <= cap"),
                                       (8, 0x250000, "exactly one")):
            with self.subTest(offset=offset, value=value):
                c = make_capture()
                mutate_bytes(c, 2, "dump", offset, value)
                self.rejected(message, c)

    def test_float_addresses_and_bools_are_rejected(self):
        for value in (9007199254740992.0, True, -1, 1 << 64):
            with self.subTest(value=value):
                c = make_capture()
                c["scenarios"][0]["events"][0]["a1"] = value
                synchronize(c)
                self.rejected("integer", c)
        for literal in ("9007199254740993.0", "9.007199254740993e15", "NaN", "Infinity"):
            with self.subTest(literal=literal), self.assertRaises(inspector.ValidationError):
                inspector.loads_exact('{"address": ' + literal + '}')

    def test_integer_precision_above_2_to_53(self):
        exact = 9007199254740993
        self.assertEqual(inspector.loads_exact('{"n":9007199254740993}')["n"], exact)
        self.assertEqual(inspector.uint(str(exact), "n"), exact)
        self.assertEqual(inspector.uint(hex(exact), "n"), exact)
        c = make_capture(base=exact)
        r = inspector.verify_capture(inspector.loads_exact(json.dumps(c)))
        self.assertEqual(r["status"], "verified", r["errors"])
        self.assertEqual(r["image_base"], hex(exact).upper().replace("0X", "0x"))
        # Decimal strings and raw JSON integer tokens above 2**53 agree exactly.
        c["scenarios"][0]["trace_batches"][0]["raw_json"] = json.dumps(c["scenarios"][0]["trace_batches"][0]["response"]).replace('"4593315984810359949"', '4593315984810359949')
        self.assertEqual(inspector.verify_capture(c)["status"], "verified")

    def test_rounded_qword_is_rejected(self):
        e = self.capture["scenarios"][0]["events"][1]
        e["dump_qwords"][2]["v"] = int(float(e["dump_qwords"][2]["v"]))
        synchronize(self.capture)
        self.rejected("dump_qwords disagrees")

    def test_sequence_gap_duplicate_reorder(self):
        for seqs in ((1, 3, 4), (1, 1, 3), (2, 1, 3)):
            with self.subTest(seqs=seqs):
                c = make_capture()
                for e, seq in zip(c["scenarios"][0]["events"], seqs):
                    e["seq"] = seq
                synchronize(c)
                self.rejected("sequence:", c)

    def test_nonzero_preflight_published_window_101_to_103(self):
        c = make_capture(published_start=100)
        before = copy.deepcopy(c)
        r = inspector.verify_capture(inspector.loads_exact(json.dumps(c)))
        self.assertEqual(r["status"], "verified", r["errors"])
        self.assertEqual(c, before)
        q = r["integrity"]
        self.assertEqual(q["sequences"], [101, 102, 103])
        self.assertEqual((q["published_start"], q["published_expected_final"], q["published_final"]), (100, 103, 103))
        self.assertEqual((q["event_count"], q["preflight_stale_event_count"]), (3, 0))
        s = c["scenarios"][0]
        self.assertEqual(json.loads(s["requests"][0]["raw_json"])["published"], 100)
        b = s["trace_batches"][0]
        self.assertEqual(b["response"]["published"], 103)
        self.assertEqual(json.loads(b["raw_json"])["events"], s["events"])
        self.assertIn("Preflight published=100; expected window seq 101..103", inspector.render_markdown(r))

    def test_nonzero_preflight_sequence_gap(self):
        c = make_capture(published_start=100)
        for e, seq in zip(c["scenarios"][0]["events"], (101, 103, 104)):
            e["seq"] = seq
        synchronize(c)
        r = self.rejected("sequence: expected ordered contiguous seq 101..103", c)
        self.assertEqual(r["integrity"]["published_start"], 100)
        self.assertIn("final published count", "\n".join(r["errors"]))

    def test_stale_preflight_events_excluded_from_window(self):
        c = make_capture(published_start=100, stale_events=True)
        # Parsed decimal-string qword and exact raw JSON integer must agree.
        s = c["scenarios"][0]
        s["requests"][0]["raw_json"] = s["requests"][0]["raw_json"].replace(
            '"4593315984810359949"', '4593315984810359949')
        r = inspector.verify_capture(c)
        self.assertEqual(r["status"], "verified", r["errors"])
        self.assertEqual(r["integrity"]["preflight_stale_event_count"], 1)
        self.assertEqual(r["integrity"]["event_count"], 3)
        self.assertEqual([e["seq"] for e in r["observations"]], [101, 102, 103])
        self.assertNotIn("0x60A0A0", [e["point_rva"] for e in r["observations"]])
        self.assertIn("1 stale preflight events excluded", inspector.render_markdown(r))

    def test_nonzero_baseline_raw_and_parsed_metadata_must_match(self):
        for location in ("preflight", "batch"):
            with self.subTest(location=location):
                c = make_capture(published_start=100, stale_events=True)
                s = c["scenarios"][0]
                if location == "preflight":
                    raw = json.loads(s["requests"][0]["raw_json"])
                    raw["published"] = 99
                    raw["events"][0]["seq"] = 99
                    s["requests"][0]["raw_json"] = json.dumps(raw)
                    self.rejected("trace request copies disagree", c)
                else:
                    b = s["trace_batches"][0]
                    raw = json.loads(b["raw_json"])
                    raw["published"] = 104
                    b["raw_json"] = json.dumps(raw)
                    self.rejected("raw_json and response disagree", c)

    def test_nonzero_final_published_and_monotonicity(self):
        for final in (3, 104):
            with self.subTest(final=final):
                c = make_capture(published_start=100)
                b = c["scenarios"][0]["trace_batches"][0]
                b["response"]["published"] = final
                b["raw_json"] = json.dumps(b["response"])
                sync_requests(c)
                self.rejected("seq exceeds published" if final == 3 else "final published count", c)
        c = make_capture(published_start=100)
        s = c["scenarios"][0]
        response = dict(copy.deepcopy(s["preflight"]), published=99)
        s["trace_batches"].insert(0, {"response": response, "raw_json": json.dumps(response)})
        sync_requests(c)
        self.rejected("published counter decreased", c)

    def test_preflight_counter_range_and_render_on_rejection(self):
        c = make_capture(published_start=100, stale_events=True)
        c["scenarios"][0]["preflight"]["events"][0]["seq"] = 101
        sync_requests(c)
        r = self.rejected("seq exceeds published", c)
        self.assertIn("Preflight baseline could not be validated", inspector.render_markdown(r))
        c = make_capture()
        c["scenarios"][0]["preflight"]["published"] = inspector.U64_MAX
        sync_requests(c)
        self.rejected("exceeds uint64 range", c)

    def test_busy_drop_skip_are_reported(self):
        for key, value, fragment in (("busy", True, "busy_observations"), ("dropped", 2, "dropped_max"),
                                     ("skipped", 1, "skipped_max"),
                                     ("reader_skipped_total", 1, "reader_skipped_total_max")):
            with self.subTest(key=key):
                c = make_capture()
                batch = c["scenarios"][0]["trace_batches"][0]
                batch["response"][key] = value
                batch["raw_json"] = json.dumps(batch["response"])
                sync_requests(c)
                r = self.rejected(fragment, c)
                self.assertIn("observations", r)
                if key != "busy":
                    self.assertEqual(r["integrity"][fragment], value)  # not multiplied by copies

    def test_busy_in_only_raw_copy_cannot_be_hidden(self):
        batch = self.capture["scenarios"][0]["trace_batches"][0]
        raw = json.loads(batch["raw_json"])
        raw["busy"] = True
        batch["raw_json"] = json.dumps(raw)
        self.rejected("raw_json and response disagree")

    def test_point_register_and_scope_checks(self):
        for key, value, fragment in (("object_reg", 1, "object_reg"),
                                     ("register_scope", "caller_entry", "register_scope"),
                                     ("capture_site", "instruction", "function_entry"),
                                     ("object_hex", "0x1234", "selected probe register"),
                                     ("rva", 0x60A0A0, "outside the supported")):
            with self.subTest(key=key):
                c = make_capture()
                c["scenarios"][0]["events"][0][key] = value
                synchronize(c)
                self.rejected(fragment, c)

    def test_strict_hex(self):
        for value in ("0", "GG", "00 00", "0x00", 0):
            with self.subTest(value=value), self.assertRaises(inspector.ValidationError):
                inspector.hex_bytes(value, "hex")
        for value in ("123", "0x", "0x10000000000000000", "0x-1", 1.0):
            with self.subTest(value=value), self.assertRaises(inspector.ValidationError):
                inspector.address(value, "address")

    def test_integer_and_string_range_limits(self):
        for value in ("9" * 5000, "0x" + "F" * 17, -1, 1 << 64, "18446744073709551616"):
            with self.subTest(value=str(value)[:30]), self.assertRaises(inspector.ValidationError):
                inspector.uint(value, "integer")
        self.assertEqual(inspector.uint(str((1 << 64) - 1), "integer"), (1 << 64) - 1)
        mutate_bytes(self.capture, 2, "follow", 0x50, (1 << 64) - 1)
        self.rejected("heap buffer range")

    def test_trace_counts_and_published_are_checked(self):
        for key, value, fragment in (("count", 2, "trace count mismatch"),
                                     ("published", 2, "seq exceeds published"),
                                     ("published", 4, "final published count")):
            with self.subTest(key=key, value=value):
                c = make_capture()
                b = c["scenarios"][0]["trace_batches"][0]
                b["response"][key] = value
                b["raw_json"] = json.dumps(b["response"])
                sync_requests(c)
                self.rejected(fragment, c)

    def test_preflight_busy_is_checked(self):
        self.capture["scenarios"][0]["preflight"]["busy"] = True
        sync_requests(self.capture)
        self.rejected("busy_observations")

    def test_probe_arming_is_checked(self):
        self.capture["scenarios"][0]["armed_detail"][0]["dump"] = 32
        self.rejected("missing/mismatched probe")

    def test_out_of_range_image_and_schema(self):
        for key, value, fragment in (("image_base", (1 << 64) - 1, "invalid image range"),
                                     ("trace_schema_version", 1, "trace schema 2")):
            with self.subTest(key=key):
                c = make_capture()
                c["scenarios"][0][key] = value
                self.rejected(fragment, c)
        self.capture["schema_version"] = 2
        self.rejected("schema 3")

    def test_duplicate_keys_and_malformed_json(self):
        for text in ('{"seq":1,"seq":2}', '{"seq":', '[1,]', '{"n":' + '9' * 5000 + '}'):
            with self.subTest(text=text[:30]), self.assertRaises(inspector.ValidationError):
                inspector.loads_exact(text)

    def test_redundant_event_and_request_copies(self):
        batch = self.capture["scenarios"][0]["trace_batches"][0]
        batch["response"]["events"][0]["tid"] = 42
        batch["raw_json"] = json.dumps(batch["response"])
        sync_requests(self.capture)
        self.rejected("batch events disagree")
        c = make_capture()
        c["scenarios"][0]["requests"].pop()
        self.rejected("trace request copies disagree", c)

    def test_output_default_has_no_file_writes(self):
        stdout = io.StringIO()
        with mock.patch.object(Path, "read_text", return_value=json.dumps(self.capture)), \
                mock.patch.object(Path, "write_text") as writer, contextlib.redirect_stdout(stdout):
            self.assertEqual(inspector.main(["example.json"]), 0)
        writer.assert_not_called()
        self.assertEqual(json.loads(stdout.getvalue())["status"], "verified")

    def test_explicit_outputs_and_input_collision(self):
        with mock.patch.object(Path, "read_text", return_value=json.dumps(self.capture)), \
                mock.patch.object(Path, "write_text") as writer:
            self.assertEqual(inspector.main(["example.json", "--json-out", "report.json", "--md-out", "report.md"]), 0)
        self.assertEqual(writer.call_count, 2)
        self.assertEqual(json.loads(writer.call_args_list[0].args[0])["status"], "verified")
        md = writer.call_args_list[1].args[0]
        for fragment in ("not established", "not_captured", "49", "5", "0x190", "other paths are not excluded"):
            self.assertIn(fragment, md)
        with mock.patch.object(Path, "read_text") as reader, mock.patch.object(Path, "write_text") as writer, \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(inspector.main(["same.json", "--json-out", "same.json"]), 2)
        reader.assert_not_called()
        writer.assert_not_called()

    def test_cli_invalid_json_and_missing_input(self):
        with mock.patch.object(Path, "read_text", return_value="{"), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(inspector.main(["broken.json"]), 1)
        self.assertEqual(json.loads(output.getvalue())["status"], "rejected")
        with mock.patch.object(Path, "read_text", side_effect=OSError("missing")), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(inspector.main(["missing.json"]), 2)

    @unittest.skipUnless(FIXTURE.is_file(), "real fixture is not present in this checkout")
    def test_real_runtime_155804_fixture(self):
        r = inspector.verify_capture(inspector.loads_exact(FIXTURE.read_text(encoding="utf-8-sig")))
        self.assertEqual(r["status"], "verified", r["errors"])
        self.assertEqual(r["integrity"]["event_count"], 3)
        self.assertEqual(r["integrity"]["sequences"], [1, 2, 3])
        self.assertEqual(r["integrity"]["trace_batch_count"], 54)
        self.assertEqual(r["integrity"]["published_start"], 0)
        self.assertEqual(r["integrity"]["published_final"], 3)
        self.assertEqual(r["integrity"]["preflight_stale_event_count"], 0)
        self.assertEqual([e["point_rva"] for e in r["observations"]], ["0x2161FC0", "0x43ACC80", "0x1649E60"])
        self.assertEqual(r["observations"][0]["selection_context"]["observed_qword"], "0x0")
        e = r["observations"][2]
        self.assertEqual(e["follow_bytes"], 256)
        self.assertEqual(e["vector"]["count"], 1)
        self.assertEqual(e["vector"]["stride"], 16)
        b = e["body"]
        self.assertEqual(b["vtable_rva"], "0x84ECF58")
        self.assertEqual(b["embedded_vtable_rva"], "0x81D14A8")
        self.assertEqual((b["string_0xB0"]["value"], b["string_0xB0"]["length"], b["string_0xB0"]["capacity"]),
                         ("filehelper", 10, 15))
        self.assertEqual((b["string_0x38"]["length"], b["string_0x38"]["capacity"], b["string_0x38"]["status"]),
                         (54, 70, "not_captured"))
        self.assertEqual((b["observed_u32"], b["observed_u32_0xE4"]), (49, 5))
        self.assertEqual(b["source_dto"]["identity_status"], "not_captured")
        for counter in ("busy_observations", "dropped_max", "skipped_max", "reader_skipped_total_max"):
            self.assertEqual(r["integrity"][counter], 0)


if __name__ == "__main__":
    unittest.main()
