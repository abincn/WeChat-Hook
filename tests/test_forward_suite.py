"""Offline contract tests: python -B -m unittest discover -s tests -p test_forward_suite.py -v.

Only temporary synthetic artifacts are changed. No probe, WeChat, install or send
endpoint is contacted. Redundant raw trace copies are regenerated after mutations
unless a test intentionally tests disagreement.
"""
import copy
import hashlib
import http.server
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import shutil
import sys
import tempfile
import threading
import unittest
import urllib.parse

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
ANALYZER = ROOT / "tools" / "analyze_forward_suite.py"
CAP_ID = "FWD-CAP-20261028-04-R3"
SUITE_ID = "FWD-SUITE-20261028-04-R3"
BUILD_ID = "FWD-PROBE-20261028-04"
BASE = 0x180000000
POINTS = (0x2161FC0, 0x16BDF60, 0x3689B10, 0x2160460)
TARGET_SHA = "F487E4F56930456A25FB0D7B058C77E2DCD364E268D49BDFFF4DC0E3BE26BA36"
PIPELINE = ("capture_forward_internal.ps1", "oneclick_forward.ps1",
            "forward-analysis-common.ps1", "forward-internal-plan.json")
PACKAGE_FILES = PIPELINE + ("capture_forward_suite.ps1", "analyze_forward_suite.py", "wxcx-common.ps1")


def runtime_identity(probe_sha="B" * 64):
    # Target Weixin file has an expected digest; the loaded probe file is only
    # observed. Neither digest attests to every byte of runtime process memory.
    target = dict(path="X:/offline/Weixin.dll", file_bytes=183094832,
                  expected_sha256=TARGET_SHA, actual_sha256=TARGET_SHA,
                  hash_scope="module_file_not_runtime_memory", mapped_headers_match=True,
                  verified=True, status="hashed")
    probe = dict(path="X:/offline/version.dll", actual_sha256=probe_sha, mapped_headers_match=True,
                 hash_scope="module_file_not_runtime_memory", status="hashed")
    return dict(probe_build_id=BUILD_ID, process_id=1234,
                process_start_filetime="134059104000000000", weixin=target, probe=probe)


def sha(data):
    return hashlib.sha256(data).hexdigest().upper()


def raw(value):
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"))


def write_json(path, value):
    path.write_text(raw(value), encoding="utf-8")
    return sha(path.read_bytes())


def sync_observation(observation):
    observation["raw_json"] = raw(observation["response"])
    observation["sha256"] = sha(observation["raw_json"].encode())


def package_metadata(bundle):
    pipeline = "\n".join(f"{n}:{sha((bundle / 'tools' / n).read_bytes())}" for n in PIPELINE)
    text = ("Package: wxcx-forward-codex-20261028-04-r3\n"
            f"Capture script ID: {CAP_ID}\nSuite script ID: {SUITE_ID}\n"
            f"DLL SHA256: {sha((bundle / 'version.dll').read_bytes())}\n"
            f"Pipeline SHA256: {sha(pipeline.encode())}\n")
    (bundle / "PACKAGE.txt").write_text(text, encoding="utf-8")
    return sha(pipeline.encode())


def trace(events, published):
    return dict(schema_version=2, image_base=BASE, image_size=0xAF0E000,
                busy=False, consuming=True, dropped=0, skipped=0,
                reader_skipped_total=0, count=len(events),
                events=copy.deepcopy(events), published=published)


def sync_trace(s):
    response = trace(s["events"], max((e["seq"] for e in s["events"]), default=100))
    s["hit_count"] = len(s["events"])
    s["trace_batches"] = [dict(response=response, raw_json=raw(response))]
    s["requests"] = [dict(method="GET", endpoint="/wxcx/probe/trace?limit=20",
                          ok=True, raw_json=raw(r)) for r in (s["preflight"], response)]


def event(rva, seq, dump=b"", follow=b"", offset=0):
    return dict(rva=rva, rva_hex=hex(rva), seq=seq, tid=7,
                rip_hex=hex(BASE + rva), capture_site="function_entry", ret_valid=True,
                register_scope="probe_site", object_reg={POINTS[0]: 3, POINTS[3]: 3}.get(rva, 2),
                a1=0x100000, a2=0x200000, a3=0x300000, a4=1,
                dump_hex=dump.hex(), dump_len=len(dump),
                follow_hex=follow.hex(), follow_len=len(follow), follow_read_offset=offset,
                stack_hex=bytes(256).hex(), stack_kind="raw_stack_scan_not_unwind")


class SuiteFixture:
    def __init__(self, directory):
        self.root = Path(directory)
        self.path = self.root / "suite.json"
        self.plan = json.loads((ROOT / "tools" / "forward-internal-plan.json").read_text())
        self.plan_path = self.root / "forward-internal-plan.json"
        self.plan_sha = write_json(self.plan_path, self.plan)
        self.script = self.root / "capture_forward_internal.ps1"
        self.script.write_text("# inert offline fixture\n", encoding="utf-8")
        self.script_sha = sha(self.script.read_bytes())
        for name in PACKAGE_FILES:
            if name in ("capture_forward_internal.ps1", "forward-internal-plan.json"):
                continue
            (self.root / name).write_text("# inert offline fixture\n", encoding="utf-8")
        pipeline_paths = [self.root / name for name in PIPELINE]
        files = [dict(path=str(p), sha256=sha(p.read_bytes()))
                 for p in (self.root / name for name in PACKAGE_FILES)]
        pipeline = "\n".join(f"{p.name}:{sha(p.read_bytes())}" for p in pipeline_paths)
        self.pipeline_sha = sha(pipeline.encode())
        bundle = self.root / "bundle"
        bundle_tools = bundle / "tools"
        bundle_tools.mkdir(parents=True, exist_ok=True)
        for p in (self.root / name for name in PACKAGE_FILES):
            shutil.copyfile(p, bundle_tools / p.name)
        dll = bundle / "version.dll"
        dll.write_bytes(b"inert offline package; never loaded")
        package_metadata = bundle / "PACKAGE.txt"
        package_metadata.write_text("Package: wxcx-forward-codex-20261028-04-r3\n"
                                    f"Capture script ID: {CAP_ID}\n"
                                    f"Suite script ID: {SUITE_ID}\n"
                                    f"DLL SHA256: {sha(dll.read_bytes())}\n"
                                    f"Pipeline SHA256: {self.pipeline_sha}\n", encoding="utf-8")
        runtime = runtime_identity(sha(dll.read_bytes()))
        caps = dict(code=0, binary_identity=copy.deepcopy(runtime["weixin"]), runtime_identity=runtime,
                    native_abi_verified=False)
        status = dict(ok=True, schema_version=2, probe_build_id=BUILD_ID,
                      runtime_identity=copy.deepcopy(runtime), features=dict(follow_read_offset=True))
        status_raw = raw(status)
        self.suite = dict(schema_version=1, suite_id="offline-suite", suite_script_id=SUITE_ID,
                          status="collected", lookup_source=False,
                          manifest=dict(scenarios=[]),
                          package=dict(expected_script_id=CAP_ID, expected_probe_build_id=BUILD_ID,
                                       expected_suite_script_id=SUITE_ID,
                                       verified=True, status="verified", directory=str(bundle),
                                       metadata_path=str(package_metadata), metadata_sha256=sha(package_metadata.read_bytes()),
                                       dll_path=str(dll), dll_sha256=sha(dll.read_bytes()),
                                       pipeline_sha256=self.pipeline_sha),
                          preflight=dict(status="success", raw_json=status_raw, response=status,
                                         observed_at="2026-10-28T00:00:00Z", method="GET",
                                         suite_id="offline-suite", plan_sha256=self.plan_sha,
                                         endpoint="http://127.0.0.1:30001/wxcx/probe/status",
                                         sha256=sha(status_raw.encode()),
                                         forward_capabilities=dict(status="success", raw_json=raw(caps),
                                                                   observed_at="2026-10-28T00:00:01Z", method="GET",
                                                                   endpoint="http://127.0.0.1:30001/wxcx/forward/capabilities",
                                                                   response=caps, sha256=sha(raw(caps).encode()))),
                          provenance=dict(plan_sha256=self.plan_sha,
                                          pipeline_sha256=self.pipeline_sha, files=files), scenarios=[])
        self.captures = []
        for i, kind in enumerate(("text", "image", "file", "link")):
            context = dict(id=f"{kind}-1", label=kind, type=kind,
                           source_msgsvrid=str(9007199254740993 + i * 2),
                           source_talker="source_chat", toid="filehelper", downloaded=True)
            self.suite["manifest"]["scenarios"].append(copy.deepcopy(context))
            context["suite_id"] = self.suite["suite_id"]
            context["suite_script_id"] = SUITE_ID
            identity_bytes = bytes((n + i + 1) % 256 for n in range(32))
            ui = bytearray(256)
            ui[0xB8:0xD8] = identity_bytes
            events = [event(POINTS[0], 101, bytes(ui)),
                      event(POINTS[1], 102, bytes(32), identity_bytes, 400),
                      event(POINTS[2], 103, bytes(32), bytes(256)),
                      event(POINTS[3], 104, bytes(96))]
            armed = []
            for point in self.plan["points"]:
                request = dict(point)
                request.pop("note", None)
                request["ms"] = 11000
                reply = dict(ok=True, rva=int(point["rva"], 16),
                             follow_read_offset=point.get("follow_read_offset", 0))
                armed.append(dict(rva=point["rva"], ok=True,
                                  request_json=raw(request), response_raw_json=raw(reply)))
            scenario = dict(scenario=context["id"], scenario_context=copy.deepcopy(context),
                            capture_status="success", arm_status="success", trace_complete=True,
                            errors=[], warnings=[], trace_schema_version=2,
                            image_base=BASE, image_size=0xAF0E000,
                            events=events, preflight=trace([], 100), armed_detail=armed,
                            requested_seconds=1, actual_window_ms=1000,
                            window_started_at=f"2026-10-28T00:00:{i*10+4:02d}Z",
                            window_ended_at=f"2026-10-28T00:00:{i*10+5:02d}Z")
            sync_trace(scenario)
            fresh_preflight = copy.deepcopy(self.suite["preflight"])
            fresh_preflight["scenario_id"] = context["id"]
            fresh_preflight["observed_at"] = f"2026-10-28T00:00:{i*10+2:02d}Z"
            fresh_preflight["forward_capabilities"]["observed_at"] = f"2026-10-28T00:00:{i*10+3:02d}Z"
            postflight = copy.deepcopy(fresh_preflight)
            postflight["phase"] = "post_window"
            postflight["observed_at"] = f"2026-10-28T00:00:{i*10+6:02d}Z"
            postflight["forward_capabilities"]["observed_at"] = f"2026-10-28T00:00:{i*10+7:02d}Z"
            capture = dict(schema_version=3, suite_id="offline-suite", suite_script_id=SUITE_ID,
                           scenario_context=copy.deepcopy(context),
                           probe_status_identity=copy.deepcopy(fresh_preflight),
                           capture_metadata=dict(script_id=CAP_ID, script_sha256=self.script_sha,
                                                 pipeline_sha256=self.pipeline_sha,
                                                 probe_plan_sha256=self.plan_sha,
                                                 suite_id="offline-suite", scenario_context=copy.deepcopy(context)),
                           probe_plan_json=self.plan_path.read_text(), scenarios=[scenario])
            path = self.root / f"capture-{kind}.json"
            self.captures.append(capture)
            self.suite["scenarios"].append(dict(id=context["id"], context=context,
                                               preflight=fresh_preflight,
                                               postflight=postflight,
                                               capture_path=str(path), capture_sha256="",
                                               status="captured", error=None))
        self.save()

    def save(self):
        manifest_path = self.root / "manifest.json"
        self.suite["manifest_path"] = str(manifest_path)
        self.suite["manifest_sha256"] = write_json(manifest_path, self.suite["manifest"])
        for entry, capture in zip(self.suite["scenarios"], self.captures):
            entry["capture_sha256"] = write_json(Path(entry["capture_path"]), capture)
        write_json(self.path, self.suite)

    def scenario(self, index=0):
        return self.captures[index]["scenarios"][0]


class ForwardSuiteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # An absent implementation is a failure, never a silently skipped suite.
        spec = importlib.util.spec_from_file_location("analyze_forward_suite_under_test", ANALYZER)
        cls.analyzer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.analyzer)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="forward-suite-offline-")
        self.addCleanup(self.temp.cleanup)
        self.fixture = SuiteFixture(self.temp.name)

    def analyze(self):
        self.fixture.save()
        return self.analyzer.analyze_suite(self.fixture.path)

    def test_exact_same_window_match_and_uint64_context(self):
        report = self.analyze()
        self.assertIsInstance(report, dict)
        diagnostics = report["errors"] + [s["errors"] for s in report["scenarios"]]
        self.assertEqual(report["status"], "sufficient", diagnostics)
        self.assertTrue(all(s["matching"]["status"] == "unique_match" and
                            s["matching"]["pair_count"] == 1 for s in report["scenarios"]))
        self.assertEqual(report.get("business_success", "not_established"), "not_established")
        self.assertEqual(self.fixture.suite["manifest"]["scenarios"][0]["source_msgsvrid"],
                         "9007199254740993")

    def assert_unverified(self, report):
        self.assertEqual(report["status"], "insufficient", report)

    def test_wrong_byte_is_not_match(self):
        s = self.fixture.scenario()
        e = s["events"][1]
        e["follow_hex"] = "FF" + e["follow_hex"][2:]
        sync_trace(s)
        self.assert_unverified(self.analyze())

    def test_worker_before_ui_equal_bytes_are_insufficient(self):
        record = self.fixture.scenario()
        record["events"][0], record["events"][1] = record["events"][1], record["events"][0]
        for seq, item in enumerate(record["events"], 101):
            item["seq"] = seq
        sync_trace(record)
        report = self.analyze()
        self.assert_unverified(report)
        matching = report["scenarios"][0]["matching"]
        self.assertEqual(matching["pair_count"], 1)
        self.assertEqual(matching["status"], "ordering_insufficient")
        self.assertEqual(matching["pairs"][0]["ordering_status"], "insufficient")
        self.assertGreater(matching["pairs"][0]["ui_seq"], matching["pairs"][0]["service_seq"])

    def test_tick_reversal_rejected_but_equal_or_later_ticks_allowed(self):
        for worker_tick in (19, 20, 21):
            with self.subTest(worker_tick=worker_tick):
                self.fixture = SuiteFixture(self.temp.name)
                record = self.fixture.scenario()
                record["events"][0]["t"] = 20
                record["events"][1]["t"] = worker_tick
                sync_trace(record)
                report = self.analyze()
                self.assertEqual(report["status"], "insufficient" if worker_tick < 20 else "sufficient")
                pair = report["scenarios"][0]["matching"]["pairs"][0]
                self.assertEqual(pair["tick_check"], "compared")
                self.assertEqual(pair["service_tick"], str(worker_tick))

    def test_missing_service_is_not_reliable_absence(self):
        s = self.fixture.scenario()
        s["events"] = [e for e in s["events"] if e["rva"] != POINTS[1]]
        for seq, e in enumerate(s["events"], 101):
            e["seq"] = seq
        sync_trace(s)
        self.assert_unverified(self.analyze())

    def test_duplicate_matching_candidate_is_ambiguous(self):
        s = self.fixture.scenario()
        extra = copy.deepcopy(s["events"][1])
        extra["seq"] = 105
        s["events"].append(extra)
        sync_trace(s)
        self.assert_unverified(self.analyze())

    def test_other_scenario_identity_cannot_supply_match(self):
        s = self.fixture.scenario()
        s["events"][1]["follow_hex"] = self.fixture.scenario(1)["events"][1]["follow_hex"]
        sync_trace(s)
        self.assert_unverified(self.analyze())

    def test_head256_and_wrong_offset_do_not_capture_identity_tail(self):
        for length, offset in ((256, 0), (32, 0), (31, 400)):
            with self.subTest(length=length, offset=offset):
                self.fixture = SuiteFixture(self.temp.name)
                s = self.fixture.scenario()
                e = s["events"][1]
                e.update(follow_hex=bytes(range(length)).hex(), follow_len=length,
                         follow_read_offset=offset)
                sync_trace(s)
                self.assert_unverified(self.analyze())

    def test_loss_partial_arm_and_incomplete_window(self):
        for field, value in (("trace_complete", False), ("arm_status", "partial"),
                             ("capture_status", "failed")):
            with self.subTest(field=field):
                self.fixture = SuiteFixture(self.temp.name)
                self.fixture.scenario()[field] = value
                self.assert_unverified(self.analyze())
        for counter in ("dropped", "skipped", "reader_skipped_total", "busy"):
            with self.subTest(counter=counter):
                self.fixture = SuiteFixture(self.temp.name)
                s = self.fixture.scenario()
                s["trace_batches"][0]["response"][counter] = True if counter == "busy" else 1
                response = s["trace_batches"][0]["response"]
                s["trace_batches"][0]["raw_json"] = raw(response)
                s["requests"][-1]["raw_json"] = raw(response)
                self.assert_unverified(self.analyze())

    def test_sequence_gap_and_raw_trace_disagreement(self):
        self.fixture.scenario()["events"][1]["seq"] = 999
        sync_trace(self.fixture.scenario())
        self.assert_unverified(self.analyze())
        self.fixture = SuiteFixture(self.temp.name)
        self.fixture.scenario()["trace_batches"][0]["raw_json"] = raw(trace([], 100))
        self.assert_unverified(self.analyze())

    def test_legacy_and_wrong_capture_script_version(self):
        for value in (None, "FWD-CAP-20261028-01", SUITE_ID):
            with self.subTest(value=value):
                self.fixture = SuiteFixture(self.temp.name)
                if value is None:
                    self.fixture.captures[0].pop("capture_metadata")
                else:
                    self.fixture.captures[0]["capture_metadata"]["script_id"] = value
                self.assert_unverified(self.analyze())

    def test_capture_hash_detects_post_capture_mutation(self):
        self.fixture.save()
        path = Path(self.fixture.suite["scenarios"][0]["capture_path"])
        path.write_bytes(path.read_bytes() + b" ")
        self.assert_unverified(self.analyzer.analyze_suite(self.fixture.path))

    def test_provenance_file_and_preflight_hash_integrity(self):
        self.fixture.script.write_text("# changed\n", encoding="utf-8")
        self.assert_unverified(self.analyze())
        self.fixture = SuiteFixture(self.temp.name)
        self.fixture.suite["preflight"]["sha256"] = "0" * 64
        self.assert_unverified(self.analyze())

    def test_package_bytes_and_manifest_snapshot_are_checked(self):
        self.fixture.save()
        dll = Path(self.fixture.suite["package"]["dll_path"])
        dll.write_bytes(b"changed package DLL, never loaded")
        self.assert_unverified(self.analyzer.analyze_suite(self.fixture.path))

    def test_all_packaged_tools_must_match_archived_provenance(self):
        for name in PACKAGE_FILES:
            with self.subTest(file=name):
                self.fixture = SuiteFixture(self.temp.name)
                packaged = self.fixture.root / "bundle" / "tools" / name
                packaged.write_bytes(packaged.read_bytes() + b"\n ")
                if name in PIPELINE:
                    package = self.fixture.suite["package"]
                    pipeline = "\n".join(f"{n}:{sha((packaged.parent/n).read_bytes())}" for n in PIPELINE)
                    package["pipeline_sha256"] = sha(pipeline.encode())
                    metadata = Path(package["metadata_path"])
                    lines = metadata.read_text().splitlines()
                    metadata.write_text("\n".join(
                        "Pipeline SHA256: " + package["pipeline_sha256"] if line.startswith("Pipeline SHA256:") else line
                        for line in lines) + "\n", encoding="utf-8")
                    package["metadata_sha256"] = sha(metadata.read_bytes())
                self.assert_unverified(self.analyze())

    def test_per_scene_preflight_rejects_reused_or_changed_process(self):
        for field in ("reuse", "process_id", "process_start_filetime", "scenario_id"):
            with self.subTest(field=field):
                self.fixture = SuiteFixture(self.temp.name)
                entry = self.fixture.suite["scenarios"][1]
                if field == "reuse":
                    entry["preflight"] = copy.deepcopy(self.fixture.suite["preflight"])
                elif field == "scenario_id":
                    entry["preflight"][field] = "another-scene"
                else:
                    observation = entry["preflight"]
                    for part in (observation, observation["forward_capabilities"]):
                        part["response"]["runtime_identity"][field] = 5678 if field == "process_id" else "134059104000000001"
                        part["raw_json"] = raw(part["response"])
                        part["sha256"] = sha(part["raw_json"].encode())
                self.fixture.captures[1]["probe_status_identity"] = copy.deepcopy(entry["preflight"])
                self.assert_unverified(self.analyze())

    def test_default_lookup_requires_evidence_and_ids_are_positive(self):
        self.fixture.suite.pop("lookup_source")
        self.assert_unverified(self.analyze())
        for field in ("source_msgsvrid", "db_msgsvrid"):
            with self.subTest(field=field):
                self.fixture = SuiteFixture(self.temp.name)
                self.fixture.suite["manifest"]["scenarios"][0][field] = "0"
                self.assert_unverified(self.analyze())
        self.fixture = SuiteFixture(self.temp.name)
        manifest = Path(self.fixture.suite["manifest_path"])
        manifest.write_bytes(manifest.read_bytes() + b" ")
        self.assert_unverified(self.analyzer.analyze_suite(self.fixture.path))

    def test_declared_artifact_integrity_is_checked(self):
        artifact = self.fixture.root / "extra-evidence.txt"
        artifact.write_bytes(b"recorded auxiliary evidence")
        self.fixture.suite["scenarios"][0]["artifacts"] = [dict(path=str(artifact), sha256=sha(artifact.read_bytes()))]
        self.assertEqual(self.analyze()["status"], "sufficient")
        artifact.write_bytes(b"changed auxiliary evidence")
        self.assert_unverified(self.analyzer.analyze_suite(self.fixture.path))

    def test_package_and_binary_identity_must_be_verified(self):
        self.fixture.suite["package"]["verified"] = False
        self.assert_unverified(self.analyze())
        self.fixture = SuiteFixture(self.temp.name)
        cap = self.fixture.suite["preflight"]["forward_capabilities"]
        cap["response"]["binary_identity"].update(verified=False, actual_sha256="B" * 64,
                                                   status="mismatch")
        cap["raw_json"] = raw(cap["response"])
        cap["sha256"] = sha(cap["raw_json"].encode())
        self.assert_unverified(self.analyze())

    def attach_lookup(self, status="found", complete=True, matches=None):
        self.fixture.suite["lookup_source"] = True
        for entry in self.fixture.suite["scenarios"][1:]:
            context = entry["context"]
            response = dict(code=0, status="found", complete=True, detail="offline",
                            matches=[dict(db="MSG0.db", table="MSG", local_id_decimal="42",
                                          msg_svr_id_decimal=context["source_msgsvrid"],
                                          talker=context["source_talker"], raw_type=1)])
            entry["source_lookup"] = dict(status="success", raw_json=raw(response), response=response,
                                          error=None, sha256=sha(raw(response).encode()))
        context = self.fixture.suite["scenarios"][0]["context"]
        if matches is None:
            matches = [dict(db="MSG0.db", table="MSG", local_id_decimal="42",
                            msg_svr_id_decimal=context["source_msgsvrid"],
                            talker=context["source_talker"], raw_type=1)]
        response = dict(code=0, status=status, complete=complete, matches=matches, detail="offline")
        observation = dict(status="success", raw_json=raw(response), response=response,
                           error=None, sha256=sha(raw(response).encode()))
        self.fixture.suite["scenarios"][0]["source_lookup"] = observation
        return observation

    def test_optional_complete_unique_lookup_preserves_exact_decimal(self):
        observation = self.attach_lookup()
        self.assertEqual(observation["response"]["matches"][0]["msg_svr_id_decimal"], "9007199254740993")
        self.assertEqual(self.analyze()["status"], "sufficient")

    def test_actual_locator_string_code_and_strict_failures(self):
        for code in ("0", 0, False, "-1", None):
            with self.subTest(code=code):
                self.fixture = SuiteFixture(self.temp.name)
                observation = self.attach_lookup()
                observation["response"]["code"] = code
                observation["raw_json"] = raw(observation["response"])
                observation["sha256"] = sha(observation["raw_json"].encode())
                expected = "sufficient" if code == "0" or (type(code) is int and code == 0) else "insufficient"
                self.assertEqual(self.analyze()["status"], expected)

    def test_common_source_entry_uses_direct_dto_identity_offset(self):
        self.assertEqual(self.analyze()["status"], "sufficient")
        scenario = self.fixture.scenario()
        source = scenario["events"][0]
        self.assertEqual(source["rva"], 0x2161FC0)
        self.assertEqual(source["object_reg"], 3)
        data = bytearray.fromhex(source["dump_hex"])
        identity = data[0xB8:0xD8]
        data[0xB8:0xD8] = bytes(32)
        data[0xC0:0xE0] = identity  # obsolete handler +8 prefix must not be used
        source["dump_hex"] = data.hex()
        sync_trace(scenario)
        self.assert_unverified(self.analyze())

    def test_lookup_failure_ambiguity_and_incomplete_are_not_found(self):
        for status, complete in (("not_found", True), ("ambiguous", True),
                                 ("lookup_incomplete", False), ("database_unavailable", False)):
            with self.subTest(status=status):
                self.attach_lookup(status, complete, [])
                self.assert_unverified(self.analyze())

    def test_lookup_raw_copy_hash_and_exact_row_identity(self):
        for mode in ("hash", "raw_copy", "rounded", "wrong_talker", "duplicate"):
            with self.subTest(mode=mode):
                observation = self.attach_lookup()
                if mode == "hash":
                    observation["sha256"] = "0" * 64
                elif mode == "raw_copy":
                    observation["response"]["complete"] = False
                else:
                    row = observation["response"]["matches"][0]
                    if mode == "rounded":
                        row["msg_svr_id_decimal"] = "9007199254740992"
                    elif mode == "wrong_talker":
                        row["talker"] = "other_chat"
                    else:
                        observation["response"]["matches"].append(copy.deepcopy(row))
                    observation["raw_json"] = raw(observation["response"])
                    observation["sha256"] = sha(observation["raw_json"].encode())
                self.assert_unverified(self.analyze())

    def test_cli_is_offline_and_preserves_inputs(self):
        self.fixture.save()
        before = {p: p.read_bytes() for p in self.fixture.root.glob("*") if p.is_file()}
        output = self.fixture.root / "analysis"
        run = subprocess.run([sys.executable, "-B", str(ANALYZER), "--suite", str(self.fixture.path),
                              "--output-directory", str(output)], capture_output=True, timeout=20)
        self.assertEqual(run.returncode, 0, run.stdout.decode(errors="replace") + run.stderr.decode(errors="replace"))
        self.assertTrue(list(output.glob("*.json")))
        self.assertTrue(list(output.glob("*.md")))
        for path, content in before.items():
            self.assertEqual(path.read_bytes(), content, str(path))

    def test_cli_refuses_to_overwrite_input_with_report(self):
        source = self.fixture.root / "forward-suite-analysis.json"
        source.write_bytes(self.fixture.path.read_bytes())
        before = source.read_bytes()
        run = subprocess.run([sys.executable, "-B", str(ANALYZER), "--suite", str(source),
                              "--output-directory", str(self.fixture.root)], capture_output=True, timeout=20)
        self.assertNotEqual(run.returncode, 0)
        self.assertEqual(source.read_bytes(), before)

    def test_zero_declared_ids_are_rejected(self):
        for field in ("source_msgsvrid", "db_msgsvrid"):
            with self.subTest(field=field):
                self.fixture = SuiteFixture(self.temp.name)
                self.fixture.suite["manifest"]["scenarios"][0][field] = "0"
                self.assert_unverified(self.analyze())

    def test_runtime_probe_hash_must_match_current_package(self):
        baseline = self.fixture.suite["preflight"]
        for observation in (baseline, baseline["forward_capabilities"]):
            observation["response"]["runtime_identity"]["probe"]["actual_sha256"] = "C" * 64
            sync_observation(observation)
        self.assert_unverified(self.analyze())

    def test_entire_packaged_script_set_must_match_provenance(self):
        for name in ("oneclick_forward.ps1", "forward-analysis-common.ps1", "capture_forward_suite.ps1",
                     "analyze_forward_suite.py", "wxcx-common.ps1"):
            with self.subTest(name=name):
                self.fixture = SuiteFixture(self.temp.name)
                package = self.fixture.suite["package"]
                bundle = Path(package["directory"])
                (bundle / "tools" / name).write_text("# different but self-consistent package\n", encoding="utf-8")
                package["pipeline_sha256"] = package_metadata(bundle)
                package["metadata_sha256"] = sha((bundle / "PACKAGE.txt").read_bytes())
                report = self.analyze()
                self.assert_unverified(report)
                self.assertTrue(any(name in error for error in report["errors"]), report["errors"])

    def test_fresh_process_identity_changes_invalidate_second_window(self):
        for field, value in (("process_id", 5678), ("process_start_filetime", "134059104000000001")):
            with self.subTest(field=field):
                self.fixture = SuiteFixture(self.temp.name)
                fresh = self.fixture.suite["scenarios"][1]["preflight"]
                for observation in (fresh, fresh["forward_capabilities"]):
                    observation["response"]["runtime_identity"][field] = value
                    sync_observation(observation)
                self.fixture.captures[1]["probe_status_identity"] = copy.deepcopy(fresh)
                self.assert_unverified(self.analyze())

    def test_uniform_identity_blocks_are_weak_even_with_one_exact_pair(self):
        for byte in (0, 255):
            with self.subTest(byte=byte):
                self.fixture = SuiteFixture(self.temp.name)
                record = self.fixture.scenario()
                block = bytes([byte]) * 32
                ui = bytearray.fromhex(record["events"][0]["dump_hex"])
                ui[0xB8:0xD8] = block
                record["events"][0]["dump_hex"] = ui.hex()
                record["events"][1]["follow_hex"] = block.hex()
                sync_trace(record)
                result = self.analyze()["scenarios"][0]
                self.assertEqual(result["status"], "insufficient")
                self.assertEqual(result["matching"]["pair_count"], 1)
                self.assertEqual(result["matching"]["status"], "weak_uniform_match")
                self.assertEqual(result["matching"]["identity_evidence"], "insufficient")

    def test_post_window_identity_mismatch_missing_or_stale_is_insufficient(self):
        for mode in ("process_id", "process_start_filetime", "probe_hash", "missing", "early", "hash"):
            with self.subTest(mode=mode):
                self.fixture = SuiteFixture(self.temp.name)
                entry = self.fixture.suite["scenarios"][0]
                post = entry["postflight"]
                if mode == "missing":
                    entry.pop("postflight")
                elif mode == "early":
                    post["observed_at"] = post["forward_capabilities"]["observed_at"] = "2026-10-28T00:00:04Z"
                elif mode == "hash":
                    post["sha256"] = "0" * 64
                else:
                    for observation in (post, post["forward_capabilities"]):
                        runtime = observation["response"]["runtime_identity"]
                        if mode == "probe_hash":
                            runtime["probe"]["actual_sha256"] = "C" * 64
                        else:
                            runtime[mode] = 5678 if mode == "process_id" else "134059104000000001"
                        sync_observation(observation)
                self.assert_unverified(self.analyze())


class SuiteRunnerOfflineTests(unittest.TestCase):
    """Run the real runner against inert files and a loopback-only HTTP server."""
    def setUp(self):
        self.shell = shutil.which("powershell.exe")
        if not self.shell:
            self.skipTest("Windows PowerShell is unavailable")
        self.temp = tempfile.TemporaryDirectory(prefix="forward-suite-runner-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bundle = self.root / "bundle"
        package_tools = self.bundle / "tools"
        package_tools.mkdir(parents=True)
        for name in PACKAGE_FILES:
            shutil.copyfile(ROOT / "tools" / name, package_tools / name)
        dll = self.bundle / "version.dll"
        dll.write_bytes(b"inert test fixture; never loaded")
        pipeline = "\n".join(f"{name}:{sha((package_tools / name).read_bytes())}" for name in PIPELINE)
        (self.bundle / "PACKAGE.txt").write_text(
            "Package: wxcx-forward-codex-20261028-04-r3\n"
            f"Capture script ID: {CAP_ID}\nDLL SHA256: {sha(dll.read_bytes())}\n"
            f"Suite script ID: {SUITE_ID}\n"
            f"Pipeline SHA256: {sha(pipeline.encode())}\n", encoding="utf-8")
        self.manifest = json.loads((ROOT / "tools" / "forward-suite.example.json").read_text())
        for i, scene in enumerate(self.manifest["scenarios"]):
            scene["source_msgsvrid"] = str(9007199254740993 + 2*i)
        self.manifest_path = self.root / "manifest.json"
        write_json(self.manifest_path, self.manifest)
        self.config_path = self.root / "config.json"
        write_json(self.config_path, {"Token": "", "Port": 1})
        self.calls = []
        self.bodies = []
        self.published = 0
        self.arm_count = 0
        self.pending = []
        self.allow_capture = False
        self.required_token = ""
        self.auth_seen = []
        self.status_reads = 0
        self.restart_field = None
        self.restart_during_window = False
        self.fail_post_status = False
        self.probe_sha = sha(dll.read_bytes())
        self.status = dict(schema_version=2, probe_build_id=BUILD_ID,
                           features=dict(follow_read_offset=True))
        self.caps = dict(binary_identity=runtime_identity(self.probe_sha)["weixin"],
                         runtime_identity=runtime_identity(self.probe_sha))
        self.status["runtime_identity"] = runtime_identity(self.probe_sha)
        owner = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def reply(self, value):
                payload = raw(value).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def authenticated(self):
                supplied = self.headers.get("X-Wxcx-Token", "")
                owner.auth_seen.append(supplied)
                if owner.required_token and supplied != owner.required_token:
                    self.send_error(401, "synthetic test token required")
                    return False
                return True

            def do_GET(self):
                if not self.authenticated():
                    return
                owner.calls.append(("GET", self.path))
                url = urllib.parse.urlsplit(self.path)
                if url.path == "/wxcx/probe/status":
                    owner.status_reads += 1
                    if owner.fail_post_status and owner.status_reads == 3:
                        self.send_error(503, "synthetic post-window identity unavailable")
                        return
                    if owner.restart_field and owner.status_reads == 4:
                        for runtime in (owner.status["runtime_identity"], owner.caps["runtime_identity"]):
                            if owner.restart_field == "process_id":
                                runtime["process_id"] = 5678
                            else:
                                runtime["process_start_filetime"] = "134059104000000001"
                    return self.reply(owner.status)
                if url.path == "/wxcx/forward/capabilities":
                    return self.reply(owner.caps)
                if owner.allow_capture and url.path == "/wxcx/probe/trace":
                    events, owner.pending = owner.pending, []
                    if events and owner.restart_during_window:
                        for runtime in (owner.status["runtime_identity"], owner.caps["runtime_identity"]):
                            runtime["process_start_filetime"] = "134059104000000001"
                    return self.reply(trace(events, owner.published))
                if owner.allow_capture and url.path == "/wxcx/sym/where":
                    rva = int(urllib.parse.parse_qs(url.query)["rva"][0], 16)
                    return self.reply(dict(ok=True, func_start=rva, is_entry=True))
                self.send_error(404)

            def do_POST(self):
                if not self.authenticated():
                    return
                owner.calls.append(("POST", self.path))
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
                owner.bodies.append((self.path, body))
                if owner.allow_capture and self.path == "/wxcx/db/locate_unique":
                    response = dict(code="0", status="found", complete=True, detail="offline exact row",
                                    matches=[dict(db="MSG0.db", table="MSG", local_id_decimal="42",
                                                  msg_svr_id_decimal=body["msgsvrid"],
                                                  talker=body["source_talker"], raw_type="1")])
                    return self.reply(response)
                if owner.allow_capture and self.path == "/wxcx/probe/disarm":
                    return self.reply(dict(ok=True))
                if owner.allow_capture and self.path == "/wxcx/probe/arm":
                    owner.arm_count += 1
                    if owner.arm_count % 4 == 0:
                        index = owner.arm_count // 4
                        identity = bytes((n + index) % 256 for n in range(32))
                        ui = bytearray(256)
                        ui[0xB8:0xD8] = identity
                        owner.pending = [event(POINTS[0], owner.published + 1, bytes(ui)),
                                         event(POINTS[1], owner.published + 2, bytes(32), identity, 400),
                                         event(POINTS[2], owner.published + 3, bytes(32), bytes(256)),
                                         event(POINTS[3], owner.published + 4, bytes(96))]
                        owner.published += 4
                    return self.reply(dict(ok=True, rva=int(body["rva"], 16),
                                           follow_read_offset=body.get("follow_read_offset", 0)))
                self.send_error(500, "No POST is permitted in a preflight failure test")

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.worker = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.worker.start()
        self.addCleanup(self.stop_server)

    def stop_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.worker.join(timeout=3)

    def run_runner(self, name, *extra):
        env = os.environ.copy()
        # Windows PowerShell launched by pwsh can inherit an incompatible module path.
        env["PSModulePath"] = str(Path(os.environ.get("SystemRoot", "C:/Windows")) /
                                   "System32/WindowsPowerShell/v1.0/Modules")
        output = self.root / name
        command = [self.shell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                   str(ROOT / "tools" / "capture_forward_suite.ps1"),
                   "-ManifestPath", str(self.manifest_path), "-PackageDirectory", str(self.bundle),
                   "-Config", str(self.config_path),
                   "-PythonPath", str(self.root / "intentionally-missing-python.exe") if "-CollectOnly" in extra else sys.executable,
                   "-Port", str(self.server.server_port),
                   "-OutputDirectory", str(output), "-Seconds", "1", "-NoPrompt", *extra]
        try:
            run = subprocess.run(command, env=env, capture_output=True, timeout=60)
        except subprocess.TimeoutExpired as exc:
            self.fail(f"Runner timed out; calls={self.calls!r}; stdout={exc.stdout!r}; stderr={exc.stderr!r}")
        detail = run.stdout.decode(errors="replace") + run.stderr.decode(errors="replace")
        paths = list(output.glob("*/suite.json"))
        suite = json.loads(paths[0].read_text(encoding="utf-8-sig")) if paths else None
        reports = list(output.glob("*/forward-suite-analysis.json"))
        if reports:
            report = json.loads(reports[0].read_text(encoding="utf-8-sig"))
            detail += "\nAnalysis diagnostics: " + repr(report["errors"] +
                                                       [s["errors"] for s in report["scenarios"]])
        return run, suite, detail

    def test_filehelper_entry_forwards_default_config_token_for_four_windows(self):
        self.allow_capture = True
        self.required_token = "offline-config-token"
        package_tools = self.bundle / "tools"
        shutil.copyfile(ROOT / "tools" / "capture_filehelper_04.ps1", package_tools / "capture_filehelper_04.ps1")
        write_json(package_tools / "forward-filehelper-04.json", self.manifest)
        write_json(package_tools / "wxcx.config.json", {"Token": self.required_token, "Port": self.server.server_port})
        env = os.environ.copy()
        env["PSModulePath"] = str(Path(os.environ.get("SystemRoot", "C:/Windows")) /
                                   "System32/WindowsPowerShell/v1.0/Modules")
        output = self.root / "authenticated-filehelper-entry"
        run = subprocess.run([self.shell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                              str(package_tools / "capture_filehelper_04.ps1"), "-Seconds", "1", "-NoPrompt",
                              "-OutputDirectory", str(output)], env=env, capture_output=True, timeout=60)
        detail = run.stdout.decode(errors="replace") + run.stderr.decode(errors="replace")
        self.assertEqual(run.returncode, 0, detail)
        self.assertIn("FWD-FILEHELPER-20261028-04-R3", detail)
        self.assertIn("【第 1/4 轮：文本】", detail)
        self.assertEqual(detail.count("【开始采集】点位已就绪"), 4)
        self.assertEqual(detail.count("【本轮采集结束】"), 4)
        self.assertNotIn("Manually forward the declared", detail)
        self.assertNotIn(self.required_token, detail)
        self.assertTrue(self.auth_seen)
        self.assertTrue(all(value == self.required_token for value in self.auth_seen))
        self.assertEqual(self.arm_count, 16)
        suite = json.loads(next(output.glob("*/suite.json")).read_text(encoding="utf-8-sig"))
        self.assertEqual(suite["status"], "collected")
        self.assertEqual(len(suite["scenarios"]), 4)
        self.assertTrue(all(scene["status"] == "captured" for scene in suite["scenarios"]))

    def test_suite_loads_configured_token_when_string_parameter_is_omitted(self):
        self.allow_capture = True
        self.required_token = "offline-suite-config-token"
        write_json(self.config_path, {"Token": self.required_token, "Port": self.server.server_port})
        run, suite, detail = self.run_runner("authenticated-config-default", "-CollectOnly")
        self.assertEqual(run.returncode, 0, detail)
        self.assertEqual(suite["status"], "collected")
        self.assertEqual(self.arm_count, 16)
        self.assertTrue(self.auth_seen)
        self.assertTrue(all(value == self.required_token for value in self.auth_seen))
        self.assertNotIn(self.required_token, detail)

    def test_four_window_runner_with_exact_source_lookup(self):
        self.allow_capture = True
        run, suite, detail = self.run_runner("full")
        self.assertEqual(run.returncode, 0, detail)
        self.assertIsNotNone(suite, detail)
        self.assertEqual(suite["status"], "collected")
        self.assertEqual(len(suite["scenarios"]), 4)
        self.assertEqual(suite["lookup_source"], True)
        self.assertEqual(self.calls.count(("GET", "/wxcx/probe/status")), 9)
        self.assertEqual(self.calls.count(("GET", "/wxcx/forward/capabilities")), 9)
        first_arm = self.calls.index(("POST", "/wxcx/probe/arm"))
        self.assertLess(self.calls.index(("GET", "/wxcx/forward/capabilities")), first_arm)
        self.assertEqual(self.arm_count, 16)
        allowed_posts = {"/wxcx/probe/arm", "/wxcx/probe/disarm", "/wxcx/db/locate_unique"}
        self.assertTrue(all(path in allowed_posts for method, path in self.calls if method == "POST"))
        lookups = [body for path, body in self.bodies if path == "/wxcx/db/locate_unique"]
        self.assertEqual(len(lookups), 4)
        self.assertEqual(lookups[0]["msgsvrid"], "9007199254740993")
        for entry in suite["scenarios"]:
            self.assertEqual(entry["status"], "captured")
            capture_path = Path(entry["capture_path"])
            self.assertEqual(entry["capture_sha256"], sha(capture_path.read_bytes()))
            capture = json.loads(capture_path.read_text(encoding="utf-8-sig"))
            self.assertEqual(capture["scenario_context"], entry["context"])
            self.assertEqual(capture["capture_metadata"]["script_id"], CAP_ID)
            self.assertEqual(capture["probe_status_identity"], entry["preflight"])
            self.assertEqual(entry["postflight"]["phase"], "post_window")
            self.assertEqual(entry["postflight"]["scenario_id"], entry["id"])
            self.assertEqual(entry["postflight"]["response"]["runtime_identity"],
                             entry["preflight"]["response"]["runtime_identity"])
            self.assertNotEqual(entry["preflight"]["observed_at"], suite["preflight"]["observed_at"])
            self.assertEqual(entry["preflight"]["response"]["runtime_identity"],
                             suite["preflight"]["response"]["runtime_identity"])
            lookup = entry["source_lookup"]
            self.assertEqual(lookup["status"], "success")
            self.assertEqual(lookup["response"]["status"], "found")
            self.assertEqual(lookup["sha256"], sha(lookup["raw_json"].encode()))
            self.assertEqual(lookup["response"], json.loads(lookup["raw_json"]))
        for record in suite["provenance"]["files"]:
            self.assertEqual(record["sha256"], sha(Path(record["path"]).read_bytes()))

    def test_collect_only_preserves_evidence_for_another_machine(self):
        self.allow_capture = True
        run, suite, detail = self.run_runner("collect-only", "-CollectOnly")
        self.assertEqual(run.returncode, 0, detail)
        self.assertEqual(suite["status"], "collected")
        self.assertEqual(suite["analysis_mode"], "deferred")
        self.assertEqual(len(suite["scenarios"]), 4)
        self.assertEqual(self.arm_count, 16)
        paths = list((self.root / "collect-only").glob("*/suite.json"))
        self.assertEqual(len(paths), 1)
        self.assertFalse(list(paths[0].parent.glob("forward-suite-analysis*")))
        spec = importlib.util.spec_from_file_location("analyze_collect_only", ANALYZER)
        analyzer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(analyzer)
        report = analyzer.analyze_suite(paths[0])
        self.assertEqual(report["status"], "sufficient", report)

    def test_validate_only_is_local_and_preserves_decimal_strings(self):
        run, suite, detail = self.run_runner("validate", "-ValidateOnly")
        self.assertEqual(run.returncode, 0, detail)
        self.assertEqual(self.calls, [])
        self.assertEqual(suite["status"], "validated")
        self.assertEqual(suite["suite_script_id"], SUITE_ID)
        self.assertEqual(suite["package"]["expected_script_id"], CAP_ID)
        self.assertEqual(suite["manifest"]["scenarios"][0]["source_msgsvrid"], "9007199254740993")
        self.assertIsNone(suite["preflight"])
        self.assertEqual(suite["scenarios"], [])
        for record in suite["provenance"]["files"]:
            snapshot = Path(record["path"])
            self.assertEqual(snapshot.parent.name, "provenance")
            self.assertNotEqual(snapshot, Path(record["source_path"]))
            self.assertEqual(record["sha256"], sha(snapshot.read_bytes()))
        self.assertFalse(list((self.root / "validate").glob("*/forward-suite-analysis*")))

    def test_bad_manifests_fail_before_network(self):
        # Validation errors occur without any probe/forward call.
        cases = []
        for field, value in (("source_msgsvrid", 9007199254740993),
                             ("db_msgsvrid", 9007199254740993),
                             ("source_msgsvrid", "0"), ("db_msgsvrid", "0"),
                             ("source_msgsvrid", "18446744073709551616"),
                             ("downloaded", None), ("type", "card")):
            manifest = copy.deepcopy(self.manifest)
            manifest["scenarios"][0][field] = value
            cases.append(manifest)
        short = copy.deepcopy(self.manifest)
        short["scenarios"].pop()
        cases.append(short)
        duplicate = copy.deepcopy(self.manifest)
        duplicate["scenarios"][1]["id"] = duplicate["scenarios"][0]["id"]
        cases.append(duplicate)
        for i, manifest in enumerate(cases):
            with self.subTest(case=i):
                write_json(self.manifest_path, manifest)
                run, suite, detail = self.run_runner(f"invalid-{i}")
                self.assertNotEqual(run.returncode, 0, detail)
                self.assertEqual(self.calls, [])
                self.assertIsNone(suite)

    def test_preflight_failure_never_posts_or_arms(self):
        cases = ("missing_build", "wrong_build", "missing_feature", "missing_identity",
                 "unverified_identity", "wrong_hash", "string_feature", "string_verified", "wrong_binary_status",
                 "wrong_probe_hash", "probe_headers_mismatch")
        for name in cases:
            with self.subTest(case=name):
                self.calls.clear()
                self.status = dict(schema_version=2, probe_build_id=BUILD_ID,
                                   features=dict(follow_read_offset=True))
                self.caps = dict(binary_identity=runtime_identity(self.probe_sha)["weixin"],
                                 runtime_identity=runtime_identity(self.probe_sha))
                self.status["runtime_identity"] = runtime_identity(self.probe_sha)
                if name == "missing_build":
                    self.status.pop("probe_build_id")
                elif name == "wrong_build":
                    self.status["probe_build_id"] = "FWD-PROBE-20261028-02"
                elif name == "missing_feature":
                    self.status["features"] = {}
                elif name == "missing_identity":
                    self.caps = {}
                elif name == "unverified_identity":
                    self.caps["binary_identity"]["verified"] = False
                elif name == "string_feature":
                    self.status["features"]["follow_read_offset"] = "true"
                elif name == "string_verified":
                    self.caps["binary_identity"]["verified"] = "false"
                elif name == "wrong_binary_status":
                    self.caps["binary_identity"]["status"] = "mapped_headers_mismatch"
                elif name in ("wrong_probe_hash", "probe_headers_mismatch"):
                    for runtime in (self.status["runtime_identity"], self.caps["runtime_identity"]):
                        if name == "wrong_probe_hash":
                            runtime["probe"]["actual_sha256"] = "C" * 64
                        else:
                            runtime["probe"]["mapped_headers_match"] = False
                else:
                    self.caps["binary_identity"]["actual_sha256"] = "B" * 64
                run, suite, detail = self.run_runner(name)
                self.assertNotEqual(run.returncode, 0, detail)
                self.assertIsNotNone(suite, detail)
                self.assertEqual(suite["status"], "failed")
                self.assertEqual(suite["scenarios"], [])
                self.assertEqual(self.calls, [("GET", "/wxcx/probe/status"),
                                               ("GET", "/wxcx/forward/capabilities")])
                for observation in (suite["preflight"], suite["preflight"]["forward_capabilities"]):
                    self.assertEqual(observation["sha256"], sha(observation["raw_json"].encode()))
                    self.assertEqual(json.loads(observation["raw_json"]), observation["response"])

    def test_current_oneclick_and_common_must_match_package_before_network(self):
        original = {name: (self.bundle / "tools" / name).read_bytes()
                    for name in ("oneclick_forward.ps1", "forward-analysis-common.ps1")}
        for name, content in original.items():
            with self.subTest(name=name):
                path = self.bundle / "tools" / name
                path.write_bytes(content + b"\n# divergent package helper\n")
                package_metadata(self.bundle)
                run, suite, detail = self.run_runner("mismatch-" + name)
                self.assertNotEqual(run.returncode, 0, detail)
                self.assertIn(name, detail)
                self.assertEqual(self.calls, [])
                self.assertIsNone(suite)
                path.write_bytes(content)
                package_metadata(self.bundle)

    def test_process_restart_blocks_second_window(self):
        self.allow_capture = True
        for field in ("process_id", "process_start_filetime"):
            with self.subTest(field=field):
                self.calls.clear(); self.bodies.clear()
                self.status_reads = self.arm_count = self.published = 0
                self.pending = []
                self.status["runtime_identity"] = runtime_identity(self.probe_sha)
                self.caps["runtime_identity"] = runtime_identity(self.probe_sha)
                self.restart_field = field
                run, suite, detail = self.run_runner("restart-" + field)
                self.assertNotEqual(run.returncode, 0, detail)
                self.assertEqual(self.arm_count, 4, detail)
                self.assertEqual(len(suite["scenarios"]), 2)
                self.assertEqual(suite["scenarios"][0]["status"], "captured")
                self.assertEqual(suite["scenarios"][1]["status"], "failed")
                self.assertIn("identity changed", suite["scenarios"][1]["error"])
                self.assertIsNone(suite["scenarios"][1]["capture_path"])

    def test_explicit_structure_only_skips_database_lookup(self):
        self.allow_capture = True
        run, suite, detail = self.run_runner("structure-only", "-StructureOnly")
        self.assertEqual(run.returncode, 0, detail)
        self.assertIs(suite["lookup_source"], False)
        self.assertFalse(any(path == "/wxcx/db/locate_unique" for _, path in self.calls))

    def test_post_window_restart_or_unavailable_identity_invalidates_saved_capture(self):
        self.allow_capture = True
        for mode in ("restart", "unavailable"):
            with self.subTest(mode=mode):
                self.calls.clear(); self.bodies.clear()
                self.status_reads = self.arm_count = self.published = 0
                self.pending = []
                self.status["runtime_identity"] = runtime_identity(self.probe_sha)
                self.caps["runtime_identity"] = runtime_identity(self.probe_sha)
                self.restart_during_window = mode == "restart"
                self.fail_post_status = mode == "unavailable"
                run, suite, detail = self.run_runner("during-window-" + mode)
                self.assertNotEqual(run.returncode, 0, detail)
                self.assertEqual(self.arm_count, 4, detail)
                self.assertEqual(len(suite["scenarios"]), 1)
                entry = suite["scenarios"][0]
                self.assertEqual(entry["status"], "failed")
                self.assertTrue(entry["error"])
                self.assertTrue(Path(entry["capture_path"]).is_file())
                self.assertEqual(entry["capture_sha256"], sha(Path(entry["capture_path"]).read_bytes()))
                self.assertIsNotNone(entry["postflight"])

    def test_bundled_tools_discover_parent_package_without_example_file(self):
        env = os.environ.copy()
        env["PSModulePath"] = str(Path(os.environ.get("SystemRoot", "C:/Windows")) /
                                   "System32/WindowsPowerShell/v1.0/Modules")
        output = self.root / "bundle-discovery"
        run = subprocess.run([self.shell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                              str(self.bundle / "tools" / "capture_forward_suite.ps1"),
                              "-ManifestPath", str(self.manifest_path), "-ValidateOnly",
                              "-PythonPath", sys.executable, "-OutputDirectory", str(output)],
                             env=env, capture_output=True, timeout=30)
        self.assertEqual(run.returncode, 0, run.stdout.decode(errors="replace") + run.stderr.decode(errors="replace"))
        suite = json.loads(next(output.glob("*/suite.json")).read_text(encoding="utf-8-sig"))
        self.assertEqual(Path(suite["package"]["directory"]), self.bundle)
        self.assertEqual(self.calls, [])
        self.assertEqual(len(suite["provenance"]["files"]), 7)


if __name__ == "__main__":
    unittest.main()
