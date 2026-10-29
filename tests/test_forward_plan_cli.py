"""Exercise the real PowerShell entry point against a loopback-only fake probe.
No WeChat, native calls, external traffic, configuration or credentials are used.
"""
import http.server
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import threading
import unittest
import urllib.parse

ROOT = pathlib.Path(__file__).resolve().parents[1]


class PlanCommandLineTest(unittest.TestCase):
    def test_windows_powershell_entry_point(self):
        shell = shutil.which("powershell.exe")
        if not shell:
            self.skipTest("Windows PowerShell is not installed")
        state = {"calls": [], "active": False, "published": 0, "emitted": False,
                 "event_rva": 0x2161FC0, "ret_rva": 0x5444DDB, "func_start": 0x54448A0}

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def reply(self, value):
                data = json.dumps(value).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
                state["calls"].append((self.path, body))
                if self.path.endswith("/disarm"):
                    state["active"] = False
                    return self.reply({"ok": True})
                if self.path.endswith("/arm"):
                    state["active"] = True
                    return self.reply({"ok": True, "rva": int(body["rva"], 16),
                                       "follow_read_offset": body.get("follow_read_offset", 0)})
                self.send_error(404)

            def do_GET(self):
                state["calls"].append((self.path, None))
                url = urllib.parse.urlsplit(self.path)
                if url.path == "/wxcx/probe/status":
                    return self.reply({"features": {"follow_read_offset": True}, "probe_build_id": "FWD-PROBE-20261028-04"})
                if url.path == "/wxcx/probe/trace":
                    events = []
                    if state["active"] and not state["emitted"]:
                        state["emitted"] = True
                        state["published"] = 1
                        events.append({"seq": 1, "rva": state["event_rva"], "ret_rva": state["ret_rva"],
                                       "tid": 7, "capture_site": "function_entry", "ret_valid": True,
                                       "a1": 1, "a2": 2, "a3": 3, "a4": 4})
                    return self.reply({"schema_version": 2, "events": events, "count": len(events),
                                       "image_base": 0x180000000, "image_size": 0xAF0E000,
                                       "busy": False, "consuming": True, "dropped": 0, "skipped": 0,
                                       "reader_skipped_total": 0, "published": state["published"]})
                if url.path == "/wxcx/sym/where":
                    rva = int(urllib.parse.parse_qs(url.query)["rva"][0], 16)
                    return self.reply({"ok": True, "func_start": state["func_start"],
                                       "is_entry": rva == state["func_start"]})
                self.send_error(404)

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        temp_root = pathlib.Path(tempfile.gettempdir()).resolve()
        try:
            cases = [
                {"script": "capture_forward_source.ps1", "rvas": ["0x2161FC0", "0x43ACC80", "0x1679340", "0x16BDF60"],
                 "event_rva": 0x2161FC0, "ret_rva": 0x5444DDB, "func_start": 0x54448A0, "profile": "source"},
                {"script": "capture_forward_internal.ps1", "rvas": ["0x2161FC0", "0x16BDF60", "0x3689B10", "0x2160460"],
                 "event_rva": 0x2161FC0, "ret_rva": 0x5444DDB, "func_start": 0x54448A0, "profile": "internal"},
            ]
            with tempfile.TemporaryDirectory(prefix="wxcx-plan-cli-", dir=str(temp_root)) as work:
                root = pathlib.Path(work).resolve()
                self.assertEqual(root.parent, temp_root)
                self.assertTrue(root.name.startswith("wxcx-plan-cli-"))
                for case in cases:
                    state.update(calls=[], active=False, published=0, emitted=False,
                                 event_rva=case["event_rva"], ret_rva=case["ret_rva"],
                                 func_start=case["func_start"])
                    target = root / pathlib.Path(case["script"]).stem
                    target.mkdir()
                    command = [shell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                               str(ROOT / "tools" / case["script"]), "-Seconds", "1", "-NoPrompt",
                               "-Config", str(root / "offline-no-config.json"),
                               "-Verbose", "-Port", str(server.server_port), "-OutputDirectory", str(target)]
                    try:
                        # PowerShell 7's inherited module paths can hide WinPS
                        # built-ins (notably Get-FileHash). Use WinPS's own modules.
                        environment = os.environ.copy()
                        environment["PSModulePath"] = str(pathlib.Path(os.environ.get("SystemRoot", "C:/Windows")) /
                                                           "System32/WindowsPowerShell/v1.0/Modules")
                        run = subprocess.run(command, capture_output=True, timeout=12, env=environment)
                    except subprocess.TimeoutExpired as exc:
                        self.fail(f"CLI timeout; probe calls={state['calls']}; stdout={exc.stdout!r}; stderr={exc.stderr!r}")
                    output = run.stdout.decode(errors="replace") + run.stderr.decode(errors="replace")
                    self.assertEqual(run.returncode, 0, output)
                    captured = list(target.glob("forward-capture-*.json"))
                    self.assertEqual(len(captured), 1)
                    data = json.loads(captured[0].read_text(encoding="utf-8-sig"))
                    scenario = data["scenarios"][0]
                    self.assertEqual(scenario["capture_status"], "success")
                    self.assertTrue(scenario["trace_complete"])
                    self.assertEqual(len(scenario["armed_detail"]), 4)
                    arms = [body for path, body in state["calls"] if path.endswith("/arm")]
                    self.assertEqual([body["rva"].upper() for body in arms], [r.upper() for r in case["rvas"]])
                    self.assertEqual(len(arms), 4)
                    if case["profile"] == "source":
                        self.assertEqual((arms[0]["dump_reg"], arms[0]["dump"]), (3, 256))
                        self.assertEqual(arms[1]["follow2_off"], 0)
                        self.assertEqual(data["symbols"]["0x5444DDB"]["func_start"], 0x54448A0)
                    else:
                        self.assertEqual((arms[0]["dump_reg"], arms[0]["dump"]), (3, 256))
                        self.assertEqual((arms[2]["follow_off"], arms[2]["follow_len"]), (0, 256))
                        self.assertEqual(data["symbols"]["0x5444DDB"]["func_start"], 0x54448A0)
                    posts = [path for path, body in state["calls"] if body is not None]
                    self.assertTrue(posts[-1].endswith("/disarm"))
                    self.assertFalse(any(path.endswith("/preset") for path, _ in state["calls"]))
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=5)


class OldProbeBuildTest(unittest.TestCase):
    def test_old_or_unmarked_build_never_arms(self):
        shell = shutil.which("powershell.exe")
        if not shell:
            self.skipTest("Windows PowerShell is not installed")
        state = {"build": "FWD-PROBE-20261028-02", "calls": []}

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                state["calls"].append(("GET", self.path))
                value = {"features": {"follow_read_offset": True}}
                if state["build"] is not None:
                    value["probe_build_id"] = state["build"]
                data = json.dumps(value).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_POST(self):
                state["calls"].append(("POST", self.path))
                self.send_error(500)

        service = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        worker = threading.Thread(target=service.serve_forever, daemon=True)
        worker.start()
        try:
            with tempfile.TemporaryDirectory(prefix="wxcx-old-probe-") as work:
                root = pathlib.Path(work)
                environment = os.environ.copy()
                environment["PSModulePath"] = str(pathlib.Path(os.environ.get("SystemRoot", "C:/Windows")) /
                                                   "System32/WindowsPowerShell/v1.0/Modules")
                for build in ("FWD-PROBE-20261028-02", None):
                    with self.subTest(build=build):
                        state.update(build=build, calls=[])
                        run = subprocess.run([shell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                            str(ROOT / "tools" / "capture_forward_internal.ps1"), "-Seconds", "1", "-NoPrompt",
                            "-Port", str(service.server_port), "-Config", str(root / "offline-no-config.json"),
                            "-OutputDirectory", str(root / "output")], env=environment, capture_output=True, timeout=12)
                        self.assertNotEqual(run.returncode, 0)
                        self.assertEqual(state["calls"], [("GET", "/wxcx/probe/status")])
                        text = run.stdout.decode(errors="replace") + run.stderr.decode(errors="replace")
                        self.assertIn("no probes were armed", " ".join(text.split()))
        finally:
            service.shutdown()
            service.server_close()
            worker.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
