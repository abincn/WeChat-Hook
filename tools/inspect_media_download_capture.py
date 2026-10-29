"""Offline projection of MEDIA-DL-CAP-20261029-01 evidence; never native calls."""
import argparse
import hashlib
import json
import struct
from pathlib import Path


def read(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def analyze(root):
    plan = read(root / "plan.json")
    summary = read(root / "summary.json")
    hashes = []
    for line in (root / "SHA256SUMS.txt").read_text(encoding="utf-8-sig").splitlines():
        expected, name = line.split(None, 1)
        path = (root / name).resolve()
        if path.parent != root.resolve():
            raise ValueError("checksum path outside evidence folder")
        hashes.append(hashlib.sha256(path.read_bytes()).hexdigest() == expected.lower())
    # Vtable addresses independently recovered from the pinned target binary.
    vtables = {0x52B5C90: 0x8BE59A8, 0x52BA8A0: 0x8BE62F8}
    expected_ids = {
        plan["expected_image_msgsvrid"]: "expected_group_image",
        plan["expected_video_msgsvrid"]: "expected_group_video",
    }
    events = []
    for page_path in sorted(root.glob("page-*.json")):
        for event in read(page_path).get("events", []):
            rva = int(event["rva"], 16)
            follow = bytes.fromhex(event["follow_hex"])
            dump = bytes.fromhex(event["dump_hex"])
            row = {"page": page_path.name, "seq": event["seq"], "tick": event["t"],
                   "rva": hex(rva), "thread_id": event["tid"],
                   "identity_complete": event["follow_read_offset"] == 328 and len(follow) == 48}
            if row["identity_complete"]:
                # Source +328 u64 server ID; +344 u32 native message type;
                # +356 u32 creation seconds, independently established earlier.
                server_id = str(struct.unpack_from("<Q", follow)[0])
                row.update(msgsvrid=server_id, native_type=struct.unpack_from("<I", follow, 16)[0],
                           create_time=struct.unpack_from("<I", follow, 28)[0],
                           source_match=expected_ids.get(server_id, "other_source"))
            if rva in vtables and len(dump) >= 8:
                base = struct.unpack_from("<Q", dump)[0] - vtables[rva]
                row["vtable_derived_module_base"] = hex(base)
                # This base is an analytical correlation, never a callable pointer.
                if event.get("ret_valid"):
                    caller = int(event["ret_hex"], 16) - base
                    if 0 <= caller < 183558144:
                        row["return_rva"] = hex(caller)
            events.append(row)
    return {"id": plan["id"], "checksums_checked": len(hashes),
            "checksums_valid": all(hashes), "capture_summary": summary,
            "events": events, "expected_source_hits": {value: sum(e.get("source_match") == value for e in events)
                                                        for value in expected_ids.values()},
            "conclusion": "Resume snapshots only; task construction, completion, file readiness and callable ABI remain unverified"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("folder", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = analyze(args.folder)
    content = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output:
        args.output.write_text(content + "\n", encoding="utf-8")
    print(content)
