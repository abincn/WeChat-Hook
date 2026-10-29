> 公开脱敏副本：真实账号、会话、消息标识和机器地址不公开。采集原件、IDA分析及验收明细仅本地保留；文中的相关路径不代表仓库包含这些文件。

# Forward implementation status — 20261028-03

This is an intermediate implementation, not a verified native Forward release.
All four native message capabilities remain unavailable. No target module was
loaded, no running WeChat DLL was replaced and no message was sent during the
offline implementation checks.

## Implemented interfaces

`POST /ForwardMsg` accepts an object containing `toid`, `msgsvrid`, optional
`source_talker` and optional `request_id`. IDs accept exact positive uint64
decimal strings or JSON integer tokens; floats, overflow and conflicting
`msgid`/`msgsvrid` aliases are rejected. Any `quad_id` is rejected with
`unsupported_legacy_identifier` rather than silently selecting the old adapter.

```json
{"toid":"filehelper","msgsvrid":"EXAMPLE_MESSAGE_ID","source_talker":"SOURCE_SESSION","request_id":"forward-example-1"}
```

New tasks return HTTP 202, `accepted:true` and `task_id`. This confirms queueing
only. Query `GET /wxcx/forward/tasks/{task_id}` for the current task record.
An identical request ID and normalized parameters returns HTTP 200 and the same
task; changed parameters return HTTP 409. A missing request ID is generated and
returned. Deduplication is local to this process, including failed/unknown tasks.
After a restart old task IDs return 404; callers must not automatically replay
an operation whose outcome is unknown.

States: `queued → resolving → downloading (media only) → submitting → submitted`,
with `failed` before/after a definite rejection and `unknown` for uncertain native
submission. Every record currently has `delivery_status:unverified`; submitted
does not assert receipt. The 300-second total deadline includes queue time. GET
and processing checkpoints expire overdue tasks even when a backend still owns
an object. Late completion does not overwrite a terminal unknown result. Owners
remain alive until the backend returns, and backends must cooperate with shutdown
and deadlines; a timeout never forcibly frees a native-owned object.

`POST /wxcx/forward/stop` stops admission, marks unfinished submissions unknown
and cooperatively drains backend work. The production registry has process
lifetime and the module is pinned while its detached HTTP thread/routes exist;
replacement/rollback requires a process restart. This avoids joining a worker
from Windows loader-lock destruction. Individual task owners are still released
after work returns; this is not an unbounded allocation per native submission.

When a backend has parsed an explicit server response, `server_response` contains
`parsed:true`, the exact `ret` and accepted/rejected status. A nonzero return
fails the task as `server_rejected` even if dispatch succeeded. Missing or invalid
response bytes never default to zero. The new SendAppMsg response decoder is
offline-tested for the referenced layout; it is not connected to an unverified
native callback. See FORWARD_UPSTREAM_REVIEW.md for the pinned reference and
local binary corroboration.

One worker serializes backend work. There are at most 64 queued tasks and 4096
records per process. Records are not silently evicted because doing so would
break process-scoped deduplication. Capacity/stopping errors return HTTP 503
before acceptance. Shutdown fails queued tasks and cooperatively ends active work.
Backend operations and native releases must execute on the verified owning
thread; the task worker itself is not evidence that it is a suitable WeChat thread.

`GET /wxcx/forward/capabilities` reports each of text/link/image/file separately,
the native adapter status, media-download availability and binary identity.
The current native backend first checks the binary identity, then gathers unique
database evidence. It returns an explicit `native_abi_unverified` error after a
unique lookup. It does not construct a native object from those database bytes,
invoke a candidate RVA, or report the adapter as working.

## Unique source evidence

`POST /wxcx/db/locate_unique` accepts `msgsvrid` and optional `source_talker`.
It enumerates registered database schemas instead of deriving shard identity
from filenames, reads the existing ID/talker/type column names and checks all
returned IDs without narrowing uint64 values. Raw type values remain raw.

The result contains `complete`, `matches`, `detail`, and one of `found`,
`not_found`, `ambiguous`, `lookup_incomplete` or `database_unavailable`.
`found` requires exactly one matching row and a complete inspected scope.
Schema/query failures, unreadable rows or uncheckable source-session constraints
cannot establish uniqueness. More than one match is ambiguous, including copies
in different registered databases. Work is bounded to 128 registered databases,
4096 tables and 128 retained matches; hitting a bound disables completeness.
Only server-ID column layouts explicitly recognized by the implementation are
supported. This is database evidence, not a native source-message reference.
The legacy `/wxcx/db/locate` remains available for compatibility and retains its
documented first-match/research-only limitations.

## Runtime identity and remaining gates

Probe build ID: `FWD-PROBE-20261028-03`. Probe status includes the SHA-256 of the
probe DLL file and target module file, PE-header correspondence and the expected
Weixin.dll digest `f487e4f56930456a25fb0d7b058c77e2dcd364e268d49bdfff4dc0e3be26ba36`.
The target file must also be 183094832 bytes. Identity is cached per process.
These are module-file hashes, not hashes of patched runtime code pages and not
proof of the native ABI. Unknown/mismatching modules fail closed.

Unfinished native work: source-object acquisition by durable ID, target-session
validation, native scheduler ownership, object construction and cleanup, native
media retrieval/completion, submission callback meaning, and actual receipt.
The fixed memory samples only establish object correspondence. The UI serializes
the qword at source DTO +0xB8 into a decimal option string; its correspondence to
MsgSvrID/local ID still requires independently identified runtime samples.

## Verification and rollout

Offline task tests compile the actual task engine and route code with bounded
backend substitutes, including exceptions after submission, held-owner timeout,
deduplication/conflicts, queue limits and shutdown. Locator tests compile the
actual locator with a string-valued DB adapter. Runtime identity tests hash only
their own executable, compare with independent PowerShell SHA-256 and verify
wrong/missing target modules are rejected. These are not WeChat ABI tests.

Build an isolated Release/x64 v143 DLL and a versioned package with file hashes.
Before live testing, review the actual test installation, package digest and
source/destination manifest together. Native capability flags can change only
after per-type runtime evidence. Acceptance remains pending until the recorded
matrix in FORWARD_ACCEPTANCE.md has real receiver-side observations.
