> 公开脱敏副本：真实账号、会话、消息标识和机器地址不公开。采集原件、IDA分析及验收明细仅本地保留；文中的相关路径不代表仓库包含这些文件。

# Forward live acceptance — pending

Manual UI reference evidence is now available for all four types in suite
`forward-suite-20261028-230158-8baead13a467`. The operator confirmed four new
messages received in filehelper and both image/file openability. Native source
and service identity fragments match the selected DB messages. This establishes
the manual reference path only; none of the automatic /ForwardMsg cases below
has been executed or passed. Missing-local-resource download remains untested.

No row below has been executed or passed. Offline tests and service-entry hits
cannot fill this table. Record the suite/case ID, probe+target module digest,
source MsgSvrID, target session, native result, receiver message and outcome for
each real run. User-provided friend/group test sessions must be designated before
active sending. The current native adapter is unavailable, so active acceptance
must not run yet.

| Message | File transfer assistant | Friend | Group |
| --- | --- | --- | --- |
| Text | pending | pending | pending |
| Link card | pending | pending | pending |
| Image, local resource ready | pending | pending | pending |
| File, local resource ready | pending | pending | pending |

Additional required cases: image and file not downloaded locally → native
retrieval → transfer → receiver can open; non-existent source; ambiguous source;
invalid/vanished destination; retrieval failure; retrieval timeout; duplicate
request; uncertain native completion; repeated operations; failure followed by
success; and process restart with old task ID returning not found.

For text compare the received text, for a link compare the title and destination,
and for media verify openability plus stable size/hash where available. Explicitly
record unobservable receiver checks as unverified. A queued task, local database
row or UI callback alone does not establish receiver acceptance.

Test installation discovered read-only:
`C:\Program Files\Tencent\Weixin\4.1.10.27`, install root
`C:\Program Files\Tencent\Weixin`, HTTP port 30001 on the test machine.
Existing authentication configuration is retained; secrets are not packaged.
Installation/restart and active test sends require the consolidated live-step
confirmation described in the accepted implementation plan.
