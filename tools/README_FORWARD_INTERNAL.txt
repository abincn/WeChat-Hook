Deeper Forward path capture (WeChat 4.1.10.27)

Current script ID: FWD-CAP-20261028-04-R3
The ID and script, pipeline, and plan SHA-256 values are printed before capture
and saved in capture_metadata in the raw JSON and analysis report. If capture_metadata is
missing, that capture came from an older script or a direct oneclick run.

Run from this directory:
  powershell -NoProfile -ExecutionPolicy Bypass -File .\capture_forward_internal.ps1

This revision reads the descriptor identity bytes at offset +0x190 and checks
that the loaded DLL advertises follow_read_offset and probe build ID
FWD-PROBE-20261028-04 before arming. An older DLL is rejected without arming.
The standalone entry archives the observed probe status and runtime identity.
Press Enter when ready, then manually forward
one received test card to File Transfer Assistant within the 30-second window. Results are saved under
..\capture. Keep WeChat running. This observes the common Forward business entry (source DTO in R8),
request-wrapper construction, the worker service input, and the UI callback bundle; it does not call a native
send function, replace the DLL, edit configuration, or restart WeChat.

A hit means the code path ran. It does not prove server-side delivery.
