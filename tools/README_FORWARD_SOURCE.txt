Forward source-object capture (WeChat 4.1.10.27)

Run from this directory:
  powershell -NoProfile -ExecutionPolicy Bypass -File .\capture_forward_source.ps1

Press Enter when ready, then manually forward one received test card to
File Transfer Assistant within the 30-second capture window. Results are saved
under ..\capture. Keep the current WeChat process running; this script only
arms observation probes and does not replace the DLL, edit configuration, or
invoke a native forward function.

The service-entry observation confirms only that execution reached that code
path. It does not prove server-side delivery or successful forwarding.
