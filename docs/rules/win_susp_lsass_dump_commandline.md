# LSASS Memory Dump Via Command Line Tools
Rule: `rules/win_susp_lsass_dump_commandline.yml` | Level: high | Log source: Windows process creation

## ATT&CK
- T1003.001 OS Credential Dumping: LSASS Memory (Credential Access)

## What it catches
`comsvcs.dll` `MiniDump` invocations (usually via `rundll32`), and ProcDump naming `lsass`.

## False positives and tuning
- Authorised red-team/pentest: confirm with the engagement calendar; allow-list by tester host.
- Microsoft support dump captures: should be ticketed.
- Does not detect handle-based or API-level dumping (Mimikatz, direct syscalls); pair with LSASS process-access telemetry (Sysmon 10) in a full pack.

## Triage runbook
1. Confirm authorisation (pentest, support ticket). If none, treat as credential theft.
2. Locate the dump file path from the command line; collect it, then delete from host.
3. Identify the account and parent; check which accounts were logged on to the host (their credentials are exposed).
4. Reset exposed credentials, including privileged and service accounts; check Kerberos tickets for reuse.
5. Hunt for lateral movement from the host within the last 24h.

## Test notes
Samples: `rundll32 ... comsvcs.dll, MiniDump` and `procdump64 -ma lsass.exe` match; ProcDump on another process and a benign rundll32 call do not.
