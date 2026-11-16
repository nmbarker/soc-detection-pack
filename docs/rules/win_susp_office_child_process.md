# Office Application Spawning Script Interpreter Or LOLBin
Rule: `rules/win_susp_office_child_process.yml` | Level: high | Log source: Windows process creation

## ATT&CK
- T1204.002 User Execution: Malicious File (Execution)
- T1059 Command and Scripting Interpreter (Execution)

## What it catches
Word, Excel, PowerPoint, Outlook, Access, Publisher or Visio starting `cmd`, PowerShell, `wscript`/`cscript`, `mshta`, `rundll32`, `regsvr32`, `certutil` or `bitsadmin`.

## False positives and tuning
- Macro-enabled business workbooks and Office add-ins that call `cmd.exe`/PowerShell. Allow-list by exact document path/add-in and parent+child+CommandLine combination.
- PDF/print/DMS plug-ins that shell out. Filter on the specific plug-in command line, not the whole parent.
- Consider removing `outlook.exe` + `rundll32.exe` if your estate has noisy Outlook helpers.

## Triage runbook
1. Get the document: which file did the user open? Check Office recent files / Sysmon file-create near the event, and mail/download origin (Mark-of-the-Web).
2. Read the child CommandLine. Encoded PowerShell, URLs, `-w hidden` = escalate.
3. Check what the child did: outbound connections, dropped files in `%TEMP%`/`AppData`, persistence (run keys, tasks).
4. Search other recipients of the same attachment/hash.
5. Verdict: legitimate macro (document owner confirms, add exception), suspicious/malicious (isolate host, pull the document, block sender/hash).

## Test notes
Samples: Word -> `cmd.exe`, Excel -> `mshta.exe` match; Explorer -> `cmd.exe` and Word -> `splwow64.exe` do not.
