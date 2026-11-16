# PowerShell Launched With Encoded Command
Rule: `rules/win_susp_powershell_encoded_command.yml` | Level: medium | Log source: Windows process creation (Sysmon 1 / Security 4688 with command line)

## ATT&CK
- T1059.001 Command and Scripting Interpreter: PowerShell (Execution)
- T1027.010 Obfuscated Files or Information: Command Obfuscation (Stealth; "Defense Evasion" in ATT&CK v18 and earlier)

## What it catches
`powershell.exe` / `pwsh.exe` started with `-enc`, `-ec`, `-e` or `/enc` (Base64 script on the command line).

## False positives and tuning
- Monitoring / RMM / deployment agents commonly use `-EncodedCommand`. Allow-list by `ParentImage` (the agent) and a stable `CommandLine` prefix, not by user.
- Some installers wrap setup logic the same way. Baseline for 1-2 weeks, then filter on parent + signed path.
- Raise to `high` when parent is Office, a browser, `wscript`/`mshta`, or the user is not an admin.
- `-e ` short flag can match other tools' args; the Image/OriginalFileName condition limits this to PowerShell.

## Triage runbook
1. Decode the Base64 (`[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String(...))`). Read the decoded script.
2. Identify the parent process and user. Parent is Office/browser/script host = escalate.
3. Look for download cradles (`IEX`, `DownloadString`, `Invoke-WebRequest`), AMSI bypass strings, or `-W Hidden -NoP`.
4. Check what the process did next: network connections, child processes, file writes, new scheduled tasks/services.
5. Scope: same command hash or domain on other hosts in the last 7 days.
6. Verdict: benign management tool (add exception), suspicious (isolate host, collect memory/script block log 4104), confirmed malicious (incident response).

## Test notes
`tests/samples.json` -> 2 matching events (`-enc`, `-ec`) and 2 non-matching (`-File`, non-PowerShell binary with `-enc`). Run `python3 tests/run_tests.py`.
