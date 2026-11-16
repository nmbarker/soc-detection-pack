# Scheduled Task Created With Suspicious Action Or Path
Rule: `rules/win_susp_schtasks_suspicious_create.yml` | Level: medium | Log source: Windows process creation

## ATT&CK
- T1053.005 Scheduled Task/Job: Scheduled Task (Persistence, Execution)

## What it catches
`schtasks /create` whose arguments reference `AppData`, `Users\Public`, `ProgramData`, `Windows\Temp`, or a script/proxy-execution binary.

## False positives and tuning
- Browser, collaboration, and remote-access updaters register tasks from AppData/ProgramData. Allow-list by task name or signed vendor path.
- Admin PowerShell maintenance jobs. Allow-list by parent script path and account.
- Tighten by requiring `/ru SYSTEM` or `/sc onlogon|onstart|minute` for higher fidelity.

## Triage runbook
1. Read the task name, trigger, run-as user and action (`/tn`, `/sc`, `/ru`, `/tr`).
2. Inspect the target file: hash, signature, location. Empty/random task names and tasks pointing at user-writable paths are suspicious.
3. Identify the creating process and user; check for remote creation (`/s host`).
4. Inspect task XML in `C:\Windows\System32\Tasks\` and look for other persistence.
5. Verdict: legit updater (add exception), malicious (delete task, remove payload, investigate initial access).

## Test notes
Samples: `/create ... C:\Users\Public\a.exe` and `/create ... powershell` match; `/query` and a `/create` pointing at `D:\backup\run.bat` do not.
