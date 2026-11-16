# Windows Event Log Cleared Via Command Line
Rule: `rules/win_susp_eventlog_cleared.yml` | Level: high | Log source: Windows process creation

## ATT&CK
- T1685.005 Clear Windows Event Logs (Stealth). Same technique as T1070.001 Indicator Removal: Clear Windows Event Logs in ATT&CK v18 and earlier.

## What it catches
`wevtutil cl` / `clear-log`, and PowerShell `Clear-EventLog` / `Remove-EventLog`.

## False positives and tuning
- Imaging/lab reset scripts. Allow-list by host group and parent script.
- Admins clearing logs after troubleshooting; require a ticket.
- Also monitor Security 1102 / System 104 events (not covered by this rule) for clearing by other means.

## Triage runbook
1. Which log was cleared (Security is highest concern) and by which account/parent?
2. Pull logs from the SIEM/forwarder; the local copy is gone, so check what was shipped before the clear.
3. Look at the hour before the clear for the activity being hidden (logons, new accounts, tool execution).
4. Treat unexplained clearing on a server as a likely active intrusion: isolate and escalate.

## Test notes
Samples: `wevtutil cl Security` and `Clear-EventLog` match; `wevtutil qe` and `Get-EventLog` do not.
