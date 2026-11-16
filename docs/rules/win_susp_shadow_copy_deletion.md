# Shadow Copy Or Backup Recovery Deletion
Rule: `rules/win_susp_shadow_copy_deletion.yml` | Level: high | Log source: Windows process creation

## ATT&CK
- T1490 Inhibit System Recovery (Impact)

## What it catches
`vssadmin delete shadows`, `wmic shadowcopy delete`, `wbadmin delete catalog`, `bcdedit ... recoveryenabled no`.

## False positives and tuning
- Backup/maintenance jobs that prune shadow copies; allow-list by parent (backup agent) and host group.
- Imaging/rebuild procedures. Pair with change tickets.
- Treat any hit on a server outside a maintenance window as urgent.

## Triage runbook
1. Treat as possible ransomware precursor. Immediately check the host for mass file renames/new extensions and ransom notes.
2. Identify parent process and account; check for earlier staging (LSASS dump, lateral movement, remote tool use).
3. If unexplained: isolate host now, disable the account, preserve memory.
4. Check neighbouring hosts for the same command in the last hour.
5. Verdict: documented maintenance (close, note ticket), unexplained (declare incident).

## Test notes
Samples: vssadmin, wmic, bcdedit matches; `vssadmin list shadows` and `bcdedit /enum` do not.
