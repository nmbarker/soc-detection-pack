# Account Added To Local Administrators Group Via Command Line
Rule: `rules/win_susp_local_admin_group_add.yml` | Level: medium | Log source: Windows process creation

## ATT&CK
- T1098 Account Manipulation (Persistence, Privilege Escalation)

## What it catches
`net`/`net1 localgroup administrators <user> /add`, and PowerShell `Add-LocalGroupMember ... Administrators`.

## False positives and tuning
- Helpdesk and provisioning/imaging automation. Allow-list by parent and the target account.
- Localised Windows builds may use different group names (e.g. "Administratoren"). Add them if relevant.
- Complement with Security Event 4732 for non-command-line additions.

## Triage runbook
1. Identify the added account (local or domain), who ran the command, and from which parent.
2. Was the account just created (event 4720) or is it an existing user being elevated?
3. Check ticketing for an approved request.
4. If unapproved: remove the account from the group, disable it, review logons by that account, inspect for follow-on persistence.

## Test notes
Samples: `net1 localgroup administrators evil /add` and PowerShell `Add-LocalGroupMember` match; listing the group and adding to `users` do not.
