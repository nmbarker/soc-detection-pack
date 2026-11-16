# Certutil Used To Download A File
Rule: `rules/win_susp_certutil_download.yml` | Level: high | Log source: Windows process creation

## ATT&CK
- T1105 Ingress Tool Transfer (Command and Control)

## What it catches
`certutil.exe` (or a renamed copy, via `OriginalFileName`) with `-urlcache` or `-verifyctl` and an `http` URL.

## False positives and tuning
- Rare. PKI/CRL health scripts may fetch CRLs. Allow-list by script parent and destination URL (internal CA host).
- Only filter on URL domain, never on the whole binary.

## Triage runbook
1. Read the URL and output filename. Resolve the host; check reputation with your threat-intel tooling.
2. Parent process and user: interactive shell from a service account or Office parent = escalate.
3. Locate and hash the downloaded file. Check if it was executed afterward (child process, service creation).
4. Hunt for the same URL/hash on other hosts. Block the domain/IP.
5. Verdict: admin CRL fetch (close), malicious download (isolate, collect file, IR).

## Test notes
Samples: `-urlcache -split -f http://...`, and a renamed binary caught via OriginalFileName `-verifyctl`; `-hashfile` and a non-certutil binary do not match.
