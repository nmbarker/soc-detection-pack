# Download Piped Directly Into A Shell On Linux
Rule: `rules/lnx_susp_curl_wget_pipe_to_shell.yml` | Level: medium | Log source: Linux process creation (auditd execve / Sysmon for Linux / EDR with command line)

## ATT&CK
- T1059.004 Command and Scripting Interpreter: Unix Shell (Execution)
- T1105 Ingress Tool Transfer (Command and Control)

## What it catches
A shell process whose command line contains `curl`/`wget` and a pipe into `sh`/`bash`/`zsh`.

## False positives and tuning
- Vendor install one-liners (package repos, dev tooling) run by admins. Allow-list by domain.
- Provisioning (cloud-init, CI bootstrap). Allow-list by parent and host group.
- This is a behaviour flag, not proof of compromise; keep at `medium` for servers, raise for internet-facing services running as `www-data` etc.

## Triage runbook
1. Read the URL. Resolve and check reputation; fetch the script safely (isolated) to inspect.
2. Parent and user: web server or app service account running this = likely exploitation.
3. Look for follow-on: new cron/systemd units, SSH keys, outbound connections, new binaries in `/tmp`, `/dev/shm`.
4. Hunt for the same URL across the fleet.
5. Verdict: known install (close), unexplained (isolate host, preserve disk/memory).

## Test notes
Samples: `curl ... | sh` and `wget ... |bash` match; a download to disk without piping and a command run as `/usr/bin/curl` image do not.
