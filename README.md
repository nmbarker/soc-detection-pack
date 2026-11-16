# SOC Detection Pack (free validation release)

10 tuned [Sigma](https://sigmahq.io) detection rules, each with ATT&CK mapping, false-positive and tuning notes, a short triage runbook, and sample-log tests proving it fires. Plus one agent skill that triages alerts from these rules.

> **Disclaimer:** these rules are not a guarantee of detection. They are starting points: test and tune them in your own environment before using them in production. Provided as is, without warranty.

## Contents
| Path | What |
|---|---|
| `rules/` | 10 Sigma rules (`.yml`) |
| `docs/rules/` | per-rule ATT&CK, false positives, tuning, triage runbook, test notes |
| `skills/soc-alert-triage/SKILL.md` | agent skill for alert triage |
| `tests/samples.json`, `tests/run_tests.py` | match / no-match sample events per rule and a runner |

## Rules
| Rule | ATT&CK | Level |
|---|---|---|
| `win_susp_powershell_encoded_command` | T1059.001, T1027.010 | medium |
| `win_susp_office_child_process` | T1204.002, T1059 | high |
| `win_susp_certutil_download` | T1105 | high |
| `win_susp_shadow_copy_deletion` | T1490 | high |
| `win_susp_lsass_dump_commandline` | T1003.001 | high |
| `win_susp_schtasks_suspicious_create` | T1053.005 | medium |
| `win_susp_local_admin_group_add` | T1098 | medium |
| `win_susp_eventlog_cleared` | T1685.005 (was T1070.001) | high |
| `lnx_susp_curl_wget_pipe_to_shell` | T1059.004, T1105 | medium |
| `aws_cloudtrail_logging_disabled` | T1685.002 (was T1562.008) | high |

ATT&CK tags follow the technique catalogue bundled in pySigma 1.5.1 (ATT&CK v20.1), where "Defense Evasion" is renamed "Stealth" and some techniques moved. Old IDs are noted above for older ATT&CK versions.

## Scope
Windows process creation (Sysmon 1 or Security 4688 with command line), Linux process creation, and AWS CloudTrail. Rules are behavioural starting points, not complete coverage; tune per environment using each rule's doc. Each rule is `status: experimental` until it has run against your data.

## Provenance
All rules and docs were written in-house from public knowledge (MITRE ATT&CK, vendor documentation, general detection-engineering practice). They use no client or employer data, rules, tickets, or environments; sample events are synthetic (`example.test` URLs, generic paths and names). No rule is copied or derived from SigmaHQ. If any SigmaHQ-derived rule is added later, it must keep Detection Rule License (DRL) 1.1 attribution and be listed here.

## Licence
- Rules (`rules/`) and rule docs (`docs/`): [Detection Rule License (DRL) 1.1](LICENSE-DRL.md).
- Scripts (`tests/`) and the agent skill (`skills/`): [MIT](LICENSE-MIT.txt).

## Validate
```
python3 -m pip install --target .tools/pylib sigma-cli pysigma-backend-splunk pysigma-backend-elasticsearch pysigma-backend-sqlite pysigma-pipeline-windows pysigma-pipeline-sysmon
sh .tools/sigma check rules
python3 tests/run_tests.py
```
`run_tests.py` converts every rule to SQLite (and executes it over the sample events), Splunk SPL, and Elasticsearch Lucene (ECS Windows). It exits non-zero on any mismatch.

## Paid version
Interested in a paid v1 (30-50 rules, more log sources, tuned exception packs)? Add a 👍 or comment on the waitlist issue: https://github.com/nmbarker/soc-detection-pack/issues/1 (GitHub reactions and comments are public; this is not an email list).
