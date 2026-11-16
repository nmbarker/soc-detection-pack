# AWS CloudTrail Logging Stopped Or Trail Deleted
Rule: `rules/aws_cloudtrail_logging_disabled.yml` | Level: high | Log source: AWS CloudTrail

## ATT&CK
- T1685.002 Disable or Modify Cloud Log (Defense Impairment). Same technique as T1562.008 Impair Defenses: Disable or Modify Cloud Logs in ATT&CK v18 and earlier.

## What it catches
CloudTrail `StopLogging` or `DeleteTrail` API calls.

## False positives and tuning
- IaC pipelines that rebuild trails (Terraform/CloudFormation roles). Allow-list by `userIdentity.arn` of the pipeline role.
- Planned decommissioning of an account/region.
- Consider adding `UpdateTrail` and `PutEventSelectors` in a separate rule for log-scope reduction.

## Triage runbook
1. Read the event: principal (`userIdentity`), source IP, user agent, region, target trail ARN.
2. Is the principal an expected pipeline/admin role? Was a change ticket opened?
3. Check other activity from the same principal/IP just before and after (IAM changes, access-key creation, S3/EC2 activity).
4. If unexplained: re-enable logging, revoke the session/keys, rotate credentials, and review the gap in coverage.
5. Check whether other trails (organisation trail, other regions) are still active.

## Test notes
Samples: `StopLogging` and `DeleteTrail` from `cloudtrail.amazonaws.com` match; `DescribeTrails` and an unrelated source do not.
