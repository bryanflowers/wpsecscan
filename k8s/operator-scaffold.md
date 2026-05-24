# WPSecScan Kubernetes Operator — design scaffold

Round-64 #106 — design doc for a future operator. Not implemented.

## CRDs

```yaml
apiVersion: wpsecscan.io/v1alpha1
kind: WordPressTarget
metadata:
  name: example-com
spec:
  url: https://example.com
  scanInterval: 24h
  aggressive: false
  notifySlack: https://hooks.slack.com/services/.../...
  thresholds:
    critical: 0
    high: 0
```

```yaml
apiVersion: wpsecscan.io/v1alpha1
kind: ScanResult
metadata:
  name: example-com-2026-05-24
spec:
  target: example-com
  summary:
    critical: 0
    high: 2
    medium: 5
status:
  phase: Complete
  startedAt: "2026-05-24T02:00:00Z"
  finishedAt: "2026-05-24T02:02:34Z"
```

## Operator responsibilities

1. Watch `WordPressTarget` resources.
2. For each, schedule a CronJob that runs wpsecscan against the URL.
3. On completion, create a `ScanResult` resource.
4. Compare against thresholds; if exceeded, fire a Slack webhook.
5. Garbage-collect ScanResults older than 90 days.

## Building

Use kubebuilder:
```bash
kubebuilder init --domain wpsecscan.io
kubebuilder create api --group wpsecscan --version v1alpha1 --kind WordPressTarget
kubebuilder create api --group wpsecscan --version v1alpha1 --kind ScanResult
```

## Out of scope (today)

- Multi-cluster federation
- Webhook admission controller for "block deploy if scan score < B"
- Operator-managed Grafana dashboard provisioning

## Why not just CronJobs?

You can use CronJobs directly — the operator just adds:
- declarative scan-policy management
- result lifecycle (no shell scripts in cron)
- webhook integration without bash glue
