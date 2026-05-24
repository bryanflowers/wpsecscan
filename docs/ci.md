# CI / CD integration

## GitHub Actions

```yaml
name: WPSecScan
on:
  pull_request:
  schedule:
    - cron: "0 4 * * 1"   # Mondays 04:00 UTC
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: actions/setup-python@v6
        with:
          python-version: "3.12"
      - run: pip install wpsecscan
      - run: wpsecscan --target ${{ vars.TARGET_URL }} --json report.json
      - run: wpsecscan ci-gate report.json --max-critical 0 --max-high 2
      - uses: actions/upload-artifact@v5
        with:
          name: wpsecscan-report
          path: report.json
```

## GitLab CI

```yaml
wpsecscan:
  image: python:3.12-slim
  script:
    - pip install wpsecscan
    - wpsecscan --target $TARGET_URL --json report.json
    - wpsecscan ci-gate report.json --max-critical 0 --max-high 2
  artifacts:
    paths: [report.json]
    reports:
      sast: report.json
```

## Jenkins

```groovy
pipeline {
  agent any
  stages {
    stage('WPSecScan') {
      steps {
        sh 'pip install wpsecscan'
        sh 'wpsecscan --target ${TARGET_URL} --json report.json'
        sh 'wpsecscan ci-gate report.json --max-critical 0'
        archiveArtifacts artifacts: 'report.json'
      }
    }
  }
}
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Scan complete, gate satisfied |
| `1` | Scan complete, gate failed (findings over threshold) |
| `2` | Scan errored (network, target unreachable) |
| `3` | Configuration error (bad flags, missing input) |

`ci-gate` only checks thresholds; the scan itself uses `0` for "ran
cleanly regardless of findings". Use `ci-gate` to fail the build.
