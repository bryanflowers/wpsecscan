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
      - run: wpsecscan "${{ vars.TARGET_URL }}" --json-only --out reports --fail-on high
      - uses: actions/upload-artifact@v5
        if: always()
        with:
          name: wpsecscan-report
          path: reports/
```

## GitLab CI

```yaml
wpsecscan:
  image: python:3.12-slim
  script:
    - pip install wpsecscan
    - wpsecscan "$TARGET_URL" --json-only --out reports --fail-on high
  artifacts:
    when: always
    paths: [reports/]
```

## Jenkins

```groovy
pipeline {
  agent any
  stages {
    stage('WPSecScan') {
      steps {
        sh 'pip install wpsecscan'
        sh 'wpsecscan "${TARGET_URL}" --json-only --out reports --fail-on critical'
        archiveArtifacts artifacts: 'reports/**'
      }
    }
  }
}
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Scan complete, clean or info-only (or below the `--fail-on` threshold) |
| `1` | Medium findings (default exit-code logic) |
| `2` | Critical or high findings, or a finding at or above `--fail-on` |
| `130` | Ctrl+C |

`--fail-on LEVEL` overrides the default exit-code logic: the scan exits
`2` when any finding is at or above that severity. Ready-made templates
for GitLab CI, Jenkins and Azure DevOps are in the repository's `ci/`
directory; they require `WPSEC_TARGET` / `TARGET_URL` to be set and have
no default target. Only point them at sites you own or are authorised to test.
