# Developer ecosystem integrations

What exists in the repository today, and what is only a sketch. Nothing
on this page is published to a package manager or marketplace; the real
distribution channels are PyPI (`pip install wpsecscan`), the GitHub
release assets, and a source install.

## VS Code extension

**Status:** source in the repository, not published to the VS Code
marketplace. Two directories: `vscode-extension/` (sidebar findings tree,
diagnostics; see its README) and `editor/vscode/` (a smaller sketch that
wraps the CLI from a terminal command).

## Browser extension and mobile app

**Status:** `browser-extension/` holds source for a browser extension and
`editor/mobile-app/README.md` is a design note. Neither is published.

## Mac `.app` / Linux `.deb` / `.rpm`

**Status:** not provided. There are no build scripts or packages for these.
On macOS and Linux install with `pip install wpsecscan`. If you want a
frozen binary, `build.ps1` builds the Windows executables with PyInstaller.

## CI templates

**Status:** templates for GitLab CI, Jenkins and Azure DevOps are in
`ci/` (`gitlab-ci.yml`, `Jenkinsfile`, `azure-pipelines.yml`). They are
copy-paste templates with no default target: set `WPSEC_TARGET` (or the
Jenkins `TARGET_URL` parameter) to a site you own or are authorised to
test. Native plugins (Jenkins HPI, GitLab catalogue entries) are not
built.

## Web UI (SaaS dashboard)

**Status:** not built. The embedded HTTP API server (`--api-server`)
provides a backend a web UI could use; the existing HTML reports and GUI
cover the dashboard use case.

## Mobile app for alerts

**Status:** not built. Webhook notifications and `wpsecscan push chat`
(Mattermost / RocketChat / Telegram) cover mobile via normal chat-app push
notifications.

## Splunk / Datadog

**Status:** `wpsecscan/siem.py` forwards to Splunk HEC and Datadog; a
packaged Datadog tile or Splunk App is not built.

## Tracking these as issues

If you want any of the unbuilt items prioritised, open a GitHub issue
with the use case.
