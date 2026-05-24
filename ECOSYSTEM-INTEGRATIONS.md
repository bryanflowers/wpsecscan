# Developer ecosystem integrations

The big-name integrations (VS Code extension, native Mac/Linux packagers,
Web UI, mobile app) are partly shipped, partly scaffolded with clear
deferral notes — same pattern as past XL items where the realistic effort
exceeds a single round.

## #73 VS Code extension

**Status:** scaffolded — see `editor/vscode/` directory.

Drop this into a new repo (`wpsecscan-vscode`) and `npm publish` to the
VS Code marketplace. The extension wraps the WPSecScan CLI:

```typescript
// editor/vscode/extension.ts
import * as vscode from 'vscode';
import { spawn } from 'child_process';

export function activate(ctx: vscode.ExtensionContext) {
  ctx.subscriptions.push(
    vscode.commands.registerCommand('wpsecscan.scan', async () => {
      const url = await vscode.window.showInputBox({ prompt: 'WordPress URL' });
      if (!url) return;
      const term = vscode.window.createTerminal('WPSecScan');
      term.sendText(`wpsecscan "${url}" --no-live`);
      term.show();
    })
  );
}
```

Adding find-replace tools, inline finding decorations, and a tree-view of
results requires ~500 more lines.

## #75 Mac `.app` bundle

**Status:** documented build recipe — see `scripts/build-mac.sh`.

Build requires a Mac. From a `mac` runner:

```bash
pip install pyinstaller
pyinstaller --onefile --windowed --name "wpsecscan-gui" run_gui.py
# Bundle into a .app:
mkdir -p "WPSecScan.app/Contents/MacOS"
cp dist/wpsecscan-gui "WPSecScan.app/Contents/MacOS/wpsecscan-gui"
cat > "WPSecScan.app/Contents/Info.plist" <<EOF
<?xml version="1.0"?>
<plist><dict>
<key>CFBundleExecutable</key><string>wpsecscan-gui</string>
<key>CFBundleIdentifier</key><string>com.bryanflowers.wpsecscan</string>
<key>CFBundleName</key><string>WPSecScan</string>
<key>CFBundleVersion</key><string>1.8.0</string>
</dict></plist>
EOF
codesign --force --sign - "WPSecScan.app"
```

Apple notarization adds a paid Apple Developer ID step.

## #76 Linux `.deb` / `.rpm` / Flatpak / Snap

**Status:** documented build recipe — see `scripts/build-linux.sh`.

```bash
# .deb (Debian / Ubuntu)
pip install pyinstaller
pyinstaller --onefile --name wpsecscan run.py
mkdir -p pkg/usr/local/bin pkg/DEBIAN
cp dist/wpsecscan pkg/usr/local/bin/
cat > pkg/DEBIAN/control <<EOF
Package: wpsecscan
Version: 1.8.0
Section: web
Priority: optional
Architecture: amd64
Maintainer: Bryan <bryaninbangkok@gmail.com>
Description: Defensive WordPress security scanner.
EOF
dpkg-deb --build pkg wpsecscan_1.8.0_amd64.deb

# .rpm (Fedora / RHEL)
fpm -s dir -t rpm -n wpsecscan -v 1.8.0 dist/wpsecscan=/usr/local/bin/wpsecscan
```

## #77 Homebrew / Scoop / winget

**Status:** manifest stubs — see `scripts/homebrew-formula.rb`,
`scripts/scoop-manifest.json`, `scripts/winget-manifest.yaml`. Each needs the
release URL + SHA256 of the binary updated per release.

## #78 GitLab / Jenkins / Circle native plugins

**Status:** GitLab CI template already shipped at `ci/gitlab-ci.yml`.
Jenkins / Circle / Bitbucket pipelines available at `ci/Jenkinsfile`,
`ci/circle-config.yml`, `ci/bitbucket-pipelines.yml`. These are template
files — true "native plugin" packaging (Jenkins HPI, GitLab CI catalogue
entries) is deferred.

## #81 Web UI (SaaS dashboard)

**Status:** intentionally deferred — see `WEB-UI.md` for the
architecture sketch. Implementation requires a multi-week Next.js + auth
+ multi-tenant build. The embedded HTTP API server (`--api-server`)
provides the backend — a Web UI would be a thin React client over that.

For now: the existing HTML reports + GUI cover most "dashboard" needs.

## #82 Mobile app for alerts

**Status:** intentionally deferred. The existing webhook + Slack/Discord
bot covers mobile via standard chat-app push notifications. A dedicated
React Native / Flutter app would be ~6 weeks of work for marginal value
over the existing channels.

## #79 Bitbucket Pipelines

**Status:** template shipped at `ci/bitbucket-pipelines.yml`.

## #80 Datadog / Splunk native exporter

**Status:** existing `audit_log_ship.py` ships to Splunk HEC + Datadog
Logs API. A "native" Datadog integration tile or Splunk App requires
their respective marketplace processes; deferred.

## Tracking these as issues

If you want any of the deferred items prioritised, open a GitHub issue
with the use case + we'll plan it in a future round.
