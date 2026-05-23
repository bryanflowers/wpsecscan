// #73 VS Code extension scaffold for WPSecScan.
//
// To publish to the marketplace:
//   1. cd editor/vscode
//   2. npm install
//   3. npm run package  (creates wpsecscan-vscode-X.Y.Z.vsix)
//   4. vsce publish  (requires a Microsoft account + publisher ID)
//
// Commands provided:
//   wpsecscan.scan          — prompts for URL, runs `wpsecscan` in a terminal
//   wpsecscan.scanCurrentDir — looks for wp-config.php in the workspace + scans the matching domain
//   wpsecscan.openDemo      — runs `wpsecscan --demo`

import * as vscode from 'vscode';
import { spawn } from 'child_process';
import * as path from 'path';
import * as fs from 'fs';

export function activate(ctx: vscode.ExtensionContext) {
  ctx.subscriptions.push(
    vscode.commands.registerCommand('wpsecscan.scan', async () => {
      const url = await vscode.window.showInputBox({
        prompt: 'WordPress URL to scan',
        placeHolder: 'https://example.com',
      });
      if (!url) return;
      const term = vscode.window.createTerminal('WPSecScan');
      term.sendText(`wpsecscan "${url}" --no-live`);
      term.show();
    }),

    vscode.commands.registerCommand('wpsecscan.scanCurrentDir', async () => {
      const ws = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
      if (!ws) {
        vscode.window.showWarningMessage('No workspace open.');
        return;
      }
      const cfg = path.join(ws, 'wp-config.php');
      if (!fs.existsSync(cfg)) {
        vscode.window.showWarningMessage('No wp-config.php in workspace root.');
        return;
      }
      const content = fs.readFileSync(cfg, 'utf8');
      const m = content.match(/define\(\s*['"]WP_HOME['"]\s*,\s*['"]([^'"]+)['"]/);
      if (!m) {
        vscode.window.showWarningMessage('No WP_HOME in wp-config.php.');
        return;
      }
      const term = vscode.window.createTerminal('WPSecScan');
      term.sendText(`wpsecscan "${m[1]}" --no-live`);
      term.show();
    }),

    vscode.commands.registerCommand('wpsecscan.openDemo', () => {
      const term = vscode.window.createTerminal('WPSecScan demo');
      term.sendText('wpsecscan --demo');
      term.show();
    }),
  );
}

export function deactivate() {}
