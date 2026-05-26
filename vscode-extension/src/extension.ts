// WPSecScan VS Code extension — minimal MVP.
//
// Features:
//   1. Sidebar "Findings" tree pulled from the most recent wpsecscan
//      JSON report in the workspace (auto-discovered).
//   2. Diagnostics provider that decorates affected files when a finding's
//      `url` field points at a file inside the workspace.
//   3. Command "WPSecScan: Open Report (JSON)" — pick a file manually.
//   4. Command "WPSecScan: Scan current site" — runs the CLI in the
//      integrated terminal using settings.wpsecscan.defaultSite.

import * as vscode from "vscode";
import * as path from "path";
import * as fs from "fs";

type Severity = "info" | "low" | "medium" | "high" | "critical";

interface Finding {
  severity: Severity;
  title: string;
  evidence?: string;
  remediation?: string;
  url?: string;
  extra?: Record<string, unknown>;
}

interface CheckResult {
  check_id: string;
  check_name: string;
  findings: Finding[];
}

interface Report {
  target: string;
  scanned_at: string;
  results: CheckResult[];
}

const SEV_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

const SEV_ICON: Record<Severity, string> = {
  critical: "$(error)",
  high: "$(warning)",
  medium: "$(circle-large-outline)",
  low: "$(info)",
  info: "$(comment)",
};

let currentReport: Report | null = null;
let currentReportPath: string | null = null;

export function activate(context: vscode.ExtensionContext) {
  const diagnostics = vscode.languages.createDiagnosticCollection("wpsecscan");
  context.subscriptions.push(diagnostics);

  const provider = new FindingsTreeProvider();
  vscode.window.registerTreeDataProvider("wpsecscanFindings", provider);

  // Auto-discover the freshest JSON report in the workspace on activation.
  void discoverAndLoad(provider, diagnostics);

  context.subscriptions.push(
    vscode.commands.registerCommand("wpsecscan.openReport", async () => {
      const picks = await vscode.window.showOpenDialog({
        canSelectFiles: true,
        canSelectMany: false,
        filters: { JSON: ["json"] },
        title: "Open WPSecScan JSON report",
      });
      if (picks?.[0]) {
        loadReport(picks[0].fsPath, provider, diagnostics);
      }
    }),
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("wpsecscan.refreshFindings", () => {
      if (currentReportPath) {
        loadReport(currentReportPath, provider, diagnostics);
      } else {
        void discoverAndLoad(provider, diagnostics);
      }
    }),
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("wpsecscan.scanCurrentSite", async () => {
      const cfg = vscode.workspace.getConfiguration("wpsecscan");
      const cliPath = cfg.get<string>("cliPath", "wpsecscan");
      const defaultSite = cfg.get<string>("defaultSite", "");
      const site =
        defaultSite ||
        (await vscode.window.showInputBox({
          prompt: "Site URL to scan",
          placeHolder: "https://example.com",
        }));
      if (!site) {
        return;
      }
      const term = vscode.window.createTerminal("WPSecScan");
      term.sendText(`${cliPath} ${site} --json-only --no-live`);
      term.show();
    }),
  );
}

async function discoverAndLoad(
  provider: FindingsTreeProvider,
  diagnostics: vscode.DiagnosticCollection,
) {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders || folders.length === 0) {
    return;
  }
  // Look for the most recent *.json in obvious places.
  const candidates: string[] = [];
  for (const f of folders) {
    const root = f.uri.fsPath;
    const subdirs = [".", "wpsecscan-reports", "reports", "out"];
    for (const sd of subdirs) {
      const dir = path.join(root, sd);
      try {
        const entries = fs.readdirSync(dir);
        for (const e of entries) {
          if (e.endsWith(".json") && !e.includes("notion") && !e.includes("annotations")) {
            candidates.push(path.join(dir, e));
          }
        }
      } catch {
        // dir doesn't exist
      }
    }
  }
  if (candidates.length === 0) {
    return;
  }
  candidates.sort((a, b) => {
    try {
      return fs.statSync(b).mtimeMs - fs.statSync(a).mtimeMs;
    } catch {
      return 0;
    }
  });
  for (const c of candidates) {
    try {
      const raw = fs.readFileSync(c, "utf8");
      const parsed = JSON.parse(raw);
      if (parsed?.target && Array.isArray(parsed?.results)) {
        loadReport(c, provider, diagnostics);
        return;
      }
    } catch {
      // not a wpsecscan report; keep looking
    }
  }
}

function loadReport(
  filePath: string,
  provider: FindingsTreeProvider,
  diagnostics: vscode.DiagnosticCollection,
) {
  try {
    const raw = fs.readFileSync(filePath, "utf8");
    const parsed = JSON.parse(raw) as Report;
    if (!parsed?.target || !Array.isArray(parsed?.results)) {
      vscode.window.showErrorMessage("Not a WPSecScan JSON report (missing target/results).");
      return;
    }
    currentReport = parsed;
    currentReportPath = filePath;
    provider.refresh();
    populateDiagnostics(parsed, diagnostics);
    vscode.window.setStatusBarMessage(
      `WPSecScan: ${parsed.results.reduce((a, r) => a + r.findings.length, 0)} ` +
        `findings for ${parsed.target}`,
      5000,
    );
  } catch (err) {
    vscode.window.showErrorMessage(`Failed to read report: ${err}`);
  }
}

function populateDiagnostics(report: Report, col: vscode.DiagnosticCollection) {
  col.clear();
  const folders = vscode.workspace.workspaceFolders;
  if (!folders) {
    return;
  }
  // Map findings whose url contains a file:// path or relative workspace path.
  const byFile = new Map<string, vscode.Diagnostic[]>();
  for (const r of report.results) {
    for (const f of r.findings) {
      const matched = resolveToWorkspace(f.url ?? "", folders);
      if (!matched) {
        continue;
      }
      const range = new vscode.Range(0, 0, 0, 0);
      const sev = mapSeverity(f.severity);
      const d = new vscode.Diagnostic(
        range,
        `[${f.severity.toUpperCase()}] ${f.title}` +
          (f.remediation ? `\n\n${f.remediation}` : ""),
        sev,
      );
      d.source = `wpsecscan/${r.check_id}`;
      const arr = byFile.get(matched) ?? [];
      arr.push(d);
      byFile.set(matched, arr);
    }
  }
  for (const [file, diags] of byFile) {
    col.set(vscode.Uri.file(file), diags);
  }
}

function resolveToWorkspace(
  url: string,
  folders: readonly vscode.WorkspaceFolder[],
): string | null {
  if (!url) {
    return null;
  }
  if (url.startsWith("file://")) {
    const p = url.replace(/^file:\/\//, "");
    if (fs.existsSync(p)) {
      return p;
    }
  }
  // Detect plugin/theme paths inside any workspace folder.
  for (const f of folders) {
    const candidate = path.join(f.uri.fsPath, url.replace(/^https?:\/\/[^/]+/, ""));
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }
  return null;
}

function mapSeverity(s: Severity): vscode.DiagnosticSeverity {
  switch (s) {
    case "critical":
    case "high":
      return vscode.DiagnosticSeverity.Error;
    case "medium":
      return vscode.DiagnosticSeverity.Warning;
    case "low":
      return vscode.DiagnosticSeverity.Information;
    default:
      return vscode.DiagnosticSeverity.Hint;
  }
}

// -----------------------------------------------------------------------------
// Tree provider — sidebar listing of severity → check → finding
// -----------------------------------------------------------------------------

class FindingsTreeProvider implements vscode.TreeDataProvider<TreeNode> {
  private _onDidChange = new vscode.EventEmitter<TreeNode | undefined | void>();
  readonly onDidChangeTreeData = this._onDidChange.event;

  refresh(): void {
    this._onDidChange.fire();
  }

  getTreeItem(node: TreeNode): vscode.TreeItem {
    const item = new vscode.TreeItem(node.label, node.collapsible);
    item.description = node.description;
    item.tooltip = node.tooltip;
    item.iconPath = node.iconPath;
    if (node.kind === "finding" && node.findingRef) {
      item.command = {
        command: "vscode.open",
        title: "Open",
        arguments: [vscode.Uri.parse(node.findingRef.url ?? "")],
      };
    }
    return item;
  }

  getChildren(node?: TreeNode): TreeNode[] {
    if (!currentReport) {
      return [
        {
          kind: "header",
          label: "No report loaded",
          collapsible: vscode.TreeItemCollapsibleState.None,
          description: "WPSecScan: Open Report (JSON)",
        },
      ];
    }
    if (!node) {
      // Top: severity buckets
      const buckets = SEV_ORDER.map((sev) => ({
        sev,
        count: currentReport!.results.reduce(
          (a, r) => a + r.findings.filter((f) => f.severity === sev).length,
          0,
        ),
      })).filter((b) => b.count > 0);
      return buckets.map((b) => ({
        kind: "severity",
        sev: b.sev,
        label: `${b.sev.toUpperCase()} (${b.count})`,
        collapsible: vscode.TreeItemCollapsibleState.Expanded,
        description: "",
      }));
    }
    if (node.kind === "severity" && node.sev) {
      // Children: per-check groups
      const groups: TreeNode[] = [];
      for (const r of currentReport.results) {
        const matches = r.findings.filter((f) => f.severity === node.sev);
        if (matches.length === 0) {
          continue;
        }
        groups.push({
          kind: "check",
          checkId: r.check_id,
          checkName: r.check_name,
          sev: node.sev,
          findings: matches,
          label: r.check_name,
          description: `(${matches.length})`,
          collapsible: vscode.TreeItemCollapsibleState.Collapsed,
        });
      }
      return groups;
    }
    if (node.kind === "check" && node.findings) {
      return node.findings.map((f) => ({
        kind: "finding",
        label: f.title,
        description: f.url ?? "",
        tooltip: f.evidence ?? "",
        findingRef: f,
        collapsible: vscode.TreeItemCollapsibleState.None,
      }));
    }
    return [];
  }
}

interface TreeNode {
  kind: "header" | "severity" | "check" | "finding";
  label: string;
  description?: string;
  tooltip?: string;
  iconPath?: vscode.ThemeIcon;
  collapsible: vscode.TreeItemCollapsibleState;
  sev?: Severity;
  checkId?: string;
  checkName?: string;
  findings?: Finding[];
  findingRef?: Finding;
}

export function deactivate() {
  // no-op
}
