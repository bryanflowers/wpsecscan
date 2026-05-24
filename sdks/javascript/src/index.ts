// WPSecScan JavaScript/TypeScript SDK — Round-64 #142
// Thin fetch-based wrapper around the daemon REST API.

export interface ScanSummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface ScanReport {
  scan_id: string;
  target: string;
  status: "running" | "complete" | "failed";
  summary?: ScanSummary;
  risk_score?: number;
}

export interface Finding {
  severity: string;
  title: string;
  evidence: string;
  remediation: string;
  url: string;
}

export interface ClientOptions {
  baseUrl: string;
  token?: string;
  timeoutMs?: number;
}

export class WPSecScanClient {
  private baseUrl: string;
  private headers: Record<string, string>;
  private timeoutMs: number;

  constructor(opts: ClientOptions) {
    this.baseUrl = opts.baseUrl.replace(/\/$/, "");
    this.headers = { "Content-Type": "application/json" };
    if (opts.token) this.headers["Authorization"] = `Bearer ${opts.token}`;
    this.timeoutMs = opts.timeoutMs ?? 30000;
  }

  private async req<T>(method: string, path: string, body?: unknown): Promise<T> {
    const ctrl = new AbortController();
    const id = setTimeout(() => ctrl.abort(), this.timeoutMs);
    try {
      const r = await fetch(`${this.baseUrl}${path}`, {
        method,
        headers: this.headers,
        body: body ? JSON.stringify(body) : undefined,
        signal: ctrl.signal,
      });
      if (!r.ok) throw new Error(`HTTP ${r.status} ${r.statusText}`);
      return (await r.json()) as T;
    } finally {
      clearTimeout(id);
    }
  }

  async startScan(target: string, aggressive = false): Promise<string> {
    const r = await this.req<{ scan_id: string }>("POST", "/scans", { target, aggressive });
    return r.scan_id;
  }

  async getScan(scanId: string): Promise<ScanReport> {
    return this.req<ScanReport>("GET", `/scans/${scanId}`);
  }

  async waitForScan(scanId: string, pollMs = 5000, timeoutMs = 600000): Promise<ScanReport> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const r = await this.getScan(scanId);
      if (r.status === "complete" || r.status === "failed") return r;
      await new Promise((res) => setTimeout(res, pollMs));
    }
    throw new Error(`Scan ${scanId} did not complete within ${timeoutMs}ms`);
  }

  async listScans(limit = 50): Promise<ScanReport[]> {
    const r = await this.req<{ scans: ScanReport[] }>("GET", `/scans?limit=${limit}`);
    return r.scans;
  }

  async listSites(): Promise<Array<{ id: string; name: string; url: string }>> {
    const r = await this.req<{ sites: Array<{ id: string; name: string; url: string }> }>("GET", "/sites");
    return r.sites;
  }

  async getFindings(scanId: string, severity?: string): Promise<Finding[]> {
    const qp = severity ? `?severity=${encodeURIComponent(severity)}` : "";
    const r = await this.req<{ findings: Finding[] }>("GET", `/scans/${scanId}/findings${qp}`);
    return r.findings;
  }
}

export default WPSecScanClient;
