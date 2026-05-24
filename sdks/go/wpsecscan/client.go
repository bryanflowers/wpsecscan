// Package wpsecscan — Go SDK for the WPSecScan daemon — Round-64 #143.
package wpsecscan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const Version = "2.2.0"

// Summary represents the per-severity counts in a scan report.
type Summary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// ScanReport is a daemon /scans/:id response.
type ScanReport struct {
	ScanID     string  `json:"scan_id"`
	Target     string  `json:"target"`
	Status     string  `json:"status"` // running / complete / failed
	Summary    Summary `json:"summary"`
	RiskScore  float64 `json:"risk_score"`
	ScannedAt  string  `json:"scanned_at"`
}

// Finding is one row.
type Finding struct {
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Evidence    string `json:"evidence"`
	Remediation string `json:"remediation"`
	URL         string `json:"url"`
}

// Client wraps the daemon API.
type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

// New returns a configured client.
func New(baseURL, token string) *Client {
	return &Client{
		BaseURL: baseURL,
		Token:   token,
		HTTP:    &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *Client) req(ctx context.Context, method, path string, body interface{}, into interface{}) error {
	var reader *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(b)
	}
	var req *http.Request
	var err error
	if reader != nil {
		req, err = http.NewRequestWithContext(ctx, method, c.BaseURL+path, reader)
	} else {
		req, err = http.NewRequestWithContext(ctx, method, c.BaseURL+path, nil)
	}
	if err != nil {
		return err
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("daemon returned %s", resp.Status)
	}
	if into != nil {
		return json.NewDecoder(resp.Body).Decode(into)
	}
	return nil
}

// StartScan kicks off a scan; returns the scan ID.
func (c *Client) StartScan(ctx context.Context, target string, aggressive bool) (string, error) {
	var out struct {
		ScanID string `json:"scan_id"`
	}
	body := map[string]interface{}{"target": target, "aggressive": aggressive}
	if err := c.req(ctx, "POST", "/scans", body, &out); err != nil {
		return "", err
	}
	return out.ScanID, nil
}

// GetScan fetches a scan's current state.
func (c *Client) GetScan(ctx context.Context, scanID string) (*ScanReport, error) {
	var r ScanReport
	if err := c.req(ctx, "GET", "/scans/"+scanID, nil, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// WaitForScan polls until status != "running" or timeout.
func (c *Client) WaitForScan(ctx context.Context, scanID string, pollEvery, timeout time.Duration) (*ScanReport, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		r, err := c.GetScan(ctx, scanID)
		if err != nil {
			return nil, err
		}
		if r.Status == "complete" || r.Status == "failed" {
			return r, nil
		}
		select {
		case <-time.After(pollEvery):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return nil, fmt.Errorf("scan %s did not complete within %s", scanID, timeout)
}

// GetFindings lists findings (optionally filtered by severity).
func (c *Client) GetFindings(ctx context.Context, scanID, severity string) ([]Finding, error) {
	var out struct {
		Findings []Finding `json:"findings"`
	}
	path := "/scans/" + scanID + "/findings"
	if severity != "" {
		path += "?severity=" + severity
	}
	if err := c.req(ctx, "GET", path, nil, &out); err != nil {
		return nil, err
	}
	return out.Findings, nil
}
