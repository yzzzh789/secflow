package app

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestNormalizeWebsiteURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		rawURL  string
		wantURL string
		wantErr bool
	}{
		{
			name:    "keeps http url and strips fragment",
			rawURL:  " https://example.com/path?q=1#section ",
			wantURL: "https://example.com/path?q=1",
		},
		{
			name:    "rejects empty",
			rawURL:  "   ",
			wantErr: true,
		},
		{
			name:    "rejects unsupported scheme",
			rawURL:  "ftp://example.com/file.txt",
			wantErr: true,
		},
		{
			name:    "rejects missing host",
			rawURL:  "https:///only-path",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := normalizeWebsiteURL(tt.rawURL)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("normalizeWebsiteURL() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeWebsiteURL() error = %v", err)
			}
			if got != tt.wantURL {
				t.Fatalf("normalizeWebsiteURL() = %q, want %q", got, tt.wantURL)
			}
		})
	}
}

func TestResolveWebsiteTargetClassifiesSensitiveAddresses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		rawURL     string
		wantRisk   string
		wantReason string
	}{
		{
			name:       "localhost name",
			rawURL:     "http://localhost:8080",
			wantRisk:   "warning",
			wantReason: "localhost_name",
		},
		{
			name:       "loopback address",
			rawURL:     "http://127.10.20.30",
			wantRisk:   "warning",
			wantReason: "loopback_address",
		},
		{
			name:       "private address",
			rawURL:     "https://192.168.1.10",
			wantRisk:   "warning",
			wantReason: "private_address",
		},
		{
			name:       "link local address",
			rawURL:     "http://169.254.10.20",
			wantRisk:   "warning",
			wantReason: "link_local_address",
		},
		{
			name:       "cloud metadata address",
			rawURL:     "http://169.254.169.254/latest/meta-data/",
			wantRisk:   "warning",
			wantReason: "cloud_metadata_address",
		},
		{
			name:     "public ip address",
			rawURL:   "https://8.8.8.8",
			wantRisk: "public",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := resolveWebsiteTarget(tt.rawURL)
			if got.RiskLevel != tt.wantRisk {
				t.Fatalf("resolveWebsiteTarget().RiskLevel = %q, want %q; reasons=%v", got.RiskLevel, tt.wantRisk, got.Reasons)
			}
			if tt.wantReason != "" && !slices.Contains(got.Reasons, tt.wantReason) {
				t.Fatalf("resolveWebsiteTarget().Reasons = %v, want %q", got.Reasons, tt.wantReason)
			}
		})
	}
}

func TestEvaluateWebsiteRecordsTargetRiskAudit(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	service := &websiteSecurityService{client: server.Client()}
	site := websiteMonitor{
		ID:              "site_test",
		URL:             server.URL,
		IntervalMinutes: 15,
		Checks: websiteMonitorChecks{
			Tamper:       websiteContentCheck{Status: "pending"},
			Malware:      websiteIssueCheck{Status: "pending"},
			Content:      websiteIssueCheck{Status: "pending"},
			Availability: websiteAvailabilityCheck{Status: "pending"},
			Baseline:     websiteIssueCheck{Status: "pending"},
			Exposure:     websiteIssueCheck{Status: "pending"},
		},
	}

	updated, _, logs := service.evaluateWebsite(site)
	if updated.TargetRiskLevel != "warning" {
		t.Fatalf("TargetRiskLevel = %q, want warning", updated.TargetRiskLevel)
	}
	if !slices.Contains(updated.TargetRiskReasons, "loopback_address") {
		t.Fatalf("TargetRiskReasons = %v, want loopback_address", updated.TargetRiskReasons)
	}

	foundAudit := false
	for _, entry := range logs {
		if entry.Type == "audit" && entry.Message != "" {
			foundAudit = true
			break
		}
	}
	if !foundAudit {
		t.Fatalf("evaluateWebsite() logs = %#v, want audit entry", logs)
	}
}

func TestNormalizeWebsiteSecurityCheckConcurrency(t *testing.T) {
	t.Parallel()

	if got := normalizeWebsiteSecurityCheckConcurrency(2); got != 2 {
		t.Fatalf("normalizeWebsiteSecurityCheckConcurrency(2) = %d, want 2", got)
	}
	if got := normalizeWebsiteSecurityCheckConcurrency(0); got != defaultWebsiteSecurityCheckConcurrency {
		t.Fatalf("normalizeWebsiteSecurityCheckConcurrency(0) = %d, want default", got)
	}
}

func TestWebsiteSecurityPerformCheckHonorsConcurrencyLimit(t *testing.T) {
	t.Parallel()

	var active int32
	var maxActive int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		current := atomic.AddInt32(&active, 1)
		for {
			peak := atomic.LoadInt32(&maxActive)
			if current <= peak || atomic.CompareAndSwapInt32(&maxActive, peak, current) {
				break
			}
		}
		time.Sleep(30 * time.Millisecond)
		atomic.AddInt32(&active, -1)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	statePath := filepath.Join(t.TempDir(), "website_security_state.json")
	service := &websiteSecurityService{
		statePath: statePath,
		client:    server.Client(),
		checkSem:  make(chan struct{}, 1),
	}
	service.state = websiteSecurityState{
		Websites: []websiteMonitor{
			newTestWebsiteMonitor("site_1", server.URL),
			newTestWebsiteMonitor("site_2", server.URL),
			newTestWebsiteMonitor("site_3", server.URL),
		},
	}

	var wg sync.WaitGroup
	for _, site := range service.state.Websites {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			service.performCheck(id)
		}(site.ID)
	}
	wg.Wait()

	if got := atomic.LoadInt32(&maxActive); got != 1 {
		t.Fatalf("max concurrent checks = %d, want 1", got)
	}
	for _, site := range service.state.Websites {
		if site.Checking {
			t.Fatalf("site %s still checking", site.ID)
		}
		if site.SummaryStatus == "pending" {
			t.Fatalf("site %s SummaryStatus remained pending", site.ID)
		}
	}
}

func newTestWebsiteMonitor(id, rawURL string) websiteMonitor {
	pendingMessage := "waiting"
	return websiteMonitor{
		ID:              id,
		URL:             rawURL,
		IntervalMinutes: 15,
		SummaryStatus:   "pending",
		SummaryMessage:  pendingMessage,
		Checks: websiteMonitorChecks{
			Tamper:       websiteContentCheck{Status: "pending", Message: pendingMessage},
			Malware:      websiteIssueCheck{Status: "pending", Message: pendingMessage},
			Content:      websiteIssueCheck{Status: "pending", Message: pendingMessage},
			Availability: websiteAvailabilityCheck{Status: "pending", Message: pendingMessage},
			Baseline:     websiteIssueCheck{Status: "pending", Message: pendingMessage},
			Exposure:     websiteIssueCheck{Status: "pending", Message: pendingMessage},
		},
	}
}
