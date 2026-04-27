package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func (s *websiteSecurityService) evaluateWebsite(site websiteMonitor) (websiteMonitor, []websiteThreat, []websiteLogEntry) {
	now := time.Now()
	site.LastCheckAt = now.Format(time.RFC3339)

	logs := []websiteLogEntry{newWebsiteLog("检测", fmt.Sprintf("开始检测 %s", site.URL))}
	var threats []websiteThreat
	target := resolveWebsiteTarget(site.URL)
	site.TargetRiskLevel = target.RiskLevel
	site.TargetRiskReasons = target.Reasons
	if target.isWarning() {
		logs = append(logs, newWebsiteLog("audit", target.auditMessage(site.URL)))
	}

	fetchResult, fetchErr := s.fetchWebsite(site.URL)
	if fetchErr != nil {
		site.Checks.Availability.Count++
		site.Checks.Availability.LastCheckAt = now.Format(time.RFC3339)
		site.Checks.Availability.Status = "danger"
		site.Checks.Availability.Message = fmt.Sprintf("璁块棶澶辫触: %v", fetchErr)
		site.Checks.Availability.FailureCount++
		site.Checks.Availability.Uptime = computeWebsiteUptime(site.Checks.Availability.SuccessCount, site.Checks.Availability.FailureCount)
		site.Checks.Availability.ResponseTimeMs = 0
		site.Checks.Availability.HTTPStatus = 0
		site.Checks.Availability.SSLDaysRemaining = 0
		site.LastError = fetchErr.Error()
		site.SummaryStatus = "danger"
		site.SummaryMessage = "缃戠珯涓嶅彲璁块棶"

		threats = append(threats, newWebsiteThreat(site, "availability", "缃戠珯涓嶅彲璁块棶", fetchErr.Error(), "high"))
		logs = append(logs, newWebsiteLog("閿欒", fmt.Sprintf("%s 璁块棶澶辫触: %v", site.URL, fetchErr)))
		logs = append(logs, newWebsiteLog("妫€娴?", fmt.Sprintf("瀹屾垚妫€娴?%s", site.URL)))
		return site, threats, logs
	}

	site.LastError = ""
	site.Checks.Availability = evaluateAvailability(site.Checks.Availability, fetchResult)
	site.Checks.Tamper, threats = evaluateTamper(site, fetchResult, site.Checks.Tamper, threats)
	site.Checks.Malware, threats = evaluateMalware(site, fetchResult, site.Checks.Malware, threats)
	site.Checks.Content, threats = evaluateContent(site, fetchResult, site.Checks.Content, threats)
	site.Checks.Baseline, threats = evaluateBaseline(site, fetchResult, site.Checks.Baseline, threats)
	site.Checks.Exposure, threats = s.evaluateExposure(site, site.Checks.Exposure, threats)
	site.SummaryStatus, site.SummaryMessage = summarizeWebsiteChecks(site.Checks)

	logs = append(logs, newWebsiteLog("妫€娴?", fmt.Sprintf("瀹屾垚妫€娴?%s锛岀姸鎬? %s", site.URL, statusLabel(site.SummaryStatus))))
	return site, threats, logs
}

func (s *websiteSecurityService) fetchWebsite(targetURL string) (*websiteFetchResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "SecFlow Website Security Monitor/1.0")

	start := time.Now()
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, err
	}

	result := &websiteFetchResult{
		CheckedAt:      time.Now(),
		ResponseTimeMs: int(time.Since(start).Milliseconds()),
		StatusCode:     resp.StatusCode,
		Body:           body,
		BodyLower:      strings.ToLower(string(body)),
		Headers:        resp.Header.Clone(),
	}

	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		days := int(time.Until(resp.TLS.PeerCertificates[0].NotAfter).Hours() / 24)
		if days < 0 {
			days = 0
		}
		result.SSLDaysRemaining = days
	}

	return result, nil
}

func evaluateAvailability(previous websiteAvailabilityCheck, fetchResult *websiteFetchResult) websiteAvailabilityCheck {
	updated := previous
	updated.Count++
	updated.LastCheckAt = fetchResult.CheckedAt.Format(time.RFC3339)
	updated.ResponseTimeMs = fetchResult.ResponseTimeMs
	updated.HTTPStatus = fetchResult.StatusCode
	updated.SSLDaysRemaining = fetchResult.SSLDaysRemaining

	if fetchResult.StatusCode >= 200 && fetchResult.StatusCode < 400 {
		updated.Status = "safe"
		updated.SuccessCount++
		updated.Message = fmt.Sprintf("鍝嶅簲 %d ms锛孒TTP %d", fetchResult.ResponseTimeMs, fetchResult.StatusCode)
	} else if fetchResult.StatusCode >= 400 && fetchResult.StatusCode < 500 {
		updated.Status = "warning"
		updated.SuccessCount++
		updated.Message = fmt.Sprintf("绔欑偣鍙闂紝浣嗚繑鍥?HTTP %d", fetchResult.StatusCode)
	} else {
		updated.Status = "danger"
		updated.FailureCount++
		updated.Message = fmt.Sprintf("绔欑偣涓嶅彲鐢紝HTTP %d", fetchResult.StatusCode)
	}

	updated.Uptime = computeWebsiteUptime(updated.SuccessCount, updated.FailureCount)
	return updated
}

func evaluateTamper(site websiteMonitor, fetchResult *websiteFetchResult, previous websiteContentCheck, threats []websiteThreat) (websiteContentCheck, []websiteThreat) {
	updated := previous
	updated.Count++
	updated.LastCheckAt = fetchResult.CheckedAt.Format(time.RFC3339)

	hashBytes := sha256.Sum256(fetchResult.Body)
	currentHash := hex.EncodeToString(hashBytes[:])
	updated.LastHash = currentHash

	if updated.BaselineHash == "" {
		updated.BaselineHash = currentHash
		updated.Status = "safe"
		updated.IssueCount = 0
		updated.Message = "宸插缓绔嬮涓〉闈㈠唴瀹瑰熀绾?"
		return updated, threats
	}

	if currentHash != previous.LastHash && previous.LastHash != "" {
		updated.Status = "warning"
		updated.IssueCount = 1
		updated.Message = "椤甸潰鍐呭鐩歌緝涓婃妫€娴嬪彂鐢熷彉鍖?"
		threats = append(threats, newWebsiteThreat(site, "tamper", "页面内容发生变化", "页面内容哈希与上次检测结果不一致，请确认是否为预期更新。", "medium"))
		return updated, threats
	}

	updated.Status = "safe"
	updated.IssueCount = 0
	updated.Message = "椤甸潰鍐呭鏈彂鐢熷紓甯稿彉鍖?"
	return updated, threats
}

func evaluateMalware(site websiteMonitor, fetchResult *websiteFetchResult, previous websiteIssueCheck, threats []websiteThreat) (websiteIssueCheck, []websiteThreat) {
	updated := previous
	updated.Count++
	updated.LastCheckAt = fetchResult.CheckedAt.Format(time.RFC3339)
	updated.Findings = collectMalwareIndicators(fetchResult.BodyLower)
	updated.IssueCount = len(updated.Findings)

	switch {
	case updated.IssueCount >= 3:
		updated.Status = "danger"
		updated.Message = fmt.Sprintf("妫€娴嬪埌 %d 椤归珮椋庨櫓鑴氭湰鐗瑰緛", updated.IssueCount)
		threats = append(threats, newWebsiteThreat(site, "malware", "妫€娴嬪埌鍙枒鑴氭湰鐗瑰緛", strings.Join(updated.Findings, "锛?"), "high"))
	case updated.IssueCount > 0:
		updated.Status = "warning"
		updated.Message = fmt.Sprintf("妫€娴嬪埌 %d 椤瑰彲鐤戣剼鏈壒寰?", updated.IssueCount)
		threats = append(threats, newWebsiteThreat(site, "malware", "椤甸潰瀛樺湪鍙枒鑴氭湰鐗瑰緛", strings.Join(updated.Findings, "锛?"), "medium"))
	default:
		updated.Status = "safe"
		updated.Message = "鏈彂鐜版槑鏄炬伓鎰忚剼鏈壒寰?"
	}

	return updated, threats
}

func evaluateContent(site websiteMonitor, fetchResult *websiteFetchResult, previous websiteIssueCheck, threats []websiteThreat) (websiteIssueCheck, []websiteThreat) {
	updated := previous
	updated.Count++
	updated.LastCheckAt = fetchResult.CheckedAt.Format(time.RFC3339)
	updated.Findings = collectSensitiveContentMatches(fetchResult.BodyLower)
	updated.IssueCount = len(updated.Findings)

	if updated.IssueCount > 0 {
		updated.Status = "warning"
		updated.Message = fmt.Sprintf("妫€娴嬪埌 %d 椤规晱鎰熷唴瀹瑰叧閿瓧", updated.IssueCount)
		threats = append(threats, newWebsiteThreat(site, "content", "椤甸潰鍐呭鍖呭惈鏁忔劅鍏抽敭瀛?", strings.Join(updated.Findings, "锛?"), "medium"))
		return updated, threats
	}

	updated.Status = "safe"
	updated.Message = "鏈彂鐜版晱鎰熷唴瀹瑰叧閿瓧"
	return updated, threats
}

func evaluateBaseline(site websiteMonitor, fetchResult *websiteFetchResult, previous websiteIssueCheck, threats []websiteThreat) (websiteIssueCheck, []websiteThreat) {
	updated := previous
	updated.Count++
	updated.LastCheckAt = fetchResult.CheckedAt.Format(time.RFC3339)
	updated.Findings = collectBaselineIssues(site.URL, fetchResult.Headers)
	updated.IssueCount = len(updated.Findings)

	switch {
	case updated.IssueCount >= 4:
		updated.Status = "danger"
		updated.Message = fmt.Sprintf("瀛樺湪 %d 椤瑰畨鍏ㄥ熀绾跨己鍙?", updated.IssueCount)
		threats = append(threats, newWebsiteThreat(site, "baseline", "缃戠珯瀹夊叏鍩虹嚎椋庨櫓杈冮珮", strings.Join(updated.Findings, "锛?"), "high"))
	case updated.IssueCount > 0:
		updated.Status = "warning"
		updated.Message = fmt.Sprintf("瀛樺湪 %d 椤瑰畨鍏ㄥ熀绾跨己鍙?", updated.IssueCount)
		threats = append(threats, newWebsiteThreat(site, "baseline", "发现网站安全基线缺口", strings.Join(updated.Findings, "；"), "medium"))
	default:
		updated.Status = "safe"
		updated.Message = "鍏抽敭瀹夊叏鍝嶅簲澶撮厤缃甯?"
	}

	return updated, threats
}

func (s *websiteSecurityService) evaluateExposure(site websiteMonitor, previous websiteIssueCheck, threats []websiteThreat) (websiteIssueCheck, []websiteThreat) {
	updated := previous
	updated.Count++
	updated.LastCheckAt = time.Now().Format(time.RFC3339)
	updated.Findings = s.scanSensitiveExposure(site.URL)
	updated.IssueCount = len(updated.Findings)

	switch {
	case updated.IssueCount >= 2:
		updated.Status = "danger"
		updated.Message = fmt.Sprintf("鍙戠幇 %d 椤规晱鎰熸毚闇插叆鍙?", updated.IssueCount)
		threats = append(threats, newWebsiteThreat(site, "exposure", "鍙戠幇鏁忔劅鏆撮湶鍏ュ彛", strings.Join(updated.Findings, "锛?"), "high"))
	case updated.IssueCount == 1:
		updated.Status = "warning"
		updated.Message = "鍙戠幇 1 椤规晱鎰熸毚闇插叆鍙?"
		threats = append(threats, newWebsiteThreat(site, "exposure", "妫€娴嬪埌鏁忔劅鏆撮湶鍏ュ彛", updated.Findings[0], "medium"))
	default:
		updated.Status = "safe"
		updated.Message = "鏈彂鐜板父瑙佹晱鎰熸毚闇插叆鍙?"
	}

	return updated, threats
}

func (s *websiteSecurityService) scanSensitiveExposure(targetURL string) []string {
	baseURL, err := url.Parse(targetURL)
	if err != nil {
		return nil
	}

	probes := []struct {
		Path      string
		Label     string
		Validator func(int, string) bool
	}{
		{Path: "/.env", Label: ".env 閰嶇疆鏂囦欢鍙兘鏆撮湶", Validator: func(code int, body string) bool {
			return code == http.StatusOK && strings.Contains(body, "=")
		}},
		{Path: "/.git/HEAD", Label: ".git 鐩綍鍙兘鏆撮湶", Validator: func(code int, body string) bool {
			return code == http.StatusOK && strings.Contains(body, "ref:")
		}},
		{Path: "/phpinfo.php", Label: "phpinfo 椤甸潰鍙兘鏆撮湶", Validator: func(code int, body string) bool {
			return code == http.StatusOK && strings.Contains(body, "phpinfo")
		}},
		{Path: "/actuator/health", Label: "Actuator 鍋ュ悍鎺ュ彛鍙兘鏆撮湶", Validator: func(code int, body string) bool {
			return code == http.StatusOK && strings.Contains(body, "status")
		}},
		{Path: "/server-status?auto", Label: "Apache server-status 鍙兘鏆撮湶", Validator: func(code int, body string) bool {
			return code == http.StatusOK && strings.Contains(body, "serverversion")
		}},
	}

	findings := make([]string, 0, len(probes))
	for _, probe := range probes {
		if len(findings) >= 4 {
			break
		}

		probeURL := *baseURL
		probeURL.Path = probe.Path
		probeURL.RawQuery = ""
		if strings.Contains(probe.Path, "?") {
			pathParts := strings.SplitN(probe.Path, "?", 2)
			probeURL.Path = pathParts[0]
			probeURL.RawQuery = pathParts[1]
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL.String(), nil)
		if err != nil {
			cancel()
			continue
		}
		req.Header.Set("User-Agent", "SecFlow Exposure Probe/1.0")

		resp, err := s.client.Do(req)
		if err != nil {
			cancel()
			continue
		}

		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 2048))
		_ = resp.Body.Close()
		cancel()
		if readErr != nil {
			continue
		}

		if probe.Validator(resp.StatusCode, strings.ToLower(string(body))) {
			findings = append(findings, probe.Label)
		}
	}

	return findings
}

func collectMalwareIndicators(bodyLower string) []string {
	patterns := []struct {
		Needles []string
		Label   string
	}{
		{Needles: []string{"eval(", "atob("}, Label: "妫€娴嬪埌娣锋穯鎵ц鐗瑰緛"},
		{Needles: []string{"fromcharcode(", "unescape("}, Label: "检测到编码解混淆特征"},
		{Needles: []string{"<iframe", "display:none"}, Label: "妫€娴嬪埌闅愯棌 iframe 鐗瑰緛"},
		{Needles: []string{"powershell", "cmd.exe"}, Label: "妫€娴嬪埌鍛戒护鎵ц鍏抽敭瀛?"},
		{Needles: []string{"document.write(", "base64,"}, Label: "妫€娴嬪埌鑴氭湰娉ㄥ叆鐗瑰緛"},
	}

	findings := make([]string, 0, len(patterns))
	for _, pattern := range patterns {
		matchAll := true
		for _, needle := range pattern.Needles {
			if !strings.Contains(bodyLower, needle) {
				matchAll = false
				break
			}
		}
		if matchAll {
			findings = append(findings, pattern.Label)
		}
	}
	return findings
}

func collectSensitiveContentMatches(bodyLower string) []string {
	keywords := []string{
		"鍗氬僵",
		"璧屽崥",
		"鑹叉儏",
		"鎴愪汉鏈嶅姟",
		"鍔炶瘉",
		"浠ｅ紑鍙戠エ",
		"浠跨墝",
		"鍏悎褰?",
	}

	findings := make([]string, 0, len(keywords))
	for _, keyword := range keywords {
		if strings.Contains(bodyLower, strings.ToLower(keyword)) {
			findings = append(findings, fmt.Sprintf("鍛戒腑鏁忔劅鍏抽敭瀛? %s", keyword))
		}
	}
	return findings
}

func collectBaselineIssues(targetURL string, headers http.Header) []string {
	findings := make([]string, 0, 6)

	requiredHeaders := []struct {
		Key   string
		Label string
	}{
		{Key: "Content-Security-Policy", Label: "缺少 Content-Security-Policy"},
		{Key: "X-Frame-Options", Label: "缺少 X-Frame-Options"},
		{Key: "X-Content-Type-Options", Label: "缺少 X-Content-Type-Options"},
		{Key: "Referrer-Policy", Label: "缺少 Referrer-Policy"},
	}

	for _, header := range requiredHeaders {
		if strings.TrimSpace(headers.Get(header.Key)) == "" {
			findings = append(findings, header.Label)
		}
	}

	if strings.HasPrefix(strings.ToLower(targetURL), "https://") && strings.TrimSpace(headers.Get("Strict-Transport-Security")) == "" {
		findings = append(findings, "缺少 Strict-Transport-Security")
	}

	if serverHeader := strings.TrimSpace(headers.Get("Server")); serverHeader != "" {
		findings = append(findings, fmt.Sprintf("鏆撮湶 Server 鏍囪瘑: %s", serverHeader))
	}
	if poweredBy := strings.TrimSpace(headers.Get("X-Powered-By")); poweredBy != "" {
		findings = append(findings, fmt.Sprintf("鏆撮湶 X-Powered-By: %s", poweredBy))
	}

	return findings
}

func summarizeWebsiteChecks(checks websiteMonitorChecks) (string, string) {
	ordered := []struct {
		Status  string
		Message string
	}{
		{checks.Availability.Status, checks.Availability.Message},
		{checks.Exposure.Status, checks.Exposure.Message},
		{checks.Malware.Status, checks.Malware.Message},
		{checks.Baseline.Status, checks.Baseline.Message},
		{checks.Content.Status, checks.Content.Message},
		{checks.Tamper.Status, checks.Tamper.Message},
	}

	for _, item := range ordered {
		if item.Status == "danger" {
			return "danger", item.Message
		}
	}
	for _, item := range ordered {
		if item.Status == "warning" {
			return "warning", item.Message
		}
	}
	for _, item := range ordered {
		if item.Status == "pending" {
			return "pending", item.Message
		}
	}
	return "safe", "鎵€鏈夋娴嬮」姝ｅ父"
}

func statusLabel(status string) string {
	switch status {
	case "safe":
		return "姝ｅ父"
	case "warning":
		return "鍛婅"
	case "danger":
		return "楂樺嵄"
	case "pending":
		return "寰呮娴?"
	default:
		return "鏈煡"
	}
}
