package app

import (
	"fmt"
	"net/url"
	"strings"
	"time"
)

func normalizeWebsiteURL(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("网站地址不能为空")
	}

	if !strings.Contains(trimmed, "://") {
		trimmed = "https://" + trimmed
	}

	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", fmt.Errorf("网站地址格式不正确")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("网站地址格式不正确")
	}
	if strings.TrimSpace(parsed.Host) == "" {
		return "", fmt.Errorf("网站地址缺少主机名")
	}

	parsed.Fragment = ""
	if parsed.Path == "" {
		parsed.Path = "/"
	}
	return parsed.String(), nil
}

func parseRFC3339(value string) time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}
	}
	ts, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}
	}
	return ts
}

func generateWebsiteSecurityID(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
}

func cloneWebsiteMonitor(site websiteMonitor) websiteMonitor {
	cloned := site
	cloned.TargetRiskReasons = append([]string(nil), site.TargetRiskReasons...)
	cloned.Checks.Malware.Findings = append([]string(nil), site.Checks.Malware.Findings...)
	cloned.Checks.Content.Findings = append([]string(nil), site.Checks.Content.Findings...)
	cloned.Checks.Baseline.Findings = append([]string(nil), site.Checks.Baseline.Findings...)
	cloned.Checks.Exposure.Findings = append([]string(nil), site.Checks.Exposure.Findings...)
	return cloned
}

func newWebsiteLog(kind, message string) websiteLogEntry {
	return websiteLogEntry{
		Time:    time.Now().Format(time.RFC3339),
		Type:    kind,
		Message: message,
	}
}

func newWebsiteThreat(site websiteMonitor, threatType, title, description, severity string) websiteThreat {
	return websiteThreat{
		ID:          generateWebsiteSecurityID("threat"),
		WebsiteID:   site.ID,
		WebsiteURL:  site.URL,
		Type:        threatType,
		Title:       title,
		Description: description,
		Severity:    severity,
		Time:        time.Now().Format(time.RFC3339),
	}
}

func computeWebsiteUptime(successCount, failureCount int) float64 {
	total := successCount + failureCount
	if total <= 0 {
		return 0
	}
	return float64(successCount) / float64(total) * 100
}
