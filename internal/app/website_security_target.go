package app

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

type websiteTargetResolution struct {
	Host      string
	Addresses []string
	RiskLevel string
	Reasons   []string
}

func resolveWebsiteTarget(rawURL string) websiteTargetResolution {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return websiteTargetResolution{RiskLevel: "unknown", Reasons: []string{"invalid_url"}}
	}

	host := strings.TrimSpace(parsed.Hostname())
	result := websiteTargetResolution{
		Host:      host,
		RiskLevel: "public",
	}
	if host == "" {
		result.RiskLevel = "unknown"
		result.Reasons = []string{"missing_host"}
		return result
	}

	normalizedHost := strings.TrimSuffix(strings.ToLower(host), ".")
	if normalizedHost == "localhost" || strings.HasSuffix(normalizedHost, ".localhost") {
		result.RiskLevel = "warning"
		result.Reasons = appendUniqueString(result.Reasons, "localhost_name")
	}

	if addr, err := netip.ParseAddr(normalizedHost); err == nil {
		result.Addresses = []string{addr.String()}
		result.Reasons = append(result.Reasons, classifyWebsiteTargetAddress(addr)...)
		result.RiskLevel = riskLevelForTargetReasons(result.Reasons)
		return result
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		if len(result.Reasons) == 0 {
			result.RiskLevel = "unknown"
			result.Reasons = []string{"resolve_failed"}
		}
		return result
	}

	seenAddresses := map[string]struct{}{}
	for _, resolved := range addrs {
		addr, ok := netip.AddrFromSlice(resolved.IP)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		if _, exists := seenAddresses[addr.String()]; exists {
			continue
		}
		seenAddresses[addr.String()] = struct{}{}
		result.Addresses = append(result.Addresses, addr.String())
		result.Reasons = append(result.Reasons, classifyWebsiteTargetAddress(addr)...)
	}
	result.Reasons = uniqueStrings(result.Reasons)
	result.RiskLevel = riskLevelForTargetReasons(result.Reasons)
	return result
}

func classifyWebsiteTargetAddress(addr netip.Addr) []string {
	addr = addr.Unmap()
	reasons := make([]string, 0, 4)
	if addr == netip.MustParseAddr("169.254.169.254") {
		reasons = append(reasons, "cloud_metadata_address")
	}
	if addr.IsLoopback() {
		reasons = append(reasons, "loopback_address")
	}
	if addr.IsPrivate() {
		reasons = append(reasons, "private_address")
	}
	if addr.IsLinkLocalUnicast() {
		reasons = append(reasons, "link_local_address")
	}
	return reasons
}

func riskLevelForTargetReasons(reasons []string) string {
	for _, reason := range reasons {
		switch reason {
		case "localhost_name", "loopback_address", "private_address", "link_local_address", "cloud_metadata_address":
			return "warning"
		}
	}
	if len(reasons) > 0 {
		return "unknown"
	}
	return "public"
}

func (r websiteTargetResolution) isWarning() bool {
	return r.RiskLevel == "warning"
}

func (r websiteTargetResolution) auditMessage(rawURL string) string {
	return fmt.Sprintf(
		"target risk observed for %s: host=%s addresses=%s reasons=%s",
		rawURL,
		r.Host,
		strings.Join(r.Addresses, ","),
		strings.Join(r.Reasons, ","),
	)
}

func uniqueStrings(items []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, exists := seen[item]; exists {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}

func appendUniqueString(items []string, item string) []string {
	for _, existing := range items {
		if existing == item {
			return items
		}
	}
	return append(items, item)
}
