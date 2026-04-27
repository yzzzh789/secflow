package app

import (
	"net"
	"net/http"
	"net/url"
	"strings"
)

const secFlowControlTokenHeader = "X-SecFlow-Token"

func controlPlaneGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isControlPlaneRequest(r) && !isAllowedHTTPRequestOrigin(r) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		if isControlPlaneRequest(r) && !hasValidControlToken(r) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isControlPlaneRequest(r *http.Request) bool {
	path := r.URL.Path
	if strings.HasPrefix(path, "/ws/") {
		return true
	}
	if !strings.HasPrefix(path, "/api/") {
		return false
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	default:
		return true
	}
}

func hasValidControlToken(r *http.Request) bool {
	token := strings.TrimSpace(appConfig.ControlToken)
	if token == "" {
		return true
	}
	if subtleConstantTimeEqual(strings.TrimSpace(r.Header.Get(secFlowControlTokenHeader)), token) {
		return true
	}
	return subtleConstantTimeEqual(strings.TrimSpace(r.URL.Query().Get("token")), token)
}

func isAllowedHTTPRequestOrigin(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	return isAllowedOriginHost(origin, r.Host)
}

func isAllowedWebSocketOrigin(r *http.Request) bool {
	return isAllowedHTTPRequestOrigin(r)
}

func isAllowedOriginHost(rawOrigin, requestHost string) bool {
	originURL, err := url.Parse(rawOrigin)
	if err != nil {
		return false
	}
	originHost := normalizeRequestHost(originURL.Host)
	host := normalizeRequestHost(requestHost)
	if originHost == "" || host == "" {
		return false
	}
	if strings.EqualFold(originHost, host) {
		return true
	}
	return isLoopbackHost(originHost) && isLoopbackHost(host)
}

func normalizeRequestHost(raw string) string {
	host := strings.TrimSpace(raw)
	if host == "" {
		return ""
	}
	if parsed, _, err := net.SplitHostPort(host); err == nil {
		host = parsed
	}
	host = strings.Trim(host, "[]")
	return strings.ToLower(host)
}

func isLoopbackHost(host string) bool {
	switch strings.ToLower(strings.TrimSpace(host)) {
	case "localhost":
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func subtleConstantTimeEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var result byte
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}
	return result == 0
}
