package app

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

var proxiedNetworkTasks = map[string]struct{}{
	taskKeyThreat:   {},
	taskKeyBehavior: {},
	taskKeyLAN:      {},
	taskKeyNIC:      {},
}

func isNetworkTask(taskName string) bool {
	_, ok := proxiedNetworkTasks[taskName]
	return ok
}

func shouldManageTaskLocally(taskName string) bool {
	if !isNetworkTask(taskName) {
		return true
	}
	return !appConfig.ShouldProxyHostAgent()
}

func hostAgentBaseURL() (*url.URL, error) {
	if !appConfig.ShouldProxyHostAgent() {
		return nil, fmt.Errorf("host agent proxy is not enabled")
	}
	target, err := url.Parse(appConfig.HostAgentURL)
	if err != nil {
		return nil, fmt.Errorf("invalid host agent url %q: %w", appConfig.HostAgentURL, err)
	}
	if target.Scheme == "" || target.Host == "" {
		return nil, fmt.Errorf("host agent url must include scheme and host")
	}
	return target, nil
}

func copyHeaders(dst, src http.Header) {
	for key, values := range src {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func proxyHostAgentRequest(w http.ResponseWriter, r *http.Request) bool {
	if !appConfig.ShouldProxyHostAgent() {
		return false
	}

	target, err := hostAgentBaseURL()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return true
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Host = target.Host
		req.Header.Set("X-Secflow-Proxy", "control-plane")
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("host agent proxy error for %s: %v", r.URL.Path, err)
		http.Error(w, "Host agent unavailable: "+err.Error(), http.StatusBadGateway)
	}
	proxy.ServeHTTP(w, r)
	return true
}

func hostAgentHealth() healthComponent {
	target, err := hostAgentBaseURL()
	if err != nil {
		return healthComponent{Status: "fail", Message: err.Error()}
	}

	healthURL := *target
	healthURL.Path = strings.TrimRight(target.Path, "/") + "/healthz"
	healthURL.RawQuery = ""

	client := &http.Client{Timeout: 2 * time.Second}
	req, err := http.NewRequest(http.MethodGet, healthURL.String(), nil)
	if err != nil {
		return healthComponent{Status: "fail", Message: err.Error(), Path: healthURL.String()}
	}
	req.Header.Set("X-Secflow-Proxy", "control-plane-healthcheck")

	resp, err := client.Do(req)
	if err != nil {
		return healthComponent{Status: "degraded", Message: err.Error(), Path: healthURL.String()}
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return healthComponent{
			Status:  "degraded",
			Message: fmt.Sprintf("host agent returned HTTP %d", resp.StatusCode),
			Path:    healthURL.String(),
		}
	}

	return healthComponent{
		Status:  "ok",
		Message: "host agent reachable",
		Path:    healthURL.String(),
	}
}
