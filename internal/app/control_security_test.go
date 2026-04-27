package app

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIsAllowedOriginHost(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		origin    string
		host      string
		wantAllow bool
	}{
		{name: "same host", origin: "http://localhost:9090", host: "localhost:9090", wantAllow: true},
		{name: "loopback aliases", origin: "http://127.0.0.1:9090", host: "localhost:9090", wantAllow: true},
		{name: "foreign host", origin: "https://evil.example", host: "localhost:9090", wantAllow: false},
		{name: "bad origin", origin: "://bad", host: "localhost:9090", wantAllow: false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := isAllowedOriginHost(tc.origin, tc.host); got != tc.wantAllow {
				t.Fatalf("isAllowedOriginHost(%q, %q) = %v, want %v", tc.origin, tc.host, got, tc.wantAllow)
			}
		})
	}
}

func TestControlPlaneGuardRejectsForeignUnsafeOrigin(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/task/threat", nil)
	req.Host = "localhost:9090"
	req.Header.Set("Origin", "https://evil.example")
	recorder := httptest.NewRecorder()

	controlPlaneGuard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(recorder, req)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusForbidden)
	}
}

func TestControlPlaneGuardRequiresConfiguredToken(t *testing.T) {
	original := appConfig
	appConfig = runtimeConfig{ControlToken: "secret"}
	defer func() {
		appConfig = original
	}()

	req := httptest.NewRequest(http.MethodPost, "/api/task/threat", nil)
	req.Host = "localhost:9090"
	req.Header.Set("Origin", "http://localhost:9090")
	recorder := httptest.NewRecorder()

	controlPlaneGuard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(recorder, req)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusUnauthorized)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/task/threat", nil)
	req.Host = "localhost:9090"
	req.Header.Set("Origin", "http://localhost:9090")
	req.Header.Set(secFlowControlTokenHeader, "secret")
	recorder = httptest.NewRecorder()

	controlPlaneGuard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(recorder, req)

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusNoContent)
	}
}
