package app

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWriteJSON(t *testing.T) {
	t.Parallel()

	recorder := httptest.NewRecorder()
	writeJSON(recorder, http.StatusCreated, map[string]string{"status": "ok"})

	if recorder.Code != http.StatusCreated {
		t.Fatalf("writeJSON() status = %d, want %d", recorder.Code, http.StatusCreated)
	}

	if got := recorder.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("writeJSON() content-type = %q, want application/json", got)
	}

	if body := recorder.Body.String(); !strings.Contains(body, `"status":"ok"`) {
		t.Fatalf("writeJSON() body = %q", body)
	}
}

func TestWriteJSONBytes(t *testing.T) {
	t.Parallel()

	recorder := httptest.NewRecorder()
	writeJSONBytes(recorder, http.StatusAccepted, []byte(`{"cached":true}`))

	if recorder.Code != http.StatusAccepted {
		t.Fatalf("writeJSONBytes() status = %d, want %d", recorder.Code, http.StatusAccepted)
	}

	if got := recorder.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("writeJSONBytes() content-type = %q, want application/json", got)
	}

	if body := strings.TrimSpace(recorder.Body.String()); body != `{"cached":true}` {
		t.Fatalf("writeJSONBytes() body = %q", body)
	}
}
