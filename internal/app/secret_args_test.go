package app

import "testing"

func TestRedactedArgs(t *testing.T) {
	t.Parallel()

	args := []string{"script.py", "--api-key", "secret", "--api-base=https://example.test", "--api-key=inline"}
	got := redactedArgs(args)

	want := []string{"script.py", "--api-key", "***", "--api-base=https://example.test", "--api-key=***"}
	if len(got) != len(want) {
		t.Fatalf("len(redactedArgs()) = %d, want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("redactedArgs()[%d] = %q, want %q; full args = %v", i, got[i], want[i], got)
		}
	}
	if args[2] != "secret" {
		t.Fatalf("redactedArgs mutated input: %v", args)
	}
}

func TestAPIKeyEnv(t *testing.T) {
	t.Parallel()

	got := apiKeyEnv(" secret ")
	if len(got) != 1 || got[0] != secFlowAIAPIKeyEnv+"=secret" {
		t.Fatalf("apiKeyEnv() = %v", got)
	}
	if got := apiKeyEnv(" "); got != nil {
		t.Fatalf("apiKeyEnv(blank) = %v, want nil", got)
	}
}
