package app

import "strings"

const secFlowAIAPIKeyEnv = "SECFLOW_AI_API_KEY"

func redactedArgs(args []string) []string {
	out := append([]string(nil), args...)
	for i := 0; i < len(out); i++ {
		if isSecretArgName(out[i]) {
			if strings.Contains(out[i], "=") {
				out[i] = strings.SplitN(out[i], "=", 2)[0] + "=***"
				continue
			}
			if i+1 < len(out) {
				out[i+1] = "***"
			}
		}
	}
	return out
}

func isSecretArgName(arg string) bool {
	name := strings.TrimSpace(arg)
	if before, _, ok := strings.Cut(name, "="); ok {
		name = before
	}
	switch strings.ToLower(name) {
	case "--api-key", "-api-key":
		return true
	default:
		return false
	}
}

func apiKeyEnv(apiKey string) []string {
	apiKey = strings.TrimSpace(apiKey)
	if apiKey == "" {
		return nil
	}
	return []string{secFlowAIAPIKeyEnv + "=" + apiKey}
}
