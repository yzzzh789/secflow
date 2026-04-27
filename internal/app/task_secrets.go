package app

import (
	"strings"
	"sync"
)

var taskAPIKeys = struct {
	mu     sync.Mutex
	values map[string]string
}{
	values: make(map[string]string),
}

func rememberTaskAPIKey(taskName, apiKey string) {
	taskName = strings.TrimSpace(taskName)
	apiKey = strings.TrimSpace(apiKey)
	if taskName == "" {
		return
	}

	taskAPIKeys.mu.Lock()
	defer taskAPIKeys.mu.Unlock()
	if apiKey == "" {
		delete(taskAPIKeys.values, taskName)
		return
	}
	taskAPIKeys.values[taskName] = apiKey
}

func taskAPIKey(taskName string) string {
	taskAPIKeys.mu.Lock()
	defer taskAPIKeys.mu.Unlock()
	return taskAPIKeys.values[strings.TrimSpace(taskName)]
}

func forgetTaskAPIKey(taskName string) {
	rememberTaskAPIKey(taskName, "")
}
