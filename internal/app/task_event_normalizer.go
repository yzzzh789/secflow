package app

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

var ansiEscapePattern = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func cleanProcessText(line string) string {
	return strings.TrimSpace(ansiEscapePattern.ReplaceAllString(line, ""))
}

func eventTimestamp() int64 {
	return time.Now().Unix()
}

func boolFromAny(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return strings.EqualFold(x, "true")
	default:
		return false
	}
}

func normalizedEvent(source, stream, rawType, level, message string, payload map[string]any, raw string) string {
	if payload == nil {
		payload = map[string]any{}
	}

	event := normalizedTaskEvent{
		Version:   "v1",
		Source:    source,
		Stream:    stream,
		Type:      rawType,
		Level:     level,
		Message:   message,
		Timestamp: eventTimestamp(),
		Payload:   payload,
		Raw:       raw,
	}

	if encoded, err := json.Marshal(event); err == nil {
		return string(encoded)
	}
	fallback, _ := json.Marshal(normalizedTaskEvent{
		Version:   "v1",
		Source:    source,
		Stream:    stream,
		Type:      "raw_text",
		Level:     "error",
		Message:   "failed to encode normalized event",
		Timestamp: eventTimestamp(),
		Payload:   map[string]any{"text": raw},
		Raw:       raw,
	})
	return string(fallback)
}

func normalizeProcessLine(source, finishMessage string, line ProcessLine) string {
	raw := strings.TrimSpace(line.Text)
	clean := cleanProcessText(raw)
	if clean == "" {
		return normalizedEvent(source, line.Stream, "raw_text", "info", "", map[string]any{"text": ""}, raw)
	}

	if finishMessage != "" && clean == finishMessage {
		return normalizedEvent(source, line.Stream, "task_finished", "info", "task finished", map[string]any{}, clean)
	}

	var obj map[string]any
	if err := json.Unmarshal([]byte(clean), &obj); err == nil {
		if _, ok := obj["id"]; ok && obj["analysis"] != nil {
			level := "info"
			message := "packet captured"
			if analysis, ok := obj["analysis"].(map[string]any); ok {
				if boolFromAny(analysis["is_threat"]) {
					level = "warning"
					if threatType, ok := analysis["threat_type"].(string); ok && strings.TrimSpace(threatType) != "" {
						message = threatType
					} else {
						message = "threat detected"
					}
				} else if summary, ok := analysis["summary"].(string); ok && strings.TrimSpace(summary) != "" {
					message = summary
				}
			}
			return normalizedEvent(source, line.Stream, "packet_event", level, message, obj, clean)
		}

		for _, key := range []string{"info", "warning", "error"} {
			if val, ok := obj[key]; ok {
				msg := fmt.Sprint(val)
				level := key
				eventType := "status"
				if key == "error" {
					eventType = "error"
				}
				return normalizedEvent(source, line.Stream, eventType, level, msg, obj, clean)
			}
		}

		msgType, _ := obj["type"].(string)
		level := "info"
		message, _ := obj["message"].(string)
		payload := map[string]any{}
		for k, v := range obj {
			if k == "type" || k == "message" {
				continue
			}
			payload[k] = v
		}

		switch msgType {
		case "error":
			level = "error"
		case "warning":
			level = "warning"
		case "security_alert":
			level = "error"
			if message == "" {
				message = "security alert"
			}
		case "activity_log":
			if _, ok := obj["data"]; ok {
				payload = map[string]any{"sessions": obj["data"]}
			}
			msgType = "session_batch"
			if message == "" {
				message = "behavior sessions updated"
			}
		case "behavior_report":
			msgType = "lan_report"
			if message == "" {
				message = "lan behavior updated"
			}
		case "realtime_data", "live_series", "history_data", "statistics":
			msgType = "nic_telemetry"
			payload["metricType"] = obj["type"]
			if data, ok := obj["data"]; ok {
				payload["data"] = data
			}
			if message == "" {
				message = "nic telemetry updated"
			}
		case "status", "info":
			msgType = "status"
		case "":
			msgType = "json"
		}

		if message == "" {
			message = msgType
		}
		return normalizedEvent(source, line.Stream, msgType, level, message, payload, clean)
	}

	level := "info"
	eventType := "raw_text"
	switch {
	case line.Stream == "stderr":
		level = "error"
		eventType = "stderr"
	case strings.HasPrefix(clean, "Traceback"):
		level = "error"
		eventType = "python_traceback"
	case strings.HasPrefix(clean, "ModuleNotFoundError"), strings.HasPrefix(clean, "File "), strings.HasPrefix(clean, "from "):
		level = "error"
		eventType = "python_traceback"
	case strings.Contains(strings.ToLower(clean), "error"):
		level = "error"
		eventType = "stderr"
	case strings.Contains(strings.ToLower(clean), "warning"):
		level = "warning"
	}
	return normalizedEvent(source, line.Stream, eventType, level, clean, map[string]any{"text": clean}, clean)
}
