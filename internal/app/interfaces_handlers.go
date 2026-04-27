package app

import (
	"bufio"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

type Interface struct {
	Name    string `json:"name"`
	RawName string `json:"rawName"`
}

type nicListPayload struct {
	Nics []Interface `json:"nics"`
}

type nicMetric struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName,omitempty"`
	RawName     string `json:"rawName,omitempty"`
	BytesSent   uint64 `json:"bytes_sent"`
	BytesRecv   uint64 `json:"bytes_recv"`
	PacketsSent uint64 `json:"packets_sent"`
	PacketsRecv uint64 `json:"packets_recv"`
	IsUp        bool   `json:"isup,omitempty"`
	SpeedMbps   int    `json:"speed_mbps,omitempty"`
	MTU         int    `json:"mtu,omitempty"`
}

type nicMetricsPayload struct {
	Nics  []nicMetric `json:"nics"`
	Error string      `json:"error,omitempty"`
}

const interfacesCacheTTL = 30 * time.Second
const nicListCacheTTL = 15 * time.Second

var (
	interfaceLinePattern = regexp.MustCompile(`\s*\d+:\s*(.*?)\s*\(Raw Name:\s*(.*?)\)`)
	interfacesCache      jsonResponseCache
	nicListCache         jsonResponseCache
)

func buildInterfacesPayload(output []byte) ([]byte, error) {
	var nicPayload nicListPayload
	if err := json.Unmarshal(output, &nicPayload); err == nil && len(nicPayload.Nics) > 0 {
		for index := range nicPayload.Nics {
			if strings.TrimSpace(nicPayload.Nics[index].RawName) == "" {
				nicPayload.Nics[index].RawName = nicPayload.Nics[index].Name
			}
		}
		return json.Marshal(nicPayload.Nics)
	}

	interfaces := make([]Interface, 0)
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		matches := interfaceLinePattern.FindStringSubmatch(scanner.Text())
		if len(matches) == 3 {
			interfaces = append(interfaces, Interface{
				Name:    strings.TrimSpace(matches[1]),
				RawName: strings.TrimSpace(matches[2]),
			})
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return json.Marshal(interfaces)
}

func interfaceDiscoveryArgs() []string {
	interfaceScript := resolveRuntimePath(resolveProjectRoot(), "", "scripts/list_interfaces.py")
	if _, err := os.Stat(interfaceScript); err == nil {
		return []string{interfaceScript}
	}
	return []string{appConfig.PacketAnalyzerScriptArg(), "list-interfaces"}
}

func nicDiscoveryArgs() []string {
	nicScript := resolveRuntimePath(resolveProjectRoot(), "", "scripts/list_nics.py")
	if _, err := os.Stat(nicScript); err == nil {
		return []string{nicScript}
	}

	legacyScript := resolveRuntimePath(resolveProjectRoot(), "", "traffic_monitor/list_nics.py")
	return []string{legacyScript}
}

func buildNICListResponse(output []byte) ([]byte, error) {
	var payload nicMetricsPayload
	if err := json.Unmarshal(output, &payload); err != nil {
		return nil, err
	}
	if strings.TrimSpace(payload.Error) != "" {
		return nil, newBadRequestError(payload.Error)
	}

	items := make([]nicMetric, 0, len(payload.Nics))
	seen := make(map[string]struct{}, len(payload.Nics))
	for _, item := range payload.Nics {
		item.Name = strings.TrimSpace(item.Name)
		item.RawName = strings.TrimSpace(item.RawName)
		item.DisplayName = strings.TrimSpace(item.DisplayName)

		if item.Name == "" {
			if item.RawName != "" {
				item.Name = item.RawName
			} else if item.DisplayName != "" {
				item.Name = item.DisplayName
			}
		}
		if item.RawName == "" {
			item.RawName = item.Name
		}
		if item.DisplayName == "" {
			item.DisplayName = item.Name
		}
		if item.Name == "" {
			continue
		}
		if _, exists := seen[item.Name]; exists {
			continue
		}
		seen[item.Name] = struct{}{}
		items = append(items, item)
	}

	sort.SliceStable(items, func(i, j int) bool {
		leftBytes := items[i].BytesSent + items[i].BytesRecv
		rightBytes := items[j].BytesSent + items[j].BytesRecv
		if items[i].IsUp != items[j].IsUp {
			return items[i].IsUp
		}
		if leftBytes != rightBytes {
			return leftBytes > rightBytes
		}
		return strings.ToLower(items[i].DisplayName) < strings.ToLower(items[j].DisplayName)
	})

	return json.Marshal(map[string]any{
		"success": true,
		"nics":    items,
	})
}

func handleGetInterfaces(w http.ResponseWriter, r *http.Request) {
	if proxyHostAgentRequest(w, r) {
		return
	}

	log.Println("Request received for /api/interfaces")
	if payload, ok := interfacesCache.load(time.Now()); ok {
		writeJSONBytes(w, http.StatusOK, payload)
		return
	}

	cmd := newPythonCommand(interfaceDiscoveryArgs()...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("Error executing python script: %s\nOutput: %s", err, string(output))
		http.Error(w, "failed to run interface discovery script", http.StatusInternalServerError)
		return
	}

	payload, err := buildInterfacesPayload(output)
	if err != nil {
		log.Printf("Error encoding interfaces to JSON: %s", err)
		http.Error(w, errJSONEncodeResponse, http.StatusInternalServerError)
		return
	}

	writeJSONBytes(w, http.StatusOK, interfacesCache.store(payload, interfacesCacheTTL))
}
