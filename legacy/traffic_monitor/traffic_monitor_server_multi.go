package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/gorilla/websocket"
)

const clientSendBuffer = 256

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

type Client struct {
	conn *websocket.Conn
	send chan []byte
}

type Hub struct {
	clients    map[*Client]bool
	broadcast  chan []byte
	register   chan *Client
	unregister chan *Client
}

func newHub() *Hub {
	return &Hub{
		clients:    make(map[*Client]bool),
		broadcast:  make(chan []byte, clientSendBuffer),
		register:   make(chan *Client),
		unregister: make(chan *Client),
	}
}

func (h *Hub) run() {
	for {
		select {
		case client := <-h.register:
			h.clients[client] = true
			log.Printf("client connected, active connections=%d", len(h.clients))

		case client := <-h.unregister:
			h.removeClient(client)
			log.Printf("client disconnected, active connections=%d", len(h.clients))

		case message := <-h.broadcast:
			for client := range h.clients {
				select {
				case client.send <- message:
				default:
					h.removeClient(client)
				}
			}
		}
	}
}

func (h *Hub) removeClient(client *Client) {
	if _, ok := h.clients[client]; !ok {
		return
	}

	delete(h.clients, client)
	close(client.send)
}

type NICMonitor struct {
	nic      string
	cmd      *exec.Cmd
	stopChan chan struct{}
	stopOnce sync.Once
	stopping atomic.Bool
}

type MultiNICMonitorService struct {
	monitors map[string]*NICMonitor
	hub      *Hub
	mu       sync.RWMutex

	warningMbps  float64
	criticalMbps float64

	baselineSeconds        int
	warmupSeconds          int
	minBaselineSamples     int
	warningMultiplier      float64
	criticalMultiplier     float64
	warningMadFactor       float64
	criticalMadFactor      float64
	warningSustainSeconds  int
	criticalSustainSeconds int
	recoverySeconds        int
	cooldownSeconds        int
	recoveryRatio          float64
}

func NewMultiNICMonitorService(hub *Hub) *MultiNICMonitorService {
	return &MultiNICMonitorService{
		monitors:               make(map[string]*NICMonitor),
		hub:                    hub,
		warningMbps:            10,
		criticalMbps:           50,
		baselineSeconds:        300,
		warmupSeconds:          60,
		minBaselineSamples:     30,
		warningMultiplier:      1.3,
		criticalMultiplier:     1.8,
		warningMadFactor:       3.0,
		criticalMadFactor:      5.0,
		warningSustainSeconds:  10,
		criticalSustainSeconds: 5,
		recoverySeconds:        15,
		cooldownSeconds:        60,
		recoveryRatio:          0.8,
	}
}

func getPythonCommand() (string, []string) {
	if pythonBin := os.Getenv("PYTHON_BIN"); pythonBin != "" {
		return pythonBin, nil
	}

	if _, err := exec.LookPath("python"); err == nil {
		return "python", nil
	}

	if _, err := exec.LookPath("python3"); err == nil {
		return "python3", nil
	}

	if runtime.GOOS == "windows" {
		if _, err := exec.LookPath("py"); err == nil {
			return "py", []string{"-3"}
		}
		return "py", []string{"-3"}
	}

	return "python3", nil
}

func (s *MultiNICMonitorService) StartMonitor(nic string) error {
	s.mu.Lock()
	if _, exists := s.monitors[nic]; exists {
		s.mu.Unlock()
		return fmt.Errorf("NIC %s is already being monitored", nic)
	}

	pythonCmd, pythonArgs := getPythonCommand()
	args := append(pythonArgs,
		"-u", "simple_traffic_monitor.py",
		"--nic", nic,
		"--interval", "1",
		"--warning-mbps", fmt.Sprintf("%.0f", s.warningMbps),
		"--critical-mbps", fmt.Sprintf("%.0f", s.criticalMbps),
		"--baseline-seconds", fmt.Sprintf("%d", s.baselineSeconds),
		"--warmup-seconds", fmt.Sprintf("%d", s.warmupSeconds),
		"--min-baseline-samples", fmt.Sprintf("%d", s.minBaselineSamples),
		"--warning-multiplier", fmt.Sprintf("%.2f", s.warningMultiplier),
		"--critical-multiplier", fmt.Sprintf("%.2f", s.criticalMultiplier),
		"--warning-mad-factor", fmt.Sprintf("%.2f", s.warningMadFactor),
		"--critical-mad-factor", fmt.Sprintf("%.2f", s.criticalMadFactor),
		"--warning-sustain-seconds", fmt.Sprintf("%d", s.warningSustainSeconds),
		"--critical-sustain-seconds", fmt.Sprintf("%d", s.criticalSustainSeconds),
		"--recovery-seconds", fmt.Sprintf("%d", s.recoverySeconds),
		"--cooldown-seconds", fmt.Sprintf("%d", s.cooldownSeconds),
		"--recovery-ratio", fmt.Sprintf("%.2f", s.recoveryRatio),
	)

	cmd := exec.Command(pythonCmd, args...)
	cmd.Env = append(os.Environ(), "PYTHONIOENCODING=utf-8")

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("failed to capture stdout: %w", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("failed to capture stderr: %w", err)
	}

	if err := cmd.Start(); err != nil {
		s.mu.Unlock()
		return fmt.Errorf("failed to start monitor: %w", err)
	}

	monitor := &NICMonitor{
		nic:      nic,
		cmd:      cmd,
		stopChan: make(chan struct{}),
	}

	s.monitors[nic] = monitor
	s.mu.Unlock()

	go s.forwardMonitorOutput(monitor, stdout)
	go s.forwardMonitorStderr(monitor, stderr)
	go s.waitForMonitorExit(monitor)

	log.Printf("monitor started for NIC %s", nic)
	return nil
}

func (s *MultiNICMonitorService) forwardMonitorOutput(monitor *NICMonitor, stdout io.ReadCloser) {
	defer stdout.Close()

	scanner := bufio.NewScanner(stdout)
	buffer := make([]byte, 0, 64*1024)
	scanner.Buffer(buffer, 1024*1024)

	for scanner.Scan() {
		select {
		case <-monitor.stopChan:
			return
		default:
		}

		line := append([]byte(nil), scanner.Bytes()...)
		var data map[string]any
		if err := json.Unmarshal(line, &data); err != nil {
			log.Printf("[%s] invalid JSON from monitor: %v", monitor.nic, err)
			continue
		}

		s.hub.broadcast <- line
	}

	if err := scanner.Err(); err != nil && !monitor.stopping.Load() {
		log.Printf("[%s] stdout read error: %v", monitor.nic, err)
	}
}

func (s *MultiNICMonitorService) forwardMonitorStderr(monitor *NICMonitor, stderr io.ReadCloser) {
	defer stderr.Close()

	scanner := bufio.NewScanner(stderr)
	buffer := make([]byte, 0, 16*1024)
	scanner.Buffer(buffer, 256*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if line != "" {
			log.Printf("[%s] %s", monitor.nic, line)
		}
	}

	if err := scanner.Err(); err != nil && !monitor.stopping.Load() {
		log.Printf("[%s] stderr read error: %v", monitor.nic, err)
	}
}

func (s *MultiNICMonitorService) waitForMonitorExit(monitor *NICMonitor) {
	err := monitor.cmd.Wait()
	if err != nil && !monitor.stopping.Load() {
		log.Printf("[%s] monitor exited unexpectedly: %v", monitor.nic, err)
	}

	s.mu.Lock()
	if current, ok := s.monitors[monitor.nic]; ok && current == monitor {
		delete(s.monitors, monitor.nic)
	}
	s.mu.Unlock()

	monitor.stopOnce.Do(func() {
		close(monitor.stopChan)
	})
}

func (s *MultiNICMonitorService) stopMonitorLocked(monitor *NICMonitor) error {
	monitor.stopping.Store(true)
	monitor.stopOnce.Do(func() {
		close(monitor.stopChan)
	})

	if monitor.cmd == nil || monitor.cmd.Process == nil {
		return nil
	}

	if err := monitor.cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}

	return nil
}

func (s *MultiNICMonitorService) StopMonitor(nic string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	monitor, exists := s.monitors[nic]
	if !exists {
		return fmt.Errorf("NIC %s is not being monitored", nic)
	}

	if err := s.stopMonitorLocked(monitor); err != nil {
		return fmt.Errorf("failed to stop monitor %s: %w", nic, err)
	}

	delete(s.monitors, nic)
	log.Printf("monitor stopped for NIC %s", nic)
	return nil
}

func (s *MultiNICMonitorService) StopAll() {
	s.mu.Lock()
	defer s.mu.Unlock()

	for nic, monitor := range s.monitors {
		if err := s.stopMonitorLocked(monitor); err != nil {
			log.Printf("failed to stop monitor %s: %v", nic, err)
		} else {
			log.Printf("monitor stopped for NIC %s", nic)
		}
		delete(s.monitors, nic)
	}
}

func (s *MultiNICMonitorService) GetActiveNICs() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nics := make([]string, 0, len(s.monitors))
	for nic := range s.monitors {
		nics = append(nics, nic)
	}
	return nics
}

func (s *MultiNICMonitorService) SetThresholds(warning, critical float64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.warningMbps = warning
	s.criticalMbps = critical
}

func handleWebSocket(hub *Hub, monitorService *MultiNICMonitorService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Printf("websocket upgrade failed: %v", err)
			return
		}

		client := &Client{
			conn: conn,
			send: make(chan []byte, clientSendBuffer),
		}

		hub.register <- client

		var closeOnce sync.Once
		cleanup := func() {
			closeOnce.Do(func() {
				hub.unregister <- client
				_ = conn.Close()
			})
		}
		defer cleanup()

		go func() {
			defer cleanup()

			for message := range client.send {
				if err := conn.WriteMessage(websocket.TextMessage, message); err != nil {
					log.Printf("websocket write failed: %v", err)
					return
				}
			}
		}()

		for {
			_, message, err := conn.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
					log.Printf("websocket read failed: %v", err)
				}
				return
			}

			var cmd map[string]any
			if err := json.Unmarshal(message, &cmd); err != nil {
				log.Printf("invalid websocket command: %v", err)
				sendError(client, "invalid command payload")
				continue
			}

			handleCommand(cmd, monitorService, client)
		}
	}
}

func handleCommand(cmd map[string]any, monitorService *MultiNICMonitorService, client *Client) {
	action, ok := cmd["action"].(string)
	if !ok {
		sendError(client, "missing action")
		return
	}

	switch action {
	case "start_monitor":
		nics, ok := cmd["nics"].([]any)
		if !ok {
			sendError(client, "invalid NIC list")
			return
		}

		for _, nicValue := range nics {
			nic, ok := nicValue.(string)
			if !ok || nic == "" {
				continue
			}
			if err := monitorService.StartMonitor(nic); err != nil {
				sendError(client, fmt.Sprintf("failed to start %s: %v", nic, err))
			}
		}

		sendActiveNICs(client, monitorService.GetActiveNICs())

	case "stop_monitor":
		nics, ok := cmd["nics"].([]any)
		if !ok {
			sendError(client, "invalid NIC list")
			return
		}

		for _, nicValue := range nics {
			nic, ok := nicValue.(string)
			if !ok || nic == "" {
				continue
			}
			if err := monitorService.StopMonitor(nic); err != nil {
				sendError(client, fmt.Sprintf("failed to stop %s: %v", nic, err))
			}
		}

		sendActiveNICs(client, monitorService.GetActiveNICs())

	case "stop_all":
		monitorService.StopAll()
		sendActiveNICs(client, []string{})

	case "get_active_nics":
		sendActiveNICs(client, monitorService.GetActiveNICs())

	case "set_thresholds":
		warning, warningOK := cmd["warning_mbps"].(float64)
		critical, criticalOK := cmd["critical_mbps"].(float64)
		if !warningOK || !criticalOK || warning <= 0 || critical <= 0 || critical < warning {
			sendError(client, "invalid threshold values")
			return
		}
		monitorService.SetThresholds(warning, critical)

	default:
		sendError(client, fmt.Sprintf("unsupported action: %s", action))
	}
}

func sendJSON(client *Client, payload []byte) {
	defer func() {
		if recover() != nil {
			log.Printf("skipped message for closed client connection")
		}
	}()

	select {
	case client.send <- payload:
	default:
		log.Printf("dropping websocket message because client buffer is full")
	}
}

func sendError(client *Client, message string) {
	data := map[string]any{
		"type":    "error",
		"message": message,
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Printf("failed to encode error payload: %v", err)
		return
	}

	sendJSON(client, jsonData)
}

func sendActiveNICs(client *Client, nics []string) {
	data := map[string]any{
		"type": "active_nics",
		"nics": nics,
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Printf("failed to encode NIC payload: %v", err)
		return
	}

	sendJSON(client, jsonData)
}

func handleGetNICs(w http.ResponseWriter, r *http.Request) {
	pythonCmd, pythonArgs := getPythonCommand()
	args := append(pythonArgs, "-u", "list_nics.py")
	cmd := exec.Command(pythonCmd, args...)
	cmd.Env = append(os.Environ(), "PYTHONIOENCODING=utf-8")

	output, err := cmd.Output()
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to list NICs: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write(output)
}

func main() {
	workDir, err := os.Getwd()
	if err != nil {
		log.Fatal("failed to get working directory:", err)
	}
	log.Printf("working directory: %s", workDir)

	hub := newHub()
	go hub.run()

	monitorService := NewMultiNICMonitorService(hub)

	http.HandleFunc("/ws", handleWebSocket(hub, monitorService))
	http.HandleFunc("/api/nics", handleGetNICs)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		htmlPath := "multi_nic_monitor.html"
		if _, err := os.Stat(htmlPath); os.IsNotExist(err) {
			htmlPath = "traffic_monitor/multi_nic_monitor.html"
		}
		http.ServeFile(w, r, htmlPath)
	})

	addr := ":8080"
	log.Printf("server listening at http://localhost%s", addr)

	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatal("server failed:", err)
	}
}
