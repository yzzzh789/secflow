package app

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return isAllowedWebSocketOrigin(r)
	},
}

func handleManagedCaptureWebSocket(
	w http.ResponseWriter,
	r *http.Request,
	connectedLog string,
	hub *ManagedCaptureHub,
	buildArgs func(managedCaptureCommand) ([]string, error),
	startLog string,
	startFailureLog string,
) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("Upgrade error:", err)
		return
	}
	defer conn.Close()

	log.Println(connectedLog)
	hub.Subscribe(conn)
	defer hub.Unsubscribe(conn)

	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			log.Println("Read error:", err)
			break
		}

		var command managedCaptureCommand
		if err := json.Unmarshal(message, &command); err != nil {
			log.Println("Invalid command format:", err)
			continue
		}

		switch command.Action {
		case "start":
			args, err := buildArgs(command)
			if err != nil {
				log.Printf("%s: %v", startFailureLog, err)
				continue
			}
			if startLog != "" {
				log.Printf("%s: %v", startLog, redactedArgs(args))
			}
			if err := hub.Start(command, args...); err != nil {
				log.Printf("%s: %v", startFailureLog, err)
				hub.Stop()
				continue
			}
		case "stop":
			hub.Stop()
		}
	}
}

func handleCapture(w http.ResponseWriter, r *http.Request) {
	if proxyHostAgentRequest(w, r) {
		return
	}

	handleManagedCaptureWebSocket(
		w,
		r,
		"WebSocket client connected",
		threatCaptureHub,
		buildThreatCaptureArgs,
		"Executing Python with args",
		"Error starting command",
	)
	log.Println("WebSocket client disconnected.")
}

func handleLANMonitor(w http.ResponseWriter, r *http.Request) {
	if proxyHostAgentRequest(w, r) {
		return
	}

	handleManagedCaptureWebSocket(
		w,
		r,
		"LAN Monitor WebSocket connected",
		lanMonitorHub,
		buildLANMonitorArgs,
		"Starting LAN Behavior Monitor",
		"Error starting LAN monitor",
	)
}

func handleNICMonitor(w http.ResponseWriter, r *http.Request) {
	if proxyHostAgentRequest(w, r) {
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("Upgrade error:", err)
		return
	}
	defer conn.Close()

	log.Println("NIC Monitor WebSocket connected")
	nicMonitorHub.Subscribe(conn)
	defer nicMonitorHub.Unsubscribe(conn)

	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			log.Println("Read error:", err)
			break
		}

		var command nicMonitorCommand
		if err := json.Unmarshal(message, &command); err != nil {
			log.Println("Invalid command format:", err)
			continue
		}

		switch command.Action {
		case "start":
			args, err := buildNICMonitorArgs(command)
			if err != nil {
				log.Printf("Error starting NIC monitor: %v", err)
				continue
			}
			log.Printf("Starting NIC Monitor: %v", redactedArgs(args))
			if err := nicMonitorHub.Start(command, args...); err != nil {
				log.Printf("Error starting NIC monitor: %v", err)
				nicMonitorHub.Stop()
				continue
			}
		case "stop":
			nicMonitorHub.Stop()
		default:
			if nicMonitorHub.IsActive() {
				if err := nicMonitorHub.Forward(command); err != nil {
					log.Printf("Error forwarding NIC monitor command: %v", err)
					nicMonitorHub.Stop()
				}
			}
		}
	}
}
