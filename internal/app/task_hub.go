package app

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

type ManagedCaptureHub struct {
	taskName           string
	restartOnCleanExit bool
	source             string
	finishMessage      string
	historyLimit       int

	proc CaptureProcess

	mu          sync.Mutex
	subscribers map[*websocket.Conn]*wsTextWriter
	history     []string
	lastCommand managedCaptureCommand
	startedAt   time.Time
}

func NewManagedCaptureHub(taskName, source, finishMessage string, historyLimit int, restartOnCleanExit bool) *ManagedCaptureHub {
	return &ManagedCaptureHub{
		taskName:           taskName,
		restartOnCleanExit: restartOnCleanExit,
		source:             source,
		finishMessage:      finishMessage,
		historyLimit:       historyLimit,
		subscribers:        make(map[*websocket.Conn]*wsTextWriter),
		history:            make([]string, 0, historyLimit),
	}
}

func (h *ManagedCaptureHub) IsActive() bool {
	return h.proc.IsActive()
}

func (h *ManagedCaptureHub) RuntimeInfo() managedCaptureRuntimeInfo {
	h.mu.Lock()
	defer h.mu.Unlock()

	return managedCaptureRuntimeInfo{
		Active:      h.proc.IsActive(),
		StartedAt:   h.startedAt.Format(time.RFC3339),
		LastCommand: h.lastCommand,
		HistorySize: len(h.history),
	}
}

func (h *ManagedCaptureHub) Subscribe(conn *websocket.Conn) {
	writer := &wsTextWriter{conn: conn}

	h.mu.Lock()
	h.subscribers[conn] = writer
	history := append([]string(nil), h.history...)
	h.mu.Unlock()

	for _, line := range history {
		if err := writer.WriteText(line); err != nil {
			h.Unsubscribe(conn)
			return
		}
	}
}

func (h *ManagedCaptureHub) Unsubscribe(conn *websocket.Conn) {
	h.mu.Lock()
	delete(h.subscribers, conn)
	h.mu.Unlock()
}

func (h *ManagedCaptureHub) appendHistory(line string) {
	h.mu.Lock()
	h.history = append(h.history, line)
	if len(h.history) > h.historyLimit {
		h.history = h.history[len(h.history)-h.historyLimit:]
	}
	h.mu.Unlock()
}

func (h *ManagedCaptureHub) broadcast(line string) {
	h.appendHistory(line)

	h.mu.Lock()
	writers := make([]*wsTextWriter, 0, len(h.subscribers))
	conns := make([]*websocket.Conn, 0, len(h.subscribers))
	for conn, writer := range h.subscribers {
		conns = append(conns, conn)
		writers = append(writers, writer)
	}
	h.mu.Unlock()

	for i, writer := range writers {
		if err := writer.WriteText(line); err != nil {
			h.Unsubscribe(conns[i])
		}
	}
}

func (h *ManagedCaptureHub) Start(command managedCaptureCommand, args ...string) error {
	if h.proc.IsActive() {
		return nil
	}

	rememberTaskAPIKey(h.taskName, command.APIKey)
	cmd := newPythonCommandWithEnv(args, apiKeyEnv(command.APIKey)...)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return h.handleStartFailure(command, args, err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return h.handleStartFailure(command, args, err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		_ = stdin.Close()
		return h.handleStartFailure(command, args, err)
	}

	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		return h.handleStartFailure(command, args, err)
	}

	h.mu.Lock()
	h.history = h.history[:0]
	h.lastCommand = command.withoutSecrets()
	h.startedAt = time.Now()
	h.mu.Unlock()

	h.proc.Set(cmd)
	if taskSupervisor != nil {
		taskSupervisor.MarkStarted(h.taskName, command.withoutSecrets(), redactedArgs(args))
	}

	lines := make(chan ProcessLine, 256)
	var readers sync.WaitGroup
	readers.Add(2)
	go pumpLines(h.source, "stdout", stdout, lines, &readers)
	go pumpLines(h.source, "stderr", stderr, lines, &readers)

	go func() {
		readers.Wait()
		close(lines)
	}()

	go func() {
		for line := range lines {
			if dbWriter != nil {
				dbWriter.Enqueue(h.source, line.Text)
			}
			h.broadcast(normalizeProcessLine(h.source, h.finishMessage, line))
		}

		waitErr := cmd.Wait()
		if waitErr != nil {
			log.Printf("%s exited with error: %v", h.source, waitErr)
		}

		manualStop := h.proc.MarkExited()
		if taskSupervisor != nil {
			taskSupervisor.HandleExit(h.taskName, waitErr, manualStop, h.restartOnCleanExit)
		}

		if h.finishMessage != "" {
			if dbWriter != nil {
				dbWriter.Enqueue(h.source, h.finishMessage)
			}
			h.broadcast(normalizeProcessLine(h.source, h.finishMessage, ProcessLine{Stream: "system", Text: h.finishMessage}))
		}

		_ = stdin.Close()
	}()

	return nil
}

func (h *ManagedCaptureHub) handleStartFailure(command managedCaptureCommand, args []string, err error) error {
	if taskSupervisor != nil {
		taskSupervisor.HandleStartFailure(h.taskName, command.withoutSecrets(), redactedArgs(args), err)
	}
	return err
}

func (h *ManagedCaptureHub) Stop() {
	if taskSupervisor != nil {
		taskSupervisor.RequestStop(h.taskName)
	}
	forgetTaskAPIKey(h.taskName)
	h.proc.Stop()
}

type ManagedInteractiveHub struct {
	taskName           string
	restartOnCleanExit bool
	source             string
	historyLimit       int

	proc CaptureProcess

	mu          sync.Mutex
	stdin       io.WriteCloser
	subscribers map[*websocket.Conn]*wsTextWriter
	history     []string
	lastCommand nicMonitorCommand
	startedAt   time.Time
}

func NewManagedInteractiveHub(taskName, source string, historyLimit int, restartOnCleanExit bool) *ManagedInteractiveHub {
	return &ManagedInteractiveHub{
		taskName:           taskName,
		restartOnCleanExit: restartOnCleanExit,
		source:             source,
		historyLimit:       historyLimit,
		subscribers:        make(map[*websocket.Conn]*wsTextWriter),
		history:            make([]string, 0, historyLimit),
	}
}

func (h *ManagedInteractiveHub) IsActive() bool {
	return h.proc.IsActive()
}

func (h *ManagedInteractiveHub) RuntimeInfo() managedInteractiveRuntimeInfo {
	h.mu.Lock()
	defer h.mu.Unlock()

	return managedInteractiveRuntimeInfo{
		Active:      h.proc.IsActive(),
		StartedAt:   h.startedAt.Format(time.RFC3339),
		LastCommand: h.lastCommand.clone(),
		HistorySize: len(h.history),
	}
}

func (h *ManagedInteractiveHub) Subscribe(conn *websocket.Conn) {
	writer := &wsTextWriter{conn: conn}

	h.mu.Lock()
	h.subscribers[conn] = writer
	history := append([]string(nil), h.history...)
	h.mu.Unlock()

	for _, line := range history {
		if err := writer.WriteText(line); err != nil {
			h.Unsubscribe(conn)
			return
		}
	}
}

func (h *ManagedInteractiveHub) Unsubscribe(conn *websocket.Conn) {
	h.mu.Lock()
	delete(h.subscribers, conn)
	h.mu.Unlock()
}

func (h *ManagedInteractiveHub) appendHistory(line string) {
	h.mu.Lock()
	h.history = append(h.history, line)
	if len(h.history) > h.historyLimit {
		h.history = h.history[len(h.history)-h.historyLimit:]
	}
	h.mu.Unlock()
}

func (h *ManagedInteractiveHub) broadcast(line string) {
	h.appendHistory(line)

	h.mu.Lock()
	writers := make([]*wsTextWriter, 0, len(h.subscribers))
	conns := make([]*websocket.Conn, 0, len(h.subscribers))
	for conn, writer := range h.subscribers {
		conns = append(conns, conn)
		writers = append(writers, writer)
	}
	h.mu.Unlock()

	for i, writer := range writers {
		if err := writer.WriteText(line); err != nil {
			h.Unsubscribe(conns[i])
		}
	}
}

func (h *ManagedInteractiveHub) Start(command nicMonitorCommand, args ...string) error {
	if h.proc.IsActive() {
		return nil
	}

	command = command.normalized()

	cmd := newPythonCommand(args...)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return h.handleStartFailure(command, args, err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return h.handleStartFailure(command, args, err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		_ = stdin.Close()
		return h.handleStartFailure(command, args, err)
	}

	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		return h.handleStartFailure(command, args, err)
	}

	h.mu.Lock()
	h.stdin = stdin
	h.history = h.history[:0]
	h.lastCommand = command.clone()
	h.startedAt = time.Now()
	h.mu.Unlock()

	h.proc.Set(cmd)
	if taskSupervisor != nil {
		taskSupervisor.MarkStarted(h.taskName, command, args)
	}

	lines := make(chan ProcessLine, 256)
	var readers sync.WaitGroup
	readers.Add(2)
	go pumpLines(h.source, "stdout", stdout, lines, &readers)
	go pumpLines(h.source, "stderr", stderr, lines, &readers)

	go func() {
		readers.Wait()
		close(lines)
	}()

	go func() {
		for line := range lines {
			if dbWriter != nil {
				dbWriter.Enqueue(h.source, line.Text)
			}
			h.broadcast(normalizeProcessLine(h.source, "", line))
		}

		waitErr := cmd.Wait()
		if waitErr != nil {
			log.Printf("%s exited with error: %v", h.source, waitErr)
		}

		h.mu.Lock()
		if h.stdin != nil {
			_ = h.stdin.Close()
			h.stdin = nil
		}
		h.mu.Unlock()
		manualStop := h.proc.MarkExited()
		if taskSupervisor != nil {
			taskSupervisor.HandleExit(h.taskName, waitErr, manualStop, h.restartOnCleanExit)
		}
	}()

	return h.Forward(command)
}

func (h *ManagedInteractiveHub) handleStartFailure(command nicMonitorCommand, args []string, err error) error {
	if taskSupervisor != nil {
		taskSupervisor.HandleStartFailure(h.taskName, command.normalized(), append([]string(nil), args...), err)
	}
	return err
}

func (h *ManagedInteractiveHub) Forward(command nicMonitorCommand) error {
	h.mu.Lock()
	stdin := h.stdin
	h.mu.Unlock()

	if stdin == nil {
		return fmt.Errorf("%s stdin unavailable", h.source)
	}
	return writeJSONLine(stdin, command.AnyMap())
}

func (h *ManagedInteractiveHub) Stop() {
	if taskSupervisor != nil {
		taskSupervisor.RequestStop(h.taskName)
	}
	h.mu.Lock()
	if h.stdin != nil {
		_ = h.stdin.Close()
		h.stdin = nil
	}
	h.mu.Unlock()
	h.proc.Stop()
}

type wsTextWriter struct {
	conn   *websocket.Conn
	mu     sync.Mutex
	closed bool
}

func (w *wsTextWriter) WriteText(line string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	if err := w.conn.WriteMessage(websocket.TextMessage, []byte(line)); err != nil {
		w.closed = true
		return err
	}
	return nil
}

func writeJSONLine(w io.Writer, payload any) error {
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if _, err := w.Write(b); err != nil {
		return err
	}
	_, err = w.Write([]byte("\n"))
	return err
}
