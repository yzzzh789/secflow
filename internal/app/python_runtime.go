package app

import (
	"bufio"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/gorilla/websocket"
)

const scannerMaxTokenSize = 1024 * 1024

type pythonCommandFactory func(args ...string) *exec.Cmd

var makePythonCommand pythonCommandFactory = defaultPythonCommand

func newPythonCommand(args ...string) *exec.Cmd {
	return makePythonCommand(args...)
}

func newPythonCommandWithEnv(args []string, extraEnv ...string) *exec.Cmd {
	cmd := newPythonCommand(args...)
	if len(extraEnv) == 0 {
		return cmd
	}
	if cmd.Env == nil {
		cmd.Env = os.Environ()
	}
	cmd.Env = append(cmd.Env, extraEnv...)
	return cmd
}

func defaultPythonCommand(args ...string) *exec.Cmd {
	pythonBin := firstNonEmpty(appConfig.PythonBin, defaultPythonBin)
	cmd := exec.Command(pythonBin, args...)
	projectRoot := resolveProjectRoot()
	cmd.Dir = projectRoot

	pythonPath := projectRoot
	if existing := strings.TrimSpace(os.Getenv("PYTHONPATH")); existing != "" {
		pythonPath = projectRoot + string(os.PathListSeparator) + existing
	}

	cmd.Env = append(os.Environ(),
		"PYTHONIOENCODING=UTF-8",
		"PYTHONPATH="+pythonPath,
	)
	return cmd
}

func newLineScanner(r io.Reader) *bufio.Scanner {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), scannerMaxTokenSize)
	return scanner
}

func pumpLines(source, stream string, pipe io.ReadCloser, lines chan<- ProcessLine, wg *sync.WaitGroup) {
	defer wg.Done()
	defer pipe.Close()

	scanner := newLineScanner(pipe)
	for scanner.Scan() {
		lines <- ProcessLine{Stream: stream, Text: scanner.Text()}
	}
	if err := scanner.Err(); err != nil {
		log.Printf("%s stream read error: %v", source, err)
	}
}

func startStreamingPythonCommand(conn *websocket.Conn, cp *CaptureProcess, source, finishMessage string, args ...string) (io.WriteCloser, error) {
	cmd := newPythonCommand(args...)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, err
	}

	cp.Set(cmd)
	if err := cmd.Start(); err != nil {
		cp.MarkExited()
		_ = stdin.Close()
		return nil, err
	}

	writer := &wsTextWriter{conn: conn}
	lines := make(chan ProcessLine, 256)
	var readers sync.WaitGroup
	readers.Add(2)
	go pumpLines(source, "stdout", stdout, lines, &readers)
	go pumpLines(source, "stderr", stderr, lines, &readers)

	go func() {
		readers.Wait()
		close(lines)
	}()

	go func() {
		for line := range lines {
			if dbWriter != nil {
				dbWriter.Enqueue(source, line.Text)
			}
			if err := writer.WriteText(normalizeProcessLine(source, finishMessage, line)); err != nil {
				log.Printf("%s websocket write error: %v", source, err)
			}
		}

		if err := cmd.Wait(); err != nil {
			log.Printf("%s exited with error: %v", source, err)
		}

		cp.MarkExited()

		if finishMessage != "" {
			if dbWriter != nil {
				dbWriter.Enqueue(source, finishMessage)
			}
			if err := writer.WriteText(normalizeProcessLine(source, finishMessage, ProcessLine{Stream: "system", Text: finishMessage})); err != nil {
				log.Printf("%s finish message write error: %v", source, err)
			}
		}

		_ = stdin.Close()
	}()

	return stdin, nil
}
