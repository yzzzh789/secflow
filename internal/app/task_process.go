package app

import (
	"fmt"
	"log"
	"os/exec"
	"runtime"
	"sync"
	"syscall"
)

type CaptureProcess struct {
	cmd           *exec.Cmd
	mu            sync.Mutex
	active        bool
	stopRequested bool
}

func (cp *CaptureProcess) IsActive() bool {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	return cp.active
}

func (cp *CaptureProcess) Stop() {
	cp.mu.Lock()
	if !cp.active || cp.cmd == nil || cp.cmd.Process == nil {
		cp.active = false
		cp.cmd = nil
		cp.stopRequested = true
		cp.mu.Unlock()
		return
	}

	cmd := cp.cmd
	cp.active = false
	cp.cmd = nil
	cp.stopRequested = true
	cp.mu.Unlock()

	log.Println("Stopping python script process...")
	if runtime.GOOS == "windows" {
		killCmd := exec.Command("taskkill", "/F", "/T", "/PID", fmt.Sprintf("%d", cmd.Process.Pid))
		if err := killCmd.Run(); err != nil {
			log.Printf("Failed to kill process tree: %v", err)
		}
	} else {
		if err := cmd.Process.Signal(syscall.SIGINT); err != nil {
			log.Printf("Failed to send SIGINT, trying to kill: %v", err)
			if killErr := cmd.Process.Kill(); killErr != nil {
				log.Printf("Failed to kill process: %v", killErr)
			}
		}
	}
}

func (cp *CaptureProcess) Set(cmd *exec.Cmd) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	cp.cmd = cmd
	cp.active = true
	cp.stopRequested = false
}

func (cp *CaptureProcess) MarkExited() bool {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	stopRequested := cp.stopRequested
	cp.active = false
	cp.cmd = nil
	cp.stopRequested = false
	return stopRequested
}
