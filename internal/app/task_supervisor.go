package app

import (
	"log"
	"sync"
	"time"
)

type TaskSupervisor struct {
	store *TaskStateStore

	mu      sync.Mutex
	timers  map[string]*time.Timer
	closing bool
}

func NewTaskSupervisor(store *TaskStateStore) *TaskSupervisor {
	return &TaskSupervisor{
		store:  store,
		timers: make(map[string]*time.Timer),
	}
}

func (s *TaskSupervisor) cancelRestart(taskName string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if timer, ok := s.timers[taskName]; ok {
		timer.Stop()
		delete(s.timers, taskName)
	}
}

func (s *TaskSupervisor) MarkStarted(taskName string, command any, args []string) {
	s.cancelRestart(taskName)
	if s.store != nil {
		if err := s.store.MarkRunning(taskName, command, args, true); err != nil {
			log.Printf("task supervisor mark running failed for %s: %v", taskName, err)
		}
	}
}

func (s *TaskSupervisor) RequestStop(taskName string) {
	s.cancelRestart(taskName)
	if s.store != nil {
		if err := s.store.MarkStopRequested(taskName); err != nil {
			log.Printf("task supervisor mark stop requested failed for %s: %v", taskName, err)
		}
	}
}

func (s *TaskSupervisor) HandleStartFailure(taskName string, command any, args []string, err error) {
	if s.store == nil {
		return
	}

	state, delay, storeErr := s.store.MarkStartFailure(taskName, command, args, err.Error(), true)
	if storeErr != nil {
		log.Printf("task supervisor mark start failure failed for %s: %v", taskName, storeErr)
		return
	}
	if state.RuntimeStatus == taskStatusBackoff {
		s.scheduleRestart(taskName, delay)
	}
}

func (s *TaskSupervisor) HandleExit(taskName string, err error, manualStop bool, restartOnCleanExit bool) {
	if manualStop {
		if s.store != nil {
			if storeErr := s.store.MarkStopped(taskName, "stopped by user"); storeErr != nil {
				log.Printf("task supervisor mark stopped failed for %s: %v", taskName, storeErr)
			}
		}
		s.cancelRestart(taskName)
		return
	}

	if err == nil && !restartOnCleanExit {
		if s.store != nil {
			if storeErr := s.store.MarkStopped(taskName, "completed"); storeErr != nil {
				log.Printf("task supervisor mark completed failed for %s: %v", taskName, storeErr)
			}
		}
		s.cancelRestart(taskName)
		return
	}

	reason := "process exited"
	if err != nil {
		reason = err.Error()
	}

	if s.store == nil {
		return
	}

	state, delay, storeErr := s.store.MarkBackoff(taskName, reason)
	if storeErr != nil {
		log.Printf("task supervisor mark backoff failed for %s: %v", taskName, storeErr)
		return
	}
	if state.RuntimeStatus == taskStatusBackoff {
		s.scheduleRestart(taskName, delay)
	}
}

func (s *TaskSupervisor) scheduleRestart(taskName string, delay time.Duration) {
	s.cancelRestart(taskName)

	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		return
	}
	timer := time.AfterFunc(delay, func() {
		s.restartTask(taskName)
	})
	s.timers[taskName] = timer
	s.mu.Unlock()
}

func (s *TaskSupervisor) restartTask(taskName string) {
	s.cancelRestart(taskName)

	state, found, err := s.store.Get(taskName)
	if err != nil {
		log.Printf("task supervisor load state failed for %s: %v", taskName, err)
		return
	}
	if !found || state.DesiredState != taskDesiredRunning || !state.AutoRestart || isManagedTaskActive(taskName) {
		return
	}

	if err := startManagedTaskFromState(state); err != nil {
		log.Printf("task supervisor restart failed for %s: %v", taskName, err)
		s.HandleStartFailure(taskName, nil, nil, err)
	}
}

func (s *TaskSupervisor) RestoreManagedTasks() {
	if s.store == nil {
		return
	}

	items, err := s.store.ListDesiredRunning()
	if err != nil {
		log.Printf("task supervisor restore query failed: %v", err)
		return
	}

	for _, item := range items {
		state := item
		go func() {
			if err := startManagedTaskFromState(state); err != nil {
				log.Printf("task supervisor restore failed for %s: %v", state.TaskName, err)
				s.HandleStartFailure(state.TaskName, nil, nil, err)
			}
		}()
	}
}

func (s *TaskSupervisor) RuntimeFields(taskName string) (managedTaskRuntimeFields, bool) {
	if s.store == nil {
		return managedTaskRuntimeFields{}, false
	}

	state, found, err := s.store.Get(taskName)
	if err != nil || !found {
		return managedTaskRuntimeFields{}, false
	}

	return managedTaskRuntimeFields{
		DesiredState:        state.DesiredState,
		RuntimeStatus:       state.RuntimeStatus,
		AutoRestart:         state.AutoRestart,
		LastExitAt:          state.LastExitAt,
		LastExitReason:      state.LastExitReason,
		RestartCount:        state.RestartCount,
		ConsecutiveFailures: state.ConsecutiveFailures,
		NextRestartAt:       state.NextRestartAt,
		LastError:           state.LastError,
	}, true
}
