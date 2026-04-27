package app

import (
	"database/sql"
	"encoding/json"
	"time"
)

type managedTaskState struct {
	TaskName            string
	DesiredState        string
	RuntimeStatus       string
	AutoRestart         bool
	CommandJSON         string
	ArgsJSON            string
	StartedAt           string
	StoppedAt           string
	UpdatedAt           string
	LastExitAt          string
	LastExitReason      string
	RestartCount        int
	ConsecutiveFailures int
	NextRestartAt       string
	LastError           string
}

type TaskStateStore struct {
	db *sql.DB
}

func NewTaskStateStore(db *sql.DB) *TaskStateStore {
	return &TaskStateStore{db: db}
}

func (s *TaskStateStore) ensureTaskRow(taskName string) error {
	now := time.Now().Format(time.RFC3339)
	_, err := s.db.Exec(`
		INSERT INTO managed_tasks (task_name, updated_at)
		VALUES (?, ?)
		ON CONFLICT(task_name) DO NOTHING
	`, taskName, now)
	return err
}

func (s *TaskStateStore) EnsureKnownTasks(taskNames ...string) error {
	for _, taskName := range taskNames {
		if err := s.ensureTaskRow(taskName); err != nil {
			return err
		}
	}
	return nil
}

func marshalJSON(v any) string {
	if v == nil {
		return ""
	}
	buf, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(buf)
}

func nullableStringValue(value sql.NullString) string {
	if value.Valid {
		return value.String
	}
	return ""
}

func (s *TaskStateStore) MarkRunning(taskName string, command any, args []string, autoRestart bool) error {
	if err := s.ensureTaskRow(taskName); err != nil {
		return err
	}

	now := time.Now().Format(time.RFC3339)
	_, err := s.db.Exec(`
		UPDATE managed_tasks
		SET desired_state = ?,
			runtime_status = ?,
			auto_restart = ?,
			command_json = ?,
			args_json = ?,
			started_at = ?,
			stopped_at = NULL,
			updated_at = ?,
			next_restart_at = NULL,
			consecutive_failures = 0,
			last_error = NULL
		WHERE task_name = ?
	`,
		taskDesiredRunning,
		taskStatusRunning,
		boolToInt(autoRestart),
		marshalJSON(command),
		marshalJSON(args),
		now,
		now,
		taskName,
	)
	return err
}

func (s *TaskStateStore) MarkStopRequested(taskName string) error {
	if err := s.ensureTaskRow(taskName); err != nil {
		return err
	}

	now := time.Now().Format(time.RFC3339)
	_, err := s.db.Exec(`
		UPDATE managed_tasks
		SET desired_state = ?,
			runtime_status = ?,
			updated_at = ?,
			next_restart_at = NULL,
			last_error = NULL
		WHERE task_name = ?
	`, taskDesiredStopped, taskStatusStopping, now, taskName)
	return err
}

func (s *TaskStateStore) MarkStopped(taskName, reason string) error {
	if err := s.ensureTaskRow(taskName); err != nil {
		return err
	}

	now := time.Now().Format(time.RFC3339)
	_, err := s.db.Exec(`
		UPDATE managed_tasks
		SET desired_state = ?,
			runtime_status = ?,
			stopped_at = ?,
			updated_at = ?,
			last_exit_at = ?,
			last_exit_reason = ?,
			next_restart_at = NULL,
			consecutive_failures = 0,
			last_error = NULL
		WHERE task_name = ?
	`, taskDesiredStopped, taskStatusStopped, now, now, now, reason, taskName)
	return err
}

func (s *TaskStateStore) MarkBackoff(taskName, reason string) (managedTaskState, time.Duration, error) {
	state, found, err := s.Get(taskName)
	if err != nil {
		return managedTaskState{}, 0, err
	}
	if !found {
		if err := s.ensureTaskRow(taskName); err != nil {
			return managedTaskState{}, 0, err
		}
		state, _, err = s.Get(taskName)
		if err != nil {
			return managedTaskState{}, 0, err
		}
	}

	failures := state.ConsecutiveFailures + 1
	delay := restartDelayForFailures(failures)
	now := time.Now()
	nextRestartAt := ""
	status := taskStatusFailed
	if state.DesiredState == taskDesiredRunning && state.AutoRestart {
		status = taskStatusBackoff
		nextRestartAt = now.Add(delay).Format(time.RFC3339)
	}

	_, err = s.db.Exec(`
		UPDATE managed_tasks
		SET runtime_status = ?,
			updated_at = ?,
			last_exit_at = ?,
			last_exit_reason = ?,
			restart_count = restart_count + 1,
			consecutive_failures = ?,
			next_restart_at = ?,
			last_error = ?
		WHERE task_name = ?
	`,
		status,
		now.Format(time.RFC3339),
		now.Format(time.RFC3339),
		reason,
		failures,
		nextRestartAt,
		reason,
		taskName,
	)
	if err != nil {
		return managedTaskState{}, 0, err
	}

	updated, _, err := s.Get(taskName)
	return updated, delay, err
}

func (s *TaskStateStore) MarkStartFailure(taskName string, command any, args []string, reason string, autoRestart bool) (managedTaskState, time.Duration, error) {
	if err := s.ensureTaskRow(taskName); err != nil {
		return managedTaskState{}, 0, err
	}

	now := time.Now().Format(time.RFC3339)
	_, err := s.db.Exec(`
		UPDATE managed_tasks
		SET desired_state = ?,
			auto_restart = ?,
			command_json = COALESCE(NULLIF(?, ''), command_json),
			args_json = COALESCE(NULLIF(?, ''), args_json),
			updated_at = ?,
			last_error = ?
		WHERE task_name = ?
	`,
		taskDesiredRunning,
		boolToInt(autoRestart),
		marshalJSON(command),
		marshalJSON(args),
		now,
		reason,
		taskName,
	)
	if err != nil {
		return managedTaskState{}, 0, err
	}

	return s.MarkBackoff(taskName, reason)
}

func (s *TaskStateStore) Get(taskName string) (managedTaskState, bool, error) {
	var state managedTaskState
	var autoRestart int
	var startedAt sql.NullString
	var stoppedAt sql.NullString
	var updatedAt sql.NullString
	var lastExitAt sql.NullString
	var lastExitReason sql.NullString
	var nextRestartAt sql.NullString
	var lastError sql.NullString
	err := s.db.QueryRow(`
		SELECT task_name, desired_state, runtime_status, auto_restart, command_json, args_json,
			started_at, stopped_at, updated_at, last_exit_at, last_exit_reason,
			restart_count, consecutive_failures, next_restart_at, last_error
		FROM managed_tasks
		WHERE task_name = ?
	`, taskName).Scan(
		&state.TaskName,
		&state.DesiredState,
		&state.RuntimeStatus,
		&autoRestart,
		&state.CommandJSON,
		&state.ArgsJSON,
		&startedAt,
		&stoppedAt,
		&updatedAt,
		&lastExitAt,
		&lastExitReason,
		&state.RestartCount,
		&state.ConsecutiveFailures,
		&nextRestartAt,
		&lastError,
	)
	if err == sql.ErrNoRows {
		return managedTaskState{}, false, nil
	}
	if err != nil {
		return managedTaskState{}, false, err
	}
	state.AutoRestart = autoRestart == 1
	state.StartedAt = nullableStringValue(startedAt)
	state.StoppedAt = nullableStringValue(stoppedAt)
	state.UpdatedAt = nullableStringValue(updatedAt)
	state.LastExitAt = nullableStringValue(lastExitAt)
	state.LastExitReason = nullableStringValue(lastExitReason)
	state.NextRestartAt = nullableStringValue(nextRestartAt)
	state.LastError = nullableStringValue(lastError)
	return state, true, nil
}

func (s *TaskStateStore) ListDesiredRunning() ([]managedTaskState, error) {
	rows, err := s.db.Query(`
		SELECT task_name, desired_state, runtime_status, auto_restart, command_json, args_json,
			started_at, stopped_at, updated_at, last_exit_at, last_exit_reason,
			restart_count, consecutive_failures, next_restart_at, last_error
		FROM managed_tasks
		WHERE desired_state = ?
		ORDER BY task_name ASC
	`, taskDesiredRunning)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []managedTaskState
	for rows.Next() {
		var state managedTaskState
		var autoRestart int
		var startedAt sql.NullString
		var stoppedAt sql.NullString
		var updatedAt sql.NullString
		var lastExitAt sql.NullString
		var lastExitReason sql.NullString
		var nextRestartAt sql.NullString
		var lastError sql.NullString
		if err := rows.Scan(
			&state.TaskName,
			&state.DesiredState,
			&state.RuntimeStatus,
			&autoRestart,
			&state.CommandJSON,
			&state.ArgsJSON,
			&startedAt,
			&stoppedAt,
			&updatedAt,
			&lastExitAt,
			&lastExitReason,
			&state.RestartCount,
			&state.ConsecutiveFailures,
			&nextRestartAt,
			&lastError,
		); err != nil {
			return nil, err
		}
		state.AutoRestart = autoRestart == 1
		state.StartedAt = nullableStringValue(startedAt)
		state.StoppedAt = nullableStringValue(stoppedAt)
		state.UpdatedAt = nullableStringValue(updatedAt)
		state.LastExitAt = nullableStringValue(lastExitAt)
		state.LastExitReason = nullableStringValue(lastExitReason)
		state.NextRestartAt = nullableStringValue(nextRestartAt)
		state.LastError = nullableStringValue(lastError)
		items = append(items, state)
	}
	return items, rows.Err()
}
