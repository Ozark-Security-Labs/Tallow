package analyzers

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"time"
)

type Executor interface {
	Run(context.Context, []byte) (RunResult, error)
}

type CommandExecutor struct {
	Command []string
	Timeout time.Duration
}

func (e CommandExecutor) Run(ctx context.Context, input []byte) (RunResult, error) {
	if len(e.Command) == 0 {
		return RunResult{}, errors.New("analyzer command required")
	}
	started := time.Now().UTC()
	if e.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, e.Timeout)
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, e.Command[0], e.Command[1:]...)
	cmd.Stdin = bytes.NewReader(input)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	finished := time.Now().UTC()
	result := RunResult{
		Stdout:     stdout.Bytes(),
		Stderr:     stderr.Bytes(),
		Duration:   finished.Sub(started),
		TimedOut:   ctx.Err() == context.DeadlineExceeded,
		StartedAt:  started,
		FinishedAt: finished,
	}
	if exitErr := new(exec.ExitError); errors.As(err, &exitErr) {
		result.ExitCode = exitErr.ExitCode()
	} else if err != nil {
		result.ExitCode = -1
	} else {
		result.ExitCode = 0
	}
	return result, err
}
