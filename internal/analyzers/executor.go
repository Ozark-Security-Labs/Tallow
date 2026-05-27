package analyzers

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"
)

const (
	defaultMaxAnalyzerOutputBytes = 4 * 1024 * 1024
	defaultAnalyzerTimeout        = 5 * time.Minute
)

var ErrOutputLimitExceeded = errors.New("analyzer output exceeded limit")

type Executor interface {
	Run(context.Context, []byte) (RunResult, error)
}

type CommandExecutor struct {
	Command        []string
	Timeout        time.Duration
	Env            []string
	WorkDir        string
	MaxOutputBytes int64
}

func (e CommandExecutor) Run(ctx context.Context, input []byte) (RunResult, error) {
	if len(e.Command) == 0 {
		return RunResult{}, errors.New("analyzer command required")
	}
	started := time.Now().UTC()
	timeout := e.effectiveTimeout()
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, e.Command[0], e.Command[1:]...)
	cmd.Env = e.sanitizedEnv()
	if e.WorkDir != "" {
		cmd.Dir = e.WorkDir
	}
	cmd.Stdin = bytes.NewReader(input)
	maxOutput := e.MaxOutputBytes
	if maxOutput <= 0 {
		maxOutput = defaultMaxAnalyzerOutputBytes
	}
	stdout := &limitedBuffer{limit: maxOutput}
	stderr := &limitedBuffer{limit: maxOutput}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
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
	if stdout.Truncated() || stderr.Truncated() {
		err = fmt.Errorf("%w: max %d bytes per stream", ErrOutputLimitExceeded, maxOutput)
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

func (e CommandExecutor) effectiveTimeout() time.Duration {
	if e.Timeout > 0 {
		return e.Timeout
	}
	return defaultAnalyzerTimeout
}

func (e CommandExecutor) sanitizedEnv() []string {
	values := map[string]string{"TALLOW_ANALYZER_NETWORK_OFF": "1"}
	mergeAllowedEnv(values, os.Environ())
	if e.Env != nil {
		mergeAllowedEnv(values, e.Env)
	}
	values["TALLOW_ANALYZER_NETWORK_OFF"] = "1"
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	env := make([]string, 0, len(keys))
	for _, key := range keys {
		env = append(env, key+"="+values[key])
	}
	return env
}

func mergeAllowedEnv(values map[string]string, env []string) {
	for _, entry := range env {
		key, value, ok := strings.Cut(entry, "=")
		if !ok || value == "" || !allowedAnalyzerEnv(key) {
			continue
		}
		values[key] = value
	}
}

func allowedAnalyzerEnv(key string) bool {
	return key == "PATH" || key == "PYTHONPATH" || strings.HasPrefix(key, "TALLOW_ANALYZER_")
}

type limitedBuffer struct {
	buf       bytes.Buffer
	limit     int64
	truncated bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.limit <= 0 {
		return len(p), nil
	}
	remaining := b.limit - int64(b.buf.Len())
	if remaining <= 0 {
		b.truncated = true
		return len(p), nil
	}
	if int64(len(p)) > remaining {
		_, _ = b.buf.Write(p[:remaining])
		b.truncated = true
		return len(p), nil
	}
	_, _ = b.buf.Write(p)
	return len(p), nil
}

func (b *limitedBuffer) Bytes() []byte { return b.buf.Bytes() }

func (b *limitedBuffer) Truncated() bool { return b.truncated }
