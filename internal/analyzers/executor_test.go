package analyzers

import (
	"context"
	"errors"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestCommandExecutorUsesSanitizedEnvironment(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses /bin/sh")
	}
	t.Setenv("TALLOW_TEST_SECRET", "do-not-inherit")
	executor := CommandExecutor{Command: []string{"/bin/sh", "-c", "env"}}
	result, err := executor.Run(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(result.Stdout), "TALLOW_TEST_SECRET") {
		t.Fatalf("executor inherited secret env: %s", result.Stdout)
	}
	if !strings.Contains(string(result.Stdout), "TALLOW_ANALYZER_NETWORK_OFF=1") {
		t.Fatalf("network-off env missing: %s", result.Stdout)
	}
}

func TestCommandExecutorBoundsOutput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses /bin/sh")
	}
	executor := CommandExecutor{
		Command:        []string{"/bin/sh", "-c", "printf 1234567890"},
		MaxOutputBytes: 4,
	}
	result, err := executor.Run(context.Background(), nil)
	if !errors.Is(err, ErrOutputLimitExceeded) {
		t.Fatalf("expected output limit error, got %v", err)
	}
	if string(result.Stdout) != "1234" {
		t.Fatalf("stdout not bounded: %q", result.Stdout)
	}
}

func TestCommandExecutorMarksTimeout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses /bin/sh")
	}
	executor := CommandExecutor{
		Command: []string{"/bin/sh", "-c", "sleep 1"},
		Timeout: 10 * time.Millisecond,
		Env:     append(os.Environ(), "TALLOW_TEST_TIMEOUT=1"),
	}
	result, err := executor.Run(context.Background(), nil)
	if err == nil || !result.TimedOut {
		t.Fatalf("expected timeout error/result, got timed_out=%v err=%v", result.TimedOut, err)
	}
}
