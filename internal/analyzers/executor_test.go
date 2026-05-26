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
	t.Setenv("AWS_SECRET_ACCESS_KEY", "do-not-inherit")
	executor := CommandExecutor{Command: []string{"/bin/sh", "-c", "env"}}
	result, err := executor.Run(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(result.Stdout), "AWS_SECRET_ACCESS_KEY") {
		t.Fatalf("executor inherited secret env: %s", result.Stdout)
	}
	if strings.Contains(string(result.Stdout), "HOME=") || strings.Contains(string(result.Stdout), "TMPDIR=") {
		t.Fatalf("executor inherited non-minimal env: %s", result.Stdout)
	}
	if !strings.Contains(string(result.Stdout), "TALLOW_ANALYZER_NETWORK_OFF=1") {
		t.Fatalf("network-off env missing: %s", result.Stdout)
	}
}

func TestCommandExecutorSanitizesOverrideEnvironment(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses /bin/sh")
	}
	executor := CommandExecutor{
		Command: []string{"/bin/sh", "-c", "env"},
		Env: []string{
			"PATH=/bin:/usr/bin",
			"HOME=/tmp/secret-home",
			"AWS_SECRET_ACCESS_KEY=do-not-inherit",
			"TALLOW_CUSTOM=allowed",
		},
	}
	result, err := executor.Run(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	stdout := string(result.Stdout)
	for _, disallowed := range []string{"HOME=", "AWS_SECRET_ACCESS_KEY"} {
		if strings.Contains(stdout, disallowed) {
			t.Fatalf("executor env contained %s: %s", disallowed, stdout)
		}
	}
	for _, required := range []string{"PATH=/bin:/usr/bin", "TALLOW_CUSTOM=allowed", "TALLOW_ANALYZER_NETWORK_OFF=1"} {
		if !strings.Contains(stdout, required) {
			t.Fatalf("executor env missing %s: %s", required, stdout)
		}
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
