//go:build !unix

package analyzers

import "os/exec"

func configureAnalyzerCommand(_ *exec.Cmd) {}
