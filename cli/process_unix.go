//go:build !windows

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

// terminalDeliveredInterrupt reports whether the foreground terminal already
// delivered SIGINT to both us and the child. os/signal does not expose siginfo,
// so a PID-directed SIGINT in the same cooked-terminal state is indistinguishable;
// the bounded shutdown below still guarantees it cannot leave a stuck child.
func terminalDeliveredInterrupt(child *os.Process) bool {
	group, err := syscall.Getpgid(child.Pid)
	if err != nil || group != syscall.Getpgrp() {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	stty := exec.CommandContext(ctx, "stty", "-a")
	stty.Stdin = os.Stdin
	state, err := stty.Output()
	if err != nil {
		return false
	}
	isig := false
	for _, field := range strings.Fields(string(state)) {
		if strings.Trim(field, ";") == "isig" {
			isig = true
		}
	}
	if !isig {
		return false
	}
	// ps exposes the controlling terminal's foreground pgid on Linux and macOS,
	// without platform-specific ioctl structures or unsafe pointers.
	ps := exec.CommandContext(ctx, "ps", "-o", "tpgid=", "-p", fmt.Sprint(os.Getpid()))
	out, err := ps.Output()
	if err != nil {
		return false
	}
	var foreground int
	_, err = fmt.Sscan(string(out), &foreground)
	return err == nil && foreground == group
}

func notifySignals(c chan os.Signal) { signal.Notify(c, os.Interrupt, syscall.SIGTERM) }
func stopSignals(c chan os.Signal)   { signal.Stop(c) }
func signalNumber(s os.Signal) int32 { return int32(s.(syscall.Signal)) }
func forwardSignal(child *os.Process, s os.Signal) {
	if s != os.Interrupt || !terminalDeliveredInterrupt(child) {
		_ = child.Signal(s)
	}
}
func restoreTerminal() func() {
	cmd := exec.Command("stty", "-g")
	cmd.Stdin = os.Stdin
	state, err := cmd.Output()
	return func() {
		if err == nil {
			restore := exec.Command("stty", strings.TrimSpace(string(state)))
			restore.Stdin = os.Stdin
			_ = restore.Run()
		}
	}
}

func childSignalExit(x *exec.ExitError) int {
	if st, ok := x.Sys().(syscall.WaitStatus); ok && st.Signaled() {
		return 128 + int(st.Signal())
	}
	return 0
}
func prepareChild(cmd *exec.Cmd) (func(), error) { return func() {}, nil }
func containChild(cmd *exec.Cmd) error           { return nil }
