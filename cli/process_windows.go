//go:build windows

package main

import (
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Share the caller's console and process group. Windows itself delivers both
// Ctrl-C and Ctrl-Break to parent and child, including ConPTY. Broadcasting a
// second CTRL_C_EVENT would also interrupt unrelated processes in that console.
// A new process group would disable Ctrl-C in the child, so do not create one.
func notifySignals(c chan os.Signal) { signal.Notify(c, os.Interrupt, syscall.SIGTERM) }
func stopSignals(c chan os.Signal)   { signal.Stop(c) }
func signalNumber(s os.Signal) int32 {
	if s == os.Interrupt {
		return 2
	}
	return 15
}
func forwardSignal(_ *os.Process, _ os.Signal) {}
func childSignalExit(_ *exec.ExitError) int    { return 0 }

func restoreTerminal() func() {
	type saved struct {
		handle windows.Handle
		mode   uint32
	}
	var states []saved
	for _, f := range []*os.File{os.Stdin, os.Stdout, os.Stderr} {
		var mode uint32
		h := windows.Handle(f.Fd())
		if windows.GetConsoleMode(h, &mode) == nil {
			states = append(states, saved{h, mode})
		}
	}
	return func() {
		for _, s := range states {
			_ = windows.SetConsoleMode(s.handle, s.mode)
		}
	}
}

// A private kill-on-close job contains only this invocation's child tree.
// Never enumerate or kill processes by name. The job handle is noninheritable.
var childJob windows.Handle

func prepareChild(_ *exec.Cmd) (func(), error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, err
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		windows.CloseHandle(job)
		return nil, err
	}
	childJob = job
	return func() { windows.CloseHandle(job) }, nil
}
func containChild(cmd *exec.Cmd) error {
	h, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid))
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	return windows.AssignProcessToJobObject(childJob, h)
}
