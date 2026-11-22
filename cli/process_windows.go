//go:build windows

package main

import (
	"errors"
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
var getProcessIDOfThread = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetProcessIdOfThread")

func prepareChild(cmd *exec.Cmd) (func(), func(*exec.Cmd) error, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, nil, err
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		windows.CloseHandle(job)
		return nil, nil, err
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_SUSPENDED}
	return func() { windows.CloseHandle(job) }, func(c *exec.Cmd) error { return containWindowsChild(c, job) }, nil
}
func containWindowsChild(cmd *exec.Cmd, childJob windows.Handle) error {
	h, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid))
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	if err := windows.AssignProcessToJobObject(childJob, h); err != nil {
		return err
	}
	// The child has not executed any code, so it has exactly its primary thread.
	// Associate it with the job before resuming to close the descendant escape race.
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(snapshot)
	entry := windows.ThreadEntry32{Size: uint32(unsafe.Sizeof(windows.ThreadEntry32{}))}
	for err = windows.Thread32First(snapshot, &entry); err == nil; err = windows.Thread32Next(snapshot, &entry) {
		if entry.OwnerProcessID != uint32(cmd.Process.Pid) {
			continue
		}
		thread, e := windows.OpenThread(windows.THREAD_SUSPEND_RESUME|windows.THREAD_QUERY_LIMITED_INFORMATION, false, entry.ThreadID)
		if e != nil {
			return e
		}
		if e := verifyThreadOwner(thread, uint32(cmd.Process.Pid), func(h windows.Handle) (uint32, error) {
			owner, _, err := getProcessIDOfThread.Call(uintptr(h))
			if owner == 0 {
				return 0, err
			}
			return uint32(owner), nil
		}); e != nil {
			windows.CloseHandle(thread)
			return e
		}
		count, e := windows.ResumeThread(thread)
		windows.CloseHandle(thread)
		if e != nil {
			return e
		}
		if count != 1 {
			return errors.New("unexpected child suspension state")
		}
		return nil
	}
	return errors.New("suspended child primary thread missing")
}

// Query on the opened handle, not the stale snapshot ID, before resuming it.
func verifyThreadOwner(thread windows.Handle, expected uint32, query func(windows.Handle) (uint32, error)) error {
	owner, err := query(thread)
	if err != nil {
		return err
	}
	if owner == 0 || owner != expected {
		return errors.New("child thread ownership changed")
	}
	return nil
}
