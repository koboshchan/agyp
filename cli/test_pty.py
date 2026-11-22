#!/usr/bin/env python3
"""Real controlling-terminal regression tests; Python stdlib + existing Go WebSocket dependency, no live credentials.

Run python3 cli/test_pty.py, or set AGYP_TEST_BINARY to test a built release.
Each process owns a fresh PTY/session, and all spawned PIDs are cleaned up.
"""
import errno
import json
import os
from pathlib import Path
import pty
import select
import signal
import subprocess
import sys
import tempfile
import termios
import time
import unittest

KEY = "agyp_0123456789abcdef.pty_regression_secret"
TIMEOUT = 5

# Built with the CLI's existing gorilla/websocket dependency, never a custom
# framing/parser implementation. Cross-build and supply AGYP_TEST_FIXTURE_BINARY
# when the target machine (e.g. macOS) doesn't have Go installed.
WS_FIXTURE_GO = r"""
package main

import (
 "crypto/hmac"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "fmt"
 "net"
 "net/http"
 "os"
 "strings"
 "sync"
 "time"

 "github.com/gorilla/websocket"
)

const key = "agyp_0123456789abcdef.pty_regression_secret"
var output sync.Mutex
func event(kind string) {
 output.Lock()
 defer output.Unlock()
 encoded, _ := json.Marshal(map[string]string{"event":kind})
 fmt.Println(string(encoded))
}
func main() {
 blocked := ""
 if len(os.Args)>1 { blocked=os.Args[1] }
 listener, err := net.Listen("tcp", "127.0.0.1:0")
 if err!=nil { panic(err) }
 fmt.Println(listener.Addr().String())
 upgrader := websocket.Upgrader{Subprotocols: []string{"agyp.v1"}}
 http.Serve(listener, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
  if r.URL.Path!="/transport" || r.Header.Get("Sec-WebSocket-Protocol")!="agyp.v1" {
   event("error:unexpected REST or transport request")
   http.Error(w, "transport only", 400)
   return
  }
  conn, err := upgrader.Upgrade(w,r,nil)
  if err!=nil {event("error:upgrade");return}
  defer conn.Close()
  conn.SetReadLimit(65536)
  event("challenge")
  // Hold the handshake at a precise stage, without sending a challenge/ready.
  // A read blocks until the interrupted client actually closes the connection.
  if blocked=="challenge" {conn.ReadMessage();return}
  nonce,salt := strings.Repeat("n",43),strings.Repeat("s",43)
  expires := time.Now().Add(30*time.Second).UnixMilli()
  conn.WriteJSON(map[string]any{"type":"challenge","nonce":nonce,"salt":salt,"expires":expires})
  var auth struct {Type string; KeyID string; Proof string}
  if conn.ReadJSON(&auth)!=nil {event("error:missing proof");return}
  mac:=hmac.New(sha256.New,[]byte(key))
  mac.Write([]byte("agyp-ws-v1\n"+salt+"\n"+nonce))
  proof,err:=hex.DecodeString(auth.Proof)
  if err!=nil || auth.Type!="auth" || auth.KeyID!="0123456789abcdef" ||
     !hmac.Equal(proof,mac.Sum(nil)) || time.Now().UnixMilli()>=expires {
   event("error:invalid HMAC proof or expired challenge");return
  }
  event("verify")
  if blocked=="verify" {conn.ReadMessage();return}
  conn.WriteJSON(map[string]string{"type":"ready"})
  event("ready")
  for {
   if _,_,err:=conn.ReadMessage();err!=nil{return}
   event("error:unexpected application frame")
  }
 }))
}
"""

class AuthServer:
    fixture_binary = None

    def __init__(self, blocked=None):
        self.blocked = blocked
        self.errors = []
        self.paths = []

    def __enter__(self):
        self.process = subprocess.Popen(
            [str(self.fixture_binary), self.blocked or ""],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)
        self.pending = b""
        self.address = self.line()
        return self

    def start(self):
        pass  # No Python threads; safe to fork the PTY child.

    def line(self):
        deadline = time.monotonic() + TIMEOUT
        while b"\n" not in self.pending:
            remaining = deadline-time.monotonic()
            if remaining<=0 or not select.select([self.process.stdout],[],[],remaining)[0]:
                raise AssertionError("WebSocket fixture did not respond")
            data = os.read(self.process.stdout.fileno(),65536)
            if not data:
                raise AssertionError("WebSocket fixture exited: "+repr(self.pending))
            self.pending += data
        line,self.pending = self.pending.split(b"\n",1)
        return line.decode()

    def read_event(self):
        event = json.loads(self.line())["event"]
        if event.startswith("error:"):
            self.errors.append(event)
        else:
            self.paths.append(event)
        return event

    def wait_entered(self):
        while self.blocked not in self.paths:
            self.read_event()
        return True

    def assert_authenticated(self):
        while "ready" not in self.paths:
            self.read_event()
        if self.errors:
            raise AssertionError(self.errors)

    @property
    def base(self):
        return "http://" + self.address

    def __exit__(self, *args):
        self.process.terminate()
        try:
            self.process.wait(TIMEOUT)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
        self.process.stdout.close()


class Terminal:
    def __init__(self, binary, base, script, pidfile):
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            env = dict(os.environ, AGYP_BASE=base, AGYP_TOKEN=KEY)
            os.execve(str(binary), [str(binary), "--", sys.executable, "-c", script, str(pidfile)], env)
        self.before = termios.tcgetattr(self.fd)
        self.output = b""
        self.status = None
        self.pidfile = pidfile

    def drain(self, duration=0.05):
        deadline = time.monotonic() + duration
        while time.monotonic() < deadline:
            ready, _, _ = select.select([self.fd], [], [], max(0, deadline-time.monotonic()))
            if not ready:
                break
            try:
                data = os.read(self.fd, 65536)
                if not data:
                    break
                self.output += data
            except OSError as exc:
                if exc.errno != errno.EIO:
                    raise
                break

    def until(self, marker, timeout=TIMEOUT):
        deadline = time.monotonic() + timeout
        while marker not in self.output and time.monotonic() < deadline:
            self.drain(0.05)
        if marker not in self.output:
            raise AssertionError("missing %r; terminal output %r" % (marker, self.output))

    def wait(self, timeout=TIMEOUT):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.drain(0.03)
            pid, status = os.waitpid(self.pid, os.WNOHANG)
            if pid:
                self.status = os.waitstatus_to_exitcode(status)
                return self.status
        raise AssertionError("agyp did not exit; terminal output %r" % self.output)

    def child_pid(self):
        return int(self.pidfile.read_text()) if self.pidfile.exists() else None

    def close(self):
        # Kill exact owned child first, including the old regression's separate pgid.
        child = self.child_pid()
        if child:
            try:
                os.kill(child, signal.SIGKILL)
            except ProcessLookupError:
                pass
        if self.status is None:
            try:
                os.kill(self.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                os.waitpid(self.pid, 0)
            except ChildProcessError:
                pass
        os.close(self.fd)


CHILD = r"""
import json, os, signal, sys, termios, tty
from pathlib import Path
Path(sys.argv[1]).write_text(str(os.getpid()))
saved = termios.tcgetattr(0)
state = dict(pid=os.getpid(), pgid=os.getpgrp(), foreground=os.tcgetpgrp(0),
             tty=[os.isatty(i) for i in range(3)])
print("CHILD_STATE " + json.dumps(state), flush=True)
def interrupted(signum, frame):
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    raise SystemExit(130)
signal.signal(signal.SIGINT, interrupted)
try:
    changed = termios.tcgetattr(0)
    changed[3] &= ~termios.ECHO
    termios.tcsetattr(0, termios.TCSANOW, changed)
    print("READY", flush=True)
    line = sys.stdin.readline()
    print("RECEIVED " + line.strip(), flush=True)
    while True:
        signal.pause()
finally:
    termios.tcsetattr(0, termios.TCSANOW, saved)
    print("RESTORED", flush=True)
"""
BLOCKED_CHILD = r"""
import os, sys
from pathlib import Path
Path(sys.argv[1]).write_text(str(os.getpid()))
print("UNEXPECTED_CHILD", flush=True)
"""


class PTYTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="agyp-pty-")
        cls.root = Path(cls.temp.name)
        configured = os.environ.get("AGYP_TEST_BINARY")
        cls.binary = Path(configured).resolve() if configured else cls.root / "agyp"
        if not configured:
            subprocess.run(["go", "build", "-o", str(cls.binary), "."],
                           cwd=Path(__file__).resolve().parent, check=True)
        fixture = os.environ.get("AGYP_TEST_FIXTURE_BINARY")
        AuthServer.fixture_binary = Path(fixture).resolve() if fixture else cls.root / "ws-fixture"
        if not fixture:
            source = cls.root / "ws-fixture.go"
            source.write_text(WS_FIXTURE_GO)
            subprocess.run(["go", "build", "-o", str(AuthServer.fixture_binary), str(source)],
                           cwd=Path(__file__).resolve().parent, check=True)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def assert_terminal_restored(self, terminal):
        self.assertEqual(terminal.before, termios.tcgetattr(terminal.fd), terminal.output)

    def blocked_auth(self, path):
        pidfile = self.root / (path.rsplit("/", 1)[-1] + ".pid")
        with AuthServer(blocked=path) as auth:
            terminal = Terminal(self.binary, auth.base, BLOCKED_CHILD, pidfile)
            auth.start()
            try:
                self.assertTrue(auth.wait_entered(), "auth endpoint was not reached")
                # Write the terminal interrupt character, not kill(SIGINT): real tty semantics.
                os.write(terminal.fd, b"\x03")
                self.assertEqual(terminal.wait(), 130, terminal.output)
                self.assertFalse(pidfile.exists(), "child spawned during canceled authentication")
                self.assert_terminal_restored(terminal)
                self.assertFalse(auth.errors, auth.errors)
                print("\nPTY_EVIDENCE " + json.dumps(dict(test=path, exit=terminal.status,
                      terminal_restored=True, child_spawned=False)), flush=True)
            finally:
                terminal.close()

    def test_ctrl_c_during_challenge(self):
        self.blocked_auth("challenge")

    def test_ctrl_c_during_verify(self):
        self.blocked_auth("verify")

    def test_cooked_ctrl_c_is_delivered_once(self):
        pidfile = self.root / "count.pid"
        script = r"""
import os, signal, sys, time
from pathlib import Path
Path(sys.argv[1]).write_text(str(os.getpid()))
count = 0
def interrupted(signum, frame):
    global count
    count += 1
signal.signal(signal.SIGINT, interrupted)
print("COUNT_READY", flush=True)
while not count:
    time.sleep(.01)
# Stay alive long enough to catch an incorrectly forwarded duplicate.
time.sleep(.8)
print("SIGNAL_COUNT " + str(count), flush=True)
raise SystemExit(130)
"""
        with AuthServer() as auth:
            terminal = Terminal(self.binary, auth.base, script, pidfile)
            auth.start()
            try:
                terminal.until(b"COUNT_READY")
                auth.assert_authenticated()
                os.write(terminal.fd, b"\x03")
                self.assertEqual(terminal.wait(), 130, terminal.output)
                self.assertIn(b"SIGNAL_COUNT 1", terminal.output)
                self.assert_terminal_restored(terminal)
                with self.assertRaises(ProcessLookupError):
                    os.kill(terminal.child_pid(), 0)
            finally:
                terminal.close()

    def test_interactive_child_foreground_and_ctrl_c(self):
        self.interactive_child(raw=False)

    def test_raw_mode_child_restores_terminal_after_ctrl_c(self):
        self.interactive_child(raw=True)

    def interactive_child(self, raw):
        pidfile = self.root / ("raw.pid" if raw else "interactive.pid")
        script = CHILD
        if raw:
            script = CHILD.replace("changed = termios.tcgetattr(0)",
                                   "tty.setraw(0)\n    changed = termios.tcgetattr(0)\n    changed[3] |= termios.ISIG")
        with AuthServer() as auth:
            terminal = Terminal(self.binary, auth.base, script, pidfile)
            auth.start()
            try:
                terminal.until(b"CHILD_STATE ")
                terminal.until(b"\n")
                state_line = next(line for line in terminal.output.splitlines()
                                  if line.startswith(b"CHILD_STATE "))
                state = json.loads(state_line[len(b"CHILD_STATE "):])
                self.assertEqual(state["tty"], [True, True, True])
                self.assertEqual(state["pgid"], state["foreground"], state)
                terminal.until(b"READY")
                auth.assert_authenticated()
                os.write(terminal.fd, b"hello from actual terminal\n")
                terminal.until(b"RECEIVED hello from actual terminal")
                os.write(terminal.fd, b"\x03")
                self.assertEqual(terminal.wait(), 130, terminal.output)
                terminal.until(b"RESTORED")
                self.assert_terminal_restored(terminal)
                with self.assertRaises(ProcessLookupError, msg="child survived wrapper exit"):
                    os.kill(state["pid"], 0)
                self.assertFalse(auth.errors, auth.errors)
                auth.assert_authenticated()
                self.assertEqual(auth.paths[:2], ["challenge", "verify"])
                print("\nPTY_EVIDENCE " + json.dumps(dict(test="raw" if raw else "interactive", exit=terminal.status,
                      terminal_restored=True, child_alive=False, **state)), flush=True)
            finally:
                terminal.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
