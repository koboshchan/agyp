#!/usr/bin/env python3
"""Real controlling-terminal regression tests; stdlib only, no live credentials.

Run python3 cli/test_pty.py, or set AGYP_TEST_BINARY to test a built release.
Each process owns a fresh PTY/session, and all spawned PIDs are cleaned up.
"""
import errno
import hashlib
import hmac
import http.server
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
import threading
import time
import unittest

KEY = "agyp_0123456789abcdef.pty_regression_secret"
NONCE = "pty_regression_nonce"
TIMEOUT = 5

class AuthServer:
    def __init__(self, blocked=None):
        self.blocked = blocked
        self.entered = threading.Event()
        self.release = threading.Event()
        self.errors = []
        self.paths = []
        owner = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                try:
                    body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                    owner.paths.append(self.path)
                    if self.path == owner.blocked:
                        owner.entered.set()
                        owner.release.wait(10)
                    if self.path == "/auth/challenge":
                        assert body["keyId"] == "0123456789abcdef"
                        response = {"nonce": NONCE, "expires": int(time.time()) + 60}
                    elif self.path == "/auth/verify":
                        assert body["nonce"] == NONCE
                        assert body["keyId"] == "0123456789abcdef"
                        assert body["client"] == "cli"
                        expected = hmac.new(KEY.encode(), NONCE.encode(), hashlib.sha256).hexdigest()
                        assert hmac.compare_digest(body["proof"], expected)
                        response = {"token": "fake-pty-session", "expires": int(time.time()) + 600}
                    elif self.path == "/auth/logout":
                        response = {}
                    else:
                        raise AssertionError("unexpected path " + self.path)
                    encoded = json.dumps(response).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(encoded)))
                    self.end_headers()
                    self.wfile.write(encoded)
                except (BrokenPipeError, ConnectionResetError):
                    pass
                except Exception as exc:
                    owner.errors.append(repr(exc))
                    self.send_error(500)

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        return self

    def start(self):
        # Fork the PTY child before starting any Python threads.
        self.thread.start()

    @property
    def base(self):
        return "http://127.0.0.1:" + str(self.server.server_port)

    def __exit__(self, *args):
        self.release.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(TIMEOUT)


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

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def assert_terminal_restored(self, terminal):
        self.assertEqual(terminal.before, termios.tcgetattr(terminal.fd), terminal.output)

    def blocked_auth(self, path):
        pidfile = self.root / (path.rsplit("/", 1)[1] + ".pid")
        with AuthServer(blocked=path) as auth:
            terminal = Terminal(self.binary, auth.base, BLOCKED_CHILD, pidfile)
            auth.start()
            try:
                self.assertTrue(auth.entered.wait(TIMEOUT), "auth endpoint was not reached")
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
        self.blocked_auth("/auth/challenge")

    def test_ctrl_c_during_verify(self):
        self.blocked_auth("/auth/verify")

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
                os.write(terminal.fd, b"hello from actual terminal\n")
                terminal.until(b"RECEIVED hello from actual terminal")
                os.write(terminal.fd, b"\x03")
                self.assertEqual(terminal.wait(), 130, terminal.output)
                terminal.until(b"RESTORED")
                self.assert_terminal_restored(terminal)
                with self.assertRaises(ProcessLookupError, msg="child survived wrapper exit"):
                    os.kill(state["pid"], 0)
                self.assertFalse(auth.errors, auth.errors)
                self.assertEqual(auth.paths[:2], ["/auth/challenge", "/auth/verify"])
                print("\nPTY_EVIDENCE " + json.dumps(dict(test="raw" if raw else "interactive", exit=terminal.status,
                      terminal_restored=True, child_alive=False, **state)), flush=True)
            finally:
                terminal.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
