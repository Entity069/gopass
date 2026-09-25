#!/usr/bin/env python3
"""Real PTY integration tests. Uses only Python's standard library (Linux/macOS).

Local:  python3 scripts/smoke.py ./bin/cli-login
Docker: python3 scripts/smoke.py --docker   (build cli-login:local first)
Docker tests use a unique Compose project and remove only that test's volume.
"""

import base64
import contextlib
import fcntl
import hashlib
import hmac
import os
import pathlib
import pty
import re
import select
import signal
import sqlite3
import struct
import subprocess
import sys
import tempfile
import termios
import time
import uuid

PASSWORD = "smoke test correct horse battery staple"
ANSI = re.compile(rb"\x1b\[[0-?]*[ -/]*[@-~]")


def totp(secret, step):
    """Independent RFC 6238 calculation to test interoperability with Go."""
    digest = hmac.new(base64.b32decode(secret), struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 15
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7fffffff
    return f"{value % 1000000:06d}"


class Shell:
    def __init__(self, command, env):
        self.buffer = b""
        self.transcript = b""
        self.pid, self.fd = pty.fork()
        self.closed = False
        if self.pid == 0:
            fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack("HHHH", 32, 120, 0, 0))
            os.execvpe(command[0], command, env)
        try:
            self.expect("login> ", timeout=60)
        except Exception:
            self.cleanup()
            raise

    def send(self, value):
        os.write(self.fd, value if isinstance(value, bytes) else value.encode() + b"\n")

    def expect(self, text, timeout=15):
        target = text.encode()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            clean = ANSI.sub(b"", self.buffer).replace(b"\r", b"")
            if target in clean:
                end = clean.index(target) + len(target)
                result = clean[:end].decode(errors="replace")
                self.buffer = clean[end:]
                return result
            ready, _, _ = select.select([self.fd], [], [], 0.1)
            if ready:
                try:
                    chunk = os.read(self.fd, 65536)
                except OSError as exc:
                    raise AssertionError(f"terminal exited before {text!r}") from exc
                if not chunk:
                    raise AssertionError(f"terminal closed before {text!r}")
                self.buffer += chunk
                self.transcript += chunk
        raise AssertionError(f"timed out waiting for {text!r}")

    def login(self, password=PASSWORD, code=None, success=True):
        self.send("login")
        self.expect("Username: ")
        self.send("alice")
        self.expect("Password: ")
        self.send(password)
        if code is not None:
            self.expect("Authenticator code (6 digits; use a fresh code): ")
            self.send(code)
        if success:
            self.expect("Login successful.")
            details = self.expect("account> ")
            for field in ("Username: alice", "Registered:", "MFA:", "Session expires:", "Last login"):
                assert field in details, f"login omitted {field}"
        else:
            self.expect("Error: authentication failed")
            self.expect("login> ")

    def finish(self, control=None):
        self.send(control if control is not None else "exit")
        self.expect("Goodbye.")
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            pid, status = os.waitpid(self.pid, os.WNOHANG)
            if pid:
                self.closed = True
                os.close(self.fd)
                assert os.waitstatus_to_exitcode(status) == 0, "CLI exited with an error"
                assert PASSWORD.encode() not in self.transcript, "password echoed to terminal"
                return
            time.sleep(0.05)
        raise AssertionError("CLI did not exit")

    def cleanup(self):
        if not self.closed:
            with contextlib.suppress(ProcessLookupError):
                os.kill(self.pid, signal.SIGTERM)
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                pid, _ = os.waitpid(self.pid, os.WNOHANG)
                if pid:
                    break
                time.sleep(0.05)
            else:
                with contextlib.suppress(ProcessLookupError):
                    os.kill(self.pid, signal.SIGKILL)
                os.waitpid(self.pid, 0)
            os.close(self.fd)
            self.closed = True


def run_suite(command, env, data_dir, docker):
    shells = []

    def start(**overrides):
        shell = Shell(command, {**env, **overrides})
        shells.append(shell)
        return shell

    try:
        s = start()
        s.send("help")
        s.expect("register     Create")
        s.expect("login> ")
        s.send(b"\x1b[A\n")  # Up-arrow command history.
        s.expect("register     Create")
        s.expect("login> ")
        s.send(b"reg\t\n")  # Real terminal tab completion.
        s.expect("Username (3–32 characters): ")
        s.send("Alice")
        s.expect("Password (at least 8 characters): ")
        s.send(PASSWORD)
        s.expect("Confirm password: ")
        s.send(PASSWORD)
        s.expect("Account created.")
        s.expect("login> ")
        s.login(password="incorrect password", success=False)
        s.login()
        s.send("whoami")
        s.expect("Username: alice")
        s.expect("account> ")
        s.send("unrecognized-sensitive-input")
        s.expect("Unknown command.")
        s.expect("account> ")
        s.send(b"\x1b[A\n")
        s.expect("Username: alice")  # History skipped the unknown text and form inputs.
        s.expect("account> ")
        print("PASS registration, private password input, login details, tab completion and history", flush=True)

        s.send("enable-2fa")
        s.expect("Current password: ")
        s.send(PASSWORD)
        enrollment = s.expect("Enter the authenticator code to confirm (Ctrl+C cancels): ")
        secret = re.search(r"Setup key: ([A-Z2-7]+)", enrollment).group(1)
        step = int(time.time()) // 30
        s.send(totp(secret, step))
        s.expect("2FA enabled. All sessions ended.")
        s.expect("login> ")
        s.login(code=totp(secret, step), success=False)  # Enrollment code is already consumed.
        login_step = max(step + 1, int(time.time()) // 30)
        s.login(code=totp(secret, login_step))
        s.send("whoami")
        s.expect("MFA: enabled")
        s.expect("account> ")
        # Exercise the real clock with the ±1-step tolerance. Wait at most 30s for
        # a new acceptable step; no test-only clock controls exist in production.
        while int(time.time()) // 30 < login_step:
            time.sleep(0.1)
        s.send("disable-2fa")
        s.expect("Current password: ")
        s.send(PASSWORD)
        s.expect("Fresh authenticator code (6 digits): ")
        s.send(totp(secret, max(login_step + 1, int(time.time()) // 30)))
        s.expect("2FA disabled. All sessions ended.")
        s.expect("login> ")
        s.login()
        s.send("logout")
        s.expect("Logged out.")
        s.expect("login> ")
        s.finish()
        print("PASS MFA enrollment, independent TOTP interoperability, replay denial, disable and logout", flush=True)

        s = start()
        s.login()  # Account/key/database persist across processes or containers.
        s.finish()
        print("PASS database persistence across fresh processes/containers", flush=True)

        s = start(APP_SESSION_TTL="1s")
        s.login()
        time.sleep(1.1)
        s.send("whoami")
        s.expect("Session expired or revoked.")
        s.expect("Please log in first.")
        s.expect("login> ")
        s.finish(b"\x04")  # EOF.
        print("PASS idle session expiration and EOF cleanup", flush=True)

        s = start(APP_MAX_ATTEMPTS="2", APP_LOCKOUT_DURATION="2s")
        s.login(password="incorrect password", success=False)
        s.login(password="incorrect password", success=False)
        s.login(success=False)
        time.sleep(2.1)
        s.login()
        s.finish(b"\x03")  # Ctrl+C exits at command prompt.
        print("PASS account lockout, timed unlock and Ctrl+C cleanup", flush=True)

        s = start()
        s.send("register")
        s.expect("Username (3–32 characters): ")
        s.send(b"\x03")
        s.expect("Cancelled.")
        s.expect("login> ")
        s.finish()
        print("PASS Ctrl+C cancels a form without quitting", flush=True)

        if not docker:
            with sqlite3.connect(data_dir / "login.db") as db:
                assert db.execute("SELECT count(*) FROM sessions").fetchone()[0] == 0
                assert db.execute("SELECT count(*) FROM mfa_enrollments").fetchone()[0] == 0
                stored = db.execute("SELECT password_hash FROM users WHERE username='alice'").fetchone()[0]
                assert stored.startswith("$argon2id$") and PASSWORD not in stored
            assert (data_dir / "master.key").stat().st_mode & 0o777 == 0o600
            assert (data_dir / "login.db").stat().st_mode & 0o777 == 0o600
            refused = subprocess.run(command, input="login\n", text=True, capture_output=True, env=env, timeout=10)
            assert refused.returncode != 0 and "interactive terminal is required" in refused.stderr
            print("PASS persisted secret permissions, session cleanup and non-TTY rejection", flush=True)
    finally:
        for shell in shells:
            shell.cleanup()


def main():
    docker = sys.argv[1:] == ["--docker"]
    env = {key: value for key, value in os.environ.items() if not key.startswith("APP_")}
    env.update(TERM="xterm", APP_SESSION_TTL="30m", APP_MAX_ATTEMPTS="5", APP_LOCKOUT_DURATION="15m", APP_ISSUER="CLI Smoke Test")
    project = "cli-login-smoke-" + uuid.uuid4().hex[:12]
    with tempfile.TemporaryDirectory(prefix="cli-login-smoke-") as temporary:
        data_dir = pathlib.Path(temporary) / "data"
        if docker:
            command = ["docker", "compose", "-p", project, "run", "--rm", "--no-deps", "login"]
        else:
            binary = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "./bin/cli-login").resolve()
            command = [str(binary)]
            env["APP_DATA_DIR"] = str(data_dir)
        try:
            run_suite(command, env, data_dir, docker)
        finally:
            if docker:
                subprocess.run(["docker", "compose", "-p", project, "down", "--volumes", "--remove-orphans"], env=env, check=True, timeout=30)
    print("All terminal smoke tests passed.", flush=True)


if __name__ == "__main__":
    main()
