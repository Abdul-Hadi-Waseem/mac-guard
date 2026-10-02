#!/usr/bin/python3
"""Local dashboard server for mac-guard. Standard library only.

Safety rules this file enforces:
  - listens on 127.0.0.1 only (socket handed over by launchd, or bound here when run by hand)
  - every /api/ request needs the secret token in the X-MG-Token header; the page gets the token
    by trading in a one-time, 60-second nonce that the `mac-guard` command wrote to a private file
  - the Host header must be exactly 127.0.0.1:PORT (blocks DNS rebinding)
  - state-changing requests must come from this page's own Origin (blocks other websites)
  - the only program it can start is server/runner.py with fixed arguments; nothing from a
    request is ever passed to a shell or used to build a command
  - it exits after IDLE_EXIT_SECONDS without requests; launchd starts it again on the next visit
"""
import ctypes
import fcntl
import hmac
import json
import os
import secrets
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import db
from remediation import fix_for
from config import (DASHBOARD_DIR, DATA_DIR, HOST, IDLE_EXIT_SECONDS, LAUNCHD_SOCKET_NAME, LOCK_PATH,
                    MAX_BODY_BYTES, MIN_TOKEN_LENGTH, NONCE_MAX_AGE_SECONDS, NONCE_PATH, PORT, PYTHON, REPORTS_DIR,
                    RUNNER, TOKEN_PATH, TOOLS, Action, Status, Trigger)

ALLOWED_HOST = f"{HOST}:{PORT}"
ALLOWED_ORIGIN = f"http://{HOST}:{PORT}"
STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
}
SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
                               "base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cache-Control": "no-store",
}
last_activity = time.monotonic()


def load_token():
    os.makedirs(DATA_DIR, mode=0o700, exist_ok=True)
    if not os.path.exists(TOKEN_PATH):
        fd = os.open(TOKEN_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(secrets.token_urlsafe(32))
    with open(TOKEN_PATH) as f:
        token = f.read().strip()
    if len(token) < MIN_TOKEN_LENGTH:  # an empty token would make every request "match"
        sys.exit(f"refusing to start: {TOKEN_PATH} is empty or too short; delete it and run mac-guard again")
    return token


def create_nonce():
    """Called by the `mac-guard` command: a single-use value the page trades for the real token,
    so the long-lived token never appears in a command line or in browser history."""
    nonce = secrets.token_urlsafe(32)
    fd = os.open(NONCE_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(nonce)
    return nonce


def redeem_nonce(candidate):
    """True once for the right nonce within its lifetime. The file is removed on every attempt."""
    try:
        age = time.time() - os.path.getmtime(NONCE_PATH)
        with open(NONCE_PATH) as f:
            expected = f.read().strip()
        os.unlink(NONCE_PATH)
    except OSError:
        return False
    return (len(expected) >= MIN_TOKEN_LENGTH and age <= NONCE_MAX_AGE_SECONDS
            and hmac.compare_digest(candidate.encode("utf-8", "replace"), expected.encode()))


def audit_is_running():
    """True while runner.py holds the run lock."""
    with open(LOCK_PATH, "a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return True
        fcntl.flock(lock, fcntl.LOCK_UN)
        return False


def tool_status():
    tools = []
    for name, paths, processes in TOOLS:
        running = any(subprocess.run(["/usr/bin/pgrep", "-x", p], capture_output=True).returncode == 0 for p in processes)
        tools.append({"name": name, "installed": running or any(os.path.exists(p) for p in paths), "running": running})
    return tools


def start_audit():
    log = open(os.path.join(DATA_DIR, "runner.log"), "a")
    subprocess.Popen([PYTHON, RUNNER, "--trigger", Trigger.DASHBOARD], stdout=log, stderr=log,
                     stdin=subprocess.DEVNULL, start_new_session=True, cwd=os.path.dirname(RUNNER))


class Handler(BaseHTTPRequestHandler):
    server_version = "mac-guard"
    sys_version = ""
    token = ""

    def log_message(self, fmt, *args):
        pass

    # ---- responses
    def send(self, code, body, content_type):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for k, v in SECURITY_HEADERS.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, code, payload):
        self.send(code, json.dumps(payload).encode(), "application/json; charset=utf-8")

    def deny(self, code, message):
        self.send_json(code, {"error": message})

    # ---- guards
    def guard(self, api):
        """Returns True when the request may proceed; otherwise it has already been answered."""
        global last_activity
        last_activity = time.monotonic()
        if self.headers.get("Host") != ALLOWED_HOST:
            self.deny(403, "bad host")
            return False
        supplied = self.headers.get("X-MG-Token", "").encode("utf-8", "replace")
        if api and not hmac.compare_digest(supplied, self.token.encode()):
            self.deny(401, "missing or wrong token - run `mac-guard` in a terminal to open the dashboard")
            return False
        return True

    def read_json(self):
        if self.headers.get("Origin") != ALLOWED_ORIGIN:
            self.deny(403, "bad origin")
            return None
        if self.headers.get("Content-Type", "").split(";")[0].strip() != "application/json":
            self.deny(415, "json only")
            return None
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = -1
        if not 0 <= length <= MAX_BODY_BYTES:
            self.deny(413, "body too large")
            return None
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            body = None
        if not isinstance(body, dict):
            self.deny(400, "bad json")
            return None
        return body

    # ---- routes
    def safely(self, handler):
        try:
            handler()
        except Exception as exc:  # a bug in one request must not drop the connection or stop the server
            print(f"request failed: {self.command} {self.path}: {exc!r}", file=sys.stderr, flush=True)
            self.deny(500, "internal error")

    def do_GET(self):
        self.safely(self.handle_get)

    def do_POST(self):
        self.safely(self.handle_post)

    def handle_get(self):
        url = urlparse(self.path)
        if url.path in STATIC_FILES:
            if not self.guard(api=False):
                return
            name, content_type = STATIC_FILES[url.path]
            with open(os.path.join(DASHBOARD_DIR, name), "rb") as f:
                return self.send(200, f.read(), content_type)
        if not self.guard(api=True):
            return
        if url.path == "/api/state":
            running = audit_is_running()
            if not running:
                db.fail_stale_runs()
            state = db.state()
            state.update(running=running, tools=tool_status())
            for finding in state["open"]:
                finding["fix"] = fix_for(finding["key"])
            return self.send_json(200, state)
        if url.path == "/api/report":
            run = parse_qs(url.query).get("run", [""])[0]
            path = db.report_path(int(run)) if run.isascii() and run.isdigit() else None
            real = os.path.realpath(path) if path else ""
            # only ever serve files that sit directly inside the reports folder
            if os.path.dirname(real) != os.path.realpath(REPORTS_DIR) or not os.path.isfile(real):
                return self.deny(404, "no such report")
            with open(real, "rb") as f:
                return self.send(200, f.read(), "text/plain; charset=utf-8")
        self.deny(404, "not found")

    def handle_post(self):
        if self.path == "/api/login":  # the one API call made before the page has the token
            if not self.guard(api=False):
                return
            body = self.read_json()
            if body is None:
                return
            nonce = body.get("nonce")
            if not isinstance(nonce, str) or not redeem_nonce(nonce):
                return self.deny(401, "sign-in link expired - run `mac-guard` again")
            return self.send_json(200, {"token": self.token})
        if not self.guard(api=True):
            return
        body = self.read_json()
        if body is None:
            return
        if self.path == "/api/run":
            if audit_is_running():
                return self.deny(409, "an audit is already running")
            start_audit()
            return self.send_json(202, {"started": True})
        if self.path == "/api/finding":
            key, action, note = body.get("key"), body.get("action"), body.get("note", "")
            if not isinstance(key, str) or action not in Action.ALL or not isinstance(note, str):
                return self.deny(400, "bad request")
            status = Status.ACCEPTED if action == Action.ACCEPT else Status.OPEN
            if not db.set_finding_status(key, status, note[:500]):
                return self.deny(404, "no such finding")
            return self.send_json(200, {"ok": True})
        self.deny(404, "not found")


def launchd_socket():
    """Take over the listening socket launchd holds for us; None when not started by launchd."""
    libc = ctypes.CDLL(None)
    fds, count = ctypes.POINTER(ctypes.c_int)(), ctypes.c_size_t()
    if libc.launch_activate_socket(LAUNCHD_SOCKET_NAME.encode(), ctypes.byref(fds), ctypes.byref(count)) != 0:
        return None
    sock = socket.socket(fileno=fds[0]) if count.value else None
    libc.free(fds)
    return sock


def exit_when_idle():
    while True:
        time.sleep(30)
        if time.monotonic() - last_activity > IDLE_EXIT_SECONDS and not audit_is_running():
            os._exit(0)


def main():
    os.umask(0o077)
    db.init()
    Handler.token = load_token()
    server = ThreadingHTTPServer((HOST, PORT), Handler, bind_and_activate=False)
    inherited = launchd_socket()
    if inherited:
        server.socket.close()
        server.socket = inherited
    else:
        server.allow_reuse_address = True
        server.server_bind()
        server.server_activate()
    if server.socket.getsockname()[0] != HOST:
        sys.exit("refusing to serve: socket is not bound to 127.0.0.1")
    threading.Thread(target=exit_when_idle, daemon=True).start()
    server.serve_forever()


if __name__ == "__main__":
    main()
