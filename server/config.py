"""Paths and constants shared by the runner, the database layer and the dashboard server."""
import os

HOME = os.path.expanduser("~")
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.environ.get("MG_DATA", os.path.join(HOME, ".mac-guard"))
DB_PATH = os.path.join(DATA_DIR, "guard.db")
TOKEN_PATH = os.path.join(DATA_DIR, "token")
NONCE_PATH = os.path.join(DATA_DIR, "nonce")
LOCK_PATH = os.path.join(DATA_DIR, "run.lock")
REPORTS_DIR = os.path.join(DATA_DIR, "reports")
CHECK_SCRIPT = os.path.join(REPO, "audit", "check.sh")
RUNNER = os.path.join(REPO, "server", "runner.py")
DASHBOARD_DIR = os.path.join(REPO, "dashboard")
PYTHON = "/usr/bin/python3"

HOST = "127.0.0.1"
PORT = 47821
LAUNCHD_SOCKET_NAME = "Listener"   # must match the Sockets key in the dashboard plist
IDLE_EXIT_SECONDS = 15 * 60
AUDIT_TIMEOUT_SECONDS = 10 * 60
MAX_BODY_BYTES = 4096
MIN_TOKEN_LENGTH = 32
NONCE_MAX_AGE_SECONDS = 60


class Severity:
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    PASS = "pass"
    TRACKED = (HIGH, MEDIUM, LOW)          # these get a lifecycle; info/pass are per-run only
    ALL = (HIGH, MEDIUM, LOW, INFO, PASS)


class Status:
    OPEN = "open"
    ACCEPTED = "accepted"
    RESOLVED = "resolved"


class RunStatus:
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"


class Trigger:
    DASHBOARD = "dashboard"
    SCHEDULED = "scheduled"
    MANUAL = "manual"
    ALL = (DASHBOARD, SCHEDULED, MANUAL)


class Action:
    ACCEPT = "accept"
    REOPEN = "reopen"
    ALL = (ACCEPT, REOPEN)


# Protection tools shown on the dashboard:
# (name, paths that mean "installed", text to find among activated system extensions, process names that mean "running")
TOOLS = (
    ("Santa", ("/Applications/Santa.app",), "santa", ()),
    ("BlockBlock", ("/Library/Objective-See/BlockBlock", "/Library/LaunchDaemons/com.objective-see.blockblock.plist"),
     None, ("BlockBlock", "BlockBlock Helper")),
    ("LuLu", ("/Applications/LuLu.app",), "lulu", ()),
)
