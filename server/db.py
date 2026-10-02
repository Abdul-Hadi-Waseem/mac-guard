"""SQLite storage: audit runs, per-run check results, and the lifecycle of each finding."""
import sqlite3
from contextlib import contextmanager
from datetime import datetime

from config import DB_PATH, RunStatus, Severity, Status

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL, finished_at TEXT,
    trigger TEXT NOT NULL, status TEXT NOT NULL,
    report_path TEXT, changes TEXT, error TEXT,
    n_high INTEGER DEFAULT 0, n_medium INTEGER DEFAULT 0, n_low INTEGER DEFAULT 0,
    n_info INTEGER DEFAULT 0, n_pass INTEGER DEFAULT 0, n_new INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS results (
    run_id INTEGER NOT NULL REFERENCES runs(id),
    severity TEXT NOT NULL, category TEXT NOT NULL, key TEXT NOT NULL, title TEXT NOT NULL, detail TEXT
);
CREATE INDEX IF NOT EXISTS results_run ON results(run_id);
CREATE TABLE IF NOT EXISTS findings (
    key TEXT PRIMARY KEY,
    category TEXT NOT NULL, severity TEXT NOT NULL, title TEXT NOT NULL, detail TEXT,
    status TEXT NOT NULL,
    first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, resolved_at TEXT,
    note TEXT, reappeared INTEGER DEFAULT 0
);
"""


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


@contextmanager
def connect():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init():
    with connect() as c:
        c.executescript(SCHEMA)


def start_run(trigger):
    with connect() as c:
        return c.execute("INSERT INTO runs (started_at, trigger, status) VALUES (?,?,?)",
                         (now(), trigger, RunStatus.RUNNING)).lastrowid


def fail_run(run_id, error):
    with connect() as c:
        c.execute("UPDATE runs SET status=?, finished_at=?, error=? WHERE id=?",
                  (RunStatus.FAILED, now(), error[:2000], run_id))


def fail_stale_runs():
    """A run still marked running while nobody holds the lock died without cleaning up."""
    with connect() as c:
        c.execute("UPDATE runs SET status=?, finished_at=?, error=? WHERE status=?",
                  (RunStatus.FAILED, now(), "audit process ended unexpectedly", RunStatus.RUNNING))


def finish_run(run_id, rows, report_path, changes):
    """Store this run's results and move every tracked finding through its lifecycle.
    rows: list of (severity, category, key, title, detail). Returns the keys that are new or reappeared."""
    ts = now()
    counts = {s: 0 for s in Severity.ALL}
    tracked = {}
    for severity, category, key, title, detail in rows:
        counts[severity] += 1
        if severity in Severity.TRACKED:
            tracked[key] = (severity, category, title, detail)
    fresh = []
    with connect() as c:
        c.executemany("INSERT INTO results VALUES (?,?,?,?,?,?)", [(run_id, *r) for r in rows])
        existing = {r["key"]: r for r in c.execute("SELECT key, status FROM findings")}
        for key, (severity, category, title, detail) in tracked.items():
            if key not in existing:
                c.execute("INSERT INTO findings (key, category, severity, title, detail, status, first_seen, last_seen) "
                          "VALUES (?,?,?,?,?,?,?,?)", (key, category, severity, title, detail, Status.OPEN, ts, ts))
                fresh.append(key)
            elif existing[key]["status"] == Status.RESOLVED:
                c.execute("UPDATE findings SET status=?, severity=?, title=?, detail=?, last_seen=?, resolved_at=NULL, "
                          "reappeared=1 WHERE key=?", (Status.OPEN, severity, title, detail, ts, key))
                fresh.append(key)
            else:  # still open or accepted: refresh what we know, keep the user's decision
                c.execute("UPDATE findings SET severity=?, title=?, detail=?, last_seen=? WHERE key=?",
                          (severity, title, detail, ts, key))
        for key, row in existing.items():
            if key not in tracked and row["status"] != Status.RESOLVED:
                c.execute("UPDATE findings SET status=?, resolved_at=? WHERE key=?", (Status.RESOLVED, ts, key))
        c.execute("UPDATE runs SET status=?, finished_at=?, report_path=?, changes=?, n_high=?, n_medium=?, n_low=?, "
                  "n_info=?, n_pass=?, n_new=? WHERE id=?",
                  (RunStatus.DONE, ts, report_path, changes, counts[Severity.HIGH], counts[Severity.MEDIUM],
                   counts[Severity.LOW], counts[Severity.INFO], counts[Severity.PASS], len(fresh), run_id))
    return fresh


def set_finding_status(key, status, note):
    with connect() as c:
        cur = c.execute("UPDATE findings SET status=?, note=? WHERE key=? AND status!=?",
                        (status, note, key, Status.RESOLVED))
        return cur.rowcount == 1


def state():
    """Everything the dashboard needs in one read."""
    with connect() as c:
        rows = lambda q, *a: [dict(r) for r in c.execute(q, a)]
        runs = rows("SELECT id, started_at, finished_at, trigger, status, error, n_high, n_medium, n_low, n_info, "
                    "n_pass, n_new FROM runs ORDER BY id DESC LIMIT 30")
        last_done = next((r for r in runs if r["status"] == RunStatus.DONE), None)
        changes, checks = "", []
        if last_done:
            changes = c.execute("SELECT changes FROM runs WHERE id=?", (last_done["id"],)).fetchone()[0] or ""
            checks = rows("SELECT severity, category, title, detail FROM results WHERE run_id=? AND severity IN (?,?) "
                          "ORDER BY severity, title", last_done["id"], Severity.INFO, Severity.PASS)
        order = "CASE severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END"
        return {
            "running": any(r["status"] == RunStatus.RUNNING for r in runs),
            "last_run": last_done,
            "runs": runs,
            "changes": changes,
            "checks": checks,
            "open": rows(f"SELECT * FROM findings WHERE status=? ORDER BY {order}, first_seen DESC", Status.OPEN),
            "accepted": rows(f"SELECT * FROM findings WHERE status=? ORDER BY {order}, title", Status.ACCEPTED),
            "resolved": rows("SELECT * FROM findings WHERE status=? ORDER BY resolved_at DESC LIMIT 50", Status.RESOLVED),
        }


def report_path(run_id):
    with connect() as c:
        row = c.execute("SELECT report_path FROM runs WHERE id=?", (run_id,)).fetchone()
        return row[0] if row else None
