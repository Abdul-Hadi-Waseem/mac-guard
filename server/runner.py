#!/usr/bin/python3
"""Run one audit: execute audit/check.sh, load its findings into SQLite, notify when something new appears.
Used by the dashboard button, the daily launchd job and `mac-guard run`."""
import argparse
import fcntl
import os
import subprocess
import sys
import tempfile
from datetime import datetime

import db
from config import (AUDIT_TIMEOUT_SECONDS, CHECK_SCRIPT, DATA_DIR, LOCK_PATH, REPORTS_DIR, Severity, Trigger)


def parse_findings(path):
    rows = []
    # newline="\n": only LF ends a row, so a stray CR inside a value cannot split (and hide) a finding
    with open(path, encoding="utf-8", errors="replace", newline="\n") as f:
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) != 5 or parts[0] not in Severity.ALL:
                print(f"malformed finding row skipped: {line[:200]!r}", file=sys.stderr)
                continue
            rows.append(tuple(p.replace("\r", " ") for p in parts))
    # the same key can be reported twice (e.g. two processes of one program); keep the first
    seen, unique = set(), []
    for row in rows:
        if row[2] not in seen:
            seen.add(row[2])
            unique.append(row)
    return unique


def notify(n_new):
    """Fixed text plus an integer only: nothing from the audit output reaches osascript."""
    script = f'display notification "{int(n_new)} new security finding(s). Run mac-guard to review." with title "mac-guard"'
    subprocess.run(["/usr/bin/osascript", "-e", script], capture_output=True, timeout=10)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--trigger", choices=Trigger.ALL, default=Trigger.MANUAL)
    args = ap.parse_args()

    os.umask(0o077)  # reports list accounts, keys and extensions: readable by this user only
    os.makedirs(DATA_DIR, mode=0o700, exist_ok=True)
    os.chmod(DATA_DIR, 0o700)
    os.makedirs(REPORTS_DIR, exist_ok=True)
    db.init()
    lock = open(LOCK_PATH, "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        print("an audit is already running")
        return 2
    db.fail_stale_runs()

    run_id = db.start_run(args.trigger)
    ts = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    fd, findings_path = tempfile.mkstemp(prefix="mg-findings-", dir=DATA_DIR)
    os.close(fd)
    env = dict(os.environ, MG_DATA=DATA_DIR, MG_TS=ts, MG_FINDINGS=findings_path,
               PATH="/usr/bin:/bin:/usr/sbin:/sbin")
    try:
        proc = subprocess.run(["/bin/bash", CHECK_SCRIPT], env=env, capture_output=True, text=True,
                              timeout=AUDIT_TIMEOUT_SECONDS)
        report = os.path.join(REPORTS_DIR, f"{ts}.txt")
        if proc.returncode != 0 or not os.path.exists(report):
            raise RuntimeError(f"check.sh exited {proc.returncode}: {proc.stderr[-500:]}")
        changes_file = os.path.join(REPORTS_DIR, f"{ts}.changes")
        changes = open(changes_file, encoding="utf-8", errors="replace").read() if os.path.exists(changes_file) else ""
        fresh = db.finish_run(run_id, parse_findings(findings_path), report, changes)
    except Exception as exc:  # record the failure so the dashboard can show it, then re-raise for the log
        db.fail_run(run_id, str(exc))
        raise
    finally:
        os.unlink(findings_path)

    print(f"run {run_id} done: {len(fresh)} new finding(s); report {report}")
    if fresh and args.trigger == Trigger.SCHEDULED:
        notify(len(fresh))
    return 0


if __name__ == "__main__":
    sys.exit(main())
