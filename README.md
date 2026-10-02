# mac-guard

A local security audit and dashboard for this Mac. Everything runs on the laptop; nothing is sent anywhere.

## Use it

| Command | What it does |
|---|---|
| `mac-guard` | Opens the dashboard in the browser |
| `mac-guard run` | Runs an audit now and prints the result |
| `mac-guard status` | One-line summary of the last audit |

An audit also runs every day at 13:00 (or at the next wake). If it finds something new, a notification appears.

## What an audit checks

- **Compromise signs**: remote-access and monitoring software, SSH `authorized_keys`, launch agents and daemons,
  login items, cron, unsigned running programs, duplicate MAC addresses on the network.
- **Hardening baseline** (CIS-style): firewall and stealth mode, FileVault, Gatekeeper, SIP, auto-updates,
  sharing services, guest/auto-login/root, screen lock, sudo, SSH key permissions, proxy, certificate trust.
- **Browsers**: every extension in every Chromium profile scored by its permissions, hijack indicators
  (search engine, homepage, startup pages, proxy), and sites allowed to send notifications or pop-ups.
- **What changed** since the previous audit in startup items, accounts, settings and extensions.

Every audit is read-only. It never fixes, removes or disables anything.

## Findings

Each finding has a lifecycle, stored in SQLite:

- **open**: needs a decision.
- **accepted**: you decided it is fine (with an optional note). It stops counting against the verdict.
- **resolved**: the audit no longer sees it. If it comes back, it reopens and is marked "came back".

## Layout

```
bin/mac-guard            the command
audit/check.sh           system audit; writes a text report and one TSV row per check
audit/browser_audit.py   browser audit
server/config.py         paths, port and constants
server/db.py             SQLite schema and the finding lifecycle
server/runner.py         runs an audit and loads the results
server/server.py         dashboard server (standard library only)
dashboard/               the page: index.html, app.js, style.css
launchd/                 templates for the two launchd jobs
install.sh               install / uninstall
```

Data lives outside the repo in `~/.mac-guard/`: `guard.db`, `reports/`, `snapshots/`, `token`, logs.

## How the dashboard is kept safe

- Listens on `127.0.0.1:47821` only.
- launchd holds the port and starts the server when the page is opened; the server exits after 15 idle minutes.
- Every API request needs the secret token from `~/.mac-guard/token`. `mac-guard` hands it to the page once,
  in the URL fragment, and the page keeps it in its own browser storage.
- Requests with any other `Host` header are refused, and state-changing requests must come from the page's own origin.
- The only thing the server can start is `server/runner.py` with fixed arguments.

## Install / uninstall

```
./install.sh             # data folder, launchd jobs, `mac-guard` command
./install.sh uninstall   # removes the jobs and the command, keeps the data
```

## Limits

- Without Full Disk Access for the terminal, macOS privacy grants (Screen Recording, Accessibility,
  Input Monitoring) and Safari data cannot be read.
- No sudo: other users' home folders and root-only logs are not inspected.
- An audit reports; it does not block. Blocking is the job of Santa, BlockBlock and LuLu.
