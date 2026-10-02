# mac-guard

A local security audit and dashboard for this Mac. Everything runs on the laptop; nothing is sent anywhere.

## Use it

| Command | What it does |
|---|---|
| `mac-guard` | Opens the dashboard in the browser |
| `mac-guard run` | Runs an audit now and prints the result |
| `mac-guard status` | One-line summary of the last audit |
| `mac-guard repo <git-url>` | Clones, scans and opens an untrusted repo in a container |

An audit also runs every day at 13:00 (or at the next wake). If it finds something new, a notification appears.

## What an audit checks

- **Compromise signs**: remote-access and monitoring software, SSH `authorized_keys`, launch agents and daemons,
  login items, cron, unsigned running programs, duplicate MAC addresses on the network.
- **Hardening baseline** (CIS-style): firewall and stealth mode, FileVault, Gatekeeper, SIP, auto-updates,
  sharing services, guest/auto-login/root, screen lock, sudo, SSH key permissions, proxy, certificate trust.
- **Browsers**: every extension in every Chromium profile scored by its permissions, hijack indicators
  (search engine, homepage, startup pages, proxy), and sites allowed to send notifications or pop-ups.
- **Secrets**: every `.env` file under `~/repos` and whether git tracks or ignores it, plus gitleaks over each
  repo's git history. Secret values are never printed or stored, only file names, rule names and counts.
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
audit/secrets_scan.py    .env inventory and gitleaks over git history
server/config.py         paths, port and constants
server/db.py             SQLite schema and the finding lifecycle
server/runner.py         runs an audit and loads the results
server/remediation.py    the "How to fix" steps shown for each finding
server/server.py         dashboard server (standard library only)
dashboard/               the page: index.html, app.js, style.css
untrusted/open-repo.sh   clone + scan + container shell for a repo you do not trust
untrusted/scan_repo.py   the static scan
launchd/                 templates for the two launchd jobs
install.sh               install / uninstall
```

Data lives outside the repo in `~/.mac-guard/`: `guard.db`, `reports/`, `snapshots/`, `token`, logs.

## How the dashboard is kept safe

- Listens on `127.0.0.1:47821` only.
- launchd holds the port and starts the server when the page is opened; the server exits after 15 idle minutes.
- Every API request needs the secret token from `~/.mac-guard/token`. `mac-guard` opens the page with a
  single-use, 60-second sign-in value; the page trades it for the token and keeps the token for that tab only.
  Open the dashboard with the `mac-guard` command; a bookmark alone will ask you to run it.
- `mac-guard` refuses to open the page if the port is held by another user account.
- Requests with any other `Host` header are refused, and state-changing requests must come from the page's own origin.
- The only thing the server can start is `server/runner.py` with fixed arguments.

## Install / uninstall

```
./install.sh             # data folder, launchd jobs, `mac-guard` command
./install.sh uninstall   # removes the jobs and the command, keeps the data
```

## Untrusted repos

For any project you did not write (a client's repo, a take-home test, something from GitHub):

```
mac-guard repo https://github.com/someone/project.git      # clone + scan + shell in a container
mac-guard repo ~/untrusted/project --port 3000             # reopen it, with the dev server on 127.0.0.1:3000
mac-guard repo ~/untrusted/project --no-network            # no network at all, once dependencies are installed
mac-guard repo <url> --scan-only                           # just the verdict
```

1. **Clone** into `~/untrusted/` with git hooks, submodules and LFS disabled, so nothing from the repo runs.
2. **Scan** without executing anything: install scripts that download or decode code, `.vscode/tasks.json` tasks
   set to run on folder open, a project `.npmrc` that re-enables scripts or changes the registry, dev-container
   host commands, obfuscated code, committed executables, symlinks out of the repo, and code that both reads
   credential locations and talks to the network. Verdict: nothing found / REVIEW / DANGEROUS.
3. **Container**: a shell as an unprivileged user that can see that one folder. No home folder, SSH keys, `.env`
   files, browser data or Docker socket; all capabilities dropped; `.git` is read-only so the code cannot plant
   git hooks. The container is deleted when you exit; the folder stays.

Limits to know:
- With the network on, code in the container can still reach the internet and services listening on this Mac
  (for example a local Postgres on 5432). Use `--no-network` whenever you can, and keep local services
  password-protected.
- The repo folder itself is writable, so the code can change its own files. Keep using `mac-guard repo`;
  do not open `~/untrusted/...` in an editor with Workspace Trust on, and do not run it on the Mac directly.
- The scan catches known tricks, not all malware. The container is the protection; the scan is a warning.

## Other protections set up by this repo

- `./install.sh tools`: gitleaks, LuLu (outbound firewall), BlockBlock (alerts on new startup items), KnockKnock
  (on-demand persistence scan) and Santa (binary authorization; starts in Monitor mode, which blocks nothing).
  Run it in Terminal: it asks for your password, and each tool then needs an approval in System Settings.
  The audit flags any of these that is not active.
- `./install.sh hygiene`: npm `ignore-scripts=true` and `min-release-age=7`, Safe Chain (blocks known-malicious
  packages for npm, pnpm, yarn, pip and others), and VS Code automatic tasks off.
  - For one trusted install that needs its build scripts: `npm install --ignore-scripts=false`
  - After a fresh clone that uses husky: `npm run prepare`

## Limits

- Without Full Disk Access for the terminal, macOS privacy grants (Screen Recording, Accessibility,
  Input Monitoring) and Safari data cannot be read.
- No sudo: other users' home folders and root-only logs are not inspected.
- An audit reports; it does not block. Blocking is the job of Santa, BlockBlock and LuLu.
