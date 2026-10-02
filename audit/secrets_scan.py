#!/usr/bin/python3
"""Read-only secrets sweep. Never prints a secret value: only file names, rule names and counts.

1. .env inventory: every .env-style file under the scan roots, and whether git tracks it, ignores it,
   or would pick it up on the next `git add .`.
2. Committed secrets: gitleaks over each repo's git history (redacted). Results are cached per repo
   and re-used until that repo's HEAD changes, so a daily audit stays fast.

When MG_FINDINGS is set, problems are appended to that file as TSV rows (same format as check.sh)."""
import json
import os
import re
import subprocess
import sys
import tempfile

HOME = os.path.expanduser("~")
SCAN_ROOTS = [os.path.join(HOME, "repos"), os.path.join(HOME, "mac-guard")]
MAX_DEPTH = 7
SKIP_DIRS = {"node_modules", ".git", "Pods", "build", "dist", ".next", ".turbo", "vendor", ".venv", "venv", "__pycache__"}
EXAMPLE_MARKERS = ("example", "sample", "template", "dist", "defaults")
GITLEAKS = "/opt/homebrew/bin/gitleaks"
GITLEAKS_TIMEOUT_SECONDS = 180
CACHE_PATH = os.path.join(os.environ.get("MG_DATA", os.path.join(HOME, ".mac-guard")), "secrets-cache.json")
# rules that fire on almost anything long and random; a repo with only these is usually mock data or public keys
WEAK_RULES = {"generic-api-key", "curl-auth-header", "jwt", "linkedin-client-id"}
ENV_NAME = re.compile(r"^(\.env(\..+)?|.+\.env)$")
ASSIGNMENT = re.compile(r"^\s*(export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=\s*\S")


def finding(severity, key, title, detail=""):
    path = os.environ.get("MG_FINDINGS")
    if not path:
        return
    row = [severity, "secrets", key, title, detail]
    with open(path, "a", encoding="utf-8") as f:
        f.write("\t".join(re.sub(r"[\x00-\x1f\x7f]", " ", str(c)) for c in row) + "\n")


def short(path):
    return path.replace(HOME, "~", 1)


def git(repo, *args):
    return subprocess.run(["/usr/bin/git", "-C", repo, *args], capture_output=True, text=True)


def walk():
    """Yield (env_files, repos) found under the scan roots."""
    env_files, repos = [], []
    for root in SCAN_ROOTS:
        base_depth = root.rstrip("/").count("/")
        for current, dirs, files in os.walk(root):
            if ".git" in dirs or os.path.isfile(os.path.join(current, ".git")):
                repos.append(current)
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS] if current.count("/") - base_depth < MAX_DEPTH else []
            env_files += [os.path.join(current, f) for f in files if ENV_NAME.match(f)]
    return sorted(env_files), sorted(repos)


def repo_of(path, repos):
    owners = [r for r in repos if path.startswith(r + "/")]
    return max(owners, key=len) if owners else None


def audit_env_files(env_files, repos):
    print(f"\n--- .env inventory: {len(env_files)} file(s)")
    loose = []
    for path in env_files:
        is_example = any(m in os.path.basename(path).lower() for m in EXAMPLE_MARKERS)
        try:
            with open(path, encoding="utf-8", errors="ignore") as f:
                values = sum(1 for line in f if ASSIGNMENT.match(line))
            mode = os.stat(path).st_mode & 0o777
        except OSError:
            continue
        repo = repo_of(path, repos)
        state = "no repo"
        if repo:
            rel = os.path.relpath(path, repo)
            if git(repo, "ls-files", "--error-unmatch", rel).returncode == 0:
                state = "TRACKED"
            elif git(repo, "check-ignore", "-q", rel).returncode == 0:
                state = "ignored"
            else:
                state = "UNIGNORED"
        print(f"  {state:<9} {oct(mode)[2:]} {values:>3} value(s)  {short(path)}{'  (example)' if is_example else ''}")
        if is_example or not values:
            continue
        if state == "TRACKED":
            finding("high", f"env-tracked:{path}", "A .env file with values is committed to git",
                    f"{short(path)} ({values} values). Anyone with the repo has these; rotate them and remove the file from git.")
        elif state == "UNIGNORED":
            finding("medium", f"env-unignored:{path}", "A .env file is not in .gitignore",
                    f"{short(path)} ({values} values). The next `git add .` would commit it.")
        if mode & 0o077:
            loose.append(path)
    if loose:
        finding("low", "env-permissions", f"{len(loose)} .env file(s) are readable by other accounts on this Mac",
                "e.g. " + ", ".join(short(p) for p in loose[:3]))


def load_cache():
    try:
        with open(CACHE_PATH) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def scan_repo(repo):
    """Returns a list of {rule, file} for one repo's history, or None when the scan could not run."""
    fd, report = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    try:
        subprocess.run([GITLEAKS, "git", "--redact", "--no-banner", "--exit-code", "0", "--report-format", "json",
                        "--report-path", report, repo], capture_output=True, timeout=GITLEAKS_TIMEOUT_SECONDS)
        with open(report) as f:
            leaks = json.load(f) or []
    except (subprocess.TimeoutExpired, OSError, ValueError):
        return None
    finally:
        os.unlink(report)
    return [{"rule": leak.get("RuleID", "?"), "file": leak.get("File", "?")} for leak in leaks]


def audit_git_history(repos):
    print(f"\n--- committed secrets (gitleaks, git history): {len(repos)} repo(s)")
    if not os.access(GITLEAKS, os.X_OK):
        print("  gitleaks is not installed: brew install gitleaks")
        finding("info", "gitleaks-missing", "gitleaks is not installed, git history was not scanned")
        return
    cache, fresh = load_cache(), {}
    for repo in repos:
        head = git(repo, "rev-parse", "HEAD").stdout.strip()
        if not head:
            continue
        cached = cache.get(repo)
        leaks = cached["leaks"] if cached and cached.get("head") == head else scan_repo(repo)
        if leaks is None:
            print(f"  TIMEOUT   {short(repo)}")
            finding("info", f"gitleaks-timeout:{repo}", "Secret scan timed out for a repo", short(repo))
            continue
        fresh[repo] = {"head": head, "leaks": leaks}
        if not leaks:
            continue
        by_place = {}
        for leak in leaks:
            by_place[(leak["rule"], leak["file"])] = by_place.get((leak["rule"], leak["file"]), 0) + 1
        # provider-specific rules (tokens, private keys) first: those are rarely false positives
        top = sorted(by_place.items(), key=lambda kv: (kv[0][0] in WEAK_RULES, -kv[1], kv[0]))
        strong = sum(n for (rule, _), n in by_place.items() if rule not in WEAK_RULES)
        print(f"  {len(leaks):>4} hit(s), {strong} provider-specific  {short(repo)}")
        for (rule, file), n in top[:8]:
            print(f"            {n:>3} x {rule}  in  {file}")
        title = (f"{strong} provider token(s) or private key(s) in git history: {os.path.basename(repo)}" if strong
                 else f"{len(leaks)} generic secret-like string(s) in git history: {os.path.basename(repo)}")
        finding("high" if strong else "low", f"git-secrets:{repo}", title,
                f"{short(repo)}; " + "; ".join(f"{n} x {rule} in {file}" for (rule, file), n in top[:4])
                + ". Check each; rotate real ones (deleting the file does not remove it from history).")
    fd = os.open(CACHE_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(fresh, f)


if __name__ == "__main__":
    env_files, repos = walk()
    audit_env_files(env_files, repos)
    audit_git_history(repos)
    sys.exit(0)
