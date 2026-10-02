#!/usr/bin/python3
"""Static pre-scan of a repo you do not trust yet. Reads files only; never runs anything from the repo.

Looks for the ways a repo gets code to run on your machine without you asking:
install-time scripts, editor auto-run tasks, config that re-enables scripts, obfuscated code,
and committed executables. Exit code: 0 nothing found, 1 worth a look, 2 dangerous.
"""
import json
import os
import re
import sys

MAX_FILE_BYTES = 2 * 1024 * 1024
SKIP_DIRS = {".git", "node_modules", "Pods", "vendor", ".venv", "venv", "dist", "build", ".next", "__pycache__"}
CODE_EXTENSIONS = (".js", ".cjs", ".mjs", ".ts", ".tsx", ".jsx", ".py", ".sh", ".rb", ".php")
LIFECYCLE_SCRIPTS = ("preinstall", "install", "postinstall", "prepare", "prepublish", "preprepare", "postprepare")
LONG_LINE = 5000


class Level:
    DANGER = "DANGER"
    WARN = "WARN"
    NOTE = "NOTE"
    ORDER = {DANGER: 0, WARN: 1, NOTE: 2}


# what a script would have to do to pull in and run outside code
FETCH_AND_RUN = re.compile(
    r"curl\s|wget\s|Invoke-WebRequest|iwr\s|\bnc\s|/dev/tcp/|base64\s+(-d|--decode)|\beval\b|node\s+-e|python3?\s+-c|"
    r"bash\s+-c|sh\s+-c|\|\s*(ba)?sh\b|powershell|osascript", re.I)
OBFUSCATION = (
    (re.compile(r"\b_0x[0-9a-f]{4,}\b"), "obfuscator-style identifiers (_0x…)"),
    (re.compile(r"eval\s*\(\s*(atob|Buffer\.from|unescape|decodeURIComponent)\s*\("), "eval of decoded data"),
    (re.compile(r"new\s+Function\s*\(\s*(atob|Buffer\.from|unescape)\s*\("), "Function built from decoded data"),
    (re.compile(r"(\\x[0-9a-f]{2}){24,}", re.I), "long hex-escaped string"),
    (re.compile(r"exec\s*\(\s*(base64\.b64decode|bytes\.fromhex|zlib\.decompress|marshal\.loads)"), "Python exec of decoded data"),
    (re.compile(r"__import__\s*\(\s*['\"]base64['\"]\s*\)"), "hidden base64 import"),
)
# reads the places credentials live, in code that also talks to the network
CREDENTIAL_PATHS = re.compile(
    r"\.ssh/|id_rsa|id_ed25519|\.aws/credentials|\.npmrc|Login Data|Cookies|keychain|\.config/gcloud|wallet\.dat|"
    r"Local Extension Settings|\.gnupg|\.docker/config\.json", re.I)
NETWORK = re.compile(r"https?://|fetch\(|axios|http\.request|requests\.(get|post)|urllib|net\.connect|WebSocket|child_process", re.I)
MACHO_MAGIC = (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe", b"\x7fELF", b"MZ\x90\x00")

results = []


def report(level, where, message):
    results.append((level, where, message))


def read(path):
    try:
        if os.path.getsize(path) > MAX_FILE_BYTES:
            return None
        with open(path, encoding="utf-8", errors="ignore") as f:
            return f.read()
    except OSError:
        return None


def strip_json_comments(text):
    """Remove // and /* */ comments that sit outside strings (editor config files allow them)."""
    out, i, in_string = [], 0, False
    while i < len(text):
        ch, nxt = text[i], text[i + 1:i + 2]
        if in_string:
            out.append(ch)
            if ch == "\\" and nxt:
                out.append(nxt)
                i += 1
            elif ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
            out.append(ch)
        elif ch == "/" and nxt == "/":
            i = text.find("\n", i)
            if i == -1:
                break
            continue
        elif ch == "/" and nxt == "*":
            end = text.find("*/", i + 2)
            i = len(text) if end == -1 else end + 2
            continue
        else:
            out.append(ch)
        i += 1
    return "".join(out)


def load_json(path):
    text = read(path)
    if text is None:
        return None
    try:
        return json.loads(re.sub(r",(\s*[}\]])", r"\1", strip_json_comments(text)))
    except ValueError:
        return None


def check_package_json(path, rel):
    data = load_json(path)
    if not isinstance(data, dict):
        return
    for name, command in (data.get("scripts") or {}).items():
        if name not in LIFECYCLE_SCRIPTS or not isinstance(command, str):
            continue
        if FETCH_AND_RUN.search(command):
            report(Level.DANGER, rel, f"'{name}' script downloads or decodes and runs code: {command[:160]}")
        elif not re.fullmatch(r"\s*(husky( install)?|patch-package|node \.husky/install\.mjs|ngcc.*|is-ci \|\| husky.*)\s*", command):
            report(Level.WARN, rel, f"'{name}' script runs automatically on install: {command[:160]}")
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        for dep, spec in (data.get(section) or {}).items():
            if isinstance(spec, str) and re.match(r"(git\+|https?://|github:|file:)", spec):
                report(Level.WARN, rel, f"dependency '{dep}' is installed from a URL, not the registry: {spec[:120]}")


def check_vscode(path, rel):
    data = load_json(path)
    if not isinstance(data, dict):
        # unreadable on purpose is a tactic too: fall back to the raw text
        if "folderOpen" in (read(path) or ""):
            report(Level.DANGER, rel, "contains a task set to run when the folder is opened (file could not be parsed)")
        else:
            report(Level.WARN, rel, "could not parse this editor config; read it by hand before trusting the folder")
        return
    for task in data.get("tasks") or []:
        if isinstance(task, dict) and (task.get("runOptions") or {}).get("runOn") == "folderOpen":
            report(Level.DANGER, rel, f"task '{task.get('label', '?')}' runs by itself when the folder is opened: "
                                      f"{str(task.get('command', ''))[:160]}")


def check_devcontainer(path, rel):
    data = load_json(path)
    if not isinstance(data, dict):
        return
    for hook in ("initializeCommand", "onCreateCommand", "postCreateCommand", "postStartCommand", "postAttachCommand"):
        if hook in data:
            level = Level.DANGER if hook == "initializeCommand" else Level.WARN  # initializeCommand runs on the host
            report(level, rel, f"{hook}: {str(data[hook])[:160]}")


def check_npmrc(path, rel):
    text = read(path) or ""
    if re.search(r"^\s*ignore-scripts\s*=\s*false", text, re.M):
        report(Level.DANGER, rel, "re-enables install scripts (ignore-scripts=false)")
    for registry in re.findall(r"^\s*(?:@[\w-]+:)?registry\s*=\s*(\S+)", text, re.M):
        if "registry.npmjs.org" not in registry:
            report(Level.WARN, rel, f"packages come from a non-default registry: {registry[:120]}")


def check_code(path, rel):
    text = read(path)
    if text is None:
        return
    for pattern, label in OBFUSCATION:
        if pattern.search(text):
            report(Level.DANGER, rel, label)
            break
    longest = max((len(line) for line in text.splitlines()), default=0)
    if longest > LONG_LINE and not rel.endswith((".min.js", ".map")):
        report(Level.WARN, rel, f"a single line of {longest} characters (minified or packed code in source)")
    if CREDENTIAL_PATHS.search(text) and NETWORK.search(text):
        report(Level.WARN, rel, "mentions credential locations (SSH keys, browser data, cloud config) and uses the network")


def check_binary(path, rel):
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
    except OSError:
        return
    if magic in MACHO_MAGIC:
        report(Level.WARN, rel, "compiled executable committed to the repo")


def scan(root):
    for current, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in files:
            path = os.path.join(current, name)
            rel = os.path.relpath(path, root)
            if os.path.islink(path):
                target = os.path.realpath(path)
                if not target.startswith(os.path.realpath(root) + os.sep):
                    report(Level.WARN, rel, f"symlink pointing outside the repo: {os.readlink(path)[:120]}")
                continue
            if name == "package.json":
                check_package_json(path, rel)
            elif rel in (".vscode/tasks.json",):
                check_vscode(path, rel)
            elif name == "devcontainer.json":
                check_devcontainer(path, rel)
            elif name == ".npmrc":
                check_npmrc(path, rel)
            elif name in ("setup.py", "Makefile", "Rakefile", "build.gradle", "Podfile"):
                report(Level.NOTE, rel, "build file that runs code when you build or install")
            if name.endswith(CODE_EXTENSIONS):
                check_code(path, rel)
            else:
                check_binary(path, rel)
    for hook_dir in (".husky", ".githooks"):
        if os.path.isdir(os.path.join(root, hook_dir)):
            report(Level.NOTE, hook_dir, "git hook scripts that run on commit once installed")


def main():
    if len(sys.argv) != 2 or not os.path.isdir(sys.argv[1]):
        sys.exit("usage: scan_repo.py <repo folder>")
    scan(sys.argv[1])
    results.sort(key=lambda r: (Level.ORDER[r[0]], r[1]))
    for level, where, message in results:
        print(f"{level:<6} {where}\n       {message}")
    worst = results[0][0] if results else None
    print()
    if worst == Level.DANGER:
        print("VERDICT: DANGEROUS. This repo is set up to run code by itself. Do not open it outside the container.")
        return 2
    if worst == Level.WARN:
        print("VERDICT: REVIEW. Read the lines above before running anything; keep it in the container.")
        return 1
    print("VERDICT: nothing suspicious found. That is not proof of safety: still run it in the container first.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
