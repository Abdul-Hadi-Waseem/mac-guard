#!/bin/bash
# Work on a repo you do not trust yet, without letting it touch this Mac.
#   mac-guard repo <git-url | folder under ~/untrusted> [options] [-- command to run in the container]
#     --scan-only       clone and scan, do not start a container
#     --no-network      container has no network at all (use after dependencies are installed)
#     --port N          publish container port N on 127.0.0.1:N (repeatable)
#
# 1. clone into ~/untrusted without hooks, submodules or LFS       (nothing from the repo runs)
# 2. static scan: install scripts, editor auto-run tasks, obfuscated code, committed binaries
# 3. shell in a container that can see that one folder and nothing else of yours
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
BASE="$HOME/untrusted"
SCAN_ONLY=0; NETWORK=(); PORTS=(); TARGET=""; CMD=()

while [ $# -gt 0 ]; do
  case "$1" in
    --scan-only)  SCAN_ONLY=1 ;;
    --no-network) NETWORK=(--network none) ;;
    --port)       shift; [[ "${1:-}" =~ ^[0-9]{2,5}$ ]] || { echo "--port needs a number" >&2; exit 64; }
                  PORTS+=(-p "127.0.0.1:$1:$1") ;;
    --)           shift; CMD=("$@"); break ;;
    -*)           echo "unknown option: $1" >&2; exit 64 ;;
    *)            [ -z "$TARGET" ] || { echo "only one repo at a time" >&2; exit 64; }; TARGET="$1" ;;
  esac
  shift
done
[ -n "$TARGET" ] || { sed -n '2,6p' "$0" | sed 's/^# \{0,1\}//'; exit 64; }

mkdir -p "$BASE"; chmod 700 "$BASE"
if [[ "$TARGET" =~ ^(https://|ssh://|git@) ]]; then
  NAME="$(basename "${TARGET%.git}" | tr -c 'A-Za-z0-9._-' '_')"
  DEST="$BASE/$NAME"
  if [ ! -d "$DEST" ]; then
    echo "== cloning into $DEST (hooks, submodules and LFS disabled)"
    GIT_LFS_SKIP_SMUDGE=1 git -c core.hooksPath=/dev/null -c protocol.file.allow=never \
      clone --no-recurse-submodules -- "$TARGET" "$DEST"
  else
    echo "== using existing $DEST"
  fi
else
  DEST="$(cd "$TARGET" 2>/dev/null && pwd -P)" || { echo "no such folder: $TARGET" >&2; exit 66; }
  case "$DEST/" in
    "$(cd "$BASE" && pwd -P)"/?*) ;;
    *) echo "refusing: only folders inside $BASE are opened in the container. Move it there first." >&2; exit 65 ;;
  esac
  NAME="$(basename "$DEST" | tr -c 'A-Za-z0-9._-' '_')"
fi

echo "== scanning (nothing from the repo is executed)"
set +e; /usr/bin/python3 "$HERE/scan_repo.py" "$DEST"; VERDICT=$?; set -e
[ "$SCAN_ONLY" = 1 ] && exit "$VERDICT"
if [ "$VERDICT" = 2 ]; then
  [ -t 0 ] || { echo "dangerous repo and no terminal to confirm on: stopping" >&2; exit 2; }
  read -r -p "The scan says DANGEROUS. Open it in the container anyway? Type yes: " answer
  [ "$answer" = "yes" ] || exit 2
fi

docker info >/dev/null 2>&1 || { echo "Docker is not running. Start Docker Desktop, then run this again." >&2; exit 69; }
if   [ -f "$DEST/package.json" ]; then IMAGE=node:24-bookworm
elif [ -f "$DEST/requirements.txt" ] || [ -f "$DEST/pyproject.toml" ] || [ -f "$DEST/setup.py" ]; then IMAGE=python:3.13-bookworm
else IMAGE=debian:bookworm-slim; fi

TTY=(-i); [ -t 0 ] && [ -t 1 ] && TTY=(-it)
[ ${#CMD[@]} -gt 0 ] || CMD=(bash)
GITDIR=(); [ -d "$DEST/.git" ] && GITDIR=(-v "$DEST/.git:/work/.git:ro")   # the repo cannot plant git hooks or config

echo "== container: $IMAGE   sees only: $DEST   network: ${NETWORK[*]:-on}   ports: ${PORTS[*]:-none}"
echo "   inside: you are user 1000 in /work. Type exit to leave; the container is deleted, the folder stays."
set +e
docker run --rm "${TTY[@]}" --name "mg-$NAME-$$" --hostname sandbox \
  --cap-drop ALL --security-opt no-new-privileges --pids-limit 1024 --memory 6g \
  --user 1000:1000 -e HOME=/home/sandbox --tmpfs /home/sandbox:rw,exec,uid=1000,gid=1000,size=4g \
  -v "$DEST:/work" ${GITDIR[@]+"${GITDIR[@]}"} -w /work \
  ${NETWORK[@]+"${NETWORK[@]}"} ${PORTS[@]+"${PORTS[@]}"} \
  "$IMAGE" "${CMD[@]}"
STATUS=$?; set -e

echo "== left the container. Scanning again, in case the code changed its own files:"
set +e; /usr/bin/python3 "$HERE/scan_repo.py" "$DEST" | tail -1; set -e
echo "   Keep working on it through this command. Do not open $DEST with a trusted editor or run it on the Mac itself."
exit "$STATUS"
