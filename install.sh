#!/bin/bash
# Sets up mac-guard for the current user. Safe to run again.
#   ./install.sh             create the data folder, load the two launchd jobs, link the `mac-guard` command
#   ./install.sh uninstall   remove the launchd jobs and the command (keeps ~/.mac-guard data)
set -euo pipefail
REPO="$(cd "$(dirname "$0")" && pwd)"
DATA="$HOME/.mac-guard"
AGENTS="$HOME/Library/LaunchAgents"
LABELS=(com.abdulhadi.mac-guard.audit com.abdulhadi.mac-guard.dashboard)
LINK=/opt/homebrew/bin/mac-guard
DOMAIN="gui/$(id -u)"

unload() { for l in "${LABELS[@]}"; do launchctl bootout "$DOMAIN/$l" 2>/dev/null || true; done; }

if [ "${1:-}" = "uninstall" ]; then
  unload
  for l in "${LABELS[@]}"; do rm -f "$AGENTS/$l.plist"; done
  [ -L "$LINK" ] && rm -f "$LINK"
  echo "mac-guard removed. Data kept in $DATA"
  exit 0
fi

mkdir -p "$DATA/reports" "$DATA/snapshots" "$AGENTS"
chmod 700 "$DATA"
PYTHONPATH="$REPO/server" PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -c "import db, server; db.init(); server.load_token()"
chmod -R go-rwx "$DATA"   # reports name accounts, keys and extensions: this user only

unload
for l in "${LABELS[@]}"; do
  sed -e "s|__REPO__|$REPO|g" -e "s|__DATA__|$DATA|g" "$REPO/launchd/$l.plist" > "$AGENTS/$l.plist"
  plutil -lint -s "$AGENTS/$l.plist"
  launchctl bootstrap "$DOMAIN" "$AGENTS/$l.plist"
done
ln -sf "$REPO/bin/mac-guard" "$LINK"

echo "Installed."
echo "  dashboard : mac-guard            (server starts on demand, exits when idle)"
echo "  audit now : mac-guard run"
echo "  schedule  : daily at 13:00, or at next wake if the Mac was asleep"
