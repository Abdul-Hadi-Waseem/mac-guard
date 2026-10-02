#!/bin/bash
# Sets up mac-guard for the current user. Safe to run again.
#   ./install.sh             create the data folder, load the two launchd jobs, link the `mac-guard` command
#   ./install.sh tools       install LuLu, KnockKnock and BlockBlock (BlockBlock asks for your password)
#   ./install.sh hygiene     npm/VS Code settings and Safe Chain, so untrusted packages cannot run code on install
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

if [ "${1:-}" = "tools" ]; then
  HOMEBREW_NO_AUTO_UPDATE=1 brew install --cask lulu knockknock blockblock
  echo "Now open LuLu once and approve its network extension, and give BlockBlock Full Disk Access when asked."
  exit 0
fi

if [ "${1:-}" = "hygiene" ]; then
  SAFE_CHAIN_VERSION=1.5.24
  SAFE_CHAIN_SHA256=99eb124a3404b3ac99e8b65406b87c4ee049c1d6c17757a7d04991ae60d16e69   # of install-safe-chain.sh
  touch ~/.npmrc ~/.zshrc
  grep -qE "^ignore-scripts" ~/.npmrc  || echo "ignore-scripts=true" >> ~/.npmrc
  grep -qE "^min-release-age" ~/.npmrc || echo "min-release-age=7" >> ~/.npmrc
  # the environment variable outranks a project's own .npmrc, so a cloned repo cannot switch scripts back on
  grep -q "NPM_CONFIG_IGNORE_SCRIPTS" ~/.zshrc || echo "export NPM_CONFIG_IGNORE_SCRIPTS=true" >> ~/.zshrc
  if [ ! -x ~/.safe-chain/bin/safe-chain ]; then
    tmp=$(mktemp)
    curl -fsSL "https://github.com/AikidoSec/safe-chain/releases/download/$SAFE_CHAIN_VERSION/install-safe-chain.sh" -o "$tmp"
    echo "$SAFE_CHAIN_SHA256  $tmp" | shasum -a 256 -c -
    sh "$tmp"; rm -f "$tmp"
  fi
  VS="$HOME/Library/Application Support/Code/User/settings.json"
  if [ -f "$VS" ] && ! grep -q '"task.allowAutomaticTasks"' "$VS"; then
    cp "$VS" "$VS.bak-$(date +%Y-%m-%d)"
    /usr/bin/python3 - "$VS" <<'PY2'
import sys
path = sys.argv[1]
text = open(path).read()
end = text.rstrip().rfind("}")
head = text[:end].rstrip()
if not head.endswith((",", "{")):
    head += ","
open(path, "w").write(head + '\n  "task.allowAutomaticTasks": "off",\n  "security.workspace.trust.enabled": true,\n' + text[end:])
PY2
  fi
  echo "Hygiene applied. Open a new terminal for it to take effect."
  echo "To allow install scripts for one trusted install: npm install --ignore-scripts=false"
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
