#!/bin/bash
# Read-only macOS compromise check. Writes a full text report, a "stable" snapshot that is
# diffed against the previous run, and (when MG_FINDINGS is set) one TSV row per check result:
#   severity <TAB> category <TAB> key <TAB> title <TAB> detail      severity: high|medium|low|info|pass
OUT="${MG_DATA:-$HOME/.mac-guard}"; mkdir -p "$OUT/reports" "$OUT/snapshots"
TS="${MG_TS:-$(date +%Y-%m-%d_%H%M%S)}"; REPORT="$OUT/reports/$TS.txt"; SNAP="$OUT/snapshots/$TS.txt"; CHANGES="$OUT/reports/$TS.changes"
HERE="$(cd "$(dirname "$0")" && pwd)"
umask 077
# every control character becomes a space, so a value can never break out of its TSV field or row
clean() { printf '%s' "$1" | tr '\000-\037\177' ' '; }
finding() { [ -n "$MG_FINDINGS" ] && printf '%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$(clean "$3")" "$(clean "$4")" "$(clean "$5")" >> "$MG_FINDINGS"; return 0; }
PREV=$(ls -1 "$OUT/snapshots"/*.txt 2>/dev/null | tail -1)
CHROME="$HOME/Library/Application Support/Google/Chrome"
sec() { printf '\n##### %s\n' "$1"; }

stable() {
  sec "USERS (uid>=500)";            dscl . list /Users UniqueID | awk '$2>=500'
  sec "ADMINS";                      dscl . -read /Groups/admin GroupMembership
  sec "POSTURE";                     csrutil status; spctl --status; fdesetup status
                                     /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate --getstealthmode
  sec "MDM / PROFILES";              profiles status -type enrollment 2>&1; profiles list 2>&1
  sec "LAUNCH AGENTS / DAEMONS";     ls -1 ~/Library/LaunchAgents /Library/LaunchAgents /Library/LaunchDaemons /Library/PrivilegedHelperTools 2>&1
  sec "LAUNCH ITEM TARGETS";         for f in ~/Library/LaunchAgents/*.plist /Library/LaunchAgents/*.plist /Library/LaunchDaemons/*.plist; do
                                       [ -f "$f" ] && echo "$f -> $(plutil -extract ProgramArguments.0 raw "$f" 2>/dev/null || plutil -extract Program raw "$f" 2>/dev/null)"; done
  # (sfltool dumpbtm would list more, but it asks for an admin password on every run; an audit must
  #  never get you used to typing your password into a dialog. BlockBlock covers new items live.)
  sec "LOADED BACKGROUND JOBS (non-Apple)"; launchctl list | awk 'NR>1{print $3}' | grep -vE "^(com\.apple\.|application\.)" | sort -u
  sec "CRON";                        crontab -l 2>&1
  sec "SYSTEM EXTENSIONS";           systemextensionsctl list 2>&1; kmutil showloaded 2>/dev/null | grep -v com.apple
  sec "SSH";                         ls -1 ~/.ssh 2>&1; echo "authorized_keys:"; cat ~/.ssh/authorized_keys 2>&1
                                     [ -s ~/.ssh/authorized_keys ] && finding high remote-access "ssh:authorized_keys" "SSH authorized_keys is not empty" "$(grep -c . ~/.ssh/authorized_keys) key(s) can log in to this Mac over SSH"
                                     grep -nE "ProxyCommand|RemoteForward|LocalForward|ProxyJump" ~/.ssh/config 2>/dev/null
  sec "SHELL RC SUSPICIOUS LINES"
  grep -nE "curl|wget|nc |base64|eval|osascript|python3? -c|bash -i|/dev/tcp" ~/.zshrc ~/.zprofile ~/.zshenv ~/.bash_profile ~/.bashrc ~/.profile 2>/dev/null | grep -v "brew shellenv" | while IFS= read -r l; do
    echo "$l"; finding low persistence "shellrc:$l" "Shell startup file runs a download/eval command" "$l"; done
  sec "/etc/hosts";                  grep -vE '^#|^$' /etc/hosts
  sec "DNS / PROXY";                 scutil --dns | grep nameserver | sort -u; scutil --proxy
  sec "FIREWALL APP RULES";          /usr/libexec/ApplicationFirewall/socketfilterfw --listapps 2>&1 | grep -v "^Total" | paste -d' ' - - | sed -E 's/^[0-9]+ : //; s/ +/ /g' | grep -v code_sign_clone | sort
  sec "APPLICATIONS";                ls -1 /Applications ~/Applications 2>/dev/null
  sec "LISTENING TCP (non-loopback)"; lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | awk 'NR>1 && $9 !~ /^127\.|^\[::1\]/ {sub(/:[0-9]+$/,":<port>",$9); print $1,$9}' | sort -u
  sec "CHROME NATIVE MESSAGING HOSTS"; ls -1 "$CHROME/NativeMessagingHosts" /Library/Google/Chrome/NativeMessagingHosts 2>&1
  sec "CHROME POLICIES";             ls -1 "/Library/Managed Preferences" 2>&1
  sec "BROWSER AUDIT (extensions risk-scored, hijack indicators, site permissions)"
  /usr/bin/python3 "$HERE/browser_audit.py" 2>&1
}

# CIS-benchmark style baseline. Each line: PASS / WARN / INFO (INFO = could not determine without sudo/FDA).
chk() {
  printf '%-5s %s%s\n' "$1" "$2" "${3:+  [$3]}"
  case "$1" in PASS) sev=pass;; WARN) sev=medium;; *) sev=info;; esac
  finding "$sev" hardening "hardening:$2" "$2" "$3"
}
hardening() {
  sec "HARDENING BASELINE (CIS-style)"
  FW=/usr/libexec/ApplicationFirewall/socketfilterfw
  $FW --getglobalstate | grep -q "enabled"            && chk PASS "Firewall on" || chk WARN "Firewall OFF"
  $FW --getstealthmode | grep -q "is on"              && chk PASS "Firewall stealth mode on" || chk WARN "Firewall stealth mode OFF"
  $FW --getblockall 2>&1 | grep -qi "disabled"        && chk INFO "Firewall 'block all incoming' is off (normal for dev machines)" || chk PASS "Firewall blocks all incoming"
  n=$($FW --listapps 2>/dev/null | grep -B1 "Allow incoming" | grep -cE "/usr/bin/(python3|ruby|perl|nc)|/bin/(ba|z)?sh")
  [ "$n" -eq 0 ] && chk PASS "No generic interpreters allowed through firewall" || chk WARN "Generic interpreters allowed incoming through firewall" "$n: python3/ruby/etc - any script can accept connections"
  csrutil status | grep -q enabled                    && chk PASS "System Integrity Protection on" || chk WARN "SIP OFF"
  spctl --status | grep -q "assessments enabled"      && chk PASS "Gatekeeper on" || chk WARN "Gatekeeper OFF"
  fdesetup status | grep -q "FileVault is On"         && chk PASS "FileVault on" || chk WARN "FileVault OFF"
  csrutil authenticated-root status 2>/dev/null | grep -q enabled && chk PASS "Signed system volume on" || chk INFO "Signed system volume status unknown"
  su=/Library/Preferences/com.apple.SoftwareUpdate
  for k in AutomaticCheckEnabled AutomaticDownload AutomaticallyInstallMacOSUpdates CriticalUpdateInstall ConfigDataInstall; do
    v=$(defaults read $su $k 2>/dev/null); case "$v" in 1) chk PASS "SoftwareUpdate $k";; 0) chk WARN "SoftwareUpdate $k is OFF";; *) chk INFO "SoftwareUpdate $k not set (macOS default applies)";; esac; done
  upd=$(defaults read $su LastFullSuccessfulDate 2>/dev/null); chk INFO "macOS $(sw_vers -productVersion) ($(sw_vers -buildVersion)); last update check: ${upd:-unknown}"
  xv=$(xprotect version 2>/dev/null | head -1); chk INFO "XProtect malware definitions: ${xv:-unknown} (stale if >45 days old)"
  for port in 22:"Remote Login (SSH)" 5900:"Screen Sharing/Remote Management" 445:"File Sharing (SMB)" 3283:"Apple Remote Desktop" 3031:"Remote Apple Events" 631:"Printer Sharing"; do
    pn=${port%%:*}; nm=${port#*:}; lsof -nP -iTCP:$pn -sTCP:LISTEN 2>/dev/null | awk 'NR>1 && $9 !~ /^127\.|^\[::1\]|^localhost/' | grep -q . && chk WARN "$nm is ON" "port $pn listening" || chk PASS "$nm off"; done
  lsof -nP -iTCP:5000 -iTCP:7000 -sTCP:LISTEN 2>/dev/null | grep -q ControlCe && chk WARN "AirPlay Receiver is ON" "ports 5000/7000; turn off in System Settings > General > AirDrop & Handoff unless used" || chk PASS "AirPlay Receiver off"
  [ "$(defaults read /Library/Preferences/SystemConfiguration/com.apple.nat NAT 2>/dev/null | grep -c 'Enabled = 1')" -gt 0 ] && chk WARN "Internet Sharing is ON" || chk PASS "Internet Sharing off"
  [ "$(defaults -currentHost read com.apple.Bluetooth PrefKeyServicesEnabled 2>/dev/null)" = "1" ] && chk WARN "Bluetooth Sharing is ON" || chk PASS "Bluetooth Sharing off"
  ad=$(defaults read com.apple.sharingd DiscoverableMode 2>/dev/null); case "$ad" in Everyone) chk WARN "AirDrop open to Everyone";; "") chk INFO "AirDrop mode not set";; *) chk PASS "AirDrop: $ad";; esac
  [ "$(defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled 2>/dev/null)" = "1" ] && chk WARN "Guest account ENABLED" || chk PASS "Guest account off"
  al=$(defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null); [ -n "$al" ] && chk WARN "Automatic login ENABLED" "$al" || chk PASS "Automatic login off"
  [ "$(dscl . -read /Users/root Password 2>/dev/null | awk '{print $2}')" = "*" ] && chk PASS "root account disabled" || chk WARN "root account is ENABLED"
  na=$(dscl . -read /Groups/admin GroupMembership | tr ' ' '\n' | grep -vcE "GroupMembership:|^root$|^_"); [ "$na" -le 1 ] && chk PASS "Single admin account" || chk WARN "More than one admin account" "$na:$(dscl . -read /Groups/admin GroupMembership | cut -d: -f2)"
  sp=$(sysadminctl -screenLock status 2>&1 | sed 's/.*\] //'); sd=$(echo "$sp" | grep -oE "[0-9]+ seconds" | grep -oE "[0-9]+")
  if echo "$sp" | grep -qi immediate || { [ -n "$sd" ] && [ "$sd" -le 5 ]; }; then chk PASS "Password required immediately after sleep/screensaver"; else chk WARN "Password not required immediately after sleep/screensaver" "$sp"; fi
  it=$(defaults -currentHost read com.apple.screensaver idleTime 2>/dev/null); ds=$(pmset -g | awk '/ displaysleep/{print $2}')
  { [ -n "$it" ] && [ "$it" -gt 0 ] && [ "$it" -le 1200 ]; } || { [ -n "$ds" ] && [ "$ds" -gt 0 ] && [ "$ds" -le 20 ]; } && chk PASS "Screen locks when idle" "screensaver idle ${it:-unset}, display sleep ${ds:-?}min" || chk WARN "Screen does not lock within 20 min idle" "screensaver idle ${it:-unset}, display sleep ${ds:-?}min"
  grep -qE "^auth.*pam_tid" /etc/pam.d/sudo_local /etc/pam.d/sudo 2>/dev/null && chk INFO "Touch ID for sudo enabled" || chk INFO "Touch ID for sudo not enabled"
  sudo -n true 2>/dev/null && chk WARN "Passwordless sudo is available" || chk PASS "sudo requires a password"
  hp=$(stat -f %Lp "$HOME"); case "$hp" in 700|750|710) chk PASS "Home folder not world-readable" "$hp";; *) chk WARN "Home folder permissions are $hp (others can list it)";; esac
  for f in ~/.ssh/id_*; do case "$f" in *.pub) ;; *) [ -f "$f" ] && { [ "$(stat -f %Lp "$f")" = "600" ] && chk PASS "SSH key perms 600: $(basename "$f")" || chk WARN "SSH private key too open: $f"; grep -q ENCRYPTED "$f" 2>/dev/null || ssh-keygen -y -P "" -f "$f" >/dev/null 2>&1 && chk INFO "SSH key has NO passphrase: $(basename "$f")"; };; esac; done
  [ "$(defaults read com.apple.Safari AutoOpenSafeDownloads 2>/dev/null)" = "1" ] && chk WARN "Safari auto-opens 'safe' downloads" || chk PASS "Safari does not auto-open downloads"
  [ "$(defaults read NSGlobalDomain AppleShowAllExtensions 2>/dev/null)" = "1" ] && chk PASS "Finder shows all file extensions" || chk INFO "Finder hides file extensions (makes disguised apps harder to spot)"
  profiles status -type enrollment 2>&1 | grep -q "MDM enrollment: Yes" && chk WARN "Device is MDM-enrolled (an organisation can manage/monitor it)" || chk PASS "Not MDM-enrolled"
  [ -n "$(scutil --proxy | grep -E 'HTTPEnable : 1|HTTPSEnable : 1|ProxyAutoConfigEnable : 1|SOCKSEnable : 1')" ] && chk WARN "A system proxy is configured" || chk PASS "No system proxy"
  nr=$(security find-certificate -a /Library/Keychains/System.keychain 2>/dev/null | grep -c '"labl"'); chk INFO "$nr certificates in System keychain (user-added roots can intercept HTTPS; listed below)"
  security find-certificate -a /Library/Keychains/System.keychain 2>/dev/null | awk -F'"' '/"labl"/{print "        - "$4}'
  # always-on protection tools (installed by `install.sh tools`)
  sx=$(systemextensionsctl list 2>/dev/null)
  echo "$sx" | grep -i "lulu" | grep -q "activated enabled" && chk PASS "LuLu outbound firewall active" || chk WARN "LuLu outbound firewall is not active" "$([ -d /Applications/LuLu.app ] && echo 'installed but its network extension is not approved' || echo 'not installed')"
  { [ -e /Library/LaunchDaemons/com.objective-see.blockblock.plist ] || pgrep -qif blockblock; } && chk PASS "BlockBlock persistence monitor installed" || chk WARN "BlockBlock persistence monitor is not installed" "nothing alerts you when a new startup item is added"
  echo "$sx" | grep -i "santa" | grep -q "activated enabled" && chk PASS "Santa binary authorization active" || chk WARN "Santa binary authorization is not active" "$([ -d /Applications/Santa.app ] && echo 'installed but its system extension is not approved' || echo 'not installed')"
  # developer supply-chain settings (set by `install.sh hygiene`)
  grep -qE "^ignore-scripts *= *true" ~/.npmrc 2>/dev/null && chk PASS "npm install scripts disabled by default" || chk WARN "npm runs dependency install scripts" "ignore-scripts=true is missing from ~/.npmrc"
  grep -qE "^min-release-age *= *[1-9]" ~/.npmrc 2>/dev/null && chk PASS "npm skips freshly published versions" || chk WARN "npm installs versions published minutes ago" "min-release-age is missing from ~/.npmrc"
  [ -x ~/.safe-chain/bin/safe-chain ] && grep -q "safe-chain" ~/.zshrc 2>/dev/null && chk PASS "Safe Chain wraps package managers" || chk WARN "Safe Chain is not active" "malicious packages are not blocked at install"
  vs="$HOME/Library/Application Support/Code/User/settings.json"
  if [ -f "$vs" ]; then grep -qE '"task.allowAutomaticTasks" *: *"off"' "$vs" && chk PASS "VS Code automatic tasks off" || chk WARN "VS Code may auto-run a repo's tasks" "task.allowAutomaticTasks is not off"; fi
  tu=$(security dump-trust-settings 2>&1 | grep -c "^Cert "); ta=$(security dump-trust-settings -d 2>&1 | grep -c "^Cert "); [ "$tu$ta" = "00" ] && chk PASS "No custom certificate trust overrides" || chk WARN "Custom certificate trust settings present" "user:$tu admin:$ta - run: security dump-trust-settings -d"
}

volatile() {
  TMPV=$(mktemp); trap 'rm -f "$TMPV"' EXIT
  sec "LOGINS";                      who; last | head -10
  sec "LISTENING TCP (all)";         lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | awk '{print $1,$2,$3,$9}' | sort -u
  sec "OUTBOUND BY PROCESS";         lsof -nP -iTCP -sTCP:ESTABLISHED 2>/dev/null | awk 'NR>1{split($9,a,"->"); print $1,a[2]}' | sort | uniq -c | sort -rn | head -60
  sec "REMOTE-ACCESS / MONITORING PROCESSES"
  ps axo pid,user,comm | grep -vE " (/System/|/usr/libexec/|/usr/sbin/|/Library/Apple/)" | awk '{n=$3; for(i=4;i<=NF;i++) n=n" "$i; b=n; sub(/.*\//,"",b); print $1, $2, n "\t" b}' | grep -iE "\t.*(teamviewer|anydesk|rustdesk|screenconnect|connectwise|logmein|splashtop|vnc|ngrok|tailscale|zerotier|cloudflared|frpc|chisel|jamf|kandji|mosyle|intune|crowdstrike|falcon|sentinel|teramind|hubstaff|activtrak|timedoctor|desktime|keylog|spyrix|refog|mspy|flexispy|hoverwatch|interguard|veriato|osquery|munki|addigy|wazuh|netskope|zscaler|forcepoint|globalprotect|ARDAgent|screensharingd|meshagent|atera|ninja|dwagent|parsec|remoting_me2me)" | cut -f1 > "$TMPV" ; if [ -s "$TMPV" ]; then cat "$TMPV"; while read -r pid usr comm; do finding high remote-access "proc:$comm" "Remote-access or monitoring software is running" "$comm (user $usr)"; done < "$TMPV"; else echo "none found"; fi
  sec "REMOTE LOGIN / SCREEN SHARING PORTS"; for p in 22 5900 445 3283; do nc -z -G1 127.0.0.1 $p >/dev/null 2>&1 && echo "port $p OPEN" || echo "port $p closed"; done
  sec "BROWSERS WITH AUTOMATION FLAGS"; ps axo pid,args | grep -E "Chrome|Firefox|Safari" | grep -E -- "--remote-debugging|--headless|--load-extension|--enable-automation" | grep -v grep | cut -c1-300 | while IFS= read -r l; do echo "$l"; finding medium browser "automation:$(echo "$l" | awk '{print $2}')" "A browser is running with automation/remote-debugging flags" "$l"; done
  sec "RUNNING BINARIES: UNSIGNED / AD-HOC (outside system paths)"
  ps axo comm | awk 'NR>1' | grep -vE "^(/System|/usr/(libexec|sbin|bin)|/sbin|/bin|/Library/Apple)" | sort -u | while read -r b; do
    [ -f "$b" ] || continue; r=$(codesign -dv "$b" 2>&1 | grep -E "not signed|Signature=adhoc"); [ -n "$r" ] && { echo "$r | $b"; finding low process "unsigned:$b" "Unsigned or ad-hoc signed program is running" "$b"; }; done
  sec "RECENT EXECUTABLES/SCRIPTS IN TEMP & DOTDIRS (14d)"
  find ~/.local ~/bin ~/.config /tmp /private/var/tmp ~/Library/LaunchAgents -maxdepth 3 -type f \( -perm -u+x -o -name "*.sh" -o -name "*.command" -o -name "*.scpt" -o -name "*.plist" \) -mtime -14 2>/dev/null | grep -v node_modules | head -40
  sec "NETWORK";                     ifconfig | grep -E "inet " ; netstat -rn -f inet | grep default
  sec "ARP: GATEWAY + DUPLICATE MACS (spoofing indicator)"
  gw=$(netstat -rn -f inet | awk '/^default/{print $2; exit}'); arp -n "$gw" 2>&1
  n=$(netstat -rn -f inet | grep -c '^default'); arp -an | awk '{print $4}' | grep -v incomplete | sort | uniq -c | awk -v n="$n" '$1>n{print "DUPLICATE MAC:",$2,"x"$1}' | while IFS= read -r l; do echo "$l"; finding high network "arp:$l" "Duplicate MAC address on the network (possible ARP spoofing)" "$l"; done
  sec "FIREWALL: INBOUND FLOWS BLOCKED, BY APP (6h; source IPs are not logged by macOS)";        log show --last 6h --style compact --predicate 'process == "socketfilterfw"' 2>/dev/null | grep -E "verdict: 2|Deny|deny" | sed -E 's/^.*KNOWN APP FLOW: //; s/, return.*//' | sort | uniq -c | sort -rn | head -20
  sec "SSH / SCREEN SHARING / AUTH FAILURES (24h)"
  log show --last 24h --style compact --predicate 'process == "sshd" OR process == "screensharingd" OR (process == "loginwindow" AND eventMessage CONTAINS[c] "authentication failed") OR (process == "sudo" AND eventMessage CONTAINS[c] "incorrect password")' 2>/dev/null | grep -v "^Timestamp" | tail -20
  sec "SECRETS (.env inventory and gitleaks over git history; values are never printed)"
  /usr/bin/python3 "$HERE/secrets_scan.py" 2>&1
  sec "PRIVACY PERMISSIONS (TCC)"
  sqlite3 "$HOME/Library/Application Support/com.apple.TCC/TCC.db" "select service,client,auth_value from access where service in ('kTCCServiceScreenCapture','kTCCServiceAccessibility','kTCCServiceListenEvent','kTCCServiceSystemPolicyAllFiles','kTCCServiceCamera','kTCCServiceMicrophone','kTCCServicePostEvent') order by 1" 2>&1 | sed 's/.*authorization denied.*/NOT READABLE: terminal lacks Full Disk Access - review manually in System Settings > Privacy \& Security/'
}

{ stable; hardening; } > "$SNAP" 2>&1
{ echo "mac-guard audit $TS  host=$(scutil --get ComputerName 2>/dev/null)  macOS $(sw_vers -productVersion)"
  sec "CHANGES SINCE PREVIOUS RUN (${PREV:-none})"
  # INFO lines carry dates/versions that change every run, so they are left out of the diff
  if [ -n "$PREV" ]; then diff <(grep -v '^INFO' "$PREV") <(grep -v '^INFO' "$SNAP") > "$CHANGES"; [ -s "$CHANGES" ] && cat "$CHANGES" || echo "no changes in persistence/config/extension snapshot"
  else : > "$CHANGES"; echo "first run - baseline created"; fi
  cat "$SNAP"; volatile; } > "$REPORT" 2>&1
echo "REPORT=$REPORT"; echo "SNAPSHOT=$SNAP"; echo "PREVIOUS=${PREV:-none}"
