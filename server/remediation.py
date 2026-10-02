"""How to fix each kind of finding. The dashboard shows this text; mac-guard itself never changes the system.
First matching entry wins: (text that must appear in the finding key, steps)."""

SHARING = "System Settings > General > Sharing: turn this service off."
USERS = "System Settings > Users & Groups."

REMEDIATION = (
    # compromise signs
    ("proc:", "If you did not install this, disconnect from the network, quit it, and uninstall the app. "
              "If you installed it on purpose, press Accept."),
    ("ssh:authorized_keys", "Open ~/.ssh/authorized_keys and delete every key you do not recognise. "
                            "If Remote Login is not needed, also turn it off in System Settings > General > Sharing."),
    ("arp:", "Someone on this network may be intercepting traffic. Disconnect from this Wi-Fi/LAN, use another "
             "network or a VPN, and tell whoever runs the network."),
    ("automation:", "A browser is being driven by a program. If you are not running tests or an automation tool, "
                    "quit that browser window and find what started it."),
    ("shellrc:", "Open the file named in the detail and remove the line if you do not recognise it. "
                 "If it is from a tool you installed, press Accept."),
    ("unsigned:", "Homebrew and node_modules programs are normally ad-hoc signed: press Accept if you know it. "
                  "Otherwise find what started it (ps -o ppid=,command= -p <pid>) and remove it."),
    # secrets
    ("env-tracked:", "Treat every value in this file as leaked: rotate them at the provider first. Then run "
                     "`git rm --cached <file>`, add it to .gitignore and commit. History still holds the old values."),
    ("env-unignored:", "Add the file name to that repo's .gitignore so it cannot be committed by accident."),
    ("env-permissions", "Run: find ~/repos -name '.env*' -not -path '*/node_modules/*' -type f -exec chmod 600 {} +"),
    ("git-secrets:", "Open the report from Run history for the file list. For each real secret: rotate it at the "
                     "provider (removing the file does not remove it from git history). For false positives such as "
                     "test fixtures or example keys, press Accept."),
    # browser
    ("ext:", "In that Chrome profile open chrome://extensions and click Remove. If you rely on the extension "
             "and trust its publisher, press Accept instead."),
    ("siteperm:", "In that Chrome profile open chrome://settings/content, choose the permission, and remove the site. "
                  "If you want this site to have it, press Accept."),
    (":search", "Chrome > Settings > Search engine: set it back to your usual one, then remove the extension that changed it."),
    (":homepage", "Chrome > Settings > Appearance / On startup: clear the custom page, then remove the extension that set it."),
    (":startup", "Chrome > Settings > On startup: choose 'Open the New Tab page', then remove the extension that set it."),
    (":proxy", "Chrome > Settings > System > proxy settings: remove the proxy. Remove any VPN/proxy extension you do not need."),
    (":safebrowsing", "Chrome > Settings > Privacy and security > Security: turn on Standard or Enhanced protection."),
    (":doh", "Chrome > Settings > Privacy and security > Security > Use secure DNS: pick a provider you trust."),
    (":policy", "This browser is managed by policy files in /Library/Managed Preferences. If no employer manages "
                "this Mac, those files should not exist: delete them with sudo and restart the browser."),
    # hardening
    ("AirPlay Receiver", "System Settings > General > AirDrop & Handoff: turn off AirPlay Receiver."),
    ("Firewall OFF", "System Settings > Network > Firewall: turn it on."),
    ("stealth mode OFF", "System Settings > Network > Firewall > Options: turn on stealth mode."),
    ("Generic interpreters", "Run: /usr/libexec/ApplicationFirewall/socketfilterfw --blockapp /usr/bin/python3 "
                             "(repeat for each interpreter listed under FIREWALL APP RULES in the report)."),
    ("SIP OFF", "Restart into Recovery (hold the power button), open Terminal, run: csrutil enable"),
    ("Gatekeeper OFF", "Run: sudo spctl --master-enable"),
    ("FileVault OFF", "System Settings > Privacy & Security > FileVault: turn it on and store the recovery key safely."),
    ("SoftwareUpdate", "System Settings > General > Software Update > Automatic Updates: turn every option on."),
    ("Remote Login", SHARING), ("Screen Sharing", SHARING), ("File Sharing", SHARING), ("Apple Remote Desktop", SHARING),
    ("Remote Apple Events", SHARING), ("Printer Sharing", SHARING), ("Internet Sharing", SHARING), ("Bluetooth Sharing", SHARING),
    ("AirDrop open", "System Settings > General > AirDrop & Handoff: set AirDrop to Contacts Only or No One."),
    ("Guest account", USERS + " Turn off Guest User."),
    ("Automatic login", USERS + " Set 'Automatically log in as' to Off."),
    ("root account", "Open Directory Utility > Edit > Disable Root User."),
    ("admin account", USERS + " Open each extra account and turn off 'Allow this user to administer this computer', "
                              "or delete the account."),
    ("Password not required", "System Settings > Lock Screen: set 'Require password after screen saver begins or "
                              "display is turned off' to Immediately."),
    ("Screen does not lock", "System Settings > Lock Screen: set 'Turn display off when inactive' to 20 minutes or less."),
    ("Passwordless sudo", "Run: sudo visudo, and remove any line containing NOPASSWD for your user."),
    ("Home folder permissions", "Run: chmod 750 ~"),
    ("SSH private key too open", "Run: chmod 600 on the key file named in the finding."),
    ("Safari auto-opens", "Safari > Settings > General: untick 'Open safe files after downloading'."),
    ("MDM-enrolled", "System Settings > General > Device Management lists who manages this Mac. If it is not your "
                     "employer, remove the profile."),
    ("system proxy", "System Settings > Network > your connection > Details > Proxies: turn off every proxy you did not set."),
    ("npm ", "Run: ~/mac-guard/install.sh hygiene"),
    ("Safe Chain", "Run: ~/mac-guard/install.sh hygiene"),
    ("VS Code", "Run: ~/mac-guard/install.sh hygiene"),
    ("certificate trust", "Open Keychain Access > System > Certificates, look for certificates marked 'always trust' "
                          "that you did not add, and delete them."),
)
DEFAULT = "Open the report from Run history for the full context, then fix it in System Settings or press Accept."


def fix_for(key):
    return next((steps for needle, steps in REMEDIATION if needle in key), DEFAULT)
