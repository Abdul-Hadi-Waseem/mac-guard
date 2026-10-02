#!/usr/bin/env python3
"""Read-only browser audit: extensions, hijack indicators, site permissions.
Covers Chromium browsers (Chrome, Brave, Edge, Arc) and Firefox. Output is deterministic so it can be diffed.
When MG_FINDINGS is set, each problem is also appended to that file as a TSV row (same format as check.sh)."""
import glob, json, os, re, sys

HOME = os.path.expanduser("~")
CHROMIUM = {
    "Chrome": "Library/Application Support/Google/Chrome",
    "Brave": "Library/Application Support/BraveSoftware/Brave-Browser",
    "Edge": "Library/Application Support/Microsoft Edge",
    "Arc": "Library/Application Support/Arc/User Data",
}
# weight = how much damage the permission allows if the extension is or turns malicious
PERM_RISK = {
    "debugger": 5, "proxy": 5, "nativeMessaging": 4, "management": 4, "cookies": 4,
    "webRequest": 3, "webRequestBlocking": 4, "declarativeNetRequest": 2, "desktopCapture": 4,
    "tabCapture": 3, "history": 3, "clipboardRead": 3, "downloads": 2, "privacy": 3,
    "scripting": 2, "tabs": 1, "webNavigation": 1, "identity": 2, "browsingData": 2,
    "contentSettings": 3, "pageCapture": 3, "userScripts": 3, "bookmarks": 1, "topSites": 1,
}
ALL_HOSTS = {"<all_urls>", "*://*/*", "http://*/*", "https://*/*", "file:///*", "ws://*/*", "wss://*/*"}
LOCATION = {1: "webstore", 2: "external-pref", 3: "external-registry", 4: "UNPACKED", 5: "component",
            6: "external-download", 7: "policy", 8: "policy", 9: "command-line", 10: "component"}
SITE_PERMS = ["notifications", "media_stream_camera", "media_stream_mic", "geolocation", "popups",
              "automatic_downloads", "clipboard", "usb_guard", "serial_guard", "hid_guard",
              "file_system_write_guard", "window_placement", "local_network_access", "protocol_handler"]
CODE_PATTERNS = {
    "opens tabs": r"tabs\.create\(", "opens windows": r"windows\.create\(", "eval/Function": r"\beval\(|new Function\(",
    "reads cookies": r"cookies\.getAll\(", "injects scripts": r"scripting\.executeScript\(",
    "sets proxy": r"proxy\.settings\.set\(", "sets uninstall URL": r"setUninstallURL\(",
    "controls other extensions": r"management\.(setEnabled|uninstall)\(",
}

# flags that mean "escalate regardless of publisher"
ESCALATE = ("UNPACKED", "NOT from Web Store", "non-Google server", "HIJACK", "third-party proxy", "disable/enable other")
NOISY_SITE_PERMS = ("notifications", "popups", "automatic_downloads")

def finding(severity, category, key, title, detail=""):
    path = os.environ.get("MG_FINDINGS")
    if not path:
        return
    row = [severity, category, key, title, detail]
    with open(path, "a", encoding="utf-8") as f:
        f.write("\t".join(re.sub(r"[\x00-\x1f\x7f]", " ", str(c)) for c in row) + "\n")

def load(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def out(level, msg):
    print(f"{level:<5} {msg}")

def ext_name(manifest, ext_dir):
    name = manifest.get("name", "?")
    m = re.match(r"__MSG_(.+)__", name)
    if m and ext_dir:
        for loc in (manifest.get("default_locale", "en"), "en", "en_US"):
            msgs = load(os.path.join(ext_dir, "_locales", loc, "messages.json"))
            for k, v in msgs.items():
                if k.lower() == m.group(1).lower():
                    return v.get("message", name)
    return name

def scan_code(ext_dir):
    """Grep the extension's JS for behaviours and third-party domains it talks to."""
    hits, domains = {}, {}
    for root, _, files in os.walk(ext_dir):
        for fn in files:
            if not fn.endswith((".js", ".html")):
                continue
            try:
                src = open(os.path.join(root, fn), encoding="utf-8", errors="ignore").read()
            except Exception:
                continue
            for label, pat in CODE_PATTERNS.items():
                n = len(re.findall(pat, src))
                if n:
                    hits[label] = hits.get(label, 0) + n
            for d in re.findall(r"https?://([a-zA-Z0-9.-]+\.[a-z]{2,})", src):
                d = ".".join(d.lower().split(".")[-2:])
                domains[d] = domains.get(d, 0) + 1
    noise = {"w3.org", "google.com", "googleapis.com", "gstatic.com", "mozilla.org", "github.com", "github.io",
             "reactjs.org", "apple.com", "chromium.org", "npmjs.com", "jquery.com", "fb.me", "schema.org",
             "example.com", "microsoft.com", "stackoverflow.com", "chrome.com", "whatwg.org", "ietf.org",
             "js.org", "mit-license.org", "opensource.org", "apache.org", "feross.org", "wikipedia.org"}
    top = [d for d, _ in sorted(domains.items(), key=lambda kv: (-kv[1], kv[0])) if d not in noise][:8]
    return hits, top

def audit_extension(eid, info, profile_dir):
    manifest = info.get("manifest") or {}
    loc = info.get("location")
    if loc in (5, 10) or not manifest:
        return None
    vers = sorted(glob.glob(os.path.join(profile_dir, "Extensions", eid, "*/")))
    ext_dir = vers[-1] if vers else info.get("path", "") if os.path.isabs(str(info.get("path", ""))) else ""
    name = ext_name(manifest, ext_dir)
    enabled = not info.get("disable_reasons")
    granted = info.get("granted_permissions") or info.get("active_permissions") or {}
    perms = set(p for p in manifest.get("permissions", []) + granted.get("api", []) if isinstance(p, str))
    hosts = set(manifest.get("host_permissions", [])) | set(granted.get("explicit_host", [])) | \
        set(p for p in perms if "://" in p or p == "<all_urls>")
    cs_hosts = set(m for cs in manifest.get("content_scripts", []) for m in cs.get("matches", []))
    main_world = any(cs.get("world") == "MAIN" for cs in manifest.get("content_scripts", []))
    all_sites = bool((hosts | cs_hosts) & ALL_HOSTS)
    risky = sorted((p for p in perms if p in PERM_RISK), key=lambda p: (-PERM_RISK[p], p))
    score = sum(PERM_RISK[p] for p in risky) + (6 if all_sites else 0) + (2 if main_world else 0)
    flags = []
    if loc == 4:
        flags.append("UNPACKED/developer-loaded (bypasses Web Store review)"); score += 6
    elif not info.get("from_webstore"):
        flags.append(f"NOT from Web Store (source: {LOCATION.get(loc, loc)})"); score += 6
    upd = manifest.get("update_url", "")
    if upd and "google.com" not in upd:
        flags.append(f"updates from non-Google server: {upd}"); score += 6
    cso = manifest.get("chrome_settings_overrides")
    if cso:
        flags.append("HIJACK: overrides " + ",".join(sorted(cso.keys()))); score += 8
    cuo = manifest.get("chrome_url_overrides")
    if cuo:
        flags.append("replaces " + ",".join(sorted(cuo.keys())) + " page")
        score += 3
    if main_world and all_sites:
        flags.append("injects script into page context on every site")
    if "proxy" in perms:
        flags.append("can route all browsing through a third-party proxy")
    if "debugger" in perms:
        flags.append("can attach debugger: read/modify any page, incl. banking sessions")
    if "management" in perms:
        flags.append("can disable/enable other extensions")
    ec = (manifest.get("externally_connectable") or {}).get("matches")
    if ec:
        flags.append("websites that can message it: " + ",".join(ec[:3]))
    behaviours, domains = scan_code(ext_dir) if ext_dir and os.path.isdir(ext_dir) else ({}, [])
    level = "HIGH" if score >= 18 else "MED" if score >= 10 else "LOW"
    return dict(id=eid, name=name[:55], enabled=enabled, level=level, score=score, risky=risky, all_sites=all_sites,
                flags=flags, behaviours=behaviours, domains=domains, version=manifest.get("version", "?"))

def audit_chromium(browser, base):
    local_state = load(os.path.join(base, "Local State"))
    doh = local_state.get("dns_over_https", {})
    if doh.get("templates"):
        out("WARN", f"{browser}: custom DNS-over-HTTPS server set: {doh.get('templates')}")
        finding("medium", "browser", f"hijack:{browser}:doh", f"Custom DNS-over-HTTPS server set in {browser}", str(doh.get("templates")))
    for profile_dir in sorted(glob.glob(os.path.join(base, "Default")) + glob.glob(os.path.join(base, "Profile *"))):
        prof = os.path.basename(profile_dir)
        prefs, sprefs = load(os.path.join(profile_dir, "Preferences")), load(os.path.join(profile_dir, "Secure Preferences"))
        if not prefs:
            continue
        label = f"{browser}/{prof}"
        pname = prefs.get("profile", {}).get("name", "")
        accts = ",".join(a.get("email", "?") for a in prefs.get("account_info", [])) or "not signed in"
        print(f"\n--- {label}  (name: {pname}; account: {accts})")

        # ---- hijack indicators
        dsp = (sprefs.get("default_search_provider_data") or prefs.get("default_search_provider_data") or {}).get("template_url_data") or {}
        if dsp:
            url = dsp.get("url", "")
            ok = re.search(r"//(www\.)?(google|bing|duckduckgo|ecosia|startpage|brave|yahoo|kagi|perplexity)\.", url)
            out("PASS" if ok else "WARN", f"default search engine: {dsp.get('short_name')} ({url[:70]})")
            if not ok:
                finding("high", "browser", f"hijack:{label}:search", f"Unusual default search engine in {label}", f"{dsp.get('short_name')} ({url[:120]})")
        else:
            out("PASS", "default search engine: browser default (Google)")
        hp = sprefs.get("homepage") or prefs.get("homepage")
        if hp and not prefs.get("homepage_is_newtabpage", True):
            out("WARN", f"custom homepage: {hp}")
            finding("medium", "browser", f"hijack:{label}:homepage", f"Custom homepage set in {label}", hp)
        sess = {**prefs.get("session", {}), **sprefs.get("session", {})}
        if sess.get("restore_on_startup") == 4 and sess.get("startup_urls"):
            out("WARN", f"opens specific pages at startup: {sess.get('startup_urls')}")
            finding("medium", "browser", f"hijack:{label}:startup", f"Forced startup pages in {label}", ", ".join(sess.get("startup_urls")))
        else:
            out("PASS", "no forced startup pages")
        proxy = prefs.get("proxy") or {}
        if proxy.get("mode") not in (None, "system", "direct"):
            out("WARN", f"browser proxy configured: {json.dumps(proxy)[:160]}")
            finding("high", "browser", f"hijack:{label}:proxy", f"Browser-level proxy configured in {label}", json.dumps(proxy)[:200])
        else:
            out("PASS", "no browser-level proxy")
        sb = prefs.get("safebrowsing", {})
        out("PASS" if sb.get("enabled", True) else "WARN",
            f"Safe Browsing {'on' if sb.get('enabled', True) else 'OFF'}{' (enhanced)' if sb.get('enhanced') else ''}")
        if not sb.get("enabled", True):
            finding("medium", "browser", f"hijack:{label}:safebrowsing", f"Safe Browsing is off in {label}")
        handlers = [h for h in prefs.get("custom_handlers", {}).get("registered_protocol_handlers", []) if h.get("url")]
        for h in handlers:
            out("INFO", f"protocol handler {h.get('protocol')} -> {h.get('url')[:80]}")
        if os.path.isdir(os.path.join(profile_dir, "Extensions", "Temp")) and os.listdir(os.path.join(profile_dir, "Extensions", "Temp")):
            out("INFO", "an extension install/update is in progress (Extensions/Temp not empty)")

        # ---- extensions
        settings = sprefs.get("extensions", {}).get("settings") or prefs.get("extensions", {}).get("settings") or {}
        rows = [r for r in (audit_extension(e, i, profile_dir) for e, i in settings.items()) if r]
        rows.sort(key=lambda r: (not r["enabled"], -r["score"], r["name"]))
        print(f"  extensions: {sum(r['enabled'] for r in rows)} enabled, {sum(not r['enabled'] for r in rows)} disabled")
        for r in rows:
            state = "ON " if r["enabled"] else "off"
            print(f"  [{r['level']:<4} {r['score']:>2}] {state} {r['name']} v{r['version']} ({r['id']})")
            if r["risky"] or r["all_sites"]:
                print(f"            perms: {','.join(r['risky']) or '-'}{'  +ALL SITES' if r['all_sites'] else ''}")
            for f in r["flags"]:
                print(f"            ! {f}")
            if r["enabled"] and r["level"] == "HIGH":
                escalate = any(e in f for f in r["flags"] for e in ESCALATE)
                finding("high" if escalate else "medium", "browser", f"ext:{label}:{r['id']}",
                        f"High-privilege extension enabled: {r['name']}",
                        f"{label} ({accts}); perms: {','.join(r['risky'])}{' +all sites' if r['all_sites'] else ''}; {'; '.join(r['flags'])}")
            if r["enabled"] and r["level"] != "LOW":
                if r["behaviours"]:
                    print("            code: " + ", ".join(f"{k} x{v}" for k, v in sorted(r["behaviours"].items())))
                if r["domains"]:
                    print("            talks to: " + ", ".join(r["domains"]))

        # ---- site permissions
        exc = prefs.get("profile", {}).get("content_settings", {}).get("exceptions", {})
        for kind in SITE_PERMS:
            allowed = sorted(p.split(",")[0] for p, v in (exc.get(kind) or {}).items()
                             if isinstance(v, dict) and v.get("setting") == 1)
            if allowed:
                lvl = "WARN" if kind in NOISY_SITE_PERMS else "INFO"
                if kind in NOISY_SITE_PERMS:
                    for site in allowed:
                        finding("low", "browser", f"siteperm:{label}:{kind}:{site}", f"Site permission granted: {kind.replace('_', ' ')}", f"{site} in {label}")
                print(f"  {lvl:<5} sites allowed '{kind}' ({len(allowed)}): {', '.join(allowed[:15])}{' ...' if len(allowed) > 15 else ''}")

    pol = "/Library/Managed Preferences"
    if os.path.isdir(pol) and os.listdir(pol):
        out("WARN", f"{browser}: managed policy files present in {pol}: {os.listdir(pol)}")
        finding("high", "browser", f"hijack:{browser}:policy", f"Managed browser policy files present", ", ".join(os.listdir(pol)))

def audit_firefox():
    base = os.path.join(HOME, "Library/Application Support/Firefox/Profiles")
    for pdir in sorted(glob.glob(os.path.join(base, "*"))):
        print(f"\n--- Firefox/{os.path.basename(pdir)}")
        for a in sorted(load(os.path.join(pdir, "extensions.json")).get("addons", []), key=lambda a: a.get("id", "")):
            if a.get("location") in ("app-builtin", "app-system-defaults") or a.get("type") != "extension":
                continue
            up = a.get("userPermissions") or {}
            allsites = bool(set(up.get("origins", [])) & ALL_HOSTS)
            print(f"  {'ON ' if a.get('active') else 'off'} {a.get('defaultLocale', {}).get('name', a.get('id'))} "
                  f"v{a.get('version')} signed={a.get('signedState')} perms={','.join(sorted(up.get('permissions', [])))}"
                  f"{'  +ALL SITES' if allsites else ''}")
        try:
            prefs = open(os.path.join(pdir, "prefs.js"), encoding="utf-8", errors="ignore").read()
        except Exception:
            continue
        for key, what in (("browser.startup.homepage", "custom homepage"), ("network.proxy.type", "proxy type"),
                          ("network.proxy.http", "proxy host"), ("network.proxy.autoconfig_url", "proxy PAC"),
                          ("network.trr.custom_uri", "custom DoH")):
            m = re.search(r'user_pref\("%s",\s*(.+?)\);' % re.escape(key), prefs)
            if m and m.group(1) not in ("0", "5", '""'):
                out("WARN" if "proxy" in key or "trr" in key else "INFO", f"{what}: {m.group(1)}")

def audit_safari():
    ext = os.path.join(HOME, "Library/Containers/com.apple.Safari/Data/Library/Safari/AppExtensions/Extensions.plist")
    print("\n--- Safari")
    if not os.access(os.path.dirname(os.path.dirname(ext)), os.R_OK):
        out("INFO", "Safari data not readable without Full Disk Access - check Safari > Settings > Extensions and > Websites manually")
        return
    out("INFO", f"Safari extensions plist {'present' if os.path.exists(ext) else 'absent (no extensions)'}")

if __name__ == "__main__":
    for b, rel in CHROMIUM.items():
        p = os.path.join(HOME, rel)
        if os.path.isdir(p):
            audit_chromium(b, p)
    audit_firefox()
    audit_safari()
    apps = sorted(glob.glob(os.path.join(HOME, "Applications/Chrome Apps.localized/*.app")) + glob.glob(os.path.join(HOME, "Applications/*.app")))
    print("\n--- Installed web apps / URL handlers in ~/Applications: " + (", ".join(os.path.basename(a) for a in apps) or "none"))
