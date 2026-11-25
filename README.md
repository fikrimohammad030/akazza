cat > README.md << 'AKAZZA_EOF'
# AKAZZA

**PHP WebShell → System Shell Framework** · *SMART PLUGIN EDITION*

Made by **joyboyvoidera**

```
▄▀█ █▄▄ ▄▀█ ▀▀█ ▀▀█ ▄▀█
█▀█ █░█ █▀█ █▄▄ █▄▄ █▀█
```

> ⚠️ **For authorized security testing and education only.** Only run this against systems you own or have explicit written permission to test. The author assumes no liability for misuse.

---

## What is AKAZZA?

AKAZZA is a modular, plugin-driven exploitation framework that takes a target web application and drives it all the way to an interactive system shell. It is designed around a simple idea: **assess first, then attack with the vector the evidence supports** — and never dead-end when a vector fails.

Key features:

- **SMART mode** — crawls the target, fingerprints it, scores every vector plugin against the observed evidence, and recommends the attack most likely to succeed.
- **Evidence-based ranking** — every vector declares what it *wants* and *avoids*; findings from recon weight the ranking.
- **Plugin architecture** — drop a `.py` file into `plugins/` and it appears in the menu, the ranking, and the recovery chooser.
- **Recovery chooser** — when every selected vector or payload fails, you get a "pick another exploit" menu instead of a dead end. Retry last, run all, re-run SMART, try a manual URL, or change target — no restart.
- **Verified shells** — the built-in listener confirms the connection by executing `id` before declaring success. No false positives.
- **Fingerprint-driven payload chain** — probes the victim for `socat`, `bash`, `nc`, `python`, `perl`, `php`, `curl` and builds a socat-first fallback chain.
- **Post-exploitation plugins** — privesc hunting (GTFOBins watchlist), DB credential harvesting.
- **HTML/JSON reports** — full session log, assessment, ranking, and findings.

---

## Requirements

- Python 3.7+
- `requests`

```bash
pip install requests
```

Linux gives you the best experience (raw TTY interactive shell via `termios`). On Windows the shell falls back to a line-based mode (`exit_akazza` to quit).

---

## Quick start

```bash
git clone https://github.com/fikrimohammad030/akazza
cd akazza
pip install requests
python3 akazza.py
```

From the menu:

| Option | What it does |
|--------|--------------|
| `[1]` | **SMART mode** — assess → rank → recommend/pick → attack |
| `[2]` | **MUZAN** — the proven DVWA upload-evasion vector (asks for target) |
| `[3]` | **Bypass Inspection Filter** — MySQL `INTO OUTFILE` delivery for DVWA Impossible |
| `[4]` | Default full-auto (upload fuzz) |
| `[5]` | PHP upload-to-RCE tester (quirk ladder) |
| `[6]` | Choose a plugin by number (blank = ALL vectors) |
| `[7]` | Manual — you already have a webshell URL |
| `[8]` | List plugins |
| `[9]` | Exit |

### Command line

```bash
python3 akazza.py --smart [URL]          # SMART: assess → rank → [p]ick → attack
python3 akazza.py --muzan                # MUZAN plugin (asks for target itself)
python3 akazza.py --bypass-filter [URL]  # ONLY the inspection-filter bypass
python3 akazza.py --auto [URL]           # recon + upload-fuzz vectors
python3 akazza.py --php-upload [URL]     # ONLY the PHP upload-to-RCE tester
python3 akazza.py --one <name> [URL]     # run one arbitrary plugin (name substring)
python3 akazza.py --list-plugins         # show registry + evidence tags
python3 akazza.py --report               # generate an HTML report
python3 akazza.py --help
```

> On **any** failed vector, the recovery menu appears automatically: pick another exploit, retry last, run all, re-SMART, enter a manual URL, or change target — no restart needed.

---

## How SMART mode works

1. **Recon (Phase R)** — crawls up to `crawl_max_pages` pages, discovers upload forms, login forms, and dynamic URL parameters. Login is CSRF-aware: hidden tokens are re-fetched on *every* credential attempt, and login is re-attempted whenever a password form is seen while unauthenticated.
2. **Assessment** — probes for `phpinfo()`, `composer.json`, Adminer, phpMyAdmin, server headers, upload-form validation weaknesses, and confirms LFI by actually reading `/etc/passwd`. Findings are tagged with a weight.
3. **Ranking** — each vector plugin declares `wants` / `avoids` tags. Positive evidence adds weight, negative findings (e.g. `upload_strict`, `pma_missing`) subtract. Ranked 0–99%.
4. **Recommendation** — the top vector is proposed. You can run it, run all, or `[p]ick` another from the ranked list.
5. **Exploitation** — the chosen vector returns a webshell URL (or an LFI helper). The engine fingerprints the victim, arms a listener, and fires the payload chain until a **verified** shell connects.
6. **Post-exploitation** — menu of postex plugins, then an interactive shell.
7. **Recovery** — if anything fails, the chooser keeps you moving.

---

## Bundled plugins

### Vectors (`plugins/`, phase `vector`)

| Plugin | CWE | Technique |
|--------|-----|-----------|
| **PHP upload-to-RCE chain tester** | CWE-434 | PHP quirk ladder: alt extensions (`.php5/.php7/.phtml/.pht/.phar/.pgif`), case bypass (`.PhP`), double extension (`.php.jpg`), null byte, GIF89a polyglot, and two-step `.htaccess` `AddType` abuse. Every variant is execution-verified. |
| **V1: upload fuzzing** | CWE-434 | Generic upload-form fuzzing with a small evasion ladder against every discovered form. |
| **V2: phpMyAdmin INTO OUTFILE** | CWE-798 | phpMyAdmin credential attempts → `SELECT ... INTO OUTFILE` plants a webshell in the webroot. |
| **V3: LFI + log poisoning** | CWE-98 | Confirms LFI in discovered params → poisons the webserver access log via `User-Agent` → the log *is* the webshell. Zero files uploaded. |
| **Muzan** | CWE-434 | The proven DVWA upload-evasion ladder, verbatim, plus a socat-first payload chain. |
| **Bypassing Inspection Filter (DVWA Impossible)** | CWE-798 | Delivers the shell via the **database tier** (`INTO OUTFILE`) so the file never passes through the Impossible upload filter. "Bypass the inspection point, don't fight it." |

### Post-exploitation (`plugins/`, phase `postex`)

| Plugin | Technique |
|--------|-----------|
| **Privesc hunt** | `sudo -l` + SUID scan against a GTFOBins watchlist + old-kernel hint. |
| **DB creds grab** | DVWA / WordPress / phpMyAdmin config files. |

### Template

`plugins/_template.py` documents the plugin contracts. The loader skips files starting with `_`.

---

## Writing a plugin

Copy `plugins/_template.py`, rename it (no leading underscore), and fill in the logic. It is auto-loaded, registered, ranked, and listed in the menus.

```python
from datetime import datetime

@register_plugin("V99: my new vector", phase="vector", priority=99,
                 cwe="CWE-XXX", attck="TXXXX", desc="one-line description",
                 wants=["upload_weak"], avoids=["upload_strict"])
def my_vector(akazza, surface, origin):
    # surface = {"upload_forms": [(url, field, extras)],
    #            "params": {url: [names]},
    #            "interesting_dirs": set}
    # success → update akazza.session_log, return (shell_url, param)
    # failure → return None, None
    return None, None
```

**Contracts**

- **vector:** `fn(akazza, surface, origin) -> (shell_url, param)` or `(None, None)`
  - Special case for LFI-style shells: return `("__LFI__", "akz")` and set `akazza._lfi_helper = (base_url, params, lfi_param, logpath, depth)`.
- **postex:** `fn(akazza, shell_url, param) -> None`; append strings to `akazza.session_log["postex_findings"]`.

Plugins receive `akazza` (the engine, with `webshell_cmd`, `payload_core`, `session_log`, etc.), `CONFIG`, and `col` (color codes).

---

## Configuration

All tunables live in the `CONFIG` dict at the top of `akazza.py` and are shared with every plugin:

```python
CONFIG = {
    "default_target": "http://192.168.44.131/",
    "listen_port": 4444,          # built-in listener port
    "shell_param": "cmd",          # webshell parameter name
    "crawl_max_pages": 25,
    "timeout": 12,
    "creds": [ ... ],             # login attempts (webapp + DB)
    "upload_dirs": [ ... ],       # candidate landing dirs
    "pma_paths": [ ... ],         # phpMyAdmin locations
    "lfi_params": [ ... ],        # parameter names worth testing for LFI
    "log_paths": [ ... ],         # log-poisoning targets
    "outfile_paths": [ ... ],     # SQL INTO OUTFILE candidates
    "webshell_php": "<?php system($_REQUEST['cmd']); ?>",
}
```

Change `listen_port` and make sure your firewall/NAT allows the victim to reach your `get_local_ip()` address on that port.

---

## Output & reports

After a session you can generate:

- **HTML report** — dark-themed summary with assessment findings, vector ranking (with bars), chain, findings, and recon.
- **JSON report** — the full `session_log` for automation.
- **Summary** — printed to the terminal.

---

## Interactive shell

- **Linux with termios:** full PTY — AKAZZA upgrades the victim shell with `pty.spawn('/bin/bash')`, sets `TERM=xterm`, and gives you a raw TTY. Exit with **Ctrl-]**.
- **Windows / no termios:** line-based mode. Type commands; quit with `exit_akazza`.

---

## Version history (highlights)

- **v1.10** — Recovery menu ("pick another exploit") on any vector/payload failure; fixed login carry-over bug (login is now re-attempted whenever a password form is seen while unauthenticated); vector functions return success booleans so the chooser knows when to stop.
- **v1.9** — CSRF-aware recon login, `[p]ick` in SMART mode, socat-first payload chain.
- **v1.8** — Plugin architecture; MUZAN vector; SMART mode.
- **v1.3** — Original proven DVWA auto-upload path (now MUZAN's core).

---

## Legal

AKAZZA is a penetration-testing tool. Using it against systems without prior authorization is illegal in most jurisdictions. The author provides this software for educational and authorized testing purposes only and accepts no responsibility for any damage or legal consequences arising from its use. **You are responsible for your own actions.**

---

*AKAZZA v1.10 — SMART PLUGIN EDITION · by joyboyvoidera*
AKAZZA_EOF
