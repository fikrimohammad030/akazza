"""AKAZZA PLUGIN TEMPLATE — copy, rename, fill in logic. (skipped by loader)

CONTRACTS:
  vector: fn(akazza, surface, origin) -> (shell_url, param) or (None, None)
          surface = {"upload_forms":[(url,field,extras)], "params":{url:[names]},
                    "interesting_dirs": set}
  postex : fn(akazza, shell_url, param) -> None
           append findings to akazza.session_log["postex_findings"]

You get free: akazza (engine), CONFIG, col (colors).
Special return: ("__LFI__", "akz") + set akazza._lfi_helper for LFI-style shells.
"""
from datetime import datetime

@register_plugin("V99: my new vector", phase="vector", priority=99,
                 cwe="CWE-XXX", attck="TXXXX", desc="one-line description")
def my_vector(akazza, surface, origin):
    # 1. inspect surface
    # 2. your technique
    # 3a. success → update akazza.session_log, return (url, param)
    # 3b. failure → return None, None   (MUZAN moves on to next vector)
    return None, None
