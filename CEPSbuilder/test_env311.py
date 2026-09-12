# -*- coding: utf-8 -*-
"""CEPS-3 env-цикл под Python 3.11 (как на телефоне, Chaquopy)."""
import subprocess
import sys
import os

UV311 = os.path.expandvars(
    r"%APPDATA%\uv\python\cpython-3.11.15-windows-x86_64-none\python.exe")
if not os.path.exists(UV311):
    UV311 = os.path.expanduser(
        r"~\AppData\Roaming\uv\python\cpython-3.11.15-windows-x86_64-none\python.exe")

r = subprocess.run([UV311, "-X", "utf8", os.path.join("CEPSbuilder", "test_env.py")],
                   capture_output=True, text=True, cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
print(r.stdout[-2500:])
if r.returncode != 0:
    print(r.stderr[-2000:])
    print("PY311 ENV TEST: FAIL")
    sys.exit(1)
print("PY311 ENV TEST: PASS")
