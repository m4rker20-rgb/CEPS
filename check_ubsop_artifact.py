# -*- coding: utf-8 -*-
"""Самопроверка UBSOP CEPS-артефакта по чек-листу (шаг 5)."""
import io
import json
import os
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
CEPS = os.path.join(HERE, "ubsop_ceps", "builds", "ubsop_py314.ceps")
HYBRID = os.path.join(HERE, "ubsop_ceps", "builds", "UBSOP-v0.1-ceps.elyx")
LOADER_PY = os.path.join(HERE, "ubsop_ceps", "builds", "ubsop_py314.py")

print("== 1. manifest ==")
with open(CEPS, "rb") as f:
    blob = f.read()
man = None
try:
    z = zipfile.ZipFile(CEPS)
    for n in z.namelist():
        if "manifest" in n or n.endswith(".json"):
            man = json.loads(z.read(n).decode("utf-8"))
            print("  manifest in zip:", n)
            break
except zipfile.BadZipFile:
    head = blob[:4096].decode("utf-8", "replace")
    i = head.find("{")
    if i >= 0:
        try:
            man = json.loads(head[i:blob.index(b"}" .decode(), i) + 1]
                             if False else head[i:].split("}\n")[0] + "}")
        except Exception:
            man = None
if man is None:
    # search whole blob for embedded json with keying
    s = blob.decode("utf-8", "replace")
    i = s.find('"keying"')
    if i >= 0:
        j = s.rfind("{", 0, i)
        k = s.find("}", i)
        frag = s[j:k + 1]
        try:
            man = json.loads(frag)
        except Exception:
            man = {"raw": frag[:400]}
if man:
    print("  keying =", man.get("keying"))
    slots = man.get("slots") or man.get("env_slots") or []
    print("  slots =", len(slots) if isinstance(slots, list) else slots)
    print("  enc =", man.get("enc") or man.get("enc_version"))
    print("  mem_dex =", man.get("mem_dex"))
    print("  rt_pyc =", man.get("rt_pyc"))
    print("  raw keys:", sorted(man.keys())[:20])
else:
    print("  !! manifest json not parsed, dump head:")
    print("  ", blob[:200])

print("== 2. no payload starts with CEPSENC1 ==")
bad = []
z = zipfile.ZipFile(HYBRID)
for n in z.namelist():
    d = z.read(n)[:16]
    if d.startswith(b"CEPSENC1"):
        bad.append(n)
print("  files with CEPSENC1 magic:", bad if bad else "none (OK)")

print("== 3. enc blocks have hmac, no plain ==")
s = blob.decode("utf-8", "replace")
print("  'hmac' occurrences:", s.count('"hmac"') + s.count("hmac="))
print("  'plain' field occurrences:", s.count('"plain"'))

print("== 4. loader guard markers ==")
with io.open(LOADER_PY, encoding="utf-8", errors="replace") as f:
    L = f.read()
for marker in ('_GUARD = (', '_GUARD_SEAL = "', '_SHARES = ()'):
    print("  %r:" % marker, marker in L)
print("  _RT_SRC absent:", "_RT_SRC" not in L)

print("== 5. engine.dex absence in hybrid ==")
print("  engine.dex entries:", [n for n in z.namelist() if "engine.dex" in n]
      or "none (OK)")

print("== 6. master not embedded ==")
# master key hex would be 64 hex chars; scan loader and manifest
import re
hexes = re.findall(r"[0-9a-f]{64}", L)
print("  64-hex literals in loader:", len(hexes))
if man:
    ms = json.dumps(man)
    print("  64-hex in manifest:", len(re.findall(r"[0-9a-f]{64}", ms)))
