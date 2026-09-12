# -*- coding: utf-8 -*-
"""Гибридная сборка UBSOP-ceps.elyx:

полный UBSOP-артефакт (ubsop_py314.elyx: pyhome-рантайм, telethon, ssl)
+ CEPS-лоадер из ubsop_ceps/builds/ubsop_py314.eaf.
src/main.py заменяется на CEPS-обёртку (payload зашифрован в блобе),
остальные записи (pyhome, rmtree-resistant runtimes) остаются как были.
"""
import os
import shutil
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

BASE_ELYX = r"C:\Users\user2\Desktop\UBSOP\build\poc\ubsop_py314.elyx"
CEPS_EAF = os.path.join(HERE, "ubsop_ceps", "builds", "ubsop_py314.eaf")
OUT_PATH = os.path.join(HERE, "ubsop_ceps", "builds", "UBSOP-v0.1-ceps.elyx")


def main():
    base = zipfile.ZipFile(BASE_ELYX)
    ceps = zipfile.ZipFile(CEPS_EAF)
    ceps_names = set(ceps.namelist())
    print("CEPS .eaf entries:", sorted(ceps_names))
    replaced = 0
    if os.path.exists(OUT_PATH):
        os.remove(OUT_PATH)
    with zipfile.ZipFile(OUT_PATH, "w", zipfile.ZIP_DEFLATED) as z:
        for info in base.infolist():
            if info.is_dir():
                continue
            name = info.filename
            if name == "src/main.py":
                # CEPS-лоадер вместо открытого исходника
                z.writestr(info, ceps.read("main.py"))
                replaced += 1
            else:
                z.writestr(info, base.read(name))
        # дополнительные записи CEPS .eaf, которых нет в базе (кроме main.py
        # и дубликатов pyhome), переносим как есть
        base_names = set(base.namelist())
        for name in ceps_names:
            if name in ("main.py", "metainfo.yml") or name in base_names:
                continue
            z.writestr(name, ceps.read(name))
            replaced += 1
    base.close()
    ceps.close()
    print("replaced/added:", replaced)
    print("OK ->", OUT_PATH, os.path.getsize(OUT_PATH), "bytes")


if __name__ == "__main__":
    main()
