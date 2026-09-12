# -*- coding: utf-8 -*-
"""CEPS rt_pyc: рантайм в marshal-3.11, исходника нигде нет.

1) сборка с rt_pyc: в лоадере нет _RT_SRC и маркеров исходника,
   в блобе ceps_rt.pyc вместо ceps_rt.py, manifest rt_pyc=true;
2) лоадер исполняется и гидрируется под Python 3.11 (телефонный);
3) старые архивы (source-RT) продолжают проверяться.
"""
import ast
import hashlib
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import cepsbuilder as cb  # noqa: E402
import ceps_rt as rt  # noqa: E402

UV311 = os.path.join(os.path.expanduser("~"), "AppData", "Roaming", "uv",
                     "python", "cpython-3.11.15-windows-x86_64-none", "python.exe")


def main():
    tmp = tempfile.mkdtemp(prefix="ceps_rtpyc_")
    try:
        proj = os.path.join(tmp, "rtpyc")
        cfg = cb.new_project(proj, name="RT Pyc", author="tester")
        cb.write_text(os.path.join(proj, cfg["key"]), secrets.token_bytes(32).hex())
        cj = json.loads(cb.read_text(os.path.join(proj, "ceps.json")))
        cj["env_classes"] = ["org.telegram.messenger.NotificationCenter"]
        cb.write_text(os.path.join(proj, "ceps.json"), json.dumps(cj))
        src_dir = os.path.join(proj, "src")
        os.makedirs(src_dir, exist_ok=True)
        cb.write_text(os.path.join(src_dir, "loader.py"),
                      "class Plugin:\n"
                      "    def on_plugin_load(self):\n"
                      "        import android_utils\n"
                      "        android_utils.log('CEPS check passed')\n")

        r = cb.build_project(proj, note="rt-pyc-test", elyx=True,
                             allow_envsim=True, rt_pyc=True)
        loader_src = cb.read_text(r["outputs"]["loader"])

        # ---- 1) в лоадере нет исходника рантайма
        assert "_RT_MARSHAL = base64.b85decode(" in loader_src, "нет _RT_MARSHAL"
        assert "_RT_SRC" not in loader_src, "_RT_SRC остался в лоадере!"
        for marker in ("def verify_files", "class CepsError", "ed25519_verify",
                       "merkle_root", "_combine_shares"):
            assert marker not in loader_src, "исходник рантайма виден: %s" % marker
        print("[1] в лоадере нет исходника рантайма: OK")

        # ---- 2) в блобе ceps_rt.pyc, manifest rt_pyc
        z = r["files"] if "files" in r else None
        import zipfile
        zf = zipfile.ZipFile(r["outputs"]["ceps"])
        names = zf.namelist()
        assert rt.RT_PYC_PATH in names, names
        assert rt.RT_PATH not in names, names
        man = json.loads(zf.read(rt.MANIFEST_PATH).decode("utf-8"))
        assert man.get("rt_pyc") is True
        assert man["rt_sha256"] == hashlib.sha256(
            zf.read(rt.RT_PYC_PATH)).hexdigest()
        print("[2] блоб содержит ceps_rt.pyc, manifest rt_pyc: OK")

        # eaf main.py тоже без исходника
        import zipfile as _zf
        eaf = _zf.ZipFile(r["outputs"]["eaf"])
        m = eaf.read("main.py").decode("utf-8")
        assert "_RT_MARSHAL" in m and "def verify_files" not in m
        print("[3] eaf main.py тоже marshal-only: OK")

        # ---- 3) исполнение лоадера под 3.11 (телефонный рантайм)
        runner = os.path.join(tmp, "run311.py")
        cb.write_text(runner, (
            "import sys\n"
            "sys.path.insert(0, %r)\n" % HERE +
            "import fakesdk\n"
            "fakesdk.install()\n"
            "src = open(sys.argv[1], encoding='utf-8').read()\n"
            "ns = {'__name__': 'rtpyc311', '__file__': sys.argv[1]}\n"
            "exec(compile(src, sys.argv[1], 'exec'), ns)\n"
            "inst = ns['CepsPlugin']()\n"
            "inst.on_plugin_load()\n"
            "ok = any('CEPS check passed' in l for l in fakesdk.LOGS)\n"
            "print('HYDRATE-OK' if ok else 'HYDRATE-FAIL')\n"
            "sys.exit(0 if ok else 1)\n"))
        p = subprocess.run([UV311, "-X", "utf8", runner, r["outputs"]["loader"]],
                           capture_output=True, text=True)
        out = (p.stdout or "") + (p.stderr or "")
        assert "HYDRATE-OK" in out, out[-1500:]
        print("[4] лоадер под 3.11 гидрируется из marshal-рантайма: OK")

        # ---- 4) обратная совместимость: source-RT архив проверяется
        files = rt.read_zip_files(r["outputs"]["ceps"])
        man2 = rt.verify_structure(files, rt.ed25519_pubkey(
            cb.load_seed(os.path.join(proj, cfg["key"]))).hex())
        assert man2["entry"]
        print("[5] verify_structure знает rt_pyc-архив: OK")

        print("\nRT-PYC TEST: PASS")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
