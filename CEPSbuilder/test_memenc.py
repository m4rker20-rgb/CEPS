# -*- coding: utf-8 -*-
"""Функциональный тест enc_v2 + mem_dex: dex не материализуется, HMAC работает."""
import json
import os
import secrets
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import cepsbuilder as cb  # noqa: E402
import ceps_rt as rt  # noqa: E402
import fakesdk  # noqa: E402


def main():
    tmp = tempfile.mkdtemp(prefix="ceps_memenc_")
    try:
        fakesdk.install()
        proj = os.path.join(tmp, "memenc")
        cfg = cb.new_project(proj, name="Mem Enc", author="tester")
        cb.write_text(os.path.join(proj, cfg["key"]), secrets.token_bytes(32).hex())
        cj = json.loads(cb.read_text(os.path.join(proj, "ceps.json")))
        cj["mem_dex"] = True
        cb.write_text(os.path.join(proj, "ceps.json"), json.dumps(cj))
        os.makedirs(os.path.join(proj, "src"), exist_ok=True)
        os.makedirs(os.path.join(proj, "java"), exist_ok=True)
        with open(os.path.join(proj, "java", "engine.dex"), "wb") as fh:
            fh.write(b"dex\n" + secrets.token_bytes(2048))
        entry_path = os.path.join(proj, cfg["entry"])
        cb.write_text(entry_path,
                      "def _ceps_dex_len():\n"
                      "    d = ceps_dex()\n"
                      "    return len(d) if d else -1\n\n"
                      "import base_plugin\n\n"
                      "class Plugin(base_plugin.BasePlugin):\n"
                      "    def on_plugin_load(self):\n"
                      "        import android_utils\n"
                      "        android_utils.log('dexmem=%d' % _ceps_dex_len())\n")

        r = cb.build_project(proj, note="memenc-test")
        man = r["manifest"]

        # enc_v2: без магии и plain, с hmac
        enc = [f for f in man["files"] if f.get("enc")]
        assert enc and all("plain" not in f and f.get("hmac") for f in enc)
        zf = r["files"] if "files" in r else None
        import zipfile
        z = zipfile.ZipFile(r["outputs"]["ceps"])
        assert not any(z.read(f["del"]).startswith(rt.ENC_MAGIC) for f in enc), \
            "магия CEPSENC1 осталась в enc-файлах!"
        print("[1] enc_v2: магии нет, plain нет, hmac есть: OK")

        # гидрация с target_dir: dex НЕ появляется на диске, ceps_dex() работает
        cache = os.path.join(tmp, "cache")
        blob = open(r["outputs"]["ceps"], "rb").read()
        # забираем master через verify (shares-режим, source-RT под 3.13)
        manifest = json.loads(z.read(rt.MANIFEST_PATH).decode("utf-8"))
        pubkey_hex = rt.ed25519_pubkey(cb.load_seed(
            os.path.join(proj, cfg["key"]))).hex()
        gt, gseal = rt._CEPS_GUARD, rt._ceps_guard_seal()
        cls = rt.load_ceps_blob(blob, pubkey_hex, manifest["shares"], [],
                                manifest["master_check"], manifest["entry"],
                                target_dir=cache, guard_table=gt,
                                guard_seal=gseal)
        inst = cls()
        inst.on_plugin_load()
        dex_on_disk = [n for n in os.listdir(cache) if n.endswith(".dex")]
        assert not dex_on_disk, "dex материализовался на диск: %s" % dex_on_disk
        logs = [l for l in fakesdk.LOGS if l.startswith("dexmem=")]
        assert logs and int(logs[0].split("=")[1]) == 2052, fakesdk.LOGS[-5:]
        print("[2] dex живёт только в памяти, ceps_dex() отдал 2052 байта: OK")

        # двойная гидрация: старых копий в кэше быть не должно
        fakesdk.LOGS.clear()
        cls2 = rt.load_ceps_blob(blob, pubkey_hex, manifest["shares"], [],
                                 manifest["master_check"], manifest["entry"],
                                 target_dir=cache, guard_table=gt,
                                 guard_seal=gseal)
        cls2().on_plugin_load()
        assert not [n for n in os.listdir(cache) if n.endswith(".dex")]
        print("[3] повторная гидрация не создаёт dex-файл: OK")

        print("\nMEM-ENC TEST: PASS")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
