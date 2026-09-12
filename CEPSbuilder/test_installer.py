# -*- coding: utf-8 -*-
"""
test_installer.py — автотест CEPS Installer на ПК (фейковый SDK).

Проверяет полный цикл приёма .ceps:
  сборка -> verify доверенным ключом -> генерация лоадера -> исполнение ->
  отклонение чужой подписи -> отклонение подделанного архива.

  python CEPSbuilder/test_installer.py
"""

import json
import os
import secrets
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, ROOT)

import fakesdk  # noqa: E402
fakesdk.install()  # важно: до импорта ceps_installer
import cepsbuilder as cb  # noqa: E402
import ceps_rt as rt  # noqa: E402


def main():
    tmp = tempfile.mkdtemp(prefix="ceps_installer_test_")
    try:
        # 1) Собираем демо-плагин, как это делал бы автор.
        proj = os.path.join(tmp, "ceps_demo")
        cfg = cb.new_project(proj, name="CEPS Demo", author="tester")
        seed = secrets.token_bytes(32)
        key_path = os.path.join(proj, cfg["key"])
        cb.write_text(key_path, seed.hex() + "\n")
        pubkey = rt.ed25519_pubkey(seed).hex()
        result = cb.build_project(proj)
        blob = open(result["outputs"]["ceps"], "rb").read()

        # 2) Импортируем установщик (fakesdk уже установлен -> импорты SDK ок).
        import ceps_installer as ci

        # 3) Верификация доверенным ключом.
        manifest, got_pub = ci.verify_blob(blob, [pubkey])
        assert got_pub == pubkey
        print("[1/5] verify_blob доверенным ключом: OK")

        # 4) Чужая подпись отклоняется.
        try:
            ci.verify_blob(blob, ["ab" * 32])
            raise AssertionError("чужой ключ не отклонён!")
        except ValueError:
            print("[2/5] чужая подпись отклонена: OK")

        # 5) Подделанный архив отклоняется.
        bad = bytearray(blob)
        bad[len(bad) // 2] ^= 1
        try:
            ci.verify_blob(bytes(bad), [pubkey])
            raise AssertionError("подделка не обнаружена!")
        except Exception:
            print("[3/5] подделанный архив отклонён: OK")

        # 6) Установщик генерирует рабочий лоадер.
        loader = ci.make_loader_from_manifest(manifest, got_pub, blob)
        ns = {"__name__": "ceps_installed_demo", "__file__": "ceps_demo.py"}
        exec(compile(loader, "<ceps_demo.py>", "exec"), ns)
        inst = ns["CepsPlugin"]()
        inst.on_plugin_load()
        assert any("CEPS check passed" in l for l in fakesdk.LOGS), \
            "on_plugin_load не дошёл до payload"
        rows = inst.create_settings()
        assert rows and rows[0]["title"] == "CEPS Demo"
        print("[4/5] сгенерированный лоадер исполняется: OK")

        # 7) Настройки установщика: добавление/удаление доверенных ключей.
        plugin = ci.CepsInstallerPlugin()
        plugin._on_add_key(pubkey)
        assert pubkey in plugin._trusted()
        assert plugin._remove_key(pubkey) is True
        assert pubkey not in plugin._trusted()
        print("[5/5] управление доверенными ключами: OK")

        # 8) CEPS-3 env-архив: установка через структурную проверку (без ключа).
        proj2 = os.path.join(tmp, "ceps_env_demo")
        cfg2 = cb.new_project(proj2, name="CEPS Env", author="tester")
        seed2 = secrets.token_bytes(32)
        cb.write_text(os.path.join(proj2, cfg2["key"]), seed2.hex() + "\n")
        pubkey2 = rt.ed25519_pubkey(seed2).hex()
        cj2 = json.loads(cb.read_text(os.path.join(proj2, "ceps.json")))
        cj2["env_classes"] = ["org.telegram.messenger.NotificationCenter"]
        cb.write_text(os.path.join(proj2, "ceps.json"), json.dumps(cj2))
        src2 = os.path.join(proj2, "src")
        os.makedirs(src2, exist_ok=True)
        cb.write_text(os.path.join(src2, "loader.py"),
                      "class Plugin:\n"
                      "    def on_plugin_load(self):\n"
                      "        import android_utils\n"
                      "        android_utils.log('CEPS check passed')\n")
        r2 = cb.build_project(proj2, note="env-installer-test", allow_envsim=True)
        blob2 = open(r2["outputs"]["ceps"], "rb").read()
        man2, got2 = ci.verify_blob(blob2, [pubkey2])
        assert man2.get("keying") == "env" and got2 == pubkey2
        loader2 = ci.make_loader_from_manifest(man2, got2, blob2)
        fakesdk.LOGS.clear()
        ns2 = {"__name__": "ceps_installed_env", "__file__": "ceps_env.py"}
        exec(compile(loader2, "<ceps_env.py>", "exec"), ns2)
        inst2 = ns2["CepsPlugin"]()
        inst2.on_plugin_load()
        assert any("CEPS check passed" in l for l in fakesdk.LOGS), \
            "env-плагин не гидратировался через установщик"
        try:
            ci.verify_blob(blob2, ["cd" * 32])
            raise AssertionError("чужой ключ принял env-архив!")
        except ValueError:
            pass
        print("[6/6] env-архив ставится структурной проверкой: OK")

        print("\nTEST INSTALLER: PASS")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
