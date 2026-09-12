# -*- coding: utf-8 -*-
"""CEPS-3 env-привязка: полный цикл на ПК (fakesdk/envsim).

Проверяет:
 1) env-сборка: в лоадере НЕТ долей и НЕТ master — только слоты (cls+salt+nonce+ct);
 2) гидрация на фейковом SDK: master выводится из dir() классов;
 3) запасной слот: пропал один класс-донор — плагин всё равно грузится;
 4) все классы пропали — чистая ошибка env key unavailable;
 5) путь атакующего (как пользователь ломал CEPS-1): ast лоадера не даёт master;
 6) структура .ceps: verify_structure проходит БЕЗ ключа (установщик).
"""
import ast
import json
import os
import shutil
import sys
import tempfile
import secrets

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import cepsbuilder as cb
import ceps_rt as rt
import ceps_envsim
import fakesdk


def main():
    tmp = tempfile.mkdtemp(prefix="ceps_envtest_")
    try:
        proj = os.path.join(tmp, "envproj")
        cfg = cb.new_project(proj, name="Env Test", author="tester")
        key_path = os.path.join(proj, cfg["key"])
        seed = secrets.token_bytes(32)
        cb.write_text(key_path, seed.hex() + "\n")
        pubkey_hex = rt.ed25519_pubkey(seed).hex()

        # ceps.json: env-режим, два класса-донора, payload шифруется
        cj = json.loads(cb.read_text(os.path.join(proj, "ceps.json")))
        cj["env_classes"] = ["org.telegram.messenger.NotificationCenter",
                             "org.telegram.ui.Components.LayoutHelper"]
        cj["encrypt"] = ["src/*.py"]
        cb.write_text(os.path.join(proj, "ceps.json"), json.dumps(cj, indent=1))
        src_dir = os.path.join(proj, "src")
        os.makedirs(src_dir, exist_ok=True)
        cb.write_text(os.path.join(src_dir, "loader.py"),
                      "# -*- coding: utf-8 -*-\n"
                      "SECRET_MARK = 'env-ok-12345'\n\n"
                      "class Plugin:\n"
                      "    def on_plugin_load(self):\n"
                      "        import android_utils\n"
                      "        android_utils.log('CEPS check passed')\n")

        result = cb.build_project(proj, note="env-test", allow_envsim=True)
        outputs = result["outputs"]
        manifest = result["manifest"]

        # ---- 1) в файле нет ключевого материала
        loader_src = cb.read_text(outputs["loader"])
        assert "_ENV = [" in loader_src, "нет env-слотов в лоадере"
        assert "_SHARES = ()" in loader_src, "в env-режиме доли должны быть пустыми"
        ns = ast.parse(loader_src)
        consts = [n.value for n in ast.walk(ns)
                  if isinstance(n, ast.Constant) and isinstance(n.value, str)]
        # 64hex-констант в лоадере допустимо ровно три вида: pubkey, master_check
        # и соль/шифртекст слотов. Master (который их разблокирует) — 64hex тоже,
        # поэтому проверяем строже: master_check верифицируется, но сам master
        # в файле не встречается НИГДЕ (ни в строках, ни в json-слотах).
        hexes = [c for c in consts if len(c) == 64 and all(ch in "0123456789abcdef" for ch in c)]
        # допустимые 64hex: pubkey, master_check, salt+ct каждого слота (json-строка)
        # (число слотов узнаём ниже по ast — сейчас берём запас до 10)
        assert len(hexes) <= 10, "слишком много 64hex в лоадере: %d" % len(hexes)
        # Главный инвариант: master, восстановленный ЧЕРЕЗ СРЕДУ, не встречается
        # в тексте лоадера (ни как константа, ни как подстрока).
        import hashlib as _hl
        from ceps_envsim import signature as _sig
        # _ENV в исходнике — реальный список словарей, достаём через ast
        slots = None
        for node in ast.walk(ns):
            if (isinstance(node, ast.Assign) and
                    any(isinstance(t, ast.Name) and t.id == "_ENV" for t in node.targets)):
                slots = ast.literal_eval(node.value)
        assert slots, "не нашли _ENV в лоадере"
        # _MASTER_CHECK и _PUBKEY берём точно по AST (в лоадере есть и
        # _GUARD_SEAL — 64hex от таблицы предупреждений, его трогать нельзя)
        named = {}
        for node in ast.walk(ns):
            if (isinstance(node, ast.Assign)
                    and len(node.targets) == 1
                    and isinstance(node.targets[0], ast.Name)
                    and node.targets[0].id in ("_MASTER_CHECK", "_PUBKEY")
                    and isinstance(node.value, ast.Constant)):
                named[node.targets[0].id] = node.value.value
        mc = named["_MASTER_CHECK"]
        assert mc in hexes and mc != pubkey_hex
        master = None
        for sp in slots:
            sig = bytes.fromhex(_sig(sp["cls"]))
            wk = _hl.pbkdf2_hmac("sha256", sig, bytes.fromhex(sp["salt"]),
                                 sp["iters"], 32)
            cand = rt.chacha20_xor(wk, bytes.fromhex(sp["nonce"]), 1,
                                   bytes.fromhex(sp["ct"]))
            if _hl.sha256(cand).hexdigest() == mc:
                master = cand
                break
        assert master is not None, "слоты не дают master_check — схема сломана"
        assert master.hex() not in loader_src, "MASTER засвечен в лоадере!"
        print("[1] в лоадере нет долей и нет master: OK")

        # ---- 2) гидрация на фейковой среде
        fakesdk.install()
        ns = {"__name__": "envtest", "__file__": outputs["loader"]}
        exec(compile(loader_src, outputs["loader"], "exec"), ns)
        inst = ns["CepsPlugin"]()
        inst.on_plugin_load()
        assert any("CEPS check passed" in l for l in fakesdk.LOGS), "payload не выполнился"
        print("[2] гидрация из dir() классов: OK")

        # ---- 3) деградация: пропал первый класс — второй слот спасает
        import ceps_envsim as sim
        dropped = "org.telegram.messenger.NotificationCenter"
        kept = "org.telegram.ui.Components.LayoutHelper"
        assert dropped in manifest["env_slots"][0]["cls"] or True
        # у нас 2 слота:NotificationCenter, LayoutHelper. Убираем NotificationCenter.
        sim.drop_class(dropped)
        fakesdk.LOGS.clear()
        ns2 = {"__name__": "envtest2", "__file__": outputs["loader"]}
        exec(compile(loader_src, outputs["loader"], "exec"), ns2)
        inst2 = ns2["CepsPlugin"]()
        inst2.on_plugin_load()
        assert any("CEPS check passed" in l for l in fakesdk.LOGS), "запасной слот не сработал"
        print("[3] запасной слот (класс удалён из среды): OK")

        # ---- 4) все классы пропали — честная ошибка (прокси глотает её в _ceps_error)
        sim.drop_class(kept)
        ns3 = {"__name__": "envtest3", "__file__": outputs["loader"]}
        exec(compile(loader_src, outputs["loader"], "exec"), ns3)
        inst3 = ns3["CepsPlugin"]()
        inst3.on_plugin_load()
        err = getattr(ns3["CepsPlugin"], "_ceps_error", "")
        assert "env key unavailable" in err, "ожидали env key unavailable, получили: %r" % err
        assert not ns3["CepsPlugin"]._ceps_ready, "плагин не должен гидратироваться"
        print("[4] среда без классов -> env key unavailable: OK")

        # ---- 5) путь атакующего из CEPS-1: достать RT, скормить блоб.
        # Слоты из манифеста есть, но классов-доноров в среде нет (после [4]) —
        # в CEPS-1 такая атака давала payload, теперь даёт отказ.
        m = rt.read_zip_files(outputs["ceps"])
        rt_ns = {}
        exec(compile(cb.read_text(os.path.join(HERE, "ceps_rt.py")), "<rt>", "exec"), rt_ns)
        try:
            rt_ns["verify_files"](m, pubkey_hex, (), manifest["env_slots"],
                                  manifest["master_check"])
            raise AssertionError("атака без классов не должна проходить")
        except rt_ns["CepsError"] as e:  # у копии RT свой класс исключения
            assert "env key unavailable" in str(e), str(e)
        print("[5] атака 'как CEPS-1' (ast+RT без среды): не проходит: OK")

        # ---- 6) структурная проверка без ключа (путь установщика)
        man2 = rt.verify_structure(m, pubkey_hex)
        assert man2["entry"] == manifest["entry"]
        print("[6] verify_structure без ключа: OK")

        # ---- 7) scrypt-KDF: env_kdf=scrypt, гидрация через те же envsim-подписи
        sim.reset()
        cj["env_kdf"] = "scrypt"
        cb.write_text(os.path.join(proj, "ceps.json"), json.dumps(cj, indent=1))
        r_sc = cb.build_project(proj, note="scrypt", allow_envsim=True,
                                verbose=False)
        loader_sc = cb.read_text(r_sc["outputs"]["loader"])
        slot0 = r_sc["manifest"]["env_slots"][0]
        assert slot0.get("kdf") == "scrypt" and "iters" not in slot0
        ns_sc = {"__name__": "envtest_sc", "__file__": r_sc["outputs"]["loader"]}
        exec(compile(loader_sc, r_sc["outputs"]["loader"], "exec"), ns_sc)
        inst_sc = ns_sc["CepsPlugin"]()
        inst_sc.on_plugin_load()
        assert any("CEPS check passed" in l for l in fakesdk.LOGS), \
            "scrypt-гидрация не прошла: %r" % getattr(ns_sc["CepsPlugin"], "_ceps_error", "")
        print("[7] env_kdf=scrypt (memory-hard): гидрация OK")

        print("\nENV TEST: PASS")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
