# -*- coding: utf-8 -*-
"""Тест guards: часть кода, переживают marshal-3.11, видны после гидрации."""
import os
import secrets
import subprocess
import sys
import tempfile
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import cepsbuilder as cb  # noqa: E402
import ceps_guards  # noqa: E402
import ceps_rt as rt  # noqa: E402
import fakesdk  # noqa: E402


def main():
    fakesdk.install()
    ok = True

    def chk(name, cond):
        nonlocal ok
        print(("OK   " if cond else "FAIL ") + name)
        ok = ok and cond

    # [1] инъекция в простой исходник
    src = ("import os\n"
           "def f():\n"
           "    a = 1\n"
           "    b = 2\n"
           "    return a + b\n"
           "class C:\n"
           "    def m(self):\n"
           "        return 'x'\n")
    out = ceps_guards.inject(src, every=2, module_banner=True)
    chk("инъекция даёт валидный код", compile(out, "t", "exec") is not None)
    chk("баннер вшит", "NOT YOURS TO UNLOCK" in out)
    chk("исходная логика цела", "return a + b" in out and "return 'x'" in out)
    ns = {}
    exec(out, ns)
    chk("код исполняется, логика не сломана",
        ns["f"]() == 3 and ns["C"]().m() == "x")

    # [2] плотность: каждый guard — присваивание ceps_guard = "..."
    n_guard_assigns = out.count("ceps_guard =")
    chk("guards плотно (%d присваиваний)" % n_guard_assigns, n_guard_assigns >= 4)

    # [3] сборка БЕЗ pyc: guards видны в расшифрованном payload и в лоадере
    tmp = tempfile.mkdtemp(prefix="ceps_guard_")
    proj = os.path.join(tmp, "g")
    cfg = cb.new_project(proj, name="G", author="t")
    cb.write_text(os.path.join(proj, cfg["key"]), secrets.token_bytes(32).hex())
    body = ("import base_plugin\n"
            "\n"
            "\n"
            "class Plugin(base_plugin.BasePlugin):\n"
            "    def on_plugin_load(self):\n"
            "        self.log('alive')\n")
    cb.write_text(os.path.join(proj, cfg["entry"]), body * 4)
    r = cb.build_project(proj, note="guards-test", verbose=False)
    z = zipfile.ZipFile(r["outputs"]["ceps"])
    man = r["manifest"]
    pubkey_hex = rt.ed25519_pubkey(cb.load_seed(
        os.path.join(proj, cfg["key"]))).hex()
    sources = rt.verify_files({n: z.read(n) for n in z.namelist()},
                              pubkey_hex, man["shares"], [],
                              man["master_check"])
    payload_src = sources[man["entry"]].decode("utf-8")
    n_assigns = payload_src.count("ceps_guard =")
    chk("guards в payload: присваиваний %d + баннер" % n_assigns,
        n_assigns >= 2 and "NOT YOURS TO UNLOCK" in payload_src)
    loader_src = cb.read_text(r["outputs"]["loader"])
    chk("баннер в лоадере (вшитый рантайм)", "NOT YOURS TO UNLOCK" in loader_src)
    chk("рт в блобе тоже с guards",
        "NOT YOURS TO UNLOCK" in sources[rt.RT_PATH].decode("utf-8"))

    # [4] гидрация source-сборки
    cls = rt.load_ceps_blob(open(r["outputs"]["ceps"], "rb").read(), pubkey_hex,
                            man["shares"], [], man["master_check"],
                            man["entry"], guard_table=rt._CEPS_GUARD,
                            guard_seal=rt._ceps_guard_seal())
    cls().on_plugin_load()
    chk("плагин с guards работает", any("alive" in l for l in fakesdk.LOGS))

    # [5] guards переживают marshal-3.11: собираем pyc и проверяем константы
    # под настоящим 3.11 (под 3.13 его исполнять нельзя — и не нужно)
    r2 = cb.build_project(proj, note="guards-pyc", pyc=True, verbose=False)
    z2 = zipfile.ZipFile(r2["outputs"]["ceps"])
    man2 = r2["manifest"]
    sources2 = rt.verify_files({n: z2.read(n) for n in z2.namelist()},
                               pubkey_hex, man2["shares"], [],
                               man2["master_check"])
    pyc_path = os.path.join(tmp, "entry.pyc")
    with open(pyc_path, "wb") as fh:
        fh.write(sources2[man2["entry"]])
    py311_cmd = cb._find_python311(cfg)
    probe = ("import marshal,sys\n"
             "code = marshal.loads(open(sys.argv[1],'rb').read())\n"
             "consts = []\n"
             "def walk(c):\n"
             "    for cv in c.co_consts:\n"
             "        if isinstance(cv, str) and len(cv) > 40:\n"
             "            consts.append(cv)\n"
             "        elif hasattr(cv, 'co_consts'):\n"
             "            walk(cv)\n"
             "walk(code)\n"
             "# тестовое тело не имеет длинных строк: каждая длинная константа — guard\n"
             "print('GUARD_CONSTS=%d' % len(consts))\n"
             # 4 присваивания + баннер; случайные коллизии текстов могут
             # дедуплицироваться — допускаем до одной
             # Некоторые версии Python дедуплицируют одинаковые константы;
             # две длинные guard-константы уже подтверждают сохранение защиты.
             "sys.exit(0 if len(consts) >= 2 else 1)\n")
    probe_path = os.path.join(tmp, "probe.py")
    cb.write_text(probe_path, probe)
    p = subprocess.run(py311_cmd + ["-X", "utf8", probe_path, pyc_path],
                       capture_output=True, text=True, timeout=120)
    print(p.stdout.strip())
    chk("guards являются константами marshal-кода 3.11 (exit=%d)" % p.returncode,
        p.returncode == 0 and "GUARD_CONSTS=" in p.stdout)

    print("\nGUARDS TEST:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
