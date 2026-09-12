# -*- coding: utf-8 -*-
"""
make_installer.py — собирает ceps_installer.py из шаблона + встроенной копии
ceps_rt.py. Запускать после правки любого из них:

  python CEPSbuilder/make_installer.py
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def main():
    sys.path.insert(0, HERE)
    import ceps_rt
    rt_src = open(os.path.join(HERE, "ceps_rt.py"), "r", encoding="utf-8").read()
    tpl = open(os.path.join(HERE, "installer_template.py"), "r", encoding="utf-8").read()
    if "@@CEPS_RT_SRC@@" not in tpl:
        raise SystemExit("В шаблоне установщика нет маркера подстановки")
    out = tpl.replace("@@GUARD_BLOCK@@", ceps_rt._ceps_guard_block())
    # Вшиваем рантайм без комментариев и докстрингов — в собранных
    # артефактах остаётся только заголовок-предупреждение. Ткач прогоняем
    # по вшиваемому рантайму (salt=2, comments_only): рантайм исполняется
    # в чужом неймспейсе — исполняемые seal-стейтменты ему не нужны.
    rt_embed = ceps_rt.strip_for_embed(rt_src)
    rt_embed = ceps_rt._weave_guard(rt_embed, salt=2, comments_only=True)
    out = out.replace("@@CEPS_RT_SRC@@", repr(rt_embed))
    # ткач по самому установщику (salt=3) — его guard-блок уже в шаблоне
    out = ceps_rt._weave_guard(out, salt=3)
    compile(out, "<ceps_installer_gen>", "exec")
    dst = os.path.join(ROOT, "ceps_installer.py")
    with open(dst, "w", encoding="utf-8") as fh:
        fh.write(out)
    print("Собран установщик: %s (%d байт)" % (dst, len(out)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
