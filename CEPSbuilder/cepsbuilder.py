# -*- coding: utf-8 -*-
"""
CEPSbuilder — сборщик защищённых плагинов формата CEPS-1 для exteraGram.

Команды:
  python cepsbuilder.py keygen --out KEY [--force]
  python cepsbuilder.py new PROJECT --name "My Plugin" --author you [--id ID] [--desc TEXT]
  python cepsbuilder.py build PROJECT [-o OUT] [--note TEXT] [-v] [--elyx]
  python cepsbuilder.py verify ARCHIVE.ceps (--key KEY | --pubkey HEX)
  python cepsbuilder.py selftest

Результат build (в <project>/builds/):
  <id>.ceps — каноничный защищённый контейнер (НЕ ставится напрямую)
  <id>.py   — одиночный файл-лоадер: ставится в exteraGram без Elyx
  <id>.eaf  — (--elyx) Elyx-обёртка с вложенным .ceps

Зависимости: только стандартная библиотека Python 3.10+.
"""

import argparse
import base64
import fnmatch
import hashlib
import json
import os
import re
import secrets
import shutil
import sys
import tempfile
import time
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import ceps_rt as rt  # noqa: E402

GENESIS_PREV = "0" * 64

DEMO_MAIN_TEMPLATE = '''# -*- coding: utf-8 -*-
# @@NAME@@ — каркас плагина exteraGram, защищается CEPSbuilder.
from typing import Any, List

from base_plugin import BasePlugin


class @@CLS@@(BasePlugin):
    def on_plugin_load(self):
        self.log("@@NAME@@: CEPS check passed, payload decrypted")

    def on_plugin_unload(self):
        self.log("@@NAME@@: unloaded")

    def create_settings(self) -> List[Any]:
        return [{"title": "@@NAME@@", "note": "protected by CEPS-1"}]
'''


# ---------------------------------------------------------------------------
# Утилиты
# ---------------------------------------------------------------------------

def read_bytes(path):
    with open(path, "rb") as fh:
        return fh.read()


def read_text(path):
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def write_text(path, text):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def normalize_id(name):
    s = name.strip().lower().replace(" ", "_")
    s = "".join(c for c in s if c.isalnum() or c in "_-")
    if not s or not s[0].isalpha():
        s = "p" + s
    return s[:32]


def class_name(name):
    parts = [p for p in "".join(c if c.isalnum() else " " for c in name).split() if p]
    s = "".join(p[:1].upper() + p[1:] for p in parts)
    if not s or not s[0].isalpha():
        s = "P" + s
    return s


def load_seed(key_path):
    seed = bytes.fromhex(read_text(key_path).strip())
    if len(seed) != 32:
        raise SystemExit("Файл ключа повреждён (нужен 64 hex-символа): %s" % key_path)
    return seed


def split_master(master):
    s1 = secrets.token_bytes(32)
    s2 = secrets.token_bytes(32)
    s3 = bytes(a ^ b ^ c for a, b, c in zip(master, s1, s2))
    return [s1.hex(), s2.hex(), s3.hex()]


def encrypt_file(master, logical_path, plain):
    """ENC v2: 12B nonce + ct — БЕЗ предсказуемой магии CEPSENC1.
    Целостность plaintext проверяется HMAC-ключом из master (см. build_project)."""
    nonce = secrets.token_bytes(12)
    file_key = hashlib.sha256(master + logical_path.encode("utf-8")).digest()
    return nonce + rt.chacha20_xor(file_key, nonce, 1, plain)


def plain_hmac(master, plain):
    key = hashlib.sha256(master + b"ceps-hmac-v1").digest()
    import hmac
    return hmac.new(key, plain, hashlib.sha256).hexdigest()


def load_config(project):
    cfg_path = os.path.join(project, "ceps.json")
    if not os.path.exists(cfg_path):
        raise SystemExit("В папке проекта нет ceps.json: %s" % project)
    cfg = json.loads(read_text(cfg_path))
    for req in ("id", "name", "author", "entry"):
        if req not in cfg:
            raise SystemExit("В ceps.json отсутствует поле: %s" % req)
    cfg.setdefault("version", "1.0.0")
    cfg.setdefault("icon", "exteraPlugins/1")
    cfg.setdefault("app_version", ">=12.5.1")
    cfg.setdefault("sdk_version", ">=1.4.5.0")
    cfg.setdefault("description", "")
    cfg.setdefault("encrypt", [])
    cfg.setdefault("exclude", [])
    cfg.setdefault("embed_shares", True)
    cfg.setdefault("env_classes", [])
    cfg.setdefault("key", os.path.join("ceps_keys", "%s.key" % cfg["id"]))
    return cfg


def walk_files(project, exclude_globs):
    collected = []
    for root, dirs, names in os.walk(project):
        dirs[:] = [d for d in dirs if d not in (".git", "__pycache__", "builds", "ceps_keys")]
        for name in names:
            rel = os.path.relpath(os.path.join(root, name), project).replace("\\", "/")
            if rel in ("ceps.json", "chain.json", ".gitignore"):
                continue
            if any(fnmatch.fnmatch(rel, g) for g in exclude_globs):
                continue
            collected.append((rel, os.path.join(project, rel)))
    return collected


# ---------------------------------------------------------------------------
# keygen / new
# ---------------------------------------------------------------------------

def cmd_keygen(args):
    out = os.path.abspath(args.out)
    if os.path.exists(out) and not args.force:
        print("Ключ уже существует: %s (--force для перезаписи)" % out)
        return 1
    seed = bytes.fromhex(args.seed) if args.seed else secrets.token_bytes(32)
    if len(seed) != 32:
        print("Seed должен быть 64 hex-символа")
        return 1
    write_text(out, seed.hex() + "\n")
    print("Приватный ключ: %s  (не показывай никому; в .gitignore)" % out)
    print("Публичный ключ: %s" % rt.ed25519_pubkey(seed).hex())
    return 0


def new_project(project, name, author, description="", plugin_id=None):
    project = os.path.abspath(project)
    if os.path.exists(project) and os.listdir(project):
        raise SystemExit("Папка не пуста: %s" % project)
    pid = normalize_id(plugin_id or name)
    os.makedirs(os.path.join(project, "src"), exist_ok=True)
    cfg = {
        "id": pid,
        "name": name,
        "description": description or ("CEPS-плагин: %s" % name),
        "author": author,
        "version": "1.0.0",
        "icon": "exteraPlugins/1",
        "app_version": ">=12.5.1",
        "sdk_version": ">=1.4.5.0",
        "entry": "src/main.py",
        "encrypt": ["src/*.py"],
        "exclude": [],
        "embed_shares": True,
        "key": "ceps_keys/%s.key" % pid,
    }
    write_text(os.path.join(project, "ceps.json"),
               json.dumps(cfg, ensure_ascii=False, indent=2) + "\n")
    demo = DEMO_MAIN_TEMPLATE.replace("@@NAME@@", name).replace("@@CLS@@", class_name(name))
    write_text(os.path.join(project, "src", "main.py"), demo)
    write_text(os.path.join(project, ".gitignore"), "ceps_keys/\nbuilds/\n__pycache__/\n")
    return cfg


def cmd_new(args):
    cfg = new_project(args.project, args.name, args.author, args.desc or "", args.id)
    key_path = os.path.join(os.path.abspath(args.project), cfg["key"])
    seed = None
    if not args.no_keygen:
        seed = secrets.token_bytes(32)
        write_text(key_path, seed.hex() + "\n")
    print("Проект создан: %s" % os.path.abspath(args.project))
    if seed is not None:
        print("Ключ подписи: %s" % key_path)
        print("Публичный ключ: %s" % rt.ed25519_pubkey(seed).hex())
    else:
        print("Дальше: python cepsbuilder.py keygen --out %s" % key_path)
    print("Сборка:  python cepsbuilder.py build %s" % args.project)
    return 0


# ---------------------------------------------------------------------------
# build
# ---------------------------------------------------------------------------

def _find_python311(cfg):
    """Найти интерпретатор 3.11 (телефонный рантайм) для компиляции в байткод.
    Порядок: ключ "python311" в ceps.json -> `py -3.11` -> известный путь uv."""
    cand = cfg.get("python311")
    if cand:
        if isinstance(cand, list):
            return cand
        if os.path.isfile(cand):
            return [cand]
    import shutil
    import subprocess
    py = shutil.which("py")
    if py:
        r = subprocess.run([py, "-3.11", "-c", "import sys;print(1)"],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if r.returncode == 0:
            return [py, "-3.11"]
    uv = os.path.join(os.path.expanduser("~"),
                      "AppData", "Roaming", "uv", "python",
                      "cpython-3.11.15-windows-x86_64-none", "python.exe")
    if os.path.isfile(uv):
        return [uv]
    raise SystemExit("--pyc: не найден Python 3.11 (укажи \"python311\" в ceps.json)")


def _compile_to_pyc(py311, src_bytes, name):
    """Скомпилировать исходник в marshal-байткод 3.11 (телефонный формат)."""
    import subprocess
    cmd = py311 + ["-c",
                   "import sys,marshal\n"
                   "code=compile(sys.stdin.buffer.read().decode('utf-8'),'<ceps>','exec')\n"
                   "sys.stdout.buffer.write(marshal.dumps(code))\n"]
    r = subprocess.run(cmd, input=src_bytes, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE)
    if r.returncode != 0 or not r.stdout.startswith(b"\xe3"):
        err = (r.stderr or b"").decode("utf-8", "replace")[-400:]
        raise SystemExit("--pyc: компиляция %s не удалась: %s" % (name, err))
    return r.stdout


def build_project(project, out_dir=None, note="", verbose=False, elyx=False,
                  obf=None, zlib_launcher=False, pyc=None, allow_envsim=False,
                  rt_pyc=None, mem_dex=None):
    project = os.path.abspath(project)
    cfg = load_config(project)
    # obf: None -> брать из ceps.json ("obfuscate"); иначе явный override
    if obf is None:
        obf = bool(cfg.get("obfuscate", False))
    # pyc: None -> брать из ceps.json ("pyc"); иначе явный override
    if pyc is None:
        pyc = bool(cfg.get("pyc", False))
    # rt_pyc: компилировать сам рантайм в marshal-3.11 (исходник не вшивается)
    if rt_pyc is None:
        rt_pyc = bool(cfg.get("rt_pyc", False))
    # mem_dex: entry-лоадер получает ceps_dex() вместо файлов на диске
    if mem_dex is None:
        mem_dex = bool(cfg.get("mem_dex", False))
    # enc_v2 включён всегда для env-режима; для legacy тоже (рантайм умеет оба)
    enc_v2 = True
    out_dir = os.path.abspath(out_dir or os.path.join(project, "builds"))
    os.makedirs(out_dir, exist_ok=True)

    obf_ctx = None
    if obf:
        import ceps_obf
        src_root = os.path.dirname(os.path.join(project, cfg["entry"]))
        obf_ctx = {
            "protected": ceps_obf.collectProtectedNames(src_root),
            "classes": ceps_obf.collectLocalClassNames(src_root),
            "cfg": cfg.get("obfuscation", {}),
            "launcher": bool(zlib_launcher or cfg.get("zlib_launcher", False)),
        }
    py311 = _find_python311(cfg) if (pyc or rt_pyc) else None
    _guard_rng = secrets.SystemRandom()

    key_path = cfg["key"]
    if not os.path.isabs(key_path):
        key_path = os.path.join(project, key_path)
    seed = load_seed(key_path)
    pubkey_hex = rt.ed25519_pubkey(seed).hex()

    rt_src = read_text(os.path.join(HERE, "ceps_rt.py"))
    if cfg.get("guards", True):
        # guards и в самом рантайме: баннер как отдельная инструкция —
        # переживает strip_for_embed (докстринги он вырезает)
        import ceps_guards
        rt_src = ceps_guards.inject(rt_src, every=4, max_per_file=250,
                                    rng=_guard_rng, docstrings=False,
                                    banner_mode="statement")
    if rt_pyc:
        # рантайм уезжает в marshal-3.11: в лоадере и в блобе не остаётся
        # ни одного питоновского исходника рантайма. Сюда же вшиваются
        # EXPECTED_GUARD_SEAL (второй затвор, пункт 4) и анти-дебаг (пункт 7).
        guard_block = rt._ceps_guard_block()
        gs_m = re.search(r'_GUARD_SEAL = "([0-9a-f]{64})"', guard_block)
        if not gs_m:
            raise SystemExit("internal: guard block без _GUARD_SEAL")
        patched = rt_src.replace(
            "EXPECTED_GUARD_SEAL = None",
            'EXPECTED_GUARD_SEAL = "%s"' % gs_m.group(1)).replace(
            "_ANTI_DEBUG = False",
            "_ANTI_DEBUG = %s" % ("True" if cfg.get("anti_debug", True) else "False"))
        if patched == rt_src:
            raise SystemExit("internal: не вшились EXPECTED_GUARD_SEAL/_ANTI_DEBUG")
        rt_marshal = _compile_to_pyc(
            py311, rt.strip_for_embed(patched).encode("utf-8"), "ceps_rt")
        rt_entry_path = rt.RT_PYC_PATH
        rt_entry_bytes = rt_marshal
        if verbose:
            print("  RT-PYC ceps_rt (%d байт, marshal 3.11)" % len(rt_marshal))
    else:
        rt_marshal = None
        rt_entry_path = rt.RT_PATH
        rt_entry_bytes = rt_src.encode("utf-8")

    master = secrets.token_bytes(32)
    shares = split_master(master)
    master_check = hashlib.sha256(master).hexdigest()

    # CEPS-3: env-привязка. Классы из cfg["env_classes"]; подписи берутся из
    # ceps_keys/env_sigs.json (реальные, снятые коллектором на телефоне),
    # при отсутствии — из ceps_envsim (ПК-заглушки, только для тестов).
    env_slots = []
    env_kdf = cfg.get("env_kdf", "pbkdf2")
    env_classes = cfg.get("env_classes") or []
    if env_classes:
        sigs_path = os.path.join(project, "ceps_keys", "env_sigs.json")
        captured = {}
        if os.path.exists(sigs_path):
            captured = json.loads(read_text(sigs_path))
        import ceps_envsim
        for cls_path in env_classes:
            if cls_path in captured:
                sig_hex = captured[cls_path]
            elif allow_envsim:
                try:
                    sig_hex = ceps_envsim.signature(cls_path)
                except Exception:
                    raise SystemExit(
                        "env-класс %r не найден ни в env_sigs.json, ни в envsim"
                        % cls_path)
            else:
                raise SystemExit(
                    "env-класс %r: нет подписи в ceps_keys/env_sigs.json.\n"
                    "Реальные подписи снимаются на телефоне: 'collect-env',\n"
                    "установить плагин-коллектор, тапнуть по классам.\n"
                    "(Для тестов: build --allow-envsim)" % cls_path)
            sig = bytes.fromhex(sig_hex)
            salt = secrets.token_bytes(16)
            nonce = secrets.token_bytes(12)
            slot = {"cls": cls_path, "salt": salt.hex(), "nonce": nonce.hex()}
            if env_kdf == "scrypt":
                slot["kdf"] = "scrypt"
                slot["kn"] = int(cfg.get("env_scrypt_n", 16384))
                slot["kr"] = int(cfg.get("env_scrypt_r", 8))
                slot["kp"] = int(cfg.get("env_scrypt_p", 1))
                try:
                    wrap_key = rt.kdf_work_key(slot, sig)
                except rt.CepsError as e:
                    raise SystemExit("env_kdf=scrypt недоступен на ПК сборки: %s" % e)
            else:
                slot["kdf"] = "pbkdf2"
                slot["iters"] = 100000
                wrap_key = rt.kdf_work_key(slot, sig)
            slot["ct"] = rt.chacha20_xor(wrap_key, nonce, 1, master).hex()
            env_slots.append(slot)
        if not captured:
            print("  ENV   WARNING: подписи из envsim (ПК) — на телефоне нужен collect-env")
    files = walk_files(project, cfg["exclude"])
    entry = cfg["entry"]
    if not any(rel == entry for rel, _ in files):
        raise SystemExit("entry-файл не найден: %s" % entry)

    def is_encrypted(rel):
        return any(fnmatch.fnmatch(rel, g) for g in cfg["encrypt"])

    entries = []
    delivered = {rt_entry_path: rt_entry_bytes}
    encrypted_count = 0
    for rel, fp in sorted(files):
        data = read_bytes(fp)
        if is_encrypted(rel):
            if obf_ctx and rel.endswith(".py"):
                text = data.decode("utf-8")
                try:
                    text = ceps_obf.applyObfuscationPipeline(
                        text, obf_ctx["protected"], secrets.randbelow(255) + 1,
                        obf_ctx["classes"], obf_ctx["cfg"])
                    if obf_ctx["launcher"]:
                        text = ceps_obf.applyZlibCompression(text)
                    compile(text, rel, "exec")  # обфускация не должна ломать синтаксис
                    data = text.encode("utf-8")
                    if verbose:
                        print("  OBF   %s (%d -> %d байт)" % (rel, len(read_bytes(fp)), len(data)))
                except Exception as e:
                    raise SystemExit("обфускация %s не удалась: %s" % (rel, e))
            if rel.endswith(".py") and cfg.get("guards", True):
                # анти-ИИ тексты как часть кода: константы + докстринги,
                # каждые ~3 инструкции, до pyc — живут в marshal-байткоде
                import ceps_guards
                try:
                    text = data.decode("utf-8")
                    text = ceps_guards.inject(
                        text, every=int(cfg.get("guards_every", 3)),
                        max_per_file=int(cfg.get("guards_max", 800)),
                        rng=_guard_rng, module_banner=rel == cfg["entry"])
                    compile(text, rel, "exec")
                    data = text.encode("utf-8")
                    if verbose:
                        print("  GUARD %s (+%d строк защиты)" % (rel, len(text.splitlines())))
                except Exception as e:
                    raise SystemExit("guards %s не удались: %s" % (rel, e))
            if pyc and rel.endswith(".py"):
                data = _compile_to_pyc(py311, data, rel)
                if verbose:
                    print("  PYC   %s (%d байт, marshal 3.11)" % (rel, len(data)))
            blob = encrypt_file(master, rel, data)
            short = hashlib.sha256(rel.encode("utf-8")).hexdigest()[:16]
            del_path = "payload/%s.enc" % short
            delivered[del_path] = blob
            enc_entry = {"path": rel, "del": del_path, "enc": True,
                         "size": len(blob),
                         "hash": hashlib.sha256(blob).hexdigest()}
            if enc_v2:
                # без "plain": HMAC от master не воспроизводим без ключа
                enc_entry["hmac"] = plain_hmac(master, data)
            else:
                enc_entry["plain"] = hashlib.sha256(data).hexdigest()
            entries.append(enc_entry)
            encrypted_count += 1
        else:
            delivered[rel] = data
            entries.append({"path": rel, "del": rel, "enc": False,
                            "size": len(data),
                            "hash": hashlib.sha256(data).hexdigest(),
                            "plain": hashlib.sha256(data).hexdigest()})
    entries.append({"path": rt_entry_path, "del": rt_entry_path, "enc": False,
                    "size": len(rt_entry_bytes),
                    "hash": hashlib.sha256(rt_entry_bytes).hexdigest(),
                    "plain": hashlib.sha256(rt_entry_bytes).hexdigest()})
    entries.sort(key=lambda e: e["del"])
    files_root = rt.merkle_root([(e["del"], e["hash"]) for e in entries])

    manifest = {
        "format": "CEPS-1",
        "entry": entry,
        "created": int(time.time()),
        "obfuscated": bool(obf_ctx),
        "meta": {k: cfg[k] for k in ("id", "name", "description", "author", "version",
                                     "icon", "app_version", "sdk_version")},
        "files": entries,
        "merkle_root": files_root,
        "master_check": master_check,
        "rt_sha256": hashlib.sha256(rt_entry_bytes).hexdigest(),
    }
    if cfg["embed_shares"] and not env_slots:
        manifest["shares"] = shares
    if env_slots:
        manifest["keying"] = "env"
        manifest["env_slots"] = env_slots
    if pyc:
        manifest["pyc"] = True
    if rt_pyc:
        manifest["rt_pyc"] = True
    if enc_v2:
        manifest["enc_v2"] = True
    if mem_dex:
        manifest["mem_dex"] = True
    if cfg.get("anti_debug", True):
        manifest["anti_debug"] = True

    # Цепочка блоков сборок (история живёт в проекте и переносится в архив).
    chain_path = os.path.join(project, "chain.json")
    chain = {"blocks": []}
    if os.path.exists(chain_path):
        chain = json.loads(read_text(chain_path))
    blocks = chain.get("blocks", [])
    prev = blocks[-1]["hash"] if blocks else GENESIS_PREV
    block = {"height": len(blocks), "ts": int(time.time()),
             "files_root": files_root, "note": note, "prev": prev}
    block["hash"] = rt.canonical_hash(block)
    blocks.append(block)
    signature = rt.ed25519_sign(seed, bytes.fromhex(block["hash"])).hex()
    chain_out = {"blocks": blocks, "signature": signature}

    ceps_path = os.path.join(out_dir, "%s.ceps" % cfg["id"])
    with zipfile.ZipFile(ceps_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(rt.MANIFEST_PATH, json.dumps(manifest, ensure_ascii=False, indent=1))
        zf.writestr(rt.CHAIN_PATH, json.dumps(chain_out, ensure_ascii=False, indent=1))
        for rel in sorted(delivered):
            zf.writestr(rel, delivered[rel])

    blob_bytes = read_bytes(ceps_path)
    loader = rt.make_loader(cfg, pubkey_hex, shares, env_slots, master_check,
                            entry, blob_bytes, rt_src, rt_marshal=rt_marshal)
    loader_path = os.path.join(out_dir, "%s.py" % cfg["id"])
    write_text(loader_path, loader)
    # .plugin — то же самое, что .py: exteraGram принимает переименованный
    # одиночный плагин (пример: visualverify.plugin). Кладём готовую копию.
    plugin_path = os.path.join(out_dir, "%s.plugin" % cfg["id"])
    write_text(plugin_path, loader)

    outputs = {"ceps": ceps_path, "loader": loader_path, "plugin": plugin_path}

    if elyx:
        meta_yml = "".join("%s: %s\n" % (k, json.dumps(v, ensure_ascii=False)) for k, v in (
            ("id", cfg["id"]), ("name", cfg["name"]), ("description", cfg["description"]),
            ("author", cfg["author"]), ("version", str(cfg["version"])),
            ("icon", cfg["icon"]), ("app_version", cfg["app_version"]),
            ("sdk_version", cfg["sdk_version"])))
        # main.py самодостаточен: блоб зашит внутрь, __file__ не нужен.
        eaf_main = rt.make_loader(cfg, pubkey_hex, shares, env_slots, master_check,
                                  entry, blob_bytes, rt_src, elyx=True,
                                  rt_marshal=rt_marshal)
        eaf_path = os.path.join(out_dir, "%s.eaf" % cfg["id"])
        with zipfile.ZipFile(eaf_path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("refmap.yml", "metainfo: meta.yml\nmain: main.py\n")
            zf.writestr("meta.yml", meta_yml)
            zf.writestr("main.py", eaf_main)
        outputs["eaf"] = eaf_path

    write_text(chain_path, json.dumps(chain_out, ensure_ascii=False, indent=1) + "\n")

    if verbose:
        for e in entries:
            print("  %s %s" % ("ENC  " if e["enc"] else "plain", e["del"]))
    print("CEPS:      %s (%d байт, зашифровано %d)" % (ceps_path, len(blob_bytes), encrypted_count))
    print("Лоадер .py: %s (%d байт) — то же содержимое" % (loader_path, os.path.getsize(loader_path)))
    print("Лоадер .plugin: %s — ставится в exteraGram напрямую" % plugin_path)
    if "eaf" in outputs:
        print("Elyx .eaf: %s" % outputs["eaf"])
    print("Блок #%d, подпись Ed25519, pubkey %s…" % (block["height"], pubkey_hex[:16]))
    return {"outputs": outputs, "manifest": manifest, "pubkey": pubkey_hex,
            "shares": shares, "block": block}


def cmd_build(args):
    build_project(args.project, args.out, args.note, args.verbose, args.elyx,
                  obf=args.obf, zlib_launcher=bool(getattr(args, "zlib", False)),
                  pyc=getattr(args, "pyc", None),
                  allow_envsim=bool(getattr(args, "allow_envsim", False)),
                  rt_pyc=getattr(args, "rt_pyc", None))
    return 0


def _project_snapshot(project):
    """Return a stable, cheap fingerprint of source/config files for watch mode."""
    rows = []
    for root, dirs, names in os.walk(project):
        dirs[:] = [d for d in dirs if d not in (".git", "__pycache__", "builds", "ceps_keys")]
        for name in names:
            path = os.path.join(root, name)
            rel = os.path.relpath(path, project).replace("\\", "/")
            try:
                stat = os.stat(path)
            except OSError:
                continue
            rows.append((rel, stat.st_mtime_ns, stat.st_size))
    return tuple(sorted(rows))


def cmd_watch(args):
    """Rebuild after source changes; --once makes this suitable for CI/smoke tests."""
    project = os.path.abspath(args.project)
    if not os.path.isdir(project):
        raise SystemExit("Проект не найден: %s" % project)
    previous = _project_snapshot(project)
    print("Watch: %s (интервал %.2f с, Ctrl+C для выхода)" % (project, args.interval))
    def rebuild():
        try:
            build_project(project, out_dir=args.out, note=args.note,
                          verbose=args.verbose, elyx=args.elyx,
                          obf=args.obf, zlib_launcher=args.zlib, pyc=args.pyc,
                          allow_envsim=args.allow_envsim, rt_pyc=args.rt_pyc)
            return True
        except (SystemExit, Exception) as exc:
            print("Watch: сборка не удалась: %s" % exc, file=sys.stderr)
            return False
    rebuild()
    try:
        while True:
            if args.once:
                return 0
            time.sleep(args.interval)
            current = _project_snapshot(project)
            if current == previous:
                continue
            previous = current
            print("Изменения обнаружены — запускаю сборку")
            rebuild()
    except KeyboardInterrupt:
        print("\nWatch остановлен")
        return 0


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------

def cmd_verify(args):
    if not args.key and not args.pubkey:
        print("Нужен --key или --pubkey")
        return 2
    if args.key:
        pubkey_hex = rt.ed25519_pubkey(load_seed(args.key)).hex()
    else:
        pubkey_hex = args.pubkey.strip().lower()

    files = rt.read_zip_files(args.archive)
    for req in (rt.MANIFEST_PATH, rt.CHAIN_PATH):
        if req not in files:
            print("FAIL: нет %s — это не CEPS-архив" % req)
            return 1
    manifest = json.loads(files[rt.MANIFEST_PATH].decode("utf-8"))
    chain = json.loads(files[rt.CHAIN_PATH].decode("utf-8"))

    prev = None
    for blk in chain.get("blocks", []):
        core = {k: blk[k] for k in ("height", "ts", "files_root", "note", "prev")}
        if rt.canonical_hash(core) != blk.get("hash"):
            print("FAIL: цепочка сломана на блоке #%s" % core["height"])
            return 1
        if prev is not None and core["prev"] != prev:
            print("FAIL: prev mismatch на блоке #%s" % core["height"])
            return 1
        prev = blk["hash"]
    last = chain["blocks"][-1]
    ok_sig = rt.ed25519_verify(bytes.fromhex(pubkey_hex), bytes.fromhex(last["hash"]),
                               bytes.fromhex(chain.get("signature", "")))
    print("Формат:           %s" % manifest.get("format"))
    print("Плагин:           %s v%s (id=%s)" % (manifest["meta"]["name"],
                                                manifest["meta"]["version"], manifest["meta"]["id"]))
    print("Блоков в цепочке: %d (последний #%d)" % (len(chain["blocks"]), last["height"]))
    print("Файлов:           %d (зашифровано %d)" % (
        len(manifest["files"]), sum(1 for f in manifest["files"] if f.get("enc"))))
    print("Merkle-корень:    %s" % manifest["merkle_root"])
    print("Подпись Ed25519:  %s" % ("VALID" if ok_sig else "INVALID"))
    if not ok_sig:
        return 1

    if manifest.get("env_slots") and not manifest.get("shares"):
        # CEPS-3: на ПК классов Telegram нет; структура проверяется без ключа,
        # полная расшифровка — только через реальные подписи (--envsigs).
        try:
            rt.verify_structure(files, pubkey_hex)
            print("Структура:        OK (подпись+целостность, без ключа)")
        except Exception as e:
            print("FAIL: %s" % e)
            return 1
        envsigs = getattr(args, "envsigs", None)
        if envsigs:
            sigs = json.loads(read_text(envsigs))
            master = None
            for sp in manifest["env_slots"]:
                sig = sigs.get(sp["cls"])
                if not sig:
                    continue
                wk = rt.kdf_work_key(sp, bytes.fromhex(sig))
                cand = rt.chacha20_xor(wk, bytes.fromhex(sp["nonce"]), 1,
                                       bytes.fromhex(sp["ct"]))
                if hashlib.sha256(cand).hexdigest() == manifest["master_check"]:
                    master = cand
                    break
            if master is None:
                print("FAIL: ни одна подпись из %s не дала master_check" % envsigs)
                return 1
            sources = {}
            hmac_key = hashlib.sha256(master + b"ceps-hmac-v1").digest()
            for f in manifest["files"]:
                dp = f.get("del") or f.get("path")
                data = files[dp]
                if f.get("enc"):
                    if manifest.get("enc_v2"):
                        nonce, cipher = data[:12], data[12:]
                    else:
                        nonce = data[len(rt.ENC_MAGIC):len(rt.ENC_MAGIC) + 12]
                        cipher = data[len(rt.ENC_MAGIC) + 12:]
                    fk = hashlib.sha256(master + f["path"].encode("utf-8")).digest()
                    plain = rt.chacha20_xor(fk, nonce, 1, cipher)
                    if f.get("hmac"):
                        import hmac as _hm
                        assert _hm.new(hmac_key, plain, hashlib.sha256).hexdigest() == f["hmac"], dp
                    elif f.get("plain") is not None:
                        assert hashlib.sha256(plain).hexdigest() == f["plain"], dp
                else:
                    plain = data
                sources[f["path"]] = plain
            print("Полная проверка:  OK по env-подписям (payload расшифрован, %d файлов)"
                  % len(sources))
        else:
            print("Расшифровка:      только на устройстве (env-привязка), "
                  "или передай --envsigs <ceps_keys/env_sigs.json>")
        return 0

    if manifest.get("shares"):
        try:
            sources = rt.verify_files(files, pubkey_hex, manifest["shares"], [],
                                      manifest["master_check"])
            print("Полная проверка:  OK (payload расшифрован, %d файлов)" % len(sources))
        except Exception as e:
            print("FAIL: %s" % e)
            return 1
    else:
        print("Полная проверка:  пропущена (ключ не встроен)")
    return 0


# ---------------------------------------------------------------------------
# selftest
# ---------------------------------------------------------------------------

def cmd_selftest(args):
    import fakesdk

    tmp = tempfile.mkdtemp(prefix="ceps_selftest_")
    try:
        proj = os.path.join(tmp, "ceps_selftest")
        cfg = new_project(proj, name="CEPS Selftest", author="tester")
        key_path = os.path.join(proj, cfg["key"])
        seed = secrets.token_bytes(32)
        write_text(key_path, seed.hex() + "\n")
        pubkey_hex = rt.ed25519_pubkey(seed).hex()

        result = build_project(proj, note="selftest", elyx=True)
        outputs = result["outputs"]

        # 1) verify_files напрямую
        files = rt.read_zip_files(outputs["ceps"])
        manifest = json.loads(files[rt.MANIFEST_PATH].decode("utf-8"))
        sources = rt.verify_files(files, pubkey_hex, manifest["shares"], [],
                                  manifest["master_check"])
        assert manifest["entry"] in sources, "entry не расшифрован"
        print("[1/5] verify_files + расшифровка: OK")

        # 2) подделка ловится
        bad = dict(files)
        enc_path = next(p for p in bad if p.startswith("payload/"))
        bad[enc_path] = bad[enc_path][:-1] + bytes([bad[enc_path][-1] ^ 1])
        try:
            rt.verify_files(bad, pubkey_hex, manifest["shares"], [],
                            manifest["master_check"])
            raise AssertionError("подделка не обнаружена!")
        except rt.CepsError:
            print("[2/5] детекция подделки payload: OK")

        # 3) лоадер .py/.plugin исполняется на фейковом SDK
        fakesdk.install()
        assert outputs["plugin"] != outputs["loader"]
        assert read_text(outputs["plugin"]) == read_text(outputs["loader"]), ".plugin должен быть копией .py"
        loader_src = read_text(outputs["loader"])
        ns = {"__name__": "ceps_selftest_loader", "__file__": outputs["loader"]}
        exec(compile(loader_src, outputs["loader"], "exec"), ns)
        inst = ns["CepsPlugin"]()
        inst.on_plugin_load()
        assert any("CEPS check passed" in l for l in fakesdk.LOGS), "on_plugin_load не дошёл до payload"
        rows = inst.create_settings()
        assert rows and rows[0]["title"] == "CEPS Selftest", "create_settings не делегировался"
        print("[3/5] одиночный лоадер .py (без Elyx): OK")

        # 4) испорченный блоб -> плагин отключается
        import re as _re
        m = _re.search(r'_BLOB = base64\.b85decode\(\n    "([!-~]+)"', loader_src)
        assert m, "не нашли b85-блок в лоадере"
        orig, repl = m.group(1)[0], ("Z" if m.group(1)[0] != "Z" else "Y")
        tampered = loader_src[:m.start(1)] + repl + loader_src[m.start(1) + 1:]
        ns2 = {"__name__": "ceps_tampered", "__file__": outputs["loader"]}
        exec(compile(tampered, "<tampered>", "exec"), ns2)
        inst2 = ns2["CepsPlugin"]()
        inst2.on_plugin_load()
        assert not ns2["CepsPlugin"]._ceps_ready, "проверка не сработала"
        assert any("integrity check failed" in l for l in fakesdk.LOGS)
        print("[4/5] битый блоб -> плагин отключён: OK")

        # 5) Elyx-обёртка
        eaf = outputs["eaf"]
        with zipfile.ZipFile(eaf) as zf:
            names = set(zf.namelist())
        assert {"refmap.yml", "meta.yml", "main.py"} <= names
        eaf_main = zipfile.ZipFile(eaf).read("main.py").decode("utf-8")
        assert "b85decode" in eaf_main, "elyx-загрузчик должен нести блоб внутри"
        prelude = eaf_main.split("_RT_SRC = ")[0]
        assert "__file__" not in prelude, "код лоадера не должен зависеть от __file__"
        print("[5/5] Elyx-обёртка .eaf: OK")

        print("\nSELFTEST: PASS")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
# collect-env: снятие подписей классов на реальном телефоне (CEPS-3)
# ---------------------------------------------------------------------------

_COLLECTOR_TEMPLATE = '''# -*- coding: utf-8 -*-
# CEPS-3 env-коллектор: снимает подписи классов на этом телефоне.
# Открой настройки плагина и тапни ОДНУ строку "СКОПИРОВАТЬ ВСЁ" —
# в буфер уйдёт готовый JSON. Отправь его автору, больше ничего не нужно.
# Этот плагин НЕ нужен пользователям: только автору, один раз перед сборкой.

__id__ = 'ceps_env_collector'
__name__ = 'CEPS Env Collector'
__author__ = '@Coder_Minecraft'
__version__ = '1.0.0'
__min_version__ = '11.9.0'
__icon__ = 'exteraPlugins/1'

import hashlib

from android_utils import copy_to_clipboard, log
from base_plugin import BasePlugin, HookResult
from ui.settings import Divider, Header, Text

_CLASSES = @@CLASSES@@


def _sig(cls_path):
    import hook_utils
    cls = hook_utils.find_class(cls_path)
    names = sorted(str(x) for x in dir(cls) if not str(x).startswith("__"))
    return hashlib.sha256("".join(names).encode("utf-8")).hexdigest()


class Plugin(BasePlugin):

    def create_settings(self):
        pairs = {}
        for cls_path in _CLASSES:
            try:
                pairs[cls_path] = _sig(cls_path)
            except Exception as e:
                pairs[cls_path] = "ERROR: " + str(e)[:60]

        def _copy_all(*_a, _pairs=dict(pairs)):
            text = "{%s}" % ", ".join(
                '"%s": "%s"' % (k, v) for k, v in _pairs.items())
            copy_to_clipboard(text)
            log("CEPS-3: JSON всех подписей скопирован")

        def _copy_one(*_a, _c=None, _s=None):
            copy_to_clipboard('"%s": "%s"' % (_c, _s))
            log("CEPS-3: подпись %s скопирована" % _c.rsplit(".", 1)[-1])

        rows = [Header(text="CEPS-3: подписи классов"),
                Text(text="СКОПИРОВАТЬ ВСЁ (отправь автору)",
                     subtext="тап — готовый JSON в буфер", on_click=_copy_all),
                Divider(text="По классам:")]
        for cls_path, sig in pairs.items():
            rows.append(Text(
                text=cls_path.rsplit(".", 1)[-1],
                subtext=sig[:32] + ("…" if not sig.startswith("ERROR") else ""),
                on_click=lambda *_a, _c=cls_path, _s=sig: _copy_one(_c=_c, _s=_s)))
        return rows
'''


def cmd_collect_env(args):
    project = os.path.abspath(args.project)
    cfg = load_config(project)
    classes = cfg.get("env_classes") or []
    if not classes:
        print("В ceps.json нет env_classes — добавь список классов-доноров.")
        return 1
    out_path = os.path.join(project, "env_collector.py")
    write_text(out_path, _COLLECTOR_TEMPLATE.replace("@@CLASSES@@", repr(classes)))
    print("Коллектор: %s" % out_path)
    print("1) собери его:  ceps build %s --note collector" % project)
    print("   (env_collector.py в шифрование не попадёт: он не в encrypt)")
    print("2) установи .plugin на телефон, открой настройки плагина")
    print("3) тапай по классам и вставляй пары в ceps_keys/env_sigs.json:")
    print('   {"org.telegram.messenger.NotificationCenter": "aabb..."}')
    print("4) пересобери проект обычным build — слоты будут из реальных подписей")
    return 0


# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(prog="ceps", description="CEPSbuilder — защищённая упаковка плагинов exteraGram")
    sub = ap.add_subparsers(dest="cmd", required=True)

    kg = sub.add_parser("keygen", help="сгенерировать пару ключей Ed25519")
    kg.add_argument("--out", required=True)
    kg.add_argument("--seed", help="64 hex-символа (по умолчанию случайный)")
    kg.add_argument("--force", action="store_true")
    kg.set_defaults(fn=cmd_keygen)

    nw = sub.add_parser("new", help="создать каркас проекта")
    nw.add_argument("project")
    nw.add_argument("--name", required=True)
    nw.add_argument("--author", required=True)
    nw.add_argument("--id", dest="id", help="id плагина (по умолчанию из имени)")
    nw.add_argument("--desc", help="описание")
    nw.add_argument("--no-keygen", action="store_true", help="не генерировать ключ")
    nw.set_defaults(fn=cmd_new)

    bd = sub.add_parser("build", help="собрать .ceps + лоадер")
    bd.add_argument("project")
    bd.add_argument("-o", "--out")
    bd.add_argument("--note", default="", help="пометка к блоку цепочки")
    bd.add_argument("--elyx", action="store_true", help="дополнительно собрать .eaf-обёртку")
    bd.add_argument("--obf", dest="obf", action="store_true", default=None,
                    help="обфускация шифруемых .py (ElyxBuilder AST-пайплайн)")
    bd.add_argument("--no-obf", dest="obf", action="store_false",
                    help="отключить обфускацию для этой сборки")
    bd.add_argument("--zlib", action="store_true",
                    help="дополнительно завернуть .py в zlib+base64 exec-лаунчер")
    bd.add_argument("--pyc", action="store_true", default=None,
                    help="компилировать .py в marshal-байткод 3.11 (в payload не остаётся исходников)")
    bd.add_argument("--allow-envsim", action="store_true",
                    help="разрешить env-сборку с ПК-заглушками (НЕ для телефона)")
    bd.add_argument("--rt-pyc", dest="rt_pyc", action="store_true", default=None,
                    help="рантайм тоже в marshal-3.11 (в артефактах нет исходника ceps_rt)")
    bd.add_argument("-v", "--verbose", action="store_true")
    bd.set_defaults(fn=cmd_build)

    wt = sub.add_parser("watch", help="следить за проектом и пересобирать при изменениях")
    wt.add_argument("project")
    wt.add_argument("-o", "--out")
    wt.add_argument("--interval", type=float, default=1.0, help="интервал проверки в секундах (по умолчанию 1)")
    wt.add_argument("--once", action="store_true", help="собрать один раз и завершиться (для CI)")
    wt.add_argument("--note", default="watch", help="пометка к блоку цепочки")
    wt.add_argument("--elyx", action="store_true")
    wt.add_argument("--obf", dest="obf", action="store_true", default=None)
    wt.add_argument("--no-obf", dest="obf", action="store_false")
    wt.add_argument("--zlib", action="store_true")
    wt.add_argument("--pyc", action="store_true", default=None)
    wt.add_argument("--allow-envsim", action="store_true")
    wt.add_argument("--rt-pyc", dest="rt_pyc", action="store_true", default=None)
    wt.add_argument("-v", "--verbose", action="store_true")
    wt.set_defaults(fn=cmd_watch)

    vf = sub.add_parser("verify", help="проверить .ceps архив")
    vf.add_argument("archive")
    vf.add_argument("--key", help="файл приватного ключа")
    vf.add_argument("--pubkey", help="hex публичного ключа")
    vf.add_argument("--envsigs", help="ceps_keys/env_sigs.json для полной проверки env-архива")
    vf.set_defaults(fn=cmd_verify)

    st = sub.add_parser("selftest", help="полный автотест на ПК")
    st.set_defaults(fn=cmd_selftest)

    ce = sub.add_parser("collect-env",
                        help="сгенерировать плагин-коллектор подписей классов (CEPS-3)")
    ce.add_argument("project")
    ce.set_defaults(fn=cmd_collect_env)

    args = ap.parse_args()
    sys.exit(args.fn(args))


if __name__ == "__main__":
    main()
