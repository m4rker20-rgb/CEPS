# -*- coding: utf-8 -*-
# Built with CEPS — https://github.com/m4rker20-rgb/CEPS (формат CEPS-1).
# Не редактируй — правки ломают подпись.
# CEPS Installer: принимает .ceps файлы в чате; собирается make_installer.py.

import io
import json
import os
import zipfile

from base_plugin import BasePlugin, HookResult
from client_utils import get_last_fragment
from file_utils import (
    FilesController,
    ensure_dir_exists,
    get_plugins_dir,
    read_file_bytes,
    write_file,
)
from ui.alert import AlertDialogBuilder
from ui.bulletin import BulletinHelper
from ui.settings import Divider, Header, Input, Switch, Text

@@GUARD_BLOCK@@

CEPS_RT_SRC = @@CEPS_RT_SRC@@

_ENC_MAGIC = b"CEPSENC1"
_MANIFEST = "ceps/manifest.json"
_CHAIN = "ceps/chain.json"


def _rt():
    global _RT_NS
    try:
        return _RT_NS
    except NameError:
        ns = {}
        exec(compile(CEPS_RT_SRC, "<ceps_rt>", "exec"), ns)
        _RT_NS = ns
        return ns


def verify_blob(blob, trusted_keys):
    _ceps_seal()
    try:
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            files = {i.filename.replace("\\", "/"): zf.read(i)
                     for i in zf.infolist() if not i.is_dir()}
    except Exception as e:
        raise ValueError("файл не читается как CEPS-архив: %s" % e)

    if _MANIFEST not in files:
        raise ValueError("это не CEPS-архив (нет манифеста)")
    try:
        manifest = json.loads(files[_MANIFEST].decode("utf-8"))
    except Exception as e:
        raise ValueError("манифест повреждён: %s" % e)

    if manifest.get("format") != "CEPS-1":
        raise ValueError("неподдерживаемый формат: %r" % manifest.get("format"))

    # CEPS-3 (env): ключа в архиве нет — расшифровка невозможна и не нужна.
    # Ставим по структурной проверке verify_structure (подпись + целостность).
    if manifest.get("env_slots"):
        last_err = None
        for pub in trusted_keys:
            try:
                _rt()["verify_structure"](files, pub)
                return manifest, pub
            except Exception as e:
                last_err = e
        raise ValueError("подпись не подтверждена ни одним доверенным ключом (%s). "
                         "Автор должен прислать свой pubkey." % (last_err or "нет ключей"))

    shares = manifest.get("shares")
    if not shares:
        raise ValueError("в архиве нет долей ключа и нет env-слотов — "
                         "проси у автора .py лоадер вместо .ceps")

    last_err = None
    for pub in trusted_keys:
        try:
            _rt()["verify_files"](files, pub, shares, [], manifest["master_check"])
            return manifest, pub
        except Exception as e:
            last_err = e
    raise ValueError("подпись не подтверждена ни одним доверенным ключом (%s). "
                     "Автор должен прислать свой pubkey." % (last_err or "нет ключей"))


def make_loader_from_manifest(manifest, pubkey_hex, blob):
    meta = manifest["meta"]
    cfg = {
        "id": meta["id"],
        "name": meta["name"],
        "description": meta.get("description", ""),
        "author": meta.get("author", ""),
        "version": str(meta.get("version", "1.0.0")),
        "icon": meta.get("icon", "exteraPlugins/1"),
        "app_version": meta.get("app_version", ">=12.5.1"),
        "sdk_version": meta.get("sdk_version", ">=1.4.5.0"),
    }
    return _rt()["make_loader"](cfg, pubkey_hex, manifest.get("shares", ()),
                                manifest.get("env_slots", []),
                                manifest["master_check"], manifest["entry"],
                                blob, CEPS_RT_SRC)


class CepsInstallerPlugin(BasePlugin):

    def on_plugin_load(self):
        self._reg_secret = None
        try:
            self._reg_secret = FilesController.register(
                FilesController.FileInfo(ext="ceps", on_click=self._on_ceps_click))
        except Exception as e:
            self.log("FilesController.register failed: %s" % e)
        self.log("CEPS Installer loaded")

    def on_plugin_unload(self):
        if self._reg_secret:
            try:
                FilesController.unregister("ceps", self._reg_secret)
            except Exception:
                pass

    def _on_ceps_click(self, args):
        try:
            path = args.file.getAbsolutePath()
        except Exception:
            BulletinHelper.show_error("CEPS: не удалось получить путь к файлу")
            return
        data = read_file_bytes(path)
        if not data:
            BulletinHelper.show_error("CEPS: сначала скачай файл полностью")
            return
        try:
            manifest, pub = verify_blob(data, self._trusted())
        except ValueError as e:
            BulletinHelper.show_error("CEPS: %s" % e)
            return
        meta = manifest["meta"]
        self._confirm_install(manifest, pub, data, meta, args)

    def _confirm_install(self, manifest, pub, blob, meta, args):
        frag = getattr(args, "parent_fragment", None) or get_last_fragment()
        activity = frag.getParentActivity() if frag else None
        if activity is None:
            self._do_install(manifest, pub, blob, meta)
            return
        builder = AlertDialogBuilder(activity)
        builder.set_title("Установить CEPS-плагин?")
        builder.set_message(
            "%s v%s\nАвтор: %s\nid: %s\n\nПодпись проверена доверенным ключом.\n"
            "Будет создан файл плагина %s.py — включи его в Настройки → Плагины."
            % (meta["name"], meta.get("version", "?"), meta.get("author", "?"),
               meta["id"], meta["id"]))
        builder.set_positive_button(
            "Установить", lambda b, w: (self._do_install(manifest, pub, blob, meta), b.dismiss()))
        builder.set_negative_button("Отмена", lambda b, w: b.dismiss())
        builder.show()

    def _do_install(self, manifest, pub, blob, meta):
        try:
            loader = make_loader_from_manifest(manifest, pub, blob)
            ensure_dir_exists(get_plugins_dir())
            target = os.path.join(get_plugins_dir(), "%s.py" % meta["id"])
            if os.path.exists(target) and not self.get_setting("allow_overwrite", True):
                BulletinHelper.show_error(
                    "CEPS: %s.py уже установлен (перезапись выключена)" % meta["id"])
                return
            write_file(target, loader)
            BulletinHelper.show_info(
                "CEPS: установлено «%s». Включи плагин в Настройки → Плагины." % meta["name"])
        except Exception as e:
            BulletinHelper.show_error("CEPS: установка не удалась: %s" % e)

    def _trusted(self):
        keys = self.get_setting("trusted_keys", []) or []
        return [k for k in keys if isinstance(k, str) and k]

    def _on_add_key(self, new_value):
        v = (new_value or "").strip().lower()
        if len(v) != 64 or any(c not in "0123456789abcdef" for c in v):
            BulletinHelper.show_error("CEPS: нужен hex-ключ из 64 символов")
            return
        keys = self._trusted()
        if v not in keys:
            keys.append(v)
            self.set_setting("trusted_keys", keys)
            self.set_setting("add_key", "", reload_settings=True)
            BulletinHelper.show_info("CEPS: ключ добавлен")

    def _remove_key(self, key):
        keys = [k for k in self._trusted() if k != key]
        self.set_setting("trusted_keys", keys, reload_settings=True)
        BulletinHelper.show_info("CEPS: ключ удалён")
        return True

    def create_settings(self):
        rows = [
            Header(text="CEPS Installer"),
            Text(text="Как пользоваться",
                 subtext="Тапни .ceps файл в любом чате — после проверки подписи плагин установится",
                 icon="msg_info"),
            Divider(text="Устанавливаются только архивы, подписанные одним из ключей ниже."),
            Header(text="Доверенные ключи"),
        ]
        keys = self._trusted()
        if not keys:
            rows.append(Text(text="Ключей пока нет",
                             subtext="Установки будут отклоняться",
                             red=True, icon="msg_error"))
        for k in keys:
            rows.append(Text(text=k[:16] + "…",
                             subtext="Долгое нажатие — удалить",
                             icon="msg_list",
                             on_long_click=lambda v, _k=k: self._remove_key(_k)))
        rows.append(Input(key="add_key",
                          text="Добавить ключ (64 hex)",
                          subtext="Публичный ключ автора плагинов",
                          default="",
                          icon="msg_edit",
                          on_change=self._on_add_key))
        rows.append(Switch(key="allow_overwrite",
                           text="Разрешить перезапись плагинов",
                           default=True,
                           icon="msg_settings"))
        return rows
