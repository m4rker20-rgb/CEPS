# -*- coding: utf-8 -*-
#
# Device Share — плагин exteraGram.
# Делится с теми, у кого стоит этот же плагин, информацией о том,
# с каких устройств ты сидишь: платформа всегда, бренд — для Android/iOS.
#
# Как это работает:
#   1. Плагин запрашивает твои сессии (TL_account_getAuthorizations).
#   2. В настройках ты отмечаешь, какие сессии публичные (по умолчанию — только текущая).
#   3. К каждому исходящему сообщению невидимо прикрепляется подписанный ключ
#      (zero-width символы в конце текста — данные внутри самого объекта сообщения).
#   4. Получатель с этим же плагином распознаёт ключ, запоминает устройства
#      отправителя и показывает их в меню его профиля → «Устройства».
#
# Честное ограничение: от «чтения» другими плагинами защититься нельзя
# (они видят то же сообщение). Здесь защита — обфускация формата + подпись
# HMAC, чтобы чужой/подделанный ключ не распознавался.

import hashlib
import hmac
import json
import os as _os
import time

from android.os import Build

from base_plugin import BasePlugin, HookResult, HookStrategy, MenuItemData, MenuItemType
from client_utils import (
    get_last_fragment,
    get_messages_controller,
    get_selected_account,
    get_user_config,
    send_request,
)
from org.telegram.tgnet import TLRPC
from ui.alert import AlertDialogBuilder
from ui.bulletin import BulletinHelper
from ui.settings import Divider, Header, Switch, Text

__id__ = "device_share"
__name__ = "Device Share"
__description__ = (
    "Делишься тем, с каких устройств ты сидишь, и видишь устройства тех, "
    "у кого стоит этот же плагин. Передаётся только платформа (и бренд для "
    "Android/iOS) и только те сессии, что отмечены публичными в настройках. "
    "Профиль → «Устройства»."
)
__author__ = "you"
__version__ = "1.0.0"
__icon__ = "exteraPlugins/1"
__app_version__ = ">=12.5.1"
__sdk_version__ = ">=1.4.5.0"

# ----------------------------------------------------------------------------
# Транспорт: невидимая упаковка данных в конец текста сообщения
# ----------------------------------------------------------------------------

# Маркер начала полезной нагрузки и алфавит из 4 невидимых символов (2 бита на
# символ, 4 символа = 1 байт). Telegram сохраняет их в сообщении как есть.
MARKER = "\u2063"  # invisible separator — начало ключа
ZW = ["\u200b", "\u200c", "\u200d", "\u2060"]
ZW_SET = frozenset(ZW) | {MARKER}


def _enc_zw(data):
    """bytes -> строка из невидимых символов (2 бита на символ)."""
    out = []
    for b in data:
        out.append(ZW[(b >> 6) & 3])
        out.append(ZW[(b >> 4) & 3])
        out.append(ZW[(b >> 2) & 3])
        out.append(ZW[b & 3])
    return "".join(out)


def _dec_zw(chars):
    """Список невидимых символов -> bytes, или None если битость не сошлась."""
    n = len(chars)
    if n == 0 or n % 4:
        return None
    out = bytearray()
    for i in range(0, n, 4):
        a = ZW.index(chars[i])
        b = ZW.index(chars[i + 1])
        c = ZW.index(chars[i + 2])
        d = ZW.index(chars[i + 3])
        out.append((a << 6) | (b << 4) | (c << 2) | d)
    return bytes(out)


# ----------------------------------------------------------------------------
# Криптоконтур: обфусцированный секрет, потоковый шифр на SHA-256, подпись HMAC
# ----------------------------------------------------------------------------

# Секрет закодирован (XOR с 0x5C), чтобы в дампе строки не читались глазами.
_OB = bytes([
    0x19, 0x7F, 0xA2, 0x4E, 0x33, 0xD1, 0x08, 0xC5,
    0xE1, 0x62, 0x9B, 0x40, 0x7A, 0x15, 0xFD, 0x8B,
    0x2C, 0x96, 0x51, 0xD8, 0x0E, 0xB4, 0x6F, 0x23,
    0xCA, 0x35, 0x9D, 0x71, 0x44, 0xAA, 0x1B, 0x8E,
])
_SECRET = bytes(b ^ 0x5C for b in _OB)
_K_ENC = hashlib.sha256(_SECRET + b"enc").digest()
_K_TAG = hashlib.sha256(_SECRET + b"tag").digest()


def _keystream_xor(key, nonce, data):
    """Потоковый XOR: ключевые блоки = SHA256(key || nonce || counter)."""
    out = bytearray()
    counter = 0
    for i in range(0, len(data), 32):
        block = hashlib.sha256(key + nonce + counter.to_bytes(4, "big")).digest()
        chunk = data[i:i + 32]
        out.extend(a ^ b for a, b in zip(chunk, block))
        counter += 1
    return bytes(out)


def _seal(plain):
    """Зашифровать и подписать: [0x44][0x01][len:2][nonce:4][cipher][tag:8]."""
    nonce = _os.urandom(4)
    cipher = _keystream_xor(_K_ENC, nonce, plain)
    tag = hmac.new(_K_TAG, nonce + cipher, hashlib.sha256).digest()[:8]
    body = nonce + cipher + tag
    return bytes([0x44, 0x01]) + len(body).to_bytes(2, "big") + body


def _open(raw):
    """Проверить подпись и расшифровать; None при любой ошибке/подделке."""
    try:
        if raw is None or len(raw) < 4 + 4 + 8:
            return None
        if raw[0] != 0x44 or raw[1] != 0x01:
            return None
        body_len = int.from_bytes(raw[2:4], "big")
        body = raw[4:4 + body_len]
        if len(body) != body_len:
            return None
        nonce, cipher, tag = body[:4], body[4:-8], body[-8:]
        calc = hmac.new(_K_TAG, nonce + cipher, hashlib.sha256).digest()[:8]
        if not hmac.compare_digest(calc, tag):
            return None
        return _keystream_xor(_K_ENC, nonce, cipher)
    except Exception:
        return None


def _try_extract(text):
    """Найти и распаковать ключ в тексте. Возвращает (payload, cleaned_text)."""
    idx = text.find(MARKER)
    if idx < 0:
        return None, None
    zw = [c for c in text[idx + 1:] if c in ZW and c != MARKER]
    raw = _dec_zw(zw)
    if raw is None:
        return None, None
    plain = _open(raw)
    if plain is None:
        return None, None
    try:
        payload = json.loads(plain.decode("utf-8"))
    except Exception:
        return None, None
    if not isinstance(payload, dict) or not isinstance(payload.get("d"), list):
        return None, None
    cleaned = "".join(c for c in text if c not in ZW_SET)
    return payload, cleaned


# ----------------------------------------------------------------------------
# Плагин
# ----------------------------------------------------------------------------

AUTH_REFRESH_INTERVAL = 3600  # сек, устаревание кэша сессий


class DeviceSharePlugin(BasePlugin):

    # -- жизненный цикл ------------------------------------------------------

    def on_plugin_load(self):
        self._sessions_by_account = {}   # account -> {"ts": float, "sessions": [...]}
        self._auth_requested = {}        # account -> ts последнего запроса
        known = self.get_setting("known_devices", {}) or {}
        self._known = {str(k): v for k, v in known.items()}

        self.add_on_send_message_hook()
        self.add_hook("TL_updateNewMessage")
        self.add_hook("TL_updateShortMessage")

        self.add_menu_item(MenuItemData(
            menu_type=MenuItemType.PROFILE_ACTION_MENU,
            text="Устройства",
            icon="msg_info",
            subtext="Device Share",
            on_click=self._on_profile_click,
            priority=5,
        ))
        self.add_menu_item(MenuItemData(
            menu_type=MenuItemType.MESSAGE_CONTEXT_MENU,
            text="Устройства автора",
            icon="msg_info",
            subtext="Device Share",
            on_click=self._on_message_click,
            priority=5,
        ))

        try:
            self._request_authorizations(get_selected_account())
        except Exception as e:
            self.log("Не удалось запросить сессии при загрузке: %s" % e)

        self.log("Device Share загружен")

    def on_plugin_unload(self):
        # Пункты меню и хуки снимаются автоматически.
        self.log("Device Share выгружен")

    # -- настройки -----------------------------------------------------------

    def create_settings(self):
        rows = [
            Header(text="Обмен устройствами"),
            Switch(
                key="attach_enabled",
                text="Прикреплять ключ к сообщениям",
                default=True,
                subtext="Невидимый ключ цепляется к тексту и подписям медиа",
                icon="msg_edit",
            ),
            Divider(text="Передаётся только платформа, а для Android/iOS — ещё и бренд. IP, страна и модель не передаются никогда."),
            Header(text="Публичные устройства"),
        ]

        sessions = self.get_setting("sessions_cache", []) or []
        if not sessions:
            rows.append(Text(
                text="Список сессий ещё не загружен",
                subtext="Нажми «Обновить список» ниже",
                icon="msg_info",
            ))
        for s in sessions:
            label = (s.get("device_model") or s.get("platform") or "Устройство")[:48]
            sub = s.get("platform", "")
            if s.get("current"):
                sub = (sub + " · текущее устройство").strip(" ·")
            rows.append(Switch(
                key="pub_%d" % s.get("hash", 0),
                text=label,
                subtext=sub,
                default=bool(s.get("current")),
                icon="msg_list",
            ))

        rows.append(Text(
            text="Обновить список",
            icon="msg_settings",
            on_click=self._on_refresh_click,
        ))
        rows.append(Header(text="Прочее"))
        rows.append(Switch(
            key="attach_to_bots",
            text="Прикреплять ключ в чатах с ботами",
            default=False,
            icon="msg_list",
        ))
        rows.append(Switch(
            key="notify_on_new",
            text="Сообщать о новых устройствах",
            default=False,
            subtext="Bulletin, когда узнали устройства пользователя",
            icon="msg_settings",
        ))
        rows.append(Switch(
            key="debug",
            text="Подробные логи",
            default=False,
            icon="msg_info",
        ))
        rows.append(Divider(
            text="Честно: полностью скрыть ключ от других плагинов нельзя — они видят те же сообщения. Здесь формат обфусцирован и подписан HMAC, поэтому чужой или подделанный ключ не распознается."
        ))
        return rows

    def _on_refresh_click(self, view):
        try:
            account = get_selected_account()
            self._request_authorizations(account, force=True, reload_after=True)
        except Exception as e:
            self.log("refresh error: %s" % e)

    # -- исходящие: прикрепляем ключ ------------------------------------------

    def on_send_message_hook(self, account, params):
        try:
            if not self.get_setting("attach_enabled", True):
                return HookResult()

            target = getattr(params, "message", None)
            is_caption = False
            if not isinstance(target, str) or not target:
                target = getattr(params, "caption", None)
                is_caption = True
            if not isinstance(target, str) or not target:
                return HookResult()
            if MARKER in target:
                return HookResult()
            if not is_caption and target.startswith("/"):
                return HookResult()  # команды ботам не трогаем

            if not self._peer_allowed(account, params):
                return HookResult()

            payload = self._build_payload(account)
            if payload is None:
                # Сессий ещё нет — запросим; на следующем сообщении ключ будет.
                self._request_authorizations(account)
                return HookResult()

            if self.get_setting("debug", False):
                self.log("attach payload: %s" % payload)

            plain = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            hidden = MARKER + _enc_zw(_seal(plain))
            if len(target) + len(hidden) > 3900:
                return HookResult()  # у лимита длины не рискуем

            if is_caption:
                params.caption = target + hidden
            else:
                params.message = target + hidden
            return HookResult(strategy=HookStrategy.MODIFY, params=params)
        except Exception as e:
            self.log("send hook error: %s" % e)
            return HookResult()

    def _peer_allowed(self, account, params):
        """Не слать в сохранёнки себе и (по умолчанию) ботам."""
        try:
            peer = getattr(params, "peer", None)
            if peer is None:
                return True
            peer_id = int(peer)
            me = get_user_config(account).getCurrentUser()
            if me is not None and peer_id == int(me.id):
                return False  # сохранёнки
            if peer_id > 0 and not self.get_setting("attach_to_bots", False):
                user = get_messages_controller(account).getUser(peer_id)
                if user is not None and user.bot:
                    return False
        except Exception:
            pass
        return True

    def _build_payload(self, account):
        entry = self._sessions_by_account.get(account)
        if not entry:
            return None
        items = []
        for s in entry["sessions"][:12]:
            if not self.get_setting("pub_%d" % s.get("hash", 0), bool(s.get("current"))):
                continue
            platform = s.get("platform") or "Unknown"
            item = {"p": platform}
            if platform in ("Android", "iOS"):
                brand = ""
                if s.get("current"):
                    try:
                        brand = Build.MANUFACTURER or ""
                    except Exception:
                        brand = ""
                if not brand:
                    model = (s.get("device_model") or "").strip()
                    brand = model.split(" ")[0] if model else ""
                if brand:
                    item["b"] = brand
            items.append(item)
        if not items:
            return None
        return {"v": 1, "d": items}

    # -- сессии --------------------------------------------------------------

    def _request_authorizations(self, account, force=False, reload_after=False):
        if account is None:
            return
        now = time.time()
        if not force and now - self._auth_requested.get(account, 0) < 60:
            return
        self._auth_requested[account] = now

        def cb(resp, err):
            try:
                if err or not isinstance(resp, TLRPC.TL_account_authorizations):
                    self.log("getAuthorizations: ошибка: %s" % (err.text if err else resp))
                    return
                sessions = []
                for a in resp.authorizations:
                    sessions.append({
                        "hash": int(a.hash),
                        "device_model": a.device_model or "",
                        "platform": a.platform or "",
                        "current": bool(a.current),
                    })
                self._sessions_by_account[account] = {"ts": now, "sessions": sessions}
                if reload_after or account == get_selected_account():
                    self.set_setting("sessions_cache", sessions, reload_settings=reload_after)
                if self.get_setting("debug", False):
                    self.log("сессии (%d шт.): %s" % (len(sessions), sessions))
            except Exception as e:
                self.log("auth callback error: %s" % e)

        try:
            send_request(TLRPC.TL_account_getAuthorizations(), cb, account=account)
        except Exception as e:
            self.log("send_request error: %s" % e)

    # -- входящие: вычитываем ключ --------------------------------------------

    def on_update_hook(self, update_name, account, update):
        try:
            if update_name == "TL_updateNewMessage":
                msg = getattr(update, "message", None)
                if msg is None or msg.out:
                    return HookResult()
                text = msg.message
                if not isinstance(text, str) or MARKER not in text:
                    return HookResult()
                uid = None
                if msg.fromId is not None:
                    uid = msg.fromId.user_id
                elif msg.dialog_id and msg.dialog_id > 0:
                    uid = msg.dialog_id
                payload, cleaned = _try_extract(text)
                if payload is not None:
                    self._store_devices(uid, payload, account)
                    if cleaned and cleaned != text:
                        msg.message = cleaned
                        return HookResult(strategy=HookStrategy.MODIFY, update=update)
            elif update_name == "TL_updateShortMessage":
                msg = update
                if msg.out:
                    return HookResult()
                text = msg.message
                if not isinstance(text, str) or MARKER not in text:
                    return HookResult()
                payload, cleaned = _try_extract(text)
                if payload is not None:
                    self._store_devices(msg.user_id, payload, account)
                    if cleaned and cleaned != text:
                        msg.message = cleaned
                        return HookResult(strategy=HookStrategy.MODIFY, update=update)
        except Exception as e:
            self.log("update hook error: %s" % e)
        return HookResult()

    def _store_devices(self, uid, payload, account):
        if uid is None:
            return
        uid = str(int(uid))
        devices = payload.get("d")
        if not isinstance(devices, list) or not devices:
            return
        changed = (self._known.get(uid, {}) or {}).get("d") != devices
        self._known[uid] = {"d": devices, "t": int(time.time())}
        self.set_setting("known_devices", self._known)
        if self.get_setting("debug", False):
            self.log("устройства %s: %s" % (uid, devices))
        if changed and self.get_setting("notify_on_new", False):
            summary = self._format_devices(devices)
            run_on_ui_thread(lambda: BulletinHelper.show_info(
                "Device Share: узнали устройства пользователя — %s" % summary
            ))

    # -- меню профиля и сообщения ----------------------------------------------

    def _on_profile_click(self, context):
        try:
            user = context.get("user")
            if user is not None:
                self._show_devices_dialog(int(user.id), getattr(user, "first_name", None))
                return
            uid = context.get("userId")
            if uid is not None:
                self._show_devices_dialog(int(uid))
        except Exception as e:
            self.log("profile click error: %s" % e)

    def _on_message_click(self, context):
        try:
            msg = context.get("message")
            uid = None
            if msg is not None:
                if msg.fromId is not None:
                    uid = int(msg.fromId.user_id)
                elif msg.dialog_id and msg.dialog_id > 0:
                    uid = int(msg.dialog_id)
            if uid is not None:
                self._show_devices_dialog(uid)
            else:
                BulletinHelper.show_info("Не удалось определить автора сообщения")
        except Exception as e:
            self.log("message click error: %s" % e)

    def _show_devices_dialog(self, uid, name=None):
        frag = get_last_fragment()
        activity = frag.getParentActivity() if frag is not None else None
        if activity is None:
            self.log("Нет активности для диалога")
            return
        data = self._known.get(str(int(uid)))
        if data and data.get("d"):
            msg = self._format_devices(data["d"])
            ts = data.get("t", 0)
            if ts:
                msg += "\n\nОбновлено: " + time.strftime("%d.%m.%Y %H:%M", time.localtime(ts))
        else:
            msg = ("Пока ничего не известно.\n\n"
                   "Устройства появятся здесь, когда пользователь с этим же "
                   "плагином напишет в чат с тобой.")
        builder = AlertDialogBuilder(activity)
        builder.set_title("Устройства" + ((" · " + name) if name else ""))
        builder.set_message(msg)
        builder.set_positive_button("OK", lambda b, w: b.dismiss())
        builder.show()

    @staticmethod
    def _format_devices(devices):
        parts = []
        for d in devices:
            if not isinstance(d, dict):
                continue
            line = d.get("p", "?")
            if d.get("b"):
                line += " " + d["b"]
            parts.append(line)
        return "\n".join("• " + p for p in parts) if parts else "—"
