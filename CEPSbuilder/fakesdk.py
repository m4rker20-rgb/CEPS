# -*- coding: utf-8 -*-
"""
fakesdk — подмена SDK-модулей exteraGram для автотестов CEPSbuilder на ПК.

После fakesdk.install() можно исполнять лоадеры и плагины в обычном Python:
base_plugin, file_utils, ui.*, client_utils, android_utils и т.д. существуют
как безвредные заглушки.
"""

import os
import sys
import tempfile

LOGS = []
BULLETINS = []
_PLUGINS_DIR = None
SETTINGS = {}  # общее хранилище для всех фейковых плагинов


class _Setting:
    def __init__(self, **kw):
        self.__dict__.update(kw)

    def __repr__(self):
        return "%s(%s)" % (type(self).__name__,
                           ",".join("%s=%r" % kv for kv in sorted(self.__dict__.items())))


def _make_module(name, **attrs):
    mod = type(sys)(name)
    for k, v in attrs.items():
        setattr(mod, k, v)
    sys.modules[name] = mod
    return mod


class BasePlugin:
    def __init__(self, *a, **kw):
        self._settings = SETTINGS

    def log(self, *a):
        LOGS.append(" ".join(str(x) for x in a))

    def get_setting(self, key, default=None):
        return self._settings.get(key, default)

    def set_setting(self, key, value, reload_settings=False):
        self._settings[key] = value
        return None

    def add_hook(self, *a, **kw):
        return None

    def add_on_send_message_hook(self, *a, **kw):
        return None

    def add_menu_item(self, *a, **kw):
        return "fake-item-id"

    def remove_menu_item(self, *a, **kw):
        return None

    def client(self, *a, **kw):
        return None

    def getName(self):
        return "FakePlugin"


class HookResult:
    def __init__(self, strategy=None, params=None, update=None, request=None,
                 response=None, updates=None):
        self.strategy = strategy
        self.params = params
        self.update = update
        self.request = request
        self.response = response
        self.updates = updates


class HookStrategy:
    DEFAULT = 0
    CANCEL = 1
    MODIFY = 2
    MODIFY_FINAL = 3


class MenuItemData:
    def __init__(self, **kw):
        self.__dict__.update(kw)


class MenuItemType:
    MESSAGE_CONTEXT_MENU = "message_context"
    DRAWER_MENU = "drawer"
    MAIN_MENU = "main"
    CHAT_ACTION_MENU = "chat_action"
    PROFILE_ACTION_MENU = "profile_action"


class MethodHook:
    pass


class _FilesController:
    SUPPORT_ICONS = False
    _registered = {}

    class Place:
        UNKNOWN = 0
        ChatActivity = 1
        FilteredSearchView = 2
        SharedMediaLayout = 3
        SearchDownloadsContainer = 4
        ChannelAdminLogActivity = 5

    class FileInfo:
        def __init__(self, ext, on_click, whitelist_places=None, blacklist_places=None,
                     get_icon=None):
            self.ext = ext
            self.on_click = on_click
            self.whitelist_places = whitelist_places or []
            self.blacklist_places = blacklist_places or []
            self.get_icon = get_icon

    class ExtensionAlreadyRegistered(Exception):
        pass

    class ExtensionNotRegistered(Exception):
        pass

    class SecretInvalid(Exception):
        pass

    @classmethod
    def register(cls, file_info):
        if file_info.ext in cls._registered:
            raise cls.ExtensionAlreadyRegistered(file_info.ext)
        secret = "secret-%s" % file_info.ext
        cls._registered[file_info.ext] = (file_info, secret)
        return secret

    @classmethod
    def unregister(cls, ext, secret):
        if ext not in cls._registered:
            raise cls.ExtensionNotRegistered(ext)
        if cls._registered[ext][1] != secret:
            raise cls.SecretInvalid(ext)
        del cls._registered[ext]
        return True


def get_plugins_dir():
    global _PLUGINS_DIR
    if _PLUGINS_DIR is None:
        _PLUGINS_DIR = os.path.join(tempfile.gettempdir(), "ceps_fake_plugins")
        os.makedirs(_PLUGINS_DIR, exist_ok=True)
    return _PLUGINS_DIR


def ensure_dir_exists(path):
    os.makedirs(path, exist_ok=True)


def read_file(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read()
    except Exception:
        return None


def read_file_bytes(path):
    try:
        with open(path, "rb") as fh:
            return fh.read()
    except Exception:
        return None


def write_file(path, content):
    ensure_dir_exists(os.path.dirname(path))
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)


def write_file_bytes(path, content):
    ensure_dir_exists(os.path.dirname(path))
    with open(path, "wb") as fh:
        fh.write(content)


def delete_file(path):
    try:
        os.remove(path)
        return True
    except Exception:
        return False


def list_dir(path=".", recursive=False, include_files=True, include_dirs=False,
             extensions=None):
    out = []
    for root, dirs, names in os.walk(path):
        if include_files:
            for n in names:
                if extensions and not any(n.endswith(e) for e in extensions):
                    continue
                out.append(os.path.join(root, n))
        if include_dirs:
            out.extend(os.path.join(root, d) for d in dirs)
        if not recursive:
            break
    return out


class BulletinHelper:
    @staticmethod
    def show_info(text):
        BULLETINS.append(("info", text))

    @staticmethod
    def show_error(text):
        BULLETINS.append(("error", text))


class AlertDialogBuilder:
    ALERT_TYPE_MESSAGE = 0
    ALERT_TYPE_LOADING = 1
    ALERT_TYPE_SPINNER = 2
    BUTTON_POSITIVE = 1
    BUTTON_NEGATIVE = 2
    BUTTON_NEUTRAL = 3

    def __init__(self, context=None, progress_style=0, resources_provider=None):
        self.title = None
        self.message = None
        self.shown = False

    def set_title(self, t):
        self.title = t

    def set_message(self, m):
        self.message = m

    def set_positive_button(self, text, listener=None):
        self._pos = (text, listener)

    def set_negative_button(self, text, listener=None):
        self._neg = (text, listener)

    def create(self):
        return self

    def show(self):
        self.shown = True
        return self

    def dismiss(self):
        self.shown = False


def _noop(*a, **kw):
    return None


def install():
    import ceps_envsim
    _make_module("hook_utils", find_class=ceps_envsim.find_class)
    _make_module("base_plugin", BasePlugin=BasePlugin, HookResult=HookResult,
                 HookStrategy=HookStrategy, MenuItemData=MenuItemData,
                 MenuItemType=MenuItemType, MethodHook=MethodHook,
                 AppEvent=None)
    _make_module("file_utils", FilesController=_FilesController,
                 get_plugins_dir=get_plugins_dir, get_cache_dir=get_plugins_dir,
                 get_files_dir=get_plugins_dir, get_documents_dir=get_plugins_dir,
                 ensure_dir_exists=ensure_dir_exists, list_dir=list_dir,
                 read_file=read_file, read_file_bytes=read_file_bytes,
                 write_file=write_file, write_file_bytes=write_file_bytes,
                 delete_file=delete_file)
    _make_module("ui")
    _make_module("ui.settings", Header=_Setting, Divider=_Setting, Switch=_Setting,
                 Selector=_Setting, Input=_Setting, Text=_Setting, EditText=_Setting,
                 Custom=_Setting, SimpleSettingFactory=_Setting)
    _make_module("ui.bulletin", BulletinHelper=BulletinHelper)
    _make_module("ui.alert", AlertDialogBuilder=AlertDialogBuilder)
    _make_module("android_utils", log=lambda *a: LOGS.append(" ".join(str(x) for x in a)),
                 run_on_ui_thread=_noop,
                 copy_to_clipboard=_noop, R=_noop, OnClickListener=_noop,
                 OnLongClickListener=_noop)
    _make_module("client_utils", send_request=_noop, send_text=_noop,
                 get_last_fragment=lambda: None, get_user_config=lambda *a, **k: None,
                 get_messages_controller=lambda *a, **k: None,
                 get_selected_account=lambda: 0, get_account_instance=lambda *a, **k: None,
                 get_connections_manager=lambda *a, **k: None,
                 get_send_messages_helper=lambda *a, **k: None,
                 get_notification_center=lambda: None,
                 NotificationCenterDelegate=object, run_on_queue=_noop)
    _make_module("android")
    _make_module("android.os", Build=type("Build", (), {"MANUFACTURER": "TestBrand",
                                                        "MODEL": "TestModel"}))
    _make_module("org")
    _make_module("org.telegram")
    _make_module("org.telegram.tgnet", TLRPC=type("TLRPC", (), {
        "TL_account_getAuthorizations": type("TL_account_getAuthorizations", (), {}),
        "TL_account_authorizations": type("TL_account_authorizations", (), {}),
    }))
