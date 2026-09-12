# -*- coding: utf-8 -*-
"""ceps_envsim — единый источник «переменных классов» для ПК-пути CEPS-3.

На реальном телефоне подписи снимаются коллектором (реальные Java-классы
через hook_utils.find_class). Здесь — воспроизводимые заглушки с теми же
именами атрибутов, чтобы билдер и fakesdk-тесты считали одинаковые
подписи. КЛАССЫ СОЗНАТЕЛЬНО СТАБИЛЬНЫЕ: dir() этих заглушек меняется
только вместе с этим файлом.
"""

_ORIG_CLASSES = {
    # Реальные имена публичных классов Telegram-FOSS (как у SEKZ), но для
    # тестов достаточно само-согласованных наборов атрибутов.
    "org.telegram.messenger.NotificationCenter": [
        "addObserver", "postNotificationName", "postNotificationNameOnUIThread",
        "removeObserver", "removeObservers", "getTotalInstanceCount",
        "didReceivedNotificationCenterDelegate", "notificationsQueue",
    ],
    "org.telegram.ui.Components.LayoutHelper": [
        "createFrameRel", "createLinear", "createLinearBack", "createScrollVertically",
        "calcViews", "getWindowSize", "fillViewLocation", "setMeasureSpec",
    ],
    "org.telegram.tgnet.TLRPC": [
        "TL_account_getAuthorizations", "TL_account_authorizations",
        "TL_error", "TL_upload_file", "TL_upload_getFile", "TL_photos_photo",
        "TL_messages_messages", "TL_messages_dialogs", "TL_userFull",
    ],
    "org.telegram.messenger.FileLoader": [
        "getFileLoader", "loadFile", "cancelLoadFile", "getMediaDir",
        "setDelegate", "checkLoadingFiles", "getDirectory", "getInstance",
    ],
}
_CLASSES = dict(_ORIG_CLASSES)


class _EnvClass:
    def __init__(self, path, names):
        self._path = path
        for n in names:
            setattr(self, n, n)


def make_class(path):
    names = _CLASSES[path]
    cls = type("EnvClass_" + path.rsplit(".", 1)[-1], (), {})
    for n in names:
        setattr(cls, n, n)
    return cls


def find_class(path):
    if path not in _CLASSES:
        raise ImportError("envsim: неизвестный класс %r" % path)
    return make_class(path)


def signature(path):
    import hashlib
    cls = find_class(path)
    names = sorted(str(x) for x in dir(cls) if not str(x).startswith("__"))
    return hashlib.sha256("".join(names).encode("utf-8")).hexdigest()


def known_classes():
    return sorted(_CLASSES)


def drop_class(path):
    """Тестовая утилита: убрать класс (эмуляция изменения Telegram)."""
    _CLASSES.pop(path, None)


def reset():
    """Восстановить все тестовые классы (после drop_class в тестах)."""
    _CLASSES.clear()
    _CLASSES.update(_ORIG_CLASSES)
