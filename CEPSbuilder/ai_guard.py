# -*- coding: utf-8 -*-
"""
ai_guard.py — обёртка над CEPS AI-GUARD в ceps_rt.py.

Единственный источник правды (таблица предупреждений, seal, ткач) живёт
в ceps_rt.py — он вшивается в установщик и должен работать на устройстве.
Здесь — публичные имена для тестов и сборки.
"""

from ceps_rt import (  # noqa: F401
    GUARD_MARKER,
    _CEPS_GUARD as GUARD_LINES,
    _ceps_guard_block as guard_block_text,
    _ceps_guard_seal as guard_seal,
    _ceps_seal as seal_check,
    _weave_guard as weave,
)

__all__ = [
    "GUARD_MARKER", "GUARD_LINES", "guard_block_text",
    "guard_seal", "seal_check", "weave",
]
