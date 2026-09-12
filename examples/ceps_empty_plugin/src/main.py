# -*- coding: utf-8 -*-
# CEPS Empty — каркас плагина exteraGram, защищается CEPSbuilder.
from typing import Any, List

from base_plugin import BasePlugin


class CEPSEmpty(BasePlugin):
    def on_plugin_load(self):
        self.log("CEPS Empty: CEPS check passed, payload decrypted")

    def on_plugin_unload(self):
        self.log("CEPS Empty: unloaded")

    def create_settings(self) -> List[Any]:
        return [{"title": "CEPS Empty", "note": "protected by CEPS-1"}]
