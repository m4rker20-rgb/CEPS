# CEPS

CEPSbuilder — защищённая упаковка плагинов exteraGram. Автор: [@Coder_Minecraft](https://t.me/Coder_Minecraft).

## Уровни защиты

- **CEPS-1**: Ed25519-подпись, цепочка сборок, Merkle-контроль файлов и ChaCha20 payload.
- **CEPS-2**: CEPS-1 + AST-обфускация, HMAC, anti-tamper guards и режимы `--pyc`/`--rt-pyc`.
- **CEPS-3**: CEPS-2 + привязка ключа к окружению Telegram, env-слоты, scrypt KDF, anti-debug и двойной seal.

CEPS-3 повышает стоимость анализа, но не делает клиентский код абсолютно неразрушаемым: код исполняется на устройстве пользователя.

## Быстрый старт

```bash
python CEPSbuilder/cepsbuilder.py new examples/my_plugin --name "My Plugin" --author @Coder_Minecraft
python CEPSbuilder/cepsbuilder.py build examples/my_plugin --obf --pyc --rt-pyc
python CEPSbuilder/cepsbuilder.py verify examples/my_plugin/builds/my_plugin.ceps --pubkey PUBLIC_KEY_HEX
```

Зависимости: Python 3.10+ и стандартная библиотека. Приватные ключи не публикуются.

## Проверка

```bash
for test_file in CEPSbuilder/test_*.py; do python "$test_file"; done
python CEPSbuilder/cepsbuilder.py selftest
```

Подробности находятся в [`CEPSbuilder/README.md`](CEPSbuilder/README.md).
