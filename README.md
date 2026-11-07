# BowlProxy tg

Локальный прокси-сервер для Telegram Desktop на Python. 

Программа предназначена для обхода блокировок провайдеров (DPI/ТСПУ). Она перехватывает MTProto-трафик, маскирует его под обычный HTTPS (WebSocket) и отправляет через серверы Cloudflare. Провайдер видит безобидное соединение, а Telegram работает.

## Возможности

* Поддержка протоколов SOCKS5 и MTProto.
* Графический интерфейс на Tkinter (темная тема).
* Работа в системном трее (сворачивается по крестику).
* Нарезка пакетов (MsgSplitter) для стабильной передачи медиафайлов.
* Встроенный список доменов Cloudflare для обхода блокировок.
* Сборка в один EXE-файл (не требует установки Python).

## Установка и использование (для пользователей)

1. Перейдите в раздел [Releases](https://github.com/NickXoGen/BowlProxy-tg/releases).
2. Скачайте файл `BowlProxy_tg.exe`.
3. Запустите программу. Если Windows SmartScreen выдаст предупреждение, нажмите «Подробнее» -> «Выполнить в любом случае» (это нормально для неподписанных EXE на Python).
4. Нажмите кнопку «Запустить сервер».
5. Нажмите кнопку «Настроить прокси в Telegram». В приложении Telegram появится окно для подтверждения настроек.

## Запуск из исходников (для разработчиков)

Требуется Python 3.12 (на версии 3.15 возможны проблемы с PyInstaller и библиотекой `cryptography`).

1. Клонируйте репозиторий:
    git clone https://github.com/NickXoGen/BowlProxy-tg.git
    cd BowlProxy-tg

2. Создайте виртуальное окружение и активируйте его:
    python -m venv .venv
    .\.venv\Scripts\activate

3. Установите зависимости:
    pip install pycryptodome pystray Pillow

4. Запустите программу:
    python main.py

## Сборка в EXE

Для компиляции используется PyInstaller. Команда сборки (запускать из корневой папки проекта):

    pyinstaller --noconsole --onefile --collect-all Crypto --hidden-import=pystray --hidden-import=pystray._win32 --hidden-import=PIL --hidden-import=PIL.Image --hidden-import=PIL.ImageDraw --hidden-import=gui.app --hidden-import=core.server --name="BowlProxy_tg" main.py

## Благодарности

* [Flowseal](https://github.com/Flowseal/tg-ws-proxy) — за реверс-инжиниринг WebSocket-протокола Telegram и список доменов.
* DeepSeek — за помощь в генерации кода и фиксе багов.

## Поддержать автора

Проект бесплатный. Если программа вам помогла и вы хотите поддержать разработку: 
[Boosty](https://boosty.to/drbowling)
