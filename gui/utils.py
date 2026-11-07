import os
import subprocess
from pathlib import Path
from typing import Optional

def find_telegram_path() -> Optional[str]:
    username = os.getlogin()
    paths = [
        rf"C:\Users\{username}\AppData\Roaming\Telegram Desktop\Telegram.exe",
        r"C:\Program Files\Telegram Desktop\Telegram.exe",
        r"C:\Program Files (x86)\Telegram Desktop\Telegram.exe",
    ]
    dl = Path(rf"C:\Users\{username}\Downloads")
    if dl.exists():
        for f in dl.glob("td-portable-*"):
            p = f / "Telegram" / "Telegram.exe"
            if p.exists(): paths.append(str(p))
        p = dl / "Telegram.exe"
        if p.exists(): paths.append(str(p))
    for p in paths:
        if os.path.exists(p): return p
    return None

def launch_telegram() -> bool:
    p = find_telegram_path()
    if p:
        try:
            subprocess.Popen([p])
            return True
        except Exception:
            return False
    return False