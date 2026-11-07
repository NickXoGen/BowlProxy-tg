import json
import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from datetime import datetime
from pathlib import Path
from queue import Queue, Empty
from typing import Optional
import pystray
from PIL import Image, ImageDraw
import os
import sys

from core.server import WsMTProtoProxy

if getattr(sys, 'frozen', False):
    BASE_DIR = Path(sys.executable).parent
else:
    BASE_DIR = Path(__file__).parent.parent

CONFIG_FILE = BASE_DIR / "bowlproxy_config.json"
DEFAULT_CONFIG = {"host": "127.0.0.1", "port": 1080, "use_ws_proxy": True, "proxy_type": "SOCKS5"}

class ProxyApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("BowlProxy tg")
        self.root.geometry("980x840"); self.root.minsize(900, 740)
        self.root.configure(bg="#2b2b2b")
        self.config = self._load(); self.server: Optional[WsMTProtoProxy] = None
        self.log_q: Queue = Queue(); self.stats_q: Queue = Queue()
        self.stats = dict(total_connections=0, active_connections=0, bytes_sent=0, bytes_received=0, errors=0)
        
        s = ttk.Style(); s.theme_use('clam')
        for k, v in [
            ('TFrame', dict(background='#2b2b2b')), ('TLabel', dict(background='#2b2b2b', foreground='#d4d4d4', font=('Segoe UI', 10))),
            ('Header.TLabel', dict(font=('Segoe UI', 16, 'bold'), foreground='#4ec9b0')), ('SubHeader.TLabel', dict(font=('Segoe UI', 10, 'italic'), foreground='#888888')),
            ('TButton', dict(font=('Segoe UI', 10, 'bold'))), ('Start.TButton', dict(background='#4ec9b0', foreground='#1e1e1e')),
            ('Stop.TButton', dict(background='#f48771', foreground='#1e1e1e')), ('Action.TButton', dict(background='#3a3a3a', foreground='#d4d4d4')),
            ('Copy.TButton', dict(background='#569cd6', foreground='#1e1e1e')), ('Save.TButton', dict(background='#dcdcaa', foreground='#1e1e1e')),
            ('Clear.TButton', dict(background='#3a3a3a', foreground='#d4d4d4')), ('Stats.TLabel', dict(font=('Segoe UI', 9), foreground='#a0a0a0')),
            ('TLabelframe', dict(background='#2b2b2b', foreground='#d4d4d4')), ('TLabelframe.Label', dict(background='#2b2b2b', foreground='#4ec9b0')),
        ]: s.configure(k, **v)
        
        self._build(); self._apply_cfg(); self._loop()

        self.tray_icon = None
        self._setup_tray()
        self.root.protocol("WM_DELETE_WINDOW", self._hide_window)

    def _setup_tray(self):
        image = Image.new('RGB', (64, 64), color=(43, 43, 43))
        d = ImageDraw.Draw(image)
        d.ellipse((16, 16, 48, 48), fill=(78, 201, 176))

        menu = pystray.Menu(
            pystray.MenuItem("Показать BowlProxy", self._show_window, default=True),
            pystray.MenuItem("Выход", self._quit_app)
        )
        self.tray_icon = pystray.Icon("BowlProxy", image, "BowlProxy tg", menu)

    def _hide_window(self):
        self.root.withdraw()
        if self.tray_icon is not None and not self.tray_icon.visible:
            self.tray_icon.run_detached()

    def _show_window(self, icon=None, item=None):
        self.root.after(0, self._do_show)

    def _do_show(self):
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()

    # ИСПРАВЛЕНИЕ ТУТ: Закрытие через главный поток
    def _quit_app(self, icon=None, item=None):
        self.root.after(0, self._do_quit)

    def _do_quit(self):
        if self.tray_icon:
            self.tray_icon.stop()
            self.tray_icon = None
        self._stop()
        self.root.quit()
        self.root.destroy()

    def _build(self):
        hf = ttk.Frame(self.root); hf.pack(fill="x", padx=20, pady=(20, 10))
        tf = ttk.Frame(hf); tf.pack(side="left")
        ttk.Label(tf, text="🚀 BowlProxy tg", style='Header.TLabel').pack(side="left")
        ttk.Label(tf, text="by Dr.Bowling", style='SubHeader.TLabel').pack(side="left", padx=(10, 0), pady=(5, 0))
        sf = ttk.LabelFrame(self.root, text="Настройки", padding=15); sf.pack(fill="x", padx=20, pady=5)

        r = ttk.Frame(sf); r.pack(fill="x", pady=5)
        ttk.Label(r, text="Хост:").pack(side="left")
        self.host_v = tk.StringVar(); ttk.Entry(r, textvariable=self.host_v, width=15).pack(side="left", padx=5)
        ttk.Label(r, text="Порт:").pack(side="left", padx=(15, 0))
        self.port_v = tk.StringVar(); ttk.Entry(r, textvariable=self.port_v, width=8).pack(side="left", padx=5)

        r2 = ttk.Frame(sf); r2.pack(fill="x", pady=5)
        ttk.Label(r2, text="Тип прокси в Telegram:").pack(side="left")
        self.ptype_v = tk.StringVar(value="SOCKS5")
        ttk.Combobox(r2, textvariable=self.ptype_v, values=["SOCKS5", "MTProto"], state="readonly", width=10).pack(side="left", padx=5)

        bf = ttk.Frame(self.root); bf.pack(fill="x", padx=20, pady=10)
        self.start_b = ttk.Button(bf, text="▶ Запустить сервер", command=self._start, style='Start.TButton')
        self.start_b.pack(side="left", ipadx=10, ipady=5)
        self.stop_b = ttk.Button(bf, text="■ Остановить", command=self._stop, state="disabled", style='Stop.TButton')
        self.stop_b.pack(side="left", padx=(10, 0), ipadx=10, ipady=5)
        ttk.Button(bf, text="🔧 Настроить прокси в Telegram", command=self._apply_proxy, style='Action.TButton').pack(side="left", padx=(10, 0), ipadx=10, ipady=5)

        stf = ttk.LabelFrame(self.root, text="Статистика", padding=15); stf.pack(fill="x", padx=20, pady=5)
        self.lbl_total = ttk.Label(stf, text="Подключений: 0", style='Stats.TLabel'); self.lbl_total.pack(side="left", padx=(0, 20))
        self.lbl_active = ttk.Label(stf, text="Активных: 0", style='Stats.TLabel'); self.lbl_active.pack(side="left", padx=(0, 20))
        self.lbl_sent = ttk.Label(stf, text="Отправлено: 0 B", style='Stats.TLabel'); self.lbl_sent.pack(side="left", padx=(0, 20))
        self.lbl_recv = ttk.Label(stf, text="Получено: 0 B", style='Stats.TLabel'); self.lbl_recv.pack(side="left")

        lf = ttk.LabelFrame(self.root, text="Журнал", padding=10); lf.pack(fill="both", expand=True, padx=20, pady=(5, 20))
        lbf = ttk.Frame(lf); lbf.pack(fill="x", pady=(0, 8))
        ttk.Button(lbf, text="📋 Копировать", command=self._copy, style='Copy.TButton').pack(side="left", ipadx=8, ipady=3)
        ttk.Button(lbf, text="💾 Сохранить", command=self._save, style='Save.TButton').pack(side="left", padx=(8, 0), ipadx=8, ipady=3)
        ttk.Button(lbf, text="🗑 Очистить", command=self._clear, style='Clear.TButton').pack(side="left", padx=(8, 0), ipadx=8, ipady=3)
        self.status_lbl = ttk.Label(lbf, text="", style='Stats.TLabel'); self.status_lbl.pack(side="left", padx=(15, 0))

        cont = ttk.Frame(lf); cont.pack(fill="both", expand=True)
        self.log = tk.Text(cont, state="disabled", font=("Consolas", 9), background="#1e1e1e", foreground="#d4d4d4", relief="flat", borderwidth=0, wrap="none")
        sb = ttk.Scrollbar(cont, orient="vertical", command=self.log.yview); self.log.configure(yscrollcommand=sb.set)
        self.log.pack(side="left", fill="both", expand=True); sb.pack(side="right", fill="y")
        for t, c in [("info", "#d4d4d4"), ("success", "#4ec9b0"), ("warn", "#dcdcaa"), ("error", "#f48771")]:
            self.log.tag_configure(t, foreground=c)

    def _apply_cfg(self):
        self.host_v.set(self.config.get("host", "127.0.0.1"))
        self.port_v.set(str(self.config.get("port", 1080)))
        self.ptype_v.set(self.config.get("proxy_type", "SOCKS5"))

    def _copy(self):
        c = self.log.get("1.0", "end-1c")
        if not c.strip(): return self._status("Журнал пуст", "warn")
        self.root.clipboard_clear(); self.root.clipboard_append(c); self.root.update(); self._status("✓ Скопировано", "success")

    def _save(self):
        c = self.log.get("1.0", "end-1c")
        if not c.strip(): return self._status("Журнал пуст", "warn")
        p = filedialog.asksaveasfilename(defaultextension=".txt", initialfile=f"log.txt")
        if not p: return
        Path(p).write_text(c, encoding="utf-8"); self._status("✓ Сохранено", "success")

    def _clear(self):
        self.log.configure(state="normal"); self.log.delete("1.0", "end"); self.log.configure(state="disabled"); self._status("Очищено")

    def _status(self, t, lv="info"):
        col = {"info": "#a0a0a0", "success": "#4ec9b0", "warn": "#dcdcaa", "error": "#f48771"}.get(lv, "#a0a0a0")
        self.status_lbl.configure(text=t, foreground=col); self.root.after(4000, lambda: self.status_lbl.configure(text=""))

    def _start(self):
        try: port = int(self.port_v.get())
        except ValueError: return messagebox.showerror("Ошибка", "Неверный порт")
        self.config.update(host=self.host_v.get(), port=port, proxy_type=self.ptype_v.get())
        self._save_cfg()
        
        self.start_b.configure(state="disabled")
        self.stop_b.configure(state="normal")
        
        self.server = WsMTProtoProxy(self.config, self._log_ts, lambda s: self.stats_q.put(s))
        self.server.start()

    def _apply_proxy(self):
        port = self.port_v.get()
        ptype = self.ptype_v.get()
        if ptype == "SOCKS5":
            link = f"tg://socks?server=127.0.0.1&port={port}"
        else:
            secret = "dd" + os.urandom(16).hex()
            link = f"tg://proxy?server=127.0.0.1&port={port}&secret={secret}"

        self._log(f"  [LINK] Отправка tg:// ссылки ({ptype})...", "info")
        try:
            os.startfile(link)
            self._log(f"✓ Отправлена ссылка ({ptype})", "success")
        except Exception as e:
            self._log(f"✗ Ошибка: {e}", "error")

    def _stop(self):
        if self.server: 
            self.server.stop()
            self.server.join(timeout=1.5) # Добавил таймаут, чтобы не зависало навсегда
            self.server = None
        if hasattr(self, 'start_b') and self.start_b.winfo_exists():
            self.start_b.configure(state="normal")
            self.stop_b.configure(state="disabled")
            self._log("Сервер остановлен", "warn")

    def _log_ts(self, m, lv="info"): self.log_q.put((m, lv))

    def _log(self, m, lv="info"):
        if not self.log.winfo_exists(): return
        self.log.configure(state="normal"); self.log.insert("end", f"[{datetime.now():%H:%M:%S}] ", "info"); self.log.insert("end", f"{m}\n", lv)
        self.log.see("end"); self.log.configure(state="disabled")

    def _loop(self):
        try:
            while True: m, lv = self.log_q.get_nowait(); self._log(m, lv)
        except Empty: pass
        upd = False
        try:
            while True: self.stats = self.stats_q.get_nowait(); upd = True
        except Empty: pass
        if upd: self._upd_stats()
        self.root.after(100, self._loop)

    def _upd_stats(self):
        if not self.lbl_total.winfo_exists(): return
        s = self.stats
        self.lbl_total.configure(text=f"Подключений: {s['total_connections']}"); self.lbl_active.configure(text=f"Активных: {s['active_connections']}")
        self.lbl_sent.configure(text=f"Отправлено: {self._fmt(s['bytes_sent'])}"); self.lbl_recv.configure(text=f"Получено: {self._fmt(s['bytes_received'])}")

    @staticmethod
    def _fmt(n: float) -> str:
        for u in ("B", "KB", "MB", "GB"):
            if n < 1024: return f"{n:.1f} {u}"
            n /= 1024
        return f"{n:.1f} TB"

    def _load(self) -> dict:
        if CONFIG_FILE.exists():
            try: return {**DEFAULT_CONFIG, **json.loads(CONFIG_FILE.read_text("utf-8"))}
            except Exception: pass
        return dict(DEFAULT_CONFIG)

    def _save_cfg(self): CONFIG_FILE.write_text(json.dumps(self.config, indent=2, ensure_ascii=False), "utf-8")