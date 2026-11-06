import asyncio, json, socket, struct, threading, tkinter as tk
from tkinter import ttk, messagebox, filedialog
from datetime import datetime
from pathlib import Path
from queue import Queue, Empty
from typing import Any, Optional, List
import subprocess, sys, os, urllib.parse, hashlib, traceback, base64

import pystray
from PIL import Image, ImageDraw

from Crypto.Cipher import AES
from Crypto.Util import Counter

if getattr(sys, 'frozen', False):
    BASE_DIR = Path(sys.executable).parent
else:
    BASE_DIR = Path(__file__).parent
CONFIG_FILE = BASE_DIR / "bowlproxy_config.json"
DEFAULT_CONFIG = {"host": "127.0.0.1", "port": 1080, "use_ws_proxy": True, "proxy_type": "SOCKS5"}

# --- Константы MTProto ---
SKIP_LEN = 8
PREKEY_LEN = 32
IV_LEN = 16
HANDSHAKE_LEN = 64
ZERO_64 = b'\x00' * 64
TAGS = (b'\xef\xef\xef\xef', b'\xee\xee\xee\xee', b'\xdd\xdd\xdd\xdd')
RESERVED_FIRST_BYTES = {0xEF, 0x48, 0x50, 0x47, 0x4F, 0x16}
RESERVED_STARTS = {b'\x48\x45\x41\x44', b'\x50\x4F\x53\x54', b'\x47\x45\x54\x20', b'\xee\xee\xee\xee', b'\xdd\xdd\xdd\xdd', b'\x16\x03\x01\x02', b'\x4F\x50\x54\x49'}

_CFPROXY_ENC = [
    'virkgj.com', 'vmmzovy.com', 'mkuosckvso.com', 'zaewayzmplad.com',
    'twdmbzcm.com', 'awzwsldi.com', 'clngqrflngqin.com', 'tjacxbqtj.com',
    'bxaxtxmrw.com', 'dmohrsgmohcrwb.com', 'vwbmtmoi.com', 'khgrre.com',
    'ulihssf.com', 'tmhqsdqmfpmk.com', 'xwuwoqbm.com', 'orgcnunpj.com',
    'zhkuldz.com', 'zypoljnslxa.com', 'efabnxaowuzs.com', 'zaftuzsftqdq.com'
]
_S = '.co.uk'

def _dd(s: str) -> str:
    if not s[-4:] == '.com': return s
    p, n = s[:-4], sum(c.isalpha() for c in s[:-4])
    return ''.join(
        chr((ord(c) - (97 if c > '`' else 65) - n) % 26 + (97 if c > '`' else 65))
        if c.isalpha() else c for c in p
    ) + _S

CF_DOMAINS = [_dd(d) for d in _CFPROXY_ENC]

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

def set_sock_opts(transport, buffer_size):
    sock = transport.get_extra_info('socket')
    if sock is None: return
    try: sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except (OSError, AttributeError): pass
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, buffer_size)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, buffer_size)
    except OSError: pass

class RawWebSocket:
    def __init__(self, reader, writer):
        self.reader = reader
        self.writer = writer
        self._closed = False
        self._frag = bytearray()

    @staticmethod
    async def connect(host: str, domain: str, timeout: float = 10.0, path: str = '/apiws') -> 'RawWebSocket':
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, 443, ssl=True, server_hostname=domain), timeout=timeout
        )
        try:
            set_sock_opts(writer.transport, 256 * 1024)
            ws_key = base64.b64encode(os.urandom(16)).decode()
            req = (
                f'GET {path} HTTP/1.1\r\n'
                f'Host: {domain}\r\n'
                f'Upgrade: websocket\r\n'
                f'Connection: Upgrade\r\n'
                f'Sec-WebSocket-Key: {ws_key}\r\n'
                f'Sec-WebSocket-Version: 13\r\n'
                f'Sec-WebSocket-Protocol: binary\r\n'
                f'\r\n'
            )
            writer.write(req.encode())
            await writer.drain()

            response_lines = []
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=timeout)
                if line in (b'\r\n', b'\n', b''): break
                response_lines.append(line.decode('utf-8', errors='replace').strip())

            if not response_lines or '101' not in response_lines[0]:
                raise ConnectionError(f"WS handshake failed: {response_lines[0] if response_lines else 'Empty'}")

            return RawWebSocket(reader, writer)
        except BaseException:
            writer.close()
            try: await writer.wait_closed()
            except Exception: pass
            raise

    async def send(self, data: bytes):
        if self._closed: raise ConnectionError("WS closed")
        frame = self._build_frame(0x2, data, mask=True)
        self.writer.write(frame)
        await self.writer.drain()

    async def send_batch(self, parts: List[bytes]):
        if self._closed: raise ConnectionError("WS closed")
        for part in parts:
            self.writer.write(self._build_frame(0x2, part, mask=True))
        await self.writer.drain()

    async def recv(self) -> Optional[bytes]:
        while not self._closed:
            try:
                hdr = await self.reader.readexactly(2)
            except asyncio.IncompleteReadError:
                self._closed = True
                return None

            opcode = hdr[0] & 0x0F
            length = hdr[1] & 0x7F

            if length == 126: length = struct.unpack('>H', await self.reader.readexactly(2))[0]
            elif length == 127: length = struct.unpack('>Q', await self.reader.readexactly(8))[0]

            if hdr[1] & 0x80:
                mask_key = await self.reader.readexactly(4)
                payload = await self.reader.readexactly(length)
                payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
            else:
                payload = await self.reader.readexactly(length)

            if opcode == 0x8: # Close
                self._closed = True
                return None
            if opcode == 0x9: # Ping
                self.writer.write(self._build_frame(0xA, payload, mask=True))
                await self.writer.drain()
                continue
            if opcode == 0xA: # Pong
                continue

            if opcode in (0x1, 0x2, 0x0):
                fin = hdr[0] & 0x80
                if fin and not self._frag:
                    return payload
                self._frag.extend(payload)
                if not fin:
                    continue
                message = bytes(self._frag)
                self._frag.clear()
                return message
        return None

    async def close(self):
        self._closed = True
        try:
            if self.writer is not None:
                self.writer.close()
                await self.writer.wait_closed()
        except Exception: pass

    @staticmethod
    def _build_frame(opcode: int, data: bytes, mask: bool = False) -> bytes:
        length = len(data)
        fb = 0x80 | opcode
        if not mask:
            if length < 126: return struct.pack('>BB', fb, length) + data
            if length < 65536: return struct.pack('>BBH', fb, 126, length) + data
            return struct.pack('>BBQ', fb, 127, length) + data

        mask_key = os.urandom(4)
        masked = bytearray(data)
        for i in range(length):
            masked[i] ^= mask_key[i % 4]

        if length < 126: return struct.pack('>BB4s', fb, 0x80 | length, mask_key) + masked
        if length < 65536: return struct.pack('>BBH4s', fb, 0x80 | 126, length, mask_key) + masked
        return struct.pack('>BBQ4s', fb, 0x80 | 127, length, mask_key) + masked

class MsgSplitter:
    def __init__(self, proto_int: int):
        self._proto = proto_int
        self._cipher_buf = bytearray()
        self._plain_buf = bytearray()
        self._disabled = False

    def split(self, chunk: bytes, plain: bytes) -> list[bytes]:
        if not chunk: return []
        if self._disabled: return [chunk]
        self._cipher_buf.extend(chunk)
        self._plain_buf.extend(plain)
        parts = []
        offset = 0
        buf_len = len(self._cipher_buf)
        while offset < buf_len:
            packet_len = self._next_packet_len(offset, buf_len - offset)
            if packet_len is None: break
            if packet_len <= 0:
                parts.append(bytes(self._cipher_buf[offset:]))
                offset = buf_len
                self._disabled = True
                break
            parts.append(bytes(self._cipher_buf[offset:offset + packet_len]))
            offset += packet_len
        if offset:
            del self._cipher_buf[:offset]
            del self._plain_buf[:offset]
        return parts

    def _next_packet_len(self, offset: int, avail: int) -> Optional[int]:
        if avail <= 0: return None
        if self._proto == 0xEFEFEFEF:
            first = self._plain_buf[offset]
            if first in (0x7F, 0xFF):
                if avail < 4: return None
                payload_len = int.from_bytes(self._plain_buf[offset+1:offset+4], 'little') * 4
                header_len = 4
            else:
                payload_len = (first & 0x7F) * 4
                header_len = 1
            if payload_len <= 0: return 0
            packet_len = header_len + payload_len
            if avail < packet_len: return None
            return packet_len
        elif self._proto in (0xEEEEEEEE, 0xDDDDDDDD):
            if avail < 4: return None
            payload_len = struct.unpack_from('<I', self._plain_buf, offset)[0] & 0x7FFFFFFF
            if payload_len <= 0: return 0
            packet_len = 4 + payload_len
            if avail < packet_len: return None
            return packet_len
        return 0

def generate_relay_init(proto_tag: bytes, dc_idx: int) -> bytes:
    while True:
        rnd = bytearray(os.urandom(HANDSHAKE_LEN))
        if rnd[0] in RESERVED_FIRST_BYTES: continue
        if bytes(rnd[:4]) in RESERVED_STARTS: continue
        if rnd[4:8] == b'\x00\x00\x00\x00': continue
        break
    enc_key = bytes(rnd[SKIP_LEN:SKIP_LEN + PREKEY_LEN])
    enc_iv = bytes(rnd[SKIP_LEN + PREKEY_LEN:SKIP_LEN + PREKEY_LEN + IV_LEN])
    ctr = Counter.new(128, initial_value=int.from_bytes(enc_iv, 'big'))
    cipher = AES.new(enc_key, AES.MODE_CTR, counter=ctr)
    dc_bytes = struct.pack('<h', dc_idx)
    tail_plain = proto_tag + dc_bytes + os.urandom(2)
    encrypted_full = cipher.encrypt(bytes(rnd))
    keystream_tail = bytes(encrypted_full[i] ^ rnd[i] for i in range(56, 64))
    encrypted_tail = bytes(tail_plain[i] ^ keystream_tail[i] for i in range(8))
    result = bytearray(rnd)
    result[56:64] = encrypted_tail
    return bytes(result)

def build_crypto_ctx(client_prekey_iv: bytes, relay_init: bytes) -> dict:
    clt_dec_key = client_prekey_iv[:PREKEY_LEN]
    clt_dec_iv = client_prekey_iv[PREKEY_LEN:]
    clt_dec = AES.new(clt_dec_key, AES.MODE_CTR, counter=Counter.new(128, initial_value=int.from_bytes(clt_dec_iv, 'big')))
    clt_dec.decrypt(ZERO_64)

    clt_enc_key_iv = client_prekey_iv[::-1]
    clt_enc_key = clt_enc_key_iv[:PREKEY_LEN]
    clt_enc_iv = clt_enc_key_iv[PREKEY_LEN:]
    clt_enc = AES.new(clt_enc_key, AES.MODE_CTR, counter=Counter.new(128, initial_value=int.from_bytes(clt_enc_iv, 'big')))

    tg_enc_key = relay_init[SKIP_LEN:SKIP_LEN + PREKEY_LEN]
    tg_enc_iv = relay_init[SKIP_LEN + PREKEY_LEN:SKIP_LEN + PREKEY_LEN + IV_LEN]
    tg_enc = AES.new(tg_enc_key, AES.MODE_CTR, counter=Counter.new(128, initial_value=int.from_bytes(tg_enc_iv, 'big')))
    tg_enc.encrypt(ZERO_64)

    tg_dec_key_iv = relay_init[SKIP_LEN:SKIP_LEN + PREKEY_LEN + IV_LEN][::-1]
    tg_dec_key = tg_dec_key_iv[:PREKEY_LEN]
    tg_dec_iv = tg_dec_key_iv[PREKEY_LEN:]
    tg_dec = AES.new(tg_dec_key, AES.MODE_CTR, counter=Counter.new(128, initial_value=int.from_bytes(tg_dec_iv, 'big')))

    return {'clt_dec': clt_dec, 'clt_enc': clt_enc, 'tg_enc': tg_enc, 'tg_dec': tg_dec}

class WsMTProtoProxy:
    def __init__(self, config, on_log, on_stats):
        self.host = config["host"]
        self.port = config["port"]
        self.on_log = on_log
        self.on_stats = on_stats
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.thread: Optional[threading.Thread] = None
        self.server: Optional[asyncio.AbstractServer] = None
        self._stop_event: Optional[asyncio.Event] = None
        self.stats = dict(total_connections=0, active_connections=0, bytes_sent=0, bytes_received=0, errors=0)

    def start(self):
        self.thread = threading.Thread(target=self._run_loop, daemon=True)
        self.thread.start()

    def _run_loop(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self._stop_event = asyncio.Event()
        try:
            self.loop.run_until_complete(self._serve())
        except Exception as e:
            self.on_log(f"Критическая: {e}\n{traceback.format_exc()}", "error")
        finally:
            self.loop.close()

    async def _serve(self):
        try:
            self.server = await asyncio.start_server(self._handle, self.host, self.port)
        except OSError as e:
            self.on_log(f"Не удалось запустить: {e}", "error")
            return
        self.on_log(f"✓ BowlProxy на {self.host}:{self.port}", "success")
        self.on_stats(self.stats)

        assert self._stop_event is not None
        await self._stop_event.wait()

        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()

    def stop(self):
        if self.loop and not self.loop.is_closed() and self._stop_event is not None:
            self.loop.call_soon_threadsafe(self._stop_event.set)

    def join(self, timeout: float = 2.0):
        if self.thread: self.thread.join(timeout=timeout)

    def _parse_header(self, header: bytes) -> dict[str, Any]:
        res = {"tag_found": False, "dc_id": None, "is_media": False, "approach": None, "proto_int": 0, "prekey_iv": None}
        iv = bytes(header[40:56])
        for key_name, key in (("raw", bytes(header[8:40])), ("sha256", hashlib.sha256(bytes(header[8:40])).digest())):
            for le_name, le in (("BE", False), ("LE", True)):
                try:
                    ctr = Counter.new(128, initial_value=int.from_bytes(iv, 'big'), little_endian=le)
                    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
                    dec = cipher.decrypt(header)
                    tag = dec[56:60]
                    if tag in TAGS:
                        dc_idx = struct.unpack("<h", dec[60:62])[0]
                        dc_abs = abs(dc_idx)
                        if 1 <= dc_abs <= 5:
                            proto_int = 0xEFEFEFEF if tag == b'\xef\xef\xef\xef' else (0xEEEEEEEE if tag == b'\xee\xee\xee\xee' else 0xDDDDDDDD)
                            res.update(
                                tag_found=True,
                                dc_id=dc_abs,
                                is_media=(dc_idx < 0),
                                proto_int=proto_int,
                                approach=f"{key_name}+{le_name}",
                                prekey_iv=bytes(header[8:56])
                            )
                            return res
                except Exception: continue
        return res

    async def _handle(self, reader, writer):
        peer = writer.get_extra_info("peername")
        ps = f"{peer[0]}:{peer[1]}" if peer else "?"
        self.stats["total_connections"] += 1
        self.stats["active_connections"] += 1
        self.on_stats(self.stats)
        self.on_log(f"═══ NEW {ps} ═══", "info")
        try:
            ver, nm = await reader.readexactly(2)
            if ver != 5: return
            await reader.readexactly(nm)
            writer.write(b"\x05\x00"); await writer.drain()

            _, cmd, _, atyp = await reader.readexactly(4)
            if cmd != 1:
                writer.write(b"\x05\x07\x00\x01" + b"\x00" * 6); await writer.drain(); return
            if atyp == 0x01: await reader.readexactly(4)
            elif atyp == 0x03: await reader.readexactly((await reader.readexactly(1))[0])
            elif atyp == 0x04: await reader.readexactly(16)
            await reader.readexactly(2)

            writer.write(b"\x05\x00\x00\x01" + b"\x00" * 6); await writer.drain()

            header = await reader.readexactly(64)
            if header[:3] in (b'\x16\x03\x01', b'\x16\x03\x03'):
                self.on_log("  ✗ FakeTLS, not obfuscated2", "error"); return

            parsed = self._parse_header(header)
            if not parsed["tag_found"]:
                self.on_log("  ✗ header parse failed (HTTP fallback?)", "warn"); return

            dc = parsed["dc_id"]
            is_media = parsed["is_media"]
            proto_int = parsed["proto_int"]

            media_tag = " media" if is_media else ""
            self.on_log(f"  ✓ PARSED ({parsed['approach']}) → DC{dc}{media_tag}", "success")

            proto_tag = TAGS[0] if proto_int == 0xEFEFEFEF else (TAGS[1] if proto_int == 0xEEEEEEEE else TAGS[2])
            dc_idx = -dc if is_media else dc
            relay_init = generate_relay_init(proto_tag, dc_idx)
            crypto = build_crypto_ctx(parsed["prekey_iv"], relay_init)

            domains_to_try = []
            for base_domain in CF_DOMAINS:
                if is_media:
                    domains_to_try.append(f"kws{dc}-1.{base_domain}")
                domains_to_try.append(f"kws{dc}.{base_domain}")

            if is_media:
                domains_to_try.append(f"kws{dc}-1.web.telegram.org")
            domains_to_try.append(f"kws{dc}.web.telegram.org")

            ws = None
            last_error = None
            for domain in domains_to_try:
                self.on_log(f"  [WS] → wss://{domain}/apiws", "info")
                try:
                    ws = await RawWebSocket.connect(domain, domain, timeout=10)
                    self.on_log(f"  ✓ WS OK ({domain}). Bridging...", "success")
                    break
                except Exception as e:
                    last_error = e
                    self.on_log(f"  ✗ WS failed ({domain}): {e}", "warn")

            if ws:
                await ws.send(relay_init)
                await self._bridge_ws(ws, reader, writer, crypto, proto_int, ps)
            else:
                self.on_log(f"  ✗ All WS domains failed. Last error: {last_error}", "error")

        except Exception as e:
            self.stats["errors"] += 1
            self.on_log(f"  [EXC] {ps}: {type(e).__name__}: {e}", "error")
        finally:
            self.stats["active_connections"] -= 1
            self.on_stats(self.stats)
            self.on_log(f"═══ CLOSE {ps} ═══", "info")
            try: writer.close()
            except Exception: pass

    async def _bridge_ws(self, ws, reader, writer, crypto, proto_int, ps):
        splitter = MsgSplitter(proto_int)

        async def c2w():
            try:
                while True:
                    data = await reader.read(65536)
                    if not data:
                        break
                    self.stats["bytes_sent"] += len(data)
                    plain = crypto['clt_dec'].decrypt(data)
                    reencrypted = crypto['tg_enc'].encrypt(plain)
                    parts = splitter.split(reencrypted, plain)
                    if not parts: continue
                    if len(parts) > 1:
                        await ws.send_batch(parts)
                    else:
                        await ws.send(parts[0])
            except Exception as e:
                self.on_log(f"  {ps} [C→WS] {type(e).__name__}: {e}", "warn")

        async def w2c():
            try:
                while True:
                    msg = await ws.recv()
                    if msg is None: break
                    self.stats["bytes_received"] += len(msg)
                    plain = crypto['tg_dec'].decrypt(msg)
                    reencrypted = crypto['clt_enc'].encrypt(plain)
                    writer.write(reencrypted)
                    await writer.drain()
            except Exception as e:
                self.on_log(f"  {ps} [WS→C] {type(e).__name__}: {e}", "warn")

        await asyncio.gather(c2w(), w2c(), return_exceptions=True)
        try: await ws.close()
        except Exception: pass

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

        # Убрали аннотацию Optional[pystray.Icon], чтобы Pylance не ругался
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
            threading.Thread(target=self.tray_icon.run, daemon=True).start()

    def _show_window(self, icon=None, item=None):
        self.root.after(0, self._do_show)

    def _do_show(self):
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()

    def _quit_app(self, icon=None, item=None):
        if self.tray_icon:
            self.tray_icon.stop()
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
        self.start_b = ttk.Button(bf, text="▶ Запустить и открыть Telegram", command=self._start, style='Start.TButton')
        self.start_b.pack(side="left", ipadx=10, ipady=5)
        self.stop_b = ttk.Button(bf, text="■ Остановить", command=self._stop, state="disabled", style='Stop.TButton')
        self.stop_b.pack(side="left", padx=(10, 0), ipadx=10, ipady=5)
        ttk.Button(bf, text="🔧 Настроить прокси", command=self._apply_proxy, style='Action.TButton').pack(side="left", padx=(10, 0), ipadx=10, ipady=5)

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
        self.start_b.configure(state="disabled"); self.stop_b.configure(state="normal")
        self.server = WsMTProtoProxy(self.config, self._log_ts, lambda s: self.stats_q.put(s))
        self.server.start(); self.root.after(500, self._launch_tg)

    def _launch_tg(self):
        self._log("Ищу Telegram...", "info")
        if launch_telegram():
            self._log("✓ Telegram запущен", "success"); self.root.after(1500, self._apply_proxy)
        else: self._log("✗ Telegram не найден", "error")

    def _apply_proxy(self):
        port = self.port_v.get()
        ptype = self.ptype_v.get()
        if ptype == "SOCKS5":
            link = f"tg://socks?server=127.0.0.1&port={port}"
        else:
            secret = "dd" + os.urandom(16).hex()
            link = f"tg://proxy?server=127.0.0.1&port={port}&secret={secret}"

        self._log(f"  [LINK] {link}", "info")
        try:
            os.startfile(link)
            self._log(f"✓ Отправлена ссылка ({ptype})", "success")
        except Exception as e:
            self._log(f"✗ Ошибка: {e}", "error")

    def _stop(self):
        if self.server: self.server.stop(); self.server.join(); self.server = None
        self.start_b.configure(state="normal"); self.stop_b.configure(state="disabled"); self._log("Сервер остановлен", "warn")

    def _log_ts(self, m, lv="info"): self.log_q.put((m, lv))

    def _log(self, m, lv="info"):
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

def main():
    root = tk.Tk(); ProxyApp(root); root.mainloop()

if __name__ == "__main__":
    main()
