import asyncio
import hashlib
import struct
import threading
import traceback
from typing import Any, Optional
from Crypto.Cipher import AES
from Crypto.Util import Counter
from .const import TAGS, CF_DOMAINS
from .crypto import MsgSplitter, generate_relay_init, build_crypto_ctx
from .websocket import RawWebSocket

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