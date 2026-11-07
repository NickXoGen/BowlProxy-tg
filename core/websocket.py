import os
import asyncio
import struct
import socket
import base64
from typing import Optional, List

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

            if opcode == 0x8:
                self._closed = True
                return None
            if opcode == 0x9:
                self.writer.write(self._build_frame(0xA, payload, mask=True))
                await self.writer.drain()
                continue
            if opcode == 0xA:
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