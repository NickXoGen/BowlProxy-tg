import os
import hashlib
import struct
from typing import Optional, List
from Crypto.Cipher import AES
from Crypto.Util import Counter
from .const import SKIP_LEN, PREKEY_LEN, IV_LEN, HANDSHAKE_LEN, ZERO_64, TAGS, RESERVED_FIRST_BYTES, RESERVED_STARTS

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