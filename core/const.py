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