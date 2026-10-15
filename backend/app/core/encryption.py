"""Per-chunk GCM tags miss reordering, deletion and splicing: confidentiality only, enough for access-controlled S3."""

import hashlib
import os
import struct
from collections.abc import AsyncIterator

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.config import settings
from app.core.constants import (
    ENCRYPTION_CHUNK_SIZE,
    ENCRYPTION_FORMAT_VERSION,
    ENCRYPTION_MAGIC,
)

NONCE_SIZE = 12


def is_encryption_enabled() -> bool:
    return bool(settings.ARCHIVE_ENCRYPTION_KEY)


def _get_key() -> bytes:
    raw = settings.ARCHIVE_ENCRYPTION_KEY
    if len(raw) == 64:
        try:
            return bytes.fromhex(raw)
        except ValueError:
            pass
    return hashlib.sha256(raw.encode("utf-8")).digest()


def _seal(aesgcm: AESGCM, plaintext: bytes) -> bytes:
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return struct.pack(">I", len(ciphertext)) + nonce + ciphertext


async def encrypt_stream(source: AsyncIterator[bytes], chunk_size: int = ENCRYPTION_CHUNK_SIZE) -> AsyncIterator[bytes]:
    aesgcm = AESGCM(_get_key())
    yield ENCRYPTION_MAGIC + bytes([ENCRYPTION_FORMAT_VERSION]) + struct.pack(">I", chunk_size)
    buffer = bytearray()
    async for data in source:
        buffer.extend(data)
        while len(buffer) >= chunk_size:
            yield _seal(aesgcm, bytes(buffer[:chunk_size]))
            del buffer[:chunk_size]
    if buffer:
        yield _seal(aesgcm, bytes(buffer))
    yield struct.pack(">I", 0)


class _StreamReader:
    def __init__(self, source: AsyncIterator[bytes]):
        self._source = source
        self._buffer = bytearray()
        self._exhausted = False

    async def read_exact(self, n: int) -> bytes:
        while len(self._buffer) < n and not self._exhausted:
            try:
                chunk = await self._source.__anext__()
            except StopAsyncIteration:
                self._exhausted = True
                break
            self._buffer.extend(chunk)
        if len(self._buffer) < n:
            raise ValueError(f"Unexpected end of encrypted stream (wanted {n} bytes, have {len(self._buffer)})")
        out = bytes(self._buffer[:n])
        del self._buffer[:n]
        return out


async def decrypt_stream(source: AsyncIterator[bytes]) -> AsyncIterator[bytes]:
    aesgcm = AESGCM(_get_key())
    reader = _StreamReader(source)

    header = await reader.read_exact(9)
    if header[:4] != ENCRYPTION_MAGIC:
        raise ValueError(f"Invalid encryption magic: {header[:4]!r}")
    if header[4] != ENCRYPTION_FORMAT_VERSION:
        raise ValueError(f"Unsupported encryption version: {header[4]}")
    # CHUNK_SIZE field is informational; per-chunk LEN drives reads.

    while True:
        len_bytes = await reader.read_exact(4)
        payload_len = struct.unpack(">I", len_bytes)[0]
        if payload_len == 0:
            return  # terminator
        nonce = await reader.read_exact(NONCE_SIZE)
        payload = await reader.read_exact(payload_len)
        plaintext = aesgcm.decrypt(nonce, payload, None)
        yield plaintext
