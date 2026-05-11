"""Chunked AES-256-GCM streaming encryption for archive bundles.

Wire format (big-endian for length fields):
    MAGIC (4 bytes)          : b"DCEN"
    VERSION (1 byte)         : ENCRYPTION_FORMAT_VERSION
    CHUNK_SIZE (4 bytes BE)  : plaintext chunk size used by writer (informational on read)
    [repeated per chunk]:
        LEN (4 bytes BE)     : ciphertext+tag length for this chunk (LEN=0 marks end)
        NONCE (12 bytes)     : random per chunk
        PAYLOAD (LEN bytes)  : ciphertext || 16-byte GCM tag

Each chunk uses a fresh random 96-bit nonce. The 32-byte key is derived from
settings.ARCHIVE_ENCRYPTION_KEY (hex-decoded if it's exactly 64 hex chars,
otherwise SHA-256 of the UTF-8 bytes).

Security note: each chunk's GCM tag authenticates only that chunk's ciphertext.
There is no sequence-number binding and no stream-level MAC. Chunk reordering,
deletion, and cross-stream injection are not detected at the crypto layer.
This is acceptable for the archive use case (storage is access-controlled and
the threat model is confidentiality against passive readers, not active
tampering by a party with both storage access and the key). Callers requiring
active-adversary resistance must add an outer MAC or sequence-number binding.
"""

import hashlib
import os
import struct
from typing import AsyncIterator, Awaitable, Callable

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


SinkFn = Callable[[bytes], Awaitable[None]]


class EncryptionStreamWriter:
    """Streaming AES-GCM encryptor.

    Buffers plaintext until CHUNK_SIZE bytes have accumulated, then emits an
    encrypted chunk to the sink. Call ``aclose()`` to flush any partial
    chunk and emit the terminator.
    """

    def __init__(self, sink: SinkFn, chunk_size: int = ENCRYPTION_CHUNK_SIZE):
        self._sink = sink
        self._chunk_size = chunk_size
        self._aesgcm = AESGCM(_get_key())
        self._buffer = bytearray()
        self._started = False
        self._closed = False

    async def start(self) -> None:
        if self._started:
            return
        header = ENCRYPTION_MAGIC + bytes([ENCRYPTION_FORMAT_VERSION]) + struct.pack(">I", self._chunk_size)
        await self._sink(header)
        self._started = True

    async def write(self, data: bytes) -> None:
        if self._closed:
            raise RuntimeError("EncryptionStreamWriter is closed")
        if not self._started:
            await self.start()
        if not data:
            return
        self._buffer.extend(data)
        while len(self._buffer) >= self._chunk_size:
            chunk = bytes(self._buffer[: self._chunk_size])
            del self._buffer[: self._chunk_size]
            await self._emit_chunk(chunk)

    async def aclose(self) -> None:
        if self._closed:
            return
        if not self._started:
            await self.start()
        if self._buffer:
            await self._emit_chunk(bytes(self._buffer))
            self._buffer.clear()
        await self._sink(struct.pack(">I", 0))  # terminator: LEN=0
        self._closed = True

    async def _emit_chunk(self, plaintext: bytes) -> None:
        nonce = os.urandom(NONCE_SIZE)
        ciphertext = self._aesgcm.encrypt(nonce, plaintext, None)
        await self._sink(struct.pack(">I", len(ciphertext)) + nonce + ciphertext)


class _StreamReader:
    """Reads exact byte counts from an AsyncIterator[bytes]."""

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
            raise ValueError(
                f"Unexpected end of encrypted stream (wanted {n} bytes, have {len(self._buffer)})"
            )
        out = bytes(self._buffer[:n])
        del self._buffer[:n]
        return out


async def decrypt_stream(source: AsyncIterator[bytes]) -> AsyncIterator[bytes]:
    """Decrypt a chunked AES-GCM stream, yielding plaintext chunks.

    Wire format reminder:
        header = 9 bytes (4 magic + 1 version + 4 chunk_size)
        per chunk: LEN(4) || NONCE(12) || PAYLOAD(LEN bytes ciphertext+tag)
        LEN excludes the nonce.
    """
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
