import os
from itertools import pairwise
from unittest.mock import patch

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.constants import ENCRYPTION_CHUNK_SIZE, ENCRYPTION_FORMAT_VERSION, ENCRYPTION_MAGIC
from app.core.encryption import NONCE_SIZE, decrypt_stream, encrypt_stream


@pytest.fixture
def encryption_key():
    """Set a deterministic 32-byte hex key for tests."""
    key = "0" * 64
    with patch("app.core.encryption.settings") as mock_settings:
        mock_settings.ARCHIVE_ENCRYPTION_KEY = key
        yield key


def _parse_chunks(blob: bytes) -> list[tuple[bytes, bytes]]:
    """Walk the wire format and return (nonce, payload) per chunk."""
    pos = 9
    chunks: list[tuple[bytes, bytes]] = []
    while True:
        payload_len = int.from_bytes(blob[pos : pos + 4], "big")
        pos += 4
        if payload_len == 0:
            return chunks
        nonce = blob[pos : pos + NONCE_SIZE]
        pos += NONCE_SIZE
        chunks.append((nonce, blob[pos : pos + payload_len]))
        pos += payload_len


async def _encrypt(*parts: bytes, chunk_size: int = ENCRYPTION_CHUNK_SIZE) -> bytes:
    async def source():
        for part in parts:
            yield part

    return b"".join([chunk async for chunk in encrypt_stream(source(), chunk_size=chunk_size)])


async def _decrypt(blob: bytes, piece: int | None = None) -> bytes:
    async def source():
        step = piece or len(blob)
        for i in range(0, len(blob), step):
            yield blob[i : i + step]

    return b"".join([chunk async for chunk in decrypt_stream(source())])


@pytest.mark.asyncio
async def test_an_empty_stream_is_the_header_and_the_terminator(encryption_key):
    output = await _encrypt()

    assert output[:4] == ENCRYPTION_MAGIC
    assert output[4] == ENCRYPTION_FORMAT_VERSION
    assert int.from_bytes(output[5:9], "big") == ENCRYPTION_CHUNK_SIZE
    assert output[9:] == b"\x00\x00\x00\x00"


@pytest.mark.asyncio
async def test_encrypt_then_decrypt_roundtrip(encryption_key):
    plaintext = b"hello world " * 100_000  # ~1.2 MB, single chunk at 8 MiB

    assert await _decrypt(await _encrypt(plaintext)) == plaintext


@pytest.mark.asyncio
async def test_encrypt_multi_chunk_roundtrip(encryption_key):
    # 25 MiB → 4 chunks at 8 MiB each (~3 full + tail), fed in sizes that don't align with the chunk boundary
    plaintext = os.urandom(25 * 1024 * 1024)
    bounds = [0, 3_000_000, 8_500_000, 15_500_000, 25_000_000, 25_000_000, len(plaintext)]
    parts = [plaintext[start:end] for start, end in pairwise(bounds)]

    encrypted = await _encrypt(*parts)

    assert len(_parse_chunks(encrypted)) == 4
    assert await _decrypt(encrypted, piece=4096) == plaintext


@pytest.mark.asyncio
async def test_decrypt_rejects_bad_magic(encryption_key):
    async def bad_source():
        yield b"WRONG" + b"\x02" + b"\x00\x80\x00\x00" + b"\x00\x00\x00\x00"

    with pytest.raises(ValueError, match="magic"):
        async for _ in decrypt_stream(bad_source()):
            pass


@pytest.mark.asyncio
async def test_decrypt_rejects_unknown_version(encryption_key):
    async def bad_source():
        yield ENCRYPTION_MAGIC + b"\x99" + b"\x00\x80\x00\x00" + b"\x00\x00\x00\x00"

    with pytest.raises(ValueError, match="version"):
        async for _ in decrypt_stream(bad_source()):
            pass


@pytest.mark.asyncio
async def test_decrypt_rejects_tampered_chunk(encryption_key):
    blob = bytearray(await _encrypt(b"x" * 100))
    # Wire format: header(9) + per-chunk { LEN(4) || NONCE(12) || PAYLOAD(LEN bytes = ciphertext+tag) }
    # So ciphertext bytes start at offset 9 + 4 + 12 = 25
    blob[30] ^= 0xFF

    with pytest.raises(InvalidTag):
        await _decrypt(bytes(blob))


@pytest.mark.asyncio
async def test_decrypt_wrong_key_raises(encryption_key):
    encrypted = await _encrypt(b"secret payload")

    with patch("app.core.encryption.settings") as mock_settings:
        mock_settings.ARCHIVE_ENCRYPTION_KEY = "f" * 64
        with pytest.raises(InvalidTag):
            await _decrypt(encrypted)


@pytest.mark.asyncio
async def test_every_chunk_of_a_stream_carries_its_own_nonce(encryption_key):
    encrypted = await _encrypt(b"A" * 64 * 6, chunk_size=64)

    nonces = [nonce for nonce, _ in _parse_chunks(encrypted)]

    assert len(nonces) == 6
    assert len(set(nonces)) == len(nonces)


@pytest.mark.asyncio
async def test_identical_plaintext_chunks_do_not_produce_identical_ciphertext(encryption_key):
    """A repeated nonce under one AES-GCM key leaks plaintext equality and destroys the tag's integrity guarantee."""
    plaintext = b"B" * 64

    first = _parse_chunks(await _encrypt(plaintext, chunk_size=64))
    second = _parse_chunks(await _encrypt(plaintext, chunk_size=64))

    assert first[0][1] != second[0][1]


@pytest.mark.asyncio
async def test_a_64_hex_character_key_is_decoded_as_hex_rather_than_hashed():
    key_hex = "0123456789abcdef" * 4
    plaintext = b"archive bundle bytes"

    with patch("app.core.encryption.settings") as mock_settings:
        mock_settings.ARCHIVE_ENCRYPTION_KEY = key_hex
        encrypted = await _encrypt(plaintext, chunk_size=64)

    nonce, payload = _parse_chunks(encrypted)[0]

    assert AESGCM(bytes.fromhex(key_hex)).decrypt(nonce, payload, None) == plaintext
