import os
from unittest.mock import patch

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.constants import ENCRYPTION_CHUNK_SIZE, ENCRYPTION_FORMAT_VERSION, ENCRYPTION_MAGIC
from app.core.encryption import NONCE_SIZE


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


async def _encrypt(plaintext: bytes, chunk_size: int) -> bytes:
    from app.core.encryption import EncryptionStreamWriter

    collected: list[bytes] = []

    async def sink(chunk: bytes) -> None:
        collected.append(chunk)

    writer = EncryptionStreamWriter(sink, chunk_size=chunk_size)
    await writer.start()
    await writer.write(plaintext)
    await writer.aclose()
    return b"".join(collected)


@pytest.mark.asyncio
async def test_encryption_stream_writer_emits_magic_and_header(encryption_key):
    from app.core.encryption import EncryptionStreamWriter

    collected: list[bytes] = []

    async def sink(chunk: bytes) -> None:
        collected.append(chunk)

    writer = EncryptionStreamWriter(sink)
    await writer.start()
    await writer.aclose()

    output = b"".join(collected)
    # Magic + version byte + chunk_size uint32 + terminator (LEN=0 = 4 zero bytes)
    assert output[:4] == ENCRYPTION_MAGIC
    assert output[4] == ENCRYPTION_FORMAT_VERSION
    assert int.from_bytes(output[5:9], "big") == ENCRYPTION_CHUNK_SIZE
    assert output[-4:] == b"\x00\x00\x00\x00"


@pytest.mark.asyncio
async def test_encrypt_then_decrypt_roundtrip(encryption_key):
    from app.core.encryption import EncryptionStreamWriter, decrypt_stream

    plaintext = b"hello world " * 100_000  # ~1.2 MB, single chunk at 8 MiB
    collected: list[bytes] = []

    async def sink(chunk: bytes) -> None:
        collected.append(chunk)

    writer = EncryptionStreamWriter(sink)
    await writer.start()
    await writer.write(plaintext)
    await writer.aclose()

    encrypted = b"".join(collected)

    async def source():
        yield encrypted

    out: list[bytes] = []
    async for chunk in decrypt_stream(source()):
        out.append(chunk)
    assert b"".join(out) == plaintext


@pytest.mark.asyncio
async def test_encrypt_multi_chunk_roundtrip(encryption_key):
    from app.core.encryption import EncryptionStreamWriter, decrypt_stream

    # 25 MiB → 4 chunks at 8 MiB each (~3 full + tail)
    plaintext = os.urandom(25 * 1024 * 1024)
    collected: list[bytes] = []

    async def sink(chunk: bytes) -> None:
        collected.append(chunk)

    writer = EncryptionStreamWriter(sink)
    await writer.start()
    # Feed in arbitrary write sizes that don't align with chunk boundary
    pos = 0
    for size in (3_000_000, 5_500_000, 7_000_000, 9_500_000, 0):
        await writer.write(plaintext[pos : pos + size])
        pos += size
    await writer.write(plaintext[pos:])
    await writer.aclose()

    encrypted = b"".join(collected)

    async def source():
        # Yield in small chunks to test stream-parsing
        for i in range(0, len(encrypted), 4096):
            yield encrypted[i : i + 4096]

    out: list[bytes] = []
    async for chunk in decrypt_stream(source()):
        out.append(chunk)
    assert b"".join(out) == plaintext


@pytest.mark.asyncio
async def test_decrypt_rejects_bad_magic(encryption_key):
    from app.core.encryption import decrypt_stream

    async def bad_source():
        yield b"WRONG" + b"\x02" + b"\x00\x80\x00\x00" + b"\x00\x00\x00\x00"

    with pytest.raises(ValueError, match="magic"):
        async for _ in decrypt_stream(bad_source()):
            pass


@pytest.mark.asyncio
async def test_decrypt_rejects_unknown_version(encryption_key):
    from app.core.encryption import decrypt_stream

    async def bad_source():
        yield ENCRYPTION_MAGIC + b"\x99" + b"\x00\x80\x00\x00" + b"\x00\x00\x00\x00"

    with pytest.raises(ValueError, match="version"):
        async for _ in decrypt_stream(bad_source()):
            pass


@pytest.mark.asyncio
async def test_decrypt_rejects_tampered_chunk(encryption_key):
    from app.core.encryption import EncryptionStreamWriter, decrypt_stream

    plaintext = b"x" * 100
    collected: list[bytes] = []

    async def sink(chunk: bytes) -> None:
        collected.append(chunk)

    writer = EncryptionStreamWriter(sink)
    await writer.start()
    await writer.write(plaintext)
    await writer.aclose()

    blob = bytearray(b"".join(collected))
    # Flip a byte in the ciphertext region.
    # Wire format: header(9) + per-chunk { LEN(4) || NONCE(12) || PAYLOAD(LEN bytes = ciphertext+tag) }
    # So ciphertext bytes start at offset 9 + 4 + 12 = 25
    blob[30] ^= 0xFF

    async def source():
        yield bytes(blob)

    with pytest.raises(InvalidTag):
        async for _ in decrypt_stream(source()):
            pass


@pytest.mark.asyncio
async def test_write_after_aclose_raises(encryption_key):
    from app.core.encryption import EncryptionStreamWriter

    async def sink(chunk: bytes) -> None:
        collected_discard: list[bytes] = []
        collected_discard.append(chunk)

    writer = EncryptionStreamWriter(sink)
    await writer.aclose()

    with pytest.raises(RuntimeError, match="closed"):
        await writer.write(b"data after close")


@pytest.mark.asyncio
async def test_decrypt_wrong_key_raises(encryption_key):
    from app.core.encryption import EncryptionStreamWriter, decrypt_stream

    plaintext = b"secret payload"
    collected: list[bytes] = []

    async def sink(chunk: bytes) -> None:
        collected.append(chunk)

    writer = EncryptionStreamWriter(sink)
    await writer.start()
    await writer.write(plaintext)
    await writer.aclose()

    encrypted = b"".join(collected)

    # Swap the key for the decryption side
    different_key = "f" * 64
    with patch("app.core.encryption.settings") as mock_settings:
        mock_settings.ARCHIVE_ENCRYPTION_KEY = different_key

        async def source():
            yield encrypted

        with pytest.raises(InvalidTag):
            async for _ in decrypt_stream(source()):
                pass


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
    from app.core.encryption import EncryptionStreamWriter

    key_hex = "0123456789abcdef" * 4
    plaintext = b"archive bundle bytes"
    collected: list[bytes] = []

    async def sink(chunk: bytes) -> None:
        collected.append(chunk)

    with patch("app.core.encryption.settings") as mock_settings:
        mock_settings.ARCHIVE_ENCRYPTION_KEY = key_hex
        writer = EncryptionStreamWriter(sink, chunk_size=64)
        await writer.start()
        await writer.write(plaintext)
        await writer.aclose()

    nonce, payload = _parse_chunks(b"".join(collected))[0]

    assert AESGCM(bytes.fromhex(key_hex)).decrypt(nonce, payload, None) == plaintext
