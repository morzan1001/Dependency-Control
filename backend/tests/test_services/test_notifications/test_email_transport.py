"""EmailProvider.send against a local SMTP server that offers STARTTLS: each encryption setting means what it says."""

import asyncio
import datetime
import ipaddress
import logging
import socket
import ssl

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app.models.system import SystemSettings
from app.services.notifications.email_provider import EmailProvider

_DELIVERY = ["MAIL", "RCPT", "DATA", "QUIT"]


def _self_signed_cert(directory) -> tuple[str, str]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = directory / "cert.pem", directory / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    return str(cert_path), str(key_path)


class _FakeSmtpServer:
    """Speaks just enough ESMTP to deliver one message and records every command verb it receives."""

    def __init__(self, tls_context: ssl.SSLContext, implicit_tls: bool):
        self.tls_context = tls_context
        self.implicit_tls = implicit_tls
        self.commands: list[str] = []
        self.data: bytes = b""

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        encrypted = self.implicit_tls
        writer.write(b"220 fake ESMTP\r\n")
        await writer.drain()
        while line := await reader.readline():
            verb = line.decode().split(" ", 1)[0].strip().upper()
            self.commands.append(verb)
            if verb == "EHLO":
                offer = b"" if encrypted else b"250-STARTTLS\r\n"
                writer.write(b"250-fake\r\n" + offer + b"250 8BITMIME\r\n")
            elif verb == "STARTTLS":
                writer.write(b"220 ready\r\n")
                await writer.drain()
                await writer.start_tls(self.tls_context)
                encrypted = True
                continue
            elif verb == "DATA":
                writer.write(b"354 go ahead\r\n")
                await writer.drain()
                while (chunk := await reader.readline()) != b".\r\n":
                    self.data += chunk
                writer.write(b"250 queued\r\n")
            elif verb == "QUIT":
                writer.write(b"221 bye\r\n")
                await writer.drain()
                break
            else:
                writer.write(b"250 ok\r\n")
            await writer.drain()
        writer.close()

    async def start(self) -> int:
        tls = self.tls_context if self.implicit_tls else None
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0, ssl=tls)
        return self.server.sockets[0].getsockname()[1]


@pytest.fixture(autouse=True)
def _fast_ehlo_name(monkeypatch):
    # aiosmtplib names itself in EHLO via socket.getfqdn, which can stall for seconds on a laptop resolver.
    monkeypatch.setattr(socket, "getfqdn", lambda *_: "client.test")


@pytest.fixture
def cert(tmp_path, monkeypatch):
    cert_path, key_path = _self_signed_cert(tmp_path)
    monkeypatch.setenv("SSL_CERT_FILE", cert_path)
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(cert_path, key_path)
    return context


async def _send(tls_context, encryption: str) -> tuple[bool, _FakeSmtpServer]:
    server = _FakeSmtpServer(tls_context, implicit_tls=encryption == "ssl")
    port = await server.start()
    settings = SystemSettings(
        smtp_host="localhost", smtp_port=port, smtp_encryption=encryption, emails_from_email="dc@example.com"
    )
    async with server.server:
        sent = await EmailProvider().send("to@example.com", "Subject", "Body", system_settings=settings)
    return sent, server


@pytest.mark.asyncio
async def test_starttls_upgrades_once_and_delivers(cert):
    sent, server = await _send(cert, "starttls")

    assert sent is True
    assert server.commands == ["EHLO", "STARTTLS", "EHLO", *_DELIVERY]


@pytest.mark.asyncio
async def test_no_encryption_stays_plaintext_although_the_server_offers_starttls(cert):
    sent, server = await _send(cert, "none")

    assert sent is True
    assert server.commands == ["EHLO", *_DELIVERY]


@pytest.mark.asyncio
async def test_ssl_speaks_tls_from_the_first_byte(cert):
    sent, server = await _send(cert, "ssl")

    assert sent is True
    assert server.commands == ["EHLO", *_DELIVERY]


@pytest.mark.asyncio
async def test_a_failed_send_is_logged_once(caplog):
    settings = SystemSettings(smtp_host="127.0.0.1", smtp_port=1, smtp_encryption="none")

    with caplog.at_level(logging.ERROR):
        sent = await EmailProvider().send("to@example.com", "Subject", "Body", system_settings=settings)

    assert sent is False
    assert len([r for r in caplog.records if r.levelno >= logging.ERROR]) == 1


@pytest.mark.asyncio
async def test_the_delivered_message_carries_a_date_and_a_message_id_of_the_sender_domain(cert):
    _, server = await _send(cert, "none")

    headers = server.data.decode().split("\r\n\r\n", 1)[0]
    assert "\r\nDate: " in f"\r\n{headers}"
    assert "@example.com>" in next(h for h in headers.split("\r\n") if h.startswith("Message-ID: "))
