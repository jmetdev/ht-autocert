from __future__ import annotations

import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

from app.vault import SecretBox


@pytest.fixture
def box() -> SecretBox:
    return SecretBox.from_b64(SecretBox.generate_master_key())


@pytest.fixture(autouse=True)
def isolated_environment(tmp_path, monkeypatch):
    """Keep tests off the real datastore.

    The FastAPI lifespan calls init_db() against the globally configured
    database; point it at a throwaway file so a test run never touches
    ./data/htac.db.
    """
    import os

    import app.config
    import app.db.session

    # Clear every HTAC_* variable first. Otherwise a developer with a real
    # .env.htac sourced into their shell sees tests pass or fail depending on
    # their own configuration.
    for key in [k for k in os.environ if k.startswith("HTAC_")]:
        monkeypatch.delenv(key, raising=False)

    # The FastAPI lifespan calls get_settings() directly, so dependency
    # overrides cannot stop it starting a real background scheduler.
    monkeypatch.setenv("HTAC_SCHEDULE_ENABLED", "false")
    monkeypatch.setenv("HTAC_DATABASE_URL", f"sqlite:///{tmp_path}/test.db")
    monkeypatch.setenv("HTAC_MASTER_KEY", SecretBox.generate_master_key())
    app.config.reset_settings()
    app.db.session.reset_engine()
    yield
    app.config.reset_settings()
    app.db.session.reset_engine()


@pytest.fixture
def session():
    # StaticPool + check_same_thread=False: TestClient runs the app in a
    # separate thread, and SQLite connections are not shareable by default.
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    import app.db.models  # noqa: F401

    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


def _make_cert(subject_cn: str, issuer_cn: str, key, issuer_key, *, ca: bool,
               days: int = 90):
    now = datetime.datetime.now(datetime.timezone.utc)
    subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, subject_cn)])
    issuer = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, issuer_cn)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    return builder.sign(issuer_key, hashes.SHA256())


@pytest.fixture
def cert_chain():
    """(leaf_key_pem, fullchain_pem) with a leaf + intermediate + root."""
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    inter_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    root = _make_cert("Test Root R1", "Test Root R1", root_key, root_key, ca=True)
    inter = _make_cert("Test Intermediate I1", "Test Root R1", inter_key, root_key, ca=True)
    leaf = _make_cert(
        "vg01.example.com", "Test Intermediate I1", leaf_key, inter_key, ca=False
    )

    fullchain = "".join(
        c.public_bytes(serialization.Encoding.PEM).decode() for c in (leaf, inter, root)
    )
    key_pem = leaf_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return key_pem, fullchain
