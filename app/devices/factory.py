"""Build a transport for a device, resolving credentials through the vault."""

import structlog
from sqlmodel import Session

from app.db.models import Device, Tenant
from app.devices.base import DeviceError
from app.devices.ssh import IosXeSshTransport
from app.vault import SecretBox

log = structlog.get_logger(__name__)


def aad_device_secret(fqdn: str, field: str) -> str:
    return f"device:{fqdn}:{field}"


def aad_tenant_secret(slug: str, field: str) -> str:
    return f"tenant:{slug}:{field}"


def _unseal(box: SecretBox, blob: bytes, aad: str, owner: str, remedy: str) -> str:
    """Open a sealed credential, turning a key mismatch into a usable message.

    A rotated or lost HTAC_MASTER_KEY otherwise surfaces as a bare
    authentication failure deep in the vault, which reads like corruption
    rather than what it is.
    """
    from app.vault import VaultError

    try:
        return box.open(blob, aad).decode()
    except VaultError as exc:
        raise DeviceError(
            f"stored credential for {owner} cannot be decrypted with the current "
            f"HTAC_MASTER_KEY. If the key was rotated or lost, re-enter the "
            f"credential: {remedy}"
        ) from exc


def resolve_credentials(
    session: Session, device: Device, box: SecretBox
) -> tuple[str, str, str | None]:
    """Return (username, password, enable_password).

    Device-level credentials win; otherwise the tenant defaults apply. The
    Ansible version used one ``VG_USERNAME``/``VG_PASSWORD`` pair for every
    gateway across every client.
    """
    tenant = session.get(Tenant, device.tenant_id)

    username = device.username or (tenant.default_username if tenant else None)
    if not username:
        raise DeviceError(
            f"{device.fqdn}: no username configured on the device or tenant "
            f"(set one with: htac device set-credentials {device.fqdn})"
        )

    if device.password_sealed:
        password = _unseal(
            box,
            device.password_sealed,
            aad_device_secret(device.fqdn, "password"),
            f"device {device.fqdn}",
            f"./htac device set-credentials {device.fqdn}",
        )
    elif tenant and tenant.default_password_sealed:
        password = _unseal(
            box,
            tenant.default_password_sealed,
            aad_tenant_secret(tenant.slug, "password"),
            f"tenant {tenant.slug}",
            f"./htac tenant set-credentials {tenant.slug}",
        )
    else:
        raise DeviceError(
            f"{device.fqdn}: no password configured on the device or tenant "
            f"(set one with: htac device set-credentials {device.fqdn})"
        )

    enable_password = None
    if device.enable_password_sealed:
        enable_password = box.open(
            device.enable_password_sealed,
            aad_device_secret(device.fqdn, "enable_password"),
        ).decode()

    return username, password, enable_password


def build_transport(session: Session, device: Device, box: SecretBox):
    username, password, enable_password = resolve_credentials(session, device, box)
    if device.strict_host_key and not device.ssh_host_key:
        log.warning(
            "device.no_pinned_host_key",
            fqdn=device.fqdn,
            hint=f"./htac device trust {device.fqdn}",
        )
    return IosXeSshTransport(
        host=device.mgmt_address,
        username=username,
        password=password,
        enable_password=enable_password,
        port=device.ssh_port,
        filesystem=device.filesystem,
        strict_host_key=device.strict_host_key,
        host_key=device.ssh_host_key,
    )


def fetch_host_key(host: str, port: int = 22) -> tuple[str, str, str]:
    """Retrieve a device's SSH host key without trusting it.

    Returns (known_hosts_line, key_type, sha256 fingerprint) so an operator can
    compare the fingerprint out of band before pinning it.
    """
    import base64
    import hashlib
    import socket

    import paramiko

    sock = socket.create_connection((host, port), timeout=15)
    transport = paramiko.Transport(sock)
    try:
        transport.start_client(timeout=15)
        key = transport.get_remote_server_key()
    finally:
        transport.close()

    fingerprint = base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode()
    line = f"{host} {key.get_name()} {key.get_base64()}"
    return line, key.get_name(), f"SHA256:{fingerprint.rstrip('=')}"
