"""Device transport interface and the shape of device-reported state.

The central idea of Phase 2: every decision is made against what the gateway
actually reports, not against what we believe we deployed. The Ansible version
never read certificate state back, so an import that silently failed looked
identical to one that worked.
"""

from datetime import datetime
from dataclasses import dataclass, field
from typing import Protocol


class DeviceError(RuntimeError):
    """A device operation failed. Message is expected to reach an operator."""


class VerificationError(DeviceError):
    """The device does not report what we just asked it to install."""


@dataclass
class TrustpointState:
    """One trustpoint as the device reports it.

    ``subject_cn``/``serial`` describe the *identity* certificate. A trustpoint
    can also hold a CA certificate -- the derived ``-rrrN`` trustpoints created
    for CAs higher in the chain hold only that -- which is recorded separately
    in ``ca_subject_cn``. Conflating the two would make a trustpoint appear to
    be issued to its own issuer.
    """

    label: str
    subject_cn: str | None = None
    serial: str | None = None
    validity_start: datetime | None = None
    validity_end: datetime | None = None
    has_certificate: bool = False
    ca_subject_cn: str | None = None

    def describe(self) -> str:
        """One-line summary for operator-facing output."""
        if self.has_certificate:
            return f"cn={self.subject_cn} serial={self.serial}"
        if self.ca_subject_cn:
            return f"CA certificate: {self.ca_subject_cn}"
        return "(no certificate)"

    def matches(self, subject_cn: str, serial: str) -> bool:
        if not self.has_certificate:
            return False
        if self.subject_cn != subject_cn:
            return False
        # IOS-XE renders serials uppercase hex without separators; normalise.
        return (self.serial or "").upper().lstrip("0") == serial.upper().lstrip("0")


@dataclass
class DeviceState:
    """Everything we need to plan a deployment."""

    trustpoints: dict[str, TrustpointState] = field(default_factory=dict)
    bound_trustpoint: str | None = None
    raw: dict[str, str] = field(default_factory=dict)

    def get(self, label: str) -> TrustpointState | None:
        return self.trustpoints.get(label)


class DeviceTransport(Protocol):
    """Operations needed to place a certificate on a gateway."""

    def read_state(self) -> DeviceState: ...

    def upload_file(self, data: bytes, remote_name: str) -> None: ...

    def delete_file(self, remote_name: str) -> None: ...

    def delete_trustpoint(self, label: str) -> None: ...

    def import_pkcs12(self, label: str, remote_name: str, password: str) -> None: ...

    def set_revocation_check(self, label: str, mode: str) -> None: ...

    def bind_trustpoint(self, label: str) -> None: ...

    def save_config(self) -> None: ...
