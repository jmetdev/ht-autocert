"""Blue/green certificate deployment.

Replaces play 2 of the playbook and the EEM applet. The ordering is the whole
point:

    upload -> clear IDLE trustpoint -> import -> VERIFY -> rebind -> verify
    -> save -> clean up

The active trustpoint is never touched until the new certificate is confirmed
present on the device. The EEM applet did the opposite -- it deleted the
trustpoint and zeroized the key *before* importing, so a PKCS12 the device
could not parse left the gateway with no key and no trustpoint, which on a
survivability gateway means a voice outage.

If verification fails here, the old trustpoint is still bound and still serving.
"""

import uuid
from dataclasses import dataclass, field

import structlog
from sqlmodel import Session

from app.db.models import (
    AuditEvent,
    CertStatus,
    Certificate,
    Device,
    RunLog,
    RunStatus,
    utcnow,
)
from app.devices.base import (
    DeviceError,
    DeviceState,
    DeviceTransport,
    VerificationError,
)

log = structlog.get_logger(__name__)

REMOTE_FILENAME = "htautocert.p12"

# Substrings identifying a lost session rather than a rejected operation.
_DISCONNECT_MARKERS = (
    "eof reading from transport",
    "closed the connection",
    "connection closed",
    "transport is not open",
    "broken pipe",
    "connection reset",
)


def _is_disconnect(exc: Exception) -> bool:
    message = str(exc).lower()
    return any(marker in message for marker in _DISCONNECT_MARKERS)


@dataclass
class DeploymentResult:
    fqdn: str
    status: str  # deployed | skipped | failed | rolled_back
    detail: str = ""
    steps: list[str] = field(default_factory=list)
    previous_trustpoint: str | None = None
    active_trustpoint: str | None = None


class Deployer:
    """Drives one device through a blue/green cutover."""

    def __init__(
        self,
        transport: DeviceTransport,
        *,
        revocation_check: str = "none",
        remote_filename: str = REMOTE_FILENAME,
        rebind: bool = True,
    ):
        self.transport = transport
        self.revocation_check = revocation_check
        self.remote_filename = remote_filename
        self.rebind = rebind
        self.steps: list[str] = []

    def _step(self, message: str) -> None:
        self.steps.append(message)
        log.info("deploy.step", step=message)

    def deploy(
        self,
        *,
        fqdn: str,
        p12: bytes,
        password: str,
        subject_cn: str,
        serial: str,
        idle_trustpoint: str,
    ) -> DeploymentResult:
        state = self.transport.read_state()
        previous = state.bound_trustpoint
        self._step(f"read device state (bound={previous or 'none'})")

        if previous == idle_trustpoint:
            raise DeviceError(
                f"{fqdn}: refusing to deploy into {idle_trustpoint}, which is the "
                "trustpoint currently bound in 'sip-ua crypto signaling'. Device "
                "state and stored state disagree; reconcile before deploying."
            )

        already = state.get(idle_trustpoint)
        if already and already.matches(subject_cn, serial):
            self._step(f"{idle_trustpoint} already holds serial {serial}")

        # --- stage the bundle ------------------------------------------------
        self.transport.upload_file(p12, self.remote_filename)
        self._step(f"uploaded {self.remote_filename}")

        try:
            # --- import into the IDLE trustpoint only ------------------------
            self._prepare_idle_trustpoint(idle_trustpoint, already)

            try:
                self.transport.import_pkcs12(
                    idle_trustpoint, self.remote_filename, password
                )
                self._step(f"imported PKCS12 into {idle_trustpoint}")
            except DeviceError as exc:
                if not _is_disconnect(exc):
                    raise
                # A dropped session is not evidence the import failed -- IOS-XE
                # can complete it and still close the connection. Reconnect and
                # let verification against the device decide.
                self._step(f"session dropped during import ({exc}); reconnecting")
                self._reconnect()

            self.transport.set_revocation_check(idle_trustpoint, self.revocation_check)
            self._step(f"set revocation-check {self.revocation_check}")

            # --- verify BEFORE touching what is serving traffic --------------
            self._verify(fqdn, idle_trustpoint, subject_cn, serial)
            self._step(f"verified {idle_trustpoint} holds serial {serial}")

            if not self.rebind:
                self._step("rebind skipped by request")
                return DeploymentResult(
                    fqdn=fqdn,
                    status="deployed",
                    detail=f"imported into {idle_trustpoint}, not bound",
                    steps=self.steps,
                    previous_trustpoint=previous,
                    active_trustpoint=previous,
                )

            # --- cutover ------------------------------------------------------
            self.transport.bind_trustpoint(idle_trustpoint)
            self._step(f"bound sip-ua to {idle_trustpoint}")

            try:
                self._verify_binding(fqdn, idle_trustpoint)
                self._step("confirmed binding")
            except VerificationError:
                if previous:
                    self.transport.bind_trustpoint(previous)
                    self._step(f"ROLLED BACK to {previous}")
                    return DeploymentResult(
                        fqdn=fqdn,
                        status="rolled_back",
                        detail=(
                            f"binding to {idle_trustpoint} did not take; restored "
                            f"{previous}"
                        ),
                        steps=self.steps,
                        previous_trustpoint=previous,
                        active_trustpoint=previous,
                    )
                raise

            self.transport.save_config()
            self._step("wrote configuration to NVRAM")

            return DeploymentResult(
                fqdn=fqdn,
                status="deployed",
                detail=f"{previous or 'none'} -> {idle_trustpoint}",
                steps=self.steps,
                previous_trustpoint=previous,
                active_trustpoint=idle_trustpoint,
            )
        finally:
            # The bundle is removed whether or not the import worked -- a p12
            # sitting on flash is an offline attack on the escrowed key.
            try:
                self.transport.delete_file(self.remote_filename)
                self._step(f"removed {self.remote_filename} from flash")
            except DeviceError as exc:
                log.warning("deploy.cleanup_failed", fqdn=fqdn, error=str(exc))

    def _prepare_idle_trustpoint(self, label: str, from_state) -> None:
        """Leave ``label`` with no trustpoint and no key pair.

        Both must go, and both are checked live rather than inferred from the
        state read at the top of the run:

        * A trustpoint left defined makes the import fail with
          ``% Trustpoint '<label>' is in use.``
        * A key pair left behind makes it prompt ``You already have RSA keys
          named <label> ... replace them? [yes/no]`` and block.

        Safe precisely because this is the *idle* trustpoint. The EEM applet
        did the same to the active one, which is what turned an unreadable
        bundle into an outage.
        """
        # Derived CA trustpoints first: they are re-created by the next import,
        # so leaving them accrues one set per renewal.
        derived = getattr(self.transport, "derived_trustpoints", None)
        for extra in derived(label) if derived else []:
            self.transport.delete_trustpoint(extra)
            self._step(f"cleared derived CA trustpoint {extra}")

        tp_exists = getattr(self.transport, "trustpoint_exists", None)
        exists = tp_exists(label) if tp_exists else from_state is not None
        if exists:
            self.transport.delete_trustpoint(label)
            self._step(f"cleared idle trustpoint {label}")

        key_exists = getattr(self.transport, "rsa_key_exists", None)
        zeroize = getattr(self.transport, "zeroize_key", None)
        if key_exists and zeroize and key_exists(label):
            zeroize(label)
            self._step(f"zeroized stale RSA key {label}")

    def _reconnect(self) -> None:
        reconnect = getattr(self.transport, "reconnect", None)
        if reconnect is None:
            raise DeviceError(
                "session was lost and this transport cannot reconnect; re-run "
                "the deployment to verify what the device actually holds"
            )
        reconnect()
        self._step("reconnected")

    def _verify(
        self, fqdn: str, trustpoint: str, subject_cn: str, serial: str
    ) -> DeviceState:
        state = self.transport.read_state()
        tp = state.get(trustpoint)
        if tp is None:
            raise VerificationError(
                f"{fqdn}: trustpoint {trustpoint} is absent after import -- the "
                "device rejected the PKCS12. If this is an older IOS-XE train, "
                "try the 'legacy' PKCS12 profile."
            )
        if not tp.has_certificate:
            raise VerificationError(
                f"{fqdn}: trustpoint {trustpoint} exists but holds no certificate "
                "after import"
            )
        if not tp.matches(subject_cn, serial):
            raise VerificationError(
                f"{fqdn}: trustpoint {trustpoint} holds "
                f"cn={tp.subject_cn} serial={tp.serial}, expected "
                f"cn={subject_cn} serial={serial}"
            )
        return state

    def _verify_binding(self, fqdn: str, trustpoint: str) -> None:
        state = self.transport.read_state()
        if state.bound_trustpoint != trustpoint:
            raise VerificationError(
                f"{fqdn}: sip-ua reports trustpoint "
                f"{state.bound_trustpoint or 'none'} after binding {trustpoint}"
            )


class DeploymentService:
    """Ties the deployer to the datastore."""

    def __init__(self, session: Session, box, transport_factory):
        self.session = session
        self.box = box
        self.transport_factory = transport_factory

    def deploy_device(
        self,
        device: Device,
        cert: Certificate,
        *,
        run_id: str | None = None,
        rebind: bool = True,
        revocation_check: str = "none",
        actor: str = "cli",
    ) -> DeploymentResult:
        from app.vault import aad_pkcs12, aad_pkcs12_password

        run_id = run_id or uuid.uuid4().hex[:12]
        bound = log.bind(run_id=run_id, fqdn=device.fqdn)

        p12 = self.box.open(cert.pkcs12_sealed, aad_pkcs12(device.fqdn, cert.serial))
        password = self.box.open(
            cert.pkcs12_password_sealed, aad_pkcs12_password(device.fqdn, cert.serial)
        ).decode()
        self.session.add(
            AuditEvent(
                actor=actor,
                action="p12.deploy",
                subject=device.fqdn,
                detail=f"serial={cert.serial}",
            )
        )
        self.session.commit()

        idle = cert.target_trustpoint or device.idle_trustpoint()

        try:
            with self.transport_factory(device) as transport:
                deployer = Deployer(
                    transport, revocation_check=revocation_check, rebind=rebind
                )
                result = deployer.deploy(
                    fqdn=device.fqdn,
                    p12=p12,
                    password=password,
                    subject_cn=cert.subject_cn,
                    serial=cert.serial,
                    idle_trustpoint=idle,
                )
        except Exception as exc:  # noqa: BLE001 - recorded, not swallowed
            bound.error("deploy.failed", error=str(exc))
            self._record(run_id, device, RunStatus.failed, str(exc))
            return DeploymentResult(fqdn=device.fqdn, status="failed", detail=str(exc))

        if result.status == "deployed" and result.active_trustpoint == idle:
            self._mark_superseded(device, cert)
            device.active_trustpoint = idle
            cert.status = CertStatus.deployed
            cert.deployed_at = utcnow()
            self.session.add(device)
            self.session.add(cert)

        self._record(
            run_id,
            device,
            RunStatus.success if result.status == "deployed" else RunStatus.failed,
            result.detail,
        )
        bound.info("deploy.completed", status=result.status, detail=result.detail)
        return result

    def _mark_superseded(self, device: Device, current: Certificate) -> None:
        from sqlmodel import select

        stmt = (
            select(Certificate)
            .where(Certificate.device_id == device.id)
            .where(Certificate.status == CertStatus.deployed)
        )
        for old in self.session.exec(stmt).all():
            if old.id != current.id:
                old.status = CertStatus.superseded
                self.session.add(old)

    def _record(
        self, run_id: str, device: Device, status: RunStatus, detail: str
    ) -> None:
        self.session.add(
            RunLog(
                run_id=run_id,
                device_id=device.id,
                action="deploy",
                status=status,
                detail=(detail or "")[:2000],
                finished_at=utcnow(),
            )
        )
        self.session.commit()
