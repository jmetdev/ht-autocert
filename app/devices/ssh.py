"""IOS-XE transport over SSH (scrapli).

PKCS12 bundles are pulled by the gateway over HTTPS (``copy https://...``) rather
than pushed with SCP, which needs ``ip scp server enable`` and is a frequent
source of transfer failures. Driving ``crypto pki import`` over SSH means the
PKCS12 password lives only in the session -- it is never rendered into
``running-config``.

Prompt handling was validated against a Catalyst 8200 running IOS-XE 17.15.3a
by capturing the raw channel; see the notes on the constants below.
"""

import os
import tempfile

import structlog
from scrapli import Scrapli
from scrapli.exceptions import ScrapliException

from app.devices.base import DeviceError, DeviceState
from app.devices.parsing import build_state

log = structlog.get_logger(__name__)

# Confirmation prompts.
#
# scrapli's send_interactive matches these as LITERAL strings, not regexes --
# passing an escaped pattern like r"\[yes/no\]" never matches, and supplying
# interaction_complete_patterns on top desynchronises the read so the session
# blocks until the device's exec-timeout drops it. Verified against a Catalyst
# 8200 on 17.15.3a.
CONFIRM_YES_NO = "[yes/no]"
CONFIRM_BRACKET = "[confirm]"
PROMPT_CONFIG = "(config)#"
PROMPT_EXEC = "#"

# A PKCS12 import takes ~60s on a Catalyst 8200; the default op timeout is short
# enough that a slow device looks like a hang.
IMPORT_TIMEOUT = 240.0

SHOW_CERTIFICATES = "show crypto pki certificates verbose"
SHOW_SIGNALING = "show running-config | include crypto signaling"
SHOW_TRUSTPOINTS = "show running-config | include ^crypto pki trustpoint"


class IosXeSshTransport:
    """SSH/SCP transport for a single gateway."""

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        *,
        enable_password: str | None = None,
        port: int = 22,
        filesystem: str = "bootflash:",
        timeout_ops: float = 120.0,
        strict_host_key: bool = True,
        known_hosts_file: str | None = None,
        host_key: str | None = None,
        driver_factory=None,
    ):
        self.host = host
        self.username = username
        self.password = password
        self.enable_password = enable_password
        self.port = port
        self.filesystem = filesystem.rstrip("/")
        self.strict_host_key = strict_host_key
        self.known_hosts_file = known_hosts_file
        self.host_key = host_key
        self._known_hosts_tmp = None
        self._timeout_ops = timeout_ops
        self._driver_factory = driver_factory or self._default_driver
        self._conn = None

    # -- connection --------------------------------------------------------

    def _known_hosts_path(self) -> str | None:
        """Path to a known_hosts file for this connection.

        A pinned key is materialised into a temporary file so both scrapli and
        paramiko can use it. Without this, host key verification depends on the
        invoking user's ~/.ssh/known_hosts -- which does not exist in a
        container, and is not a per-device trust decision anywhere.
        """
        if self.known_hosts_file:
            return self.known_hosts_file
        if not self.host_key:
            return None
        if self._known_hosts_tmp is None:
            tmp = tempfile.NamedTemporaryFile(
                "w", suffix=".known_hosts", delete=False
            )
            tmp.write(self.host_key.strip() + "\n")
            tmp.close()
            os.chmod(tmp.name, 0o600)
            self._known_hosts_tmp = tmp.name
        return self._known_hosts_tmp

    def _discard_known_hosts_tmp(self) -> None:
        if self._known_hosts_tmp:
            try:
                os.unlink(self._known_hosts_tmp)
            except OSError:
                pass
            self._known_hosts_tmp = None

    def _default_driver(self):
        return Scrapli(
            platform="cisco_iosxe",
            host=self.host,
            port=self.port,
            auth_username=self.username,
            auth_password=self.password,
            auth_secondary=self.enable_password or self.password,
            # The Ansible config set host_key_checking=False globally; here it
            # defaults on and is an explicit per-device decision to relax.
            auth_strict_key=self.strict_host_key,
            ssh_known_hosts_file=self._known_hosts_path() or True,
            transport="paramiko",
            timeout_ops=self._timeout_ops,
        )

    def open(self) -> None:
        if self._conn is None:
            self._conn = self._driver_factory()
        try:
            self._conn.open()
        except ScrapliException as exc:
            raise DeviceError(f"could not open SSH session to {self.host}: {exc}") from exc

    def close(self) -> None:
        try:
            if self._conn is not None:
                try:
                    self._conn.close()
                finally:
                    self._conn = None
        finally:
            self._discard_known_hosts_tmp()

    def __enter__(self) -> "IosXeSshTransport":
        self.open()
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    @property
    def conn(self):
        if self._conn is None:
            raise DeviceError("transport is not open")
        return self._conn

    # -- helpers -----------------------------------------------------------

    def _send_command(self, command: str) -> str:
        response = self.conn.send_command(command)
        if response.failed:
            raise DeviceError(f"{self.host}: '{command}' failed: {response.result}")
        return response.result

    def _send_configs(self, configs: list[str]) -> str:
        response = self.conn.send_configs(configs, stop_on_failed=True)
        if response.failed:
            raise DeviceError(
                f"{self.host}: config failed: {'; '.join(configs)} -> {response.result}"
            )
        return response.result

    def _send_interactive(
        self,
        events,
        *,
        privilege_level: str = "configuration",
        timeout_ops: float | None = None,
    ) -> str:
        # No interaction_complete_patterns: scrapli falls back to the device
        # prompt, which is what actually terminates these exchanges.
        response = self.conn.send_interactive(
            events,
            privilege_level=privilege_level,
            timeout_ops=timeout_ops or self._timeout_ops,
        )
        return response.result

    def _remote_path(self, remote_name: str) -> str:
        return f"{self.filesystem}/{remote_name}"

    # -- DeviceTransport ---------------------------------------------------

    def read_state(self) -> DeviceState:
        certificates = self._send_command(SHOW_CERTIFICATES)
        signaling = self._send_command(SHOW_SIGNALING)
        trustpoints = self._send_command(SHOW_TRUSTPOINTS)
        state = build_state(certificates, signaling, trustpoints)
        log.debug(
            "device.state_read",
            host=self.host,
            trustpoints=sorted(state.trustpoints),
            bound=state.bound_trustpoint,
        )
        return state

    def fetch_file(self, url: str, remote_name: str) -> None:
        """Have the gateway download a file over HTTPS onto flash.

        ``file prompt quiet`` suppresses the destination-filename confirmation
        so a fully-specified ``copy <url> <dest>`` returns to the exec prompt.
        The prompt mode is restored afterwards. The origin must be HTTPS:
        Cloudflare Tunnel does not publish plaintext HTTP, and IOS will not
        follow a redirect.
        """
        dest = self._remote_path(remote_name)
        self._send_interactive(
            [("file prompt quiet", PROMPT_EXEC)],
            privilege_level="privilege_exec",
        )
        try:
            response = self.conn.send_command(
                f"copy {url} {dest}", timeout_ops=max(self._timeout_ops, 120.0)
            )
            result = response.result
            if response.failed:
                raise DeviceError(
                    f"{self.host}: HTTP copy of {remote_name} failed: {result}"
                )
            lowered = result.lower()
            for marker in (
                "%error",
                "error opening",
                "connection refused",
                "timed out",
                "404",
                "401",
                "403",
                "failed to",
            ):
                if marker in lowered:
                    raise DeviceError(
                        f"{self.host}: HTTP copy of {remote_name} reported: "
                        f"{result.strip()}"
                    )
        finally:
            try:
                self._send_interactive(
                    [("file prompt noisy", PROMPT_EXEC)],
                    privilege_level="privilege_exec",
                )
            except DeviceError:
                pass

        log.info(
            "device.file_fetched",
            host=self.host,
            path=dest,
            url_host=url.split("/")[2] if "://" in url else url,
        )

    def delete_file(self, remote_name: str) -> None:
        # 'file prompt quiet' is set around the import, but delete runs
        # outside that window, so answer a confirm if one appears.
        self._send_interactive(
            [
                (f"delete /force {self._remote_path(remote_name)}", PROMPT_EXEC),
            ],
            privilege_level="privilege_exec",
        )
        log.info("device.file_deleted", host=self.host, name=remote_name)

    def delete_trustpoint(self, label: str) -> None:
        """Remove a trustpoint. Only ever called on the *idle* trustpoint."""
        self._send_interactive(
            [
                (f"no crypto pki trustpoint {label}", CONFIRM_YES_NO),
                ("yes", PROMPT_CONFIG),
            ]
        )
        log.info("device.trustpoint_deleted", host=self.host, trustpoint=label)

    def trustpoint_exists(self, label: str) -> bool:
        """Whether ``label`` is present in running-config.

        Checked immediately before acting rather than inferred from an earlier
        state read: a partially-completed import leaves the trustpoint defined
        but empty, and ``crypto pki import`` then refuses with
        ``% Trustpoint '<label>' is in use.``
        """
        output = self._send_command(
            f"show running-config | include ^crypto pki trustpoint {label}$"
        )
        return f"crypto pki trustpoint {label}" in output

    def derived_trustpoints(self, label: str) -> list[str]:
        """Trustpoints IOS-XE created for CAs higher in the hierarchy.

        Answering "yes" to the hierarchy prompt installs the intermediate and
        root as their own trustpoints, named ``<label>-rrr1``, ``-rrr2`` and so
        on. They are re-created by every import, so without cleanup they
        accumulate one set per renewal.
        """
        output = self._send_command(
            f"show running-config | include ^crypto pki trustpoint {label}-rrr"
        )
        found: list[str] = []
        for line in output.splitlines():
            parts = line.strip().split()
            if len(parts) >= 4 and parts[3].startswith(f"{label}-rrr"):
                found.append(parts[3])
        return found

    def rsa_key_exists(self, label: str) -> bool:
        """Whether an RSA key pair named ``label`` is present."""
        output = self._send_command(
            f"show crypto key mypubkey rsa | include {label}"
        )
        return label in output

    def zeroize_key(self, label: str) -> None:
        """Remove the RSA key pair named ``label``.

        Only ever called on the idle trustpoint's key. Leaving it in place makes
        ``crypto pki import`` prompt "You already have RSA keys named <label> ...
        Do you really want to replace them? [yes/no]", which is what the first
        implementation blocked on.
        """
        self._send_interactive(
            [
                (f"crypto key zeroize rsa {label}", CONFIRM_YES_NO),
                ("yes", PROMPT_CONFIG),
            ]
        )
        log.info("device.key_zeroized", host=self.host, label=label)

    def import_pkcs12(self, label: str, remote_name: str, password: str) -> None:
        """Import a PKCS12 bundle into ``label``.

        Any publicly-issued certificate arrives with a non-self-signed CA cert
        in the bundle, so IOS-XE asks::

            % The CA cert is not self-signed.
            % Do you also want to create trustpoints for CAs higher in
            % the hierarchy? [yes/no]:

        Answer **yes**, so the device also installs the intermediate and root
        as trustpoints. Without them the gateway cannot present a complete
        chain, and the peer rejects the certificate even though the identity
        cert imported cleanly.

        Leaving it unanswered blocks the session while the device completes the
        import regardless -- which is what made this look like a device
        disconnect.

        The import itself takes roughly a minute on a Catalyst 8200, hence the
        longer timeout.
        """
        command = (
            f"crypto pki import {label} pkcs12 {self._remote_path(remote_name)} "
            f"password {password}"
        )

        result = self._send_interactive(
            [
                (command, CONFIRM_YES_NO),
                ("yes", PROMPT_CONFIG),
            ],
            timeout_ops=max(self._timeout_ops, IMPORT_TIMEOUT),
        )

        lowered = result.lower()
        for marker in ("import failed", "% error", "failed to", "invalid"):
            if marker in lowered:
                raise DeviceError(
                    f"{self.host}: PKCS12 import into {label} reported: {result.strip()}"
                )
        log.info("device.pkcs12_imported", host=self.host, trustpoint=label)

    def reconnect(self) -> None:
        """Drop and re-establish the session.

        Used to re-read state after a disconnect, so a dropped connection is
        not mistaken for a failed operation.
        """
        try:
            self.close()
        except Exception:  # noqa: BLE001 - already tearing down
            pass
        self._conn = None
        self.open()

    def set_revocation_check(self, label: str, mode: str = "none") -> None:
        """Set revocation checking on a trustpoint.

        The Webex template ships ``revocation-check crl``. Let's Encrypt retired
        OCSP and its leaf certificates carry no CRL distribution point IOS can
        use, so leaving CRL checking on can fail peer validation.
        """
        self._send_configs(
            [f"crypto pki trustpoint {label}", f"revocation-check {mode}", "exit"]
        )
        log.info("device.revocation_check_set", host=self.host, trustpoint=label, mode=mode)

    def bind_trustpoint(self, label: str) -> None:
        """Point ``sip-ua`` at a trustpoint. The blue/green cutover."""
        self._send_configs(
            ["sip-ua", f"crypto signaling default trustpoint {label}", "exit"]
        )
        log.info("device.trustpoint_bound", host=self.host, trustpoint=label)

    def save_config(self) -> None:
        """Persist to NVRAM.

        Nothing in the Ansible version ever did this, so the EEM applet and
        ``ip scp server enable`` were both lost on reload.
        """
        self._send_interactive(
            [
                ("write memory", PROMPT_EXEC),
            ],
            privilege_level="privilege_exec",
        )
        log.info("device.config_saved", host=self.host)
