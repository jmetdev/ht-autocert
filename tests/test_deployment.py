"""Blue/green deployment safety.

These are the tests that matter most: the EEM applet's failure mode was that a
bad PKCS12 destroyed the working trustpoint before the import was attempted. The
invariant asserted throughout here is that nothing touches the bound trustpoint
until the new certificate is verified present on the device.
"""

import pytest

from app.deployment import Deployer
from app.devices.base import DeviceError, DeviceState, TrustpointState

CN = "vg01.husd.clients.example.com"
SERIAL = "0A1B2C3D"


class FakeTransport:
    """Records every operation and simulates device state transitions."""

    def __init__(
        self,
        *,
        bound="HT-WxCAutoCert-A",
        trustpoints=None,
        import_result="ok",
        binding_takes=True,
    ):
        self.calls: list[tuple] = []
        self.bound = bound
        self.trustpoints: dict[str, TrustpointState] = trustpoints or {
            "HT-WxCAutoCert-A": TrustpointState(
                label="HT-WxCAutoCert-A",
                subject_cn=CN,
                serial="OLDSERIAL",
                has_certificate=True,
            )
        }
        self.import_result = import_result
        self.binding_takes = binding_takes
        self.files: dict[str, bytes] = {}

    # -- DeviceTransport ---------------------------------------------------

    def read_state(self) -> DeviceState:
        self.calls.append(("read_state",))
        return DeviceState(
            trustpoints=dict(self.trustpoints), bound_trustpoint=self.bound
        )

    def upload_file(self, data, remote_name):
        self.calls.append(("upload_file", remote_name, len(data)))
        self.files[remote_name] = data

    def delete_file(self, remote_name):
        self.calls.append(("delete_file", remote_name))
        self.files.pop(remote_name, None)

    def delete_trustpoint(self, label):
        self.calls.append(("delete_trustpoint", label))
        self.trustpoints.pop(label, None)

    def import_pkcs12(self, label, remote_name, password):
        self.calls.append(("import_pkcs12", label, remote_name))
        if self.import_result == "reject":
            # Device parses nothing and leaves no trustpoint behind.
            return
        if self.import_result == "error":
            raise DeviceError("PKCS12 import failed: Unknown reason")
        if self.import_result == "wrong_cert":
            self.trustpoints[label] = TrustpointState(
                label=label, subject_cn=CN, serial="SOMETHINGELSE", has_certificate=True
            )
            return
        self.trustpoints[label] = TrustpointState(
            label=label, subject_cn=CN, serial=SERIAL, has_certificate=True
        )

    def set_revocation_check(self, label, mode):
        self.calls.append(("set_revocation_check", label, mode))

    def bind_trustpoint(self, label):
        self.calls.append(("bind_trustpoint", label))
        if self.binding_takes:
            self.bound = label

    def save_config(self):
        self.calls.append(("save_config",))

    # -- helpers -----------------------------------------------------------

    def names(self):
        return [c[0] for c in self.calls]


def run(transport, *, idle="HT-WxCAutoCert-B", **kwargs):
    deployer = Deployer(transport, **kwargs)
    return deployer.deploy(
        fqdn=CN,
        p12=b"pkcs12-bytes",
        password="secret",
        subject_cn=CN,
        serial=SERIAL,
        idle_trustpoint=idle,
    )


# -- happy path --------------------------------------------------------------


def test_successful_cutover():
    t = FakeTransport()
    result = run(t)

    assert result.status == "deployed"
    assert result.previous_trustpoint == "HT-WxCAutoCert-A"
    assert result.active_trustpoint == "HT-WxCAutoCert-B"
    assert t.bound == "HT-WxCAutoCert-B"


def test_operations_happen_in_the_safe_order():
    t = FakeTransport()
    run(t)
    names = t.names()

    # Upload must precede import.
    assert names.index("upload_file") < names.index("import_pkcs12")
    assert names.index("import_pkcs12") < names.index("bind_trustpoint")
    assert names.index("set_revocation_check") < names.index("bind_trustpoint")
    # Config is saved only after the binding is confirmed.
    assert names.index("bind_trustpoint") < names.index("save_config")


def test_config_is_saved():
    """The Ansible version never wrote to NVRAM, so changes vanished on reload."""
    t = FakeTransport()
    run(t)
    assert "save_config" in t.names()


def test_bundle_is_removed_from_flash():
    t = FakeTransport()
    run(t)
    assert ("delete_file", "htautocert.p12") in t.calls
    assert t.files == {}


def test_revocation_check_defaults_to_none():
    """Let's Encrypt certificates cannot satisfy the template's 'crl' setting."""
    t = FakeTransport()
    run(t)
    assert ("set_revocation_check", "HT-WxCAutoCert-B", "none") in t.calls


# -- the safety invariant ----------------------------------------------------


def test_rejected_pkcs12_leaves_active_trustpoint_untouched():
    """The EEM applet's outage scenario: device cannot parse the bundle."""
    t = FakeTransport(import_result="reject")

    with pytest.raises(Exception, match="absent after import"):
        run(t)

    assert t.bound == "HT-WxCAutoCert-A"
    assert t.trustpoints["HT-WxCAutoCert-A"].has_certificate is True
    assert ("delete_trustpoint", "HT-WxCAutoCert-A") not in t.calls
    assert ("bind_trustpoint", "HT-WxCAutoCert-B") not in t.calls


def test_import_error_leaves_active_trustpoint_untouched():
    t = FakeTransport(import_result="error")

    with pytest.raises(DeviceError):
        run(t)

    assert t.bound == "HT-WxCAutoCert-A"
    assert "bind_trustpoint" not in t.names()


def test_wrong_certificate_is_caught_before_rebind():
    """A trustpoint holding the wrong serial must not be bound."""
    t = FakeTransport(import_result="wrong_cert")

    with pytest.raises(Exception, match="expected"):
        run(t)

    assert t.bound == "HT-WxCAutoCert-A"
    assert "bind_trustpoint" not in t.names()


def test_bundle_is_cleaned_up_even_on_failure():
    """A .p12 left on flash is an offline attack on the escrowed key."""
    t = FakeTransport(import_result="error")

    with pytest.raises(DeviceError):
        run(t)

    assert ("delete_file", "htautocert.p12") in t.calls
    assert t.files == {}


def test_never_deploys_into_the_bound_trustpoint():
    """If stored idle is the live sip-ua trustpoint, import the other slot."""
    t = FakeTransport(bound="HT-WxCAutoCert-B")

    result = run(t, idle="HT-WxCAutoCert-B")

    assert result.status == "deployed"
    assert ("import_pkcs12", "HT-WxCAutoCert-A", "htautocert.p12") in t.calls
    assert ("import_pkcs12", "HT-WxCAutoCert-B", "htautocert.p12") not in t.calls
    assert t.bound == "HT-WxCAutoCert-A"


def test_first_deploy_uses_b_when_gateway_already_has_a_bound():
    """Control Hub / Ansible gateways often already bind A; stored active is empty."""
    t = FakeTransport(bound="HT-WxCAutoCert-A")

    result = run(t, idle="HT-WxCAutoCert-A")

    assert result.status == "deployed"
    assert ("import_pkcs12", "HT-WxCAutoCert-B", "htautocert.p12") in t.calls
    assert t.bound == "HT-WxCAutoCert-B"


def test_idle_trustpoint_is_cleared_only_when_it_exists():
    t = FakeTransport()  # only trustpoint A exists
    run(t)
    assert "delete_trustpoint" not in t.names()


def test_existing_idle_trustpoint_is_cleared_first():
    t = FakeTransport(
        trustpoints={
            "HT-WxCAutoCert-A": TrustpointState(
                label="HT-WxCAutoCert-A", subject_cn=CN, serial="OLD", has_certificate=True
            ),
            "HT-WxCAutoCert-B": TrustpointState(
                label="HT-WxCAutoCert-B", subject_cn=CN, serial="STALE", has_certificate=True
            ),
        }
    )
    run(t)
    names = t.names()

    assert ("delete_trustpoint", "HT-WxCAutoCert-B") in t.calls
    assert names.index("delete_trustpoint") < names.index("import_pkcs12")
    # The bound trustpoint is never the one cleared.
    assert ("delete_trustpoint", "HT-WxCAutoCert-A") not in t.calls


# -- rollback ----------------------------------------------------------------


def test_failed_binding_rolls_back():
    t = FakeTransport(binding_takes=False)
    result = run(t)

    assert result.status == "rolled_back"
    assert result.active_trustpoint == "HT-WxCAutoCert-A"
    assert t.calls.count(("bind_trustpoint", "HT-WxCAutoCert-A")) == 1
    assert "save_config" not in t.names()


def test_rollback_is_reported_in_steps():
    t = FakeTransport(binding_takes=False)
    result = run(t)
    assert any("ROLLED BACK" in step for step in result.steps)


# -- no-rebind mode ----------------------------------------------------------


def test_no_rebind_imports_and_verifies_only():
    """Staging a certificate ahead of a maintenance window."""
    t = FakeTransport()
    result = run(t, rebind=False)

    assert result.status == "deployed"
    assert result.active_trustpoint == "HT-WxCAutoCert-A"
    assert t.bound == "HT-WxCAutoCert-A"
    assert "bind_trustpoint" not in t.names()
    assert ("import_pkcs12", "HT-WxCAutoCert-B", "htautocert.p12") in t.calls


def test_first_deployment_with_no_prior_binding():
    t = FakeTransport(bound=None, trustpoints={})
    result = run(t)

    assert result.status == "deployed"
    assert result.previous_trustpoint is None
    assert t.bound == "HT-WxCAutoCert-B"


# -- disconnect during import ------------------------------------------------


class DroppingTransport(FakeTransport):
    """Completes the import, then reports the session as dropped.

    Observed on a Catalyst 8200 running 17.15.3a: the certificate lands in the
    trustpoint but the SSH session closes, so treating the exception as a
    failed import both loses the work and misreports device state.
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.reconnects = 0

    def import_pkcs12(self, label, remote_name, password):
        super().import_pkcs12(label, remote_name, password)
        raise DeviceError(
            "encountered EOF reading from transport; typically means the "
            "device closed the connection"
        )

    def reconnect(self):
        self.reconnects += 1
        self.calls.append(("reconnect",))


def test_disconnect_after_successful_import_recovers():
    t = DroppingTransport()
    result = run(t)

    assert result.status == "deployed"
    assert t.reconnects == 1
    assert t.bound == "HT-WxCAutoCert-B"


def test_disconnect_is_recorded_in_the_steps():
    t = DroppingTransport()
    result = run(t)
    assert any("session dropped during import" in s for s in result.steps)
    assert any("reconnected" in s for s in result.steps)


def test_disconnect_with_a_failed_import_still_fails():
    """Reconnecting must not paper over an import that did not take."""

    class DroppedAndEmpty(DroppingTransport):
        def import_pkcs12(self, label, remote_name, password):
            raise DeviceError("encountered EOF reading from transport")

    t = DroppedAndEmpty()
    with pytest.raises(Exception, match="absent after import"):
        run(t)

    assert t.reconnects == 1
    assert t.bound == "HT-WxCAutoCert-A"
    assert "bind_trustpoint" not in t.names()


def test_non_disconnect_errors_are_not_retried():
    t = FakeTransport(import_result="error")  # "PKCS12 import failed"
    with pytest.raises(DeviceError):
        run(t)
    assert "reconnect" not in t.names()


def test_transport_without_reconnect_fails_clearly():
    class NoReconnect(FakeTransport):
        def import_pkcs12(self, label, remote_name, password):
            raise DeviceError("encountered EOF reading from transport")

    t = NoReconnect()
    with pytest.raises(DeviceError, match="cannot reconnect"):
        run(t)


# -- stale RSA key pairs -----------------------------------------------------


class KeyAwareTransport(FakeTransport):
    """Models the key pair outliving its trustpoint.

    On a real 8200, `no crypto pki trustpoint X` leaves the RSA key pair named
    X in place. The next `crypto pki import` then prompts "You already have RSA
    keys named X ... replace them? [yes/no]" and blocks.
    """

    def __init__(self, *, key_present=True, **kwargs):
        super().__init__(**kwargs)
        self.key_present = key_present

    def rsa_key_exists(self, label):
        self.calls.append(("rsa_key_exists", label))
        return self.key_present

    def zeroize_key(self, label):
        self.calls.append(("zeroize_key", label))
        self.key_present = False

    def import_pkcs12(self, label, remote_name, password):
        if self.key_present:
            raise DeviceError(
                "encountered EOF reading from transport; blocked on "
                "'Do you really want to replace them? [yes/no]'"
            )
        super().import_pkcs12(label, remote_name, password)


def test_stale_key_is_zeroized_before_import():
    t = KeyAwareTransport(key_present=True)
    result = run(t)

    assert result.status == "deployed"
    names = t.names()
    assert names.index("zeroize_key") < names.index("import_pkcs12")


def test_zeroize_is_skipped_when_no_key_exists():
    t = KeyAwareTransport(key_present=False)
    result = run(t)

    assert result.status == "deployed"
    assert "zeroize_key" not in t.names()
    assert ("rsa_key_exists", "HT-WxCAutoCert-B") in t.calls


def test_only_the_idle_trustpoint_key_is_zeroized():
    """The active trustpoint's key must never be touched."""
    t = KeyAwareTransport(key_present=True)
    run(t)

    zeroized = [c[1] for c in t.calls if c[0] == "zeroize_key"]
    assert zeroized == ["HT-WxCAutoCert-B"]
    assert "HT-WxCAutoCert-A" not in zeroized


def test_transport_without_key_helpers_still_works():
    """Older/simpler transports must not break."""
    t = FakeTransport()
    assert run(t).status == "deployed"


# -- dirty device state ------------------------------------------------------


class StatefulTransport(FakeTransport):
    """Tracks trustpoint and key existence independently, as IOS-XE does.

    A partially-completed import leaves the trustpoint *defined but empty* and
    the key pair present. Deciding what to clean from the state read taken at
    the start of the run misses both.
    """

    def __init__(self, *, tp_defined=False, key_present=False, derived=(), **kwargs):
        super().__init__(**kwargs)
        self.tp_defined = tp_defined
        self.key_present = key_present
        self.derived = list(derived)

    def trustpoint_exists(self, label):
        self.calls.append(("trustpoint_exists", label))
        return self.tp_defined if label == "HT-WxCAutoCert-B" else True

    def derived_trustpoints(self, label):
        self.calls.append(("derived_trustpoints", label))
        return list(self.derived)

    def rsa_key_exists(self, label):
        self.calls.append(("rsa_key_exists", label))
        return self.key_present

    def zeroize_key(self, label):
        self.calls.append(("zeroize_key", label))
        self.key_present = False

    def delete_trustpoint(self, label):
        super().delete_trustpoint(label)
        if label in self.derived:
            self.derived.remove(label)
        else:
            self.tp_defined = False

    def import_pkcs12(self, label, remote_name, password):
        if self.tp_defined:
            raise DeviceError(f"% Trustpoint '{label}' is in use.")
        if self.key_present:
            raise DeviceError("encountered EOF reading from transport")
        super().import_pkcs12(label, remote_name, password)


def test_trustpoint_defined_but_absent_from_state_read_is_still_cleared():
    """The exact state a hung import leaves behind."""
    t = StatefulTransport(tp_defined=True, key_present=True)

    result = run(t)

    assert result.status == "deployed"
    names = t.names()
    assert names.index("delete_trustpoint") < names.index("import_pkcs12")
    assert names.index("zeroize_key") < names.index("import_pkcs12")


def test_live_check_preferred_over_the_earlier_state_read():
    t = StatefulTransport(tp_defined=True, key_present=False)
    run(t)
    assert ("trustpoint_exists", "HT-WxCAutoCert-B") in t.calls
    assert ("delete_trustpoint", "HT-WxCAutoCert-B") in t.calls


def test_clean_label_skips_both_cleanup_steps():
    t = StatefulTransport(tp_defined=False, key_present=False)
    result = run(t)

    assert result.status == "deployed"
    assert "delete_trustpoint" not in t.names()
    assert "zeroize_key" not in t.names()


def test_active_trustpoint_is_never_cleaned():
    t = StatefulTransport(tp_defined=True, key_present=True)
    run(t)

    for call in t.calls:
        if call[0] in ("delete_trustpoint", "zeroize_key"):
            assert call[1] == "HT-WxCAutoCert-B"


def test_derived_ca_trustpoints_are_cleaned_up():
    """Answering 'yes' to the CA-hierarchy prompt installs <label>-rrrN
    trustpoints. Each import recreates them, so they must be removed first or
    they accumulate one set per renewal."""
    t = StatefulTransport(
        tp_defined=True,
        key_present=True,
        derived=["HT-WxCAutoCert-B-rrr1", "HT-WxCAutoCert-B-rrr2"],
    )

    result = run(t)

    assert result.status == "deployed"
    deleted = [c[1] for c in t.calls if c[0] == "delete_trustpoint"]
    assert "HT-WxCAutoCert-B-rrr1" in deleted
    assert "HT-WxCAutoCert-B-rrr2" in deleted
    assert any("derived CA trustpoint" in s for s in result.steps)


def test_derived_cleanup_precedes_the_import():
    t = StatefulTransport(tp_defined=True, derived=["HT-WxCAutoCert-B-rrr1"])
    run(t)
    names = t.names()
    assert names.index("derived_trustpoints") < names.index("import_pkcs12")


def test_no_derived_trustpoints_is_fine():
    t = StatefulTransport(tp_defined=False, key_present=False, derived=[])
    assert run(t).status == "deployed"
    assert "delete_trustpoint" not in t.names()


def test_active_trustpoint_derivatives_are_never_touched():
    t = StatefulTransport(tp_defined=True, derived=["HT-WxCAutoCert-B-rrr1"])
    run(t)
    for call in t.calls:
        if call[0] == "delete_trustpoint":
            assert call[1].startswith("HT-WxCAutoCert-B")
