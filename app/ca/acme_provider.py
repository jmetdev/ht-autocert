"""ACME issuance via the ``acme`` library (the one certbot is built on).

Using the library rather than the ``certbot`` CLI buys three things the Ansible
version could not have:

* **Any ACME CA**, selected by directory URL, with External Account Binding --
  which ZeroSSL requires and the certbot invocation had no way to supply.
* **Structured results.** Renewal state came from grepping stdout for
  ``"Successfully received certificate"``; here an order either yields a chain
  or raises.
* **Explicit chain selection.** Let's Encrypt's Generation Y default is
  EE ← YR ← Root YR (cross-signed by ISRG Root X1). ``preferred_chain``
  picks which alternate ACME offers; the X1 *certificate* is then appended
  because ACME omits roots and IOS PKCS12 import needs them in the bag.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta

import josepy as jose
import structlog
from acme import challenges, client, crypto_util, errors, messages
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from app.ca.base import IssuedCertificate
from app.ca.trust_anchors import complete_chain
from app.dns.base import DnsSolver, TxtRecord
from app.dns.propagation import wait_for_txt

log = structlog.get_logger(__name__)

USER_AGENT = "ht-autocert/2.0.0"


class AcmeError(RuntimeError):
    pass


def _order_deadline(seconds: int) -> datetime:
    """A deadline the ``acme`` library can compare against.

    Its polling loops use a bare ``datetime.datetime.now()``, so the deadline
    must be naive local time. Passing an aware datetime fails at finalization
    with "can't compare offset-naive and offset-aware datetimes" -- after the
    challenge has already been answered.
    """
    return datetime.now() + timedelta(seconds=seconds)


class RateLimitedError(AcmeError):
    """The CA refused the order under a rate limit."""

    def __init__(self, message: str, *, retry_after: str | None = None,
                 duplicate_limit: bool = False):
        super().__init__(message)
        self.retry_after = retry_after
        self.duplicate_limit = duplicate_limit


def _translate_acme_error(exc: messages.Error, fqdn: str) -> AcmeError:
    """Turn an ACME problem document into something actionable.

    The duplicate-certificate limit in particular reads like a fleet-wide
    outage but is scoped to one exact name set, is global across accounts (so
    a new ACME account does not evade it), and expires on its own.
    """
    detail = str(getattr(exc, "detail", "") or exc)
    typ = str(getattr(exc, "typ", "") or "")

    if "ratelimited" not in typ.lower() and "too many" not in detail.lower():
        return AcmeError(f"CA rejected the order for {fqdn}: {detail}")

    retry_after = None
    match = re.search(r"retry after ([0-9]{4}-[0-9]{2}-[0-9]{2}[^:]*:[0-9]{2}:[0-9]{2} \w+)",
                      detail)
    if match:
        retry_after = match.group(1)

    duplicate = "exact set of identifiers" in detail
    if duplicate:
        message = (
            f"Rate limited on {fqdn}: 5 certificates for this exact name have "
            f"already been issued in the last 7 days"
            + (f", retry after {retry_after}" if retry_after else "")
            + ". This limit is per-name and global across ACME accounts, so a "
            "new account will not help. It only affects this one gateway. "
            "Use the staging CA for further testing, or issue from a different "
            "CA profile."
        )
    else:
        message = f"Rate limited on {fqdn}: {detail}"

    return RateLimitedError(message, retry_after=retry_after,
                            duplicate_limit=duplicate)


def generate_private_key(key_type: str):
    kt = key_type.lower()
    if kt in ("rsa2048", "rsa"):
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    if kt == "rsa4096":
        return rsa.generate_private_key(public_exponent=65537, key_size=4096)
    if kt in ("ec256", "ecdsa", "p256"):
        return ec.generate_private_key(ec.SECP256R1())
    raise AcmeError(f"unsupported key type {key_type!r}")


def _chain_issuer_cn(fullchain_pem: str) -> str:
    """Issuer CN of the topmost certificate in a chain.

    This is what ``certbot --preferred-chain`` matches on, and what identifies
    the root a relying party must trust.
    """
    if not (fullchain_pem or "").strip():
        raise AcmeError("empty certificate chain")
    try:
        certs = x509.load_pem_x509_certificates(fullchain_pem.encode())
    except ValueError as exc:
        raise AcmeError(f"could not parse certificate chain: {exc}") from exc
    if not certs:
        raise AcmeError("empty certificate chain")
    top = certs[-1]
    attrs = top.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    if attrs:
        return str(attrs[0].value)
    return top.issuer.rfc4514_string()


class AccountStore:
    """Persistence hook for the ACME account key and URI.

    Kept abstract so the provider does not depend on the DB layer; the
    orchestrator supplies an implementation backed by the sealed columns on
    ``CAProfile``.
    """

    def load_account_key_pem(self) -> bytes | None:
        raise NotImplementedError

    def save_account_key_pem(self, pem: bytes) -> None:
        raise NotImplementedError

    def load_account_uri(self) -> str | None:
        raise NotImplementedError

    def save_account_uri(self, uri: str) -> None:
        raise NotImplementedError


class AcmeProvider:
    def __init__(
        self,
        *,
        directory_url: str,
        contact_email: str,
        solver: DnsSolver,
        account_store: AccountStore,
        eab_kid: str | None = None,
        eab_hmac_key: str | None = None,
        preferred_chain: str | None = None,
        propagation_timeout: int = 300,
        poll_interval: int = 5,
        order_timeout: int = 300,
    ):
        self.directory_url = directory_url
        self.contact_email = contact_email
        self.solver = solver
        self.account_store = account_store
        self.eab_kid = eab_kid
        self.eab_hmac_key = eab_hmac_key
        self.preferred_chain = preferred_chain
        self.propagation_timeout = propagation_timeout
        self.poll_interval = poll_interval
        self.order_timeout = order_timeout
        self._client: client.ClientV2 | None = None

    # -- account -----------------------------------------------------------

    def _load_or_create_account_key(self) -> jose.JWKRSA:
        pem = self.account_store.load_account_key_pem()
        if pem:
            key = serialization.load_pem_private_key(pem, password=None)
            return jose.JWKRSA(key=key)

        log.info("acme.account_key_generated", directory=self.directory_url)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.account_store.save_account_key_pem(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        return jose.JWKRSA(key=key)

    def _acme_client(self) -> client.ClientV2:
        if self._client is not None:
            return self._client

        account_key = self._load_or_create_account_key()
        net = client.ClientNetwork(key=account_key, user_agent=USER_AGENT)
        directory = client.ClientV2.get_directory(self.directory_url, net)
        acme_client = client.ClientV2(directory, net=net)

        account_uri = self.account_store.load_account_uri()
        if account_uri:
            # Re-attach the existing account so requests are signed with its kid.
            net.account = messages.RegistrationResource(
                body=messages.Registration(), uri=account_uri
            )
        else:
            eab = None
            if self.eab_kid and self.eab_hmac_key:
                eab = messages.ExternalAccountBinding.from_data(
                    account_public_key=account_key.public_key(),
                    kid=self.eab_kid,
                    hmac_key=self.eab_hmac_key,
                    directory=directory,
                )
                log.info("acme.eab_configured", kid=self.eab_kid)

            registration = messages.NewRegistration.from_data(
                email=self.contact_email,
                terms_of_service_agreed=True,
                external_account_binding=eab,
            )
            try:
                regr = acme_client.new_account(registration)
            except errors.Error as exc:
                raise AcmeError(
                    f"ACME account registration failed at {self.directory_url}: {exc}"
                ) from exc
            self.account_store.save_account_uri(regr.uri)
            log.info("acme.account_registered", uri=regr.uri)

        self._client = acme_client
        return acme_client

    # -- issuance ----------------------------------------------------------

    def issue(
        self,
        fqdn: str,
        key_type: str = "rsa2048",
        sans: list[str] | None = None,
    ) -> IssuedCertificate:
        """Order a certificate for ``fqdn``, optionally covering extra names.

        The full name list is the certificate's identifier set, which is what
        Let's Encrypt scopes its duplicate-certificate limit to.
        """
        acme_client = self._acme_client()
        account_key = acme_client.net.key
        names = sans or [fqdn]
        if fqdn not in names:
            names = [fqdn, *names]

        private_key = generate_private_key(key_type)
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        csr_pem = crypto_util.make_csr(key_pem, names)
        if len(names) > 1:
            log.info("acme.order_names", fqdn=fqdn, names=names)

        try:
            order = acme_client.new_order(csr_pem)
        except messages.Error as exc:
            raise _translate_acme_error(exc, fqdn) from exc

        created: list[TxtRecord] = []

        try:
            for authz in order.authorizations:
                domain = authz.body.identifier.value
                challb = self._dns_challenge(authz, domain)
                response, validation = challb.chall.response_and_validation(account_key)
                record_name = challb.chall.validation_domain_name(domain)

                self._reject_if_delegated(record_name)
                created.append(self.solver.create_txt(record_name, validation))
                wait_for_txt(
                    record_name,
                    validation,
                    self.solver.authoritative_nameservers(),
                    timeout=self.propagation_timeout,
                    interval=self.poll_interval,
                )
                acme_client.answer_challenge(challb, response)
                log.info("acme.challenge_answered", fqdn=fqdn, domain=domain)

            # Naive on purpose: acme's poll_authorizations/poll_finalization
            # compare this against a bare datetime.datetime.now(), so an
            # aware value raises "can't compare offset-naive and offset-aware
            # datetimes" the moment finalization starts polling.
            deadline = _order_deadline(self.order_timeout)
            try:
                order = acme_client.finalize_order(
                    order, deadline, fetch_alternative_chains=True
                )
            except errors.ValidationError as exc:
                raise AcmeError(self._explain_validation_error(fqdn, exc)) from exc
            except errors.TimeoutError as exc:
                raise AcmeError(
                    f"ACME order for {fqdn} did not finalize within "
                    f"{self.order_timeout}s"
                ) from exc
        finally:
            for record in created:
                self.solver.delete_txt(record)

        return self._select_chain(fqdn, order, key_pem)

    def _reject_if_delegated(self, record_name: str) -> None:
        """Fail fast when the challenge name is CNAME'd elsewhere.

        Writing a TXT into the parent zone underneath an existing CNAME is
        silently useless: the record is accepted by the DNS provider's API but
        never served, and the CA validates against the delegation target.
        """
        from app.dns.propagation import _resolve_ns_addresses, detect_cname

        try:
            servers = _resolve_ns_addresses(
                self.solver.authoritative_nameservers(),
                zone_hint=record_name.split(".", 1)[-1],
            )
            target = detect_cname(record_name, servers) if servers else None
        except Exception:  # noqa: BLE001 - never let the probe break issuance
            return

        if target:
            raise AcmeError(
                f"{record_name} is a CNAME to {target}, so a TXT record written "
                f"into the managed zone will not be served and validation will "
                f"fail. This is the acme-dns delegation pattern: the challenge "
                f"token must be published at {target} instead. Either remove the "
                f"CNAME so this tool can answer the challenge directly in "
                f"Cloudflare, or configure an acme-dns solver for this host."
            )

    @staticmethod
    def _dns_challenge(authz, domain: str) -> messages.ChallengeBody:
        for challb in authz.body.challenges:
            if isinstance(challb.chall, challenges.DNS01):
                return challb
        raise AcmeError(
            f"CA offered no dns-01 challenge for {domain}; available: "
            + ", ".join(c.chall.typ for c in authz.body.challenges)
        )

    @staticmethod
    def _explain_validation_error(fqdn: str, exc: errors.ValidationError) -> str:
        details = []
        for authzr in exc.failed_authzrs:
            for challb in authzr.body.challenges:
                if challb.error:
                    details.append(f"{challb.chall.typ}: {challb.error.detail}")
        joined = "; ".join(details) or str(exc)
        return f"ACME validation failed for {fqdn} -- {joined}"

    def _select_chain(self, fqdn: str, order, key_pem: bytes) -> IssuedCertificate:
        candidates = [order.fullchain_pem] + list(order.alternative_fullchains_pem or [])
        issuers = [_chain_issuer_cn(c) for c in candidates]

        chosen_idx = 0
        if self.preferred_chain:
            for idx, issuer in enumerate(issuers):
                if issuer == self.preferred_chain:
                    chosen_idx = idx
                    break
            else:
                log.warning(
                    "acme.preferred_chain_unavailable",
                    fqdn=fqdn,
                    preferred=self.preferred_chain,
                    available=issuers,
                )

        log.info(
            "acme.certificate_issued",
            fqdn=fqdn,
            chain_issuer=issuers[chosen_idx],
            alternates=issuers,
        )
        fullchain_pem = complete_chain(candidates[chosen_idx])
        return IssuedCertificate(
            fqdn=fqdn,
            private_key_pem=key_pem,
            fullchain_pem=fullchain_pem,
            chain_issuer_cn=_chain_issuer_cn(fullchain_pem),
            alternate_chain_issuers=issuers,
        )
