"""Runtime configuration.

Secrets are read from the environment or from Docker secret files (``*_FILE``
convention). Nothing sensitive is ever written to the repo directory -- the
Ansible version rendered the PKCS12 password into ``htautocert_rendered.eem``
on a bind mount, which this deliberately does not do.
"""

from __future__ import annotations

import os
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _read_secret(name: str) -> str | None:
    """Resolve NAME from env, or NAME_FILE pointing at a Docker secret."""
    direct = os.environ.get(name)
    if direct:
        return direct
    path = os.environ.get(f"{name}_FILE")
    if path and Path(path).is_file():
        return Path(path).read_text().strip()
    return None


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="HTAC_", env_file=".env", extra="ignore"
    )

    # Envelope-encryption key wrapping every escrowed private key in the DB.
    # 32 bytes, base64. Generate with: openssl rand -base64 32
    master_key: str = Field(default="")

    database_url: str = "sqlite:////srv/data/htac.db"

    # Single Cloudflare zone hosting every tenant's gateway FQDNs.
    cloudflare_api_token: str = Field(default="")
    cloudflare_zone: str = "managedcollab.com"

    # DNS-01: poll the zone's authoritative nameservers instead of sleeping a
    # fixed interval the way the certbot plugin did.
    dns_propagation_timeout: int = 300
    dns_poll_interval: int = 5

    acme_order_timeout: int = 300

    # Scheduler. Daily, not monthly: a monthly cron against a 30-day renewal
    # threshold can leave a single day of margin on a 90-day certificate.
    schedule_enabled: bool = True
    schedule_time: str = "02:00"  # UTC
    # Stable per-device offset added to the renewal threshold, so gateways
    # provisioned together do not renew together. Simulated over 50 gateways
    # all issued on the same day: 0d spreads nothing and peaks at 50 certs in
    # one week (exactly Let's Encrypt's per-registered-domain cap), 14d peaks
    # at 27, 21d at 17. Past 21d there is no further gain.
    renewal_spread_days: int = 21
    schedule_deploy: bool = True

    # API. The bearer token stays for automation (CLI, cron); humans sign in
    # with Webex when it is configured.
    api_token: str = Field(default="")
    api_cors_origins: str = ""

    # --- Webex OAuth ---------------------------------------------------------
    webex_client_id: str = ""
    webex_client_secret: str = Field(default="")
    # Must exactly match the redirect URI registered on the Webex integration.
    webex_redirect_uri: str = "https://autocert.managedcollab.com/auth/callback"
    # Authorisation policy. Authentication proves identity; these decide who is
    # actually allowed in. With none set, every Webex login is refused.
    # OAuth scopes, comma- or space-separated. Commas are safer: this value is
    # read both by `source .env.htac` in the wrapper and by docker compose's
    # env_file parser, which disagree about quoting spaces.
    #
    # The admin scopes only work when the signed-in user is a Webex
    # administrator, and the integration must be registered with every scope
    # requested or Webex rejects the whole authorization.
    # Only what discovery actually calls, all read-only:
    #   spark:people_read                    identity, for sign-in
    #   spark-admin:organizations_read       the org selector
    #   spark-admin:telephony_config_read    trunks (i.e. Local Gateways)
    # Nothing here reads phones, workspaces or PSTN carrier config -- a Local
    # Gateway appears only as a trunk, so those scopes bought nothing.
    webex_scopes: str = (
        "spark:people_read,"
        "spark-admin:organizations_read,"
        "spark-admin:telephony_config_read"
    )
    webex_allowed_emails: str = ""
    webex_allowed_domains: str = ""
    webex_allowed_org_id: str = ""
    # Role granted to a domain-matched user who has no explicit grant.
    # "none" denies -- signing in is not the same as being an operator.
    webex_default_role: str = "none"
    # Emails always treated as admin, so a fresh deployment is reachable before
    # anyone has been granted a role. Keep this short and remove it later.
    bootstrap_admins: str = ""
    session_ttl_hours: int = 12
    # Set false only when terminating TLS elsewhere and testing over plain HTTP.
    session_cookie_secure: bool = True

    # Shared PKCS12 password for every issued bundle. A random per-issuance
    # password made it impossible to retry an import with the same .p12 file
    # when the router rejected it. Alphanumeric only: the value is typed into
    # an IOS-XE exec command.
    pkcs12_password: str = "HtAcPkcs12"

    @property
    def webex_scope_string(self) -> str:
        """Scopes as Webex wants them: space separated."""
        return " ".join(
            s for s in self.webex_scopes.replace(",", " ").split() if s
        )

    @property
    def webex_enabled(self) -> bool:
        return bool(self.webex_client_id and self.webex_client_secret)

    log_level: str = "info"
    log_json: bool = False

    @field_validator(
        "master_key",
        "cloudflare_api_token",
        "api_token",
        "webex_client_secret",
        "pkcs12_password",
        mode="before",
    )
    @classmethod
    def _allow_file_secrets(cls, v: str, info) -> str:
        if v:
            return v
        return _read_secret(f"HTAC_{info.field_name.upper()}") or ""

    def require_master_key(self) -> str:
        if not self.master_key:
            raise RuntimeError(
                "HTAC_MASTER_KEY is not set. This key wraps every escrowed "
                "private key; without it the datastore cannot be opened. "
                "Generate one with: openssl rand -base64 32"
            )
        return self.master_key

    def require_cloudflare_token(self) -> str:
        if not self.cloudflare_api_token:
            raise RuntimeError("HTAC_CLOUDFLARE_API_TOKEN is not set.")
        return self.cloudflare_api_token


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def reset_settings() -> None:
    """Test hook."""
    global _settings
    _settings = None
