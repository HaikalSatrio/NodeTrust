"""Runtime configuration, read from environment variables (prefix NODETRUST_).

No secret has a default value. Network access is disabled unless explicitly
enabled, so tests and offline demos can never reach the internet by accident.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # hide_input_in_errors: a rejected value (a token, a password) must never be echoed into logs.
    model_config = SettingsConfigDict(env_prefix="NODETRUST_", env_file=None, extra="ignore",
                                      hide_input_in_errors=True)

    db_path: Path = Path("data/nodetrust.db")
    # Operator token for instance-level actions (create project, manage incidents).
    # Unset => operator endpoints are disabled.
    admin_token: SecretStr | None = None

    allow_network: bool = False
    npm_registry_url: str = "https://registry.npmjs.org"
    # Checked live on 26 Sep 2026 (engine npm-replicate); see docs/audit/live-checks.md.
    npm_changes_url: str = "https://replicate.npmjs.com/registry/_changes"
    osv_api_url: str = "https://api.osv.dev/v1"
    http_timeout_s: float = 20.0
    max_packument_bytes: int = 20 * 1024 * 1024
    fetch_rate_per_s: float = 5.0

    max_sbom_bytes: int = 10 * 1024 * 1024
    max_sbom_components: int = 50_000
    # Bounds on registry fetches that scan input can trigger.
    fetch_budget_per_scan: int = Field(default=200, ge=0)
    max_pending_sbom_fetches: int = Field(default=5000, ge=0)
    sbom_fetch_cooldown_hours: float = Field(default=24.0, ge=0)

    # D06: sources whose last successful sync must be fresh for a live assessment.
    required_sources: str = "feed:npm,intel:osv"
    # Offline demo / snapshot instances: verdicts are labelled "snapshot, not live"
    # instead of being judged stale (D06 last paragraph).
    snapshot_mode: bool = False

    alert_outbox_dir: Path = Path("data/outbox")
    alert_max_attempts: int = 5
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_user: str | None = None
    smtp_password: SecretStr | None = None
    smtp_from: str = "nodetrust@localhost"
    # PEM bundle to trust for a relay with a private CA. Certificates are always verified.
    smtp_ca_file: Path | None = None

    # API surface hardening
    expose_api_docs: bool = False  # /docs and /openapi.json; enable for development only
    auth_max_failures: int = Field(default=30, ge=1)  # failed auth attempts per client IP ...
    auth_failure_window_s: int = Field(default=300, ge=1)  # ... per window, then 429 until it expires
    # Behind a reverse proxy: comma-separated proxy IPs whose X-Forwarded-For is trusted,
    # so rate limits apply to the real client instead of the proxy.
    forwarded_allow_ips: str | None = None

    log_level: str = "INFO"
    retention_days: int = Field(default=90, ge=1)
    traversal_max_nodes: int = 5_000
    traversal_max_depth: int = 25

    @field_validator("admin_token")
    @classmethod
    def _admin_token_is_strong(cls, v: SecretStr | None) -> SecretStr | None:
        # The operator token is instance-wide: it can verify incidents, which gates builds in
        # enforce mode. A placeholder copied from .env.example must never become that credential.
        if v is None or not v.get_secret_value().strip():
            return None  # empty = operator endpoints disabled
        raw = v.get_secret_value()
        if len(raw) < 32 or raw.lower().startswith(("change", "example", "placeholder", "secret", "password")):
            raise ValueError("NODETRUST_ADMIN_TOKEN must be at least 32 random characters "
                             '(python -c "import secrets; print(secrets.token_urlsafe(32))"), or empty to disable it')
        return v


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
