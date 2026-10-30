"""Minimal collector settings: no database, JWT, Redis, or provider credentials."""
from dataclasses import dataclass, field
import os


@dataclass(frozen=True)
class EmailCollectorSettings:
    EMAIL_SHARED_DIR: str = field(default_factory=lambda: os.getenv("EMAIL_SHARED_DIR", "/shared/scans"))
    EMAIL_OWNER_USER_ID: str = field(default_factory=lambda: os.getenv("EMAIL_OWNER_USER_ID", ""))
    EMAIL_ADDRESS: str = field(default_factory=lambda: os.getenv("EMAIL_ADDRESS", ""))
    EMAIL_POLLER_TOKEN: str = field(default_factory=lambda: os.getenv("EMAIL_POLLER_TOKEN", ""), repr=False)


settings = EmailCollectorSettings()
