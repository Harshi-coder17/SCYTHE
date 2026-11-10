from urllib.parse import unquote, urlparse

from config import Settings


def test_database_url_default_does_not_duplicate_password():
    default = Settings.model_fields["DATABASE_URL"].default
    assert urlparse(default).password is None


def test_authoritative_database_password_is_injected_when_url_has_none():
    settings = Settings(
        DATABASE_URL="postgresql+psycopg2://scythe_user@postgres:5432/scythe_db",
        SCYTHE_DB_PASSWORD="unit-test-database-password",
    )
    parsed = urlparse(settings.DATABASE_URL)
    assert unquote(parsed.password or "") == "unit-test-database-password"
