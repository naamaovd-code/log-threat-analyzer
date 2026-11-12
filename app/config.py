"""Database settings, read from environment variables or the .env file (decision D7).

The password is never written in the code. scripts/setup_db.sh creates .env,
and .env is listed in .gitignore so it never reaches GitHub.
"""
import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")   # real environment variables take priority over .env


class ConfigError(Exception):
    """A required setting is missing."""


@dataclass(frozen=True)
class DatabaseConfig:
    host: str
    port: int
    user: str
    password: str
    database: str


def database_config(test: bool = False) -> DatabaseConfig:
    """Settings for the app database, or for the separate test database when test=True."""
    name_key = "DB_TEST_NAME" if test else "DB_NAME"
    required = ["DB_HOST", "DB_USER", "DB_PASSWORD", name_key]
    missing = [key for key in required if not os.getenv(key)]
    if missing:
        raise ConfigError(f"Missing database settings: {', '.join(missing)}. Run scripts/setup_db.sh")

    return DatabaseConfig(
        host=os.environ["DB_HOST"],
        port=int(os.getenv("DB_PORT", "3306")),
        user=os.environ["DB_USER"],
        password=os.environ["DB_PASSWORD"],
        database=os.environ[name_key],
    )
