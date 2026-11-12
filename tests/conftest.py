"""Shared pytest fixtures.

Database tests use the separate TEST database (DB_TEST_NAME in .env), never the app
database, and start every test with empty tables. If MySQL is not set up, every test
that needs it is skipped instead of failing: run scripts/setup_db.sh to enable them.
"""
from pathlib import Path

import mysql.connector
import pytest

from app.config import ConfigError, database_config
from app.repository import Repository

PROJECT_ROOT = Path(__file__).parent.parent


def _connect(config, **options):
    return mysql.connector.connect(
        host=config.host, port=config.port, user=config.user,
        password=config.password, database=config.database, **options,
    )


@pytest.fixture(scope="session")
def test_db_config():
    """Settings of the test database, with the tables created from the real schema.sql."""
    try:
        config = database_config(test=True)
        connection = _connect(config)
    except (ConfigError, mysql.connector.Error) as error:
        pytest.skip(f"MySQL test database not available ({error}). Run scripts/setup_db.sh")

    cursor = connection.cursor()
    for statement in (PROJECT_ROOT / "schema.sql").read_text(encoding="utf-8").split(";"):
        if statement.strip():
            cursor.execute(statement)
    connection.commit()
    connection.close()
    return config


@pytest.fixture
def db(test_db_config):
    """Empty tables before every test, then a connection for test-only SQL."""
    connection = _connect(test_db_config, time_zone="+00:00")
    cursor = connection.cursor()
    cursor.execute("DELETE FROM alerts")
    cursor.execute("DELETE FROM analysis_runs")
    connection.commit()
    yield connection
    connection.close()


@pytest.fixture
def repo(db, test_db_config):
    """A repository connected to the (empty) test database."""
    return Repository(test_db_config)


@pytest.fixture
def set_created_at(db):
    """Test helper: move a run to a known time (naive UTC), to test date filters."""
    def move(run_id, utc_naive):
        cursor = db.cursor()
        cursor.execute("UPDATE analysis_runs SET created_at = %s WHERE id = %s", (utc_naive, run_id))
        db.commit()
    return move
