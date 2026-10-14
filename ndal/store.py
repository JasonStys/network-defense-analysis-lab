"""Jason Stys: transactional metadata-only SQLite evidence store and parameterized search."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 25
# definition: database — line 28
# parameter: events — line 28
# parameter: issues — line 28
# variable: connection — line 32
# variable: value — line 38
# variable: value — line 41
# definition: search — line 49
# parameter: connection — line 50
# parameter: limit — line 50
# parameter: value — line 50
# END CODE MAP

from __future__ import annotations

import sqlite3
from dataclasses import astuple
from pathlib import Path
from typing import Any

from ndal.model import MAX_EVENTS, Event, Issue, integer

ROOT = Path(__file__).resolve().parents[1]


def database(events: list[Event], issues: list[Issue]) -> sqlite3.Connection:
    """Construct an ephemeral strict SQLite snapshot; duplicate evidence fails the whole transaction."""
    if len(events) > MAX_EVENTS * 2 or len(issues) > MAX_EVENTS * 2:
        raise ValueError("evidence count limit")
    connection = sqlite3.connect(":memory:")
    try:
        connection.executescript((ROOT / "sql/schema.sql").read_text(encoding="utf-8"))
        with connection:
            connection.executemany(
                "INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                [astuple(value) for value in events],
            )
            connection.executemany(
                "INSERT INTO issues VALUES (?,?)", [astuple(value) for value in issues]
            )
    except Exception:
        connection.close()
        raise
    return connection


def search(
    connection: sqlite3.Connection, value: str, limit: int = 100
) -> list[tuple[Any, ...]]:
    """Search exact source/destination/hostname, sorted and capped; quotes and SQL syntax stay data."""
    integer(limit, 1, 1000)
    if len(value) > 253:
        raise ValueError("search value limit")
    return connection.execute(
        (ROOT / "sql/search.sql").read_text(encoding="utf-8"),
        (value, value, value, limit),
    ).fetchall()
