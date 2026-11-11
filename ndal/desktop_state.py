"""Owner-local desktop profile, bounded durable bundles and non-overwriting export. Jason Stys.

No host collection, network listener, shell command or public account is involved.
An exclusive OS lock owns one marked profile; SQLite keeps actual core outputs.
"""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: MAX_FILE — line 136
# variable: MAX_BUNDLE — line 137
# variable: MAX_HISTORY — line 138
# variable: MAX_RUNS — line 139
# definition: package_identity — line 142
# parameter: root — line 143
# parameter: product — line 144
# parameter: version — line 145
# parameter: names — line 146
# parameter: resource_limits — line 147
# variable: path — line 150
# variable: value — line 153
# variable: limits — line 177
# variable: value — line 180
# variable: name — line 183
# variable: identity — line 189
# definition: profile_path — line 207
# parameter: name — line 207
# variable: base — line 210
# variable: base — line 212
# variable: base — line 214
# definition: unlinked — line 218
# parameter: path — line 218
# variable: path — line 220
# variable: p — line 221
# definition: Workspace — line 226
# definition: __init__ — line 229
# parameter: path — line 230
# parameter: product — line 230
# parameter: resources — line 230
# parameter: self — line 230
# parameter: synthetic — line 230
# attribute: path — line 233
# variable: marker — line 239
# variable: expected — line 240
# variable: stream — line 244
# variable: actual — line 247
# variable: flags — line 255
# attribute: lock — line 261
# variable: info — line 263
# variable: database — line 277
# attribute: database — line 288
# variable: connection — line 289
# definition: connect — line 310
# parameter: self — line 310
# variable: connection — line 314
# definition: close — line 324
# parameter: self — line 324
# attribute: lock — line 328
# definition: save — line 330
# parameter: self — line 331
# parameter: kind — line 332
# parameter: summary — line 333
# parameter: parameters — line 334
# parameter: files — line 335
# variable: name — line 343
# variable: value — line 348
# variable: data — line 352
# variable: total — line 352
# variable: data — line 353
# variable: connection — line 355
# variable: count — line 357
# variable: size — line 358
# variable: identity — line 365
# variable: data — line 385
# variable: name — line 385
# definition: history — line 390
# parameter: self — line 390
# variable: connection — line 392
# variable: rows — line 393
# variable: row — line 399
# definition: _rows — line 402
# parameter: connection — line 403
# parameter: identity — line 403
# parameter: self — line 403
# variable: count — line 406
# variable: largest — line 406
# variable: total — line 406
# variable: rows — line 412
# variable: row — line 420
# variable: row — line 427
# definition: files — line 432
# parameter: identity — line 432
# parameter: self — line 432
# variable: connection — line 436
# variable: rows — line 438
# variable: _digest — line 439
# variable: data — line 439
# variable: name — line 439
# definition: remove — line 441
# parameter: expected — line 441
# parameter: identity — line 441
# parameter: self — line 441
# variable: connection — line 445
# variable: rows — line 447
# variable: _data — line 448
# variable: digest — line 448
# variable: manifest — line 448
# variable: name — line 448
# definition: export — line 454
# parameter: identity — line 454
# parameter: parent — line 454
# parameter: product — line 454
# parameter: self — line 454
# variable: files — line 456
# variable: parent — line 459
# variable: target — line 462
# variable: data — line 464
# variable: name — line 464
# variable: stream — line 467
# END CODE MAP

from __future__ import annotations

import hashlib
import os
import re
import secrets
import sqlite3
import stat
import sys
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .desktop_io import Rejected, canonical, json_value, read_bytes
from .inputs import file_hash

MAX_FILE = 32 * 1024 * 1024
MAX_BUNDLE = 64 * 1024 * 1024
MAX_HISTORY = 128 * 1024 * 1024
MAX_RUNS = 20


def package_identity(
    root: Path,
    product: str,
    version: str,
    names: tuple[str, ...],
    resource_limits: dict[str, int] | None = None,
) -> dict[str, Any]:
    """Bind frozen resource bytes to reviewed source metadata before opening a durable profile."""
    path = root / "native-release.json"
    if not path.exists() and not getattr(sys, "frozen", False):
        return {"source": "development", "source_dirty": True}
    value = json_value(read_bytes(path, 16384))
    if not isinstance(value, dict) or set(value) != {
        "schema",
        "product",
        "version",
        "source",
        "source_dirty",
        "resources",
    }:
        raise Rejected("invalid package identity")
    if (
        type(value["schema"]) is not int
        or value["schema"] != 1
        or value["product"] != product
        or value["version"] != version
        or not isinstance(value["source"], str)
        or re.fullmatch("[a-f0-9]{40}", value["source"]) is None
        or type(value["source_dirty"]) is not bool
    ):
        raise Rejected("invalid package source identity")
    if not isinstance(value["resources"], dict) or set(value["resources"]) != set(
        names
    ):
        raise Rejected("incomplete package resources")
    limits = resource_limits or {}
    if set(limits) - set(names) or any(
        type(value) is not int or not MAX_FILE <= value <= 128 * 1024 * 1024
        for value in limits.values()
    ):
        raise Rejected("invalid fixed package resource bounds")
    for name in names:
        if (
            file_hash(root / name, limits.get(name, MAX_FILE))
            != value["resources"][name]
        ):
            raise Rejected("package resource hash mismatch")
    identity = {"source": value["source"], "source_dirty": value["source_dirty"]}
    if getattr(sys, "frozen", False):
        if (
            sys.version_info[:3] != (3, 14, 10)
            or "python314.dll" not in value["resources"]
        ):
            raise Rejected(
                "frozen application requires patched CPython3.14.10 and its verified runtime DLL"
            )
        identity.update(
            {
                "python_version": sys.version.split()[0],
                "python_dll_sha256": value["resources"]["python314.dll"],
            }
        )
    return identity


def profile_path(name: str) -> Path:
    """Select a version-independent OS-local workspace, never the executable directory."""
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData/Local"))
    elif sys.platform == "darwin":
        base = Path.home() / "Library/Application Support"
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share"))
    return base / "JasonStys" / name


def unlinked(path: Path) -> Path:
    """Reject linked ancestors before normalizing a caller-selected local path."""
    path = path.absolute()
    if any(p.is_symlink() or p.is_junction() for p in (path, *path.parents)):
        raise Rejected("linked workspace or output path")
    return path.resolve()


class Workspace:
    """One-owner plaintext history; preserving evidence does not authenticate its publisher or analyst."""

    def __init__(
        self, path: Path, product: str, resources: Path, *, synthetic: bool = False
    ) -> None:
        """Open only a new or explicitly marked profile and take an exclusive nonblocking OS lock."""
        self.path = unlinked(path)
        if self.path.is_relative_to(resources.resolve()) or self.path.is_relative_to(
            Path(sys.executable).parent.resolve()
        ):
            raise Rejected("workspace must be outside the application installation")
        self.path.mkdir(parents=True, exist_ok=True, mode=0o700)
        marker = self.path / "profile.json"
        expected = {"schema": 1, "product": product, "synthetic_acceptance": synthetic}
        if not marker.exists():
            if any(self.path.iterdir()):
                raise Rejected("unknown nonempty workspace; no files were reset")
            with marker.open("xb") as stream:
                os.chmod(marker, 0o600)
                stream.write(canonical(expected))
        actual = json_value(read_bytes(marker, 4096))
        if (
            not isinstance(actual, dict)
            or actual != expected
            or type(actual.get("schema")) is not int
            or type(actual.get("synthetic_acceptance")) is not bool
        ):
            raise Rejected("workspace belongs to another application or profile type")
        flags = (
            os.O_RDWR
            | os.O_CREAT
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
        )
        self.lock = os.open(self.path / "instance.lock", flags, 0o600)
        try:
            info = os.fstat(self.lock)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise Rejected("workspace lock must be a regular one-link file")
            if info.st_size == 0:
                os.write(self.lock, b"0")
            os.lseek(self.lock, 0, os.SEEK_SET)
            if sys.platform == "win32":
                import msvcrt

                msvcrt.locking(self.lock, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            database = self.path / "history.sqlite"
            if (
                database.is_symlink()
                or database.is_junction()
                or database.exists()
                and (
                    not stat.S_ISREG(database.lstat().st_mode)
                    or database.lstat().st_nlink != 1
                )
            ):
                raise Rejected("linked history database")
            self.database = database
            with closing(self.connect()) as connection, connection:
                connection.executescript("""
                    CREATE TABLE IF NOT EXISTS run(id INTEGER PRIMARY KEY, created TEXT NOT NULL, kind TEXT NOT NULL,
                        summary TEXT NOT NULL, parameters TEXT NOT NULL) STRICT;
                    CREATE TABLE IF NOT EXISTS bundle(run_id INTEGER NOT NULL REFERENCES run(id), name TEXT NOT NULL,
                        payload BLOB NOT NULL, sha256 TEXT NOT NULL, PRIMARY KEY(run_id,name)) STRICT;
                    CREATE TABLE IF NOT EXISTS counter(id INTEGER PRIMARY KEY CHECK(id=1),next_id INTEGER NOT NULL CHECK(next_id>0)) STRICT;
                    INSERT OR IGNORE INTO counter VALUES(1,(SELECT coalesce(max(id),0)+1 FROM run));
                """)
                if (
                    connection.execute("PRAGMA integrity_check").fetchone() != ("ok",)
                    or connection.execute("PRAGMA foreign_key_check").fetchall()
                ):
                    raise Rejected(
                        "history integrity check failed; retain a private backup"
                    )
            os.chmod(database, 0o600)
        except BaseException:
            os.close(self.lock)
            raise

    def connect(self) -> sqlite3.Connection:
        """Use short transactions and no shared mutable SQLite connection across GUI/worker threads."""
        if self.lock < 0:
            raise Rejected("workspace is closed")
        connection = sqlite3.connect(self.database, timeout=5)
        try:
            connection.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, MAX_FILE + 8192)
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA synchronous=FULL")
        except BaseException:
            connection.close()
            raise
        return connection

    def close(self) -> None:
        """Release only this process's owned lock; saved bundles are never removed during shutdown."""
        if self.lock >= 0:
            os.close(self.lock)
            self.lock = -1

    def save(
        self,
        kind: str,
        summary: str,
        parameters: dict[str, str],
        files: dict[str, bytes],
    ) -> int:
        """Atomically retain a completed real-core bundle; finite limits fail without evicting earlier evidence."""
        if (
            not files
            or len(files) > 8
            or any(
                re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,95}", name) is None
                for name in files
            )
        ):
            raise Rejected("invalid output bundle names")
        if (
            sum(len(value.encode("utf-8")) for value in parameters.values())
            > 512 * 1024
        ):
            raise Rejected("desktop parameter text exceeds its limit")
        total = sum(len(data) for data in files.values())
        if total > MAX_BUNDLE or any(len(data) > MAX_FILE for data in files.values()):
            raise Rejected("desktop bundle exceeds its documented byte limit")
        with closing(self.connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            count = connection.execute("SELECT count(*) FROM run").fetchone()[0]
            size = connection.execute(
                "SELECT coalesce(sum(length(payload)),0) FROM bundle"
            ).fetchone()[0]
            if count >= MAX_RUNS or size + total > MAX_HISTORY:
                raise Rejected(
                    "desktop history is full; export backups and explicitly remove selected local analyses"
                )
            identity = int(
                connection.execute("SELECT next_id FROM counter WHERE id=1").fetchone()[
                    0
                ]
            )
            connection.execute(
                "INSERT INTO run(id,created,kind,summary,parameters) VALUES(?,?,?,?,?)",
                (
                    identity,
                    datetime.now(UTC).isoformat(),
                    kind,
                    summary[:500],
                    canonical(parameters).decode(),
                ),
            )
            connection.execute("UPDATE counter SET next_id=next_id+1 WHERE id=1")
            connection.executemany(
                "INSERT INTO bundle VALUES(?,?,?,?)",
                [
                    (identity, name, data, hashlib.sha256(data).hexdigest())
                    for name, data in files.items()
                ],
            )
        return identity

    def history(self) -> list[dict[str, Any]]:
        """List bounded local history newest first without reading all private report payloads."""
        with closing(self.connect()) as connection:
            rows = connection.execute(
                "SELECT id,created,kind,summary FROM run ORDER BY id DESC LIMIT ?",
                (MAX_RUNS,),
            ).fetchall()
        return [
            dict(zip(("id", "created", "kind", "summary"), row, strict=True))
            for row in rows
        ]

    def _rows(
        self, connection: sqlite3.Connection, identity: int
    ) -> list[tuple[str, bytes, str]]:
        """Check row/aggregate bounds before fetching BLOBs inside the caller's SQLite snapshot."""
        count, total, largest = connection.execute(
            "SELECT count(*),coalesce(sum(length(payload)),0),coalesce(max(length(payload)),0) FROM bundle WHERE run_id=?",
            (identity,),
        ).fetchone()
        if not 1 <= count <= 8 or total > MAX_BUNDLE or largest > MAX_FILE:
            raise Rejected("saved analysis is missing or outside byte/count limits")
        rows = connection.execute(
            "SELECT name,payload,sha256 FROM bundle WHERE run_id=?", (identity,)
        ).fetchall()
        if (
            not rows
            or len(rows) > 8
            or any(
                re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,95}", row[0]) is None
                for row in rows
            )
        ):
            raise Rejected("saved analysis is missing or malformed")
        if any(
            not isinstance(row[1], bytes)
            or hashlib.sha256(row[1]).hexdigest() != row[2]
            for row in rows
        ):
            raise Rejected("saved analysis hash/size check failed")
        return rows

    def files(self, identity: int) -> dict[str, bytes]:
        """Read only one exact existing bundle and verify every stored byte hash before rendering/export."""
        if type(identity) is not int or identity < 1:
            raise Rejected("select a saved analysis first")
        with closing(self.connect()) as connection:
            connection.execute("BEGIN")
            rows = self._rows(connection, identity)
        return {name: bytes(data) for name, data, _digest in rows}

    def remove(self, identity: int, expected: str) -> None:
        """Delete only one explicitly confirmed exact local bundle; original input/export files are never removed."""
        if type(identity) is not int or identity < 1:
            raise Rejected("select a saved analysis first")
        with closing(self.connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            rows = self._rows(connection, identity)
            manifest = {name: digest for name, _data, digest in rows}
            if hashlib.sha256(canonical(manifest)).hexdigest() != expected:
                raise Rejected("saved bundle changed after selection")
            connection.execute("DELETE FROM bundle WHERE run_id=?", (identity,))
            connection.execute("DELETE FROM run WHERE id=?", (identity,))

    def export(self, identity: int, parent: Path, product: str) -> Path:
        """Copy a verified bundle into a new owner-selected directory; do not overwrite or execute its contents."""
        files = self.files(identity)
        if re.fullmatch(r"[a-z0-9][a-z0-9-]{1,79}", product) is None:
            raise Rejected("invalid export product namespace")
        parent = unlinked(parent)
        if not parent.is_dir():
            raise Rejected("select an existing private export parent")
        target = parent / f"{product}-run-{identity}-{secrets.token_hex(4)}"
        target.mkdir(mode=0o700)
        for name, data in files.items():
            if Path(name).name != name or ":" in name:
                raise Rejected("invalid saved export name")
            with (target / name).open("xb") as stream:
                os.chmod(stream.name, 0o600)
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
        return target
