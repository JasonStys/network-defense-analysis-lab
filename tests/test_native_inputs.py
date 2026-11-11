"""Actual descriptor identity, FIFO availability, resource bounds and minimal native environment. Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: test_actual_bytes_hash_bounds_and_mutation — line 55
# parameter: monkeypatch — line 55
# parameter: tmp_path — line 55
# variable: selected — line 57
# variable: function — line 61
# variable: limit — line 62
# variable: path — line 62
# variable: actual — line 65
# variable: count — line 66
# definition: mutate — line 68
# parameter: descriptor — line 68
# variable: count — line 71
# variable: stream — line 73
# definition: test_hardlink_descriptor_swap_and_minimal_decoder_environment — line 82
# parameter: monkeypatch — line 83
# parameter: tmp_path — line 83
# variable: selected — line 86
# variable: alias — line 88
# variable: actual — line 93
# variable: patch — line 94
# parameter: descriptor — line 98
# variable: execute — line 102
# variable: seen — line 103
# definition: observe — line 107
# parameter: argv — line 107
# parameter: kwargs — line 107
# definition: test_regular_input_replaced_with_fifo_cannot_block — line 125
# parameter: tmp_path — line 125
# variable: selected — line 127
# variable: script — line 129
# variable: completed — line 143
# definition: test_resource_bound_cannot_increase_evidence_or_unknown_resources — line 153
# parameter: tmp_path — line 153
# variable: selected — line 155
# variable: value — line 157
# variable: limits — line 177
# END CODE MAP

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from ndal import cli, desktop_state, inputs
from ndal.desktop_io import Rejected
from ndal.synthetic import scenario


def test_actual_bytes_hash_bounds_and_mutation(tmp_path, monkeypatch):
    """The original CLI and native adapter cannot accept changed, oversized, linked or nonregular input."""
    selected = tmp_path / "data"
    selected.write_bytes(b"0123456789")
    assert cli.read(selected, 10) == b"0123456789"
    assert inputs.file_hash(selected, 10) == hashlib.sha256(b"0123456789").hexdigest()
    for function in (inputs.read_source, inputs.file_hash):
        for path, limit in ((selected, 9), (tmp_path / "missing", 10), (tmp_path, 10)):
            with pytest.raises(Rejected):
                function(path, limit)
    actual = inputs.os.fstat
    count = 0

    def mutate(descriptor):
        """Append real bytes between the opened descriptor's first and final observations."""
        nonlocal count
        count += 1
        if count == 2:
            with selected.open("ab") as stream:
                stream.write(b"changed")
        return actual(descriptor)

    monkeypatch.setattr(inputs.os, "fstat", mutate)
    with pytest.raises(Rejected, match="changed"):
        inputs.file_hash(selected, 30)


def test_hardlink_descriptor_swap_and_minimal_decoder_environment(
    tmp_path, monkeypatch
):
    """A selected regular path does not authorize another file type or inheriting provider/developer state."""
    selected = tmp_path / "input"
    selected.write_bytes(b"{}")
    alias = tmp_path / "alias"
    os.link(selected, alias)
    with pytest.raises(Rejected):
        inputs.read_source(selected, 20)
    alias.unlink()
    actual = inputs.os.fstat
    with monkeypatch.context() as patch:
        patch.setattr(
            inputs.os,
            "fstat",
            lambda descriptor: os.stat_result((0, *tuple(actual(descriptor))[1:])),
        )
        with pytest.raises(Rejected, match="changed"):
            inputs.read_source(selected, 20)
    execute = cli.subprocess.run
    seen = []
    monkeypatch.setenv("SYNTHETIC_PROVIDER_SECRET", "never-in-child")
    monkeypatch.setenv("PYTHONPATH", "never-in-child")

    def observe(argv, **kwargs):
        """Inspect actual fixed invocation, then execute the genuine native Rust decoder on fictional bytes."""
        assert set(kwargs["env"]) <= {"SYSTEMROOT", "WINDIR", "TEMP", "TMP"}
        assert "never-in-child" not in str(kwargs["env"])
        assert kwargs["timeout"] == 15 and kwargs["check"] is False
        assert len(argv) == 2 and "shell" not in kwargs
        seen.append(argv)
        return execute(argv, **kwargs)

    monkeypatch.setattr(cli.subprocess, "run", observe)
    assert len(cli.decode(scenario("office_baseline"), scratch=tmp_path)[1]) == 3
    assert len(seen) == 1


@pytest.mark.skipif(
    os.name == "nt",
    reason="Actual POSIX FIFO swap; Windows same-descriptor controls and frozen GUI are separate",
)
def test_regular_input_replaced_with_fifo_cannot_block(tmp_path):
    """A real no-writer FIFO replacement is refused by an owned child under a fixed three-second deadline."""
    selected = tmp_path / "input"
    selected.write_bytes(b"{}")
    script = """
import os,sys
from pathlib import Path
from ndal import inputs
from ndal.desktop_io import Rejected
path=Path(sys.argv[1]);actual=inputs.os.open
def replace(name,flags,*args):
 path.unlink();os.mkfifo(path)
 return actual(name,flags,*args)
inputs.os.open=replace
try:inputs.read_source(path,65536)
except Rejected:raise SystemExit(0)
raise SystemExit(3)
"""
    completed = subprocess.run(
        [sys.executable, "-c", script, str(selected)],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        check=False,
        timeout=3,
    )
    assert completed.returncode == 0


def test_resource_bound_cannot_increase_evidence_or_unknown_resources(tmp_path):
    """Only a declared fixed large tool may have a separate cap; history/report limits stay finite."""
    selected = tmp_path / "tool.exe"
    selected.write_bytes(b"inert file never executed")
    value = {
        "schema": 1,
        "product": "fixture-app",
        "version": "1.1.0",
        "source": "a" * 40,
        "source_dirty": False,
        "resources": {"tool.exe": hashlib.sha256(selected.read_bytes()).hexdigest()},
    }
    (tmp_path / "native-release.json").write_text(json.dumps(value), encoding="utf-8")
    assert (
        desktop_state.package_identity(
            tmp_path,
            "fixture-app",
            "1.1.0",
            ("tool.exe",),
            {"tool.exe": 128 * 1024 * 1024},
        )["source"]
        == "a" * 40
    )
    assert desktop_state.MAX_FILE == 32 * 1024 * 1024
    for limits in (
        {"unknown": 128 * 1024 * 1024},
        {"tool.exe": True},
        {"tool.exe": 1},
        {"tool.exe": 128 * 1024 * 1024 + 1},
    ):
        with pytest.raises(Rejected, match="resource bounds"):
            desktop_state.package_identity(
                tmp_path, "fixture-app", "1.1.0", ("tool.exe",), limits
            )
