"""Independent actual Rust/detector/SQLite/native-adapter and saved cursor oracles. Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: workspace — line 81
# parameter: tmp_path — line 81
# variable: state — line 83
# definition: execute — line 90
# parameter: index — line 90
# parameter: tmp_path — line 90
# parameter: workspace — line 90
# variable: stage — line 92
# variable: parameters — line 94
# definition: test_real_prepared_inputs_have_independent_results — line 109
# parameter: events — line 110
# parameter: index — line 110
# parameter: issues — line 110
# parameter: rules — line 110
# parameter: tmp_path — line 110
# parameter: workspace — line 110
# variable: files — line 113
# variable: kind — line 113
# variable: parameters — line 113
# variable: summary — line 113
# variable: page — line 114
# variable: report — line 114
# variable: row — line 117
# variable: rows — line 124
# variable: row — line 125
# variable: hits — line 132
# variable: row — line 134
# definition: test_saved_snapshot_next_pages_filters_and_no_source_reopen — line 139
# parameter: tmp_path — line 139
# parameter: workspace — line 139
# variable: files — line 141
# variable: kind — line 141
# variable: parameters — line 141
# variable: summary — line 141
# variable: identity — line 142
# variable: first — line 143
# variable: next_parameters — line 144
# variable: stage — line 148
# variable: _ — line 150
# variable: later — line 150
# variable: second — line 151
# variable: row — line 154
# variable: row — line 158
# variable: row — line 159
# variable: bad — line 163
# variable: filtered — line 168
# variable: _ — line 170
# variable: value — line 170
# definition: test_actual_external_logs_custom_policy_and_invalids — line 175
# parameter: tmp_path — line 175
# parameter: workspace — line 175
# variable: parameters — line 177
# variable: outside — line 178
# variable: stage — line 183
# variable: _ — line 185
# variable: files — line 185
# variable: row — line 187
# variable: field — line 193
# variable: invalid — line 193
# variable: bad — line 203
# variable: malformed — line 207
# definition: test_edited_prepared_files_never_overwritten — line 220
# parameter: workspace — line 220
# variable: parameters — line 222
# variable: capture — line 223
# END CODE MAP

from pathlib import Path

import pytest

from ndal import desktop_project as project
from ndal.desktop_io import Rejected, json_value
from ndal.desktop_state import Workspace
from ndal.synthetic import log_sample


@pytest.fixture
def workspace(tmp_path):
    """Own synthetic history only; no default application profile is opened."""
    state = Workspace(tmp_path / "profile", project.PRODUCT, project.ROOT)
    try:
        yield state
    finally:
        state.close()


def execute(workspace, tmp_path, index):
    """Run the real core on a prepared editable input in a fresh private staging directory."""
    stage = tmp_path / f"stage-{index}"
    stage.mkdir()
    parameters = project.scenario(project.SCENARIOS[index], workspace)
    return parameters, project.analyze(workspace, parameters, stage)


@pytest.mark.parametrize(
    "index,events,rules,issues",
    [
        (0, 20, {"dns_nxdomain_burst", "tcp_periodicity"}, 0),
        (1, 3, set(), 0),
        (2, 30, set(), 0),
        (3, 10, {"tcp_port_fanout"}, 0),
        (4, 0, {"capture_quality"}, 3),
        (5, 10, set(), 0),
    ],
)
def test_real_prepared_inputs_have_independent_results(
    workspace, tmp_path, index, events, rules, issues
):
    """Selected policy changes true detections; malformed capture gaps cannot disappear into a benign result."""
    parameters, (kind, summary, files) = execute(workspace, tmp_path, index)
    report, page = json_value(files["report.json"]), json_value(files["query.json"])
    assert kind == project.MODES[0] and "full events" in summary
    assert len(report["events"]) == events
    assert {row["rule"] for row in report["findings"]} == rules
    assert len(report["issues"]) == issues
    assert page["capture_issues_unfiltered"] == report["issues"]
    assert page["total_matches"] == events and len(page["events"]) == min(2, events)
    assert report["input_sha256"]["capture"]
    assert "not original" in report["policy_hash_scope"]
    assert len(project.views(files)) >= 4
    for rows in project.views(files).values():
        assert all(len(project.cells(row)) == 4 for row in rows)
    if index == 0:
        assert project.cells(report["findings"][0])[0] == "192.0.2.10"
        assert (
            project.cells(report["findings"][0])[2]
            == report["findings"][0]["explanation"]
        )
        hits = project.views(files)["Exact SQL evidence search"]
        assert hits and all(
            "192.0.2.10" in (row["src"], row["dst"], row["name"]) for row in hits
        )
    assert Path(parameters["capture"]).is_relative_to(workspace.path)


def test_saved_snapshot_next_pages_filters_and_no_source_reopen(workspace, tmp_path):
    """Actual cursor advances equal-source rows; later source removal cannot change already saved normalized evidence."""
    parameters, (kind, summary, files) = execute(workspace, tmp_path, 0)
    identity = workspace.save(kind, summary, parameters, files)
    first = json_value(files["query.json"])
    next_parameters = project.next_page(files)
    next_parameters["_run"] = str(identity)
    Path(parameters["capture"]).unlink()
    Path(parameters["logs"]).unlink()
    stage = tmp_path / "next"
    stage.mkdir()
    _, _, later = project.analyze(workspace, next_parameters, stage)
    second = json_value(later["query.json"])
    assert second["snapshot_filter_sha256"] == first["snapshot_filter_sha256"]
    assert second["total_matches"] == 20
    assert [(row["identifier"], row["time_ns"]) for row in second["events"]] == [
        ("packet-2", 1000000000),
        ("packet-3", 2000000000),
    ]
    assert {row["identifier"] for row in first["events"]}.isdisjoint(
        row["identifier"] for row in second["events"]
    )
    assert files["report.json"] == later["report.json"]
    next_parameters["protocol"] = "tcp"
    bad = tmp_path / "changed"
    bad.mkdir()
    with pytest.raises(ValueError, match="snapshot/filter"):
        project.analyze(workspace, next_parameters, bad)
    next_parameters.update(cursor="", search="' OR 1=1 --")
    filtered = tmp_path / "filtered"
    filtered.mkdir()
    _, _, value = project.analyze(workspace, next_parameters, filtered)
    assert json_value(value["query.json"])["total_matches"] == 10
    assert json_value(value["search.json"]) == []


def test_actual_external_logs_custom_policy_and_invalids(workspace, tmp_path):
    """External files use actual original detection; malformed policies/paths/filters never substitute a default scenario."""
    parameters = project.scenario(project.SCENARIOS[0], workspace)
    outside = tmp_path / "authorized-connections.jsonl"
    outside.write_bytes(log_sample())
    parameters.update(
        capture="", logs=str(outside), rule="tcp_periodicity", limit="1000"
    )
    stage = tmp_path / "external"
    stage.mkdir()
    _, _, files = project.analyze(workspace, parameters, stage)
    assert len(json_value(files["report.json"])["events"]) == 10
    assert {row["rule"] for row in json_value(files["report.json"])["findings"]} == {
        "tcp_periodicity"
    }
    assert json_value(files["query.json"])["total_matches"] == 10
    with pytest.raises(Rejected, match="no_next"):
        project.next_page(files)
    for field, invalid in [
        ("mode", "run arbitrary shell"),
        ("limit", "0"),
        ("start", "nan"),
        ("end", "-1"),
        ("protocol", "icmp"),
        ("severity", "safe"),
        ("rule", "bad-rule!"),
        ("cursor", "not-a-cursor"),
    ]:
        bad = tmp_path / ("bad-" + field)
        bad.mkdir()
        with pytest.raises(ValueError):
            project.analyze(workspace, parameters | {field: invalid}, bad)
    malformed = tmp_path / "bad-policy.json"
    malformed.write_text('{"window_seconds":60,"window_seconds":0}', encoding="utf-8")
    with pytest.raises(Rejected):
        project.analyze(workspace, parameters | {"policy": str(malformed)}, tmp_path)
    with pytest.raises(Rejected):
        project.analyze(workspace, parameters | {"capture": "", "logs": ""}, tmp_path)
    with pytest.raises(Rejected):
        project.scenario("unknown", workspace)
    with pytest.raises(Rejected):
        project.number("١", 0, 10)
    assert workspace.history() == []


def test_edited_prepared_files_never_overwritten(workspace):
    """A user edit is retained byte-for-byte rather than reset or misrepresented as a known prepared result."""
    parameters = project.scenario(project.SCENARIOS[1], workspace)
    capture = Path(parameters["capture"])
    capture.write_bytes(b"operator edited input")
    with pytest.raises(Rejected, match="changed"):
        project.scenario(project.SCENARIOS[1], workspace)
    assert capture.read_bytes() == b"operator edited input"
