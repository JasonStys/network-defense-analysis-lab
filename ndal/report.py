"""Jason Stys: deterministic machine-readable and escaped inert HTML analyst reports, no active content."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: document — line 27
# parameter: events — line 28
# parameter: issues — line 29
# parameter: findings — line 30
# parameter: settings — line 31
# parameter: digests — line 32
# variable: value — line 42
# variable: value — line 43
# variable: value — line 44
# definition: render — line 48
# parameter: value — line 48
# variable: safe — line 50
# END CODE MAP

from __future__ import annotations

import html
import json
from dataclasses import asdict

from ndal.detect import Policy
from ndal.model import Event, Finding, Issue


def document(
    events: list[Event],
    issues: list[Issue],
    findings: list[Finding],
    settings: Policy,
    digests: dict[str, str],
) -> dict[str, object]:
    """Produce metadata-only evidence and explicit scope/provenance; raw payloads never enter reports."""
    return {
        "schema": "ndal-report-v1",
        "author": "Jason Stys",
        "mode": "offline-human-review",
        "warning": "Hypotheses, not attack attribution or automatic blocking. Absence of a finding is not proof of safety.",
        "input_sha256": digests,
        "policy": asdict(settings),
        "events": [asdict(value) for value in events],
        "issues": [asdict(value) for value in issues],
        "findings": [asdict(value) for value in findings],
    }


def render(value: dict[str, object]) -> str:
    """Escape the complete JSON report; strict CSP denies scripts, frames, network and form submission."""
    safe = html.escape(json.dumps(value, sort_keys=True, indent=2, allow_nan=False))
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; base-uri \'none\'; form-action \'none\'"><title>Network Defense Analysis Lab — Jason Stys</title></head><body><header><h1>Network Defense Analysis Lab</h1><p>Created by Jason Stys. Offline evidence for human review.</p></header><main><h2>Evidence report</h2><p>Use browser Find to locate a rule, IP or event ID. These are hypotheses, not attack attribution.</p><pre>'
        + safe
        + "</pre></main><footer><p>Help: docs/usage.md in the repository. Contact: github.com/JasonStys</p></footer></body></html>\n"
    )
