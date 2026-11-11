"""Jason Stys: actual current Word XML remains inspected; unknown binary documents are not excluded."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: test_current_illustrated_word_remains_visible_to_existing_scan — line 18
# parameter: monkeypatch — line 19
# parameter: tmp_path — line 19
# variable: path — line 23
# variable: package — line 25
# variable: unknown — line 32
# END CODE MAP

from zipfile import ZipFile

import pytest

from scripts import validate_repo as policy


def test_current_illustrated_word_remains_visible_to_existing_scan(
    tmp_path, monkeypatch
):
    """Read real ZIP/XML for the exact new edition, without bypassing source/privacy scanning."""
    monkeypatch.setattr(policy, "ROOT", tmp_path)
    path = tmp_path / "docs/reports/windows-application-guide-1.1.0.docx"
    path.parent.mkdir(parents=True)
    with ZipFile(path, "w") as package:
        package.writestr("[Content_Types].xml", "<Types/>")
        package.writestr(
            "word/document.xml", "<document>review-visible-marker</document>"
        )
        package.writestr("word/_rels/document.xml.rels", "<Relationships/>")
    assert "review-visible-marker" in policy.public_text(path)
    unknown = path.with_name("unreviewed.docx")
    unknown.write_bytes(path.read_bytes())
    with pytest.raises(UnicodeDecodeError):
        policy.public_text(unknown)
