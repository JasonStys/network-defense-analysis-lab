"""Jason Stys: private-evidence exclusion, exact links/pins and dependency-free/offline runtime gates."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 36
# definition: public_text — line 39
# parameter: path — line 39
# variable: package — line 46
# variable: members — line 47
# variable: member — line 48
# variable: names — line 48
# variable: member — line 52
# variable: item — line 57
# variable: inspected — line 61
# variable: member — line 62
# variable: member — line 64
# variable: member — line 68
# definition: main — line 71
# variable: names — line 73
# variable: name — line 80
# variable: path — line 81
# variable: text — line 87
# variable: target — line 92
# variable: action — line 98
# variable: word — line 102
# variable: word — line 116
# variable: graph — line 123
# variable: tool — line 129
# END CODE MAP

import json
import re
import subprocess
import tomllib
from pathlib import Path
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[1]


def public_text(path: Path) -> str:
    """Inspect all XML/relationships in the exact reviewed Word editions; unknown binary files still fail closed."""
    if path.relative_to(ROOT).as_posix() not in {
        "docs/reports/project-guide.docx",
        "docs/reports/windows-application-guide-1.1.0.docx",
    }:
        return path.read_text(encoding="utf-8")
    with ZipFile(path) as package:
        members = package.infolist()
        names = [member.filename for member in members]
        if (
            len(members) > 256
            or len(set(names)) != len(names)
            or sum(member.file_size for member in members) > 8 * 1024 * 1024
            or "word/document.xml" not in names
            or "[Content_Types].xml" not in names
            or any(
                "vbaProject" in item or item.startswith("word/embeddings/")
                for item in names
            )
        ):
            raise ValueError("Invalid or unsupported reviewed Word package")
        inspected = [
            member for member in members if member.filename.endswith((".xml", ".rels"))
        ]
        if sum(member.file_size for member in inspected) > 2 * 1024 * 1024:
            raise ValueError("Reviewed Word XML exceeds inspection budget")
        if package.testzip() is not None:
            raise ValueError("Reviewed Word package integrity failed")
        return "\n".join(package.read(member).decode("utf-8") for member in inspected)


def main() -> None:
    """Inspect the entire tracked inventory; fail on private state, dangling links or mutable/cache actions."""
    names = (
        subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT)
        .decode()
        .rstrip("\0")
        .split("\0")
    )
    assert names != [""]
    for name in names:
        path = ROOT / name
        assert path.is_file()
        assert not name.startswith(("out/", "target/", ".tools/", ".venv/"))
        assert not re.search(
            r"\.(?:pem|key|token|env|pcap|pcapng|db|sqlite)(?:$|[.-])", name
        )
        text = public_text(path)
        assert not re.search(
            r"(?:ghp_|github_pat_)[A-Za-z0-9]{20,}|BEGIN [A-Z ]*PRIVATE KEY", text
        ), "possible credential in tracked source"
        if name.endswith(".md"):
            for target in re.findall(r"\]\(([^)]+)\)", text):
                if not target.startswith(("http:", "https:", "#", "mailto:")):
                    assert (path.parent / target.split("#")[0]).is_file(), (
                        name + ": " + target
                    )
        if name.startswith(".github/workflows/"):
            for action in re.findall(r"uses:\s*([^\s#]+)", text):
                assert re.fullmatch(r"[\w/.-]+@[a-f0-9]{40}", action)
                assert not any(
                    word in action
                    for word in (
                        "upload-artifact",
                        "download-artifact",
                        "actions/cache",
                    )
                )
            assert (
                "persist-credentials: false" in text and "id-token: write" not in text
            )
            assert "pull_request_target" not in text
        if name.startswith("native/"):
            assert not re.search(r"\bunsafe\s*\{", text)
            assert not any(
                word in text
                for word in ("TcpStream", "UdpSocket", "std::net", "libpcap")
            )
        if name.startswith("ndal/"):
            assert "shell=True" not in text
            assert not re.search(
                r"^(?:import socket|from urllib|import requests)", text, re.M
            )
    graph = tomllib.loads((ROOT / "Cargo.lock").read_text())
    assert len(graph["package"]) == 1 and "source" not in graph["package"][0]
    assert not tomllib.loads((ROOT / "pyproject.toml").read_text())["project"][
        "dependencies"
    ]
    assert "--hash=sha256:" in (ROOT / "requirements-dev.lock").read_text()
    for tool in json.loads((ROOT / "tools.lock.json").read_text())["tools"].values():
        assert re.fullmatch(r"[a-f0-9]{64}", tool["sha256"])
    print(f"Privacy/link/pin/offline gates: {len(names)} files passed")


if __name__ == "__main__":
    main()
