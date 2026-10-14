"""Jason Stys: private-evidence exclusion, exact links/pins and dependency-free/offline runtime gates."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 23
# definition: main — line 26
# variable: names — line 28
# variable: name — line 35
# variable: path — line 36
# variable: text — line 42
# variable: target — line 47
# variable: action — line 53
# variable: word — line 57
# variable: word — line 71
# variable: graph — line 78
# variable: tool — line 84
# END CODE MAP

import json
import re
import subprocess
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


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
        text = path.read_text(encoding="utf-8")
        assert not re.search(
            r"(?:ghp_|github_pat_)[A-Za-z0-9]{20,}|BEGIN [A-Z ]*PRIVATE KEY", text
        )
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
