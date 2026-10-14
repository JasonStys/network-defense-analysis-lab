"""Jason Stys: exact tracked-file README purpose inventory, unknown files fail rather than receive guesses."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 29
# variable: BEGIN — line 30
# variable: END — line 30
# variable: SPECIAL — line 31
# definition: purpose — line 44
# parameter: name — line 44
# variable: text — line 48
# variable: line — line 53
# definition: main — line 59
# variable: parser — line 61
# variable: args — line 63
# variable: names — line 64
# variable: rows — line 72
# variable: name — line 73
# variable: path — line 75
# variable: original — line 76
# variable: end — line 77
# variable: start — line 77
# variable: expected — line 78
# END CODE MAP

import argparse
import ast
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BEGIN, END = "<!-- BEGIN FILE GUIDE -->", "<!-- END FILE GUIDE -->"
SPECIAL = {
    ".gitignore": "Exclude private captures, evidence, local environments and generated builds.",
    ".gitattributes": "Consistent LF text checkouts across operating systems.",
    "Cargo.lock": "Complete dependency-free native package graph, checked with --locked.",
    "LICENSE": "MIT license for Jason Stys's authored code.",
    "config/default.json": "Strict tunable detection thresholds with empty explicitly scoped allowlists.",
    "requirements-dev.lock": "Full universal hash-locked Python development dependency graph.",
    "tools.lock.json": "Official scanner versions, release URLs and pinned SHA256 digests.",
    "docs/reports/ci.json": "Immutable accepted-source CI job snapshot, not a future guarantee.",
    "docs/reports/benchmark.json": "Measured synthetic Windows benchmark snapshot, not a throughput promise.",
}


def purpose(name: str) -> str:
    """Read the authored module/header/title purpose or explicit noncommentable-file description."""
    if name in SPECIAL:
        return SPECIAL[name]
    text = (ROOT / name).read_text(encoding="utf-8")
    if name.endswith(".py"):
        return (ast.get_docstring(ast.parse(text)) or "").splitlines()[0]
    if name.endswith(".md"):
        return text.splitlines()[0].lstrip("# ") + "."
    for line in text.splitlines():
        if "Jason Stys:" in line:
            return line.lstrip("#!/- ")
    raise ValueError("Tracked-file purpose missing: " + name)


def main() -> None:
    """Generate/check an exact full tracked-file table after staging only reviewed nonprivate files."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    names = (
        subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT)
        .decode()
        .rstrip("\0")
        .split("\0")
    )
    if names == [""]:
        raise ValueError("Stage reviewed files first")
    rows = ["| File | Purpose |", "| --- | --- |"]
    for name in sorted(names):
        rows.append(f"| [{name}]({name}) | {purpose(name).replace('|', '/')} |")
    path = ROOT / "README.md"
    original = path.read_text(encoding="utf-8")
    start, end = original.index(BEGIN) + len(BEGIN), original.index(END)
    expected = original[:start] + "\n\n" + "\n".join(rows) + "\n\n" + original[end:]
    if args.check and expected != original:
        raise ValueError("README file guide stale")
    if not args.check:
        path.write_text(expected, encoding="utf-8", newline="\n")
    print(f"README complete inventory: {len(names)}")


if __name__ == "__main__":
    main()
