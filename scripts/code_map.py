"""Jason Stys: generate exact definition/variable line maps and verify Python function/class contracts."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 53
# definition: mapped — line 56
# parameter: source — line 56
# parameter: suffix — line 56
# variable: prefix — line 58
# variable: begin — line 59
# variable: end — line 59
# variable: source — line 60
# variable: lines — line 66
# variable: records — line 67
# variable: tree — line 69
# variable: first — line 70
# variable: insertion — line 71
# variable: node — line 78
# variable: insertion — line 90
# variable: insertion — line 92
# variable: line — line 93
# variable: number — line 93
# variable: name — line 96
# variable: name — line 98
# variable: name — line 100
# variable: name — line 102
# variable: kind — line 105
# variable: name — line 105
# variable: name — line 109
# variable: binding — line 113
# variable: name — line 114
# variable: binding — line 117
# variable: name — line 118
# variable: count — line 120
# variable: header — line 121
# variable: kind — line 125
# variable: name — line 125
# variable: number — line 125
# parameter: item — line 126
# definition: main — line 135
# variable: parser — line 137
# variable: args — line 139
# variable: paths — line 140
# variable: stale — line 148
# variable: path — line 149
# variable: original — line 150
# variable: expected — line 151
# END CODE MAP

import argparse
import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def mapped(source: str, suffix: str) -> str:
    """Parse Python AST or lexical Rust/SQL/workflow declarations without executing authored source."""
    prefix = "--" if suffix == ".sql" else "//" if suffix in {".rs"} else "#"
    begin, end = prefix + " BEGIN CODE MAP", prefix + " END CODE MAP"
    source = re.sub(
        r"^" + re.escape(begin) + r"[^\n]*\n.*?^" + re.escape(end) + r"\n",
        "",
        source,
        flags=re.M | re.S,
    )
    lines = source.splitlines(keepends=True)
    records = set()
    if suffix == ".py":
        tree = ast.parse(source)
        first = tree.body[0] if tree.body else None
        insertion = (
            first.end_lineno
            if isinstance(first, ast.Expr)
            and isinstance(first.value, ast.Constant)
            and isinstance(first.value.value, str)
            else 0
        )
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if not ast.get_docstring(node):
                    raise ValueError(f"Missing function/class description: {node.name}")
                records.add(("definition", node.name, node.lineno))
            elif isinstance(node, ast.arg):
                records.add(("parameter", node.arg, node.lineno))
            elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                records.add(("variable", node.id, node.lineno))
            elif isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Store):
                records.add(("attribute", node.attr, node.lineno))
    else:
        insertion = 1 if source.startswith(("#!", "<?php", "/**", "//")) else 0
        while insertion < len(lines) and lines[insertion].startswith(prefix):
            insertion += 1
        for number, line in enumerate(lines, 1):
            if line.lstrip().startswith(prefix):
                continue
            for name in re.findall(r"^\s*(?:- )?([\w-]+):", line):
                records.add(("parameter", name, number))
            for name in re.findall(r"CREATE (?:TABLE|TRIGGER|INDEX) (\w+)", line):
                records.add(("SQL object", name, number))
            for name in re.findall(r"\b(\w+) (?:INTEGER|TEXT|BLOB)\b", line):
                records.add(("column", name, number))
            for name in re.findall(r"\$([A-Za-z_][A-Za-z0-9_]*)", line):
                records.add(("variable", name, number))
            if suffix == ".rs":
                for kind, name in re.findall(
                    r"\b(fn|struct|enum|const|mod)\s+([A-Za-z_]\w*)", line
                ):
                    records.add((kind, name, number))
                for name in re.findall(
                    r"(?:pub\s+)?([a-z_]\w*)\s*:\s*(?:&|[A-Za-z_])", line
                ):
                    records.add(("field/parameter", name, number))
                for binding in re.findall(r"\blet\s+(?:mut\s+)?([^=;]+)", line):
                    for name in re.findall(r"\b[a-z_]\w*\b", binding.split(":")[0]):
                        if name != "mut":
                            records.add(("binding", name, number))
                for binding in re.findall(r"\bfor\s+(.+?)\s+in\b", line):
                    for name in re.findall(r"\b[a-z_]\w*\b", binding):
                        records.add(("loop binding", name, number))
    count = len(records) + 2
    header = [
        begin + " (generated; python scripts/code_map.py)",
        *[
            f"{prefix} {kind}: {name} — line {number + count if number > insertion else number}"
            for kind, name, number in sorted(
                records, key=lambda item: (item[2], item[0], item[1])
            )
        ],
        end,
    ]
    lines.insert(insertion, "\n".join(header) + "\n")
    return "".join(lines)


def main() -> int:
    """Generate/check all authored Python and operational declarative files; stale headers fail CI."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    paths = [
        *(ROOT / "ndal").glob("*.py"),
        *(ROOT / "scripts").glob("*.py"),
        *(ROOT / "tests").glob("*.py"),
        *(ROOT / "native").glob("*.rs"),
        *(ROOT / "sql").glob("*.sql"),
        *(ROOT / ".github/workflows").glob("*.yml"),
    ]
    stale = []
    for path in paths:
        original = path.read_text(encoding="utf-8")
        expected = mapped(original, path.suffix)
        if original != expected:
            stale.append(str(path.relative_to(ROOT)))
            if not args.check:
                path.write_text(expected, encoding="utf-8", newline="\n")
    print("Code maps current" if not stale else "Code maps: " + ", ".join(stale))
    return int(args.check and bool(stale))


if __name__ == "__main__":
    raise SystemExit(main())
