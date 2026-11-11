"""Actual frozen Tk widgets, Rust decoder, SQLite paging and persisted export acceptance. Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: capture — line 116
# parameter: target — line 116
# parameter: window — line 116
# variable: load — line 122
# variable: gdi — line 123
# variable: user — line 123
# variable: pointer — line 124
# variable: arguments — line 125
# variable: library — line 125
# variable: name — line 125
# variable: result — line 125
# variable: function — line 151
# attribute: argtypes — line 152
# attribute: restype — line 152
# variable: handle — line 155
# variable: rectangle — line 156
# variable: height — line 159
# variable: width — line 159
# variable: source — line 162
# variable: destination — line 163
# variable: bitmap — line 164
# variable: previous — line 165
# variable: pixels — line 170
# variable: header — line 171
# variable: raw — line 189
# variable: scanlines — line 190
# variable: row — line 191
# variable: column — line 193
# variable: offset — line 194
# definition: chunk — line 197
# parameter: data — line 197
# parameter: name — line 197
# definition: oracle — line 219
# parameter: files — line 219
# parameter: index — line 219
# variable: page — line 221
# variable: report — line 221
# variable: expected — line 222
# variable: row — line 233
# variable: row — line 238
# definition: exercise — line 243
# parameter: output — line 243
# parameter: reopen — line 243
# parameter: window — line 243
# variable: expected — line 248
# variable: started — line 248
# variable: deadline — line 249
# variable: receipt — line 250
# definition: progress — line 271
# parameter: stage — line 271
# definition: finish — line 278
# parameter: failed — line 278
# attribute: acceptance_result — line 280
# variable: name — line 286
# variable: raw — line 286
# variable: row — line 288
# definition: callback_failed — line 293
# parameter: _traceback — line 294
# parameter: _value — line 294
# parameter: kind — line 294
# attribute: report_callback_exception — line 300
# definition: checked — line 302
# parameter: callback — line 302
# definition: wait — line 310
# parameter: callback — line 310
# definition: layout — line 320
# variable: widgets — line 325
# variable: name — line 326
# variable: widget — line 328
# definition: rejected — line 347
# definition: runtime_notices — line 356
# variable: dialogs — line 360
# variable: child — line 362
# variable: close — line 366
# variable: pending — line 366
# variable: texts — line 366
# variable: widget — line 368
# variable: close — line 376
# definition: completed — line 390
# parameter: index — line 390
# variable: files — line 397
# variable: parent — line 419
# variable: path — line 427
# variable: bad — line 429
# definition: start — line 440
# parameter: index — line 440
# variable: external — line 454
# definition: begin — line 468
# variable: index — line 473
# END CODE MAP

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import struct
import sys
import time
import tkinter as tk
import zlib
from pathlib import Path
from tkinter import ttk
from typing import TYPE_CHECKING, Any

from ndal import desktop_project as project
from ndal.desktop_io import json_value

if TYPE_CHECKING:
    from ndal.desktop import Workbench


def capture(window: Workbench, target: Path) -> None:
    """Capture only this owned synthetic Tk window via PrintWindow, never the user's whole desktop."""
    if sys.platform != "win32":
        raise OSError("native screenshot acceptance targets Windows")
    from ctypes import wintypes

    load = ctypes.WinDLL
    user, gdi = load("user32", use_last_error=True), load("gdi32", use_last_error=True)
    pointer = ctypes.c_void_p
    for library, name, arguments, result in [
        (user, "GetAncestor", [pointer, ctypes.c_uint], pointer),
        (user, "GetWindowDC", [pointer], pointer),
        (gdi, "CreateCompatibleDC", [pointer], pointer),
        (gdi, "CreateCompatibleBitmap", [pointer, ctypes.c_int, ctypes.c_int], pointer),
        (gdi, "SelectObject", [pointer, pointer], pointer),
        (gdi, "DeleteObject", [pointer], ctypes.c_int),
        (gdi, "DeleteDC", [pointer], ctypes.c_int),
        (user, "ReleaseDC", [pointer, pointer], ctypes.c_int),
        (user, "PrintWindow", [pointer, pointer, ctypes.c_uint], ctypes.c_int),
        (user, "GetWindowRect", [pointer, ctypes.POINTER(wintypes.RECT)], ctypes.c_int),
        (
            gdi,
            "GetDIBits",
            [
                pointer,
                pointer,
                ctypes.c_uint,
                ctypes.c_uint,
                pointer,
                pointer,
                ctypes.c_uint,
            ],
            ctypes.c_int,
        ),
    ]:
        function = getattr(library, name)
        function.argtypes, function.restype = arguments, result
    # Flush this owned native window's pending control messages before reading its pixels.
    window.root.update()
    handle = user.GetAncestor(window.root.winfo_id(), 2)
    rectangle = wintypes.RECT()
    if not user.GetWindowRect(handle, ctypes.byref(rectangle)):
        raise OSError("owned window bounds unavailable")
    width, height = rectangle.right - rectangle.left, rectangle.bottom - rectangle.top
    if not 1 <= width <= 4096 or not 1 <= height <= 4096:
        raise OSError("owned screenshot outside bounded dimensions")
    source = user.GetWindowDC(handle)
    destination = gdi.CreateCompatibleDC(source)
    bitmap = gdi.CreateCompatibleBitmap(source, width, height)
    previous = gdi.SelectObject(destination, bitmap)
    try:
        if not user.PrintWindow(handle, destination, 2):
            raise OSError("owned window rendering unavailable")
        gdi.SelectObject(destination, previous)
        pixels = ctypes.create_string_buffer(width * height * 4)
        header = ctypes.create_string_buffer(
            struct.pack(
                "<IiiHHIIiiII",
                40,
                width,
                -height,
                1,
                32,
                0,
                width * height * 4,
                0,
                0,
                0,
                0,
            )
        )
        if gdi.GetDIBits(source, bitmap, 0, height, pixels, header, 0) != height:
            raise OSError("owned screenshot pixels incomplete")
        raw = pixels.raw
        scanlines = bytearray()
        for row in range(height):
            scanlines.append(0)
            for column in range(width):
                offset = (row * width + column) * 4
                scanlines.extend((raw[offset + 2], raw[offset + 1], raw[offset]))

        def chunk(name: bytes, data: bytes) -> bytes:
            """Encode a bounded standard PNG chunk with its actual CRC."""
            return (
                struct.pack(">I", len(data))
                + name
                + data
                + struct.pack(">I", zlib.crc32(name + data))
            )

        target.write_bytes(
            b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(bytes(scanlines)))
            + chunk(b"IEND", b"")
        )
    finally:
        gdi.SelectObject(destination, previous)
        gdi.DeleteObject(bitmap)
        gdi.DeleteDC(destination)
        user.ReleaseDC(handle, source)


def oracle(index: int, files: dict[str, bytes]) -> None:
    """Check absolute real Rust/Python/SQLite outcomes without stored golden results."""
    report, page = json_value(files["report.json"]), json_value(files["query.json"])
    expected = [
        (20, {"dns_nxdomain_burst", "tcp_periodicity"}, 0),
        (3, set(), 0),
        (30, set(), 0),
        (10, {"tcp_port_fanout"}, 0),
        (0, {"capture_quality"}, 3),
        (10, set(), 0),
        (20, {"dns_nxdomain_burst", "tcp_periodicity"}, 0),
        (10, {"tcp_periodicity"}, 0),
    ][index]
    assert len(report["events"]) == expected[0]
    assert {row["rule"] for row in report["findings"]} == expected[1]
    assert len(report["issues"]) == expected[2]
    assert page["capture_issues_unfiltered"] == report["issues"]
    if index == 6:
        assert len(page["events"]) == 2 and page["total_matches"] == 20
        assert {row["identifier"] for row in page["events"]} == {"packet-2", "packet-3"}
    if index == 7:
        assert page["total_matches"] == 10 and len(page["events"]) == 2


def exercise(window: Workbench, output: Path, reopen: bool) -> None:
    """Drive the real widgets/worker/mainloop for eight complete workflows and restart, with no live traffic."""
    from unittest.mock import patch

    output.mkdir(mode=0o700)
    started, expected = time.monotonic(), 8
    deadline = started + 55
    receipt: dict[str, Any] = {
        "schema": 1,
        "product": project.PRODUCT,
        "version": project.VERSION,
        "source": window.identity.get("source"),
        "source_dirty": window.identity.get("source_dirty"),
        "python_version": sys.version.split()[0],
        "python_dll_sha256": window.identity.get("python_dll_sha256"),
        "decoder_sha256": hashlib.sha256(
            (project.ROOT / "native/packet-decoder.exe").read_bytes()
        ).hexdigest(),
        "pid": os.getpid(),
        "parent_pid": os.getppid(),
        "synthetic": True,
        "reopen": reopen,
        "passed": False,
        "steps": [],
        "tcl_version": str(window.root.tk.call("info", "patchlevel")),
        "tk_version": str(window.root.tk.call("package", "require", "Tk")),
    }

    def progress(stage: str) -> None:
        """Save bounded value-free stage evidence before real operations."""
        receipt["last_stage"] = stage
        (output / "acceptance.json").write_text(
            json.dumps(receipt, indent=2) + "\n", encoding="utf-8"
        )

    def finish(failed: bool = False) -> None:
        """Retain actual bundle hashes and request normal owned shutdown without killing a process."""
        window.acceptance_result = not failed
        receipt["passed"] = not failed
        receipt["journey_elapsed_ms"] = round((time.monotonic() - started) * 1000, 3)
        receipt["bundles"] = {
            str(row["id"]): {
                name: hashlib.sha256(raw).hexdigest()
                for name, raw in window.state.files(row["id"]).items()
            }
            for row in window.state.history()
        }
        progress("failed" if failed else "normal-exit-requested")
        window.exit()

    def callback_failed(
        kind: type[BaseException], _value: BaseException, _traceback: Any
    ) -> None:
        """Treat hidden windowed-Tk callback exceptions as actual failed acceptance."""
        receipt.update(failure_stage="tk-callback", failure_type=kind.__name__[:60])
        finish(True)

    window.root.report_callback_exception = callback_failed

    def checked(callback: Any) -> None:
        """Fail once with only an authored stage name, never private exception contents."""
        try:
            callback()
        except Exception:
            receipt["failure_stage"] = callback.__name__
            finish(True)

    def wait(callback: Any) -> None:
        """Poll the actual owned worker under a fixed deadline, with no retries or fabricated outcomes."""
        if time.monotonic() > deadline:
            receipt["failure_stage"] = "owned-operation-deadline"
            finish(True)
        elif window.busy:
            window.root.after(50, lambda: wait(callback))
        else:
            checked(callback)

    def layout() -> None:
        """Verify active inputs and normal exit remain within the supported minimum native viewport."""
        window.root.geometry("980x700")
        window.tabs.tk.call(str(window.tabs), "select", str(window.inputs_page))
        window.root.update()
        widgets: list[ttk.Widget] = [window.run_button, *window.footer_buttons.values()]
        for name in project.ACTIVE_FIELDS[window.mode.get()]:
            widgets.extend(window.field_widgets[name])
        for widget in widgets:
            assert widget.winfo_ismapped()
            assert widget.winfo_rootx() >= window.root.winfo_rootx()
            assert widget.winfo_rooty() >= window.root.winfo_rooty()
            assert (
                widget.winfo_rootx() + widget.winfo_width()
                <= window.root.winfo_rootx() + window.root.winfo_width()
            )
            assert (
                widget.winfo_rooty() + widget.winfo_height()
                <= window.root.winfo_rooty() + window.root.winfo_height()
            )
        receipt["minimum_layout"] = {
            "width": 980,
            "height": 700,
            "activeInputsRunAndLifecycleVisible": True,
        }
        window.root.geometry("1260x860")

    def rejected() -> None:
        """Malformed real input leaves all eight previous complete bundles intact."""
        assert (
            len(window.state.history()) == expected
            and "rejected" in window.status.get().lower()
        )
        receipt["steps"].append("actual-invalid-capture-retains-eight-bundles")
        finish()

    def runtime_notices() -> None:
        """Open the actual bundled license dialog, inspect its readable text and close through its own button."""
        window.footer_buttons["Licenses"].invoke()
        window.root.update()
        dialogs = [
            child
            for child in window.root.winfo_children()
            if child.winfo_class() == "Toplevel"
        ]
        assert len(dialogs) == 1
        pending, texts, close = [dialogs[0]], [], None
        while pending:
            widget = pending.pop()
            pending.extend(widget.winfo_children())
            if isinstance(widget, tk.Text):
                texts.append(widget.get("1.0", "end"))
            if (
                isinstance(widget, ttk.Button)
                and widget.cget("text") == "Close licenses"
            ):
                close = widget
        assert len(texts) == 1 and "Python runtime" in texts[0]
        assert "Copyright notices for The Rust Standard Library" in texts[0]
        assert (
            "Tcl " + receipt["tcl_version"] in texts[0]
            and "Tk " + receipt["tk_version"] in texts[0]
        )
        assert (
            "pyinstaller license and applicable exception" in texts[0]
            and close is not None
        )
        close.invoke()
        receipt["steps"].append("actual-readable-runtime-license-window")

    def completed(index: int) -> None:
        """Inspect original results and exact export through the actual rendered controls."""
        progress("workflow-" + str(index) + "-check")
        assert (
            len(window.state.history()) == index + 1
            and window.selected_run == index + 1
        )
        files = window.state.files(index + 1)
        oracle(index, files)
        if index in (0, 4):
            if index == 4:
                window.view.set("Capture quality issues (unfiltered)")
                window.render()
            window.table.selection_set("0")
            window.inspect()
            window.root.update()
            assert json.loads(window.details.get("1.0", "end"))
            capture(
                window,
                output
                / (
                    "selected-evidence.png"
                    if index == 0
                    else "owner-unknown-review.png"
                ),
            )
        receipt["steps"].append("actual-workflow-" + str(index + 1))
        if index == expected - 1:
            runtime_notices()
            parent = output / "exact-export"
            parent.mkdir()
            with patch(
                "ndal.desktop.filedialog.askdirectory", return_value=str(parent)
            ):
                window.export_button.invoke()
            assert {
                path.name: path.read_bytes()
                for path in next(parent.iterdir()).iterdir()
            } == files
            bad = output / "bad.pcap"
            bad.write_bytes(b"not a supported capture")
            window.prepared.set(project.SCENARIOS[0])
            window.load_prepared()
            window.values["capture"].set(str(bad))
            window.authorized.set(True)
            window.run_button.invoke()
            wait(rejected)
        else:
            start(index + 1)

    def start(index: int) -> None:
        """Ordinary prepared/custom-file/paging widgets feed the original engines, not acceptance-only result paths."""
        progress("workflow-" + str(index) + "-prepare")
        if index == 6:
            window.history_table.selection_set("1")
            window.open_button.invoke()
            window.page_button.invoke()
            assert window.mode.get() == project.MODES[1] and not window.authorized.get()
        else:
            window.prepared.set(project.SCENARIOS[index if index < 6 else 0])
            window.load_prepared()
            if index == 7:
                from ndal.synthetic import log_sample

                external = output / "authorized-connections.jsonl"
                external.write_bytes(log_sample())
                window.values["capture"].set("")
                with patch(
                    "ndal.desktop.filedialog.askopenfilename",
                    return_value=str(external),
                ):
                    window.choose("logs", "file")
                window.values["rule"].set("tcp_periodicity")
        layout()
        window.authorized.set(True)
        window.run_button.invoke()
        wait(lambda: completed(index))

    def begin() -> None:
        """Reopen exact saved bundles in a second actual process without recomputing their detector results."""
        progress("acceptance-entered")
        if reopen:
            assert len(window.state.history()) == expected
            for index in range(expected):
                oracle(index, window.state.files(index + 1))
            window.history_table.selection_set("1")
            window.open_button.invoke()
            assert "without re-running" in window.status.get()
            receipt["steps"].append("actual-second-process-eight-exact-bundles")
            finish()
        else:
            assert window.state.history() == []
            window.run_button.invoke()
            assert not window.busy and not window.state.history()
            start(0)

    checked(begin)
