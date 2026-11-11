"""Presentation-adapter unit tests with real core/SQLite workers; real widgets are separately frozen-tested. Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: Variable — line 238
# definition: __init__ — line 241
# parameter: self — line 241
# parameter: value — line 241
# attribute: callbacks — line 243
# attribute: value — line 243
# definition: get — line 245
# parameter: self — line 245
# definition: set — line 249
# parameter: self — line 249
# parameter: value — line 249
# attribute: value — line 251
# variable: callback — line 252
# definition: trace_add — line 255
# parameter: _event — line 255
# parameter: callback — line 255
# parameter: self — line 255
# definition: Widget — line 260
# definition: __init__ — line 263
# parameter: _args — line 263
# parameter: kwargs — line 263
# parameter: self — line 263
# attribute: options — line 265
# attribute: rows — line 265
# attribute: selected — line 265
# attribute: flags — line 266
# attribute: tk — line 267
# parameter: _items — line 267
# definition: pack — line 269
# parameter: _kwargs — line 269
# parameter: self — line 269
# definition: grid — line 272
# parameter: _kwargs — line 272
# parameter: self — line 272
# definition: grid_remove — line 275
# parameter: self — line 275
# definition: columnconfigure — line 278
# parameter: _args — line 278
# parameter: _kwargs — line 278
# parameter: self — line 278
# definition: add — line 281
# parameter: _args — line 281
# parameter: _kwargs — line 281
# parameter: self — line 281
# definition: theme_use — line 284
# parameter: _args — line 284
# parameter: self — line 284
# definition: configure — line 287
# parameter: _args — line 287
# parameter: kwargs — line 287
# parameter: self — line 287
# definition: heading — line 291
# parameter: _args — line 291
# parameter: _kwargs — line 291
# parameter: self — line 291
# definition: column — line 294
# parameter: _args — line 294
# parameter: _kwargs — line 294
# parameter: self — line 294
# definition: bind — line 297
# parameter: _args — line 297
# parameter: self — line 297
# definition: yview — line 300
# parameter: _args — line 300
# parameter: self — line 300
# definition: set — line 303
# parameter: _args — line 303
# parameter: self — line 303
# definition: state — line 306
# parameter: flags — line 306
# parameter: self — line 306
# variable: flag — line 308
# definition: invoke — line 314
# parameter: self — line 314
# definition: insert — line 320
# parameter: _parent — line 320
# parameter: _position — line 320
# parameter: iid — line 320
# parameter: self — line 320
# parameter: values — line 320
# definition: delete — line 324
# parameter: items — line 324
# parameter: self — line 324
# variable: item — line 326
# attribute: selected — line 328
# variable: item — line 328
# definition: get_children — line 330
# parameter: self — line 330
# definition: selection — line 334
# parameter: self — line 334
# definition: selection_set — line 338
# parameter: identity — line 338
# parameter: self — line 338
# attribute: selected — line 341
# definition: Text — line 344
# definition: delete — line 347
# parameter: _args — line 347
# parameter: self — line 347
# attribute: text — line 349
# definition: insert — line 351
# parameter: _position — line 351
# parameter: self — line 351
# parameter: text — line 351
# attribute: text — line 353
# definition: Root — line 356
# definition: __init__ — line 359
# parameter: self — line 359
# attribute: callbacks — line 361
# attribute: destroyed — line 361
# attribute: on_loop — line 362
# definition: title — line 364
# parameter: _args — line 364
# parameter: self — line 364
# definition: geometry — line 367
# parameter: _args — line 367
# parameter: self — line 367
# definition: minsize — line 370
# parameter: _args — line 370
# parameter: self — line 370
# definition: protocol — line 373
# parameter: _event — line 373
# parameter: callback — line 373
# parameter: self — line 373
# attribute: close_callback — line 375
# definition: after — line 377
# parameter: _delay — line 377
# parameter: callback — line 377
# parameter: self — line 377
# definition: destroy — line 381
# parameter: self — line 381
# attribute: destroyed — line 383
# definition: mainloop — line 385
# parameter: self — line 385
# variable: _ — line 389
# definition: presentation — line 397
# parameter: monkeypatch — line 397
# parameter: _parent — line 402
# variable: name — line 404
# variable: messages — line 418
# parameter: _kwargs — line 420
# parameter: args — line 420
# parameter: _kwargs — line 423
# parameter: args — line 423
# definition: app — line 429
# parameter: presentation — line 429
# parameter: tmp_path — line 429
# variable: state — line 431
# variable: root — line 432
# variable: window — line 433
# definition: settle — line 443
# parameter: window — line 443
# variable: deadline — line 445
# definition: test_real_controller_run_filter_detail_history_export_and_help — line 452
# parameter: app — line 453
# parameter: monkeypatch — line 453
# parameter: presentation — line 453
# parameter: tmp_path — line 453
# parameter: _kwargs — line 479
# variable: original — line 481
# variable: exported — line 483
# variable: path — line 484
# parameter: _kwargs — line 489
# definition: test_explicit_retention_confirmation_removes_only_selected_local_copy — line 495
# parameter: app — line 496
# parameter: monkeypatch — line 496
# parameter: tmp_path — line 496
# variable: exported — line 506
# variable: original — line 507
# parameter: _args — line 508
# parameter: _kwargs — line 508
# parameter: _args — line 511
# parameter: _kwargs — line 511
# variable: path — line 514
# attribute: busy — line 515
# attribute: busy — line 518
# definition: test_input_selection_cancel_busy_failure_and_literal_row_cap — line 521
# parameter: app — line 522
# parameter: monkeypatch — line 522
# parameter: tmp_path — line 522
# variable: name — line 525
# parameter: _kwargs — line 529
# parameter: _kwargs — line 534
# parameter: _kwargs — line 537
# variable: kind — line 539
# variable: value — line 543
# parameter: _kwargs — line 544
# attribute: busy — line 547
# attribute: busy — line 553
# attribute: current — line 560
# variable: index — line 560
# definition: test_close_retains_lock_until_actual_core_transaction_finishes — line 572
# parameter: app — line 573
# parameter: monkeypatch — line 573
# parameter: tmp_path — line 573
# variable: ready — line 576
# variable: release — line 576
# variable: actual — line 577
# definition: pause — line 579
# parameter: args — line 579
# variable: reopened — line 597
# definition: test_main_native_close_and_rejected_acceptance_paths — line 604
# parameter: monkeypatch — line 605
# parameter: presentation — line 605
# parameter: tmp_path — line 605
# variable: actual — line 608
# definition: create — line 610
# parameter: root — line 610
# parameter: state — line 610
# variable: window — line 612
# attribute: on_loop — line 613
# variable: profile — line 617
# variable: reopened — line 619
# variable: unknown — line 643
# definition: test_real_next_page_control_and_changed_prepared_input_retention — line 651
# parameter: app — line 651
# variable: original — line 663
# variable: second — line 670
# variable: row — line 674
# variable: selected — line 685
# attribute: busy — line 692
# attribute: busy — line 695
# END CODE MAP

import threading
import time
from types import SimpleNamespace

import pytest

from ndal import desktop as module
from ndal import desktop_project as project
from ndal.desktop_io import Rejected
from ndal.desktop_state import Workspace


class Variable:
    """Inert presentation variable; invokes the same registered GUI trace callbacks."""

    def __init__(self, value=""):
        """Keep a scalar control value and registered change callbacks."""
        self.value, self.callbacks = value, []

    def get(self):
        """Return the current presentation control value."""
        return self.value

    def set(self, value):
        """Change a control and exercise actual application rendering callbacks."""
        self.value = value
        for callback in self.callbacks:
            callback()

    def trace_add(self, _event, callback):
        """Retain the GUI's value-change handler."""
        self.callbacks.append(callback)


class Widget:
    """Minimal inert ttk presentation adapter; no core, storage or analysis output is mocked."""

    def __init__(self, *_args, **kwargs):
        """Retain properties, rows and command closures."""
        self.options, self.rows, self.selected = kwargs, {}, ()
        self.flags = set()
        self.tk = SimpleNamespace(call=lambda *_items: None)

    def pack(self, **_kwargs):
        """Accept presentation layout."""

    def grid(self, **_kwargs):
        """Accept presentation grid coordinates."""

    def grid_remove(self):
        """Accept operation-specific hidden controls."""

    def columnconfigure(self, *_args, **_kwargs):
        """Accept resize weights."""

    def add(self, *_args, **_kwargs):
        """Accept notebook/paned-window children."""

    def theme_use(self, *_args):
        """Accept native style selection."""

    def configure(self, *_args, **kwargs):
        """Retain updated widget options."""
        self.options.update(kwargs)

    def heading(self, *_args, **_kwargs):
        """Accept a literal table heading."""

    def column(self, *_args, **_kwargs):
        """Accept table sizing."""

    def bind(self, *_args):
        """Accept event registration; tests invoke actual handlers explicitly."""

    def yview(self, *_args):
        """Accept scroll requests."""

    def set(self, *_args):
        """Accept scrollbar position updates."""

    def state(self, flags):
        """Preserve disabled controls so a simulated click cannot bypass a busy guard."""
        for flag in flags:
            if flag.startswith("!"):
                self.flags.discard(flag[1:])
            else:
                self.flags.add(flag)

    def invoke(self):
        """Invoke the actual registered command unless the control is disabled."""
        if "disabled" not in self.flags:
            return self.options["command"]()
        return None

    def insert(self, _parent, _position, *, iid, values):
        """Retain exact rows inserted by real project rendering."""
        self.rows[iid] = values

    def delete(self, *items):
        """Remove rows and their selections like a real treeview."""
        for item in items:
            self.rows.pop(item, None)
        self.selected = tuple(item for item in self.selected if item in self.rows)

    def get_children(self):
        """Return displayed row identities."""
        return tuple(self.rows)

    def selection(self):
        """Return the current selected row identity."""
        return self.selected

    def selection_set(self, identity):
        """Select one existing row like a real single-selection control."""
        assert identity in self.rows
        self.selected = (identity,)


class Text(Widget):
    """Retain literal detail output without interpreting markup or executing event fields."""

    def delete(self, *_args):
        """Clear existing literal detail text."""
        self.text = ""

    def insert(self, _position, text):
        """Retain the exact rendered detail text."""
        self.text = text


class Root:
    """Deterministic presentation event queue; actual Tk mainloops are independently exercised by frozen acceptance."""

    def __init__(self):
        """Create a fresh owned presentation root."""
        self.callbacks, self.destroyed = [], False
        self.on_loop = None

    def title(self, *_args):
        """Accept window title."""

    def geometry(self, *_args):
        """Accept initial geometry."""

    def minsize(self, *_args):
        """Accept minimum geometry."""

    def protocol(self, _event, callback):
        """Keep the application's native close callback."""
        self.close_callback = callback

    def after(self, _delay, callback):
        """Queue the actual lifecycle callback without a platform display server."""
        self.callbacks.append(callback)

    def destroy(self):
        """Mark only this owned root as closed."""
        self.destroyed = True

    def mainloop(self):
        """Run the requested test lifecycle using real application callbacks."""
        if self.on_loop:
            self.on_loop()
        for _ in range(200):
            if self.destroyed:
                return
            self.callbacks.pop(0)()
        raise AssertionError("presentation lifecycle did not close")


@pytest.fixture
def presentation(monkeypatch):
    """Replace only OS presentation surfaces; real worker, core, SQLite and export code remain active."""
    monkeypatch.setattr(module.tk, "StringVar", Variable)
    monkeypatch.setattr(module.tk, "BooleanVar", Variable)
    monkeypatch.setattr(module.tk, "Tk", Root)
    monkeypatch.setattr(module.tk, "Toplevel", lambda _parent: Root())
    monkeypatch.setattr(module.tk, "Text", Text)
    for name in (
        "Frame",
        "Label",
        "Notebook",
        "Combobox",
        "Entry",
        "Button",
        "Checkbutton",
        "Panedwindow",
        "Treeview",
        "Scrollbar",
        "Style",
    ):
        monkeypatch.setattr(module.ttk, name, Widget)
    messages = []
    monkeypatch.setattr(
        module.messagebox, "showinfo", lambda *args, **_kwargs: messages.append(args)
    )
    monkeypatch.setattr(
        module.messagebox, "showerror", lambda *args, **_kwargs: messages.append(args)
    )
    return messages


@pytest.fixture
def app(tmp_path, presentation):
    """Build the actual workbench controller against an isolated real durable workspace."""
    state = Workspace(tmp_path / "profile", project.PRODUCT, project.ROOT)
    root = Root()
    window = module.Workbench(root, state)
    try:
        yield window
    finally:
        if window.worker_thread:
            window.worker_thread.join(10)
            assert not window.worker_thread.is_alive()
        state.close()


def settle(window):
    """Observe completion of one actual owned analysis; no retries or invented report values."""
    deadline = time.monotonic() + 10
    while window.busy and time.monotonic() < deadline:
        window.poll()
        time.sleep(0.005)
    assert not window.busy


def test_real_controller_run_filter_detail_history_export_and_help(
    app, tmp_path, monkeypatch, presentation
):
    """Real core results drive controls, literal filters, exact private exports and history reopening."""
    app.export()
    assert "completed" in app.status.get()
    app.run_button.invoke()
    assert not app.busy and app.state.history() == []
    app.authorized.set(True)
    app.run_button.invoke()
    settle(app)
    assert app.selected_run == 1 and len(app.state.history()) == 1
    assert len(app.table.get_children()) > 0
    app.table.selection_set("0")
    app.inspect()
    assert "{" in app.details.text
    app.review_selected()
    if project.REVIEW_MODE is not None:
        assert app.mode.get() == project.REVIEW_MODE and app.authorized.get() is False
    app.search.set("not-a-supported-record-never-present")
    assert app.table.get_children() == ()
    app.inspect()
    app.search.set("")
    app.history_table.selection_set("1")
    app.open_button.invoke()
    assert "without re-running" in app.status.get()
    monkeypatch.setattr(
        module.filedialog, "askdirectory", lambda **_kwargs: str(tmp_path)
    )
    original = app.state.files(1)
    app.export_button.invoke()
    exported = next(tmp_path.glob(project.PRODUCT + "-run-*"))
    assert {path.name: path.read_bytes() for path in exported.iterdir()} == original
    app.help()
    assert "plaintext" in presentation[-1][1]
    app.licenses()
    monkeypatch.setattr(
        module.filedialog, "askdirectory", lambda **_kwargs: str(tmp_path / "missing")
    )
    app.export()
    assert "unavailable" in app.status.get()


def test_explicit_retention_confirmation_removes_only_selected_local_copy(
    app, tmp_path, monkeypatch
):
    """Cancellation preserves data; confirmation deletes one exact DB bundle without touching a prior export."""
    app.remove_history()
    assert "Select" in app.status.get()
    app.review_selected()
    app.authorized.set(True)
    app.run_button.invoke()
    settle(app)
    app.history_table.selection_set("1")
    exported = app.state.export(1, tmp_path, project.PRODUCT)
    original = app.state.files(1)
    monkeypatch.setattr(module.messagebox, "askyesno", lambda *_args, **_kwargs: False)
    app.remove_button.invoke()
    assert app.state.files(1) == original
    monkeypatch.setattr(module.messagebox, "askyesno", lambda *_args, **_kwargs: True)
    app.remove_button.invoke()
    assert app.state.history() == [] and app.selected_run == 0
    assert {path.name: path.read_bytes() for path in exported.iterdir()} == original
    app.busy = True
    app.remove_history()
    assert "Wait" in app.status.get()
    app.busy = False


def test_input_selection_cancel_busy_failure_and_literal_row_cap(
    app, tmp_path, monkeypatch
):
    """Operator mistakes do not silently run a prepared fixture, overwrite results or defeat close semantics."""
    name = project.FIELDS[0][0]
    monkeypatch.setattr(
        module.filedialog,
        "askopenfilename",
        lambda **_kwargs: str(tmp_path / "authorized.json"),
    )
    monkeypatch.setattr(
        module.filedialog,
        "askopenfilenames",
        lambda **_kwargs: ("one.json", "two.json"),
    )
    monkeypatch.setattr(
        module.filedialog, "askdirectory", lambda **_kwargs: str(tmp_path)
    )
    for kind in ("file", "files", "directory"):
        app.authorized.set(True)
        app.choose(name, kind)
        assert app.authorized.get() is False
    value = app.values[name].get()
    monkeypatch.setattr(module.filedialog, "askopenfilename", lambda **_kwargs: "")
    app.choose(name, "file")
    assert app.values[name].get() == value
    app.busy = True
    app.choose(name, "file")
    app.load_prepared()
    app.open_history()
    app.run()
    assert app.state.history() == []
    app.busy = False
    app.load_prepared()
    app.mode.set("unsupported-operation")
    app.authorized.set(True)
    app.run()
    settle(app)
    assert "rejected" in app.status.get().lower() and app.state.history() == []
    app.current = {"bounded": [{"event": str(index)} for index in range(5001)]}
    app.view.set("bounded")
    app.render()
    assert len(app.table.get_children()) == 5000
    app.search.set('"5000"')
    assert len(app.table.get_children()) == 1
    app.exit()
    app.run()
    app.poll()
    assert app.root.destroyed and app.state.lock == -1


def test_close_retains_lock_until_actual_core_transaction_finishes(
    app, tmp_path, monkeypatch
):
    """An in-flight real analysis is drained rather than abandoned, force-killed or exposed to a second owner."""
    ready, release = threading.Event(), threading.Event()
    actual = project.analyze

    def pause(*args):
        """Control only scheduling; completion still invokes the actual project core and durable output."""
        ready.set()
        assert release.wait(5)
        return actual(*args)

    monkeypatch.setattr(project, "analyze", pause)
    app.authorized.set(True)
    app.run_button.invoke()
    assert ready.wait(3)
    app.exit()
    app.poll()
    assert not app.root.destroyed and app.busy
    with pytest.raises((Rejected, OSError)):
        Workspace(app.state.path, project.PRODUCT, project.ROOT)
    release.set()
    settle(app)
    assert app.root.destroyed and app.state.lock == -1
    reopened = Workspace(app.state.path, project.PRODUCT, project.ROOT)
    try:
        assert len(reopened.history()) == 1
    finally:
        reopened.close()


def test_main_native_close_and_rejected_acceptance_paths(
    tmp_path, presentation, monkeypatch
):
    """Normal startup never auto-analyzes; test flags cannot enter existing real-profile state or claim partial success."""
    actual = module.Workbench

    def create(root, state):
        """Use actual controls/controller; request the normal close callback at the start of the event loop."""
        window = actual(root, state)
        root.on_loop = window.exit
        return window

    monkeypatch.setattr(module, "Workbench", create)
    profile = tmp_path / "normal"
    assert module.main(["--profile", str(profile)]) == 0
    reopened = Workspace(profile, project.PRODUCT, project.ROOT)
    assert reopened.history() == []
    reopened.close()
    with pytest.raises(SystemExit):
        module.main(["--acceptance-output", str(tmp_path / "output")])
    with pytest.raises(SystemExit):
        module.main(["--acceptance-reopen"])
    assert (
        module.main(
            ["--profile", str(profile), "--acceptance-output", str(tmp_path / "output")]
        )
        == 2
    )
    assert (
        module.main(
            [
                "--profile",
                str(tmp_path / "synthetic"),
                "--acceptance-output",
                str(tmp_path / "new-output"),
            ]
        )
        == 2
    )
    unknown = tmp_path / "unknown"
    unknown.mkdir()
    (unknown / "keep").write_bytes(b"unchanged")
    assert module.main(["--profile", str(unknown)]) == 2
    assert (unknown / "keep").read_bytes() == b"unchanged"
    assert presentation and "No saved evidence was reset" in presentation[-1][1]


def test_real_next_page_control_and_changed_prepared_input_retention(app):
    """The visible paging action preserves the complete snapshot, rejects end-of-stream and retains edited prepared files."""
    from pathlib import Path

    from ndal.desktop_io import json_value

    app.page_button.invoke()
    assert "Open a completed" in app.status.get()
    app.authorized.set(True)
    app.run_button.invoke()
    settle(app)
    assert app.selected_run == 1
    original = app.state.files(1)
    app.page_button.invoke()
    assert app.mode.get() == project.MODES[1] and not app.authorized.get()
    app.authorized.set(True)
    app.run_button.invoke()
    settle(app)
    assert app.selected_run == 2
    second = app.state.files(2)
    assert second["report.json"] == original["report.json"]
    assert [
        (row["identifier"], row["time_ns"])
        for row in json_value(second["query.json"])["events"]
    ] == [("packet-2", 1000000000), ("packet-3", 2000000000)]
    app.values["limit"].set("1000")
    app.values["cursor"].set("")
    app.authorized.set(True)
    app.run_button.invoke()
    settle(app)
    app.page_button.invoke()
    assert "no valid next" in app.status.get()
    app.prepared.set(project.SCENARIOS[1])
    app.load_prepared()
    selected = Path(app.values["capture"].get())
    selected.write_bytes(b"operator retained data")
    app.load_prepared()
    assert (
        "edited" in app.status.get()
        and selected.read_bytes() == b"operator retained data"
    )
    app.busy = True
    app.next_page()
    assert "Open a completed" in app.status.get()
    app.busy = False
