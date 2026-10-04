"""Runs the detectors in a background thread, then asks the local model to review them."""

import threading
import time
import traceback

from . import actions, detectors, installed, llm
from .fsutil import human
from .models import CLEANABLE_ACTIONS, VERDICT_ORDER

STEPS = [
    ("Reading your installed apps", None),
    ("Walking through your folders", detectors.deep_walk),
    ("Measuring unpacked installers", detectors.scan_installer_folders),
    ("Checking your Downloads folder", detectors.scan_downloads),
    ("Looking for duplicate files", detectors.scan_duplicates),
    ("Measuring temporary files", detectors.scan_temp),
    ("Measuring browser and app caches", detectors.scan_caches),
    ("Measuring developer tool caches", detectors.scan_dev_caches),
    ("Sizing up old project dependencies", detectors.scan_projects),
    ("Checking AI model downloads", detectors.scan_ai_models),
    ("Checking driver and Windows leftovers", detectors.scan_system),
    ("Looking for app data nothing claims", detectors.scan_unrecognized_appdata),
    ("Listing your biggest files", detectors.scan_large_files),
    ("Checking the Recycle Bin", detectors.scan_recycle_bin),
]


class ScanJob:
    def __init__(self, paths, drives_fn):
        self.paths = paths
        self.drives_fn = drives_fn
        self.lock = threading.RLock()
        self._reset()

    def _reset(self):
        self.phase = "idle"  # idle → scanning → analyzing → done
        self.step = ""
        self.step_index = 0
        self.findings = []
        self.by_id = {}
        self.errors = []
        self.notes = []
        self.ai = {"status": "idle", "summary": "", "top_tip": "", "error": "", "seconds": None}
        self.started = None
        self.scan_seconds = None
        self.walk_complete = True
        self.version = 0

    def start(self):
        with self.lock:
            if self.phase in ("scanning", "analyzing"):
                return
            self._reset()
            self.phase = "scanning"
            self.started = time.time()
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        try:
            apps = installed.installed_apps()
        except Exception as exc:
            apps = []
            self.errors.append(f"Reading installed apps: {exc}")
        ctx = detectors.Context(self.paths, apps, llm.list_models() or [], llm.MODEL)

        for i, (label, fn) in enumerate(STEPS):
            self.step, self.step_index = label, i
            if fn is None:
                continue
            try:
                fn(ctx)
            except Exception as exc:  # one broken detector shouldn't sink the scan
                traceback.print_exc()
                self.errors.append(f"{label}: {exc}")

        findings = sorted(ctx.findings, key=lambda f: (VERDICT_ORDER[f.verdict], -f.size))
        with self.lock:
            self.findings = findings
            self.by_id = {f.id: f for f in findings}
            self.walk_complete = ctx.walk["complete"]
            self.notes = ctx.notes
            self.scan_seconds = round(time.time() - self.started, 1)
            self.phase = "analyzing" if findings else "done"
            self.ai["status"] = "running" if findings else "idle"
            self.version += 1
        if not findings:
            return

        # Unrecognised AppData folders get their own, more focused model call.
        mystery = [f for f in findings if f.kind == "unrecognized"]
        regular = [f for f in findings if f.kind != "unrecognized"]
        t0 = time.time()
        try:
            result = llm.analyze(regular, self.paths, self.drives_fn()) if regular else {}
            ai = {"status": "done", **result, "seconds": round(time.time() - t0, 1)}
        except llm.LLMError as exc:
            ai = {"status": "error", "error": str(exc)}
        except Exception as exc:
            traceback.print_exc()
            ai = {"status": "error", "error": f"Unexpected error: {exc}"}
        with self.lock:
            self.ai.update(ai)
            self.ai["identify"] = "running" if mystery and ai["status"] == "done" else ""
            self.version += 1

        if self.ai["identify"]:
            try:
                llm.identify_folders(mystery[0], self.paths)
                status = "done"
            except Exception as exc:  # the main review already succeeded; don't throw it away
                traceback.print_exc()
                status = "error"
            with self.lock:
                self.ai["identify"] = status
                self.version += 1

        with self.lock:
            self.phase = "done"
            self.version += 1

    def snapshot(self, since=None):
        with self.lock:
            unchanged = since is not None and since == self.version
            now = time.time()
            data = [f.to_dict(self.paths, now) for f in self.findings]
            totals = {v: 0 for v in VERDICT_ORDER}
            for f in data:
                totals[f["verdict"]] += f["cleanable_size"]
            return {
                "phase": self.phase,
                "step": self.step,
                "step_index": self.step_index,
                "steps": [label for label, _ in STEPS],
                "version": self.version,
                "findings": None if unchanged else data,
                "totals": totals,
                "ai": dict(self.ai),
                "errors": self.errors[-10:],
                "notes": self.notes,
                "scan_seconds": self.scan_seconds,
                "walk_complete": self.walk_complete,
            }

    def clean(self, selections):
        report = actions.Report(self.paths)
        with self.lock:
            for sel in selections:
                f = self.by_id.get(str(sel.get("finding_id")))
                if not f or f.action not in CLEANABLE_ACTIONS:
                    continue
                for idx in sel.get("items") or []:
                    if isinstance(idx, int) and 0 <= idx < len(f.items) and not f.items[idx].removed:
                        actions.apply(f.action, f.items[idx], self.paths, report)
            self.version += 1
        return report.to_dict()

    def context_text(self, drives, apps):
        """A compact description of this PC for the Ask tab."""
        lines = [
            f"Drive {d['name']} {human(d['used'])} used of {human(d['total'])}, {human(d['free'])} free"
            for d in drives
        ]
        with self.lock:
            if self.findings:
                lines.append("Latest scan findings (biggest first):")
                for f in sorted(self.findings, key=lambda f: -f.size)[:20]:
                    if f.size:
                        lines.append(f"- {f.title}: {human(f.size)}, {len(f.items)} items, verdict {f.final_verdict}")
                if self.ai.get("summary"):
                    lines.append(f"Scan summary: {self.ai['summary']}")
            else:
                lines.append("No scan has been run yet.")
        if apps:
            biggest = sorted((a for a in apps if a["size"]), key=lambda a: -a["size"])[:20]
            lines.append(f"{len(apps)} apps installed. Largest: " + ", ".join(f"{a['name']} ({human(a['size'])})" for a in biggest))
        return "\n".join(lines)
