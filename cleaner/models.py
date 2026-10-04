"""The two data types the whole app passes around."""

from dataclasses import dataclass, field

from .fsutil import DAY

VERDICT_ORDER = {"safe": 0, "review": 1, "keep": 2}
CLEANABLE_ACTIONS = {"recycle", "delete", "delete_contents", "ollama_rm", "empty_bin"}
MAX_ITEMS_SENT = 500


@dataclass
class Item:
    """One concrete thing on disk (or an Ollama model) that a finding could act on."""

    path: str
    size: int
    mtime: float = 0.0
    note: str = ""
    ai_note: str = ""
    removed: bool = False
    meta: dict = field(default_factory=dict)


@dataclass
class Finding:
    """A group of items with one explanation, one verdict and one cleanup action."""

    id: str
    category: str
    kind: str
    title: str
    detail: str
    verdict: str  # the scanner's own verdict
    action: str
    items: list
    needs_item_notes: bool = False
    ai_verdict: str = ""
    ai_reason: str = ""

    @property
    def size(self):
        return sum(i.size for i in self.items if not i.removed)

    @property
    def final_verdict(self):
        # The model may make a verdict more cautious, never less.
        v = self.verdict
        if VERDICT_ORDER.get(self.ai_verdict, -1) > VERDICT_ORDER[v]:
            v = self.ai_verdict
        return v

    def to_dict(self, paths, now):
        live = [i for i in self.items if not i.removed]
        return {
            "id": self.id,
            "category": self.category,
            "kind": self.kind,
            "title": self.title,
            "detail": self.detail,
            "verdict": self.final_verdict,
            "scanner_verdict": self.verdict,
            "ai_verdict": self.ai_verdict,
            "ai_reason": self.ai_reason,
            "action": self.action,
            "size": self.size,
            "count": len(live),
            "total_items": len(self.items),
            "items": [
                {
                    "index": idx,
                    "path": paths.display(i.path),
                    "size": i.size,
                    "age_days": int((now - i.mtime) // DAY) if i.mtime else None,
                    "note": i.note,
                    "ai_note": i.ai_note,
                    "removed": i.removed,
                }
                for idx, i in enumerate(self.items[:MAX_ITEMS_SENT])
            ],
        }
