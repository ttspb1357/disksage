"""The only code in DiskSage that removes anything.

Every action re-checks the path against the safety rules right before acting,
even though the path came from DiskSage's own scan.
"""

import os
import re
import shutil
import stat
import sys
import time

from send2trash import send2trash

from . import llm, winapi
from .fsutil import MB, dir_stats, human, is_link_dir, is_link_path


class Refused(Exception):
    pass


def recycle_problem(path, size):
    """Why this can't safely go to the Recycle Bin (Windows would delete it for good), or None."""
    enabled, limit = winapi.recycle_bin_limit(path)
    if not enabled:
        return ("Your Recycle Bin is switched off for this drive, so Windows would delete this permanently. "
                "DiskSage won't — switch the Recycle Bin back on in its Properties, or delete it yourself if you're sure.")
    if limit is None:  # no setting recorded yet: assume Windows' default of about 5% of the drive
        try:
            limit = shutil.disk_usage(os.path.splitdrive(os.path.abspath(path))[0] + "\\").total // 20
        except OSError:
            return None
    if size > limit:
        return (f"It's bigger ({human(size)}) than your Recycle Bin can hold ({human(limit)}), so Windows would "
                "delete it permanently. DiskSage won't — delete it yourself (Shift+Delete) if you're sure.")
    return None


class Report:
    def __init__(self, paths):
        self.paths = paths
        self.freed = 0        # permanently gone
        self.recycled = 0     # in the Recycle Bin (frees space once it's emptied)
        self.done = 0
        self.in_use = 0       # files skipped because a program had them open
        self.failed = []

    def fail(self, item, message):
        self.failed.append({"path": self.paths.display(item.path), "error": message})

    def to_dict(self):
        return {
            "freed": self.freed, "recycled": self.recycled, "done": self.done,
            "in_use": self.in_use, "failed": self.failed[:20], "failed_count": len(self.failed),
        }


def _check(path, paths, allow_exact=False):
    if not os.path.lexists(path):
        raise Refused("It's already gone.")
    if is_link_path(path):
        raise Refused("Refused: it's a link to another location.")
    reason = paths.protected_reason(path, allow_exact=allow_exact)
    if reason:
        raise Refused(f"Refused: it's {reason}.")


def _remove(path):
    """Delete a file or folder permanently. Returns how many entries couldn't be removed."""
    failures = []

    def onexc(func, target, exc):
        if isinstance(exc, PermissionError):
            try:  # read-only files (common in caches and git objects)
                os.chmod(target, stat.S_IWRITE)
                func(target)
                return
            except OSError:
                pass
        if not isinstance(exc, FileNotFoundError):
            failures.append(target)

    if os.path.isdir(path) and not is_link_path(path):
        if sys.version_info >= (3, 12):
            shutil.rmtree(path, onexc=onexc)
        else:
            shutil.rmtree(path, onerror=lambda func, target, info: onexc(func, target, info[1]))
    else:
        try:
            os.remove(path)
        except FileNotFoundError:
            pass
        except PermissionError as exc:
            onexc(os.remove, path, exc)
        except OSError:
            failures.append(path)
    return len(failures)


def _size_of(path):
    if not os.path.lexists(path):
        return 0
    if os.path.isdir(path):
        return dir_stats(path)[0]
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def _delete_contents(item, paths, report):
    """Empty a cache folder but keep the folder itself."""
    root = item.path
    _check(root, paths, allow_exact=True)
    older_than = item.meta.get("older_than")
    cutoff = time.time() - older_than if older_than else None
    freed = remaining = 0
    with os.scandir(root) as it:
        entries = list(it)
    for e in entries:
        try:
            st = e.stat(follow_symlinks=False)
            if cutoff and st.st_mtime > cutoff:
                continue
            is_dir = e.is_dir(follow_symlinks=False)
            if is_dir and is_link_dir(e):
                continue
            before = dir_stats(e.path)[0] if is_dir else st.st_size
        except OSError:
            continue
        report.in_use += _remove(e.path)
        after = _size_of(e.path)
        freed += max(before - after, 0)
        remaining += after
    report.freed += freed
    item.size = remaining
    item.removed = remaining < MB


def apply(action, item, paths, report):
    try:
        if action == "recycle":
            _check(item.path, paths)
            problem = recycle_problem(item.path, max(item.size, _size_of(item.path)))
            if problem:
                raise Refused(problem)
            send2trash(item.path)
            report.recycled += item.size
            item.removed = True
        elif action == "delete":
            _check(item.path, paths)
            report.in_use += _remove(item.path)
            left = _size_of(item.path)
            report.freed += max(item.size - left, 0)
            item.size, item.removed = left, left == 0
        elif action == "delete_contents":
            _delete_contents(item, paths, report)
        elif action == "ollama_rm":
            llm.delete_model(item.meta["model"])
            report.freed += item.size
            item.removed = True
        elif action == "empty_bin":
            size, _ = winapi.recycle_bin_info()
            if not winapi.empty_recycle_bin():
                raise Refused("Windows couldn't empty the Recycle Bin.")
            report.freed += size
            item.removed = True
        else:
            return
        report.done += 1
    except Refused as exc:
        report.fail(item, str(exc))
    except Exception as exc:  # one bad item must never stop the rest
        report.fail(item, f"{type(exc).__name__}: {exc}")


def split_command(cmd):
    """Split an UninstallString into (program, arguments)."""
    cmd = cmd.strip()
    if cmd.startswith('"'):
        end = cmd.find('"', 1)
        if end > 0:
            return cmd[1:end], cmd[end + 1:].strip()
    m = re.match(r"(.+?\.exe)\s*(.*)$", cmd, re.IGNORECASE)
    return (m.group(1), m.group(2)) if m else (cmd, "")


def run_uninstaller(app):
    """Launch the app's own uninstaller with its normal UI (never silently)."""
    program, args = split_command(app["uninstall_string"])
    if os.path.basename(program).lower() in ("msiexec.exe", "msiexec"):
        # Many MSI entries use /I (opens "modify/repair"); /X goes straight to uninstall.
        args = re.sub(r"(?i)/I\s*(\{)", r"/X\1", args)
    return winapi.shell_open(program, args or None)
