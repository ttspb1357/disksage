"""Small filesystem helpers. Nothing here follows links or deletes anything."""

import os
import time
from concurrent.futures import ThreadPoolExecutor

KB = 1024
MB = 1024 * KB
GB = 1024 * MB
DAY = 86400

FILE_ATTRIBUTE_REPARSE_POINT = 0x400
# OneDrive "online-only" placeholders look like files but take no disk space,
# and reading one would trigger a download — so DiskSage skips them.
CLOUD_ONLY_ATTRS = 0x1000 | 0x40000 | 0x400000
NAME_SURROGATE_BIT = 0x20000000  # set on symlinks and junctions


class Budget:
    """A time limit, so one enormous folder can't stall the whole scan."""

    def __init__(self, seconds):
        self.end = time.monotonic() + seconds

    @property
    def expired(self):
        return time.monotonic() > self.end


def _is_link_stat(st):
    if not getattr(st, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT:
        return False
    tag = getattr(st, "st_reparse_tag", 0)
    return tag == 0 or bool(tag & NAME_SURROGATE_BIT)


def is_link_dir(entry):
    """True for symlinks and junctions — following them risks loops or leaving the folder."""
    try:
        return entry.is_symlink() or _is_link_stat(entry.stat(follow_symlinks=False))
    except OSError:
        return True


def is_link_path(path):
    try:
        return os.path.islink(path) or _is_link_stat(os.lstat(path))
    except OSError:
        return False


def subdirs(root):
    """Real (non-link) subfolders of root as DirEntry objects."""
    try:
        with os.scandir(root) as it:
            return [e for e in it if e.is_dir(follow_symlinks=False) and not is_link_dir(e)]
    except OSError:
        return []


def is_cloud_only(st):
    return bool(getattr(st, "st_file_attributes", 0) & CLOUD_ONLY_ATTRS)


_POOL = ThreadPoolExecutor(max_workers=8, thread_name_prefix="dirsize")


def _scan_level(path):
    """Files directly inside path as (bytes, count, newest mtime), plus its real subfolders."""
    total = files = 0
    newest = 0.0
    subdirs = []
    try:
        with os.scandir(path) as it:
            for entry in it:
                try:
                    if entry.is_dir(follow_symlinks=False):
                        if not is_link_dir(entry):
                            subdirs.append(entry.path)
                        continue
                    st = entry.stat(follow_symlinks=False)
                except OSError:
                    continue
                if is_cloud_only(st):
                    continue
                total += st.st_size
                files += 1
                newest = max(newest, st.st_mtime)
    except OSError:
        pass  # permission denied, vanished, etc.
    return total, files, newest, subdirs


def _dir_stats_serial(path, budget):
    total = files = 0
    newest = 0.0
    stack = [path]
    while stack:
        if budget is not None and budget.expired:
            return total, files, newest, False
        t, f, n, subdirs = _scan_level(stack.pop())
        total, files, newest = total + t, files + f, max(newest, n)
        stack += subdirs
    return total, files, newest, True


def dir_stats(path, budget=None):
    """(total bytes, file count, newest mtime, finished) for everything under path.

    Big trees are split across threads: listing folders waits on the disk, not the CPU.
    """
    total = files = 0
    newest = 0.0
    frontier = [path]
    for _ in range(2):
        below = []
        for d in frontier:
            t, f, n, subdirs = _scan_level(d)
            total, files, newest = total + t, files + f, max(newest, n)
            below += subdirs
        frontier = below
        if len(frontier) >= 16:
            break
    complete = True
    for t, f, n, done in _POOL.map(lambda d: _dir_stats_serial(d, budget), frontier):
        total, files, newest = total + t, files + f, max(newest, n)
        complete = complete and done
    return total, files, newest, complete


def list_files(root, max_depth, budget, skip=()):
    """[(path, name, size, mtime)] for real (non-placeholder) files up to max_depth levels down."""
    out = []
    stack = [(root, 0)]
    while stack and not budget.expired:
        current, depth = stack.pop()
        if os.path.normcase(current) in skip:
            continue
        try:
            with os.scandir(current) as it:
                entries = list(it)
        except OSError:
            continue
        for entry in entries:
            try:
                if entry.is_dir(follow_symlinks=False):
                    if depth < max_depth and not is_link_dir(entry):
                        stack.append((entry.path, depth + 1))
                    continue
                st = entry.stat(follow_symlinks=False)
            except OSError:
                continue
            if not is_cloud_only(st):
                out.append((entry.path, entry.name, st.st_size, st.st_mtime))
    return out


def human(n):
    n = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if abs(n) < 1024:
            return f"{n:.0f} {unit}" if unit in ("B", "KB") else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"
