"""What DiskSage looks for.

Every detector only *measures* and adds findings to the scan context. Nothing in
this module deletes anything — that lives in actions.py, behind the safety checks.
"""

import glob
import hashlib
import os
import re
import time
from collections import defaultdict
from datetime import datetime

from . import installed, winapi
from .fsutil import DAY, MB, Budget, dir_stats, is_cloud_only, is_link_dir, list_files
from .models import Finding, Item
from .paths import inside, norm

INCOMPLETE_EXT = {".crdownload", ".part", ".partial", ".download", ".opdownload", ".!ut", ".!qb", ".tmp"}
INSTALLER_EXT = {".exe", ".msi", ".msix", ".msixbundle", ".appx", ".appxbundle"}
ARCHIVE_EXT = (".tar.gz", ".tar.xz", ".tar.bz2", ".tgz", ".zip", ".rar", ".7z", ".tar")
DISK_IMAGE_EXT = {".iso", ".img", ".dmg"}

LARGE_FILE_MIN = 300 * MB
DUPLICATE_MIN = 1 * MB
STALE_PROJECT_DAYS = 60
STALE_DOWNLOAD_DAYS = 180


class Context:
    def __init__(self, paths, apps, ollama_models=None, active_model=None):
        self.paths = paths
        self.apps = apps
        self.ollama_models = ollama_models or []
        self.active_model = active_model
        self.findings = []
        self.covered = set()
        self.walk = {"artifacts": [], "large": [], "dup_candidates": [], "packages": [], "complete": True}
        self.notes = []
        self.now = time.time()
        self.base = {"local": paths.local, "roaming": paths.roaming, "locallow": paths.locallow, "home": paths.home}

    def age(self, mtime):
        return int((self.now - mtime) // DAY) if mtime else 0

    def expand(self, pattern):
        return pattern.format(**self.base)

    def add(self, category, kind, title, detail, verdict, action, items, needs_item_notes=False):
        if action not in ("disk_cleanup", "none"):
            items = [i for i in items if i.size > 0]
        if not items:
            return None
        finding = Finding(
            id=f"{kind}-{len(self.findings) + 1}", category=category, kind=kind, title=title,
            detail=detail, verdict=verdict, action=action, items=items, needs_item_notes=needs_item_notes,
        )
        self.findings.append(finding)
        for item in items:
            if not item.path.startswith(("ollama:", "recycle-bin:")):
                self.covered.add(norm(item.path))
        return finding

    def is_covered(self, path):
        p = norm(path)
        return p in self.covered or any(p.startswith(c + "\\") for c in self.covered)


def _dedupe(items):
    seen, out = set(), []
    for item in items:
        n = norm(item.path)
        if n not in seen:
            seen.add(n)
            out.append(item)
    return out


def _by_size(items):
    return sorted(items, key=lambda i: -i.size)


# --- Downloads ----------------------------------------------------------------

def _archive_stem(name):
    low = name.lower()
    for ext in ARCHIVE_EXT:
        if low.endswith(ext):
            return name[: -len(ext)]
    return name


def _installer_item(path, size, mtime, info, match, prefix=""):
    if match:
        app = match["app"]
        note = f"{prefix}Installed: {app['name']}"
        if app["version"] and app["version"] not in app["name"]:
            note += f" {app['version']}"
        if match["setup_version"]:
            note += f" · this setup is v{match['setup_version']}"
    else:
        label = info.get("product_name") or info.get("description") or ""
        if label.lower() in ("setup", "installer", "install"):
            label = ""
        note = f"{prefix}Not in your installed apps" + (f" · file says “{label}”" if label else "")
    return Item(path, size, mtime, note=note)


def scan_installer_folders(ctx):
    """Setup packages unpacked into a folder (setup.exe + .cab files…), treated as one item —
    deleting single files from inside one would only break it."""
    token_cache = {}
    done, unknown = [], []
    for folder, setup in ctx.walk["packages"]:
        size, files, newest, complete = dir_stats(folder, Budget(20))
        if size < 5 * MB:
            continue
        info = winapi.file_version_strings(setup) if setup else {}
        match = installed.match_installer(os.path.basename(folder), info, ctx.apps, token_cache)
        item = _installer_item(folder, size, newest, info, match, prefix=f"Unpacked setup, {files:,} files · ")
        (done if match and match["relation"] != "newer" else unknown).append(item)
    ctx.add(
        "downloads", "packages_done", "Unpacked installers for apps you've installed",
        "Setup folders (setup.exe plus its data files) for apps that are now installed. "
        "The app doesn't need its installer to run.",
        "safe", "recycle", _by_size(done),
    )
    ctx.add(
        "downloads", "packages_unknown", "Unpacked installers for apps that aren't installed",
        "Complete setup folders for software that doesn't appear in your installed apps. "
        "If you're not planning to install it, the whole folder can go.",
        "review", "recycle", _by_size(unknown), needs_item_notes=True,
    )


def scan_downloads(ctx):
    dl = ctx.paths.downloads
    if not os.path.isdir(dl) or ctx.paths.in_cloud(dl):
        return
    # Unpacked installer folders are handled whole by scan_installer_folders.
    packages = {norm(pkg) for pkg, _ in ctx.walk["packages"]}
    files = list_files(dl, max_depth=2, budget=Budget(20), skip=packages)

    incomplete, installers, archives, images, other = [], [], [], [], []
    for path, name, size, mtime in files:
        low = name.lower()
        ext = os.path.splitext(low)[1]
        if ext in INCOMPLETE_EXT:
            # Anything newer than a day might still be downloading.
            if ctx.age(mtime) >= 1:
                incomplete.append(Item(path, size, mtime, note=f"{ctx.age(mtime)} days old"))
        elif ext in INSTALLER_EXT:
            installers.append((path, name, size, mtime))
        elif low.endswith(ARCHIVE_EXT):
            archives.append((path, name, size, mtime))
        elif ext in DISK_IMAGE_EXT:
            images.append((path, name, size, mtime))
        else:
            other.append((path, name, size, mtime))

    ctx.add(
        "downloads", "incomplete", "Unfinished downloads",
        "Leftovers from downloads that failed or were cancelled (.crdownload, .part…). "
        "They can't be opened by anything.",
        "safe", "recycle", _by_size(incomplete),
    )

    # Setup files vs. what's actually installed.
    token_cache = {}
    same, newer, unmatched = [], [], []
    for path, name, size, mtime in installers:
        info = winapi.file_version_strings(path) if name.lower().endswith(".exe") else {}
        match = installed.match_installer(os.path.splitext(name)[0], info, ctx.apps, token_cache)
        item = _installer_item(path, size, mtime, info, match)
        if not match:
            unmatched.append(item)
        else:
            (newer if match["relation"] == "newer" else same).append(item)

    ctx.add(
        "downloads", "installers_done", "Setup files for apps you've already installed",
        "You already ran these installers — the apps are on your PC. If you ever need one "
        "again, the latest version is a quick download away.",
        "safe", "recycle", _by_size(same),
    )
    ctx.add(
        "downloads", "installers_newer", "Setup files newer than what's installed",
        "These look like updates you downloaded but may not have run yet. Run them first, "
        "or remove them if you don't need the update.",
        "review", "recycle", _by_size(newer),
    )
    ctx.add(
        "downloads", "installers_unknown", "Setup files for apps that aren't installed",
        "These programs don't appear in your installed apps. Maybe you never ran them, "
        "uninstalled them since, or they're portable tools that run without installing.",
        "review", "recycle", _by_size(unmatched), needs_item_notes=True,
    )

    # Archives that were already extracted next to themselves.
    folder_cache = {}
    extracted = []
    for path, name, size, mtime in archives:
        parent = os.path.dirname(path)
        if parent not in folder_cache:
            try:
                with os.scandir(parent) as it:
                    folder_cache[parent] = {
                        e.name.lower(): e.path for e in it if e.is_dir(follow_symlinks=False)
                    }
            except OSError:
                folder_cache[parent] = {}
        stem = _archive_stem(name)
        candidates = {stem.lower(), re.sub(r"\s*\(\d+\)$", "", stem).lower()}
        hit = next((folder_cache[parent][c] for c in candidates if c in folder_cache[parent]), None)
        if hit and any(True for _ in os.scandir(hit)):
            extracted.append(Item(path, size, mtime, note=f"Already extracted to “{os.path.basename(hit)}”"))
        else:
            other.append((path, name, size, mtime))

    ctx.add(
        "downloads", "extracted", "Zip files you've already extracted",
        "Each of these archives has an extracted folder with the same name right next to it, "
        "so the archive itself is a redundant copy.",
        "safe", "recycle", _by_size(extracted),
    )

    image_items = []
    for path, name, size, mtime in images:
        if name.lower().endswith(".dmg"):
            note = "macOS disk image — it can't be used on Windows"
        else:
            note = f"Disk image, {ctx.age(mtime)} days old"
        image_items.append(Item(path, size, mtime, note=note))
    ctx.add(
        "downloads", "disk_images", "Disk images (.iso / .img / .dmg)",
        "Disk images are usually used once — to install an OS or program, or to make a "
        "bootable USB. If you're done with them, they're some of the biggest easy wins.",
        "review", "recycle", _by_size(image_items), needs_item_notes=True,
    )

    stale = [
        Item(path, size, mtime, note=f"Last changed {ctx.age(mtime)} days ago")
        for path, name, size, mtime in other
        if ctx.age(mtime) >= STALE_DOWNLOAD_DAYS
    ]
    ctx.add(
        "downloads", "stale_downloads", "Downloads you haven't touched in 6+ months",
        "Old downloads that aren't installers — documents, videos, random files. Some might "
        "matter to you, so look through the list.",
        "review", "recycle", _by_size(stale), needs_item_notes=True,
    )


# --- One walk through your folders for projects, big files and duplicates -----

SKIP_DIR_NAMES = {
    ".git", ".hg", ".svn", "$recycle.bin", "system volume information", "windowsapps",
    "steamapps", "steamlibrary", "epic games", "gog games", "riot games", "xboxgames",
    "ea games", "ubisoft game launcher", "site-packages",
}
DRIVE_ROOT_SKIP = {
    "windows", "program files", "program files (x86)", "programdata", "users", "recovery",
    "perflogs", "config.msi", "$winreagent", "msocache", "documents and settings",
    "onedrivetemp", "$windows.~bt", "$windows.~ws", "windows.old", "$sysreset",
    "$getcurrent", "nvidia", "amd", "intel", "swsetup", "esupport", "dell", "boot", "efi", "inetpub",
}
HOME_SKIP = (
    "AppData", ".cache", ".ollama", ".gradle", ".m2", ".nuget", ".cargo", ".rustup",
    ".lmstudio", ".vscode", ".vscode-insiders", ".cursor", ".conda", ".android",
    ".docker", ".local", "anaconda3", "miniconda3", "miniforge3", "scoop", "go",
)
PROJECT_ARTIFACTS = {"node_modules", ".venv", "venv", "env", "target", ".next", ".nuxt",
                     ".turbo", ".parcel-cache", ".svelte-kit", ".gradle"}
PACKAGE_MARKERS = {"setup.exe", "autorun.inf", "install.exe", "installer.exe", "setup.msi"}
# Program parts — identical copies of these inside software folders are normal.
DUPLICATE_SKIP_EXT = {".dll", ".cab", ".msp", ".pak", ".so", ".pyd", ".node", ".jar",
                      ".class", ".lib", ".obj", ".pdb", ".sys", ".mui"}


def _artifact_kind(name, siblings, path):
    if name == "node_modules" and "package.json" in siblings:
        return "node_modules"
    if name in (".venv", "venv", "env") and os.path.isfile(os.path.join(path, "pyvenv.cfg")):
        return "venv"
    if name == "target" and "cargo.toml" in siblings:
        return "rust"
    if name in (".next", ".nuxt", ".turbo", ".parcel-cache", ".svelte-kit") and "package.json" in siblings:
        return "build_cache"
    if name == ".gradle" and siblings & {"build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts", "gradlew"}:
        return "gradle"
    return None


def deep_walk(ctx, budget_s=75):
    p = ctx.paths
    roots = [p.home]
    for drive in [p.system_drive, *p.other_drives]:
        try:
            with os.scandir(drive) as it:
                for e in it:
                    if (e.is_dir(follow_symlinks=False) and not is_link_dir(e)
                            and e.name.lower() not in DRIVE_ROOT_SKIP and not e.name.startswith("$")):
                        roots.append(e.path)
        except OSError:
            pass

    skip = {norm(os.path.join(p.home, name)) for name in HOME_SKIP}
    skip |= {norm(od) for od in p.onedrive}
    skip |= {norm(a["install_location"]) for a in ctx.apps if a.get("install_location")}
    dup_roots = [
        r for r in (p.downloads, p.desktop, p.documents, p.pictures, p.videos, p.music)
        if os.path.isdir(r) and not p.in_cloud(r)
    ]

    budget = Budget(budget_s)
    walk = ctx.walk
    stack = list(dict.fromkeys(roots))
    visited = set()
    while stack:
        if budget.expired:
            walk["complete"] = False
            break
        current = stack.pop()
        key = norm(current)
        if key in visited or key in skip:
            continue
        visited.add(key)
        try:
            with os.scandir(current) as it:
                entries = list(it)
        except OSError:
            continue
        siblings = {e.name.lower() for e in entries}

        if PACKAGE_MARKERS & siblings and p.protected_reason(current) is None:
            # An unpacked installer: report the folder as a whole and don't look inside.
            setup = next((os.path.join(current, n) for n in ("setup.exe", "install.exe", "installer.exe") if n in siblings), None)
            folder = current
            while True:  # "Foo.zip" extracted to Foo\Foo\setup.exe → offer the outer Foo
                parent = os.path.dirname(folder)
                if parent == folder or p.protected_reason(parent) is not None:
                    break
                try:
                    if len(os.listdir(parent)) != 1:
                        break
                except OSError:
                    break
                folder = parent
            walk["packages"].append((folder, setup))
            continue

        in_dup_root = any(inside(current, r) for r in dup_roots)
        for e in entries:
            try:
                is_dir = e.is_dir(follow_symlinks=False)
            except OSError:
                continue
            if is_dir:
                low = e.name.lower()
                if low in SKIP_DIR_NAMES or is_link_dir(e):
                    continue
                kind = _artifact_kind(low, siblings, e.path)
                if kind:
                    walk["artifacts"].append((kind, e.path, current))
                else:
                    stack.append(e.path)
                continue
            try:
                st = e.stat(follow_symlinks=False)
            except OSError:
                continue
            if is_cloud_only(st):
                continue
            if st.st_size >= LARGE_FILE_MIN:
                walk["large"].append((e.path, st.st_size, st.st_mtime))
            if (in_dup_root and st.st_size >= DUPLICATE_MIN
                    and os.path.splitext(e.name)[1].lower() not in DUPLICATE_SKIP_EXT):
                walk["dup_candidates"].append((e.path, st.st_size, st.st_mtime))

    skipped = [name for name, folder in (("Desktop", p.desktop), ("Documents", p.documents), ("Pictures", p.pictures))
               if p.in_cloud(folder)]
    if skipped:
        ctx.notes.append(
            f"Your {', '.join(skipped)} folders sync to OneDrive, so DiskSage skipped them — deleting a file "
            "there would delete it from the cloud too."
        )
    if not walk["complete"]:
        ctx.notes.append("The folder walk hit its time limit, so some deep folders weren't checked.")


# --- Duplicates -----------------------------------------------------------------

def _partial_hash(path, size):
    h = hashlib.blake2b(digest_size=16)
    try:
        with open(path, "rb") as f:
            h.update(f.read(64 * 1024))
            if size > 128 * 1024:
                f.seek(-64 * 1024, os.SEEK_END)
                h.update(f.read(64 * 1024))
    except OSError:
        return None
    return h.digest()


def _full_hash(path, budget):
    h = hashlib.blake2b(digest_size=20)
    try:
        with open(path, "rb") as f:
            while chunk := f.read(1024 * 1024):
                h.update(chunk)
                if budget.expired:
                    return None
    except OSError:
        return None
    return h.digest()


_COPY_SUFFIX = re.compile(r"\(\d+\)|\bcopy\b|- copy", re.IGNORECASE)


def scan_duplicates(ctx):
    p = ctx.paths
    location_rank = [(p.documents, 0), (p.pictures, 1), (p.videos, 1), (p.music, 1), (p.desktop, 2), (p.downloads, 3)]

    def keeper_key(entry):
        path, mtime = entry
        rank = next((r for root, r in location_rank if inside(path, root)), 4)
        return (rank, bool(_COPY_SUFFIX.search(os.path.basename(path))), mtime)

    by_size = defaultdict(list)
    for path, size, mtime in ctx.walk["dup_candidates"]:
        if not ctx.is_covered(path):
            by_size[size].append((path, mtime))

    budget = Budget(40)
    groups = []
    for size, entries in sorted(by_size.items(), key=lambda kv: -kv[0]):
        if len(entries) < 2:
            continue
        if budget.expired:
            break
        partial = defaultdict(list)
        for path, mtime in entries:
            digest = _partial_hash(path, size)
            if digest:
                partial[digest].append((path, mtime))
        for candidates in partial.values():
            if len(candidates) < 2:
                continue
            full = defaultdict(list)
            for path, mtime in candidates:
                digest = _full_hash(path, budget) if size > 128 * 1024 else b"small"
                if digest:
                    full[digest].append((path, mtime))
            groups += [(size, g) for g in full.values() if len(g) >= 2]

    in_downloads, elsewhere = [], []
    for size, group in groups:
        keeper = min(group, key=keeper_key)[0]
        for path, mtime in group:
            if path == keeper:
                continue
            item = Item(path, size, mtime, note=f"Identical to {p.display(keeper)}")
            (in_downloads if inside(path, p.downloads) else elsewhere).append(item)

    ctx.add(
        "duplicates", "dups_downloads", "Duplicate files in Downloads",
        "Exact byte-for-byte copies — usually the same file downloaded twice "
        "(“report (1).pdf”). One copy is always kept; these are the extras.",
        "safe", "recycle", _by_size(in_downloads),
    )
    ctx.add(
        "duplicates", "dups_elsewhere", "Duplicate files in your other folders",
        "Exact copies spread across Documents, Desktop, Pictures… One copy is always kept, "
        "but you may have put a copy somewhere on purpose.",
        "review", "recycle", _by_size(elsewhere),
    )


# --- Temp files and caches --------------------------------------------------------

def scan_temp(ctx):
    temp = ctx.paths.temp
    try:
        with os.scandir(temp) as it:
            entries = list(it)
    except OSError:
        return
    cutoff = ctx.now - DAY
    budget = Budget(25)
    total = count = 0
    for e in entries:
        try:
            st = e.stat(follow_symlinks=False)
            if st.st_mtime > cutoff:
                continue
            if e.is_dir(follow_symlinks=False):
                if is_link_dir(e):
                    continue
                total += dir_stats(e.path, budget)[0]
            else:
                total += st.st_size
            count += 1
        except OSError:
            continue
    ctx.add(
        "caches", "temp", "Temporary files",
        "Programs and installers leave scratch files in your Temp folder and often forget to "
        "clean up. Only items older than a day are included, so nothing in use is touched.",
        "safe", "delete_contents",
        [Item(temp, total, note=f"{count:,} items older than a day", meta={"older_than": DAY})],
    )


BROWSERS = [
    ("Chrome", "{local}\\Google\\Chrome\\User Data"),
    ("Edge", "{local}\\Microsoft\\Edge\\User Data"),
    ("Brave", "{local}\\BraveSoftware\\Brave-Browser\\User Data"),
    ("Vivaldi", "{local}\\Vivaldi\\User Data"),
    ("Opera", "{local}\\Opera Software\\Opera Stable"),
    ("Opera GX", "{local}\\Opera Software\\Opera GX Stable"),
]
CHROMIUM_PROFILE_CACHES = ("Cache", "Code Cache", "GPUCache", "DawnCache", "DawnGraphiteCache", "DawnWebGPUCache")
CHROMIUM_ROOT_CACHES = ("ShaderCache", "GrShaderCache", "GraphiteDawnCache")
CHROMIUM_MARKERS = {"local storage", "preferences", "network", "session storage", "local state"}
PRETTY_APP_NAMES = {
    "code": "VS Code", "code - insiders": "VS Code Insiders", "discord": "Discord", "slack": "Slack",
    "spotify": "Spotify", "postman": "Postman", "notion": "Notion", "obsidian": "Obsidian",
    "figma": "Figma", "whatsapp": "WhatsApp", "zoom": "Zoom", "cursor": "Cursor",
    "microsoft teams": "Microsoft Teams", "teams": "Microsoft Teams", "github desktop": "GitHub Desktop",
}
WINDOWS_CACHES = [
    ("Windows web cache (INetCache)", "{local}\\Microsoft\\Windows\\INetCache", ""),
    ("Crash dumps", "{local}\\CrashDumps", "memory snapshots saved when apps crashed"),
    ("Windows error reports", "{local}\\Microsoft\\Windows\\WER\\ReportArchive", ""),
    ("Windows error reports (queued)", "{local}\\Microsoft\\Windows\\WER\\ReportQueue", ""),
    ("DirectX shader cache", "{local}\\D3DSCache", "games may stutter briefly while it rebuilds"),
    ("NVIDIA shader cache", "{local}\\NVIDIA\\DXCache", "games may stutter briefly while it rebuilds"),
    ("NVIDIA OpenGL cache", "{local}\\NVIDIA\\GLCache", ""),
    ("NVIDIA shader cache", "{locallow}\\NVIDIA\\PerDriverVersion\\DXCache", "games may stutter briefly while it rebuilds"),
    ("NVIDIA OpenGL cache", "{locallow}\\NVIDIA\\PerDriverVersion\\GLCache", ""),
    ("AMD shader cache", "{local}\\AMD\\DxCache", "games may stutter briefly while it rebuilds"),
    ("AMD shader cache", "{local}\\AMD\\DxcCache", ""),
    ("AMD OpenGL cache", "{local}\\AMD\\GLCache", ""),
    ("AMD Vulkan cache", "{local}\\AMD\\VkCache", ""),
    ("Intel shader cache", "{locallow}\\Intel\\ShaderCache", ""),
]
OTHER_APP_CACHES = [
    ("Spotify", "{local}\\Spotify\\Data", "offline-downloaded songs are stored separately and stay"),
    ("Steam web cache", "{local}\\Steam\\htmlcache", ""),
]


def _pretty(name):
    if name.lower() in PRETTY_APP_NAMES:
        return PRETTY_APP_NAMES[name.lower()]
    if name.islower() or "-" in name or "_" in name:
        return " ".join(w.capitalize() for w in re.split(r"[-_ ]+", name) if w)
    return name


def _measure(label, dirs, note="", seconds=25):
    items = []
    for d in dirs:
        if not os.path.isdir(d):
            continue
        size, files, newest, complete = dir_stats(d, Budget(seconds))
        if size >= MB:
            text = label + (f" · {note}" if note else "")
            if not complete:
                text += " · at least this much (still counting when time ran out)"
            items.append(Item(d, size, newest, note=text))
    return items


def _chromium_cache_dirs(root):
    profiles = [os.path.join(root, "Default"), os.path.join(root, "Guest Profile"), root]
    profiles += glob.glob(os.path.join(glob.escape(root), "Profile *"))
    dirs = [os.path.join(prof, name) for prof in profiles for name in CHROMIUM_PROFILE_CACHES]
    dirs += [os.path.join(root, name) for name in CHROMIUM_ROOT_CACHES]
    return list(dict.fromkeys(dirs))


def _electron_caches(base, skip_roots):
    """Desktop apps built on Electron/Chromium (Discord, Slack, VS Code…) keep browser-style caches."""
    found = []
    try:
        with os.scandir(base) as it:
            level1 = [e for e in it if e.is_dir(follow_symlinks=False) and not is_link_dir(e)]
    except OSError:
        return found
    for e1 in level1:
        candidates = [(e1.path, _pretty(e1.name))]
        try:
            with os.scandir(e1.path) as it:
                candidates += [
                    (e2.path, _pretty(f"{e1.name} {e2.name}"))
                    for e2 in it if e2.is_dir(follow_symlinks=False) and not is_link_dir(e2)
                ]
        except OSError:
            pass
        for folder, label in candidates:
            if any(inside(folder, s) for s in skip_roots):
                continue
            try:
                with os.scandir(folder) as it:
                    names = {x.name.lower(): x.name for x in it}
            except OSError:
                continue
            if not CHROMIUM_MARKERS & names.keys():
                continue
            dirs = [os.path.join(folder, names[c.lower()]) for c in CHROMIUM_PROFILE_CACHES if c.lower() in names]
            if dirs:
                found.append((label, dirs))
    return found


def scan_caches(ctx):
    p = ctx.paths

    browser_items, skip_roots = [], []
    for label, pattern in BROWSERS:
        root = ctx.expand(pattern)
        if os.path.isdir(root):
            skip_roots.append(root)
            browser_items += _measure(label, _chromium_cache_dirs(root), f"close {label} first to clear it all")
    firefox = glob.glob(os.path.join(glob.escape(os.path.join(p.local, "Mozilla", "Firefox", "Profiles")), "*", "cache2"))
    browser_items += _measure("Firefox", firefox, "close Firefox first to clear it all")
    ctx.add(
        "caches", "browser_cache", "Browser caches",
        "Copies of websites your browsers keep to load pages faster. They refill as you browse. "
        "Clearing them doesn't log you out or touch history, bookmarks or passwords.",
        "safe", "delete_contents", _by_size(_dedupe(browser_items)),
    )

    app_items = []
    for base in (p.roaming, p.local):
        for label, dirs in _electron_caches(base, skip_roots):
            app_items += _measure(label, dirs, f"close {label} first to clear it all")
    for name in ("Code", "Code - Insiders", "Cursor", "Windsurf", "VSCodium"):
        root = os.path.join(p.roaming, name)
        extra = [os.path.join(root, d) for d in ("CachedData", "CachedExtensionVSIXs", "logs")]
        app_items += _measure(_pretty(name), extra)
    for label, pattern, note in OTHER_APP_CACHES:
        app_items += _measure(label, [ctx.expand(pattern)], note)
    ctx.add(
        "caches", "app_cache", "App caches",
        "Discord, VS Code, Slack, Teams and many other desktop apps are built on Chromium and keep "
        "the same kind of web cache a browser does. They rebuild it automatically.",
        "safe", "delete_contents", _by_size(_dedupe(app_items)),
    )

    win_items = []
    for label, pattern, note in WINDOWS_CACHES:
        win_items += _measure(label, [ctx.expand(pattern)], note)
    ctx.add(
        "caches", "windows_cache", "Windows and graphics caches",
        "Crash reports, and the shader caches your graphics driver builds for games and apps. "
        "All of it is regenerated when needed.",
        "safe", "delete_contents", _by_size(_dedupe(win_items)),
    )


DEV_CACHES = [
    ("pip download cache", "{local}\\pip\\Cache", "safe", "pip re-downloads packages when it needs them"),
    ("uv cache", "{local}\\uv\\cache", "safe", "uv re-downloads packages when it needs them"),
    ("npm cache", "{local}\\npm-cache", "safe", "npm re-downloads packages when it needs them"),
    ("Yarn cache", "{local}\\Yarn\\Cache", "safe", "Yarn re-downloads packages when it needs them"),
    ("NuGet HTTP cache", "{local}\\NuGet\\v3-cache", "safe", "re-downloaded on the next restore"),
    ("NuGet packages", "{home}\\.nuget\\packages", "safe", "restored automatically on the next build"),
    ("Gradle caches", "{home}\\.gradle\\caches", "safe", "the next build re-downloads what it needs (slower once)"),
    ("Go build cache", "{local}\\go-build", "safe", "rebuilt automatically"),
    ("Cargo download cache", "{home}\\.cargo\\registry\\cache", "safe", "re-downloaded by cargo"),
    ("Cargo unpacked sources", "{home}\\.cargo\\registry\\src", "safe", "re-extracted by cargo"),
    ("Composer cache", "{local}\\Composer", "safe", "re-downloaded by Composer"),
    ("node-gyp headers", "{local}\\node-gyp\\Cache", "safe", "re-downloaded when a native module builds"),
    ("Electron downloads", "{local}\\electron\\Cache", "safe", "re-downloaded when needed"),
    ("pnpm store", "{local}\\pnpm\\store", "review", "shared by all your pnpm projects — `pnpm store prune` removes only unused packages"),
    ("Maven repository", "{home}\\.m2\\repository", "review", "re-downloadable, except anything you installed locally with `mvn install`"),
    ("Go module cache", "{home}\\go\\pkg\\mod", "review", "`go clean -modcache` is the official way to clear it"),
    ("Playwright browsers", "{local}\\ms-playwright", "review", "`npx playwright install` brings them back"),
    ("Puppeteer browsers", "{home}\\.cache\\puppeteer", "review", "re-downloaded on the next `npm install`"),
]


def scan_dev_caches(ctx):
    safe, review = [], []
    for label, pattern, verdict, note in DEV_CACHES:
        items = _measure(label, [ctx.expand(pattern)], note)
        (safe if verdict == "safe" else review).extend(items)
    ctx.add(
        "dev", "dev_caches", "Developer tool caches",
        "Package managers keep a copy of everything they ever downloaded. Clearing the cache "
        "doesn't touch your projects — packages are simply downloaded again when needed.",
        "safe", "delete_contents", _by_size(safe),
    )
    ctx.add(
        "dev", "dev_caches_review", "Developer caches to think about",
        "Also re-downloadable, but each has a catch worth knowing first.",
        "review", "delete_contents", _by_size(review),
    )

    conda = []
    for name in ("anaconda3", "miniconda3", "miniforge3", ".conda"):
        conda += _measure("Conda packages", [os.path.join(ctx.paths.home, name, "pkgs")], seconds=40)
    ctx.add(
        "dev", "conda", "Conda package cache",
        "Run `conda clean --all` in an Anaconda Prompt — it knows which packages your environments "
        "still use, which is safer than deleting this folder by hand.",
        "review", "none", conda,
    )


REINSTALL_HINTS = {
    "node_modules": "`npm install` brings it back",
    "venv": "recreate with `python -m venv` and `pip install -r requirements.txt`",
    "rust": "`cargo build` rebuilds it",
    "build_cache": "rebuilt on the next build",
    "gradle": "rebuilt on the next build",
}


def _project_activity(project, budget):
    """Newest file change in a project, ignoring dependency folders."""
    newest, seen = 0.0, 0
    stack = [(project, 0)]
    while stack and seen < 3000 and not budget.expired:
        current, depth = stack.pop()
        try:
            with os.scandir(current) as it:
                entries = list(it)
        except OSError:
            continue
        for e in entries:
            seen += 1
            try:
                if e.is_dir(follow_symlinks=False):
                    low = e.name.lower()
                    if depth < 3 and low not in PROJECT_ARTIFACTS and low not in (".git", "dist", "build", "__pycache__") and not is_link_dir(e):
                        stack.append((e.path, depth + 1))
                    continue
                newest = max(newest, e.stat(follow_symlinks=False).st_mtime)
            except OSError:
                continue
    return newest


def scan_projects(ctx):
    budget = Budget(60)
    stale, active = [], []
    for kind, path, project in ctx.walk["artifacts"]:
        if budget.expired:
            break
        size, files, newest, _ = dir_stats(path, budget)
        if size < 5 * MB:
            continue
        last = _project_activity(project, budget) or newest
        days = ctx.age(last)
        note = (f"Project “{os.path.basename(project)}” · last changed {days} days ago · "
                f"{files:,} files · {REINSTALL_HINTS[kind]}")
        (stale if days >= STALE_PROJECT_DAYS else active).append(Item(path, size, last, note=note))
    ctx.add(
        "dev", "projects_stale", "Dependencies in projects you haven't touched in 2+ months",
        "Folders like node_modules, .venv and Rust's target are rebuilt from your project's config "
        "files with one command. In projects you're not working on, they're dead weight.",
        "safe", "delete", _by_size(stale),
    )
    ctx.add(
        "dev", "projects_active", "Dependencies in projects you're working on",
        "Same kind of folders, but these projects changed recently — removing them just means "
        "reinstalling next time you open the project.",
        "review", "delete", _by_size(active),
    )


# --- AI models ------------------------------------------------------------------

def _iso_to_ts(text):
    try:
        return datetime.fromisoformat(text).timestamp()
    except (TypeError, ValueError):
        return 0.0


def scan_ai_models(ctx):
    items = []
    for model in ctx.ollama_models:
        if model.get("name") == ctx.active_model:
            continue  # never suggest removing the model DiskSage itself runs on
        ts = _iso_to_ts(model.get("modified_at"))
        items.append(Item(
            f"ollama:{model['name']}", int(model.get("size") or 0), ts,
            note=f"Ollama model · downloaded/updated {ctx.age(ts)} days ago · `ollama pull {model['name']}` brings it back",
            meta={"model": model["name"]},
        ))
    ctx.add(
        "ai", "ollama", "Ollama models",
        "Local AI models are huge. These aren't the one DiskSage runs on — if you haven't used one "
        "in a while, remove it.",
        "review", "ollama_rm", _by_size(items),
    )

    budget = Budget(30)
    hf_items = []
    hub = os.path.join(ctx.paths.home, ".cache", "huggingface", "hub")
    for entry in sorted(glob.glob(os.path.join(glob.escape(hub), "models--*")) + glob.glob(os.path.join(glob.escape(hub), "datasets--*"))):
        size, _, newest, _ = dir_stats(entry, budget)
        kind, _, name = os.path.basename(entry).partition("--")
        hf_items.append(Item(entry, size, newest, note=f"Hugging Face {kind[:-1]} {name.replace('--', '/')} · last used {ctx.age(newest)} days ago"))
    ctx.add(
        "ai", "huggingface", "Hugging Face downloads",
        "Models and datasets downloaded by Python libraries like transformers and diffusers. "
        "A script that needs one again downloads it automatically.",
        "review", "delete", _by_size(hf_items),
    )

    lms_items = []
    for root in (os.path.join(ctx.paths.home, ".lmstudio", "models"), os.path.join(ctx.paths.home, ".cache", "lm-studio", "models")):
        for entry in glob.glob(os.path.join(glob.escape(root), "*", "*")):
            if os.path.isdir(entry):
                size, _, newest, _ = dir_stats(entry, budget)
                lms_items.append(Item(entry, size, newest, note=f"LM Studio model · last used {ctx.age(newest)} days ago"))
    ctx.add(
        "ai", "lmstudio", "LM Studio models",
        "Models downloaded in LM Studio. You can download them again from inside the app.",
        "review", "delete", _by_size(lms_items),
    )


# --- Drivers, Windows, giant files, Recycle Bin ------------------------------------

def scan_system(ctx):
    p = ctx.paths
    budget = Budget(30)
    sd = p.system_drive

    safe, review = [], []
    for name, verdict, note in (
        ("NVIDIA", "safe", "NVIDIA's driver installer unpacks itself here and leaves the files behind"),
        ("AMD", "safe", "AMD's driver installer unpacks itself here and leaves the files behind"),
        ("Intel", "review", "often driver-installer leftovers, but some Intel tools keep files here"),
        ("SWSetup", "review", "HP driver installers — HP's recovery tools sometimes use them"),
        ("eSupport", "review", "ASUS driver and utility installers — MyASUS can use them to reinstall drivers"),
        ("Dell", "review", "Dell driver and support files — SupportAssist may use them"),
    ):
        path = os.path.join(sd, name)
        if os.path.isdir(path):
            size, _, newest, _ = dir_stats(path, budget)
            (safe if verdict == "safe" else review).append(Item(path, size, newest, note=note))
    ctx.add(
        "system", "drivers_safe", "Driver installer leftovers",
        "Graphics driver installers extract themselves to the root of your drive and never clean up.",
        "safe", "recycle", safe,
    )
    ctx.add(
        "system", "drivers_review", "Other driver folders",
        "Probably leftovers, but they aren't always safe to remove.",
        "review", "recycle", review,
    )

    system_items = []
    for label, path, always in (
        ("Previous Windows installation (Windows.old)", os.path.join(sd, "Windows.old"), True),
        ("Windows upgrade files", os.path.join(sd, "$WINDOWS.~BT"), True),
        ("Windows upgrade files", os.path.join(sd, "$WINDOWS.~WS"), True),
        ("Windows Update downloads", os.path.join(p.windir, "SoftwareDistribution", "Download"), False),
        ("Windows temp folder", os.path.join(p.windir, "Temp"), False),
    ):
        if not os.path.isdir(path):
            continue
        size, files, newest, _ = dir_stats(path, budget)
        if files == 0 and not always:
            continue
        note = label if files else f"{label} · Windows needs admin rights to measure it"
        if size >= 50 * MB or always:
            system_items.append(Item(path, size, newest, note=note))
    ctx.add(
        "system", "windows_leftovers", "Windows update and upgrade leftovers",
        "These belong to Windows itself, so DiskSage won't touch them directly. Windows' own Disk "
        "Cleanup removes them safely: open it, then choose “Clean up system files”.",
        "review", "disk_cleanup", _by_size(system_items),
    )

    notes = {
        "hiberfil.sys": "Hibernation file — used for hibernate and Fast Startup. If you never hibernate, "
                        "an admin can run `powercfg /h off` to get this space back",
        "pagefile.sys": "Virtual memory — Windows manages it. It grows when RAM runs short (for example "
                        "while a big local AI model is loaded) and usually shrinks back after a restart",
    }
    memory_items = []
    try:
        with os.scandir(sd) as it:
            for e in it:
                if e.name.lower() in notes:
                    memory_items.append(Item(e.path, e.stat(follow_symlinks=False).st_size, note=notes[e.name.lower()]))
    except OSError:
        pass
    ctx.add(
        "system", "memory_files", "Windows memory files",
        "Hidden system files Windows needs for hibernation and virtual memory. They can't be deleted by "
        "hand while Windows is running — the notes below say how to shrink them properly.",
        "keep", "none", _by_size(memory_items),
    )


KEEP_EXTENSIONS = {
    ".vhdx": "Virtual disk (WSL, Docker or a VM) — deleting it erases everything inside it",
    ".vhd": "Virtual disk — deleting it erases everything inside it",
    ".vmdk": "VMware virtual machine disk — deleting it destroys the VM",
    ".vdi": "VirtualBox virtual machine disk — deleting it destroys the VM",
    ".qcow2": "Virtual machine disk — deleting it destroys the VM",
    ".pst": "Outlook mailbox data — your emails live in here",
    ".ost": "Outlook's offline mailbox — remove it from Outlook's account settings, not by hand",
}


def scan_large_files(ctx):
    p = ctx.paths
    review, keep = [], []
    for path, size, mtime in sorted(ctx.walk["large"], key=lambda x: -x[1]):
        if ctx.is_covered(path):
            continue
        ext = os.path.splitext(path)[1].lower()
        if ext in KEEP_EXTENSIONS:
            keep.append(Item(path, size, mtime, note=KEEP_EXTENSIONS[ext]))
        elif len(review) < 25:
            review.append(Item(path, size, mtime, note=f"Last changed {ctx.age(mtime)} days ago"))

    # WSL and Docker disks hide inside AppData, which the walk skips.
    for pattern, note in (
        ("{local}\\Packages\\*\\LocalState\\ext4.vhdx", "Your WSL Linux disk — to shrink it, clean up inside Linux and compact it; don't delete it"),
        ("{local}\\Docker\\wsl\\*\\*.vhdx", "Docker's disk — run `docker system prune` to free space inside it instead"),
    ):
        for path in glob.glob(ctx.expand(pattern)):
            try:
                keep.append(Item(path, os.path.getsize(path), os.path.getmtime(path), note=note))
            except OSError:
                pass

    ctx.add(
        "large", "large_files", "Large files worth a look",
        "The biggest files in your folders that aren't covered above. DiskSage can't know if these "
        "matter to you — but this is where the space is.",
        "review", "recycle", review, needs_item_notes=True,
    )
    ctx.add(
        "large", "large_keep", "Big files to leave alone",
        "These are large, but deleting them would break something or lose data.",
        "keep", "none", _by_size(_dedupe(keep)),
    )


def scan_recycle_bin(ctx):
    size, count = winapi.recycle_bin_info()
    if size > 0:
        ctx.add(
            "bin", "recycle_bin", "Recycle Bin",
            f"{count:,} things you already deleted are still taking up space. Emptying the bin makes "
            "that permanent.",
            "review", "empty_bin", [Item("recycle-bin:", size, note=f"{count:,} items")],
        )
