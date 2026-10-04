"""Installed apps (from the registry), matching setup files to them, and app leftovers."""

import glob
import hashlib
import os
import re
import winreg

from .fsutil import Budget, dir_stats, is_link_dir
from .models import Item
from .paths import norm

UNINSTALL_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
_HIVES = [
    (winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_64KEY, "machine"),
    (winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_32KEY, "machine32"),
    (winreg.HKEY_CURRENT_USER, 0, "user"),
]
_SKIP_RELEASE_TYPES = {"update", "hotfix", "security update", "service pack"}


def _value(key, name):
    try:
        return winreg.QueryValueEx(key, name)[0]
    except OSError:
        return None


def installed_apps():
    """Apps listed in Settings > Apps, read from the same registry keys Windows uses."""
    apps = {}
    for hive, flag, source in _HIVES:
        try:
            root = winreg.OpenKey(hive, UNINSTALL_KEY, 0, winreg.KEY_READ | flag)
        except OSError:
            continue
        with root:
            index = 0
            while True:
                try:
                    sub = winreg.EnumKey(root, index)
                except OSError:
                    break
                index += 1
                try:
                    key = winreg.OpenKey(root, sub, 0, winreg.KEY_READ | flag)
                except OSError:
                    continue
                with key:
                    name = _value(key, "DisplayName")
                    uninstall = _value(key, "UninstallString")
                    if not isinstance(name, str) or not name.strip() or not uninstall:
                        continue
                    if _value(key, "SystemComponent") == 1 or _value(key, "ParentKeyName"):
                        continue
                    if str(_value(key, "ReleaseType") or "").lower() in _SKIP_RELEASE_TYPES:
                        continue
                    ver = str(_value(key, "DisplayVersion") or "")
                    dedupe = (name.strip().lower(), ver)
                    if dedupe in apps:
                        continue
                    size_kb = _value(key, "EstimatedSize")
                    date = str(_value(key, "InstallDate") or "")
                    apps[dedupe] = {
                        "id": hashlib.sha1(f"{source}|{sub}".encode()).hexdigest()[:12],
                        "name": name.strip(),
                        "version": ver,
                        "publisher": str(_value(key, "Publisher") or "").strip(),
                        "install_location": str(_value(key, "InstallLocation") or "").strip().strip('"'),
                        "uninstall_string": str(uninstall),
                        "size": size_kb * 1024 if isinstance(size_kb, int) else 0,
                        "install_date": f"{date[:4]}-{date[4:6]}-{date[6:8]}" if re.fullmatch(r"\d{8}", date) else "",
                    }
    return sorted(apps.values(), key=lambda a: a["name"].lower())


# --- Fuzzy name matching ------------------------------------------------------
# Installer names are messy ("VSCodeUserSetup-x64-1.93.1.exe") and app names are
# different ("Microsoft Visual Studio Code"), so compare word sets, not strings.

STOPWORDS = {
    "setup", "installer", "install", "installation", "win", "windows", "bit", "full",
    "offline", "online", "web", "latest", "stable", "release", "final", "version",
    "beta", "en", "us", "english", "msi", "exe", "the", "of", "for", "and", "by",
}
COMPANY_WORDS = {
    "microsoft", "google", "adobe", "apple", "mozilla", "oracle", "corporation", "corp",
    "inc", "llc", "ltd", "limited", "software", "technologies", "technology",
    "foundation", "gmbh", "co", "systems", "labs",
}


_ARCH_RE = re.compile(r"(?<![a-z0-9])(amd64|arm64|aarch64|x86_64|x64|x86|i[36]86|win32|win64)(?![a-z0-9])", re.IGNORECASE)


def tokens(text):
    text = _ARCH_RE.sub(" ", text or "")
    text = re.sub(r"([a-z])([A-Z])", r"\1 \2", text)
    text = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", text)
    out = []
    for word in re.split(r"[^a-z0-9]+", text.lower()):
        word = re.sub(r"^\d+|\d+$", "", word)  # "anaconda3" → "anaconda"
        if len(word) >= 2 and word not in STOPWORDS:
            out.append(word)
    return out


def _core(words):
    return [w for w in words if w not in COMPANY_WORDS] or words


def score(a, b, require_lead=False):
    """How well word list `a` (a file/folder name) matches word list `b` (an app name), 0..1.

    require_lead: the app's first real word must match — so "python-3.10.exe" doesn't
    match "Anaconda3 (Python 3.13)" just because both mention Python.
    """
    ca, cb = _core(a), _core(b)
    if not ca or not cb:
        return 0.0
    ja, jb = "".join(ca), "".join(cb)
    if len(ja) >= 4 and ja == jb:
        return 1.0
    sa, sb = set(ca), set(cb)
    common = sa & sb
    if not any(len(w) >= 3 for w in common):
        if len(ja) >= 5 and len(jb) >= 5 and (ja in jb or jb in ja):
            return 0.7
        return 0.0
    if require_lead and cb[0] not in common:
        return 0.0
    return 0.7 * len(common) / len(sa) + 0.3 * len(common) / len(sb)


def parse_version(text):
    m = re.search(r"\d+(?:\.\d+)+", text or "")
    return tuple(int(x) for x in m.group(0).split(".")) if m else None


def compare_versions(a, b):
    n = max(len(a), len(b))
    a, b = a + (0,) * (n - len(a)), b + (0,) * (n - len(b))
    return (a > b) - (a < b)


def match_installer(stem, info, apps, token_cache):
    """Find the installed app a setup file (or unpacked setup folder) belongs to. None or a dict."""
    texts = [t for t in (info.get("product_name"), info.get("description"), stem) if t]
    best = None
    for text in texts:
        words = tokens(text)
        if not words:
            continue
        for app in apps:
            app_words = token_cache.setdefault(app["id"], tokens(app["name"]))
            s = score(words, app_words, require_lead=True)
            if s >= 0.6 and (best is None or s > best[0]):
                best = (s, app)
    if not best:
        return None

    app = best[1]
    setup_version = parse_version(stem) or parse_version(info.get("product_version", ""))
    app_version = parse_version(app["version"])
    relation = "unknown"
    if setup_version and app_version:
        relation = "newer" if compare_versions(setup_version, app_version) > 0 else "same_or_older"
    return {
        "app": app,
        "relation": relation,
        "setup_version": ".".join(map(str, setup_version)) if setup_version else "",
    }


# --- Leftovers ------------------------------------------------------------------

def _subdirs(root):
    try:
        with os.scandir(root) as it:
            return [e for e in it if e.is_dir(follow_symlinks=False) and not is_link_dir(e)]
    except OSError:
        return []


# Folders some popular apps keep under names that don't match the app's name.
KNOWN_EXTRA_FOLDERS = {
    "visual studio code": ["{home}\\.vscode"],
    "vs code": ["{home}\\.vscode"],
    "cursor": ["{home}\\.cursor"],
    "windsurf": ["{home}\\.windsurf", "{home}\\.codeium"],
    "android studio": ["{home}\\.android", "{local}\\Google\\AndroidStudio*", "{roaming}\\Google\\AndroidStudio*"],
    "docker desktop": ["{home}\\.docker", "{local}\\Docker", "{roaming}\\Docker", "{roaming}\\Docker Desktop"],
    "postman": ["{home}\\Postman"],
    "unity hub": ["{roaming}\\UnityHub"],
    "epic games launcher": ["{local}\\EpicGamesLauncher"],
}


def find_leftovers(app, paths, apps, budget_s=20):
    """Folders on this PC that look like they belong to `app` (settings, caches, data)."""
    app_words = tokens(app["name"])
    pub_words = tokens(app.get("publisher", ""))
    if not app_words:
        return []
    others = [tokens(a["name"]) for a in apps if a["id"] != app["id"]]
    other_locations = {
        norm(a["install_location"]) for a in apps if a["id"] != app["id"] and a.get("install_location")
    }

    def belongs(folder_name):
        words = tokens(folder_name.lstrip("."))
        if len("".join(words)) < 3:
            return False
        mine = score(words, app_words)
        # If another installed app matches this folder better, it's theirs.
        return mine >= 0.75 and all(score(words, o) <= mine for o in others)

    found = {}

    def consider(path):
        n = norm(path)
        if n not in found and n not in other_locations:
            found[n] = path

    roots = [
        paths.roaming, paths.local, os.path.join(paths.local, "Programs"),
        paths.locallow, paths.programdata, *paths.program_files,
    ]
    for root in roots:
        for entry in _subdirs(root):
            if belongs(entry.name):
                consider(entry.path)
            elif pub_words and score(tokens(entry.name), pub_words) >= 0.8:
                # Publisher folder (e.g. AppData\Roaming\Mozilla) — look one level in,
                # but never offer the whole publisher folder.
                for child in _subdirs(entry.path):
                    if belongs(child.name):
                        consider(child.path)
    for entry in _subdirs(paths.home):
        if entry.name.startswith(".") and belongs(entry.name):
            consider(entry.path)  # e.g. ~\.vscode
    base = {"home": paths.home, "local": paths.local, "roaming": paths.roaming}
    lowered = app["name"].lower()
    for key, patterns in KNOWN_EXTRA_FOLDERS.items():
        if key in lowered:
            for pattern in patterns:
                for path in glob.glob(pattern.format(**base)):
                    if os.path.isdir(path):
                        consider(path)
    location = app.get("install_location")
    if location and os.path.isdir(location):
        consider(location)

    budget = Budget(budget_s)
    items = []
    for path in found.values():
        size, files, newest, _ = dir_stats(path, budget)
        items.append(
            Item(path, size, newest, note=f"{files:,} files", meta={"protected": paths.protected_reason(path)})
        )
    items.sort(key=lambda i: -i.size)
    return items
