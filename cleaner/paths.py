"""Where things live on this PC, and the rules for what DiskSage may never touch."""

import os
from dataclasses import dataclass, field

from . import winapi


def norm(path):
    return os.path.normcase(os.path.abspath(path))


def inside(path, parent):
    """True if path is parent itself or anywhere below it."""
    p, q = norm(path), norm(parent).rstrip("\\")
    return p == q or p.startswith(q + "\\")


@dataclass
class Paths:
    home: str
    local: str
    roaming: str
    locallow: str
    temp: str
    downloads: str
    documents: str
    desktop: str
    pictures: str
    videos: str
    music: str
    system_drive: str
    windir: str
    programdata: str
    program_files: list = field(default_factory=list)
    onedrive: list = field(default_factory=list)
    other_drives: list = field(default_factory=list)

    @classmethod
    def detect(cls):
        env = os.environ.get
        home = env("USERPROFILE") or os.path.expanduser("~")
        local = env("LOCALAPPDATA") or os.path.join(home, "AppData", "Local")
        system_drive = (env("SystemDrive") or "C:") + "\\"

        def known(name, fallback):
            return winapi.known_folder(name) or os.path.join(home, fallback)

        return cls(
            home=home,
            local=local,
            roaming=env("APPDATA") or os.path.join(home, "AppData", "Roaming"),
            locallow=os.path.join(home, "AppData", "LocalLow"),
            temp=winapi.long_path(os.path.abspath(env("TEMP") or os.path.join(local, "Temp"))),
            downloads=known("downloads", "Downloads"),
            documents=known("documents", "Documents"),
            desktop=known("desktop", "Desktop"),
            pictures=known("pictures", "Pictures"),
            videos=known("videos", "Videos"),
            music=known("music", "Music"),
            system_drive=system_drive,
            windir=env("WINDIR") or os.path.join(system_drive, "Windows"),
            programdata=env("ProgramData") or os.path.join(system_drive, "ProgramData"),
            program_files=sorted(
                {p for p in (env("ProgramFiles"), env("ProgramFiles(x86)"), env("ProgramW6432")) if p}
            ),
            onedrive=sorted(
                {p for p in (env("OneDrive"), env("OneDriveConsumer"), env("OneDriveCommercial")) if p}
            ),
            other_drives=[d for d in winapi.fixed_drives() if norm(d) != norm(system_drive)],
        )

    def in_cloud(self, path):
        return any(inside(path, od) for od in self.onedrive)

    def protected_reason(self, path, allow_exact=False):
        """Why DiskSage refuses to remove this path, or None if it's allowed.

        allow_exact lets a cache action empty a folder (e.g. Temp) without the
        folder itself being removable.
        """
        p = norm(path)
        if os.path.splitdrive(p)[1] in ("", "\\"):
            return "a whole drive"
        if not allow_exact:
            core = [
                self.home, self.local, self.roaming, self.locallow, self.temp,
                self.downloads, self.documents, self.desktop, self.pictures,
                self.videos, self.music, os.path.join(self.home, "AppData"), *self.onedrive,
            ]
            if any(p == norm(c) for c in core):
                return "one of your main folders"
        for parent in (self.windir, self.programdata, *self.program_files):
            if inside(p, parent):
                return "part of Windows or an installed program"
        if self.in_cloud(p):
            return "in OneDrive (deleting it here deletes it from the cloud too)"
        return None

    def display(self, path):
        if path.startswith("ollama:"):
            return "Ollama model " + path[len("ollama:"):]
        if path.startswith("recycle-bin:"):
            return "Recycle Bin"
        if inside(path, self.home):
            return "~" + path[len(self.home):]
        return path
