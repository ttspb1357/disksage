"""Thin ctypes wrappers for the handful of Windows APIs DiskSage needs."""

import ctypes
import os
import re
import uuid
import winreg
from ctypes import wintypes

shell32 = ctypes.WinDLL("shell32")
ole32 = ctypes.WinDLL("ole32")
kernel32 = ctypes.WinDLL("kernel32")
version = ctypes.WinDLL("version")


class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8),
    ]


class SHQUERYRBINFO(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("i64Size", ctypes.c_longlong),
        ("i64NumItems", ctypes.c_longlong),
    ]


shell32.SHGetKnownFolderPath.argtypes = [
    ctypes.POINTER(GUID), wintypes.DWORD, wintypes.HANDLE, ctypes.POINTER(ctypes.c_wchar_p)
]
shell32.SHGetKnownFolderPath.restype = ctypes.c_long
ole32.CoTaskMemFree.argtypes = [ctypes.c_void_p]
ole32.CoTaskMemFree.restype = None
shell32.SHQueryRecycleBinW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(SHQUERYRBINFO)]
shell32.SHQueryRecycleBinW.restype = ctypes.c_long
shell32.SHEmptyRecycleBinW.argtypes = [wintypes.HWND, wintypes.LPCWSTR, wintypes.DWORD]
shell32.SHEmptyRecycleBinW.restype = ctypes.c_long
shell32.ShellExecuteW.argtypes = [
    wintypes.HWND, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.c_int
]
shell32.ShellExecuteW.restype = ctypes.c_void_p
kernel32.GetDriveTypeW.argtypes = [wintypes.LPCWSTR]
kernel32.GetDriveTypeW.restype = wintypes.UINT
kernel32.GetLongPathNameW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
kernel32.GetLongPathNameW.restype = wintypes.DWORD
kernel32.GetLogicalDrives.argtypes = []
kernel32.GetLogicalDrives.restype = wintypes.DWORD
kernel32.GetVolumeNameForVolumeMountPointW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
kernel32.GetVolumeNameForVolumeMountPointW.restype = wintypes.BOOL
version.GetFileVersionInfoSizeW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(wintypes.DWORD)]
version.GetFileVersionInfoSizeW.restype = wintypes.DWORD
version.GetFileVersionInfoW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p]
version.GetFileVersionInfoW.restype = wintypes.BOOL
version.VerQueryValueW.argtypes = [
    ctypes.c_void_p, wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.UINT)
]
version.VerQueryValueW.restype = wintypes.BOOL

KNOWN_FOLDERS = {
    "downloads": "{374DE290-123F-4565-9164-39C4925E467B}",
    "documents": "{FDD39AD0-238F-46AF-ADB4-6C85480369C7}",
    "desktop": "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}",
    "pictures": "{33E28130-4E1E-4676-835A-98395C3BC3BB}",
    "videos": "{18989B1D-99B5-455B-841C-AB7C74E4DDFC}",
    "music": "{4BD8D571-6D19-48D3-BE97-422220080E43}",
}


def known_folder(name):
    """The real location of Downloads, Documents, etc. (they can be moved, e.g. into OneDrive)."""
    guid = GUID.from_buffer_copy(uuid.UUID(KNOWN_FOLDERS[name]).bytes_le)
    out = ctypes.c_wchar_p()
    if shell32.SHGetKnownFolderPath(ctypes.byref(guid), 0, None, ctypes.byref(out)) != 0:
        return None
    try:
        return out.value
    finally:
        ole32.CoTaskMemFree(ctypes.cast(out, ctypes.c_void_p))


def long_path(path):
    """Expand 8.3 short names like C:\\Users\\JOHNSM~1 so path comparisons work."""
    buf = ctypes.create_unicode_buffer(32768)
    n = kernel32.GetLongPathNameW(path, buf, len(buf))
    return buf.value if 0 < n < len(buf) else path


def fixed_drives():
    mask = kernel32.GetLogicalDrives()
    letters = [f"{chr(65 + i)}:\\" for i in range(26) if mask >> i & 1]
    return [d for d in letters if kernel32.GetDriveTypeW(d) == 3]  # DRIVE_FIXED


def _reg_dword(hive, key, name):
    try:
        with winreg.OpenKey(hive, key) as k:
            value = winreg.QueryValueEx(k, name)[0]
            return value if isinstance(value, int) else None
    except OSError:
        return None


def recycle_bin_limit(path):
    """(enabled, max bytes or None if unknown) for the Recycle Bin on path's drive.

    Windows silently deletes for good anything bigger than this limit, and everything
    when the bin is switched off — so DiskSage checks before promising "restorable".
    """
    policy = r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    if 1 in (_reg_dword(winreg.HKEY_CURRENT_USER, policy, "NoRecycleFiles"),
             _reg_dword(winreg.HKEY_LOCAL_MACHINE, policy, "NoRecycleFiles")):
        return False, 0
    root = os.path.splitdrive(os.path.abspath(path))[0] + "\\"
    buf = ctypes.create_unicode_buffer(64)
    if not kernel32.GetVolumeNameForVolumeMountPointW(root, buf, len(buf)):
        return True, None
    match = re.search(r"\{[0-9A-Fa-f-]+\}", buf.value)
    if not match:
        return True, None
    key = rf"Software\Microsoft\Windows\CurrentVersion\Explorer\BitBucket\Volume\{match.group(0)}"
    if _reg_dword(winreg.HKEY_CURRENT_USER, key, "NukeOnDelete") == 1:
        return False, 0
    capacity_mb = _reg_dword(winreg.HKEY_CURRENT_USER, key, "MaxCapacity")
    return True, capacity_mb * 1024 * 1024 if capacity_mb else None


def recycle_bin_info():
    """(bytes, item count) across all drives' Recycle Bins."""
    info = SHQUERYRBINFO(cbSize=ctypes.sizeof(SHQUERYRBINFO))
    if shell32.SHQueryRecycleBinW(None, ctypes.byref(info)) != 0:
        return 0, 0
    return info.i64Size, info.i64NumItems


def empty_recycle_bin():
    # SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND — DiskSage asks first.
    hr = shell32.SHEmptyRecycleBinW(None, None, 0x1 | 0x2 | 0x4)
    return hr in (0, -2147418113)  # S_OK, or E_UNEXPECTED when it was already empty


def shell_open(target, params=None):
    """ShellExecute 'open' — shows UAC itself when the target needs admin rights."""
    return (shell32.ShellExecuteW(None, "open", target, params, None, 1) or 0) > 32


def file_version_strings(path):
    """ProductName, FileDescription, versions… embedded in an .exe, if any."""
    size = version.GetFileVersionInfoSizeW(path, None)
    if not size:
        return {}
    buf = ctypes.create_string_buffer(size)
    if not version.GetFileVersionInfoW(path, 0, size, buf):
        return {}

    ptr, length = ctypes.c_void_p(), wintypes.UINT()
    codepages = []
    if version.VerQueryValueW(buf, "\\VarFileInfo\\Translation", ctypes.byref(ptr), ctypes.byref(length)):
        words = (wintypes.WORD * (length.value // 2)).from_address(ptr.value)
        codepages = [f"{words[i]:04x}{words[i + 1]:04x}" for i in range(0, len(words) - 1, 2)]
    codepages += ["040904b0", "040904e4", "000004b0"]

    fields = {
        "product_name": "ProductName",
        "description": "FileDescription",
        "company": "CompanyName",
        "product_version": "ProductVersion",
        "file_version": "FileVersion",
    }
    out = {}
    for key, field in fields.items():
        for cp in codepages:
            query = f"\\StringFileInfo\\{cp}\\{field}"
            if version.VerQueryValueW(buf, query, ctypes.byref(ptr), ctypes.byref(length)) and length.value > 1:
                value = ctypes.wstring_at(ptr.value, length.value).rstrip("\x00").strip()
                if value:
                    out[key] = value
                    break
    return out
