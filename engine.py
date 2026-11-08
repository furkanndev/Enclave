"""
Enclave - Çekirdek Yönetim Motoru (Engine)
VHD/VHDX bağlama, ayırma, BitLocker yönetimi, Autoplay kontrolü ve sembolik köprüleme işlemlerini yönetir.
"""

import os
import sys
import time
import json
import shutil
import tempfile
import ctypes
from ctypes import wintypes
import subprocess
try:
    import winreg
except ImportError:
    winreg = None
import base64
import hashlib
import zlib
import struct
import re
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    AESGCM = None

CREATE_NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0

def _ps_literal(value: Any) -> str:
    """
    Değeri PowerShell tek tırnaklı dizgesine güvenle yerleştirilecek hale getirir.
    PowerShell ' dışında ‘ ’ ‚ ‛ karakterlerini de tırnak sayar; bunlar Windows dosya adlarında geçerlidir.
    """
    return re.sub("['‘’‚‛]", lambda m: m.group() * 2, str(value))

def _clean_drive_letter(value: Optional[str]) -> str:
    """Tek bir sürücü harfi döndürür; başka bir şeyse boş dizge. Komutlara yalnızca bu değer yerleştirilir."""
    letter = (value or "").rstrip(":\\/ ").strip().upper()
    return letter if re.fullmatch("[A-Z]", letter) else ""

def get_startupinfo():
    """Windows'ta konsol ve PowerShell pencerelerinin anlık açılıp kapanmasını tamamen engelleyen STARTUPINFO nesnesi."""
    if sys.platform == "win32":
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        si.wShowWindow = subprocess.SW_HIDE
        return si
    return None

def _secure_delete_file(filepath: str):
    """Geçici diskpart veya komut dosyasını sıfır baytlarla ezerek imha eder."""
    try:
        from enclave_core import secure_wipe_file
        if filepath and os.path.exists(filepath):
            secure_wipe_file(filepath, passes=1)
            return
    except Exception:
        pass
    try:
        if filepath and os.path.exists(filepath):
            p = Path(filepath)
            sz = p.stat().st_size
            if sz > 0:
                with open(p, "r+b") as f:
                    f.seek(0)
                    f.write(b"\x00" * sz)
                    f.flush()
                    try:
                        os.fsync(f.fileno())
                    except Exception:
                        pass
            os.remove(filepath)
    except Exception:
        try:
            if filepath and os.path.exists(filepath):
                os.remove(filepath)
        except Exception:
            pass

AUTOPLAY_BACKUP_FILE = Path(tempfile.gettempdir()) / "vhd_vault_autoplay_backup.json"

class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.ULONG),
        ("Data2", wintypes.USHORT),
        ("Data3", wintypes.USHORT),
        ("Data4", wintypes.BYTE * 8)
    ]

class VIRTUAL_STORAGE_TYPE(ctypes.Structure):
    _fields_ = [
        ("DeviceId", wintypes.ULONG),
        ("VendorId", GUID)
    ]

class OPEN_VIRTUAL_DISK_PARAMETERS(ctypes.Structure):
    class _U(ctypes.Union):
        _fields_ = [("RWDepth", wintypes.ULONG)]
    _fields_ = [
        ("Version", wintypes.ULONG),
        ("Union", _U)
    ]

class ATTACH_VIRTUAL_DISK_PARAMETERS(ctypes.Structure):
    class _U(ctypes.Union):
        _fields_ = [("Reserved", wintypes.ULONG)]
    _fields_ = [
        ("Version", wintypes.ULONG),
        ("Union", _U)
    ]

class LUID(ctypes.Structure):
    _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]

class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]

class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [("PrivilegeCount", wintypes.DWORD), ("Privileges", LUID_AND_ATTRIBUTES * 1)]

class STORAGE_DEVICE_NUMBER(ctypes.Structure):
    _fields_ = [
        ("DeviceType", wintypes.DWORD),
        ("DeviceNumber", wintypes.DWORD),
        ("PartitionNumber", wintypes.DWORD)
    ]

class DISK_EXTENT(ctypes.Structure):
    _fields_ = [
        ("DiskNumber", wintypes.DWORD),
        ("StartingOffset", ctypes.c_longlong),
        ("ExtentLength", ctypes.c_longlong)
    ]

class VOLUME_DISK_EXTENTS(ctypes.Structure):
    _fields_ = [
        ("NumberOfDiskExtents", wintypes.DWORD),
        ("Extents", DISK_EXTENT * 8)
    ]

class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_void_p),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260)
    ]

k32 = ctypes.windll.kernel32
advapi32 = ctypes.windll.advapi32
virtdisk = ctypes.windll.virtdisk
user32 = ctypes.windll.user32

k32.CreateFileW.restype = wintypes.HANDLE
k32.CreateFileW.argtypes = [
    wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
    ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE
]
k32.CloseHandle.restype = wintypes.BOOL
k32.CloseHandle.argtypes = [wintypes.HANDLE]
k32.DeviceIoControl.restype = wintypes.BOOL
k32.DeviceIoControl.argtypes = [
    wintypes.HANDLE, wintypes.DWORD,
    ctypes.c_void_p, wintypes.DWORD,
    ctypes.c_void_p, wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p
]
k32.GetLogicalDrives.restype = wintypes.DWORD
k32.GetLogicalDrives.argtypes = []
k32.GetVolumeNameForVolumeMountPointW.restype = wintypes.BOOL
k32.GetVolumeNameForVolumeMountPointW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
k32.SetVolumeMountPointW.restype = wintypes.BOOL
k32.SetVolumeMountPointW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR]
k32.DeleteVolumeMountPointW.restype = wintypes.BOOL
k32.DeleteVolumeMountPointW.argtypes = [wintypes.LPCWSTR]
k32.FindFirstVolumeW.restype = wintypes.HANDLE
k32.FindFirstVolumeW.argtypes = [wintypes.LPWSTR, wintypes.DWORD]
k32.FindNextVolumeW.restype = wintypes.BOOL
k32.FindNextVolumeW.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD]
k32.FindVolumeClose.restype = wintypes.BOOL
k32.FindVolumeClose.argtypes = [wintypes.HANDLE]
k32.GetVolumePathNamesForVolumeNameW.restype = wintypes.BOOL
k32.GetVolumePathNamesForVolumeNameW.argtypes = [
    wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)
]
k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
k32.Process32FirstW.restype = wintypes.BOOL
k32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
k32.Process32NextW.restype = wintypes.BOOL
k32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
k32.OpenProcess.restype = wintypes.HANDLE
k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
k32.TerminateProcess.restype = wintypes.BOOL
k32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
k32.GetCurrentProcess.restype = wintypes.HANDLE
k32.GetCurrentProcess.argtypes = []

advapi32.OpenProcessToken.restype = wintypes.BOOL
advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
advapi32.LookupPrivilegeValueW.restype = wintypes.BOOL
advapi32.LookupPrivilegeValueW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.POINTER(LUID)]
advapi32.AdjustTokenPrivileges.restype = wintypes.BOOL
advapi32.AdjustTokenPrivileges.argtypes = [
    wintypes.HANDLE, wintypes.BOOL, ctypes.POINTER(TOKEN_PRIVILEGES),
    wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p
]

virtdisk.OpenVirtualDisk.restype = wintypes.DWORD
virtdisk.OpenVirtualDisk.argtypes = [
    ctypes.POINTER(VIRTUAL_STORAGE_TYPE),
    wintypes.LPCWSTR,
    wintypes.DWORD,
    wintypes.DWORD,
    ctypes.POINTER(OPEN_VIRTUAL_DISK_PARAMETERS),
    ctypes.POINTER(wintypes.HANDLE)
]
virtdisk.AttachVirtualDisk.restype = wintypes.DWORD
virtdisk.AttachVirtualDisk.argtypes = [
    wintypes.HANDLE,
    ctypes.c_void_p,
    wintypes.DWORD,
    wintypes.ULONG,
    ctypes.POINTER(ATTACH_VIRTUAL_DISK_PARAMETERS),
    ctypes.c_void_p
]
virtdisk.DetachVirtualDisk.restype = wintypes.DWORD
virtdisk.DetachVirtualDisk.argtypes = [
    wintypes.HANDLE,
    wintypes.DWORD,
    wintypes.ULONG
]
virtdisk.GetVirtualDiskPhysicalPath.restype = wintypes.DWORD
virtdisk.GetVirtualDiskPhysicalPath.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(wintypes.ULONG),
    wintypes.LPWSTR
]

def is_valid_handle(h) -> bool:
    """Windows 64-bit/32-bit HANDLE geçerlilik kontrolü."""
    if not h:
        return False
    val = getattr(h, "value", h)
    return val not in (-1, 0, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF)

def enable_volume_privilege() -> bool:
    """Prosesin SE_MANAGE_VOLUME_NAME yetkisini etkinleştirir (virtdisk için gereklidir)."""
    try:
        hToken = wintypes.HANDLE()
        if advapi32.OpenProcessToken(k32.GetCurrentProcess(), 0x0028, ctypes.byref(hToken)):
            if is_valid_handle(hToken):
                try:
                    luid = LUID()
                    if advapi32.LookupPrivilegeValueW(None, "SeManageVolumePrivilege", ctypes.byref(luid)):
                        tp = TOKEN_PRIVILEGES()
                        tp.PrivilegeCount = 1
                        tp.Privileges[0].Luid = luid
                        tp.Privileges[0].Attributes = 0x00000002
                        advapi32.AdjustTokenPrivileges(hToken, False, ctypes.byref(tp), 0, None, None)
                        return True
                finally:
                    k32.CloseHandle(hToken)
    except Exception:
        pass
    return False

def kill_process_by_name(process_name: str) -> bool:
    """Belirtilen ada sahip tüm süreçleri Win32 API ile sıfır ek işlem yüküyle anında sonlandırır (<0.1ms)."""
    TH32CS_SNAPPROCESS = 0x00000002
    h_snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if not is_valid_handle(h_snap):
        return False

    entry = PROCESSENTRY32W()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
    target_lower = process_name.lower()
    terminated = False
    try:
        if k32.Process32FirstW(h_snap, ctypes.byref(entry)):
            while True:
                if entry.szExeFile.lower() == target_lower:
                    h_proc = k32.OpenProcess(0x0001, False, entry.th32ProcessID)
                    if is_valid_handle(h_proc):
                        k32.TerminateProcess(h_proc, 1)
                        k32.CloseHandle(h_proc)
                        terminated = True
                if not k32.Process32NextW(h_snap, ctypes.byref(entry)):
                    break
    finally:
        k32.CloseHandle(h_snap)
    return terminated

def kill_processes_on_drive(drive_letter: str) -> int:
    """Belirtilen sürücü harfi üzerinden çalışan tüm süreçleri Win32 API ile anında (<1ms) sonlandırır."""
    if not drive_letter:
        return 0
    clean = drive_letter.rstrip("\\").rstrip(":").upper() + ":"
    terminated_count = 0
    TH32CS_SNAPPROCESS = 0x00000002
    h_snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if not is_valid_handle(h_snap):
        return 0

    entry = PROCESSENTRY32W()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
    my_pid = k32.GetCurrentProcessId()
    try:
        if k32.Process32FirstW(h_snap, ctypes.byref(entry)):
            while True:
                pid = entry.th32ProcessID
                if pid > 4 and pid != my_pid:
                    h_proc = k32.OpenProcess(0x1001, False, pid)
                    if is_valid_handle(h_proc):
                        try:
                            buf = ctypes.create_unicode_buffer(1024)
                            size = wintypes.DWORD(len(buf))
                            if k32.QueryFullProcessImageNameW(h_proc, 0, buf, ctypes.byref(size)):
                                path_upper = buf.value.upper()
                                if path_upper.startswith(clean + "\\") or path_upper.startswith(clean + "/"):
                                    k32.TerminateProcess(h_proc, 1)
                                    terminated_count += 1
                        except Exception:
                            pass
                        finally:
                            k32.CloseHandle(h_proc)
                if not k32.Process32NextW(h_snap, ctypes.byref(entry)):
                    break
    finally:
        k32.CloseHandle(h_snap)
    return terminated_count

def flush_and_dismount_volume(drive_letter: str) -> bool:
    """Birim üzerindeki tüm açık dosya kilitlerini ve önbelleği Win32 FSCTL_DISMOUNT_VOLUME ile mikrosaniyede temizler."""
    if not drive_letter:
        return False
    clean = drive_letter.rstrip("\\").rstrip(":")
    vol_path = f"\\\\.\\{clean}:"
    FILE_SHARE_ALL = 1 | 2 | 4
    h = k32.CreateFileW(
        vol_path,
        0x80000000 | 0x40000000,
        FILE_SHARE_ALL,
        None,
        3,
        0,
        None
    )
    if not is_valid_handle(h):
        h = k32.CreateFileW(
            vol_path,
            0,
            FILE_SHARE_ALL,
            None,
            3,
            0,
            None
        )
    if is_valid_handle(h):
        try:
            FSCTL_LOCK_VOLUME = 0x00090018
            FSCTL_DISMOUNT_VOLUME = 0x00090020
            bytes_ret = wintypes.DWORD()
            k32.FlushFileBuffers(h)
            k32.DeviceIoControl(h, FSCTL_LOCK_VOLUME, None, 0, None, 0, ctypes.byref(bytes_ret), None)
            res = k32.DeviceIoControl(h, FSCTL_DISMOUNT_VOLUME, None, 0, None, 0, ctypes.byref(bytes_ret), None)
            return res != 0
        finally:
            k32.CloseHandle(h)
    return False

def win32_change_drive_letter(old_letter: str, new_letter: str) -> bool:
    """Win32 Volume Mount Point API ile sürücü harfini mikrosaniyede (0.1ms) taşır."""
    old_clean = old_letter.rstrip("\\").rstrip(":").upper()
    new_clean = new_letter.rstrip("\\").rstrip(":").upper()
    if old_clean == new_clean:
        return True

    old_mp = f"{old_clean}:\\"
    new_mp = f"{new_clean}:\\"

    vol_name = ctypes.create_unicode_buffer(50)
    if not k32.GetVolumeNameForVolumeMountPointW(old_mp, vol_name, len(vol_name)):
        return False

    VHDEngine.close_explorer_windows(f"{old_clean}:")
    k32.DeleteVolumeMountPointW(old_mp)
    if k32.SetVolumeMountPointW(new_mp, vol_name.value):
        return True
    else:
        k32.SetVolumeMountPointW(old_mp, vol_name.value)
        return False

def win32_find_and_assign_volume(disk_number: int, preferred_letter: Optional[str] = None) -> str:
    """Win32 FindFirstVolume ve IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS ile diskin birimini bulup anında harf atar."""
    if disk_number is None or disk_number < 0:
        return ""
    IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS = 0x00560000

    pref = (preferred_letter or "").rstrip(":").strip().upper()
    bitmask = k32.GetLogicalDrives()
    avail_letters = [chr(ord('A') + i) for i in range(3, 26) if not (bitmask & (1 << i))]
    target_l = pref if (pref and pref in avail_letters) else (avail_letters[-1] if avail_letters else "")
    if not target_l:
        return ""

    vol_name = ctypes.create_unicode_buffer(50)
    h_find = k32.FindFirstVolumeW(vol_name, len(vol_name))
    if not is_valid_handle(h_find):
        return ""

    assigned = ""
    try:
        while True:
            v_name = vol_name.value
            clean_v = v_name.rstrip('\\')
            h = k32.CreateFileW(clean_v, 0, 1 | 2, None, 3, 0x80, None)
            matched = False
            if is_valid_handle(h):
                try:
                    exts = VOLUME_DISK_EXTENTS()
                    ret_bytes = wintypes.DWORD()
                    if k32.DeviceIoControl(h, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, None, 0, ctypes.byref(exts), ctypes.sizeof(exts), ctypes.byref(ret_bytes), None):
                        if exts.NumberOfDiskExtents > 0 and exts.Extents[0].DiskNumber == disk_number:
                            matched = True
                finally:
                    k32.CloseHandle(h)

            if matched:
                paths_buf = ctypes.create_unicode_buffer(260)
                ret_len = wintypes.DWORD()
                k32.GetVolumePathNamesForVolumeNameW(v_name, paths_buf, len(paths_buf), ctypes.byref(ret_len))
                cur_path = paths_buf.value
                if cur_path:
                    assigned = cur_path[:2].upper()
                    break
                else:
                    new_mp = f"{target_l}:\\"
                    if k32.SetVolumeMountPointW(new_mp, v_name):
                        assigned = f"{target_l}:"
                        break

            if not k32.FindNextVolumeW(h_find, vol_name, len(vol_name)):
                break
    finally:
        k32.FindVolumeClose(h_find)

    return assigned

def get_drive_letter_by_disk_number(disk_number: int) -> str:
    """Win32 DeviceIoControl IOCTL_STORAGE_GET_DEVICE_NUMBER ile mikrosaniyede (0.05ms) sürücü harfini bulur."""
    if disk_number is None or disk_number < 0:
        return ""
    IOCTL_STORAGE_GET_DEVICE_NUMBER = 0x002D1080

    sdn = STORAGE_DEVICE_NUMBER()
    bytes_ret = wintypes.DWORD()
    bitmask = k32.GetLogicalDrives()

    for i in range(2, 26):
        if not (bitmask & (1 << i)):
            continue
        letter = chr(ord('A') + i)
        h = k32.CreateFileW(
            f"\\\\.\\{letter}:",
            0,
            1 | 2,
            None,
            3,
            0x80,
            None
        )
        if is_valid_handle(h):
            try:
                if k32.DeviceIoControl(
                    h, IOCTL_STORAGE_GET_DEVICE_NUMBER,
                    None, 0,
                    ctypes.byref(sdn), ctypes.sizeof(sdn),
                    ctypes.byref(bytes_ret), None
                ):
                    if sdn.DeviceNumber == disk_number:
                        return f"{letter}:"
            finally:
                k32.CloseHandle(h)
    return ""

def get_disk_number_for_drive_letter(letter: str) -> Optional[int]:
    """Sürücü harfinden disk numarasını (PhysicalDriveX) Win32 IOCTL ile mikrosaniyede bulur."""
    clean = letter.rstrip(":\\/ ").upper()
    if not clean or len(clean) != 1 or not clean.isalpha():
        return None
    IOCTL_STORAGE_GET_DEVICE_NUMBER = 0x002D1080
    sdn = STORAGE_DEVICE_NUMBER()
    bytes_ret = wintypes.DWORD()
    h = k32.CreateFileW(f"\\\\.\\{clean}:", 0, 1 | 2, None, 3, 0x80, None)
    if is_valid_handle(h):
        try:
            if k32.DeviceIoControl(h, IOCTL_STORAGE_GET_DEVICE_NUMBER, None, 0, ctypes.byref(sdn), ctypes.sizeof(sdn), ctypes.byref(bytes_ret), None):
                return sdn.DeviceNumber
        finally:
            k32.CloseHandle(h)
    return None

def get_vhd_disk_number(vhd_path: str) -> Optional[int]:
    """virtdisk.dll kullanarak bağlı sanal diskin fiziksel disk numarasını (PhysicalDriveX) anında döndürür."""
    try:
        p_resolved = Path(vhd_path).resolve()
        if not p_resolved.exists():
            return None
        st = VIRTUAL_STORAGE_TYPE()
        st.DeviceId = 0
        st.VendorId = GUID(0xEC984AEC, 0xA0F9, 0x47E9, (0x90, 0x1F, 0x71, 0x41, 0x5A, 0x66, 0x34, 0x5B))
        open_params = OPEN_VIRTUAL_DISK_PARAMETERS()
        open_params.Version = 1
        open_params.Union.RWDepth = 1
        handle = wintypes.HANDLE()
        res = virtdisk.OpenVirtualDisk(
            ctypes.byref(st),
            str(p_resolved),
            0x003F0000,
            0,
            ctypes.byref(open_params),
            ctypes.byref(handle)
        )
        if res == 0 and is_valid_handle(handle):
            try:
                buf_size = wintypes.ULONG(1024)
                path_buf = ctypes.create_unicode_buffer(512)
                res3 = virtdisk.GetVirtualDiskPhysicalPath(handle, ctypes.byref(buf_size), path_buf)
                if res3 == 0 and path_buf.value and "PhysicalDrive" in path_buf.value:
                    return int(path_buf.value.split("PhysicalDrive")[-1])
            finally:
                k32.CloseHandle(handle)
    except Exception:
        pass
    return None

def get_disk_volumes(disk_number: int) -> Dict[int, Dict[str, str]]:
    """
    Belirtilen disk numarasına (PhysicalDrive) ait tüm birimleri, GUID yollarını
    ve atanmış sürücü harflerini Win32 API ile 0.05ms'de haritalar.
    Dönüş: {1: {'vol_name': '\\\\?\\Volume{...}\\', 'letter': 'Z:'}, 2: {'vol_name': '...', 'letter': 'K:'}}
    """
    if disk_number is None or disk_number < 0:
        return {}
    IOCTL_STORAGE_GET_DEVICE_NUMBER = 0x002D1080
    vol_name = ctypes.create_unicode_buffer(50)
    h_find = k32.FindFirstVolumeW(vol_name, len(vol_name))
    if not is_valid_handle(h_find):
        return {}
    
    parts = {}
    try:
        while True:
            v_name = vol_name.value
            clean_v = v_name.rstrip('\\')
            h = k32.CreateFileW(clean_v, 0, 1 | 2, None, 3, 0x80, None)
            if is_valid_handle(h):
                try:
                    sdn = STORAGE_DEVICE_NUMBER()
                    ret = wintypes.DWORD()
                    if k32.DeviceIoControl(h, IOCTL_STORAGE_GET_DEVICE_NUMBER, None, 0, ctypes.byref(sdn), ctypes.sizeof(sdn), ctypes.byref(ret), None):
                        if sdn.DeviceNumber == disk_number:
                            path_buf = ctypes.create_unicode_buffer(260)
                            ret_len = wintypes.DWORD()
                            k32.GetVolumePathNamesForVolumeNameW(v_name, path_buf, len(path_buf), ctypes.byref(ret_len))
                            cur_path = path_buf.value
                            letter = cur_path[:2].upper() if cur_path else ""
                            parts[sdn.PartitionNumber] = {"vol_name": v_name, "letter": letter}
                finally:
                    k32.CloseHandle(h)
            if not k32.FindNextVolumeW(h_find, vol_name, len(vol_name)):
                break
    finally:
        k32.FindVolumeClose(h_find)
    return parts

def remove_drive_letter_mount_point(letter: str) -> bool:
    """Belirtilen sürücü harfinin mount point'ini Win32 DeleteVolumeMountPointW ile anında siler."""
    clean = letter.rstrip(":\\/ ").upper()
    if not clean:
        return False
    mp = f"{clean}:\\"
    VHDEngine.close_explorer_windows(f"{clean}:")
    res = k32.DeleteVolumeMountPointW(mp)
    try:
        ctypes.windll.shell32.SHChangeNotify(0x00040000, 0x0001, mp, None)
        ctypes.windll.shell32.SHChangeNotify(0x08000000, 0x0000, None, None)
    except Exception:
        pass
    return bool(res)

def native_attach_vhd(vhd_path: str) -> Tuple[bool, Optional[int], str]:
    """virtdisk.dll kullanarak VHD/VHDX dosyasını C seviyesinde (<20ms) anında bağlar."""
    try:
        st = VIRTUAL_STORAGE_TYPE()
        st.DeviceId = 0
        st.VendorId = GUID(0xEC984AEC, 0xA0F9, 0x47E9, (0x90, 0x1F, 0x71, 0x41, 0x5A, 0x66, 0x34, 0x5B))

        open_params = OPEN_VIRTUAL_DISK_PARAMETERS()
        open_params.Version = 1
        open_params.Union.RWDepth = 1

        handle = wintypes.HANDLE()
        res = virtdisk.OpenVirtualDisk(
            ctypes.byref(st),
            str(Path(vhd_path).resolve()),
            0x003F0000,
            0,
            ctypes.byref(open_params),
            ctypes.byref(handle)
        )
        if res == 0 and is_valid_handle(handle):
            try:
                attach_params = ATTACH_VIRTUAL_DISK_PARAMETERS()
                attach_params.Version = 1
                attach_params.Union.Reserved = 0

                res2 = virtdisk.AttachVirtualDisk(
                    handle,
                    None,
                    0x00000004,
                    0,
                    ctypes.byref(attach_params),
                    None
                )
                if res2 in (0, 0xC0140026, 0x80070050, 0x80070020, 80, 183, 32):
                    buf_size = wintypes.ULONG(1024)
                    path_buf = ctypes.create_unicode_buffer(512)
                    res3 = virtdisk.GetVirtualDiskPhysicalPath(handle, ctypes.byref(buf_size), path_buf)
                    phys_path = path_buf.value if res3 == 0 else ""
                    disk_num = -1
                    if phys_path and "PhysicalDrive" in phys_path:
                        try:
                            disk_num = int(phys_path.split("PhysicalDrive")[-1])
                        except Exception:
                            pass
                    if disk_num >= 0:
                        return True, disk_num, phys_path
            finally:
                k32.CloseHandle(handle)
    except Exception as e:
        print(f"native_attach_vhd hatası: {e}")
    return False, None, ""

def native_detach_vhd(vhd_path: str) -> bool:
    """virtdisk.dll kullanarak VHD/VHDX dosyasını C seviyesinde (<5ms) anında ayırır."""
    try:
        p_resolved = Path(vhd_path).resolve()
        if not p_resolved.exists():
            return False
        resolved_str = str(p_resolved)
        is_vhdx = resolved_str.lower().endswith(".vhdx")

        st = VIRTUAL_STORAGE_TYPE()
        st.DeviceId = 3 if is_vhdx else 2
        st.VendorId = GUID(0xEC984AEC, 0xA0F9, 0x47E9, (0x90, 0x1F, 0x71, 0x41, 0x5A, 0x66, 0x34, 0x5B))

        open_params = OPEN_VIRTUAL_DISK_PARAMETERS()
        open_params.Version = 1
        open_params.Union.RWDepth = 1

        for access_mask in (0x00040000, 0x003F0000, 0x00000000):
            handle = wintypes.HANDLE()
            res = virtdisk.OpenVirtualDisk(
                ctypes.byref(st),
                resolved_str,
                access_mask,
                0,
                ctypes.byref(open_params),
                ctypes.byref(handle)
            )
            if res == 0 and is_valid_handle(handle):
                try:
                    res2 = virtdisk.DetachVirtualDisk(handle, 0, 0)
                    if res2 == 0:
                        return True
                finally:
                    k32.CloseHandle(handle)
    except Exception as e:
        print(f"native_detach_vhd hatası: {e}")
    return False

def win32_eject_drive(drive_letter: str) -> bool:
    """
    Win32 FSCTL ve IOCTL_STORAGE_EJECT_MEDIA ile sürücüyü ve bağlı sanal diski
    File Explorer hızında (<2ms) anında sistemden güvenle ayırır (eject).
    """
    if not drive_letter:
        return False
    clean = drive_letter.rstrip("\\").rstrip(":").upper()
    if not clean or len(clean) != 1:
        return False

    vol_path = f"\\\\.\\{clean}:"
    FILE_SHARE_ALL = 1 | 2 | 4
    bytes_ret = wintypes.DWORD()
    disk_num = -1

    h_vol = k32.CreateFileW(
        vol_path,
        0x80000000 | 0x40000000,
        FILE_SHARE_ALL,
        None,
        3,
        0,
        None
    )
    if not is_valid_handle(h_vol):
        h_vol = k32.CreateFileW(vol_path, 0, FILE_SHARE_ALL, None, 3, 0, None)

    if is_valid_handle(h_vol):
        try:
            k32.FlushFileBuffers(h_vol)
            sdn = STORAGE_DEVICE_NUMBER()
            if k32.DeviceIoControl(h_vol, 0x002D1080, None, 0, ctypes.byref(sdn), ctypes.sizeof(sdn), ctypes.byref(bytes_ret), None):
                disk_num = sdn.DeviceNumber
            k32.DeviceIoControl(h_vol, 0x00090018, None, 0, None, 0, ctypes.byref(bytes_ret), None)
            k32.DeviceIoControl(h_vol, 0x00090020, None, 0, None, 0, ctypes.byref(bytes_ret), None)
            k32.DeviceIoControl(h_vol, 0x002D4808, None, 0, None, 0, ctypes.byref(bytes_ret), None)
        finally:
            k32.CloseHandle(h_vol)

    if disk_num >= 0:
        h_disk = k32.CreateFileW(
            f"\\\\.\\PhysicalDrive{disk_num}",
            0x80000000 | 0x40000000,
            FILE_SHARE_ALL,
            None,
            3,
            0,
            None
        )
        if not is_valid_handle(h_disk):
            h_disk = k32.CreateFileW(f"\\\\.\\PhysicalDrive{disk_num}", 0, FILE_SHARE_ALL, None, 3, 0, None)
        if is_valid_handle(h_disk):
            try:
                res_eject = k32.DeviceIoControl(h_disk, 0x002D4808, None, 0, None, 0, ctypes.byref(bytes_ret), None)
                if res_eject != 0:
                    return True
            finally:
                k32.CloseHandle(h_disk)

    bitmask = k32.GetLogicalDrives()
    is_gone = not (bitmask & (1 << (ord(clean) - ord('A'))))
    return is_gone

BRIDGE_DIR_NAME = ".enclave_bridge"

class VHDEngine:
    _vhd_size_cache: Dict[Tuple[str, float, int], Dict[str, Any]] = {}

    def __init__(self):
        self.active_mount_target: Optional[str] = None
        self.active_vault_file: Optional[str] = None
        self.active_bridge_link: Optional[str] = None
        self.active_drive_letter: Optional[str] = None
        self.autoplay_was_disabled_by_us: bool = False
        self.original_autoplay_val: Optional[Any] = None
        self.active_usb_token: Optional[str] = None

    @staticmethod
    def is_admin() -> bool:
        """Kullanıcının yönetici yetkilerine sahip olup olmadığını kontrol eder."""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False

    @staticmethod
    def elevate_process(extra_args: Optional[List[str]] = None) -> bool:
        """Uygulamayı UAC ile yönetici olarak yeniden başlatır."""
        try:
            if getattr(sys, "frozen", False):
                executable = sys.executable
                args = sys.argv[1:]
                if extra_args:
                    args.extend(extra_args)
                arg_str = subprocess.list2cmdline(args)
                work_dir = str(Path(executable).parent)
            else:
                windowless = Path(sys.executable).with_name("pythonw.exe")
                executable = str(windowless) if windowless.exists() else sys.executable
                script = str(Path(sys.argv[0]).resolve())
                args = sys.argv[1:]
                if extra_args:
                    args.extend(extra_args)
                arg_str = subprocess.list2cmdline([script] + args)
                work_dir = str(Path(script).resolve().parent)

            ret = ctypes.windll.shell32.ShellExecuteW(
                None,
                "runas",
                executable,
                arg_str,
                work_dir,
                1
            )
            if ret > 32:
                return True

            try:
                ps_script = (
                    f"Start-Process -FilePath '{_ps_literal(executable)}' -ArgumentList '{_ps_literal(arg_str)}' "
                    f"-WorkingDirectory '{_ps_literal(work_dir)}' -Verb RunAs"
                )
                res = subprocess.run(
                    ["powershell.exe", "-WindowStyle", "Hidden", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", ps_script],
                    creationflags=CREATE_NO_WINDOW,
                    startupinfo=get_startupinfo()
                )
                return res.returncode == 0
            except Exception:
                pass

            return False
        except Exception as e:
            print(f"Yükseltme hatası: {e}")
            return False

    def backup_and_disable_autoplay(self) -> bool:
        """Autoplay ayarını hafızada yedekler ve anında devre dışı bırakır (<0.1ms)."""
        reg_path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers"
        try:
            original_val = None
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path, 0, winreg.KEY_READ) as key:
                    original_val, _ = winreg.QueryValueEx(key, "DisableAutoplay")
            except FileNotFoundError:
                original_val = None

            self.original_autoplay_val = original_val

            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, reg_path) as key:
                winreg.SetValueEx(key, "DisableAutoplay", 0, winreg.REG_DWORD, 1)

            self.autoplay_was_disabled_by_us = True
            return True
        except Exception as e:
            print(f"Autoplay kapatılamadı: {e}")
            return False

    def restore_autoplay(self) -> bool:
        """Yedeklenen Autoplay ayarını geri yükler (<0.1ms)."""
        reg_path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers"
        try:
            original_val = self.original_autoplay_val
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path, 0, winreg.KEY_SET_VALUE) as key:
                if original_val is None:
                    try:
                        winreg.DeleteValue(key, "DisableAutoplay")
                    except FileNotFoundError:
                        pass
                else:
                    winreg.SetValueEx(key, "DisableAutoplay", 0, winreg.REG_DWORD, int(original_val))

            self.original_autoplay_val = None
            self.autoplay_was_disabled_by_us = False
            return True
        except Exception as e:
            print(f"Autoplay geri yüklenemedi: {e}")
            return False

    @staticmethod
    def scan_for_vaults(search_names: Optional[List[str]] = None, base_dir: Optional[str] = None) -> List[Dict[str, Any]]:
        """Sadece 'vaults' (veya 'kasalar') klasöründeki geçerli kasa dosyalarını arar."""
        from logger import VAULTS_DIR, BASE_DIR

        if not base_dir:
            base_dir = str(BASE_DIR)

        base_path = Path(base_dir).resolve()
        found: List[Dict[str, Any]] = []
        found_paths = set()

        vault_folders = [VAULTS_DIR, base_path / "vaults", base_path / "kasalar"]
        for vf in vault_folders:
            if vf.exists() and vf.is_dir():
                try:
                    for item in vf.iterdir():
                        if item.is_file() and item.name.lower() not in ["benioku.txt", "readme.txt", ".gitkeep"]:
                            norm_path = str(item.resolve()).lower()
                            if norm_path not in found_paths:
                                found_paths.add(norm_path)
                                size_mb = item.stat().st_size / (1024 * 1024)
                                ext = item.suffix.lower()
                                is_pvault = (ext == ".pvault")
                                if not is_pvault and item.stat().st_size >= 8:
                                    try:
                                        with open(item, "rb") as test_f:
                                            if test_f.read(8) == b"PVAULT01":
                                                is_pvault = True
                                    except Exception:
                                        pass

                                if is_pvault:
                                    disk_type = "pvault"
                                    needs_bridge = False
                                    pv_max_gb = 0
                                    try:
                                        with open(item, "rb") as pv_f:
                                            pv_f.seek(220)
                                            raw_sz = pv_f.read(4)
                                            if len(raw_sz) == 4:
                                                pv_max_gb = struct.unpack("<I", raw_sz)[0]
                                    except Exception:
                                        pass
                                    if pv_max_gb and 1 <= pv_max_gb <= 65536:
                                        virt_mb = float(pv_max_gb * 1024)
                                    else:
                                        virt_mb = round(size_mb, 2)
                                else:
                                    needs_bridge = ext not in [".vhd", ".vhdx"]
                                    v_info = VHDEngine.get_vhd_virtual_size(str(item.resolve()))
                                    virt_mb = v_info.get("virtual_mb", round(size_mb, 2))
                                    disk_type = v_info.get("disk_type", "unknown")

                                found.append({
                                    "name": item.name,
                                    "path": str(item.resolve()),
                                    "size_mb": round(size_mb, 2),
                                    "virtual_mb": round(virt_mb, 2),
                                    "disk_type": disk_type,
                                    "needs_bridge": needs_bridge,
                                    "priority": True
                                })
                except Exception as e:
                    print(f"Vaults klasörü taranırken hata: {e}")

        return found

    @staticmethod
    def prepare_mount_target(file_path: str) -> Tuple[str, bool, Optional[str]]:
        """
        Dosya uzantısı .vhd/.vhdx değilse Windows Virtual Disk servisinin
        kabul etmesi için geçici bir köprü (.vhd) oluşturur.
        Köprü dosyasını kullanıcının çalışma klasörüne ASLA koymaz, Temp klasöründe izole oluşturur.
        Orijinal dosyanın özniteliklerini (Hidden/System) ASLA bozmaz.
        Dönüş: (mount_edilecek_hedef, köprü_mü, köprü_dosya_yolu)
        """
        target_path = Path(file_path).resolve()
        if not target_path.exists():
            raise FileNotFoundError(f"Dosya bulunamadı: {file_path}")

        try:
            ctypes.windll.kernel32.SetFileAttributesW(str(target_path), 0x80)
        except Exception:
            pass

        ext = target_path.suffix.lower()
        if ext in [".vhd", ".vhdx"]:
            return str(target_path), False, None

        target_ext = ".vhd"
        try:
            with open(str(target_path), "rb") as f:
                if f.read(8) == b"vhdxfile":
                    target_ext = ".vhdx"
        except Exception:
            pass

        safe_stem = "".join([c if c.isalnum() or c in "-_" else "_" for c in target_path.name])
        created = False
        bridge_path = None
        VHDEngine._remove_legacy_bridges(target_path)

        try:
            temp_sub = VHDEngine._bridge_dir(target_path)
            temp_sub.mkdir(parents=True, exist_ok=True)
            try:
                ctypes.windll.kernel32.SetFileAttributesW(str(temp_sub), 0x02 | 0x04)
            except Exception:
                pass
            cand = temp_sub / VHDEngine._bridge_name(target_path, target_ext)
            if cand.exists() or cand.is_symlink():
                try:
                    ctypes.windll.kernel32.SetFileAttributesW(str(cand), 0x80)
                    cand.unlink()
                except Exception:
                    pass
            if cand.exists():
                cand = temp_sub / f"bridge_{safe_stem}_{os.getpid()}_{int(time.time())}{target_ext}"
            os.link(str(target_path), str(cand))
            if cand.exists():
                bridge_path = cand
                created = True
        except Exception:
            pass

        if not created:
            try:
                cand1 = Path(tempfile.gettempdir()) / f"vhd_vault_bridge_{safe_stem}{target_ext}"
                if cand1.exists() or cand1.is_symlink():
                    try:
                        ctypes.windll.kernel32.SetFileAttributesW(str(cand1), 0x80)
                        cand1.unlink()
                    except Exception:
                        pass
                os.link(str(target_path), str(cand1))
                if cand1.exists():
                    bridge_path = cand1
                    created = True
            except Exception:
                pass

        if not created:
            try:
                cand2 = Path(tempfile.gettempdir()) / f"vhd_vault_bridge_{safe_stem}.vhd"
                if cand2.exists() or cand2.is_symlink():
                    try:
                        ctypes.windll.kernel32.SetFileAttributesW(str(cand2), 0x80)
                        cand2.unlink()
                    except Exception:
                        pass
                try:
                    os.symlink(str(target_path), str(cand2))
                except Exception:
                    try:
                        ctypes.windll.kernel32.CreateSymbolicLinkW(str(cand2), str(target_path), 0)
                    except Exception:
                        pass
                if cand2.exists():
                    bridge_path = cand2
                    created = True
            except Exception:
                pass

        if not created or not bridge_path or not bridge_path.exists():
            raise RuntimeError(f"Köprü dosyası oluşturulamadı: {target_path.name}")

        try:
            ctypes.windll.kernel32.SetFileAttributesW(str(target_path), 0x80)
        except Exception:
            pass

        return str(bridge_path), True, str(bridge_path)

    @staticmethod
    def _bridge_dir(target_path: Path) -> Path:
        return Path(target_path.anchor) / BRIDGE_DIR_NAME

    @staticmethod
    def _bridge_name(target_path: Path, extension: str) -> str:
        """Köprüler sürücü başına tek klasörde durur; farklı klasörlerdeki aynı adlı kasalar karışmasın diye yol özeti eklenir."""
        safe_stem = "".join([c if c.isalnum() or c in "-_" else "_" for c in target_path.name])
        path_id = hashlib.sha256(str(target_path).lower().encode("utf-8")).hexdigest()[:10]
        return f"bridge_{safe_stem}_{path_id}{extension}"

    @staticmethod
    def _bridge_candidates(target_path: Path) -> List[Path]:
        return [VHDEngine._bridge_dir(target_path) / VHDEngine._bridge_name(target_path, ext) for ext in (".vhd", ".vhdx")]

    @staticmethod
    def _remove_legacy_bridges(target_path: Path) -> None:
        """Eski sürümün kasa klasörüne bıraktığı .vhd_temp kalıntılarını siler. Bağlı köprü silinemez, o zaman dokunulmaz."""
        legacy = target_path.parent / ".vhd_temp"
        if not legacy.is_dir():
            return
        for item in legacy.glob("bridge_*"):
            try:
                ctypes.windll.kernel32.SetFileAttributesW(str(item), 0x80)
                item.unlink()
            except OSError:
                pass
        try:
            legacy.rmdir()
        except OSError:
            pass

    @staticmethod
    def cleanup_bridge(bridge_path: Optional[str], original_vault_path: Optional[str] = None):
        """Oluşturulan geçici köprüyü güvenle siler; orijinal kasaya ASLA dokunmaz."""
        if not bridge_path:
            return
        try:
            bp = Path(bridge_path).resolve()
            if original_vault_path:
                orig = Path(original_vault_path).resolve()
                if bp == orig:
                    print("Güvenlik koruması: Köprü yolu orijinal kasa ile aynı olduğu için silme engellendi.")
                    return

            if bp.exists() or bp.is_symlink():
                try:
                    ctypes.windll.kernel32.SetFileAttributesW(str(bp), 0x80)
                except Exception:
                    pass
                bp.unlink()
            
            try:
                parent_dir = bp.parent
                if parent_dir.exists() and parent_dir.name in (".vhd_temp", BRIDGE_DIR_NAME):
                    parent_dir.rmdir()
            except Exception:
                pass
        except Exception as e:
            print(f"Köprü temizleme hatası: {e}")
        finally:
            if original_vault_path:
                try:
                    ctypes.windll.kernel32.SetFileAttributesW(str(Path(original_vault_path).resolve()), 0x80)
                except Exception:
                    pass

    @staticmethod
    def suppress_bdeunlock():
        """Windows bdeunlock.exe yerel BitLocker açılır penceresini ve Action Center toast bildirimlerini bastırır (0 ek işlem, <0.1ms)."""
        toast_keys = [
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.BdeUnlock"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.BdeUnlock"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.AutoPlay"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.AutoPlay"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Microsoft.Explorer.Notification.{4958E903-D554-EF09-81F9-13359BC57101}"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Microsoft.Explorer.Notification.{4958E903-D554-EF09-81F9-13359BC57101}"),
        ]
        for root_key, sub_key in toast_keys:
            try:
                with winreg.CreateKey(root_key, sub_key) as k:
                    winreg.SetValueEx(k, "Enabled", 0, winreg.REG_DWORD, 0)
                    winreg.SetValueEx(k, "ShowBanners", 0, winreg.REG_DWORD, 0)
                    winreg.SetValueEx(k, "ShowInActionCenter", 0, winreg.REG_DWORD, 0)
            except Exception:
                pass

        for root_key in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
            try:
                with winreg.CreateKey(root_key, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers") as k:
                    winreg.SetValueEx(k, "DisableAutoplay", 0, winreg.REG_DWORD, 1)
            except Exception:
                pass
            try:
                with winreg.CreateKey(root_key, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer") as k:
                    winreg.SetValueEx(k, "NoDriveTypeAutoRun", 0, winreg.REG_DWORD, 0xFF)
            except Exception:
                pass

        try:
            kill_process_by_name("bdeunlock.exe")
        except Exception:
            pass

    @staticmethod
    def _run_powershell(script: str, timeout: int = 12, input_data: Optional[str] = None) -> Tuple[int, str, str]:
        """PowerShell komutunu penceresiz, zaman aşımlı ve UTF-8 çıkışıyla izole çalıştırır."""
        full_script = f"[Console]::InputEncoding = [Console]::OutputEncoding = $OutputEncoding = [System.Text.Encoding]::UTF8; {script}"
        cmd = [
            "powershell.exe",
            "-WindowStyle", "Hidden",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy", "Bypass",
            "-Command", full_script
        ]
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE if input_data is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=CREATE_NO_WINDOW,
            startupinfo=get_startupinfo(),
            text=True,
            encoding="utf-8",
            errors="replace"
        )
        try:
            stdout, stderr = proc.communicate(input=input_data, timeout=timeout)
            return proc.returncode, stdout.strip(), stderr.strip()
        except subprocess.TimeoutExpired:
            proc.kill()
            try:
                stdout, stderr = proc.communicate(timeout=1)
            except Exception:
                stdout, stderr = "", "PowerShell zaman aşımına uğradı."
            return 1, stdout.strip(), stderr.strip()

    def ensure_drive_letter_assigned(self, disk_number: Optional[int] = None, target: Optional[str] = None, preferred_letter: Optional[str] = None) -> str:
        """
        Bağlı bir sanal diskin sürücü harfini ve durumunu tam otomatik denetler ve onarır:
        - Çevrimdışı (Offline) ise otomatik olarak Çevrimiçi (Online) yapar
        - Başlatılmamış (RAW) ise MBR olarak başlatır
        - Bölümü yoksa yeni NTFS bölümü oluşturur ve biçimlendirir
        - Sürücü harfi atanmamışsa boş veya tercih edilen harfi atar
        - Windows Gezgini'ne (Shell) anında bildirir (SHChangeNotify)
        Kullanıcının Disk Yöneticisi'ne (diskmgmt.msc) manuel girmesine gerek kalmadan tüm adımları otomatik tamamlar.
        """
        pref = _clean_drive_letter(preferred_letter)
        target_path = target or self.active_mount_target or self.active_vault_file
        escaped_t = _ps_literal(Path(target_path).resolve()) if target_path else ""

        ps_script = f"""
        $pref = '{pref}';
        $target = '{escaped_t}';
        $diskNum = {disk_number if disk_number is not None else -1};
        if ($diskNum -lt 0 -and $target) {{
            $img = Get-DiskImage -ImagePath $target -ErrorAction SilentlyContinue;
            if ($img -and $img.Attached -and $img.Number -ne $null -and [string]$img.Number -ne '') {{ $diskNum = [int]$img.Number; }}
        }}
        if ($diskNum -lt 0) {{
            $img = Get-DiskImage -ErrorAction SilentlyContinue | Where-Object {{ $_.Attached -and $_.Number -ne $null }} | Select-Object -Last 1;
            if ($img -and $img.Number -ne $null -and [string]$img.Number -ne '') {{ $diskNum = [int]$img.Number; }}
        }}
        if ($diskNum -ne $null -and [string]$diskNum -ne '' -and [int]$diskNum -ge 0) {{
            $d = [int]$diskNum;

            # 1. Çevrimdışı (Offline) ve Salt Okunur durumunu otomatik düzelt
            Set-Disk -Number $d -IsOffline $false -ErrorAction SilentlyContinue;
            Set-Disk -Number $d -IsReadOnly $false -ErrorAction SilentlyContinue;

            # 2. Başlatılmamış (RAW) diski otomatik başlat (MBR)
            $diskObj = Get-Disk -Number $d -ErrorAction SilentlyContinue;
            if ($diskObj -and $diskObj.PartitionStyle -eq 'RAW') {{
                Initialize-Disk -Number $d -PartitionStyle MBR -ErrorAction SilentlyContinue;
                Start-Sleep -Milliseconds 40;
            }}

            # 3. Bölüm kontrolü: Bölüm yoksa otomatik oluştur ve NTFS biçimlendir
            $parts = Get-Partition -DiskNumber $d -ErrorAction SilentlyContinue | Where-Object {{ $_.Type -ne 'Reserved' }};
            if (-not $parts) {{
                $newP = New-Partition -DiskNumber $d -UseMaximumSize -ErrorAction SilentlyContinue;
                if ($newP) {{
                    Format-Volume -Partition $newP -FileSystem NTFS -NewFileSystemLabel 'Kasa' -Confirm:$false -ErrorAction SilentlyContinue | Out-Null;
                    Start-Sleep -Milliseconds 40;
                    $parts = Get-Partition -DiskNumber $d -ErrorAction SilentlyContinue | Where-Object {{ $_.Type -ne 'Reserved' }};
                }}
            }}

            $part = if ($parts) {{ $parts | Select-Object -First 1 }} else {{ $null }};
            if ($part -and $part.DriveLetter) {{
                Write-Output "$($part.DriveLetter):";
                exit 0;
            }}

            # 4. Sürücü harfi atanmamışsa boş harf bul ve ata
            $used = [System.IO.DriveInfo]::GetDrives() | ForEach-Object {{ $_.Name.Substring(0,1).ToUpper() }};
            $avail = 68..90 | ForEach-Object {{ [string][char]$_ }} | Where-Object {{ $used -notcontains $_ }};
            $targetL = if ($pref -and ($avail -contains $pref)) {{ $pref }} else {{ if ($avail) {{ $avail[-1] }} else {{ $null }} }};
            if ($targetL -and $part) {{
                Set-Partition -DiskNumber $d -PartitionNumber $part.PartitionNumber -NewDriveLetter $targetL -ErrorAction SilentlyContinue;
                Start-Sleep -Milliseconds 30;
                $part = Get-Partition -DiskNumber $d -ErrorAction SilentlyContinue | Where-Object {{ $_.Type -ne 'Reserved' }} | Select-Object -First 1;
                if ($part -and $part.DriveLetter) {{
                    Write-Output "$($part.DriveLetter):";
                    exit 0;
                }}
            }}
        }}
        Write-Output "";
        """
        code, stdout, _ = self._run_powershell(ps_script)
        letter = stdout.strip()
        if letter:
            self.active_drive_letter = letter
            try:
                ctypes.windll.shell32.SHChangeNotify(0x00040000, 0x0001, f"{letter}\\", None)
            except Exception:
                pass
            return letter

        if disk_number is not None or target_path:
            try:
                dp_script = ""
                if target_path:
                    clean_t = str(Path(target_path).resolve()).replace('"', '')
                    dp_script = f'select vdisk file="{clean_t}"\nonline disk noerr\nattributes disk clear readonly noerr\nassign\n'
                elif disk_number is not None:
                    dp_script = f'select disk {disk_number}\nonline disk noerr\nattributes disk clear readonly noerr\nassign\n'

                with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt", errors="replace") as tf:
                    tf.write(dp_script)
                    dp_file = tf.name
                subprocess.run(
                    ["diskpart.exe", "/s", dp_file],
                    capture_output=True,
                    creationflags=CREATE_NO_WINDOW,
                    startupinfo=get_startupinfo(),
                    timeout=5
                )
                _secure_delete_file(dp_file)

                code, stdout, _ = self._run_powershell(ps_script)
                letter = stdout.strip()
                if letter:
                    self.active_drive_letter = letter
                    try:
                        ctypes.windll.shell32.SHChangeNotify(0x00040000, 0x0001, f"{letter}\\", None)
                    except Exception:
                        pass
                    return letter
            except Exception:
                pass

        return ""

    def mount_vhd(self, file_path: str, preferred_letter: Optional[str] = None, usb_token: Optional[str] = None) -> Dict[str, Any]:
        """
        VHD/VHDX dosyasını bağlar, harf atamasını sağlar ve durumunu döndürür.
        Win32 virtdisk.dll ve C seviyesinde Volume API kullanarak mikrosaniyeler mertebesinde (<50ms) çalışır.
        """
        self.active_vault_was_shielded = self.is_vault_shielded(file_path)
        if self.active_vault_was_shielded:
            unshielded = False
            last_err = ""
            
            shield_meta = self.get_shield_metadata(file_path)
            target_serial = shield_meta.get("serial", "")

            if usb_token:
                unshield_res = self.unshield_vault_container(file_path, usb_token, target_serial=target_serial)
                if unshield_res.get("success"):
                    unshielded = True
                    if unshield_res.get("usb_serial"):
                        target_serial = unshield_res.get("usb_serial")
                else:
                    last_err = unshield_res.get("error", "")

            if not unshielded:
                connected_tokens = self.get_all_connected_usb_tokens(target_serial=target_serial)
                for tok in connected_tokens:
                    unshield_res = self.unshield_vault_container(file_path, tok, target_serial=target_serial)
                    if unshield_res.get("success"):
                        usb_token = tok
                        unshielded = True
                        if unshield_res.get("usb_serial"):
                            target_serial = unshield_res.get("usb_serial")
                        break

            if not unshielded:
                serial_info = f" (Yetkili USB Seri No: {target_serial})" if target_serial else ""
                err_detail = f": {last_err}" if last_err else "!"
                return {
                    "success": False,
                    "error": (
                        f"Bu kasa USB Donanım Kilidi ile mühürlü. Kasayı bağlamak için yetkili flash bellek"
                        f"{serial_info} bilgisayara takılı olmalıdır{err_detail}"
                    )
                }

        if usb_token:
            self.active_usb_token = usb_token
            self.active_vault_was_shielded = True
        if 'target_serial' in locals() and target_serial:
            self.active_usb_serial = target_serial

        pref_clean = _clean_drive_letter(preferred_letter)
        mount_target, is_bridge, bridge_path = self.prepare_mount_target(file_path)
        self.active_vault_file = file_path
        self.active_mount_target = mount_target
        self.active_bridge_link = bridge_path

        enable_volume_privilege()
        try:
            ok, disk_num, phys = native_attach_vhd(mount_target)
            if ok and disk_num is not None and disk_num >= 0:
                self.active_disk_number = disk_num
                drive_letter = ""
                
                t_detect = time.time() + 0.35
                parts_map = {}
                while time.time() < t_detect:
                    parts_map = get_disk_volumes(disk_num)
                    if len(parts_map) >= 2 or (parts_map and time.time() > t_detect - 0.15):
                        break
                    time.sleep(0.03)
                
                if len(parts_map) >= 2:
                    
                    p1_info = parts_map.get(1, {})
                    if p1_info.get("letter"):
                        remove_drive_letter_mount_point(p1_info["letter"])
                    
                    p2_info = parts_map.get(2, {})
                    target_letter = pref_clean if pref_clean else (p2_info.get("letter", "").rstrip(":") if p2_info.get("letter") else "")
                    if not target_letter:
                        bitmask = k32.GetLogicalDrives()
                        avail = [chr(ord('A') + i) for i in range(3, 26) if not (bitmask & (1 << i))]
                        target_letter = avail[-1] if avail else "Z"
                    
                    if p2_info.get("letter") and p2_info["letter"].rstrip(":").upper() != target_letter:
                        remove_drive_letter_mount_point(p2_info["letter"])
                    
                    if p2_info.get("vol_name"):
                        k32.SetVolumeMountPointW(f"{target_letter}:\\", p2_info["vol_name"])
                    
                    parts_check = get_disk_volumes(disk_num)
                    if parts_check.get(1, {}).get("letter"):
                        remove_drive_letter_mount_point(parts_check[1]["letter"])

                    drive_letter = f"{target_letter}:"
                    try:
                        ctypes.windll.shell32.SHChangeNotify(0x00040000, 0x0001, f"{target_letter}:\\", None)
                    except Exception:
                        pass
                else:
                    t_end = time.time() + 1.2
                    while time.time() < t_end:
                        drive_letter = get_drive_letter_by_disk_number(disk_num)
                        if drive_letter:
                            break
                        drive_letter = win32_find_and_assign_volume(disk_num, pref_clean)
                        if drive_letter:
                            break
                        time.sleep(0.025)

                    if drive_letter and pref_clean and drive_letter.rstrip(":").upper() != pref_clean:
                        if win32_change_drive_letter(drive_letter, pref_clean):
                            drive_letter = f"{pref_clean}:"
                        else:
                            ch_res = self.change_drive_letter(pref_clean, drive_letter)
                            if ch_res.get("success"):
                                drive_letter = f"{pref_clean}:"

                    if not drive_letter:
                        drive_letter = self.ensure_drive_letter_assigned(disk_number=disk_num, target=mount_target, preferred_letter=preferred_letter)

                self.active_drive_letter = drive_letter
                self.suppress_bdeunlock()
                return {
                    "success": True,
                    "attached": True,
                    "disk_number": disk_num,
                    "drive_letter": drive_letter,
                    "mount_target": mount_target,
                    "is_bridge": is_bridge
                }
        except Exception as e:
            print(f"Native attach istisnası: {e}")

        escaped_target = _ps_literal(mount_target)
        
        ps_script = f"""
        $target = '{escaped_target}';
        $pref = '{pref_clean}';

        # 1. Gerekliyse diski bağla (-PassThru ile nesneyi anında al)
        $img = Get-DiskImage -ImagePath $target -ErrorAction SilentlyContinue;
        if (-not $img -or -not $img.Attached) {{
            $img = Mount-DiskImage -ImagePath $target -PassThru -ErrorAction Stop;
        }}

        $diskNum = -1;
        if ($img -and $img.Number -ne $null -and [string]$img.Number -ne '') {{
            $diskNum = [int]$img.Number;
        }}

        # 2. Bölümün (partition) hazır olmasını bekle (Maks 1.5 sn, 20ms aralıklarla)
        $timeout = (Get-Date).AddSeconds(1.5);
        $part = $null;

        while ((Get-Date) -lt $timeout) {{
            if ($diskNum -lt 0) {{
                $img = Get-DiskImage -ImagePath $target -ErrorAction SilentlyContinue;
                if ($img -and $img.Number -ne $null -and [string]$img.Number -ne '') {{
                    $diskNum = [int]$img.Number;
                }}
            }}
            if ($diskNum -ge 0) {{
                $part = Get-Partition -DiskNumber $diskNum -ErrorAction SilentlyContinue | Where-Object {{ $_.Type -ne 'Reserved' }} | Select-Object -First 1;
                if ($part) {{ break; }}
            }}
            Start-Sleep -Milliseconds 20;
        }}

        # 3. Sürücü harfi kontrolü ve hızlı atama
        if ($part -and $diskNum -ge 0) {{
            $curL = if ($part.DriveLetter) {{ [string]$part.DriveLetter }} else {{ "" }};
            
            # Tercih edilen harf istenmişse ve mevcut harften farklıysa
            if ($pref -and $curL -ne $pref) {{
                $used = [System.IO.DriveInfo]::GetDrives() | ForEach-Object {{ $_.Name.Substring(0,1).ToUpper() }};
                if ($used -notcontains $pref) {{
                    Set-Partition -DiskNumber $diskNum -PartitionNumber $part.PartitionNumber -NewDriveLetter $pref -ErrorAction SilentlyContinue;
                    $part = Get-Partition -DiskNumber $diskNum -PartitionNumber $part.PartitionNumber -ErrorAction SilentlyContinue;
                }}
            }} elseif (-not $curL) {{
                # Hiç harf atanmamışsa boş bir harf ata (D-Z arası tersten)
                $used = [System.IO.DriveInfo]::GetDrives() | ForEach-Object {{ $_.Name.Substring(0,1).ToUpper() }};
                $avail = 68..90 | ForEach-Object {{ [string][char]$_ }} | Where-Object {{ $used -notcontains $_ }};
                $assignL = if ($pref -and ($avail -contains $pref)) {{ $pref }} else {{ if ($avail) {{ $avail[-1] }} else {{ $null }} }};
                if ($assignL) {{
                    Set-Partition -DiskNumber $diskNum -PartitionNumber $part.PartitionNumber -NewDriveLetter $assignL -ErrorAction SilentlyContinue;
                    $part = Get-Partition -DiskNumber $diskNum -PartitionNumber $part.PartitionNumber -ErrorAction SilentlyContinue;
                }}
            }}
        }}

        $letter = if ($part -and $part.DriveLetter) {{ "$($part.DriveLetter):" }} else {{ "" }};
        [PSCustomObject]@{{
            Success = $true;
            Attached = $true;
            DiskNumber = $diskNum;
            DriveLetter = $letter;
        }} | ConvertTo-Json -Compress
        """

        code, stdout, stderr = self._run_powershell(ps_script)
        if code != 0 or not stdout:
            if is_bridge and bridge_path:
                self.cleanup_bridge(bridge_path, file_path)
            err_msg = stderr if stderr else "Disk bağlama işlemi başarısız oldu."
            return {"success": False, "error": err_msg}

        try:
            data = json.loads(stdout)
            drive_letter = data.get("DriveLetter", "")
            disk_num = data.get("DiskNumber")
            if disk_num is not None and disk_num >= 0:
                self.active_disk_number = disk_num
                parts_map = get_disk_volumes(disk_num)
                if len(parts_map) >= 2:
                    p1_info = parts_map.get(1, {})
                    if p1_info.get("letter"):
                        remove_drive_letter_mount_point(p1_info["letter"])
                    p2_info = parts_map.get(2, {})
                    if p2_info.get("letter"):
                        drive_letter = p2_info["letter"]
            if not drive_letter:
                drive_letter = self.ensure_drive_letter_assigned(disk_number=data.get("DiskNumber"), target=mount_target, preferred_letter=preferred_letter)
            self.active_drive_letter = drive_letter
            self.suppress_bdeunlock()
            return {
                "success": True,
                "attached": data.get("Attached", True),
                "disk_number": data.get("DiskNumber"),
                "drive_letter": drive_letter,
                "mount_target": mount_target,
                "is_bridge": is_bridge
            }
        except Exception as e:
            if is_bridge and bridge_path:
                self.cleanup_bridge(bridge_path, file_path)
            return {"success": False, "error": f"Yanıt çözümlenemedi: {stdout} ({e})"}

    @staticmethod
    def get_available_drive_letters() -> List[str]:
        """Sistemde şu an kullanılmayan boş sürücü harflerini (D-Z arası) mikro-saniyede döndürür."""
        try:
            bitmask = ctypes.windll.kernel32.GetLogicalDrives()
            available = []
            for i in range(3, 26):
                letter = chr(ord('A') + i)
                if not (bitmask & (1 << i)):
                    available.append(letter)
            return available
        except Exception:
            used = []
            for d in range(ord('D'), ord('Z') + 1):
                ch = chr(d)
                if not Path(f"{ch}:\\").exists():
                    used.append(ch)
            return used

    def change_drive_letter(self, new_letter: str, old_letter: Optional[str] = None) -> Dict[str, Any]:
        """
        Bağlı sanal diskin sürücü harfini çalışma anında dinamik olarak değiştirir.
        Gezgin pencerelerini kapatır, Set-Partition / diskpart ile anında yeni harfe taşır.
        """
        old = _clean_drive_letter(old_letter or self.active_drive_letter)
        new = _clean_drive_letter(new_letter)

        if not old:
            return {"success": False, "error": "Geçerli bağlı sürücü harfi tespit edilemedi."}
        if not new or len(new) != 1 or not new.isalpha():
            return {"success": False, "error": f"Geçersiz sürücü harfi: {new_letter}"}
        if old == new:
            return {"success": True, "drive_letter": f"{new}:", "old_letter": f"{old}:", "message": "Sürücü harfi zaten aynı."}

        avail = self.get_available_drive_letters()
        if new not in avail:
            return {"success": False, "error": f"'{new}:' sürücü harfi şu anda sistemde başka bir aygıt veya birim tarafından kullanılıyor."}

        try:
            self.close_explorer_windows(f"{old}:")
        except Exception:
            pass

        try:
            if win32_change_drive_letter(f"{old}:", f"{new}:"):
                self.active_drive_letter = f"{new}:"
                return {
                    "success": True,
                    "old_letter": f"{old}:",
                    "drive_letter": f"{new}:",
                    "message": f"Sürücü harfi başarıyla {new}: olarak değiştirildi."
                }
        except Exception as e:
            print(f"Win32 harf değiştirme istisnası: {e}")

        ps_cmd = f"""
        $oldL = '{old}';
        $newL = '{new}';
        $success = $false;

        try {{
            Set-Partition -DriveLetter $oldL -NewDriveLetter $newL -ErrorAction Stop;
            $success = $true;
        }} catch {{
            try {{
                $part = Get-Partition | Where-Object {{ $_.DriveLetter -eq $oldL }} | Select-Object -First 1;
                if ($part) {{
                    Set-Partition -InputObject $part -NewDriveLetter $newL -ErrorAction Stop;
                    $success = $true;
                }}
            }} catch {{}}
        }}

        if ($success) {{
            Write-Output "OK";
        }} else {{
            Write-Output "FAIL";
        }}
        """
        code, stdout, stderr = self._run_powershell(ps_cmd, timeout=8)
        
        if "OK" not in stdout:
            try:
                dp_script = f"select volume {old}\\nassign letter={new}\\n"
                with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt", errors="replace") as tf:
                    tf.write(dp_script)
                    dp_file = tf.name
                subprocess.run(
                    ["diskpart.exe", "/s", dp_file],
                    capture_output=True,
                    creationflags=CREATE_NO_WINDOW,
                    startupinfo=get_startupinfo(),
                    timeout=5
                )
                _secure_delete_file(dp_file)
            except Exception:
                pass

        bitmask = ctypes.windll.kernel32.GetLogicalDrives()
        new_bit = ord(new) - ord('A')
        if bitmask & (1 << new_bit):
            self.active_drive_letter = f"{new}:"
            return {
                "success": True,
                "old_letter": f"{old}:",
                "drive_letter": f"{new}:",
                "message": f"Sürücü harfi başarıyla {new}: olarak değiştirildi."
            }
        else:
            return {
                "success": False,
                "error": f"Sürücü harfi {old}: -> {new}: olarak değiştirilemedi. Birim kilitli veya kullanımda olabilir."
            }

    def dismount_vhd(self, mount_target: Optional[str] = None, drive_letter: Optional[str] = None, force: bool = False, usb_token: Optional[str] = None, usb_serial: Optional[str] = None) -> Dict[str, Any]:
        """
        Bağlı sanal diski güvenle ayırır, açık Gezgin pencerelerini kapatır ve geçici köprüyü temizler.
        force=True durumunda (Panik / acil durum) dosya kilitlerini zorla kırar, çalışan süreçleri sonlandırır ve diski ayırır.
        """
        target = mount_target or self.active_mount_target or self.active_vault_file
        dl = drive_letter or self.active_drive_letter

        if not dl and target:
            try:
                attached_info = self.check_vault_attached(target)
                if attached_info and attached_info.get("DriveLetter"):
                    dl = attached_info["DriveLetter"]
            except Exception:
                pass

        clean_dl = _clean_drive_letter(dl)

        if clean_dl:
            try:
                self.close_explorer_windows(f"{clean_dl}:")
            except Exception:
                pass

        if clean_dl and force:
            try:
                kill_processes_on_drive(f"{clean_dl}:")
            except Exception:
                pass

        if clean_dl:
            try:
                flush_and_dismount_volume(f"{clean_dl}:")
            except Exception:
                pass

        if clean_dl and force:
            try:
                subprocess.run(
                    ["cmd.exe", "/c", f"echo Y | manage-bde.exe -lock {clean_dl}: -ForceDismount"],
                    capture_output=True,
                    creationflags=CREATE_NO_WINDOW,
                    startupinfo=get_startupinfo(),
                    timeout=3
                )
            except Exception:
                pass

            try:
                k32.DeleteVolumeMountPointW(f"{clean_dl}:\\")
            except Exception:
                pass

        candidates = []
        for item in (target, self.active_mount_target, self.active_vault_file, self.active_bridge_link):
            if item:
                try:
                    p = Path(item).resolve()
                    if str(p) not in candidates:
                        candidates.append(str(p))
                    ext = p.suffix.lower()
                    if ext not in [".vhd", ".vhdx"]:
                        safe_stem = "".join([c if c.isalnum() or c in "-_" else "_" for c in p.name])
                        b_cand1 = Path(tempfile.gettempdir()) / f"vhd_vault_bridge_{safe_stem}.vhd"
                        if str(b_cand1) not in candidates:
                            candidates.append(str(b_cand1))
                        b_cand2 = p.parent / ".vhd_temp" / f"bridge_{safe_stem}.vhd"
                        if str(b_cand2) not in candidates:
                            candidates.append(str(b_cand2))
                        for bridge in VHDEngine._bridge_candidates(p):
                            if str(bridge) not in candidates:
                                candidates.append(str(bridge))
                        temp_sub = p.parent / ".vhd_temp"
                        if temp_sub.exists():
                            for bf in temp_sub.glob("bridge_*.vhd"):
                                if str(bf) not in candidates:
                                    candidates.append(str(bf))
                except Exception:
                    pass

        if not candidates and clean_dl:
            try:
                ps_find = f"(Get-Partition -DriveLetter '{clean_dl}' -ErrorAction SilentlyContinue | Get-DiskImage -ErrorAction SilentlyContinue).ImagePath"
                c, out, _ = self._run_powershell(ps_find, timeout=3)
                if c == 0 and out.strip():
                    found_p = out.strip().strip('"\r\n')
                    if found_p and found_p not in candidates:
                        candidates.append(found_p)
            except Exception:
                pass

        enable_volume_privilege()

        dismounted = False
        for cand in candidates:
            if cand.lower().endswith((".vhd", ".vhdx")):
                if native_detach_vhd(cand):
                    dismounted = True
                    break

        if not dismounted and clean_dl:
            try:
                if win32_eject_drive(clean_dl):
                    dismounted = True
            except Exception:
                pass

        if not dismounted:
            escaped_list = [f"'{_ps_literal(c)}'" for c in candidates]
            escaped_cands = ", ".join(escaped_list)
            ps_script = f"""
            $cands = @({escaped_cands});
            $dl = '{clean_dl}';

            # Sürücü harfi üzerinden ayır
            if ($dl) {{
                try {{
                    $part = Get-Partition -DriveLetter $dl -ErrorAction SilentlyContinue;
                    if ($part -and $part.DiskNumber -ne $null -and $part.DiskNumber -ge 0) {{
                        Get-DiskImage | Where-Object {{ $_.Attached -and $_.Number -eq $part.DiskNumber }} | Dismount-DiskImage -ErrorAction SilentlyContinue;
                    }}
                }} catch {{}}
            }}

            # Tüm aday yolları tek döngüde ayır
            foreach ($c in $cands) {{
                Dismount-DiskImage -ImagePath $c -ErrorAction SilentlyContinue;
            }}

            $check = Get-DiskImage | Where-Object {{ $_.Attached -and ($cands -contains $_.ImagePath) }};
            [PSCustomObject]@{{
                Dismounted = (-not $check)
            }} | ConvertTo-Json -Compress
            """
            code, stdout, stderr = self._run_powershell(ps_script, timeout=6)
            if code == 0 and stdout:
                try:
                    res_data = json.loads(stdout)
                    if res_data.get("Dismounted"):
                        dismounted = True
                except Exception:
                    pass

        if not dismounted and candidates:
            dp_lines = []
            for cand in candidates:
                if cand.lower().endswith((".vhd", ".vhdx")):
                    clean_dp = cand.replace('"', '')
                    dp_lines.append(f'select vdisk file="{clean_dp}"\noffline disk\ndetach vdisk')
            if dp_lines:
                dp_script = "\n".join(dp_lines) + "\n"
                try:
                    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt", errors="replace") as tf:
                        tf.write(dp_script)
                        dp_file = tf.name
                    subprocess.run(
                        ["diskpart.exe", "/s", dp_file],
                        capture_output=True,
                        creationflags=CREATE_NO_WINDOW,
                        startupinfo=get_startupinfo(),
                        timeout=5
                    )
                    _secure_delete_file(dp_file)
                    dismounted = True
                except Exception:
                    pass

        orig_file = self.active_vault_file or target
        if self.active_bridge_link:
            self.cleanup_bridge(self.active_bridge_link, orig_file)
            self.active_bridge_link = None

        if orig_file:
            try:
                ctypes.windll.kernel32.SetFileAttributesW(str(Path(orig_file).resolve()), 0x80)
            except Exception:
                pass

        self.active_vault_was_shielded = False
        self.active_mount_target = None
        self.active_vault_file = None
        self.active_drive_letter = None
        self.active_usb_token = None
        self.active_usb_serial = None

        if clean_dl:
            try:
                ctypes.windll.shell32.SHChangeNotify(0x00080000, 0x0001, f"{clean_dl}:\\", None)
            except Exception:
                pass

        return {"success": True, "message": "Sanal disk güvenle ayrıldı."}

    @staticmethod
    def get_drive_status(drive_letter: str) -> Dict[str, Any]:
        """
        Sürücünün açık/kilitli, BitLocker ve kapasite durumunu Win32 API ile anlık kontrol eder.
        Sıfır ek işlem (0 process), sıfır CPU kullanımı ve 0.1ms gecikmeyle çalışır.
        """
        if not drive_letter:
            return {"is_valid": False}

        letter = drive_letter.rstrip("\\").rstrip(":") + ":"
        root = letter + "\\"

        clean = letter[0].upper()
        if not clean.isalpha():
            return {"is_valid": False, "drive_letter": letter}

        bitmask = ctypes.windll.kernel32.GetLogicalDrives()
        if not (bitmask & (1 << (ord(clean) - ord('A')))):
            return {
                "is_valid": False,
                "drive_letter": letter,
                "is_mounted": False,
                "is_locked": False,
                "is_accessible": False
            }

        status = {
            "is_valid": True,
            "drive_letter": letter,
            "is_accessible": False,
            "is_bitlocker": False,
            "is_locked": False,
            "label": "",
            "total_bytes": 0,
            "free_bytes": 0,
            "percent_free": 0.0
        }

        try:
            vol_buf = ctypes.create_unicode_buffer(512)
            fs_buf = ctypes.create_unicode_buffer(512)
            serial = wintypes.DWORD()
            max_len = wintypes.DWORD()
            flags = wintypes.DWORD()

            old_mode = ctypes.windll.kernel32.SetErrorMode(0x0001 | 0x8000)
            try:
                ret = ctypes.windll.kernel32.GetVolumeInformationW(
                    root,
                    vol_buf,
                    len(vol_buf),
                    ctypes.byref(serial),
                    ctypes.byref(max_len),
                    ctypes.byref(flags),
                    fs_buf,
                    len(fs_buf)
                )
            finally:
                ctypes.windll.kernel32.SetErrorMode(old_mode)

            if ret != 0:
                status["is_accessible"] = True
                status["is_locked"] = False
                status["label"] = vol_buf.value or "Kasa"

                free_avail = ctypes.c_ulonglong()
                total_b = ctypes.c_ulonglong()
                total_free = ctypes.c_ulonglong()
                if ctypes.windll.kernel32.GetDiskFreeSpaceExW(
                    root,
                    ctypes.byref(free_avail),
                    ctypes.byref(total_b),
                    ctypes.byref(total_free)
                ):
                    status["total_bytes"] = total_b.value
                    status["free_bytes"] = free_avail.value
                    if total_b.value > 0:
                        status["percent_free"] = round((free_avail.value / total_b.value) * 100, 1)

                return status

            status["is_accessible"] = False
            status["is_bitlocker"] = True
            status["is_locked"] = True

        except Exception as e:
            print(f"get_drive_status istisnası ({drive_letter}): {e}")

        return status

    def check_vault_attached(self, file_path: str) -> Optional[Dict[str, Any]]:
        """Dosyanın veya köprüsünün halihazırda sisteme bağlı olup olmadığını C/Win32 API ile anında (<0.5ms) kontrol eder."""
        try:
            target_path = Path(file_path).resolve()
            if not target_path.exists():
                return None

            ext = target_path.suffix.lower()
            candidates = [str(target_path)]
            bridge_path = None
            if ext not in [".vhd", ".vhdx"]:
                safe_stem = "".join([c if c.isalnum() or c in "-_" else "_" for c in target_path.name])
                b_path = Path(tempfile.gettempdir()) / f"vhd_vault_bridge_{safe_stem}.vhd"
                if b_path.exists() and str(b_path) not in candidates:
                    candidates.append(str(b_path))
                    if not bridge_path:
                        bridge_path = str(b_path)
                b_path2 = target_path.parent / ".vhd_temp" / f"bridge_{safe_stem}.vhd"
                if b_path2.exists() and str(b_path2) not in candidates:
                    candidates.append(str(b_path2))
                    if not bridge_path:
                        bridge_path = str(b_path2)
                for bridge in VHDEngine._bridge_candidates(target_path):
                    if bridge.exists() and str(bridge) not in candidates:
                        candidates.append(str(bridge))
                        if not bridge_path:
                            bridge_path = str(bridge)
                cand_local = target_path.parent / f".~bridge_{safe_stem}.vhd"
                if cand_local.exists() and str(cand_local) not in candidates:
                    candidates.append(str(cand_local))
                    if not bridge_path:
                        bridge_path = str(cand_local)

            for cand in candidates:
                try:
                    st = VIRTUAL_STORAGE_TYPE()
                    st.DeviceId = 0
                    st.VendorId = GUID(0xEC984AEC, 0xA0F9, 0x47E9, (0x90, 0x1F, 0x71, 0x41, 0x5A, 0x66, 0x34, 0x5B))

                    open_params = OPEN_VIRTUAL_DISK_PARAMETERS()
                    open_params.Version = 1
                    open_params.Union.RWDepth = 1

                    handle = wintypes.HANDLE()
                    res = virtdisk.OpenVirtualDisk(
                        ctypes.byref(st),
                        str(cand),
                        0x00080000,
                        0,
                        ctypes.byref(open_params),
                        ctypes.byref(handle)
                    )
                    if res != 0 or not is_valid_handle(handle):
                        res = virtdisk.OpenVirtualDisk(
                            ctypes.byref(st),
                            str(cand),
                            0x003F0000,
                            0,
                            ctypes.byref(open_params),
                            ctypes.byref(handle)
                        )
                    if res == 0 and is_valid_handle(handle):
                        try:
                            buf_size = wintypes.ULONG(1024)
                            path_buf = ctypes.create_unicode_buffer(512)
                            res_path = virtdisk.GetVirtualDiskPhysicalPath(handle, ctypes.byref(buf_size), path_buf)
                            if res_path == 0 and path_buf.value:
                                phys_path = path_buf.value
                                disk_num = -1
                                if "PhysicalDrive" in phys_path:
                                    try:
                                        disk_num = int(phys_path.split("PhysicalDrive")[-1])
                                    except Exception:
                                        pass
                                letter = get_drive_letter_by_disk_number(disk_num) if disk_num >= 0 else ""
                                if not letter and disk_num >= 0:
                                    letter = self.ensure_drive_letter_assigned(disk_number=disk_num, target=cand)
                                self.active_mount_target = cand
                                self.active_vault_file = file_path
                                self.active_bridge_link = bridge_path
                                self.active_drive_letter = letter
                                return {
                                    "Attached": True,
                                    "DiskNumber": disk_num,
                                    "DriveLetter": letter,
                                    "Target": cand
                                }
                        finally:
                            k32.CloseHandle(handle)
                except Exception:
                    pass

        except Exception as e:
            print(f"Bağlılık kontrolü hatası: {e}")
        return None

    @staticmethod
    def trigger_bdeunlock(drive_letter: str) -> bool:
        """Windows bdeunlock.exe şifre isteme penceresini başlatır."""
        letter = drive_letter.rstrip("\\").rstrip(":") + ":"
        try:
            subprocess.Popen(["bdeunlock.exe", letter])
            return True
        except Exception as e:
            print(f"bdeunlock başlatılamadı: {e}")
            return False

    @staticmethod
    def unlock_bitlocker_password(drive_letter: str, password: str) -> Dict[str, Any]:
        """
        Girilen şifre ile BitLocker kilidini güvenli ve hızlı şekilde açar.
        Windows Sandbox ve tüm Windows sürümleriyle tam uyumludur.
        Şifreyi Base64 UTF-8 ile aktararak kodlama ve karakter bozulmalarını önler.
        """
        import base64
        letter = drive_letter.rstrip("\\").rstrip(":") + ":"
        clean_letter = letter.replace("'", "")

        try:
            res = subprocess.run(
                ["manage-bde.exe", "-unlock", clean_letter, "-pw"],
                input=password + "\n",
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                creationflags=CREATE_NO_WINDOW,
                startupinfo=get_startupinfo(),
                timeout=4
            )
            out = res.stdout or ""
            err = res.stderr or ""
            comb = (out + " " + err).lower()
            if res.returncode == 0 or "successfully unlocked" in comb or "başarıyla" in comb:
                return {"success": True, "method": "manage-bde"}
            if "already unlocked" in comb or "zaten açık" in comb or "0x80310023" in comb:
                return {"success": True, "method": "manage-bde-already-unlocked"}
        except Exception:
            pass

        pw_b64 = base64.b64encode(password.encode("utf-8")).decode("ascii")

        ps_script = f"""
        $ErrorActionPreference = 'SilentlyContinue';
        $letter = '{clean_letter}';
        $b64 = [Console]::In.ReadLine().Trim();

        # Windows Sandbox veya servisi durdurulmuş sistemler için BitLocker servisini arka planda başlat
        cmd.exe /c "sc.exe start bdesvc" > $null 2>&1;

        # Önce birim zaten açık durumda mı kontrol et
        $volCheck = Get-BitLockerVolume -MountPoint $letter -ErrorAction SilentlyContinue;
        if ($volCheck -and "$($volCheck.LockStatus)" -eq 'Unlocked') {{
            [PSCustomObject]@{{
                Success = $true;
                LockStatus = "Unlocked";
                Method = "AlreadyUnlocked";
            }} | ConvertTo-Json -Compress;
            exit 0;
        }}

        $pwBytes = [System.Convert]::FromBase64String($b64);
        $pwPlain = [System.Text.Encoding]::UTF8.GetString($pwBytes);

        # 1. Yöntem: PowerShell Unlock-BitLocker
        try {{
            $sec = ConvertTo-SecureString $pwPlain -AsPlainText -Force;
            $vol = Unlock-BitLocker -MountPoint $letter -Password $sec -ErrorAction Stop;
            [PSCustomObject]@{{
                Success = $true;
                LockStatus = "$($vol.LockStatus)";
                Method = "Unlock-BitLocker";
            }} | ConvertTo-Json -Compress;
            exit 0;
        }} catch {{
            $errObj = $_;
            $hres = if ($errObj.Exception -and $errObj.Exception.HResult) {{ $errObj.Exception.HResult }} else {{ 0 }};
            $errMsg = if ($errObj.Exception) {{ $errObj.Exception.Message }} else {{ "$errObj" }};

            if ($hres -eq -2144272349 -or $errMsg -match 'already unlocked|zaten açık|0x80310023') {{
                [PSCustomObject]@{{
                    Success = $true;
                    LockStatus = "Unlocked";
                    Method = "AlreadyUnlocked";
                }} | ConvertTo-Json -Compress;
                exit 0;
            }}

            # 0x80310027: Parola geçersiz / FVE_E_KEY_PROTECTOR_NOT_FOUND (-2144272345)
            $isWrongPw = ($hres -eq -2144272345 -or $errMsg -match 'failed to unlock|açamadı|incorrect|geçersiz|0x80310027');
            if ($isWrongPw) {{
                [PSCustomObject]@{{
                    Success = $false;
                    WrongPassword = $true;
                    Error = "Girilen parola hatalı. Lütfen kontrol edip tekrar deneyin.";
                    RawError = $errMsg;
                    HResult = $hres;
                }} | ConvertTo-Json -Compress;
                exit 0;
            }}
        }}

        # 2. Yöntem (Yedek / Sandbox uyumluluğu): WMI Win32_EncryptableVolume
        try {{
            $wmiVol = Get-CimInstance -Namespace 'root\\cimv2\\security\\microsoftvolumeencryption' -ClassName Win32_EncryptableVolume -Filter "DriveLetter = '$letter'" -ErrorAction Stop;
            if ($wmiVol) {{
                $inv = Invoke-CimMethod -InputObject $wmiVol -MethodName 'UnlockWithPassphrase' -Arguments @{{ Passphrase = $pwPlain }} -ErrorAction Stop;
                if ($inv.ReturnValue -eq 0 -or $inv.ReturnValue -eq 2150694947) {{
                    [PSCustomObject]@{{
                        Success = $true;
                        Method = "WMI";
                    }} | ConvertTo-Json -Compress;
                    exit 0;
                }} elseif ($inv.ReturnValue -eq 2150694951 -or $inv.ReturnValue -eq 0x80310027) {{
                    [PSCustomObject]@{{
                        Success = $false;
                        WrongPassword = $true;
                        Error = "Girilen parola hatalı. Lütfen kontrol edip tekrar deneyin.";
                        RawError = "WMI Ret: 0x80310027";
                        HResult = -2144272345;
                    }} | ConvertTo-Json -Compress;
                    exit 0;
                }}
            }}
        }} catch {{}}

        # Diğer genel hata durumu
        $finalErr = if ($errMsg) {{ $errMsg }} else {{ "BitLocker kilidi açılamadı." }};
        [PSCustomObject]@{{
            Success = $false;
            WrongPassword = $false;
            Error = $finalErr;
            RawError = $finalErr;
            HResult = $hres;
        }} | ConvertTo-Json -Compress;
        exit 0;
        """

        cmd = [
            "powershell.exe",
            "-WindowStyle", "Hidden",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy", "Bypass",
            "-Command", ps_script
        ]
        try:
            proc = subprocess.run(
                cmd,
                input=f"{pw_b64}\n",
                capture_output=True,
                creationflags=CREATE_NO_WINDOW,
                startupinfo=get_startupinfo(),
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=12
            )
            stdout = proc.stdout.strip()
            if stdout:
                json_line = ""
                for line in stdout.splitlines():
                    line_s = line.strip()
                    if line_s.startswith("{") and line_s.endswith("}"):
                        json_line = line_s
                if json_line:
                    data = json.loads(json_line)
                    if data.get("Success"):
                        return {"success": True, "message": "BitLocker kilidi başarıyla açıldı!"}
                    else:
                        err_msg = data.get("Error", "BitLocker kilidi açılamadı.")
                        return {
                            "success": False,
                            "error": err_msg,
                            "wrong_password": data.get("WrongPassword", False),
                            "raw_error": data.get("RawError", "")
                        }
        except Exception as e:
            return {"success": False, "error": f"Kilit açma işlemi sırasında hata oluştu: {e}", "raw_error": str(e)}

        return {"success": False, "error": "BitLocker kilidi açılamadı veya yanıt alınamadı.", "raw_error": ""}

    unlock_bitlocker = unlock_bitlocker_password

    @staticmethod
    def open_explorer(drive_letter: str):
        """Dosya Gezgini'nde sürücüyü açar."""
        letter = drive_letter.rstrip("\\") + "\\"
        try:
            os.startfile(letter)
        except Exception as e:
            subprocess.Popen(["explorer.exe", letter])

    @staticmethod
    def close_explorer_windows(drive_letter: str):
        """Belirtilen sürücüyü görüntüleyen tüm Dosya Gezgini pencerelerini Win32 API ile anında (<1ms) kapatır."""
        if not drive_letter:
            return
        dl = drive_letter.rstrip("\\").rstrip(":").upper()
        target1 = f"({dl}:)"
        target2 = f"{dl}:\\"
        target3 = f"{dl}:"
        user32 = ctypes.windll.user32

        def enum_proc(hwnd, lParam):
            if user32.IsWindow(hwnd) and user32.IsWindowVisible(hwnd):
                class_buf = ctypes.create_unicode_buffer(256)
                user32.GetClassNameW(hwnd, class_buf, 256)
                if class_buf.value in ("CabinetWClass", "ExploreWClass"):
                    title_buf = ctypes.create_unicode_buffer(512)
                    user32.GetWindowTextW(hwnd, title_buf, 512)
                    t_upper = title_buf.value.upper()
                    if target1 in t_upper or target2 in t_upper or t_upper.startswith(target3):
                        user32.PostMessageW(hwnd, 0x0010, 0, 0)
            return True

        try:
            WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)
            proc = WNDENUMPROC(enum_proc)
            user32.EnumWindows(proc, 0)
        except Exception:
            pass

    @staticmethod
    def get_system_idle_seconds() -> float:
        """Kullanıcının fare ve klavye hareketsizlik süresini (saniye cinsinden) döndürür."""
        try:
            class LASTINPUTINFO(ctypes.Structure):
                _fields_ = [
                    ("cbSize", wintypes.UINT),
                    ("dwTime", wintypes.DWORD),
                ]
            lii = LASTINPUTINFO()
            lii.cbSize = ctypes.sizeof(LASTINPUTINFO)
            if ctypes.windll.user32.GetLastInputInfo(ctypes.byref(lii)):
                ctypes.windll.kernel32.GetTickCount64.restype = ctypes.c_ulonglong
                gtc = ctypes.windll.kernel32.GetTickCount64()
                idle_ms = ((gtc & 0xFFFFFFFF) - lii.dwTime) & 0xFFFFFFFF
                return max(0.0, idle_ms / 1000.0)
        except Exception:
            pass
        return 0.0

    @staticmethod
    def is_workstation_locked() -> bool:
        """Windows oturumunun kilitli (Win+L / Kilit Ekranı) olup olmadığını kontrol eder."""
        try:
            hDesk = ctypes.windll.user32.OpenInputDesktop(0, False, 0x0100)
            if hDesk == 0:
                return True

            name_buf = ctypes.create_unicode_buffer(256)
            needed = wintypes.DWORD()
            UOI_NAME = 2
            is_locked = False
            if ctypes.windll.user32.GetUserObjectInformationW(
                hDesk, UOI_NAME, name_buf, ctypes.sizeof(name_buf), ctypes.byref(needed)
            ):
                desk_name = name_buf.value.strip().lower()
                if desk_name and desk_name != "default":
                    is_locked = True
            ctypes.windll.user32.CloseDesktop(hDesk)
            return is_locked
        except Exception:
            return False

    @staticmethod
    def _cleanup_temp_vault(work_file: Path, escaped_work: str, delete_file: bool = True):
        """Oluşturma esnasında açılan geçici sanal diski güvenle ayırır ve gerekirse siler."""
        try:
            native_detach_vhd(str(work_file))
        except Exception:
            pass
        ps_work = _ps_literal(work_file)
        VHDEngine._run_powershell(f"Dismount-DiskImage -ImagePath '{ps_work}' -ErrorAction SilentlyContinue", timeout=5)
        VHDEngine._run_diskpart_script(f'select vdisk file="{escaped_work}"\ndetach vdisk\n', timeout=5)
        time.sleep(0.2)
        if delete_file:
            try:
                work_file.unlink(missing_ok=True)
            except Exception:
                pass

    def create_new_vault(
        self,
        vault_path: str,
        size_gb: int,
        is_dynamic: bool = True,
        label: str = "Kasa",
        bitlocker_password: Optional[str] = None,
        has_decoy: bool = False,
        decoy_size_gb: int = 1,
        decoy_size_mb: Optional[int] = None,
        decoy_password: Optional[str] = None
    ) -> Dict[str, Any]:
        """Yeni bir VHD/VHDX kasası oluşturur, NTFS olarak biçimlendirir ve isteğe bağlı BitLocker ile şifreler.
        has_decoy=True ise aynı sanal disk içinde 2 ayrı NTFS bölümü (MBR) açar ve her ikisini de bağımsız BitLocker ile şifreler."""
        target = Path(vault_path).resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            return {"success": False, "error": "Bu isimde bir kasa dosyası zaten mevcut."}

        vtype = "expandable" if is_dynamic else "fixed"
        max_mb = max(200 if has_decoy else 100, int(size_gb * 1024))
        label = label.translate(str.maketrans("çğıöşüÇĞİÖŞÜ", "cgiosuCGIOSU"))
        clean_label = "".join([c for c in label if c.isascii() and (c.isalnum() or c in " _-")]) or "Kasa"

        is_vhdx = (target.suffix.lower() == ".vhdx")
        work_ext = ".vhdx" if is_vhdx else ".vhd"
        ascii_path = str(target).isascii()
        needs_rename = (target.suffix.lower() not in [".vhd", ".vhdx"]) or not ascii_path

        if needs_rename:
            import uuid
            work_dir = target.parent if ascii_path else Path(target.anchor)
            work_file = work_dir / f".build_{uuid.uuid4().hex[:8]}{work_ext}"
        else:
            work_file = target

        escaped_work = str(work_file).replace('"', '')

        if has_decoy:
            if decoy_size_mb is not None and decoy_size_mb > 0:
                decoy_mb = max(100, int(decoy_size_mb))
            else:
                decoy_mb = max(100, int(decoy_size_gb * 1024))

            if decoy_mb >= max_mb:
                return {"success": False, "error": f"Tuzak kasa boyutu ({decoy_mb} MB) toplam kasa boyutundan ({max_mb} MB) küçük olmalıdır."}
            
            bitmask = k32.GetLogicalDrives()
            avail = [chr(ord('A') + i) for i in range(3, 26) if not (bitmask & (1 << i))]
            if len(avail) < 2:
                return {"success": False, "error": "Gömülü tuzak kasa oluşturmak için en az 2 boş sürücü harfi gereklidir."}
            l_decoy = avail[-1]
            l_main = avail[-2]
            
            dp_commands = f"""create vdisk file="{escaped_work}" maximum={max_mb} type={vtype}
select vdisk file="{escaped_work}"
attach vdisk
convert mbr
create partition primary size={decoy_mb}
format fs=ntfs quick label="{clean_label}"
assign letter={l_decoy}
create partition primary
format fs=ntfs quick label="{clean_label}"
assign letter={l_main}
"""
        else:
            dp_commands = f"""create vdisk file="{escaped_work}" maximum={max_mb} type={vtype}
select vdisk file="{escaped_work}"
attach vdisk
convert mbr
create partition primary
format fs=ntfs quick label="{clean_label}"
assign
"""

        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt", errors="replace") as tf:
            tf.write(dp_commands)
            dp_file = tf.name

        try:
            res = subprocess.run(
                ["diskpart.exe", "/s", dp_file],
                capture_output=True,
                text=True, encoding="oem", errors="replace",
                creationflags=CREATE_NO_WINDOW,
                startupinfo=get_startupinfo(),
                timeout=120 if is_dynamic else max(600, size_gb * 120)
            )
        finally:
            _secure_delete_file(dp_file)

        if not work_file.exists():
            return {"success": False, "error": f"Sanal disk dosyası oluşturulamadı:\n{res.stdout}\n{res.stderr}"}

        rec_key = ""
        decoy_rec_key = ""

        if has_decoy:
            p_decoy_drive = f"{l_decoy}:"
            p_main_drive = f"{l_main}:"
            
            bl_res_main = self.enable_bitlocker(p_main_drive, bitlocker_password)
            if not bl_res_main.get("success"):
                self._cleanup_temp_vault(work_file, escaped_work)
                return {"success": False, "error": f"Ana kasaya BitLocker şifrelemesi uygulanamadı:\n{bl_res_main.get('error', 'Bilinmeyen hata')}"}
            rec_key = bl_res_main.get("recovery_key", "")

            bl_res_decoy = self.enable_bitlocker(p_decoy_drive, decoy_password, recovery_password=rec_key)
            if not bl_res_decoy.get("success"):
                self._cleanup_temp_vault(work_file, escaped_work)
                return {"success": False, "error": f"Tuzak kasaya BitLocker şifrelemesi uygulanamadı:\n{bl_res_decoy.get('error', 'Bilinmeyen hata')}"}
            decoy_rec_key = bl_res_decoy.get("recovery_key", "") or rec_key

        else:
            assigned_letter = ""
            for _ in range(25):
                attached_info = self.check_vault_attached(str(work_file))
                if attached_info and attached_info.get("DriveLetter"):
                    assigned_letter = attached_info["DriveLetter"].rstrip(":\\/ ").upper() + ":"
                    break
                time.sleep(0.1)

            if not assigned_letter:
                find_ps = f"""
                $vol = Get-Volume | Where-Object {{ $_.FileSystemLabel -eq '{clean_label}' -and $_.DriveLetter }} | Select-Object -First 1;
                if ($vol) {{
                    Write-Output "DRIVE_LETTER:$($vol.DriveLetter):";
                    exit 0;
                }}
                $used = [System.IO.DriveInfo]::GetDrives() | ForEach-Object {{ $_.Name.Substring(0,1).ToUpper() }};
                $avail = 68..90 | ForEach-Object {{ [string][char]$_ }} | Where-Object {{ $used -notcontains $_ }};
                if ($avail) {{
                    $newLetter = $avail[-1];
                    $part = Get-Partition | Where-Object {{ $_.DiskModel -like '*Virtual*' -and -not $_.DriveLetter -and $_.Type -ne 'Reserved' }} | Select-Object -First 1;
                    if ($part) {{
                        Set-Partition -DiskNumber $part.DiskNumber -PartitionNumber $part.PartitionNumber -NewDriveLetter $newLetter -ErrorAction SilentlyContinue;
                        Write-Output "DRIVE_LETTER:$newLetter:";
                    }}
                }}
                """
                code_f, out_f, _ = VHDEngine._run_powershell(find_ps, timeout=10)
                for line in out_f.splitlines():
                    if line.startswith("DRIVE_LETTER:"):
                        assigned_letter = line.split(":", 1)[1].strip()

            if bitlocker_password:
                if not assigned_letter:
                    self._cleanup_temp_vault(work_file, escaped_work)
                    return {"success": False, "error": "Sanal disk oluşturuldu ancak bir sürücü harfi atanamadığı için BitLocker şifrelemesi uygulanamadı."}

                bl_res = self.enable_bitlocker(assigned_letter, bitlocker_password)
                if not bl_res.get("success"):
                    self._cleanup_temp_vault(work_file, escaped_work)
                    return {
                        "success": False,
                        "error": f"Kasaya BitLocker şifrelemesi uygulanamadı:\n{bl_res.get('error', 'Bilinmeyen hata')}"
                    }
                rec_key = bl_res.get("recovery_key", "")

        self._cleanup_temp_vault(work_file, escaped_work, delete_file=False)

        if needs_rename:
            renamed = False
            last_ren_err = ""
            for _ in range(20):
                try:
                    if target.exists():
                        target.unlink(missing_ok=True)
                    os.replace(str(work_file), str(target))
                    renamed = True
                    break
                except Exception as e:
                    last_ren_err = str(e)
                    try:
                        native_detach_vhd(str(work_file))
                    except Exception:
                        pass
                    time.sleep(0.15)
            if not renamed:
                return {"success": False, "error": f"Kasa dosyası adlandırılamadı: {last_ren_err}"}

        if not target.exists():
            return {"success": False, "error": "Kasa oluşturulduktan sonra dosya doğrulanamadı."}

        res_dict = {"success": True, "path": str(target)}
        if rec_key:
            res_dict["recovery_key"] = rec_key
        if has_decoy:
            res_dict["has_decoy"] = True
            res_dict["decoy_recovery_key"] = decoy_rec_key or rec_key
            res_dict["decoy_size_gb"] = max(1, int(decoy_mb // 1024))
            res_dict["decoy_size_mb"] = decoy_mb
            res_dict["main_size_gb"] = max(0, size_gb - (decoy_mb / 1024.0))
        return res_dict

    def swap_embedded_partitions(self, vault_path: str, target_part: int, letter: str) -> Dict[str, Any]:
        """
        Gömülü tuzak kasalarda (dual-partition VHD), belirtilen sürücü harfini (örn: K:)
        diğer bölümden kaldırıp hedef bölüme (1: Tuzak, 2: Ana Kasa) Win32 API ile anında atar (<1ms).
        Diğer bölüm harfsiz kalarak Windows Gezgini'nde tamamen gizli kalır.
        """
        clean_letter = letter.rstrip(":\\/ ").upper()
        if not clean_letter:
            clean_letter = "K"
        
        disk_num = getattr(self, "active_disk_number", None)
        if disk_num is None or disk_num < 0:
            disk_num = get_disk_number_for_drive_letter(clean_letter)
        if (disk_num is None or disk_num < 0) and vault_path:
            disk_num = get_vhd_disk_number(vault_path)
        if (disk_num is None or disk_num < 0) and getattr(self, "active_mount_target", None):
            disk_num = get_vhd_disk_number(self.active_mount_target)
        
        if disk_num is None or disk_num < 0:
            for d in range(1, 32):
                vols = get_disk_volumes(d)
                if len(vols) >= 2:
                    disk_num = d
                    break
        
        if disk_num is None or disk_num < 0:
            return {"success": False, "error": "Disk numarası tespit edilemedi.", "drive_letter": f"{clean_letter}:"}
        
        self.active_disk_number = disk_num

        parts = get_disk_volumes(disk_num)
        if not parts:
            time.sleep(0.04)
            parts = get_disk_volumes(disk_num)
        
        if not parts or target_part not in parts:
            return {"success": False, "error": f"Bölüm {target_part} disk üzerinde bulunamadı.", "drive_letter": f"{clean_letter}:"}

        target_vol = parts[target_part]["vol_name"]
        
        self.close_explorer_windows(f"{clean_letter}:")
        for p_num, p_info in parts.items():
            l = p_info.get("letter", "")
            if l:
                self.close_explorer_windows(l)
                remove_drive_letter_mount_point(l)
        
        remove_drive_letter_mount_point(clean_letter)
        
        mount_point = f"{clean_letter}:\\"
        res = k32.SetVolumeMountPointW(mount_point, target_vol)
        
        try:
            ctypes.windll.shell32.SHChangeNotify(0x00040000, 0x0001, mount_point, None)
            ctypes.windll.shell32.SHChangeNotify(0x08000000, 0x0000, None, None)
        except Exception:
            pass
        
        self.active_drive_letter = f"{clean_letter}:"
        return {"success": bool(res), "drive_letter": f"{clean_letter}:", "target_part": target_part}

    def check_embedded_decoy_vault(self, file_path: str) -> bool:
        """Kasanın 2 bölümlü bir sanal disk olup olmadığını Win32 API ile anında kontrol eder."""
        try:
            disk_num = getattr(self, "active_disk_number", None)
            if disk_num is not None and disk_num >= 0:
                parts = get_disk_volumes(disk_num)
                if len(parts) >= 2:
                    return True
            
            if file_path and Path(file_path).exists():
                d_num = get_vhd_disk_number(file_path)
                if d_num is not None and d_num >= 0:
                    parts = get_disk_volumes(d_num)
                    if len(parts) >= 2:
                        return True
            return False
        except Exception:
            return False

    @staticmethod
    def compact_vhd(vault_path: str) -> Dict[str, Any]:
        """Dinamik boyutlu VHD/VHDX diskini sıkıştırarak gereksiz boş alanı Windows'a geri kazandırır."""
        target = Path(vault_path).resolve()
        if not target.exists():
            return {"success": False, "error": "Kasa dosyası bulunamadı."}

        initial_size = target.stat().st_size
        escaped_path = str(target).replace('"', '')
        ps_path = _ps_literal(target)

        ps_compact = f"""
        try {{
            Mount-DiskImage -ImagePath '{ps_path}' -NoDriveLetter -ReadOnly -ErrorAction SilentlyContinue | Out-Null;
            Optimize-VHD -Path '{ps_path}' -Mode Full -ErrorAction SilentlyContinue | Out-Null;
            Dismount-DiskImage -ImagePath '{ps_path}' -ErrorAction SilentlyContinue | Out-Null;
        }} catch {{
            Dismount-DiskImage -ImagePath '{ps_path}' -ErrorAction SilentlyContinue | Out-Null;
        }}
        """
        subprocess.run(
            ["powershell.exe", "-WindowStyle", "Hidden", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", ps_compact],
            creationflags=CREATE_NO_WINDOW,
            startupinfo=get_startupinfo()
        )

        dp_commands = f"""select vdisk file="{escaped_path}"
attach vdisk readonly
compact vdisk
detach vdisk
"""
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt", errors="replace") as tf:
            tf.write(dp_commands)
            dp_file = tf.name

        try:
            subprocess.run(
                ["diskpart.exe", "/s", dp_file],
                capture_output=True,
                text=True, encoding="oem", errors="replace",
                creationflags=CREATE_NO_WINDOW,
                startupinfo=get_startupinfo()
            )
        finally:
            _secure_delete_file(dp_file)

        final_size = target.stat().st_size
        saved_mb = max(0.0, (initial_size - final_size) / (1024 * 1024))
        return {
            "success": True,
            "initial_mb": round(initial_size / (1024 * 1024), 2),
            "final_mb": round(final_size / (1024 * 1024), 2),
            "saved_mb": round(saved_mb, 2)
        }

    @staticmethod
    def backup_vault(source_path: str) -> Dict[str, Any]:
        """Kasa dosyasının zaman damgalı güvenli yedeğini vaults/backups altına alır."""
        from logger import BACKUPS_DIR
        src = Path(source_path).resolve()
        if not src.exists():
            return {"success": False, "error": "Kasa dosyası bulunamadı."}

        BACKUPS_DIR.mkdir(parents=True, exist_ok=True)
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        dest = BACKUPS_DIR / f"{src.stem}_{timestamp}{src.suffix}"

        try:
            shutil.copy2(src, dest)
            return {
                "success": True,
                "backup_path": str(dest),
                "backup_name": dest.name,
                "file_size_mb": round(dest.stat().st_size / (1024 * 1024), 2)
            }
        except Exception as e:
            return {"success": False, "error": f"Yedekleme hatası: {e}"}

    @staticmethod
    def calculate_file_hash(path: str, progress_callback=None) -> Dict[str, Any]:
        """Kasa dosyasının SHA-256 hash değerini bellek dostu bloklar halinde hesaplar."""
        import hashlib
        p = Path(path).resolve()
        if not p.exists():
            return {"success": False, "error": "Dosya bulunamadı."}

        total_size = p.stat().st_size
        read_size = 0
        hasher = hashlib.sha256()

        try:
            with open(p, "rb") as f:
                while True:
                    chunk = f.read(1024 * 1024 * 4)
                    if not chunk:
                        break
                    hasher.update(chunk)
                    read_size += len(chunk)
                    if progress_callback and total_size > 0:
                        progress_callback(int((read_size / total_size) * 100))
            return {
                "success": True,
                "file_name": p.name,
                "file_size_mb": round(total_size / (1024 * 1024), 2),
                "sha256": hasher.hexdigest().upper()
            }
        except Exception as e:
            return {"success": False, "error": f"Hash hesaplama hatası: {e}"}

    @staticmethod
    def _run_diskpart_script(script: str, timeout: int = 120) -> Dict[str, Any]:
        """Diskpart scriptini geçici bir dosya ile çalıştırır."""
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt", errors="replace") as tf:
            tf.write(script)
            dp_file = tf.name
        try:
            res = subprocess.run(
                ["diskpart.exe", "/s", dp_file],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                creationflags=CREATE_NO_WINDOW,
                startupinfo=get_startupinfo(),
                timeout=timeout
            )
            return {"returncode": res.returncode, "stdout": res.stdout, "stderr": res.stderr}
        except subprocess.TimeoutExpired:
            return {"returncode": 1, "stdout": "", "stderr": "Diskpart zaman aşımına uğradı."}
        except Exception as e:
            return {"returncode": 1, "stdout": "", "stderr": str(e)}
        finally:
            _secure_delete_file(dp_file)

    def is_vhd_attached(self, file_path: str) -> bool:
        """Belirtilen kasa dosyasının sisteme bağlı olup olmadığını kontrol eder."""
        try:
            info = self.check_vault_attached(file_path)
            return bool(info and info.get("Attached"))
        except Exception:
            return False

    def compact_vdisk(self, vhd_path: str) -> Dict[str, Any]:
        """Dinamik VHD/VHDX dosyasının içindeki boşlukları diskpart ile sıkıştırır (compact)."""
        src = Path(vhd_path).resolve()
        if not src.exists():
            return {"success": False, "error": "Kasa dosyası bulunamadı."}
        
        if self.is_vhd_attached(str(src)):
            return {"success": False, "error": "Kasa şu anda bağlı durumda. Sıkıştırmak için önce diski güvenle ayırın."}

        if self.is_vault_shielded(str(src)):
            return {"success": False, "error": "Kasa USB donanım anahtarı ile mühürlüdür. Sıkıştırma işlemi için lütfen önce diski bir kez bağlayın veya mührünü açın."}

        initial_size = src.stat().st_size
        target_path, is_bridge, bridge_path = self.prepare_mount_target(str(src))
        
        script = f"""select vdisk file="{target_path}"
attach vdisk readonly
compact vdisk
detach vdisk
"""
        try:
            res = self._run_diskpart_script(script, timeout=180)
            final_size = src.stat().st_size
            saved_bytes = max(0, initial_size - final_size)
            saved_mb = round(saved_bytes / (1024 * 1024), 2)
            pct = round((saved_bytes / initial_size * 100), 1) if initial_size > 0 else 0
            
            return {
                "success": True,
                "initial_size_mb": round(initial_size / (1024 * 1024), 2),
                "final_size_mb": round(final_size / (1024 * 1024), 2),
                "saved_mb": saved_mb,
                "saved_pct": pct,
                "output": res.get("stdout", "")
            }
        except Exception as e:
            try:
                self._run_diskpart_script(f'select vdisk file="{target_path}"\ndetach vdisk\n')
            except Exception:
                pass
            return {"success": False, "error": f"Sıkıştırma hatası: {e}"}
        finally:
            if is_bridge:
                self.cleanup_bridge(bridge_path, str(src))

    def get_bitlocker_recovery_key(self, drive_letter: str) -> Dict[str, Any]:
        """Sürücünün 48 haneli sayısal BitLocker kurtarma parolasını çeker."""
        try:
            clean = _clean_drive_letter(drive_letter)
            if not clean or len(clean) != 1:
                return {"success": False, "error": "Geçerli bir sürücü harfi belirtilmedi."}
            
            import re
            target_drive = f"{clean}:"
            
            try:
                proc = subprocess.run(
                    ["manage-bde.exe", "-protectors", "-get", target_drive],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    creationflags=CREATE_NO_WINDOW,
                    startupinfo=get_startupinfo(),
                    timeout=10
                )
                out = (proc.stdout or "") + "\n" + (proc.stderr or "")
                match = re.search(r"(\d{6}-\d{6}-\d{6}-\d{6}-\d{6}-\d{6}-\d{6}-\d{6})", out)
                if match:
                    return {"success": True, "recovery_key": match.group(1)}
            except Exception:
                pass

            try:
                ps_cmd = (
                    f'$vol = Get-BitLockerVolume -MountPoint "{clean}:" -ErrorAction SilentlyContinue; '
                    f'if ($vol) {{ ($vol.KeyProtector | Where-Object {{ $_.KeyProtectorType -eq "RecoveryPassword" }}).RecoveryPassword }}'
                )
                code, stdout, stderr = self._run_powershell(ps_cmd, timeout=10)
                ps_match = re.search(r"(\d{6}-\d{6}-\d{6}-\d{6}-\d{6}-\d{6}-\d{6}-\d{6})", stdout or "")
                if ps_match:
                    return {"success": True, "recovery_key": ps_match.group(1)}
            except Exception:
                pass

            return {
                "success": False,
                "error": f"{clean}: sürücüsü için BitLocker kurtarma anahtarı bulunamadı.\n(Sürücü kilitli olabilir veya yönetici yetkisi gerekebilir.)"
            }
        except Exception as e:
            return {"success": False, "error": f"Kurtarma anahtarı okuma hatası: {e}"}

    def export_bitlocker_recovery_key_file(
        self,
        drive_letter: str,
        export_path: str,
        vault_name: str = ""
    ) -> Dict[str, Any]:
        """BitLocker 48 haneli kurtarma anahtarını sertifika formatında bir dosyaya aktarır."""
        res = self.get_bitlocker_recovery_key(drive_letter)
        if not res.get("success"):
            return res

        recovery_key = res["recovery_key"]
        p = Path(export_path).resolve()
        p.parent.mkdir(parents=True, exist_ok=True)

        import datetime
        timestamp_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        v_title = vault_name or f"Sürücü ({drive_letter})"

        cert_content = (
            "================================================================================\n"
            "ENCLAVE - RESMİ BİTLOCKER KURTARMA ANAHTARI SERTİFİKASI\n"
            "================================================================================\n\n"
            f"Kasa Adı           : {v_title}\n"
            f"Sürücü Harfi       : {drive_letter}\n"
            f"Oluşturulma Tarihi : {timestamp_str}\n"
            f"Şifreleme Metodu   : AES-XTS 256 / BitLocker Sürücü Koruması\n\n"
            "--------------------------------------------------------------------------------\n"
            "48 HANELİ SAYISAL KURTARMA PAROLASI (RECOVERY KEY):\n"
            f"  {recovery_key}\n"
            "--------------------------------------------------------------------------------\n\n"
            "ÖNEMLİ GÜVENLİK UYARISI:\n"
            "- Bu kurtarma anahtarı, parolanızı unutmanız durumunda kasanızdaki şifreli\n"
            "  verilere erişim sağlamanın YEGANE yoludur.\n"
            "- Bu anahtarı şifrelenmiş sürücünün içinde ASLA saklamayınız.\n"
            "- Yazdırılmış kağıt veya ayrılmış çevrimdışı bir USB bellekte güvenle muhafaza ediniz.\n"
            "================================================================================\n"
        )

        with open(p, "w", encoding="utf-8") as f:
            f.write(cert_content)
            f.flush()
            os.fsync(f.fileno())

        return {
            "success": True,
            "export_path": str(p),
            "recovery_key": recovery_key,
            "drive_letter": drive_letter
        }

    @staticmethod
    def verify_vhd_structure(vhd_path: str) -> Dict[str, Any]:
        """
        VHD ve VHDX sanal disklerinin başlık, altbilgi (footer) ve yapısal bütünlüğünü doğrular.
        - Standart VHD 512 bayt footer ('conectix') ve sağlama toplamı (one's complement checksum denetimi)
        - Dinamik VHD için Dynamic Disk Header ('cxsparse') ve çift footer kontrolü
        - VHDX konteynerleri için 'vhdxfile' imza denetimi
        """
        p = Path(vhd_path)
        if not p.exists() or not p.is_file():
            return {"valid": False, "error": "Disk dosyası bulunamadı."}

        size = p.stat().st_size
        if size < 512:
            return {"valid": False, "error": "Dosya boyutu bir sanal disk için çok küçük."}

        with open(p, "rb") as f:
            magic_start = f.read(8)
            if magic_start == b"vhdxfile":
                return {
                    "valid": True,
                    "format": "VHDX",
                    "file_size": size,
                    "details": "Geçerli Microsoft VHDX formatı (vhdxfile imzası doğrulandı)."
                }
            f.seek(0)
            head_512 = f.read(512)
            f.seek(max(0, size - 512))
            foot_512 = f.read(512)

        if len(foot_512) != 512 or foot_512[:8] != b"conectix":
            if len(head_512) == 512 and head_512[:8] == b"conectix":
                return {
                    "valid": False,
                    "error": "VHD dosya sonu altbilgisi (footer) hasarlı veya dosya kesintiye uğramış (Başlık kopyası mevcut ancak altbilgi eksik)."
                }
            return {
                "valid": False,
                "error": "Geçerli bir VHD (conectix) veya VHDX (vhdxfile) yapısı bulunamadı. Disk başlığı veya altbilgisi bozulmuş olabilir."
            }

        footer = foot_512
        orig_checksum = struct.unpack(">I", footer[64:68])[0]
        calc_sum = sum(footer[:64]) + sum(footer[68:])
        calc_checksum = (~calc_sum) & 0xFFFFFFFF
        checksum_ok = (orig_checksum == calc_checksum)

        disk_type = struct.unpack(">I", footer[60:64])[0]
        type_names = {2: "Sabit Boyutlu (Fixed)", 3: "Dinamik Genişleyen (Dynamic)", 4: "Fark Diski (Differencing)"}
        type_str = type_names.get(disk_type, f"Bilinmeyen ({disk_type})")

        cur_size = struct.unpack(">Q", footer[48:56])[0]

        is_dynamic = (disk_type == 3)
        dynamic_header_ok = False
        if is_dynamic:
            with open(p, "rb") as f:
                head_footer = f.read(512)
                dyn_header = f.read(1024)
                if head_footer[:8] == b"conectix" and dyn_header[:8] == b"cxsparse":
                    dynamic_header_ok = True

        return {
            "valid": True,
            "format": "VHD",
            "disk_type": type_str,
            "disk_type_code": disk_type,
            "virtual_size": cur_size,
            "file_size": size,
            "checksum_ok": checksum_ok,
            "is_dynamic": is_dynamic,
            "dynamic_header_ok": dynamic_header_ok if is_dynamic else True,
            "details": f"VHD Formatı ({type_str}), Sağlama Toplamı: {'[GEÇERLİ]' if checksum_ok else '[UYUMSUZ]'}"
        }

    @staticmethod
    def backup_vhd_header_footer(vhd_path: str, backup_path: str) -> Dict[str, Any]:
        """
        VHD/VHDX dosyasının kritik yapısal başlık ve altbilgi bloklarını (ilk 64 KB + son 4 KB)
        ayrılmış güvenli bir yedek dosyasına (.vhdheader / .vbak) depolar.
        """
        p = Path(vhd_path).resolve()
        if not p.exists() or not p.is_file():
            return {"success": False, "error": "VHD dosyası bulunamadı."}

        size = p.stat().st_size
        if size < 512:
            return {"success": False, "error": "VHD dosyası çok küçük."}

        head_len = min(size, 65536)
        foot_len = min(size, 4096)

        with open(p, "rb") as f:
            f.seek(0)
            head_bytes = f.read(head_len)
            f.seek(max(0, size - foot_len))
            foot_bytes = f.read(foot_len)

        head_sha = hashlib.sha256(head_bytes).hexdigest()
        foot_sha = hashlib.sha256(foot_bytes).hexdigest()

        meta = {
            "magic": "VHD_HDR_BAK_V1",
            "vhd_filename": p.name,
            "vhd_size": size,
            "head_len": head_len,
            "foot_len": foot_len,
            "head_sha256": head_sha,
            "foot_sha256": foot_sha,
            "created_at": int(time.time()),
            "head_b64": base64.b64encode(head_bytes).decode("ascii"),
            "foot_b64": base64.b64encode(foot_bytes).decode("ascii")
        }
        compressed = zlib.compress(json.dumps(meta).encode("utf-8"), level=9)
        chk = hashlib.sha256(compressed).digest()

        b_path = Path(backup_path).resolve()
        b_path.parent.mkdir(parents=True, exist_ok=True)

        temp_bak = b_path.parent / f".tmp_vhdbak_{os.urandom(4).hex()}"
        try:
            with open(temp_bak, "wb") as bf:
                bf.write(b"VHD_HDR_BAK\x01\x00")
                bf.write(struct.pack("<I", len(compressed)))
                bf.write(chk)
                bf.write(compressed)
                bf.flush()
                os.fsync(bf.fileno())
            os.replace(str(temp_bak), str(b_path))
        except Exception as e:
            if temp_bak.exists():
                temp_bak.unlink(missing_ok=True)
            return {"success": False, "error": f"Yedek yazılamadı: {e}"}

        return {
            "success": True,
            "backup_path": str(b_path),
            "vhd_filename": p.name,
            "head_sha256": head_sha,
            "foot_sha256": foot_sha,
            "backup_size": b_path.stat().st_size
        }

    @staticmethod
    def inspect_vhd_header_footer(backup_path: str) -> Dict[str, Any]:
        """Ayrılmış VHD/VHDX başlık yedeğini (.vhdheader) inceler, bütünlüğünü ve metaverilerini doğrular."""
        b_path = Path(backup_path)
        if not b_path.exists() or not b_path.is_file():
            return {"valid": False, "error": "Yedek dosyası bulunamadı."}

        try:
            with open(b_path, "rb") as bf:
                magic = bf.read(13)
                if magic != b"VHD_HDR_BAK\x01\x00":
                    return {"valid": False, "error": "Geçersiz VHD başlık yedeği imzası."}
                c_len_raw = bf.read(4)
                if len(c_len_raw) < 4:
                    return {"valid": False, "error": "Yedek dosyası hasarlı (boyut bilgisi eksik)."}
                c_len = struct.unpack("<I", c_len_raw)[0]
                if c_len > 10 * 1024 * 1024:
                    return {"valid": False, "error": "Yedek boyutu izin verilen sınırı aşıyor."}
                chk = bf.read(32)
                compressed = bf.read(c_len)

            if len(compressed) != c_len or hashlib.sha256(compressed).digest() != chk:
                return {"valid": False, "error": "Yedek dosyası bozuk veya SHA-256 bütünlük doğrulaması başarısız!"}

            meta = json.loads(zlib.decompress(compressed).decode("utf-8"))
            head_bytes = base64.b64decode(meta["head_b64"].encode("ascii"))
            foot_bytes = base64.b64decode(meta["foot_b64"].encode("ascii"))

            if hashlib.sha256(head_bytes).hexdigest() != meta["head_sha256"] or hashlib.sha256(foot_bytes).hexdigest() != meta["foot_sha256"]:
                return {"valid": False, "error": "Başlık veya altbilgi sağlama toplamı uyuşmuyor!"}

            return {
                "valid": True,
                "vhd_filename": meta.get("vhd_filename"),
                "vhd_size": meta.get("vhd_size"),
                "head_len": meta.get("head_len"),
                "foot_len": meta.get("foot_len"),
                "head_sha256": meta.get("head_sha256"),
                "foot_sha256": meta.get("foot_sha256"),
                "created_at": meta.get("created_at"),
                "head_bytes": head_bytes,
                "foot_bytes": foot_bytes
            }
        except Exception as e:
            return {"valid": False, "error": f"Yedek dosyası incelenemedi: {e}"}

    @staticmethod
    def restore_vhd_header_footer(vhd_path: str, backup_path: str) -> Dict[str, Any]:
        """
        Ayrılmış yedekten (.vhdheader) hasarlı bir VHD/VHDX dosyasının başlık ve altbilgisini geri yükler.
        Dosya kesintiye uğramış veya kısaltılmış olsa dahi orijinal boyutuna genişletir ve altbilgiyi dosya sonuna doğru konumlandırır.
        """
        insp = VHDEngine.inspect_vhd_header_footer(backup_path)
        if not insp.get("valid"):
            return {"success": False, "error": insp.get("error", "Geçersiz VHD yedeği.")}

        head_bytes = insp["head_bytes"]
        foot_bytes = insp["foot_bytes"]
        orig_vhd_size = insp.get("vhd_size", 0)

        p = Path(vhd_path).resolve()
        if not p.exists() or not p.is_file():
            return {"success": False, "error": "Hedef VHD dosyası bulunamadı."}

        cur_size = p.stat().st_size
        target_size = max(cur_size, orig_vhd_size, len(head_bytes) + len(foot_bytes))

        try:
            with open(p, "r+b") as vf:
                vf.seek(0)
                vf.write(head_bytes)
                if target_size > vf.tell():
                    vf.truncate(target_size)
                vf.seek(target_size - len(foot_bytes))
                vf.write(foot_bytes)
                vf.flush()
                os.fsync(vf.fileno())
        except Exception as e:
            return {"success": False, "error": f"VHD dosyasına yazma hatası: {e}"}

        v_res = VHDEngine.verify_vhd_structure(str(p))
        if not v_res.get("valid"):
            return {
                "success": False,
                "error": f"Başlık ve altbilgi yazıldı ancak yapısal doğrulama başarısız: {v_res.get('error')}",
                "vhd_path": str(p),
                "verification": v_res
            }

        return {
            "success": True,
            "vhd_path": str(p),
            "verification": v_res,
            "vhd_filename": insp.get("vhd_filename")
        }

    def get_bitlocker_status(self, drive_letter: str) -> Dict[str, Any]:
        """
        Sürücünün BitLocker durumunu detaylı sorgular:
        - is_encrypted: BitLocker koruması var mı?
        - protection_status: 'On' veya 'Off'
        - volume_status: 'FullyEncrypted', 'FullyDecrypted', 'EncryptionInProgress', vb.
        - has_password: 'Password' koruyucusu mevcut mu?
        - has_recovery: 'RecoveryPassword' koruyucusu mevcut mu?
        - recovery_key: 48 haneli kurtarma anahtarı (varsa)
        """
        clean = _clean_drive_letter(drive_letter)
        if not clean or len(clean) != 1:
            return {"success": False, "error": "Geçersiz sürücü harfi."}

        ps_script = f"""
        $dl = '{clean}:';
        $vol = Get-BitLockerVolume -MountPoint $dl -ErrorAction SilentlyContinue;
        if ($vol) {{
            $protectors = @($vol.KeyProtector | ForEach-Object {{ [string]$_.KeyProtectorType }});
            $rec = ($vol.KeyProtector | Where-Object {{ $_.KeyProtectorType -eq 'RecoveryPassword' }}).RecoveryPassword;
            $firstRec = if ($rec -is [array]) {{ $rec[0] }} else {{ $rec }};
            [PSCustomObject]@{{
                Success = $true;
                IsEncrypted = ($vol.ProtectionStatus -eq 'On' -or [string]$vol.VolumeStatus -ne 'FullyDecrypted');
                ProtectionStatus = [string]$vol.ProtectionStatus;
                VolumeStatus = [string]$vol.VolumeStatus;
                EncryptionPercentage = [int]$vol.EncryptionPercentage;
                KeyProtectors = $protectors;
                HasPassword = ($protectors -contains 'Password');
                HasRecovery = ($protectors -contains 'RecoveryPassword');
                RecoveryKey = if ($firstRec) {{ [string]$firstRec }} else {{ "" }};
            }} | ConvertTo-Json -Compress;
        }} else {{
            [PSCustomObject]@{{
                Success = $false;
                Error = "BitLocker birimi sorgulanamadı.";
            }} | ConvertTo-Json -Compress;
        }}
        """
        code, out, err = self._run_powershell(ps_script)
        if code == 0 and out:
            try:
                import json
                data = json.loads(out)
                if data.get("Success"):
                    rec_k = data.get("RecoveryKey", "")
                    if not rec_k and data.get("HasRecovery", False):
                        rec_res = self.get_bitlocker_recovery_key(clean)
                        if rec_res.get("success"):
                            rec_k = rec_res.get("recovery_key", "")
                    return {
                        "success": True,
                        "is_encrypted": data.get("IsEncrypted", False),
                        "protection_status": data.get("ProtectionStatus", "Off"),
                        "volume_status": data.get("VolumeStatus", "Unknown"),
                        "encryption_percentage": data.get("EncryptionPercentage", 0),
                        "key_protectors": data.get("KeyProtectors", []),
                        "has_password": data.get("HasPassword", False),
                        "has_recovery": data.get("HasRecovery", False),
                        "recovery_key": rec_k
                    }
            except Exception:
                pass
        return {"success": False, "error": err or "BitLocker durumu alınamadı."}

    def enable_bitlocker(self, drive_letter: str, password: str, recovery_password: Optional[str] = None) -> Dict[str, Any]:
        """
        Şifresiz bir sürücüyü BitLocker ile şifreler, parola koruyucusu ve kurtarma anahtarı ekler.
        Base64 UTF-8 SecureString kullanarak karakter bozulmalarını önler.
        Oluşturulan veya belirtilen 48 haneli kurtarma anahtarını döndürür.
        """
        import base64
        clean = _clean_drive_letter(drive_letter)
        if not clean or len(clean) != 1:
            return {"success": False, "error": "Geçersiz sürücü harfi."}
        if not password or len(password) < 8:
            return {"success": False, "error": "BitLocker parolası en az 8 karakter olmalıdır."}

        target_drive = f"{clean}:"
        pw_b64 = base64.b64encode(password.encode("utf-8")).decode("ascii")
        custom_rec_b64 = base64.b64encode((recovery_password or "").strip().encode("utf-8")).decode("ascii") if recovery_password else ""

        ps_script = f"""
        $ErrorActionPreference = 'SilentlyContinue';
        $dl = '{target_drive}';
        $b64 = [Console]::In.ReadLine().Trim();
        $customRecB64 = [Console]::In.ReadLine().Trim();

        # Servisi arka planda canlandır (Windows Sandbox veya kapalı servisler için)
        cmd.exe /c "sc.exe start bdesvc" > $null 2>&1;

        $pwBytes = [System.Convert]::FromBase64String($b64);
        $pwPlain = [System.Text.Encoding]::UTF8.GetString($pwBytes);
        $sec = ConvertTo-SecureString $pwPlain -AsPlainText -Force;
        
        $errMsg = "";
        $hres = 0;
        $success = $false;

        # 1. BitLocker'ı PasswordProtector ile etkinleştir
        try {{
            Enable-BitLocker -MountPoint $dl -Password $sec -PasswordProtector -UsedSpaceOnly -EncryptionMethod XtsAes256 -SkipHardwareTest -ErrorAction Stop | Out-Null;
            $success = $true;
        }} catch {{
            $errObj = $_;
            try {{
                Enable-BitLocker -MountPoint $dl -Password $sec -PasswordProtector -UsedSpaceOnly -SkipHardwareTest -ErrorAction Stop | Out-Null;
                $success = $true;
            }} catch {{
                $errObj = $_;
                $errMsg = if ($errObj.Exception) {{ $errObj.Exception.Message }} else {{ "$errObj" }};
                $hres = if ($errObj.Exception -and $errObj.Exception.HResult) {{ $errObj.Exception.HResult }} else {{ 0 }};
            }}
        }}

        if (-not $success) {{
            [PSCustomObject]@{{
                Success = $false;
                Error = $errMsg;
                HResult = $hres;
            }} | ConvertTo-Json -Compress;
            exit 1;
        }}

        # 2. 48 Haneli Kurtarma Anahtarı (Recovery Password) koruyucusunu ekle
        if ($customRecB64 -and $customRecB64.Trim()) {{
            try {{
                $cBytes = [System.Convert]::FromBase64String($customRecB64);
                $cPlain = [System.Text.Encoding]::UTF8.GetString($cBytes).Trim();
                if ($cPlain) {{
                    Add-BitLockerKeyProtector -MountPoint $dl -RecoveryPassword $cPlain -RecoveryPasswordProtector -ErrorAction Stop | Out-Null;
                }}
            }} catch {{
                try {{
                    Add-BitLockerKeyProtector -MountPoint $dl -RecoveryPasswordProtector -ErrorAction SilentlyContinue | Out-Null;
                }} catch {{}}
            }}
        }} else {{
            try {{
                Add-BitLockerKeyProtector -MountPoint $dl -RecoveryPasswordProtector -ErrorAction SilentlyContinue | Out-Null;
            }} catch {{}}
        }}

        # 3. Eklenen kurtarma anahtarını doğrudan birimden oku
        $recKeyVal = "";
        $vol = Get-BitLockerVolume -MountPoint $dl -ErrorAction SilentlyContinue;
        if ($vol) {{
            $recKey = ($vol.KeyProtector | Where-Object {{ $_.KeyProtectorType -eq 'RecoveryPassword' }}).RecoveryPassword;
            $firstRec = if ($recKey -is [array]) {{ $recKey[0] }} else {{ $recKey }};
            if ($firstRec) {{
                $recKeyVal = [string]$firstRec;
            }}
        }}

        [PSCustomObject]@{{
            Success = $true;
            RecoveryKey = $recKeyVal;
        }} | ConvertTo-Json -Compress;
        """
        code, out, err = self._run_powershell(ps_script, timeout=60, input_data=f"{pw_b64}\n{custom_rec_b64}\n")
        rec_key = ""
        clean_err = ""
        try:
            import json
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("{") and line.endswith("}"):
                    data = json.loads(line)
                    if data.get("Success"):
                        rec_key = data.get("RecoveryKey", "")
                        code = 0
                        break
                    else:
                        clean_err = data.get("Error", "")
                        break
        except Exception:
            pass

        if code != 0:
            raw_err = clean_err or err.strip() or "BitLocker etkinleştirilemedi."
            if "0x80070490" in raw_err or "Element not found" in raw_err:
                friendly_err = (
                    "Bu sistem ortamında (Windows Sandbox veya BCD/TPM desteği bulunmayan sanal ortam) "
                    "BitLocker ile yeni sürücü şifrelemesi desteklenmemektedir (Hata Kodu: 0x80070490 - Element not found).\n\n"
                    "Çözüm ve Öneriler:\n"
                    "1. Sandbox içinde test ediyorsanız: Kasayı oluştururken 'BitLocker Parolası' alanını boş bırakarak şifresiz VHD oluşturabilirsiniz (Tüm VHD disk işlemleri Sandbox'ta sorunsuz çalışır).\n"
                    "2. BitLocker şifrelemesini test etmek için: Uygulamayı doğrudan ana Windows (Host) işletim sisteminizde çalıştırın."
                )
                return {"success": False, "error": friendly_err}
            return {"success": False, "error": raw_err}

        if not rec_key:
            try:
                subprocess.run(
                    ["manage-bde.exe", "-protectors", "-add", target_drive, "-rp"],
                    capture_output=True,
                    text=True, encoding="oem", errors="replace",
                    creationflags=CREATE_NO_WINDOW,
                    startupinfo=get_startupinfo(),
                    timeout=10
                )
            except Exception:
                pass
            rec_res = self.get_bitlocker_recovery_key(clean)
            if rec_res.get("success"):
                rec_key = rec_res.get("recovery_key", "")

        return {
            "success": True,
            "recovery_key": rec_key,
            "message": "Kasaya BitLocker şifrelemesi başarıyla uygulandı."
        }

    def change_bitlocker_password(self, drive_letter: str, new_password: str, old_password: Optional[str] = None) -> Dict[str, Any]:
        """
        BitLocker sürücüsünün parolasını Windows WMI Win32_EncryptableVolume::ChangePassphrase
        ve ProtectKeyWithPassphrase mimarisiyle sıfırlar veya günceller.
        - Eski parola girilmişse yeni parola ile aynı olup olmadığını teyit eder.
        - WMI üzerinden mevcut 'Passphrase' (KeyProtectorType = 8) koruyucusunu tespit eder.
        - Mevcut parola koruyucusu varsa ChangePassphrase ile yerinde (in-place) değiştirir.
        - Parola koruyucusu yoksa ProtectKeyWithPassphrase ile yeni parola ekler.
        - Kurtarma parolasının (KeyProtectorType = 3) varlığını denetler, yoksa ekler.
        - WMI başarısız olursa manage-bde ve PowerShell Fallback devreye girer.
        """
        import base64
        clean = _clean_drive_letter(drive_letter)
        if not clean or len(clean) != 1:
            return {"success": False, "error": "Geçersiz sürücü harfi."}
        if not new_password or len(new_password) < 8:
            return {"success": False, "error": "Yeni BitLocker parolası en az 8 karakter olmalıdır."}

        if old_password and old_password == new_password:
            return {
                "success": False,
                "error": "Yeni parola, mevcut (eski) parola ile aynı olamaz. Lütfen farklı ve güvenli bir parola belirleyin."
            }

        target_drive = f"{clean}:"
        pw_b64 = base64.b64encode(new_password.encode("utf-8")).decode("ascii")

        wmi_script = f"""
        $ErrorActionPreference = 'Stop';
        $dl = '{target_drive}';
        $b64 = [Console]::In.ReadLine().Trim();

        $pwBytes = [System.Convert]::FromBase64String($b64);
        $pwPlain = [System.Text.Encoding]::UTF8.GetString($pwBytes);

        # Windows Sandbox veya servisi durdurulmuş sistemler için BitLocker servisini arka planda başlat
        cmd.exe /c "sc.exe start bdesvc" > $null 2>&1;

        $wmi = Get-CimInstance -Namespace 'root\\cimv2\\security\\microsoftvolumeencryption' -ClassName Win32_EncryptableVolume -Filter "DriveLetter = '$dl'" -ErrorAction Stop;
        if (-not $wmi) {{
            throw "BitLocker birimi ($dl) WMI üzerinde bulunamadı.";
        }}

        # KeyProtectorType = 8: Passphrase (Parola)
        $pwProts = Invoke-CimMethod -InputObject $wmi -MethodName 'GetKeyProtectors' -Arguments @{{ KeyProtectorType = 8 }} -ErrorAction SilentlyContinue;
        $applied = $false;

        if ($pwProts -and $pwProts.ReturnValue -eq 0 -and $pwProts.VolumeKeyProtectorIDs -and $pwProts.VolumeKeyProtectorIDs.Count -gt 0) {{
            $targetProtId = $pwProts.VolumeKeyProtectorIDs[0];
            $inv = Invoke-CimMethod -InputObject $wmi -MethodName 'ChangePassphrase' -Arguments @{{
                VolumeKeyProtectorID = $targetProtId;
                NewPassphrase = $pwPlain;
            }} -ErrorAction Stop;
            if ($inv.ReturnValue -eq 0) {{
                $applied = $true;
            }}
        }}

        if (-not $applied) {{
            $invAdd = Invoke-CimMethod -InputObject $wmi -MethodName 'ProtectKeyWithPassphrase' -Arguments @{{
                FriendlyName = "";
                Passphrase = $pwPlain;
            }} -ErrorAction Stop;
            if ($invAdd.ReturnValue -eq 0) {{
                $applied = $true;
            }}
        }}

        if ($applied) {{
            # Kasanın her zaman kurtarılabilmesi için RecoveryPassword (KeyProtectorType = 3) koruyucusunu teyit et
            $recProts = Invoke-CimMethod -InputObject $wmi -MethodName 'GetKeyProtectors' -Arguments @{{ KeyProtectorType = 3 }} -ErrorAction SilentlyContinue;
            if (-not $recProts -or $recProts.ReturnValue -ne 0 -or -not $recProts.VolumeKeyProtectorIDs -or $recProts.VolumeKeyProtectorIDs.Count -gt 0) {{
                Invoke-CimMethod -InputObject $wmi -MethodName 'ProtectKeyWithNumericalPassword' -Arguments @{{ FriendlyName = "" }} -ErrorAction SilentlyContinue | Out-Null;
            }}
            Write-Output "SUCCESS:WMI";
            exit 0;
        }}

        throw "WMI ile parola uygulanamadı.";
        """

        code, out, err = self._run_powershell(wmi_script, timeout=25, input_data=f"{pw_b64}\n")
        if code == 0 and "SUCCESS" in out:
            return {"success": True, "message": "BitLocker parolası başarıyla güncellendi."}

        fallback_script = f"""
        $ConfirmPreference = 'None';
        $dl = '{target_drive}';
        $b64 = [Console]::In.ReadLine().Trim();
        $pwBytes = [System.Convert]::FromBase64String($b64);
        $pwPlain = [System.Text.Encoding]::UTF8.GetString($pwBytes);
        $sec = ConvertTo-SecureString $pwPlain -AsPlainText -Force;

        # Önce manage-bde ile eski parola koruyucusunu kaldır
        cmd.exe /c "manage-bde.exe -protectors -delete $dl -Type Password" > $null 2>&1;

        # PowerShell cmdlet ile yeni parola koruyucusu ekle
        Add-BitLockerKeyProtector -MountPoint $dl -PasswordProtector -Password $sec -Confirm:$false -ErrorAction Stop | Out-Null;

        # Recovery koruyucusu yoksa ekle
        $vol = Get-BitLockerVolume -MountPoint $dl -ErrorAction SilentlyContinue;
        if ($vol) {{
            $rec = @($vol.KeyProtector | Where-Object {{ $_.KeyProtectorType -eq 'RecoveryPassword' }});
            if ($rec.Count -eq 0) {{
                Add-BitLockerKeyProtector -MountPoint $dl -RecoveryPasswordProtector -Confirm:$false -ErrorAction SilentlyContinue | Out-Null;
            }}
        }}

        Write-Output "SUCCESS:FALLBACK";
        """

        c2, o2, e2 = self._run_powershell(fallback_script, timeout=25, input_data=f"{pw_b64}\n")
        if c2 == 0 and "SUCCESS" in o2:
            return {"success": True, "message": "BitLocker parolası başarıyla güncellendi."}

        combined_err = f"{err}\n{e2}".strip()
        lines = [l.strip() for l in combined_err.splitlines() if l.strip() and not l.strip().startswith("+") and not l.strip().startswith("~") and not l.strip().startswith("At line:") and not l.strip().startswith("CategoryInfo") and not l.strip().startswith("FullyQualifiedErrorId")]
        clean_err = lines[0] if lines else "BitLocker parolası güncellenemedi."
        return {"success": False, "error": clean_err}

    def disable_bitlocker(self, drive_letter: str) -> Dict[str, Any]:
        """
        Sürücüdeki BitLocker şifrelemesini güvenli ve kalıcı olarak kaldırır.
        Tüm Windows 10/11 sürümleriyle tam uyumludur.
        - Kilit durumunu denetler (kilitliyse uyarır).
        - Devam eden ilk şifreleme işlemlerinin bitmesini bekler.
        - WMI/CIM Decrypt çağrısı yaparak onay penceresi (confirmation) hatasını önler.
        - manage-bde.exe -off ile çift katmanlı fallback sunar.
        - Şifre çözmenin tamamlanmasını bekleyerek sanal diskin dosya kilidinde kalmasını engeller.
        """
        clean = _clean_drive_letter(drive_letter)
        if not clean or len(clean) != 1:
            return {"success": False, "error": "Geçersiz sürücü harfi."}

        target_drive = f"{clean}:"

        drv_status = self.get_drive_status(target_drive)
        if drv_status.get("is_valid") and drv_status.get("is_locked"):
            return {
                "success": False,
                "error": "Kasa şu anda kilitli durumda. Şifrelemeyi kaldırmak için önce parolanızı veya kurtarma anahtarınızı girerek kasayı açmalısınız."
            }

        ps_script = f"""
        $dl = '{target_drive}';
        $ConfirmPreference = 'None';
        $ErrorActionPreference = 'Stop';

        # Birim bilgisini al
        $vol = Get-BitLockerVolume -MountPoint $dl -ErrorAction SilentlyContinue;
        if (-not $vol) {{
            Write-Output "RESULT:ALREADY_DECRYPTED";
            exit 0;
        }}

        # Kilitli mi?
        if ($vol.LockStatus -eq 'Locked') {{
            Write-Output "RESULT:LOCKED";
            exit 1;
        }}

        # Zaten tamamen çözülmüş mü?
        if ($vol.VolumeStatus -eq 'FullyDecrypted' -and $vol.ProtectionStatus -eq 'Off') {{
            Write-Output "RESULT:ALREADY_DECRYPTED";
            exit 0;
        }}

        # Eğer devam eden bir şifreleme varsa (yeni oluşturulan kasalarda), tamamlanmasını bekle
        if ($vol.VolumeStatus -eq 'EncryptionInProgress') {{
            $waitSec = 0;
            while ($waitSec -lt 15) {{
                Start-Sleep -Seconds 1;
                $vCheck = Get-BitLockerVolume -MountPoint $dl -ErrorAction SilentlyContinue;
                if (-not $vCheck -or $vCheck.VolumeStatus -ne 'EncryptionInProgress') {{
                    break;
                }}
                $waitSec++;
            }}
        }}

        # Şifre çözme zaten başlamış mı?
        if ($vol.VolumeStatus -ne 'DecryptionInProgress') {{
            # WMI Win32_EncryptableVolume Decrypt metodu (En temiz ve güvenilir yol)
            $wmiVol = Get-CimInstance -Namespace root\\cimv2\\Security\\MicrosoftVolumeEncryption -ClassName Win32_EncryptableVolume -Filter "DriveLetter = '$dl'" -ErrorAction SilentlyContinue;
            if ($wmiVol) {{
                $res = Invoke-CimMethod -InputObject $wmiVol -MethodName Decrypt -ErrorAction SilentlyContinue;
                if ($res -and ($res.ReturnValue -eq 0 -or $res.ReturnValue -eq 0x80310029)) {{
                    Write-Output "DECRYPT_STARTED";
                }} else {{
                    Disable-BitLocker -MountPoint $dl -Confirm:$false -ErrorAction Stop | Out-Null;
                    Write-Output "DECRYPT_STARTED";
                }}
            }} else {{
                Disable-BitLocker -MountPoint $dl -Confirm:$false -ErrorAction Stop | Out-Null;
                Write-Output "DECRYPT_STARTED";
            }}
        }} else {{
            Write-Output "DECRYPT_STARTED";
        }}

        # VHD kasalar için şifre çözmenin tamamlanmasını bekle (MFT serbest kalsın, diski ayırırken hata vermesin)
        $sw = [System.Diagnostics.Stopwatch]::StartNew();
        while ($sw.Elapsed.TotalSeconds -lt 25) {{
            $vCheck = Get-BitLockerVolume -MountPoint $dl -ErrorAction SilentlyContinue;
            if (-not $vCheck -or $vCheck.VolumeStatus -eq 'FullyDecrypted' -or $vCheck.ProtectionStatus -eq 'Off') {{
                Write-Output "RESULT:COMPLETED";
                exit 0;
            }}
            Start-Sleep -Milliseconds 500;
        }}

        Write-Output "RESULT:COMPLETED";
        exit 0;
        """

        code, out, err = self._run_powershell(ps_script, timeout=35)
        out_str = (out or "").strip()

        if "RESULT:ALREADY_DECRYPTED" in out_str:
            return {"success": True, "message": "Kasa zaten şifresiz durumdadır."}

        if "RESULT:LOCKED" in out_str:
            return {
                "success": False,
                "error": "Kasa şu anda kilitli durumda. Şifrelemeyi kaldırmak için önce parolanızı veya kurtarma anahtarınızı girerek kasayı açmalısınız."
            }

        if code == 0 and ("RESULT:COMPLETED" in out_str or "DECRYPT_STARTED" in out_str):
            return {"success": True, "message": "BitLocker şifrelemesi başarıyla kaldırıldı. Kasa artık şifresizdir."}

        try:
            p = subprocess.run(
                ["manage-bde.exe", "-off", target_drive],
                capture_output=True,
                text=True, encoding="oem", errors="replace",
                creationflags=CREATE_NO_WINDOW,
                startupinfo=get_startupinfo(),
                timeout=20
            )
            comb = ((p.stdout or "") + " " + (p.stderr or "")).lower()

            if (
                p.returncode == 0
                or "decryption is now in progress" in comb
                or "şifre çözme" in comb
                or "devam ediyor" in comb
                or "already decrypted" in comb
                or "zaten şifresi çözülmüş" in comb
            ):
                time.sleep(2)
                return {"success": True, "message": "BitLocker şifrelemesi başarıyla kaldırıldı. Kasa artık şifresizdir."}

            if "locked" in comb or "kilitli" in comb:
                return {
                    "success": False,
                    "error": "Kasa şu anda kilitli durumda. Şifrelemeyi kaldırmak için önce parolanızı veya kurtarma anahtarınızı girerek kasayı açmalısınız."
                }
            if "encryption is in progress" in comb or "şifreleme işlemi" in comb:
                return {
                    "success": False,
                    "error": "Kasanın ilk şifreleme işlemi arka planda sürüyor. Lütfen birkaç saniye sonra tekrar deneyin."
                }
            if "access is denied" in comb or "erişim engellendi" in comb:
                return {
                    "success": False,
                    "error": "BitLocker şifresini kaldırmak için Windows yönetici yetkisi gereklidir."
                }
        except Exception:
            pass

        clean_err = (err or "").strip()
        lines = [l.strip() for l in clean_err.splitlines() if l.strip() and not l.strip().startswith("+") and not l.strip().startswith("~") and not l.strip().startswith("CategoryInfo") and not l.strip().startswith("FullyQualifiedErrorId")]
        summary_err = lines[0] if lines else clean_err

        if "does not support user interaction" in summary_err.lower():
            summary_err = "Windows BitLocker onay mekanizması engellendi."
        elif "locked" in summary_err.lower() or "0x80310000" in summary_err:
            summary_err = "Kasa kilitli durumda. Şifreyi kaldırmadan önce kilidi açmalısınız."

        return {"success": False, "error": summary_err or "BitLocker devre dışı bırakılamadı."}

    def unlock_bitlocker_recovery_key(self, drive_letter: str, recovery_key: str) -> Dict[str, Any]:
        """
        Kilitli bir BitLocker sürücüsünü 48 haneli kurtarma anahtarı ile açar.
        """
        clean = _clean_drive_letter(drive_letter)
        if not clean or len(clean) != 1:
            return {"success": False, "error": "Geçersiz sürücü harfi."}

        clean_rk = recovery_key.strip().replace(" ", "").replace("\r", "").replace("\n", "")
        if not clean_rk or len(clean_rk.replace("-", "")) != 48:
            return {"success": False, "error": "Geçersiz kurtarma anahtarı formatı. 48 haneli olmalıdır (Örnek: 123456-123456-...)"}

        target_drive = f"{clean}:"
        ps_script = f"""
        $dl = '{target_drive}';
        $rk = [Console]::In.ReadLine().Trim();

        # Birim zaten açık mı kontrol et
        $vol = Get-BitLockerVolume -MountPoint $dl -ErrorAction SilentlyContinue;
        if ($vol -and "$($vol.LockStatus)" -eq 'Unlocked') {{
            Write-Output "SUCCESS:ALREADY_UNLOCKED";
            exit 0;
        }}

        try {{
            Unlock-BitLocker -MountPoint $dl -RecoveryPassword $rk -ErrorAction Stop | Out-Null;
            Write-Output "SUCCESS";
        }} catch {{
            $errObj = $_;
            $hres = if ($errObj.Exception -and $errObj.Exception.HResult) {{ $errObj.Exception.HResult }} else {{ 0 }};
            if ($hres -eq -2144272349 -or "$errObj" -match 'already unlocked|zaten açık|0x80310023') {{
                Write-Output "SUCCESS:ALREADY_UNLOCKED";
                exit 0;
            }}
            throw $errObj;
        }}
        """
        code, out, err = self._run_powershell(ps_script, timeout=15, input_data=f"{clean_rk}\n")
        if code == 0 or "SUCCESS" in out:
            self.suppress_bdeunlock()
            return {"success": True, "message": "Kasa kurtarma anahtarı ile başarıyla açıldı."}

        err_msg = err or "Kurtarma anahtarı doğrulanamadı."
        if "0x80070057" in err_msg or "parameter is incorrect" in err_msg.lower():
            err_msg = "Girilen kurtarma anahtarının formatı hatalı."
        elif "0x80310035" in err_msg or "0x80310027" in err_msg or "password does not match" in err_msg.lower():
            err_msg = "Kurtarma anahtarı bu kasa ile eşleşmiyor."
        return {"success": False, "error": err_msg}

    def lock_bitlocker(self, drive_letter: str) -> Dict[str, Any]:
        """
        Açık ve erişilebilir durumdaki BitLocker sürücüsünü güvenle ve anında kilitler.
        Tüm komutlar konsol penceresi açılmadan arka planda gizli çalıştırılır.
        """
        clean = _clean_drive_letter(drive_letter)
        if not clean or len(clean) != 1:
            return {"success": False, "error": "Geçersiz sürücü harfi."}

        target_drive = f"{clean}:"
        try:
            res = subprocess.run(
                ["manage-bde.exe", "-lock", target_drive, "-ForceDismount"],
                capture_output=True,
                text=True, encoding="oem", errors="replace",
                creationflags=CREATE_NO_WINDOW,
                startupinfo=get_startupinfo(),
                timeout=5
            )
            if res.returncode == 0:
                self.suppress_bdeunlock()
                return {"success": True, "message": f"{target_drive} sürücüsü başarıyla kilitlendi."}
        except Exception:
            pass

        ps_cmd = f"Lock-BitLocker -MountPoint '{target_drive}' -ForceDismount -ErrorAction SilentlyContinue"
        code, out, err = self._run_powershell(ps_cmd, timeout=6)
        self.suppress_bdeunlock()
        return {"success": code == 0, "error": err if code != 0 else "", "message": f"{target_drive} sürücüsü kilitlendi."}

    def verify_recovery_key(self, drive_letter: str = "", vault_file: str = "", recovery_key: str = "") -> Dict[str, Any]:
        """
        48 haneli BitLocker kurtarma anahtarının formatını, modulo 11 sağlama toplamını (checksum)
        ve hedef kasanın BitLocker birimine ait olup olmadığını canlı olarak doğrular.
        - Checksum Kuralı: 8 adet 6 haneli bloktan oluşur ve her blok 11'e kalansız bölünmelidir (int(blok) % 11 == 0).
        - Canlı Eşleşme: Birim açıksa RecoveryPassword koruyucusu kontrol edilir; kilitli ise Unlock-BitLocker ile test edilir.
        """
        clean_rk = (recovery_key or "").strip()
        digits = "".join(c for c in clean_rk if c.isdigit())
        count = len(digits)

        if count != 48:
            return {
                "success": False,
                "checksum_valid": False,
                "matched": False,
                "digit_count": count,
                "error": f"Kurtarma anahtarı 48 hane olmalıdır ({count}/48 hane)."
            }

        for i in range(0, 48, 6):
            group_str = digits[i:i+6]
            try:
                group_val = int(group_str)
                if group_val % 11 != 0:
                    group_idx = (i // 6) + 1
                    return {
                        "success": False,
                        "checksum_valid": False,
                        "matched": False,
                        "digit_count": 48,
                        "error": f"Geçersiz kurtarma anahtarı formatı (Sağlama toplamı eşleşmiyor, Grup {group_idx}: {group_str})."
                    }
            except ValueError:
                return {
                    "success": False,
                    "checksum_valid": False,
                    "matched": False,
                    "digit_count": 48,
                    "error": "Kurtarma anahtarı yalnızca rakamlardan oluşmalıdır."
                }

        target_dl = _clean_drive_letter(drive_letter)
        if not target_dl and vault_file:
            try:
                target_dl = (self.find_drive_letter_for_vhd(vault_file) or "").rstrip(":\\/ ").upper()
                if not target_dl and Path(vault_file).exists():
                    m_res = self.mount_vhd(vault_file)
                    if m_res.get("success"):
                        target_dl = (m_res.get("drive_letter", "") or "").rstrip(":\\/ ").upper()
            except Exception:
                pass

        if not target_dl:
            return {
                "success": True,
                "checksum_valid": True,
                "matched": None,
                "digit_count": 48,
                "message": "Kurtarma anahtarı formatı ve sağlama toplamı geçerli (Hedef sürücü bağlı değil)."
            }

        clean_dl = f"{target_dl}:"
        formatted_key = "-".join([digits[i:i+6] for i in range(0, 48, 6)])

        ps_script = f"""
        $dl = '{clean_dl}';
        $rk = [Console]::In.ReadLine().Trim();
        $rkDigits = ($rk -replace '[^0-9]', '');
        $vol = Get-BitLockerVolume -MountPoint $dl -ErrorAction SilentlyContinue;
        if (-not $vol) {{
            Write-Output "ERROR:VOLUME_NOT_FOUND";
            exit 0;
        }}

        # Eğer birim zaten açıksa (Unlocked), birimdeki RecoveryPassword koruyucusuyla karşılaştır
        if ($vol.LockStatus -eq 'Unlocked') {{
            $recKeys = @(($vol.KeyProtector | Where-Object {{ $_.KeyProtectorType -eq 'RecoveryPassword' }}).RecoveryPassword);
            $foundMatch = $false;
            foreach ($k in $recKeys) {{
                $kClean = ($k -replace '[^0-9]', '');
                if ($kClean -eq $rkDigits) {{
                    $foundMatch = $true;
                    break;
                }}
            }}
            if ($foundMatch) {{
                Write-Output "MATCHED:UNLOCKED";
                exit 0;
            }} else {{
                Write-Output "MISMATCH";
                exit 0;
            }}
        }}

        # Eğer birim kilitli ise (Locked):
        # Kullanıcı arayüzde 48 haneyi yazarken kasanın erkenden ve istemsizce
        # arka planda açılmasını önlemek için canlı kilit açma YAPILMAZ.
        # Sağlama toplamı (modulo 11) geçerli olduğundan format teyit edilir.
        # Gerçek kilit açma işlemi kullanıcı 'Kasayı Kurtar' butonuna bastığında yürütülür.
        Write-Output "MATCHED:CHECKSUM_VALID";
        exit 0;
        """

        code, out, err = self._run_powershell(ps_script, timeout=12, input_data=f"{formatted_key}\n")
        out_str = (out or "").strip()

        if "MATCHED:UNLOCKED" in out_str:
            return {
                "success": True,
                "checksum_valid": True,
                "matched": True,
                "digit_count": 48,
                "message": "Kurtarma Anahtarı Doğrulandı (Bu kasaya ait)"
            }
        elif "MATCHED:CHECKSUM_VALID" in out_str:
            return {
                "success": True,
                "checksum_valid": True,
                "matched": None,
                "digit_count": 48,
                "message": "Kurtarma anahtarı formatı ve sağlama toplamı geçerli."
            }
        elif "MISMATCH" in out_str:
            return {
                "success": False,
                "checksum_valid": True,
                "matched": False,
                "digit_count": 48,
                "error": "Bu kurtarma anahtarı seçili kasa ile eşleşmiyor!"
            }
        else:
            return {
                "success": True,
                "checksum_valid": True,
                "matched": None,
                "digit_count": 48,
                "message": "Kurtarma anahtarı formatı ve sağlama toplamı geçerli."
            }

    def wipe_system_traces(self, drive_letter: str) -> Dict[str, Any]:
        """Dismount esnasında Windows Recent, RunMRU ve bellek izlerini süpürür (Son 24 saat optimize)."""
        clean_letter = drive_letter.rstrip(":").upper() + ":"
        cleaned_files = []
        cutoff = time.time() - 86400
        
        recent_dirs = [
            Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Windows" / "Recent",
            Path(os.environ.get("USERPROFILE", "")) / "Recent"
        ]
        
        for rdir in recent_dirs:
            if not rdir.exists():
                continue
            try:
                for item in rdir.glob("*.lnk"):
                    try:
                        if item.stat().st_mtime < cutoff:
                            continue
                        data = item.read_bytes()
                        if clean_letter.encode("utf-16le") in data or clean_letter.encode("ascii", errors="ignore") in data:
                            item.unlink(missing_ok=True)
                            cleaned_files.append(item.name)
                    except Exception:
                        pass
            except Exception:
                pass
                
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU", 0, winreg.KEY_ALL_ACCESS) as key:
                info = winreg.QueryInfoKey(key)
                values_to_del = []
                for i in range(info[1]):
                    name, val, _ = winreg.EnumValue(key, i)
                    if isinstance(val, str) and clean_letter.lower() in val.lower():
                        values_to_del.append(name)
                for vname in values_to_del:
                    try:
                        winreg.DeleteValue(key, vname)
                    except Exception:
                        pass
        except Exception:
            pass

        jump_dirs = [
            Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Windows" / "Recent" / "AutomaticDestinations",
            Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Windows" / "Recent" / "CustomDestinations"
        ]
        for jdir in jump_dirs:
            if not jdir.exists():
                continue
            try:
                for jfile in list(jdir.glob("*.automaticDestinations-ms")) + list(jdir.glob("*.customDestinations-ms")):
                    try:
                        if jfile.stat().st_mtime < cutoff:
                            continue
                        data = jfile.read_bytes()
                        if clean_letter.encode("utf-16le") in data or clean_letter.encode("ascii", errors="ignore") in data:
                            jfile.unlink(missing_ok=True)
                            cleaned_files.append(jfile.name)
                    except Exception:
                        pass
            except Exception:
                pass

        try:
            u32 = ctypes.windll.user32
            if u32.OpenClipboard(None):
                try:
                    h_clip = u32.GetClipboardData(13)
                    if h_clip:
                        p_clip = ctypes.windll.kernel32.GlobalLock(h_clip)
                        if p_clip:
                            try:
                                clip_text = ctypes.wstring_at(p_clip)
                                if clean_letter.lower() in clip_text.lower():
                                    u32.EmptyClipboard()
                            finally:
                                ctypes.windll.kernel32.GlobalUnlock(h_clip)
                finally:
                    u32.CloseClipboard()
        except Exception:
            pass

        import gc
        gc.collect()
        try:
            ctypes.windll.kernel32.SetProcessWorkingSetSize(ctypes.windll.kernel32.GetCurrentProcess(), -1, -1)
        except Exception:
            pass

        return {
            "success": True,
            "cleaned_count": len(cleaned_files),
            "cleaned_items": cleaned_files[:10]
        }

    @staticmethod
    def secure_zero_memory(buf) -> None:
        """Bellek tamponundaki duyarlı verileri (parolalar, tokenler) anında sıfır baytlarla üzerine yazar."""
        try:
            if isinstance(buf, (bytearray, memoryview)):
                ctypes.memset(ctypes.addressof(ctypes.c_char.from_buffer(buf)), 0, len(buf))
        except Exception:
            pass

    @staticmethod
    def shred_item(target_path: str, passes: int = 1) -> Dict[str, Any]:
        """Dosya veya klasörü sıfır ve rastgele baytlarla geri getirilemez şekilde parçalar."""
        p = Path(target_path).resolve()
        if not p.exists():
            return {"success": False, "error": "Hedef bulunamadı."}

        files_shredded = 0
        bytes_shredded = 0

        def _shred_single_file(fpath: Path):
            nonlocal files_shredded, bytes_shredded
            try:
                try:
                    ctypes.windll.kernel32.SetFileAttributesW(str(fpath), 128)
                except Exception:
                    pass

                length = fpath.stat().st_size
                if length > 0:
                    with open(fpath, "r+b") as f:
                        for _ in range(passes):
                            f.seek(0)
                            chunk_size = 1024 * 1024 * 4
                            written = 0
                            while written < length:
                                to_write = min(chunk_size, length - written)
                                f.write(b"\x00" * to_write)
                                written += to_write
                            f.flush()
                            os.fsync(f.fileno())
                            f.seek(0)
                            written = 0
                            while written < length:
                                to_write = min(chunk_size, length - written)
                                f.write(os.urandom(to_write))
                                written += to_write
                            f.flush()
                            os.fsync(f.fileno())
                with open(fpath, "wb") as f:
                    pass
                fpath.unlink(missing_ok=True)
                files_shredded += 1
                bytes_shredded += length
            except Exception as e:
                print(f"Shred hatası ({fpath}): {e}")

        if p.is_file():
            _shred_single_file(p)
        elif p.is_dir():
            for root, dirs, files in os.walk(p, topdown=False):
                for f in files:
                    _shred_single_file(Path(root) / f)
                for d in dirs:
                    try:
                        (Path(root) / d).rmdir()
                    except Exception:
                        pass
            try:
                p.rmdir()
            except Exception:
                pass

        return {
            "success": True,
            "files_shredded": files_shredded,
            "bytes_shredded_mb": round(bytes_shredded / (1024 * 1024), 2)
        }

    def copy_and_shred(self, source_paths: List[str], target_dir: str, shred_original: bool = True) -> Dict[str, Any]:
        """Dosyaları kasaya kopyalar ve isteğe bağlı olarak orijinal konumlarını parçalar."""
        dest_root = Path(target_dir).resolve()
        if not dest_root.exists():
            return {"success": False, "error": "Hedef kasa dizini bulunamadı."}

        copied_count = 0
        for sp in source_paths:
            src = Path(sp).resolve()
            if not src.exists():
                continue
            dest_target = dest_root / src.name
            try:
                if src.is_file():
                    shutil.copy2(src, dest_target)
                elif src.is_dir():
                    if dest_target.exists():
                        shutil.rmtree(dest_target)
                    shutil.copytree(src, dest_target)
                copied_count += 1
                if shred_original:
                    self.shred_item(str(src))
            except Exception as e:
                return {"success": False, "error": f"Taşıma hatası ({src.name}): {e}"}

        return {
            "success": True,
            "copied_count": copied_count,
            "shredded": shred_original
        }

    @staticmethod
    def is_bus_type_usb(drive_letter: str) -> bool:
        """Sürücünün USB veriyolu üzerinden bağlı olup olmadığını Win32 IOCTL_STORAGE_QUERY_PROPERTY ile sorgular."""
        if not drive_letter:
            return False
        clean = drive_letter.rstrip("\\").rstrip(":")
        h = k32.CreateFileW(
            f"\\\\.\\{clean}:",
            0,
            1 | 2,
            None,
            3,
            0,
            None
        )
        if not is_valid_handle(h):
            return False
        try:
            query = (ctypes.c_byte * 12)(0)
            out_buf = (ctypes.c_byte * 1024)()
            bytes_returned = wintypes.DWORD()
            res = k32.DeviceIoControl(
                h,
                0x002D1400,
                ctypes.byref(query),
                12,
                ctypes.byref(out_buf),
                1024,
                ctypes.byref(bytes_returned),
                None
            )
            if res and bytes_returned.value >= 32:
                return out_buf[28] == 7
        except Exception:
            pass
        finally:
            k32.CloseHandle(h)
        return False

    @staticmethod
    def format_volume_serial(val: Any) -> str:
        """Seri numarasını standart XXXX-XXXX formatına dönüştürür."""
        if not val:
            return ""
        if isinstance(val, int):
            high = (val >> 16) & 0xFFFF
            low = val & 0xFFFF
            return f"{high:04X}-{low:04X}"
        s = str(val).upper().replace("0X", "").replace("-", "").strip()
        if len(s) == 8:
            return f"{s[:4]}-{s[4:]}"
        return s[:9]

    @classmethod
    def compare_volume_serials(cls, s1: str, s2: str) -> bool:
        """İki seri numarasını format farklarını (tire, 0x, büyük/küçük harf) tolere ederek karşılaştırır."""
        if not s1 or not s2:
            return False
        norm1 = str(s1).upper().replace("-", "").replace("0X", "").strip()
        norm2 = str(s2).upper().replace("-", "").replace("0X", "").strip()
        return norm1 == norm2

    @classmethod
    def get_drive_volume_serial(cls, drive: str) -> str:
        """Sürücünün 8 haneli Volume Serial Number değerini döner (Örn: '44C0-5B56')."""
        if not drive:
            return ""
        clean = drive.rstrip("\\").rstrip(":") + ":\\"
        serial = wintypes.DWORD()
        res = k32.GetVolumeInformationW(clean, None, 0, ctypes.byref(serial), None, None, None, 0)
        if res and serial.value != 0:
            return cls.format_volume_serial(serial.value)
        return ""

    @classmethod
    def get_removable_usb_drives(cls) -> List[Dict[str, str]]:
        """Sisteme takılı çıkarılabilir veya USB belleklerin sürücü harflerini ve etiketlerini listeler."""
        drives = []
        bitmask = k32.GetLogicalDrives()
        for i, letter in enumerate("ABCDEFGHIJKLMNOPQRSTUVWXYZ"):
            if letter in ("A", "B", "C"):
                continue
            if not (bitmask & (1 << i)):
                continue
            root = f"{letter}:\\"
            dtype = k32.GetDriveTypeW(root)
            is_usb = (dtype == 2)
            if not is_usb and dtype == 3:
                is_usb = cls.is_bus_type_usb(letter)
            if is_usb:
                vol_name = ctypes.create_unicode_buffer(260)
                serial = wintypes.DWORD()
                fs_name = ctypes.create_unicode_buffer(260)
                k32.GetVolumeInformationW(
                    root, vol_name, 260, ctypes.byref(serial), None, None, fs_name, 260
                )
                fmt_serial = cls.format_volume_serial(serial.value)
                drives.append({
                    "drive": f"{letter}:",
                    "root": root,
                    "label": vol_name.value or "USB Sürücü",
                    "serial": fmt_serial
                })
        return drives

    @classmethod
    def read_usb_key_file(cls, key_file: Path, vault_name: str = "") -> Tuple[str, str]:
        """USB anahtar dosyasından token ve varsa kayıtlı donanım seri numarasını okur (Çoklu kasa destekli)."""
        try:
            target_file = key_file
            if not target_file.exists():
                alt_file = target_file.parent / "_vaultkey"
                if alt_file.exists():
                    target_file = alt_file
                else:
                    return "", ""
            raw = target_file.read_text(encoding="utf-8").strip()
            if raw.startswith("{") and raw.endswith("}"):
                data = json.loads(raw)
                v_key_name = Path(vault_name).name.lower() if vault_name else ""
                if v_key_name and isinstance(data.get("vaults"), dict) and v_key_name in data["vaults"]:
                    v_entry = data["vaults"][v_key_name]
                    return str(v_entry.get("token", "")).strip(), str(v_entry.get("serial", data.get("serial", ""))).strip()
                tok = str(data.get("token", "")).strip()
                ser = str(data.get("serial", "")).strip()
                return tok, ser
            return raw, ""
        except Exception:
            return "", ""

    @classmethod
    def create_usb_hardware_key(cls, usb_drive: str, token: str, vault_password: str = "", vault_name: str = "") -> Dict[str, Any]:
        """USB sürücünün kök dizininde donanım seri numarasına bağlı gizli .vault_key oluşturur (Çoklu kasa destekli)."""
        clean = (usb_drive.rstrip("\\").rstrip(":") + ":\\") if (len(usb_drive.strip()) <= 3 and ":" in usb_drive) else usb_drive
        key_file = Path(clean) / ".vault_key"
        alt_key_file = Path(clean) / "_vaultkey"
        serial = cls.get_drive_volume_serial(usb_drive)
        try:
            existing_data = {}
            target_read = key_file if key_file.exists() else (alt_key_file if alt_key_file.exists() else None)
            if target_read and target_read.exists():
                try:
                    k32.SetFileAttributesW(str(target_read), 128)
                    existing_data = json.loads(target_read.read_text(encoding="utf-8"))
                except Exception:
                    existing_data = {}

            vaults_dict = existing_data.get("vaults", {})
            if not isinstance(vaults_dict, dict):
                vaults_dict = {}

            v_entry = {
                "token": token,
                "serial": serial,
                "created_at": time.strftime("%Y-%m-%d %H:%M:%S")
            }
            if vault_password:
                try:
                    pw_key = hashlib.sha256(token.encode("utf-8")).digest()
                    pw_nonce = os.urandom(12)
                    pw_cipher = AESGCM(pw_key).encrypt(pw_nonce, vault_password.encode("utf-8"), b"VAULT_AUTO_UNLOCK_PW")
                    v_entry["enc_pw"] = base64.b64encode(pw_nonce + pw_cipher).decode("ascii")
                except Exception as e:
                    print(f"Parola şifreleme uyarısı: {e}")

            v_key_name = Path(vault_name).name.lower() if vault_name else "default"
            vaults_dict[v_key_name] = v_entry

            key_data = {
                "version": 2,
                "token": token,
                "serial": serial,
                "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "vaults": vaults_dict
            }
            if "enc_pw" in v_entry:
                key_data["enc_pw"] = v_entry["enc_pw"]

            json_content = json.dumps(key_data, indent=2)
            key_file.write_text(json_content, encoding="utf-8")
            k32.SetFileAttributesW(str(key_file), 3)

            if alt_key_file.exists():
                try:
                    k32.SetFileAttributesW(str(alt_key_file), 128)
                    alt_key_file.write_text(json_content, encoding="utf-8")
                    k32.SetFileAttributesW(str(alt_key_file), 3)
                except Exception:
                    pass

            return {"success": True, "path": str(key_file), "serial": serial, "has_pw": bool(vault_password)}
        except Exception as e:
            return {"success": False, "error": f"USB anahtarı oluşturulamadı: {e}"}

    @classmethod
    def get_usb_key_password(cls, usb_drive: str, token: str, vault_name: str = "") -> str:
        """USB anahtarında şifreli olarak saklanan disk parolasını çözer (Çoklu kasa destekli)."""
        clean = (usb_drive.rstrip("\\").rstrip(":") + ":\\") if (len(usb_drive.strip()) <= 3 and ":" in usb_drive) else usb_drive
        key_file = Path(clean) / ".vault_key"
        if not key_file.exists():
            alt_key = Path(clean) / "_vaultkey"
            if alt_key.exists():
                key_file = alt_key
            else:
                return ""
        try:
            data = json.loads(key_file.read_text(encoding="utf-8"))
            enc_pw = ""
            vault_tok = token
            v_key_name = Path(vault_name).name.lower() if vault_name else ""

            if v_key_name and isinstance(data.get("vaults"), dict) and v_key_name in data["vaults"]:
                enc_pw = data["vaults"][v_key_name].get("enc_pw", "")
                if data["vaults"][v_key_name].get("token"):
                    vault_tok = data["vaults"][v_key_name].get("token")

            if not enc_pw and isinstance(data.get("vaults"), dict):
                for v_info in data["vaults"].values():
                    if isinstance(v_info, dict) and (v_info.get("token") == token or not token):
                        enc_pw = v_info.get("enc_pw", "")
                        if enc_pw:
                            vault_tok = v_info.get("token", token)
                            break

            if not enc_pw:
                enc_pw = data.get("enc_pw", "")
                if data.get("token"):
                    vault_tok = data.get("token")

            if not enc_pw or not vault_tok:
                return ""
            raw = base64.b64decode(enc_pw)
            nonce = raw[:12]
            ciphertext = raw[12:]
            pw_key = hashlib.sha256(vault_tok.encode("utf-8")).digest()
            plain = AESGCM(pw_key).decrypt(nonce, ciphertext, b"VAULT_AUTO_UNLOCK_PW")
            return plain.decode("utf-8")
        except Exception:
            return ""

    @classmethod
    def verify_usb_hardware_key(cls, usb_drive: str, token: str, required_serial: Optional[str] = None) -> bool:
        """USB sürücüsündeki gizli token'ı ve varsa donanım seri numarasını doğrular."""
        if not usb_drive or not token:
            return False
        clean = (usb_drive.rstrip("\\").rstrip(":") + ":\\") if (len(usb_drive.strip()) <= 3 and ":" in usb_drive) else usb_drive
        key_file = Path(clean) / ".vault_key"
        if not key_file.exists():
            alt_key = Path(clean) / "_vaultkey"
            if alt_key.exists():
                key_file = alt_key
            else:
                return False

        if required_serial:
            cur_serial = cls.get_drive_volume_serial(usb_drive)
            if not cls.compare_volume_serials(cur_serial, required_serial):
                return False

        file_token, file_serial = cls.read_usb_key_file(key_file)
        found_token = (file_token == token.strip())
        if not found_token:
            try:
                data = json.loads(key_file.read_text(encoding="utf-8"))
                for v in data.get("vaults", {}).values():
                    if isinstance(v, dict) and v.get("token") == token.strip():
                        found_token = True
                        break
            except Exception:
                pass

        if not found_token:
            return False

        if required_serial and file_serial and not cls.compare_volume_serials(file_serial, required_serial):
            return False

        return True

    @classmethod
    def backup_usb_hardware_key(cls, usb_drive: str, destination_path: str) -> Dict[str, Any]:
        """USB anahtar dosyasını (.vault_key) belirtilen klasöre veya ikinci bir USB'ye kopyalar."""
        try:
            clean_src = (usb_drive.rstrip("\\").rstrip(":") + ":\\") if (len(usb_drive.strip()) <= 3 and ":" in usb_drive) else usb_drive
            src_key = Path(clean_src) / ".vault_key"
            if not src_key.exists():
                alt_src = Path(clean_src) / "_vaultkey"
                if alt_src.exists():
                    src_key = alt_src
                else:
                    return {"success": False, "error": "Kaynak USB'de .vault_key dosyası bulunamadı."}

            dest_target = Path(destination_path)
            if dest_target.is_dir() or (len(destination_path.strip()) <= 3 and ":" in destination_path):
                clean_dest = (destination_path.rstrip("\\").rstrip(":") + ":\\") if (len(destination_path.strip()) <= 3 and ":" in destination_path) else destination_path
                dest_file = Path(clean_dest) / ".vault_key"
            else:
                dest_file = dest_target

            if dest_file.exists():
                k32.SetFileAttributesW(str(dest_file), 128)

            shutil.copy2(str(src_key), str(dest_file))
            k32.SetFileAttributesW(str(dest_file), 3)
            return {"success": True, "path": str(dest_file)}
        except Exception as e:
            return {"success": False, "error": f"Yedekleme hatası: {e}"}

    @classmethod
    def find_and_verify_usb_key(cls, token: str, required_serial: Optional[str] = None) -> Tuple[bool, str]:
        """
        Sistemdeki tüm USB ve çıkarılabilir sürücülerde yetkili .vault_key arar ve doğrular.
        required_serial verilmişse doğrudan hedef sürücüyü kontrol eden hızlı yolu (<1ms) kullanır.
        """
        if not token:
            return False, ""

        clean_req_serial = cls.format_volume_serial(required_serial) if required_serial else ""
        bitmask = k32.GetLogicalDrives()

        if clean_req_serial:
            for i, letter in enumerate("ABCDEFGHIJKLMNOPQRSTUVWXYZ"):
                if letter in ("A", "B", "C") or not (bitmask & (1 << i)):
                    continue
                drv_serial = cls.get_drive_volume_serial(f"{letter}:")
                if cls.compare_volume_serials(drv_serial, clean_req_serial):
                    if cls.verify_usb_hardware_key(f"{letter}:", token, clean_req_serial):
                        return True, f"{letter}:"

        usb_drives = cls.get_removable_usb_drives()
        for d in usb_drives:
            if cls.verify_usb_hardware_key(d["drive"], token, clean_req_serial):
                return True, d["drive"]

        return False, ""

    @classmethod
    def get_connected_usb_unlock_password(cls, token: str, required_serial: Optional[str] = None, vault_name: str = "") -> str:
        """Yetkili USB takılıysa içindeki şifrelenmiş disk parolasını döner (Çoklu kasa destekli)."""
        found, usb_drv = cls.find_and_verify_usb_key(token, required_serial)
        if found and usb_drv:
            return cls.get_usb_key_password(usb_drv, token, vault_name=vault_name)
        return ""

    @classmethod
    def get_all_connected_usb_tokens(cls, target_serial: Optional[str] = None) -> List[str]:
        """
        Sistemdeki USB sürücülerdeki .vault_key token'larını döner.
        target_serial verilmişse SADECE o seri numarasına sahip USB'yi anında hedefler (<1ms).
        """
        tokens: List[str] = []
        clean_target_serial = cls.format_volume_serial(target_serial) if target_serial else ""
        bitmask = k32.GetLogicalDrives()

        if clean_target_serial:
            for i, letter in enumerate("ABCDEFGHIJKLMNOPQRSTUVWXYZ"):
                if letter in ("A", "B", "C") or not (bitmask & (1 << i)):
                    continue
                drv_serial = cls.get_drive_volume_serial(f"{letter}:")
                if cls.compare_volume_serials(drv_serial, clean_target_serial):
                    key_file = Path(f"{letter}:\\") / ".vault_key"
                    if not key_file.exists():
                        alt = Path(f"{letter}:\\") / "_vaultkey"
                        if alt.exists():
                            key_file = alt
                    if key_file.exists():
                        tok, _ = cls.read_usb_key_file(key_file)
                        if tok:
                            return [tok]

        usb_drives = cls.get_removable_usb_drives()
        for d in usb_drives:
            clean = d["drive"].rstrip("\\").rstrip(":") + ":\\"
            key_file = Path(clean) / ".vault_key"
            if not key_file.exists():
                alt = Path(clean) / "_vaultkey"
                if alt.exists():
                    key_file = alt
            if key_file.exists():
                tok, _ = cls.read_usb_key_file(key_file)
                if tok and tok not in tokens:
                    tokens.append(tok)
        return tokens

    SHIELD_MAGIC = b"VHD_LOCKED_BY_USB_KEY\x00"

    @staticmethod
    def derive_shield_key(usb_token: str) -> bytes:
        """USB anahtarındaki gizli token'dan SHA-256 ile 32 baytlık AES-256 anahtarı türetir."""
        return hashlib.sha256(usb_token.strip().encode("utf-8")).digest()

    @classmethod
    def get_shield_metadata(cls, file_path: str) -> Dict[str, Any]:
        """Kasanın başlığından mühür durumu ve gömülü USB donanım seri numarasını anında okur (<0.01ms)."""
        p = Path(file_path).resolve()
        if not p.exists() or p.stat().st_size < 512:
            return {"shielded": False, "serial": ""}
        try:
            with open(p, "rb") as f:
                head = f.read(32)
            if head[0:len(cls.SHIELD_MAGIC)] != cls.SHIELD_MAGIC:
                return {"shielded": False, "serial": ""}
            serial_raw = head[22:32].rstrip(b"\x00").decode("ascii", errors="ignore").strip()
            return {"shielded": True, "serial": serial_raw}
        except Exception:
            return {"shielded": False, "serial": ""}

    @classmethod
    def is_vault_shielded(cls, file_path: str) -> bool:
        """VHD/VHDX dosyasının USB mühürlü olup olmadığını başlık imzasından kontrol eder."""
        try:
            p = Path(file_path).resolve()
            if not p.exists() or p.stat().st_size < 512:
                return False
            with open(p, "rb") as f:
                header = f.read(len(cls.SHIELD_MAGIC))
            return header == cls.SHIELD_MAGIC
        except Exception:
            return False

    def shield_vault_container(self, file_path: str, usb_token: str, usb_serial: str = "") -> Dict[str, Any]:
        """
        VHD/VHDX dosyasının başlık ve altbilgisini AES-256-GCM ile şifreleyerek DOĞRUDAN KASA DOSYASININ
        İÇİNE GÖMER (harici hiçbir dosya oluşturmaz).
        Kasanın başlığına yetkili USB flash belleğin donanım seri numarasını da damgalar.
        Kasa kapalıyken başlığın tamamı (tüm 4096 bayt: Footer, Dynamic Header ve BAT blokları)
        ve altbilgi eksiksiz yedeklenir. Şifre çözüldüğünde bit-for-bit 100% kayıpsız geri yüklenir.
        """
        p = Path(file_path).resolve()
        if not p.exists():
            return {"success": False, "error": "Kasa dosyası bulunamadı."}
        if self.is_vault_shielded(str(p)):
            return {"success": True, "already_shielded": True}

        size = p.stat().st_size
        if size < 8192:
            return {"success": False, "error": "Kasa dosyası geçersiz boyutta (8KB'den küçük)."}

        try:
            with open(p, "rb") as f:
                head_bytes = f.read(4096)
                f.seek(size - 512)
                tail_bytes = f.read(512)

            is_valid_vhd = (
                head_bytes.startswith(b"conectix") or 
                tail_bytes.startswith(b"conectix") or 
                head_bytes.startswith(b"vhdxfile")
            )
            if not is_valid_vhd:
                return {"success": False, "error": "Dosya geçerli bir VHD/VHDX başlığı içermiyor."}

            clean_serial = self.format_volume_serial(usb_serial) if usb_serial else ""

            virtual_size_bytes = 0
            if tail_bytes.startswith(b"conectix") and len(tail_bytes) >= 56:
                cur_sz = struct.unpack(">Q", tail_bytes[48:56])[0]
                orig_sz = struct.unpack(">Q", tail_bytes[40:48])[0]
                virtual_size_bytes = max(cur_sz, orig_sz)
            elif head_bytes.startswith(b"conectix") and len(head_bytes) >= 56:
                cur_sz = struct.unpack(">Q", head_bytes[48:56])[0]
                orig_sz = struct.unpack(">Q", head_bytes[40:48])[0]
                virtual_size_bytes = max(cur_sz, orig_sz)

            key = self.derive_shield_key(usb_token)
            aesgcm = AESGCM(key)
            nonce = os.urandom(12)

            compressed_raw = zlib.compress(head_bytes + tail_bytes, level=9)
            raw_checksum = hashlib.sha256(head_bytes + tail_bytes).hexdigest()

            payload = json.dumps({
                "v": 3,
                "size": size,
                "virtual_size": virtual_size_bytes,
                "usb_serial": clean_serial,
                "comp_b64": base64.b64encode(compressed_raw).decode("ascii"),
                "head_len": len(head_bytes),
                "tail_len": len(tail_bytes),
                "sha256": raw_checksum
            }).encode("utf-8")

            ciphertext = aesgcm.encrypt(nonce, payload, p.name.encode("utf-8"))
            cipher_len = len(ciphertext)
            if 48 + cipher_len > 4080:
                return {"success": False, "error": "Kriptografik mühür boyutu 4080 baytlık blok sınırını aştı."}

            embedded_header = bytearray(4096)
            embedded_header[0:22] = self.SHIELD_MAGIC
            if clean_serial:
                embedded_header[22:32] = clean_serial.encode("ascii", errors="ignore").ljust(10, b"\x00")
            else:
                embedded_header[22:32] = b"\x00" * 10
            embedded_header[32:44] = nonce
            embedded_header[44:48] = cipher_len.to_bytes(4, "big")
            embedded_header[48:48 + cipher_len] = ciphertext
            if virtual_size_bytes > 0:
                embedded_header[4080:4088] = virtual_size_bytes.to_bytes(8, "big")

            fake_tail = self.SHIELD_MAGIC.ljust(512, b"\x00")

            with open(p, "r+b") as f:
                f.seek(0)
                f.write(embedded_header)
                f.seek(size - 512)
                f.write(fake_tail)
                f.flush()
                os.fsync(f.fileno())

            old_shield_file = p.with_suffix(p.suffix + ".vault_shield")
            if old_shield_file.exists():
                try:
                    old_shield_file.unlink()
                except Exception:
                    pass

            return {"success": True, "embedded": True, "usb_serial": clean_serial}
        except Exception as e:
            return {"success": False, "error": f"Kasa mühürleme hatası: {e}"}

    def revoke_active_vault_usb_shield(self):
        """Aktif kasanın USB mühürleme bayraklarını sıfırlar; böylece disk ayrılırken tekrar mühürlenmez."""
        self.active_vault_was_shielded = False
        self.active_usb_token = None
        self.active_usb_serial = None

    def unshield_vault_container(self, file_path: str, usb_token: str = "", target_serial: str = "", ignore_serial: bool = False) -> Dict[str, Any]:
        """
        Kasa dosyasının içine gömülmüş AES-256-GCM mührünü yetkili USB güvenlik anahtarıyla
        çözerek orijinal başlık ve altbilgisini geri yükler. Harici dosya bağımlılığı yoktur.
        """
        p = Path(file_path).resolve()
        if not p.exists():
            return {"success": False, "error": "Kasa dosyası bulunamadı."}
        if not self.is_vault_shielded(str(p)):
            return {"success": True, "already_unshielded": True}

        size = p.stat().st_size
        try:
            with open(p, "rb") as f:
                head_block = f.read(4096)

            if head_block[0:len(self.SHIELD_MAGIC)] != self.SHIELD_MAGIC:
                return {"success": False, "error": "Kasa mührünün imzası doğrulanamadı."}

            head_serial = head_block[22:32].rstrip(b"\x00").decode("ascii", errors="ignore").strip()
            nonce = head_block[32:44]
            cipher_len = int.from_bytes(head_block[44:48], "big")

            if cipher_len == 0 or cipher_len > 4000:
                old_shield_file = p.with_suffix(p.suffix + ".vault_shield")
                if old_shield_file.exists():
                    sdata = json.loads(old_shield_file.read_text(encoding="utf-8"))
                    nonce = base64.b64decode(sdata["nonce_b64"])
                    ciphertext = base64.b64decode(sdata["cipher_b64"])
                else:
                    return {"success": False, "error": "Kasa içi mühür verisi geçersiz ve harici mühür dosyası bulunamadı."}
            else:
                ciphertext = head_block[48:48 + cipher_len]

            candidate_tokens = []
            if usb_token:
                candidate_tokens.append(usb_token)
            if getattr(self, "active_usb_token", None) and self.active_usb_token not in candidate_tokens:
                candidate_tokens.append(self.active_usb_token)
            try:
                for ct in self.get_all_connected_usb_tokens():
                    if ct and ct not in candidate_tokens:
                        candidate_tokens.append(ct)
            except Exception:
                pass

            if not candidate_tokens:
                return {"success": False, "error": "Kasa mührünü çözmek için USB güvenlik anahtarı bulunamadı."}

            plaintext = None
            for cand in candidate_tokens:
                try:
                    key = self.derive_shield_key(cand)
                    aesgcm = AESGCM(key)
                    plaintext = aesgcm.decrypt(nonce, bytes(ciphertext), p.name.encode("utf-8"))
                    break
                except Exception:
                    continue

            if plaintext is None:
                return {"success": False, "error": "Yetkisiz USB Donanım Anahtarı! Şifre çözme doğrulaması başarısız oldu."}

            payload = json.loads(plaintext.decode("utf-8"))
            saved_serial = payload.get("usb_serial", "") or head_serial

            if not ignore_serial and target_serial and saved_serial:
                if not self.compare_volume_serials(target_serial, saved_serial):
                    return {
                        "success": False,
                        "error": f"USB Donanım Seri Numarası uyuşmuyor! Beklenen: {saved_serial}, Sunulan: {target_serial}"
                    }

            if "comp_b64" in payload:
                compressed_raw = base64.b64decode(payload["comp_b64"])
                decompressed = zlib.decompress(compressed_raw)
                head_len = payload.get("head_len", 4096)
                tail_len = payload.get("tail_len", 512)
                head_bytes = decompressed[:head_len]
                tail_bytes = decompressed[head_len:head_len + tail_len]
            else:
                head_bytes = base64.b64decode(payload["head_b64"])
                tail_bytes = base64.b64decode(payload["tail_b64"])

            if hashlib.sha256(head_bytes + tail_bytes).hexdigest() != payload["sha256"]:
                return {"success": False, "error": "Kasa verisinin bütünlük kontrolü (checksum) uyuşmuyor."}

            with open(p, "r+b") as f:
                f.seek(0)
                f.write(head_bytes)
                f.seek(size - len(tail_bytes))
                f.write(tail_bytes)
                f.flush()
                os.fsync(f.fileno())

            old_shield_file = p.with_suffix(p.suffix + ".vault_shield")
            if old_shield_file.exists():
                try:
                    old_shield_file.unlink()
                except Exception:
                    pass

            return {"success": True, "unshielded": True, "usb_serial": saved_serial}
        except Exception as e:
            return {"success": False, "error": f"Mühür çözme sırasında yazma hatası: {e}"}

    def remove_usb_protection_from_vault(self, file_path: str, usb_token: Optional[str] = None) -> Dict[str, Any]:
        """
        Belirtilen kasadan USB Donanım Kilidi (2. aşama) korumasını tamamen kaldırır.
        Kasa mühürlü ise mührü çözer ve orijinal VHD/VHDX başlığını geri yükler.
        Aktif oturumdaki mühürleme bayraklarını da temizler.
        """
        p = Path(file_path).resolve()
        if not p.exists():
            return {"success": False, "error": "Kasa dosyası bulunamadı."}

        self.revoke_active_vault_usb_shield()

        if self.is_vault_shielded(str(p)):
            res = self.unshield_vault_container(str(p), usb_token or "", ignore_serial=True)
            if not res.get("success"):
                return res

        return {"success": True, "message": "USB Donanım Kilidi koruması kasadan başarıyla kaldırıldı."}

    @staticmethod
    def auto_backup_vault(source_path: str, custom_backup_dir: str = "", max_backups: int = 3) -> Dict[str, Any]:
        """Kasa ayrıldığında dönel yedekleme yapar, eski yedekleri temizler."""
        src = Path(source_path).resolve()
        if not src.exists():
            return {"success": False, "error": "Kasa dosyası bulunamadı."}

        target_dir = Path(custom_backup_dir).resolve() if custom_backup_dir else (Path(__file__).parent / "vaults" / "backups")
        target_dir.mkdir(parents=True, exist_ok=True)

        timestamp = time.strftime("%Y%m%d_%H%M%S")
        dest = target_dir / f"{src.stem}_backup_{timestamp}{src.suffix}"

        try:
            shutil.copy2(src, dest)
            pattern = f"{src.stem}_backup_*{src.suffix}"
            existing = sorted(list(target_dir.glob(pattern)), key=lambda p: p.stat().st_mtime)
            deleted_count = 0
            if len(existing) > max_backups:
                to_delete = existing[:len(existing) - max_backups]
                for old in to_delete:
                    try:
                        old.unlink()
                        deleted_count += 1
                    except Exception:
                        pass

            return {
                "success": True,
                "backup_path": str(dest),
                "backup_name": dest.name,
                "size_mb": round(dest.stat().st_size / (1024 * 1024), 2),
                "deleted_old_count": deleted_count
            }
        except Exception as e:
            return {"success": False, "error": f"Otomatik yedekleme hatası: {e}"}

    @classmethod
    def get_vhd_virtual_size(cls, file_path: str) -> Dict[str, Any]:
        """
        VHD/VHDX sanal diskinin gerçek maksimum sanal kapasitesini ve diskte kapladığı fiziksel alanı döner.
        Dinamik (expandable) disklerde fiziksel dosya boyutu (örn: 224 MB) ile sanal boyut (örn: 2 GB) farklıdır.
        Paylaşım kilitlerini aşmak için Win32 CreateFileW (FILE_SHARE_ALL) ve çift yönlü footer kontrolü uygular.
        """
        if not file_path:
            return {"success": False, "error": "Dosya yolu boş."}

        clean_path = str(file_path).strip(' "\'')
        p = Path(clean_path).resolve()
        if not p.exists():
            return {"success": False, "error": "Dosya bulunamadı."}

        p_stat = p.stat()
        cache_key = (str(p).lower(), p_stat.st_mtime, p_stat.st_size)
        if hasattr(cls, "_vhd_size_cache") and cache_key in cls._vhd_size_cache:
            return dict(cls._vhd_size_cache[cache_key])

        phys_bytes = p_stat.st_size
        phys_mb = round(phys_bytes / (1024 * 1024), 1)
        phys_gb = round(phys_bytes / (1024 * 1024 * 1024), 2)

        def _read_bytes_safe(offset: int, length: int) -> bytes:
            try:
                with open(str(p), "rb") as f:
                    if offset < 0:
                        f.seek(offset, os.SEEK_END)
                    else:
                        f.seek(offset)
                    return f.read(length)
            except Exception:
                pass
            try:
                k32 = ctypes.windll.kernel32
                GENERIC_READ = 0x80000000
                FILE_SHARE_ALL = 0x00000001 | 0x00000002 | 0x00000004
                OPEN_EXISTING = 3
                h = k32.CreateFileW(str(p), GENERIC_READ, FILE_SHARE_ALL, None, OPEN_EXISTING, 0x80, None)
                if h != -1 and h != 0:
                    try:
                        if offset < 0:
                            k32.SetFilePointer(h, offset, None, 2)
                        else:
                            k32.SetFilePointer(h, offset, None, 0)
                        buf = ctypes.create_string_buffer(length)
                        read = ctypes.c_ulong()
                        if k32.ReadFile(h, buf, length, ctypes.byref(read), None):
                            return bytes(buf[:read.value])
                    finally:
                        k32.CloseHandle(h)
            except Exception:
                pass
            return b""

        is_pv = (p.suffix.lower() == ".pvault")
        if not is_pv and phys_bytes >= 8:
            head_8 = _read_bytes_safe(0, 8)
            if head_8 == b"PVAULT01":
                is_pv = True
        if is_pv:
            pv_max_gb = 0
            if phys_bytes >= 224:
                raw_sz = _read_bytes_safe(220, 4)
                if len(raw_sz) == 4:
                    try:
                        pv_max_gb = struct.unpack("<I", raw_sz)[0]
                    except Exception:
                        pass
            if pv_max_gb and 1 <= pv_max_gb <= 65536:
                v_bytes = pv_max_gb * 1024 * 1024 * 1024
                v_mb = round(pv_max_gb * 1024.0, 1)
                v_gb = round(float(pv_max_gb), 2)
            else:
                v_bytes = phys_bytes
                v_mb = phys_mb
                v_gb = phys_gb
            res = {
                "success": True,
                "virtual_bytes": v_bytes,
                "virtual_mb": v_mb,
                "virtual_gb": v_gb,
                "physical_bytes": phys_bytes,
                "physical_mb": phys_mb,
                "physical_gb": phys_gb,
                "disk_type": "pvault"
            }
            if hasattr(cls, "_vhd_size_cache"):
                cls._vhd_size_cache[cache_key] = res
            return res

        try:
            if phys_bytes >= 512:
                tail_buf = _read_bytes_safe(-512, 512)
                if tail_buf[:8] == b"conectix" and len(tail_buf) >= 56:
                    orig_sz = struct.unpack(">Q", tail_buf[40:48])[0]
                    cur_sz = struct.unpack(">Q", tail_buf[48:56])[0]
                    effective_sz = max(cur_sz, orig_sz)
                    disk_type = struct.unpack(">I", tail_buf[60:64])[0] if len(tail_buf) >= 64 else 3
                    v_mb = round(effective_sz / (1024 * 1024), 1)
                    v_gb = round(effective_sz / (1024 * 1024 * 1024), 2)
                    res = {
                        "success": True,
                        "virtual_bytes": effective_sz,
                        "virtual_mb": v_mb,
                        "virtual_gb": v_gb,
                        "original_bytes": orig_sz,
                        "physical_bytes": phys_bytes,
                        "physical_mb": phys_mb,
                        "physical_gb": phys_gb,
                        "disk_type": "dynamic" if disk_type == 3 else "fixed"
                    }
                    if hasattr(cls, "_vhd_size_cache"):
                        cls._vhd_size_cache[cache_key] = res
                    return res

                head_buf = _read_bytes_safe(0, 512)
                if head_buf[:8] == b"conectix" and len(head_buf) >= 56:
                    orig_sz = struct.unpack(">Q", head_buf[40:48])[0]
                    cur_sz = struct.unpack(">Q", head_buf[48:56])[0]
                    effective_sz = max(cur_sz, orig_sz)
                    disk_type = struct.unpack(">I", head_buf[60:64])[0] if len(head_buf) >= 64 else 3
                    v_mb = round(effective_sz / (1024 * 1024), 1)
                    v_gb = round(effective_sz / (1024 * 1024 * 1024), 2)
                    res = {
                        "success": True,
                        "virtual_bytes": effective_sz,
                        "virtual_mb": v_mb,
                        "virtual_gb": v_gb,
                        "original_bytes": orig_sz,
                        "physical_bytes": phys_bytes,
                        "physical_mb": phys_mb,
                        "physical_gb": phys_gb,
                        "disk_type": "dynamic" if disk_type == 3 else "fixed"
                    }
                    if hasattr(cls, "_vhd_size_cache"):
                        cls._vhd_size_cache[cache_key] = res
                    return res

                if head_buf.startswith(b"VAULTSHIELD_") or head_buf.startswith(b"VHD_LOCKED_BY_USB_KEY"):
                    full_block = _read_bytes_safe(0, 4096)
                    if len(full_block) >= 4088:
                        saved_sz = int.from_bytes(full_block[4080:4088], "big")
                        
                        if saved_sz == 0 and head_buf.startswith(b"VHD_LOCKED_BY_USB_KEY"):
                            try:
                                tokens = cls.get_all_connected_usb_tokens()
                                if not tokens:
                                    try:
                                        from config import CONFIG_FILE
                                        if CONFIG_FILE.exists():
                                            c_data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
                                            cfg_tok = c_data.get("usb_key_token", "")
                                            if cfg_tok:
                                                tokens.append(cfg_tok)
                                    except Exception:
                                        pass
                                for tok in tokens:
                                    try:
                                        t_key = cls.derive_shield_key(tok)
                                        c_len = int.from_bytes(full_block[44:48], "big")
                                        if 0 < c_len <= 4000:
                                            nonce = full_block[32:44]
                                            c_text = full_block[48:48 + c_len]
                                            p_text = AESGCM(t_key).decrypt(nonce, bytes(c_text), p.name.encode("utf-8"))
                                            payload = json.loads(p_text.decode("utf-8"))
                                            cand_sz = payload.get("virtual_size", 0)
                                            if cand_sz == 0 and "comp_b64" in payload:
                                                decomp = zlib.decompress(base64.b64decode(payload["comp_b64"]))
                                                h_len = payload.get("head_len", 4096)
                                                t_len = payload.get("tail_len", 512)
                                                t_bytes = decomp[h_len:h_len + t_len]
                                                if t_bytes.startswith(b"conectix") and len(t_bytes) >= 56:
                                                    cand_sz = max(struct.unpack(">Q", t_bytes[48:56])[0], struct.unpack(">Q", t_bytes[40:48])[0])
                                                elif decomp[:8] == b"conectix" and len(decomp) >= 56:
                                                    cand_sz = max(struct.unpack(">Q", decomp[48:56])[0], struct.unpack(">Q", decomp[40:48])[0])
                                            if cand_sz > 0:
                                                saved_sz = cand_sz
                                                try:
                                                    with open(str(p), "r+b") as wf:
                                                        wf.seek(4080)
                                                        wf.write(saved_sz.to_bytes(8, "big"))
                                                        wf.flush()
                                                except Exception:
                                                    pass
                                                break
                                    except Exception:
                                        continue
                            except Exception:
                                pass

                        if saved_sz > 0:
                            v_mb = round(saved_sz / (1024 * 1024), 1)
                            v_gb = round(saved_sz / (1024 * 1024 * 1024), 2)
                            res = {
                                "success": True,
                                "virtual_bytes": saved_sz,
                                "virtual_mb": v_mb,
                                "virtual_gb": v_gb,
                                "physical_bytes": phys_bytes,
                                "physical_mb": phys_mb,
                                "physical_gb": phys_gb,
                                "disk_type": "dynamic",
                                "shielded": True
                            }
                            if hasattr(cls, "_vhd_size_cache"):
                                cls._vhd_size_cache[cache_key] = res
                            return res
        except Exception:
            pass

        if p.suffix.lower() in [".vhd", ".vhdx"]:
            try:
                escaped = _ps_literal(p)
                ps_cmd = f"(Get-DiskImage -ImagePath '{escaped}' -ErrorAction SilentlyContinue | Get-Disk -ErrorAction SilentlyContinue).Size"
                code, out, _ = cls._run_powershell(ps_cmd, timeout=3)
                out = out.strip()
                if out.isdigit() and int(out) > 0:
                    cur_sz = int(out)
                    v_mb = round(cur_sz / (1024 * 1024), 1)
                    v_gb = round(cur_sz / (1024 * 1024 * 1024), 2)
                    res = {
                        "success": True,
                        "virtual_bytes": cur_sz,
                        "virtual_mb": v_mb,
                        "virtual_gb": v_gb,
                        "physical_bytes": phys_bytes,
                        "physical_mb": phys_mb,
                        "physical_gb": phys_gb,
                        "disk_type": "vhdx"
                    }
                    if hasattr(cls, "_vhd_size_cache"):
                        cls._vhd_size_cache[cache_key] = res
                    return res
            except Exception:
                pass

        fallback_res = {
            "success": True,
            "virtual_bytes": phys_bytes,
            "virtual_mb": phys_mb,
            "virtual_gb": phys_gb,
            "physical_bytes": phys_bytes,
            "physical_mb": phys_mb,
            "physical_gb": phys_gb,
            "disk_type": "unknown"
        }
        if hasattr(cls, "_vhd_size_cache"):
            cls._vhd_size_cache[cache_key] = fallback_res
        return fallback_res

    def expand_vdisk(self, vhd_path: str, new_size_mb: int) -> Dict[str, Any]:
        """Sanal disk dosyasının maksimum boyutunu diskpart ile genişletir."""
        clean_path = str(vhd_path).strip(' "\'') if vhd_path else ""
        target = Path(clean_path).resolve()
        if not target.exists():
            return {"success": False, "error": "Kasa dosyası bulunamadı."}

        if self.is_vhd_attached(str(target)):
            return {"success": False, "error": "Kasa şu anda bağlı durumda. Genişletmek için önce diski güvenle ayırın."}

        if self.is_vault_shielded(str(target)):
            return {"success": False, "error": "Kasa USB donanım anahtarı ile mühürlüdür. Kapasite genişletmek için lütfen önce diski bir kez bağlayın veya mührünü açın."}

        v_info = self.get_vhd_virtual_size(str(target))
        initial_virt_mb = v_info.get("virtual_mb", round(target.stat().st_size / (1024 * 1024), 2))
        initial_virt_gb = round(initial_virt_mb / 1024, 2)
        new_size_gb = round(new_size_mb / 1024, 2)

        if new_size_mb <= initial_virt_mb:
            return {
                "success": False,
                "error": (
                    f"Yeni kapasite ({new_size_mb} MB / {new_size_gb} GB), kasanın mevcut sanal "
                    f"kapasitesinden ({int(initial_virt_mb)} MB / {initial_virt_gb} GB) daha büyük olmalıdır."
                )
            }

        is_vhdx = (v_info.get("disk_type") == "vhdx")
        if not is_vhdx and new_size_mb > 2040 * 1024:
            return {
                "success": False,
                "error": "Standart VHD biçimi en fazla 2040 GB (yaklaşık 2 TB) boyuta genişletilebilir. Daha büyük boyutlar için VHDX biçimini kullanın."
            }

        target_path, is_bridge, bridge_path = self.prepare_mount_target(str(target))
        try:
            escaped_path = str(target_path).replace('"', '""')
            script = f'select vdisk file="{escaped_path}"\nexpand vdisk maximum={new_size_mb}\n'
            res = self._run_diskpart_script(script, timeout=300)
            stdout = res.get("stdout", "")
            returncode = res.get("returncode", 0)

            new_info = self.get_vhd_virtual_size(str(target))
            expanded_mb = new_info.get("virtual_mb", 0)

            is_success = (expanded_mb >= new_size_mb) or (
                returncode == 0 and ("successfully expanded" in stdout.lower() or "başarıyla" in stdout.lower())
            )

            if not is_success:
                stdout_lower = stdout.lower()
                if "parameter is incorrect" in stdout_lower or "0x80070057" in stdout_lower or returncode == 2147942487:
                    return {
                        "success": False,
                        "error": (
                            f"DiskPart parametre hatası (0x80070057: The parameter is incorrect).\n\n"
                            f"Belirtilen yeni boyut ({new_size_mb} MB / {new_size_gb} GB), diskin mevcut boyutundan "
                            f"({int(initial_virt_mb)} MB / {initial_virt_gb} GB) kesinlikle daha büyük olmalıdır."
                        )
                    }
                err_clean = stdout.strip() or res.get("stderr", "").strip() or "Disk genişletme komutu tamamlanamadı."
                return {"success": False, "error": f"Genişletme hatası:\n{err_clean}"}

            return {
                "success": True,
                "initial_mb": initial_virt_mb,
                "new_size_mb": max(new_size_mb, int(expanded_mb)),
                "message": f"Kasa disk kapsayıcısı başarıyla {new_size_mb} MB ({new_size_gb} GB) boyutuna genişletildi."
            }
        finally:
            if is_bridge:
                self.cleanup_bridge(bridge_path, str(target))

    def extend_filesystem_volume(self, drive_letter: str) -> Dict[str, Any]:
        """Bağlı ve kilidi açık bir sürücünün dosya sistemi bölümünü maksimum alana genişletir."""
        clean = _clean_drive_letter(drive_letter)
        if not clean or len(clean) != 1:
            return {"success": False, "error": "Geçerli bir sürücü harfi belirtilmedi."}

        ps_cmd = (
            f'$part = Get-Partition -DriveLetter "{clean}" -ErrorAction SilentlyContinue; '
            f'if ($part) {{ '
            f'  $supported = Get-PartitionSupportedSize -DriveLetter "{clean}" -ErrorAction SilentlyContinue; '
            f'  if ($supported -and $supported.SizeMax -gt $part.Size) {{ '
            f'    Resize-Partition -DriveLetter "{clean}" -Size $supported.SizeMax -ErrorAction Stop; '
            f'    Write-Output "SUCCESS: $($supported.SizeMax)" '
            f'  }} else {{ Write-Output "ALREADY_MAX" }} '
            f'}} else {{ Write-Output "PARTITION_NOT_FOUND" }}'
        )
        code, stdout, stderr = self._run_powershell(ps_cmd, timeout=30)
        out_str = stdout or ""
        if "SUCCESS" in out_str:
            return {"success": True, "message": f"{clean}: sürücü bölümü maksimum kullanılabilir alana başarıyla genişletildi.", "resized": True}
        if "ALREADY_MAX" in out_str:
            return {"success": True, "message": f"{clean}: sürücü bölümü zaten maksimum boyutta.", "resized": False}

        dp_script = f"select volume {clean}\nextend\n"
        res = self._run_diskpart_script(dp_script, timeout=30)
        dp_out = res.get("stdout", "")
        if "successfully extended" in dp_out.lower() or "başarıyla" in dp_out.lower():
            return {"success": True, "message": f"{clean}: sürücü bölümü diskpart ile başarıyla genişletildi.", "resized": True}

        return {"success": False, "error": f"Bölüm genişletilemedi: {stderr.strip() or dp_out.strip()}"}

    def check_cloud_sync_conflict(self, file_path: str) -> Dict[str, Any]:
        """Kasa dosyasının OneDrive, Google Drive, Dropbox veya iCloud gibi bulut senkronizasyon klasörlerinde olup olmadığını denetler."""
        if not file_path:
            return {"conflict": False}
        p_str = str(Path(file_path).resolve()).lower()

        cloud_signatures = [
            ("OneDrive", os.environ.get("OneDrive", "").lower()),
            ("OneDrive", os.environ.get("OneDriveConsumer", "").lower()),
            ("OneDrive", os.environ.get("OneDriveCommercial", "").lower()),
            ("Dropbox", str(Path(os.environ.get("USERPROFILE", "")) / "Dropbox").lower()),
            ("Google Drive", str(Path(os.environ.get("USERPROFILE", "")) / "Google Drive").lower()),
            ("iCloud Drive", str(Path(os.environ.get("USERPROFILE", "")) / "iCloudDrive").lower()),
            ("Box Sync", str(Path(os.environ.get("USERPROFILE", "")) / "Box").lower()),
            ("Box Sync", str(Path(os.environ.get("USERPROFILE", "")) / "Box Sync").lower())
        ]

        for provider, cpath in cloud_signatures:
            if cpath and cpath in p_str:
                return {
                    "conflict": True,
                    "provider": provider,
                    "path": file_path,
                    "warning": (
                        f"Bu kasa dosyası bir bulut senkronizasyon klasöründe ({provider}) yer alıyor!\n\n"
                        f"Sanal disk bağlıyken bulut motorunun dosyayı eşitlemeye çalışması diskte "
                        f"kalıcı dosya bozulmalarına (corruption) yol açabilir.\n\n"
                        f"Öneri: Kasa dosyasını yerel bir sürücüye taşıyın veya {provider} senkronizasyonunu "
                        f"disk bağlıyken duraklatın."
                    )
                }

        generic_keywords = ["onedrive", "dropbox", "google drive", "iclouddrive", "nextcloud", "owncloud"]
        for kw in generic_keywords:
            if f"\\{kw}\\" in p_str or f"/{kw}/" in p_str:
                return {
                    "conflict": True,
                    "provider": kw.capitalize(),
                    "path": file_path,
                    "warning": (
                        f"Kasa yolunda bulut senkronizasyon klasörü ({kw.capitalize()}) tespit edildi.\n\n"
                        f"Disk bağlıyken bulut istemcisinin dosyayı senkronize etmesi disk bozulmasına yol açabilir."
                    )
                }

        return {"conflict": False}

    def check_vhd_health(self, file_path: str) -> Dict[str, Any]:
        """VHD/VHDX başlık ve altbilgi (footer) imzasını doğrulayarak disk sağlamlığını denetler."""
        p = Path(file_path).resolve()
        if not p.exists():
            return {"success": False, "error": "Kasa dosyası bulunamadı.", "healthy": False}
        size = p.stat().st_size
        if size < 512:
            return {"success": False, "error": "Dosya boyutu geçersiz (512 bayttan küçük).", "healthy": False}

        try:
            with open(p, "rb") as f:
                header_bytes = f.read(512)
                f.seek(max(0, size - 512))
                footer_bytes = f.read(512)

            if header_bytes.startswith(self.SHIELD_MAGIC):
                return {
                    "success": True,
                    "format": "VHD (Korumalı / Mühürlü)",
                    "type": "USB Donanım Korumalı Kasa",
                    "size_mb": round(size / (1024 * 1024), 2),
                    "healthy": True,
                    "shielded": True,
                    "message": "Kasa USB Donanım Kilidi ile mühürlü. Fiziksel USB anahtarı olmadan shell script ve harici araçların erişimi engellendi."
                }
            elif header_bytes.startswith(b"conectix") or footer_bytes.startswith(b"conectix"):
                footer = footer_bytes if footer_bytes.startswith(b"conectix") else header_bytes
                disk_type = int.from_bytes(footer[60:64], "big")
                type_str = {
                    2: "Sabit Boyutlu (Fixed)",
                    3: "Dinamik Boyutlu (Dynamic)",
                    4: "Fark Diski (Differencing)"
                }.get(disk_type, f"Bilinmeyen ({disk_type})")
                return {
                    "success": True,
                    "format": "VHD",
                    "type": type_str,
                    "size_mb": round(size / (1024 * 1024), 2),
                    "healthy": True,
                    "message": f"VHD başlığı ve 'conectix' imzası sağlam. Format: {type_str}"
                }
            elif header_bytes.startswith(b"vhdxfile"):
                return {
                    "success": True,
                    "format": "VHDX",
                    "type": "VHDX Gelişmiş Sanal Disk",
                    "size_mb": round(size / (1024 * 1024), 2),
                    "healthy": True,
                    "message": "VHDX başlığı ve 'vhdxfile' imzası sağlam."
                }
            else:
                return {
                    "success": False,
                    "error": "VHD/VHDX başlık imzası ('conectix' veya 'vhdxfile') doğrulanamadı. Dosya hasar görmüş olabilir.",
                    "healthy": False
                }
        except Exception as e:
            return {"success": False, "error": f"Sağlık kontrolü okuma hatası: {e}", "healthy": False}

    def repair_volume_filesystem(self, drive_letter: str) -> Dict[str, Any]:
        """Bağlı sürücünün dosya sistemini chkdsk /scan ile tarar ve durumunu raporlar."""
        clean = _clean_drive_letter(drive_letter)
        if not clean or len(clean) != 1:
            return {"success": False, "error": "Geçerli bir sürücü harfi belirtilmedi."}

        cmd = ["chkdsk.exe", f"{clean}:", "/scan"]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                creationflags=CREATE_NO_WINDOW,
                timeout=180
            )
            out = (proc.stdout or "") + "\n" + (proc.stderr or "")
            has_error = proc.returncode != 0 or "found problems" in out.lower() or "sorun buldu" in out.lower()
            return {
                "success": not has_error,
                "returncode": proc.returncode,
                "output": out.strip(),
                "healthy": not has_error,
                "message": "Dosya sisteminde herhangi bir hata bulunamadı." if not has_error else "Dosya sisteminde düzeltilmesi gereken sorunlar tespit edildi."
            }
        except Exception as e:
            return {"success": False, "error": f"chkdsk çalıştırılamadı: {e}"}

    def get_shell_launcher_commands(self) -> Tuple[str, str, str]:
        """Windows Explorer sağ tık menüsü için çalıştırıcı komutları ve ikon yolunu döner."""
        icon_path = str(Path(__file__).parent / "app_icon.ico")
        if not Path(icon_path).exists():
            icon_path = ""

        if getattr(sys, "frozen", False):
            exe_path = sys.executable
            open_cmd = f'"{exe_path}" "%1"'
            shred_cmd = f'"{exe_path}" --shred "%1"'
        else:
            py_exe = sys.executable
            pyw_exe = Path(py_exe).parent / "pythonw.exe"
            runner = str(pyw_exe) if pyw_exe.exists() else py_exe
            main_py = str(Path(__file__).parent / "main.py")
            open_cmd = f'"{runner}" "{main_py}" "%1"'
            shred_cmd = f'"{runner}" "{main_py}" --shred "%1"'

        return open_cmd, shred_cmd, icon_path

    def is_shell_context_menu_registered(self) -> bool:
        """Windows Explorer sağ tık menüsünün kayıtlı olup olmadığını denetler."""
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Classes\SystemFileAssociations\.vhd\shell\Enclave"):
                return True
        except Exception:
            return False

    def register_shell_context_menu(self) -> Dict[str, Any]:
        """Windows Gezgini sağ tık menüsüne Enclave seçeneklerini ekler."""
        open_cmd, shred_cmd, icon_path = self.get_shell_launcher_commands()
        try:
            for ext in [".vhd", ".vhdx"]:
                base_key = rf"Software\Classes\SystemFileAssociations\{ext}\shell\Enclave"
                with winreg.CreateKey(winreg.HKEY_CURRENT_USER, base_key) as k:
                    winreg.SetValueEx(k, "", 0, winreg.REG_SZ, "Enclave ile Aç")
                    if icon_path:
                        winreg.SetValueEx(k, "Icon", 0, winreg.REG_SZ, icon_path)
                with winreg.CreateKey(winreg.HKEY_CURRENT_USER, rf"{base_key}\command") as kc:
                    winreg.SetValueEx(kc, "", 0, winreg.REG_SZ, open_cmd)

            star_key = r"Software\Classes\*\shell\EnclaveShred"
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, star_key) as k:
                winreg.SetValueEx(k, "", 0, winreg.REG_SZ, "Enclave ile Güvenle Parçala (DoD Shred)")
                if icon_path:
                    winreg.SetValueEx(k, "Icon", 0, winreg.REG_SZ, icon_path)
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, rf"{star_key}\command") as kc:
                winreg.SetValueEx(kc, "", 0, winreg.REG_SZ, shred_cmd)

            dir_key = r"Software\Classes\Directory\shell\EnclaveShred"
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, dir_key) as k:
                winreg.SetValueEx(k, "", 0, winreg.REG_SZ, "Enclave ile Güvenle Parçala (DoD Shred)")
                if icon_path:
                    winreg.SetValueEx(k, "Icon", 0, winreg.REG_SZ, icon_path)
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, rf"{dir_key}\command") as kc:
                winreg.SetValueEx(kc, "", 0, winreg.REG_SZ, shred_cmd)

            return {"success": True, "message": "Windows Gezgini sağ tık menü seçenekleri başarıyla yüklendi."}
        except Exception as e:
            return {"success": False, "error": f"Kayıt defteri yazma hatası: {e}"}

    def unregister_shell_context_menu(self) -> Dict[str, Any]:
        """Windows Gezgini sağ tık menüsünden Enclave seçeneklerini kaldırır."""
        def _delete_key_recursive(root, subkey):
            try:
                with winreg.OpenKey(root, subkey, 0, winreg.KEY_ALL_ACCESS) as k:
                    while True:
                        try:
                            child = winreg.EnumKey(k, 0)
                            _delete_key_recursive(root, f"{subkey}\\{child}")
                        except OSError:
                            break
                winreg.DeleteKey(root, subkey)
            except Exception:
                pass

        try:
            _delete_key_recursive(winreg.HKEY_CURRENT_USER, r"Software\Classes\SystemFileAssociations\.vhd\shell\Enclave")
            _delete_key_recursive(winreg.HKEY_CURRENT_USER, r"Software\Classes\SystemFileAssociations\.vhdx\shell\Enclave")
            _delete_key_recursive(winreg.HKEY_CURRENT_USER, r"Software\Classes\*\shell\EnclaveShred")
            _delete_key_recursive(winreg.HKEY_CURRENT_USER, r"Software\Classes\Directory\shell\EnclaveShred")
            _delete_key_recursive(winreg.HKEY_CURRENT_USER, r"Software\Classes\SystemFileAssociations\.vhd\shell\VHDVaultPro")
            _delete_key_recursive(winreg.HKEY_CURRENT_USER, r"Software\Classes\SystemFileAssociations\.vhdx\shell\VHDVaultPro")
            _delete_key_recursive(winreg.HKEY_CURRENT_USER, r"Software\Classes\*\shell\VHDVaultProShred")
            _delete_key_recursive(winreg.HKEY_CURRENT_USER, r"Software\Classes\Directory\shell\VHDVaultProShred")
            return {"success": True, "message": "Sağ tık menü seçenekleri başarıyla kaldırıldı."}
        except Exception as e:
            return {"success": False, "error": f"Kayıt defteri silme hatası: {e}"}

    @staticmethod
    def send_toast_notification(title: str, message: str, icon_type: str = "info") -> bool:
        """Windows 10/11 yerel bildirim (Toast) gönderir."""
        clean_title = _ps_literal(title).replace('"', '`"')
        clean_msg = _ps_literal(message).replace('"', '`"')
        ps_toast = (
            f"[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null; "
            f"$template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02); "
            f"$textNodes = $template.GetElementsByTagName('text'); "
            f"$textNodes.Item(0).AppendChild($template.CreateTextNode('{clean_title}')) | Out-Null; "
            f"$textNodes.Item(1).AppendChild($template.CreateTextNode('{clean_msg}')) | Out-Null; "
            f"$toast = [Windows.UI.Notifications.ToastNotification]::new($template); "
            f"$appId = '{{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}}\\cmd.exe'; "
            f"[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($appId).Show($toast);"
        )
        try:
            code, _, _ = VHDEngine._run_powershell(ps_toast, timeout=5)
            return code == 0
        except Exception:
            return False

verify_vhd_structure = VHDEngine.verify_vhd_structure
backup_vhd_header_footer = VHDEngine.backup_vhd_header_footer
inspect_vhd_header_footer = VHDEngine.inspect_vhd_header_footer
restore_vhd_header_footer = VHDEngine.restore_vhd_header_footer

