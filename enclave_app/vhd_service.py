"""
Enclave - VHD/VHDX ve BitLocker oturumu (yalnızca Windows).
Qt içermez. engine.py Windows modüllerine bağlı olduğundan yalnızca gerektiğinde yüklenir.
"""

import json
import os
import secrets
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from enclave_core import CustomVaultError, InvalidPasswordError, MAGIC_HEADER
from .i18n import tr

def make_engine() -> Any:
    from engine import VHDEngine
    return VHDEngine()

def is_virtual_disk(path: str) -> bool:
    """
    Sanal disk mi? Ad ve uzantı serbest olduğundan imzaya bakılır: .pvault imzası varsa kasadır,
    VHD ya da VHDX imzası (başta veya sonda) varsa sanal disktir. Bu, köprü modunda farklı uzantılı diskleri de bulur.
    """
    if sys.platform != "win32":
        return False
    try:
        with open(path, "rb") as source:
            head = source.read(8)
            if head == MAGIC_HEADER:
                return False
            if head in (b"conectix", b"vhdxfile"):
                return True
            source.seek(0, os.SEEK_END)
            size = source.tell()
            if size >= 512:
                source.seek(size - 512)
                if source.read(8) == b"conectix":
                    return True
    except OSError:
        return False
    return Path(path).suffix.lower() in (".vhd", ".vhdx")

def needs_elevation() -> bool:
    return not make_engine().is_admin()

def elevate(arguments: List[str]) -> bool:
    """Yönetici olarak yeniden açar; ayar dizini aktarılır, böylece hatırlanan kasalar kaybolmaz."""
    from logger import USER_DATA_DIR
    return bool(make_engine().elevate_process(extra_args=[*arguments, "--data-dir", str(USER_DATA_DIR)]))

class VhdSession:
    """Bağlı bir sanal disk. Dosyalar Windows sürücüsünde durduğu için iş Dosya Gezgini'nde yapılır."""

    second_factor_pending = False

    def __init__(self, vault_path: str):
        self.path = str(Path(vault_path).resolve())
        self.name = Path(vault_path).stem
        self.engine = make_engine()
        self.drive_letter = ""
        self.autoplay_changed = False

    def unlock(self, password: str) -> bool:
        """Diski bağlar, BitLocker kilitliyse açar. Başarısız olursa disk bağlı bırakılmaz."""
        self.autoplay_changed = bool(self.engine.backup_and_disable_autoplay())
        result = self.engine.mount_vhd(self.path)
        if not result.get("success"):
            self._restore_autoplay()
            raise CustomVaultError(result.get("error", "Disk bağlanamadı."))
        self.drive_letter = result.get("drive_letter", "")
        try:
            self._unlock_volume(password)
        except Exception:
            self.close()
            raise
        return False

    def unlock_with_recovery_key(self, recovery_key: str) -> None:
        """Diski bağlar ve 48 haneli BitLocker kurtarma anahtarıyla açar. Başarısız olursa disk bağlı bırakılmaz."""
        digits = "".join(c for c in recovery_key if c.isdigit())
        if len(digits) != 48:
            raise CustomVaultError(tr("Kurtarma anahtarı 48 rakamdan oluşmalı."))
        self.autoplay_changed = bool(self.engine.backup_and_disable_autoplay())
        result = self.engine.mount_vhd(self.path)
        if not result.get("success"):
            self._restore_autoplay()
            raise CustomVaultError(result.get("error", "Disk bağlanamadı."))
        self.drive_letter = result.get("drive_letter", "")
        try:
            if not self.drive_letter:
                raise CustomVaultError(tr("Sürücü harfi atanamadı."))
            if not self.engine.get_drive_status(self.drive_letter).get("is_locked"):
                return
            key = "-".join(digits[i:i + 6] for i in range(0, 48, 6))
            partitions = [2, 1] if self.engine.check_embedded_decoy_vault(self.path) else [None]
            error = tr("Kurtarma anahtarı doğrulanamadı.")
            for partition in partitions:
                if partition is not None:
                    swap = self.engine.swap_embedded_partitions(self.path, target_part=partition, letter=self.drive_letter)
                    self.drive_letter = swap.get("drive_letter") or self.drive_letter
                result = self.engine.unlock_bitlocker_recovery_key(self.drive_letter, key)
                if result.get("success"):
                    return
                error = result.get("error", error)
            raise CustomVaultError(tr(error))
        except Exception:
            self.close()
            raise

    def _unlock_volume(self, password: str) -> None:
        if not self.drive_letter:
            raise CustomVaultError(tr("Sürücü harfi atanamadı."))
        if not self.engine.get_drive_status(self.drive_letter).get("is_locked"):
            return
        if not password:
            raise InvalidPasswordError(tr("Bu disk BitLocker parolası istiyor."))

        partitions = [2, 1] if self.engine.check_embedded_decoy_vault(self.path) else [None]
        last_error = tr("BitLocker kilidi açılamadı.")
        for partition in partitions:
            if partition is not None:
                swap = self.engine.swap_embedded_partitions(self.path, target_part=partition, letter=self.drive_letter)
                self.drive_letter = swap.get("drive_letter") or self.drive_letter
            result = self.engine.unlock_bitlocker_password(self.drive_letter, password)
            if result.get("success"):
                return
            if not result.get("wrong_password"):
                last_error = result.get("error", last_error)
                raise CustomVaultError(last_error)
        raise InvalidPasswordError(tr("Girdiğiniz parola hatalı."))

    def verify_second_factor(self, _code: str) -> tuple:
        return True, ""

    def status(self) -> Dict[str, Any]:
        return self.engine.get_drive_status(self.drive_letter) if self.drive_letter else {}

    def open_in_explorer(self) -> None:
        self.engine.open_explorer(self.drive_letter)

    def recovery_key(self) -> Dict[str, Any]:
        return self.engine.get_bitlocker_recovery_key(self.drive_letter)

    def bitlocker_status(self) -> Dict[str, Any]:
        return self.engine.get_bitlocker_status(self.drive_letter)

    def check_health(self) -> Dict[str, Any]:
        return self.engine.check_vhd_health(self.path)

    def change_password(self, new_password: str) -> None:
        result = self.engine.change_bitlocker_password(self.drive_letter, new_password)
        if not result.get("success"):
            raise CustomVaultError(result.get("error", "Parola değiştirilemedi."))

    def idle_seconds(self) -> float:
        return float(self.engine.get_system_idle_seconds())

    def _restore_autoplay(self) -> None:
        if self.autoplay_changed:
            self.engine.restore_autoplay()
            self.autoplay_changed = False

    def close(self) -> None:
        """Gezgin pencerelerini kapatır, diski ayırır ve sistem izlerini temizler."""
        letter, self.drive_letter = self.drive_letter, ""
        if letter:
            self.engine.close_explorer_windows(letter)
        result = self.engine.dismount_vhd(mount_target=self.path, drive_letter=letter or None, force=True)
        if letter:
            self.engine.wipe_system_traces(letter)
        self._restore_autoplay()
        if not result.get("success"):
            raise CustomVaultError(result.get("error", "Disk ayrılamadı."))

def create_virtual_disk(
    path: str, password: str, size_gb: int, is_dynamic: bool, decoy_password: Optional[str],
    decoy_size_mb: Optional[int] = None
) -> Dict[str, Any]:
    """Yeni VHD/VHDX oluşturur ve BitLocker ile şifreler. Yönetici izni gerekir."""
    result = make_engine().create_new_vault(
        path, size_gb, is_dynamic=is_dynamic, label=Path(path).stem, bitlocker_password=password,
        has_decoy=bool(decoy_password), decoy_size_mb=decoy_size_mb or max(100, size_gb * 256), decoy_password=decoy_password,
    )
    if not result.get("success"):
        raise CustomVaultError(result.get("error", "Sanal disk oluşturulamadı."))
    return result

HELPER_FLAG = "--vhd-helper"
HELPER_CONSENT_SECONDS = 120

def _spawn_helper(address: str, key: bytes) -> bool:
    """Yalnızca oluşturma işini yapan yetkili süreci başlatır. Anahtar komut satırındadır; yetkili sürecin satırını sıradan süreç okuyamaz."""
    import ctypes
    import subprocess
    from logger import USER_DATA_DIR
    arguments = [HELPER_FLAG, address, key.hex(), "--data-dir", str(USER_DATA_DIR)]
    root = Path(__file__).resolve().parent.parent
    if getattr(sys, "frozen", False):
        executable, work_dir = sys.executable, str(Path(sys.executable).parent)
    else:
        windowless = Path(sys.executable).with_name("pythonw.exe")
        executable = str(windowless) if windowless.exists() else sys.executable
        arguments.insert(0, str(root / "main.py"))
        work_dir = str(root)
    result = ctypes.windll.shell32.ShellExecuteW(None, "runas", executable, subprocess.list2cmdline(arguments), work_dir, 0)
    return int(result) > 32

def create_virtual_disk_elevated(
    path: str, password: str, size_gb: int, is_dynamic: bool, decoy_password: Optional[str],
    decoy_size_mb: Optional[int] = None
) -> Dict[str, Any]:
    """Uygulamayı yeniden başlatmadan, UAC onayıyla açılan yardımcıda sanal disk oluşturur. Parola adlandırılmış kanaldan gider."""
    import threading
    from multiprocessing.connection import Listener
    key = secrets.token_bytes(32)
    address = rf"\\.\pipe\enclave_{secrets.token_hex(16)}"
    with Listener(address, family="AF_PIPE", authkey=key) as listener:
        if not _spawn_helper(address, key):
            raise CustomVaultError(tr("Yönetici izni verilmedi."))
        accepted: List[Any] = []

        def accept() -> None:
            try:
                accepted.append(listener.accept())
            except Exception as error:
                accepted.append(error)

        threading.Thread(target=accept, daemon=True).start()
        waiter = threading.Event()
        for _ in range(HELPER_CONSENT_SECONDS * 10):
            if accepted:
                break
            waiter.wait(0.1)
        if not accepted or isinstance(accepted[0], Exception):
            raise CustomVaultError(tr("Yönetici yardımcısı başlatılamadı."))
        with accepted[0] as connection:
            request = {"path": path, "password": password, "size_gb": size_gb, "is_dynamic": is_dynamic,
                       "decoy_password": decoy_password, "decoy_size_mb": decoy_size_mb}
            connection.send_bytes(json.dumps(request).encode("utf-8"))
            try:
                reply = json.loads(connection.recv_bytes().decode("utf-8"))
            except EOFError:
                raise CustomVaultError(tr("Yönetici yardımcısı beklenmedik şekilde kapandı.")) from None
    if not reply.get("ok"):
        raise CustomVaultError(tr(reply.get("error", "Sanal disk oluşturulamadı.")))
    return reply["result"]

def serve_helper(address: str, key_hex: str) -> None:
    """Yetkili yardımcı: tek bir oluşturma isteğini yerine getirir ve çıkar."""
    from multiprocessing.connection import Client
    with Client(address, family="AF_PIPE", authkey=bytes.fromhex(key_hex)) as connection:
        request = json.loads(connection.recv_bytes().decode("utf-8"))
        try:
            reply = {"ok": True, "result": create_virtual_disk(**request)}
        except Exception as error:
            reply = {"ok": False, "error": str(error)}
        connection.send_bytes(json.dumps(reply).encode("utf-8"))
