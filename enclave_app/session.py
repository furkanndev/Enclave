"""
Enclave - Kasa Oturumu
Açık bir kasa üzerindeki tüm işlemleri arayüzden bağımsız olarak yürütür.
Qt içermez; bu sayede arayüz olmadan test edilebilir.
"""

import functools
import gc
import os
import re
import shutil
import sys
import threading
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from enclave_core import (
    CustomVaultEngine as Engine,
    CustomVaultError,
    InvalidPasswordError,
    VaultFileLock,
    safe_vault_name,
    secure_wipe_directory,
    secure_wipe_file,
)
import totp_engine

from .i18n import tr

PREVIEW_LIMIT = 64 * 1024 * 1024
IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".webp", ".gif", ".bmp"}
TEXT_EXTS = {
    ".txt", ".md", ".log", ".csv", ".json", ".xml", ".yml", ".yaml", ".ini", ".toml",
    ".py", ".js", ".ts", ".html", ".css", ".sh", ".bat", ".ps1", ".rs", ".c", ".cpp", ".h", ".java",
}
CATEGORIES = {
    "image": IMAGE_EXTS | {".heic", ".tiff", ".svg"},
    "video": {".mp4", ".mkv", ".avi", ".mov", ".wmv", ".webm", ".m4v"},
    "audio": {".mp3", ".flac", ".wav", ".aac", ".ogg", ".m4a", ".opus"},
    "document": {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".ods", ".rtf"},
    "archive": {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz"},
    "text": TEXT_EXTS,
}
CLOUD_FOLDERS = ("onedrive", "dropbox", "google drive", "googledrive", "icloud", "icloud drive", "mega", "pcloud")

def file_category(name: str) -> str:
    suffix = Path(name).suffix.lower()
    for category, extensions in CATEGORIES.items():
        if suffix in extensions:
            return category
    return "file"

def cloud_provider(vault_path: str) -> Optional[str]:
    """
    Kasa bir bulut eşitleme klasöründeyse adını döndürür. Bu klasörler dosyayı her değişiklikte
    baştan yükler ve iki cihazda aynı anda düzenlenirse birini sessizce ezer.
    """
    for part in Path(vault_path).parts:
        lowered = part.lower()
        if any(lowered == name or lowered.startswith(name + " ") for name in CLOUD_FOLDERS):
            return part
    return None

def password_strength(password: str) -> Tuple[int, str]:
    """(0-4 arası puan, açıklama) döndürür. Tahmin saldırısına dayanımı kabaca ölçer."""
    if not password:
        return 0, tr("Parola girilmedi")
    pool = 0
    pool += 26 if re.search(r"[a-zçğıöşü]", password) else 0
    pool += 26 if re.search(r"[A-ZÇĞİÖŞÜ]", password) else 0
    pool += 10 if re.search(r"\d", password) else 0
    pool += 33 if re.search(r"[^\w\s]", password) else 0
    pool += 1 if " " in password else 0
    unique_ratio = len(set(password)) / len(password)
    bits = len(password) * max(1.0, _log2(pool)) * min(1.0, unique_ratio + 0.35)
    if len(password) < 8 or bits < 40:
        return 1, tr("Zayıf: kolayca tahmin edilebilir")
    if bits < 60:
        return 2, tr("Orta: birkaç kelime daha ekleyin")
    if bits < 90:
        return 3, tr("Güçlü")
    return 4, tr("Çok güçlü")

def _log2(value: int) -> float:
    import math
    return math.log2(value) if value > 0 else 0.0

def exclusive_write(method: Callable) -> Callable:
    """
    Kasayı değiştiren işlemleri tek tek çalıştırır. Her işlem kataloğu bellekte tutup sonunda bütün olarak yazar;
    ikisi üst üste binerse sonraki yazan öncekini siler ve sıfırlanmış alanları gösteren kayıtlar geri gelir.
    Bekletilmez, reddedilir: arayüz iş parçacığı uzun bir aktarımın bitmesini beklerken donardı.
    """
    @functools.wraps(method)
    def guarded(self: "VaultSession", *args: Any, **kwargs: Any) -> Any:
        if not self._write_gate.acquire(blocking=False):
            raise CustomVaultError(tr("Devam eden işlem bitmeden kasa değiştirilemez."))
        try:
            return method(self, *args, **kwargs)
        finally:
            self._write_gate.release()
    return guarded

class VaultSession:
    """Tek bir açık kasa. Kilitlendiğinde anahtarlar ve geçici dosyalar temizlenir."""

    def __init__(self, vault_path: str):
        self.path = str(Path(vault_path).resolve())
        self.name = Path(vault_path).stem
        self.auth: Optional[Dict[str, Any]] = None
        self.catalog: Dict[str, Any] = {}
        self.second_factor_pending = False
        self.maintenance = False
        self._lock = VaultFileLock(self.path)
        self._write_gate = threading.Lock()
        self._closing = threading.Event()
        self._temp_files: Dict[str, Tuple[str, float]] = {}

    def _needs_second_factor(self) -> bool:
        two_factor = self.catalog.get("two_factor") or {}
        self.second_factor_pending = bool(two_factor.get("enabled") or Engine.read_header_flags(self.path) & 1)
        return self.second_factor_pending

    def unlock(self, password: str, key_digest: Optional[bytes] = None) -> bool:
        """Parolayı doğrular. Ek doğrulama kodu gerekiyorsa True döner."""
        self._lock.acquire()
        try:
            self.auth = Engine.authenticate(self.path, password, key_digest)
            self.refresh()
        except BaseException:
            self.close()
            raise
        return self._needs_second_factor()

    def unlock_with_recovery_key(self, recovery_key: str) -> bool:
        """
        Parolasız açar; çağıran hemen yeni parola belirletmelidir. Kurtarma anahtarı parolanın yerini alır,
        ikinci faktörün değil: 2FA açıksa True döner ve kod ya da yedek kod istenir.
        """
        self._lock.acquire()
        try:
            self.auth = Engine.authenticate_with_recovery_key(self.path, recovery_key)
            self.refresh()
        except BaseException:
            self.close()
            raise
        return self._needs_second_factor()

    def recovery_key(self) -> str:
        return Engine.get_recovery_key(self.auth)

    @exclusive_write
    def confirm_identity(self, password: str, code: str = "") -> None:
        """Açık bırakılmış pencereden hassas işlem yapılamasın diye parolayı (ve varsa kodu) yeniden doğrular."""
        fresh = Engine.authenticate(self.path, password, self.auth.get("key_digest"))
        if fresh["slot_idx"] != self.auth["slot_idx"]:
            raise InvalidPasswordError(tr("Girdiğiniz parola hatalı."))
        if self.two_factor_enabled:
            ok, _message = Engine.verify_vault_2fa(self.path, self.auth, code)
            if not ok:
                raise CustomVaultError(tr("Kod geçersiz veya az önce kullanıldı. Yeni kodu bekleyin."))
            self.refresh()

    @property
    def has_key_file(self) -> bool:
        return bool(self.catalog.get("key_file"))

    @property
    def is_stego(self) -> bool:
        return bool(self.auth and self.auth.get("is_stego"))

    @property
    def carrier_offset(self) -> int:
        return self.auth.get("carrier_offset", 0) if self.auth else 0

    @exclusive_write
    def set_key_file(self, password: str, key_digest: Optional[bytes]) -> None:
        """Anahtar dosyasını ekler veya (None ile) kaldırır. Eski başlıklar işe yaramasın diye bölme yeniden şifrelenir."""
        try:
            Engine.change_password(self.path, self.auth, password, None, self._closing.is_set, key_digest)
        finally:
            if not self._closing.is_set():
                self.refresh()
    @exclusive_write
    def verify_second_factor(self, code: str) -> Tuple[bool, str]:
        if not (self.catalog.get("two_factor") or {}).get("enabled"):
            self.second_factor_pending = False
            return True, ""
        ok, message = Engine.verify_vault_2fa(self.path, self.auth, code)
        if ok:
            self.second_factor_pending = False
            self.refresh()
        return ok, message

    @property
    def is_open(self) -> bool:
        return self.auth is not None and not self.second_factor_pending

    def close(self) -> None:
        """Anahtarları bellekten bırakır, geçici dosyaları siler, kilidi kaldırır. Süren yazma önce durdurulur."""
        self._closing.set()
        with self._write_gate:
            for temp_path in list(self._temp_files):
                parent = Path(temp_path).parent
                secure_wipe_directory(str(parent))
            self._temp_files.clear()
            if self.auth:
                self.auth.clear()
            self.auth = None
            self.catalog = {}
            self._lock.release()
        gc.collect()

    def refresh(self) -> None:
        self.catalog = Engine.load_catalog(self.path, self.auth)

    @property
    def files(self) -> List[Dict[str, Any]]:
        return self.catalog.get("files", [])

    def all_folders(self) -> List[str]:
        """Açıkça oluşturulan ve dosya yollarından türeyen tüm klasörler."""
        found: Set[str] = set(self.catalog.get("folders", []))
        for item in self.files:
            parts = item["path"].split("/")[:-1]
            for depth in range(1, len(parts) + 1):
                found.add("/".join(parts[:depth]))
        for folder in list(found):
            parts = folder.split("/")
            for depth in range(1, len(parts)):
                found.add("/".join(parts[:depth]))
        return sorted(found, key=str.casefold)

    def list_folder(self, folder: str) -> Tuple[List[str], List[Dict[str, Any]]]:
        prefix = f"{folder}/" if folder else ""
        folders = [f for f in self.all_folders() if f.startswith(prefix) and "/" not in f[len(prefix):]]
        files = [f for f in self.files if f["path"].startswith(prefix) and "/" not in f["path"][len(prefix):]]
        return folders, sorted(files, key=lambda f: f["path"].casefold())

    def search(self, text: str, category: Optional[str] = None) -> List[Dict[str, Any]]:
        needle = text.casefold()
        return sorted(
            (f for f in self.files
             if needle in f["path"].casefold() and (category is None or file_category(f["path"]) == category)),
            key=lambda f: f["path"].casefold()
        )

    def stats(self) -> Dict[str, Any]:
        used = sum(f.get("size", 0) for f in self.files)
        quota = self.catalog.get("max_size_mb", 0) * 1024 * 1024 or None
        return {"count": len(self.files), "used": used, "quota": quota, "size_on_disk": os.path.getsize(self.path)}

    def _unique_path(self, rel_path: str, taken: Set[str]) -> str:
        if rel_path not in taken:
            return rel_path
        stem, suffix = os.path.splitext(rel_path)
        index = 2
        while f"{stem} ({index}){suffix}" in taken:
            index += 1
        return f"{stem} ({index}){suffix}"

    def images(self, folder: Optional[str] = None) -> List[Dict[str, Any]]:
        """Slayt gösterisi için görseller; klasör verilirse yalnızca o klasördekiler."""
        pool = self.list_folder(folder)[1] if folder is not None else self.files
        return [f for f in pool if Path(f["path"]).suffix.lower() in IMAGE_EXTS and f.get("size", 0) <= PREVIEW_LIMIT]

    def plan_import(self, sources: List[str], folder: str) -> List[Tuple[str, str]]:
        """Bırakılan dosya ve klasörleri (kaynak, kasa yolu) listesine çevirir; ad çakışmalarını çözer."""
        taken = {f["path"] for f in self.files}
        plan: List[Tuple[str, str]] = []

        def add(source: Path, rel_dir: str) -> None:
            target = "/".join(p for p in (rel_dir, safe_vault_name(source.name)) if p)
            target = self._unique_path(target, taken)
            taken.add(target)
            plan.append((str(source), target))

        for raw in sources:
            source = Path(raw)
            if source.is_dir():
                root = source.parent
                for dirpath, _dirnames, filenames in os.walk(source):
                    rel_parts = Path(dirpath).relative_to(root).parts
                    rel_dir = "/".join(p for p in ([folder] if folder else []) + [safe_vault_name(p) for p in rel_parts])
                    for filename in filenames:
                        add(Path(dirpath) / filename, rel_dir)
            elif source.is_file():
                add(source, folder)
        return plan

    @exclusive_write
    def import_files(
        self,
        plan: List[Tuple[str, str]],
        on_bytes: Optional[Callable[[int], None]] = None,
        should_cancel: Optional[Callable[[], bool]] = None
    ) -> int:
        try:
            result = Engine.add_files(self.path, self.auth, plan, on_bytes, should_cancel)
        finally:
            self.refresh()
        return len(result["entries"])

    def plan_export(self, file_ids: List[str], folders: List[str], destination: str) -> List[Tuple[str, str]]:
        """(dosya kimliği, hedef yol) listesi üretir; var olan dosyaların üzerine yazmaz."""
        taken: Set[str] = set()
        plan: List[Tuple[str, str]] = []

        def add(file_id: str, rel: str) -> None:
            rel_parts = [safe_vault_name(p) for p in rel.split("/")]
            target = os.path.join(destination, *rel_parts)
            stem, suffix = os.path.splitext(target)
            index = 2
            while target in taken or os.path.exists(target):
                target = f"{stem} ({index}){suffix}"
                index += 1
            taken.add(target)
            plan.append((file_id, target))

        by_id = {f["id"]: f for f in self.files}
        for file_id in file_ids:
            add(file_id, by_id[file_id]["path"].rsplit("/", 1)[-1])
        for folder in folders:
            parent = folder.rsplit("/", 1)[0] + "/" if "/" in folder else ""
            for item in self.files:
                if item["path"].startswith(folder + "/"):
                    add(item["id"], item["path"][len(parent):])
        return plan

    def export_files(
        self,
        plan: List[Tuple[str, str]],
        on_bytes: Optional[Callable[[int], None]] = None,
        should_cancel: Optional[Callable[[], bool]] = None
    ) -> int:
        done = 0
        for file_id, target in plan:
            if should_cancel and should_cancel():
                break
            Engine.extract_file(self.path, self.auth, file_id, target, on_bytes, should_cancel)
            done += 1
        return done

    def read_preview(self, file_id: str) -> bytes:
        """Önizleme baytlarını yalnızca RAM'e çözer."""
        return Engine.extract_file_bytes(self.path, self.auth, file_id)[0]

    @exclusive_write
    def write_bytes(self, file_id: str, data: bytes) -> None:
        """Uygulama içi düzenleyicinin kaydı. Veri doğrudan RAM'den şifrelenir, diske düz yazılmaz."""
        entry = next((f for f in self.files if f["id"] == file_id), None)
        if entry is None:
            raise CustomVaultError(tr("Dosya kasada bulunamadı."))
        Engine.write_file_bytes(self.path, self.auth, entry["path"], data)
        self.refresh()

    def open_temp_copy(self, file_id: str) -> str:
        """
        Dosyayı harici uygulamada açmak için geçici kopya çıkarır. Bu kopya şifresizdir;
        kasa kilitlenince silinir ama açan uygulama kendi önbelleğinde iz bırakabilir.
        """
        temp_path, _entry = Engine.extract_to_temp_for_viewing(self.path, self.auth, file_id)
        self._temp_files[temp_path] = (file_id, os.path.getmtime(temp_path))
        return temp_path

    def modified_temp_files(self) -> List[Tuple[str, str]]:
        """Harici uygulamada değiştirilmiş kopyaları (geçici yol, kasa yolu) olarak döndürür."""
        by_id = {f["id"]: f["path"] for f in self.files}
        return [
            (temp_path, by_id[file_id])
            for temp_path, (file_id, mtime) in self._temp_files.items()
            if file_id in by_id and os.path.exists(temp_path) and os.path.getmtime(temp_path) > mtime
        ]

    @exclusive_write
    def save_temp_back(self, temp_path: str, rel_path: str) -> None:
        Engine.add_files(self.path, self.auth, [(temp_path, rel_path)])
        self.refresh()

    @exclusive_write
    def create_folder(self, folder: str, name: str) -> None:
        target = "/".join(p for p in (folder, safe_vault_name(name)) if p)
        result = Engine.add_folder(self.path, self.auth, target)
        if not result.get("success"):
            raise CustomVaultError(result.get("error", "Klasör oluşturulamadı."))
        self.refresh()

    @exclusive_write
    def rename_file(self, file_id: str, new_name: str) -> None:
        entry = next(f for f in self.files if f["id"] == file_id)
        parent = entry["path"].rsplit("/", 1)[0] + "/" if "/" in entry["path"] else ""
        Engine.rename_file(self.path, self.auth, file_id, parent + safe_vault_name(new_name))
        self.refresh()

    @exclusive_write
    def rename_folder(self, folder: str, new_name: str) -> None:
        parent = folder.rsplit("/", 1)[0] + "/" if "/" in folder else ""
        Engine.rename_folder(self.path, self.auth, folder, parent + safe_vault_name(new_name))
        self.refresh()

    @exclusive_write
    def delete(self, file_ids: List[str], folders: List[str]) -> None:
        for file_id in file_ids:
            Engine.delete_file(self.path, self.auth, file_id)
        for folder in folders:
            Engine.delete_folder(self.path, self.auth, folder)
        self.refresh()

    @exclusive_write
    def compact(self) -> Dict[str, Any]:
        """Dosyayı küçültür. Windows açık tutamaçlı dosyanın değiştirilmesine izin vermez, kilit kısa süre bırakılır."""
        self._lock.release()
        try:
            return Engine.compact_vault(self.path, self.auth, discard_other_compartment=True)
        finally:
            self._lock.acquire()
            self.refresh()

    @exclusive_write
    def change_password(self, new_password: str, on_bytes: Optional[Callable[[int], None]] = None) -> None:
        """Parolayı değiştirir ve bölmeyi yeni anahtarla yeniden şifreler. Süre dosya boyutuyla orantılıdır."""
        try:
            Engine.change_password(self.path, self.auth, new_password, on_bytes, self._closing.is_set)
        finally:
            if not self._closing.is_set():
                self.refresh()

    @property
    def two_factor_enabled(self) -> bool:
        return bool((self.catalog.get("two_factor") or {}).get("enabled"))

    def _other_partition(self, password: str) -> Dict[str, Any]:
        """Bölmeler ayrı anahtarla şifrelidir; diğer bölmeye yalnızca kendi parolasıyla yazılabilir."""
        other = Engine.authenticate(self.path, password)
        if other["slot_idx"] == self.auth["slot_idx"]:
            raise CustomVaultError(tr("Bu parola şu an açık olan bölmenin parolası. Diğer bölmenin parolasını girin."))
        return other

    @exclusive_write
    def enable_two_factor(self, secret: str, backup_codes: List[str], other_password: str = "") -> None:
        other = self._other_partition(other_password) if other_password else None
        Engine.set_vault_2fa_config(self.path, self.auth, True, secret, backup_codes)
        if other:
            Engine.set_vault_2fa_config(self.path, other, True, secret, backup_codes)
        self.refresh()

    @exclusive_write
    def disable_two_factor(self, code: str, other_password: str = "") -> None:
        """Açık oturum yetmez: kapatmak için geçerli kod gerekir, yoksa bırakılan pencereden 2FA kaldırılabilirdi."""
        other = self._other_partition(other_password) if other_password else None
        ok, _message = Engine.verify_vault_2fa(self.path, self.auth, code)
        if not ok:
            raise CustomVaultError(tr("Kod geçersiz veya az önce kullanıldı. Yeni kodu bekleyin."))
        Engine.set_vault_2fa_config(self.path, self.auth, False)
        if other:
            Engine.set_vault_2fa_config(self.path, other, False)
        self.refresh()

def open_with_system(path: str) -> None:
    """Dosyayı işletim sisteminin varsayılan uygulamasıyla açar."""
    if sys.platform == "win32":
        os.startfile(path)
    else:
        import subprocess
        subprocess.Popen(["open" if sys.platform == "darwin" else "xdg-open", path])
