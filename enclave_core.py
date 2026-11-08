"""
Enclave - Bağımsız AES-256-GCM Şifreli Kasa Motoru (Custom Encrypted Vault)
Windows BitLocker veya harici hiçbir sürücüye (driver) ihtiyaç duymadan,
tamamen açık kaynaklı, bağımsız, taşınabilir ve yüksek güvenlikli dosya kasası motoru.

Özellikler:
- KDF: Argon2id (256 MiB, 3 tur, 4 şerit) + 32 bayt rastgele Salt. Biçim 1 kasalar PBKDF2 ile açılmaya devam eder.
- Şifreleme: AES-256-GCM (Authenticated Encryption with Associated Data - AEAD)
- Büyük dosyalar: 4 MiB parçalar halinde akışla şifrelenir; dosya boyutu RAM ile sınırlı değildir.
- Bütünlük: Her dosya için 16 bayt kimlik doğrulama etiketi (Auth Tag) + SHA-256 özeti
- İki bölme: Başlıkta iki bağımsız yuva vardır; biçim 2'de gerçek bölmenin yuvası rastgele seçilir.
  Bir parola hangi yuvayı açarsa açsın, ikinci yuvanın dolu mu gürültü mü olduğu başlıktan anlaşılamaz.
  Sınır: Dosya boyutu ile katalogdaki toplam karşılaştırılarak gizli veri olduğundan şüphelenilebilir.
- Kesintiye dayanıklı kayıt: Yeni katalog önce diske yazılır, sonra yuva çevrilir, en son eski alan temizlenir.
- Güvenli Silme: Geçici dosyaların üzerine yazılır. SSD ve kopyala-yaz (APFS, Btrfs) disklerde bu garanti edilemez;
  bu yüzden Linux'ta geçici dosyalar mümkünse RAM diskinde (/dev/shm) tutulur.
"""

import os
import sys
import time
import json
import zlib
import struct
import shutil
import base64
import hashlib
import hmac
import secrets
import tempfile
import unicodedata
from pathlib import Path
from typing import Optional, Dict, Any, Iterable, List, Tuple, BinaryIO, Callable, Iterator

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

MAGIC_HEADER = b"PVAULT01"
VERSION = 2
LEGACY_VERSION = 1
SUPPORTED_VERSIONS = (LEGACY_VERSION, VERSION)
SALT_SIZE = 32
SLOT_PAYLOAD_SIZE = 60
SLOT_NONCE_SIZE = 12
SLOT_TAG_SIZE = 16
SLOT_TOTAL_SIZE = SLOT_NONCE_SIZE + SLOT_PAYLOAD_SIZE + SLOT_TAG_SIZE
HEADER_RESERVED = 44
HEADER_FLAGS_OFFSET = 224
HEADER_2FA_MARKER = b"2F"
FLAG_2FA_ENFORCED = 0x01
FLAG_2FA_TOTP = 0x02
HEADER_TOTAL_SIZE = 256

HEADER_BACKUP_MAGIC = b"PVAULT_HDR_BAK\x01\x00"
HEADER_BACKUP_VERSION = 1

KDF_ITERATIONS = 600000

HEADER_KDF_OFFSET = 252
KDF_ID_ARGON2ID = 2
ARGON2_TIME_COST = 3
ARGON2_LANES = 4
ARGON2_MEMORY_LOG2 = 18
ARGON2_MEMORY_LOG2_MAX = 22

STREAM_THRESHOLD = 32 * 1024 * 1024
STREAM_CHUNK_SIZE = 4 * 1024 * 1024
TOC_EXTENT_ALIGN = 4096

KEY_FILE_SIZE = 64
_KEEP_KEY_FILE = object()

class CustomVaultError(Exception):
    """Özel kasa işlemlerinde oluşan temel hata sınıfı."""
    pass

class InvalidPasswordError(CustomVaultError):
    """Parola yanlış veya dosya bozulmuş."""
    pass

class VaultTamperedError(CustomVaultError):
    """Kasa dosyası üzerinde yetkisiz değişiklik tespit edildi (AEAD Doğrulama Hatası)."""
    pass

def _derive_key(password: str, salt: bytes, kdf_params: Optional[Tuple[int, int, int]] = None) -> bytes:
    """
    Paroladan 256-bit anahtar türetir.
    kdf_params (tur, şerit, log2 KiB) verilirse Argon2id, verilmezse biçim 1 PBKDF2 kullanılır.
    Parola NFC biçimine getirilir: aynı parola macOS ve Windows'ta farklı Unicode dizilimiyle gelebilir.
    """
    pw_bytes = unicodedata.normalize("NFC", password).encode("utf-8")
    if kdf_params is not None:
        time_cost, lanes, memory_log2 = kdf_params
        return Argon2id(
            salt=salt,
            length=32,
            iterations=time_cost,
            lanes=lanes,
            memory_cost=1 << memory_log2
        ).derive(pw_bytes)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS
    )
    return kdf.derive(pw_bytes)

def _apply_key_file(kdf_key: bytes, key_digest: Optional[bytes]) -> bytes:
    """
    Parola anahtarını anahtar dosyasıyla birleştirir: yuva ikisi birden olmadan açılmaz.
    Başlığa işaret yazılmaz; anahtar dosyası kullanılan bir kasa ve bölme dışarıdan ayırt edilemez.
    """
    if not key_digest:
        return kdf_key
    return hmac.new(kdf_key, b"PVAULT_KEYFILE_V1" + key_digest, hashlib.sha256).digest()

def read_key_file(path: str) -> bytes:
    """Anahtar dosyasının özetini döndürür. Dosyanın içeriği değişirse kasa açılmaz."""
    digest = hashlib.sha256()
    size = 0
    try:
        with open(path, "rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
                size += len(chunk)
    except OSError as error:
        raise CustomVaultError(f"Anahtar dosyası okunamadı: {error}")
    if not size:
        raise CustomVaultError("Anahtar dosyası boş.")
    return digest.digest()

def create_key_file(path: str) -> bytes:
    """Rastgele anahtar dosyası oluşturur ve özetini döndürür. Var olan dosyanın üzerine yazmaz."""
    try:
        with open(path, "xb") as target:
            target.write(os.urandom(KEY_FILE_SIZE))
            target.flush()
            os.fsync(target.fileno())
    except FileExistsError:
        raise CustomVaultError("Bu adda bir dosya zaten var; anahtar dosyası üzerine yazılmaz.")
    except OSError as error:
        raise CustomVaultError(f"Anahtar dosyası yazılamadı: {error}")
    return read_key_file(path)

def _read_kdf_params(header_bytes: bytes, version: int) -> Optional[Tuple[int, int, int]]:
    """Başlıktaki KDF parametrelerini okur; biçim 1 için None döner."""
    if version == LEGACY_VERSION:
        return None
    kdf_id, time_cost, lanes, memory_log2 = header_bytes[HEADER_KDF_OFFSET:HEADER_KDF_OFFSET + 4]
    if kdf_id != KDF_ID_ARGON2ID or not time_cost or not lanes or not 3 <= memory_log2 <= ARGON2_MEMORY_LOG2_MAX:
        raise CustomVaultError("Kasa başlığındaki anahtar türetme parametreleri geçersiz.")
    return time_cost, lanes, memory_log2

def _slot_ad(version: int, slot_idx: int, salt: bytes) -> bytes:
    """Yuva şifrelemesinin ek doğrulama verisi. Biçim 2'de yuva numarası gizli bilgi taşımaz."""
    if version == LEGACY_VERSION:
        return b"SLOT1" if slot_idx == 1 else b"SLOT2"
    return b"PVAULT_SLOT_V2" + salt

def _toc_ad(version: int, is_decoy: bool) -> bytes:
    """Katalog şifrelemesinin ek doğrulama verisi."""
    if version == LEGACY_VERSION:
        return b"TOC_DECOY" if is_decoy else b"TOC_REAL"
    return b"PVAULT_TOC_V2"

def _quota_bytes(catalog: Dict[str, Any]) -> Optional[int]:
    if catalog.get("max_size_mb"):
        return catalog["max_size_mb"] * 1024 * 1024
    if catalog.get("max_size_gb"):
        return catalog["max_size_gb"] * 1024 * 1024 * 1024
    return None

def _coalesce_free(free: List[List[int]]) -> List[List[int]]:
    """Boş alan listesini sıralar ve bitişik alanları birleştirir."""
    merged: List[List[int]] = []
    for off, length in sorted(free):
        if merged and merged[-1][0] + merged[-1][1] == off:
            merged[-1][1] += length
        else:
            merged.append([off, length])
    return merged

class _ChunkReader:
    """Parça üreteciyle gelen düz metni, dosya gibi okunabilir hale getirir."""

    def __init__(self, chunks: Iterator[bytes]):
        self._chunks = chunks
        self._buffer = bytearray()

    def read(self, size: int) -> bytes:
        while len(self._buffer) < size:
            chunk = next(self._chunks, None)
            if chunk is None:
                break
            self._buffer += chunk
        data = bytes(self._buffer[:size])
        del self._buffer[:size]
        return data

def _allocate(
    vf: BinaryIO, catalog: Dict[str, Any], auth_info: Dict[str, Any], size: int,
    reserved: Iterable[List[int]] = ()
) -> int:
    """
    Kasa içinde yer ayırır: önce bu bölmenin kendi boş alanları, sonra dosya sonu.
    Komşu bölmenin verisine dokunmamak için katalogda listelenmeyen boşluklar asla kullanılmaz.
    reserved: Kayıttan sonra sıfırlanacak alanlar; bunların üzerine yazılan veri sıfırlamada yok olurdu.
    """
    free = catalog.setdefault("free", [])
    for idx, (off, length) in enumerate(free):
        if length >= size:
            if length == size:
                free.pop(idx)
            else:
                free[idx] = [off + size, length - size]
            return off

    if catalog.get("is_dynamic", True):
        if auth_info.get("is_stego") and auth_info.get("anchor_block"):
            vf.seek(0, os.SEEK_END)
            if vf.tell() >= 512:
                vf.seek(-512, os.SEEK_END)
                if vf.read(512) == auth_info["anchor_block"]:
                    vf.seek(0, os.SEEK_END)
                    vf.truncate(vf.tell() - 512)
        vf.seek(0, os.SEEK_END)
        return vf.tell()

    carrier_off = auth_info.get("carrier_offset", 0)
    base = catalog.get("base_offset", carrier_off + HEADER_TOTAL_SIZE)
    toc_extent = catalog.get("toc_extent", auth_info["toc_len"])
    ends = [base, auth_info["toc_offset"] + toc_extent]
    ends += [item["offset"] + item["len"] for item in catalog.get("files", [])]
    ends += [off + length for off, length in free]
    ends += [off + length for off, length in reserved]
    offset = max(ends)
    quota = _quota_bytes(catalog)
    if quota and offset + size > base + quota:
        raise CustomVaultError(f"Kasa kapasitesi yetersiz! Belirlenen kota: {quota // (1024 * 1024)} MB.")
    return offset

def _zero_extents(vault_path: str, extents: List[Tuple[int, int]]) -> None:
    """Artık kullanılmayan alanların üzerine sıfır yazar (en iyi çaba)."""
    extents = [(off, length) for off, length in extents if off and length > 0]
    if not extents:
        return
    try:
        with open(vault_path, "r+b") as vf:
            chunk = 1024 * 1024
            zero_buf = b"\x00" * chunk
            for off, length in extents:
                vf.seek(off)
                rem = length
                while rem > 0:
                    sz = min(rem, chunk)
                    vf.write(zero_buf if sz == chunk else b"\x00" * sz)
                    rem -= sz
            vf.flush()
            os.fsync(vf.fileno())
    except OSError:
        pass

def secure_wipe_file(filepath: str, passes: int = 1) -> bool:
    """
    Belirtilen geçici dosyanın üzerine yazar ve siler. Klasik disklerde kurtarmayı engeller;
    SSD ve kopyala-yaz dosya sistemlerinde eski blokların silindiği garanti edilemez.
    - Dosyanın ilk baytından son baytına kadar (%100) 4 MB akış bloklarıyla b"\\x00" yazar.
    - os.fsync ile NTFS/işletim sistemi disk önbelleğini fiziksel depolamaya zorlar.
    - Dosyayı 0 bayta budar (truncate) ve MFT dosya adı kayıt kalıntılarını önlemek için rastgele adla siler.
    """
    p = Path(filepath)
    if not p.exists() or not p.is_file():
        return False
    try:
        size = p.stat().st_size
        if size > 0:
            CHUNK = 4 * 1024 * 1024
            zero_chunk = b"\x00" * CHUNK
            with open(p, "r+b") as f:
                f.seek(0)
                rem = size
                while rem > 0:
                    sz = min(rem, CHUNK)
                    f.write(zero_chunk if sz == CHUNK else b"\x00" * sz)
                    rem -= sz
                f.flush()
                try:
                    os.fsync(f.fileno())
                except Exception:
                    pass

                if passes > 1:
                    pattern = b"\xff" * CHUNK
                    f.seek(0)
                    rem = size
                    while rem > 0:
                        sz = min(rem, CHUNK)
                        f.write(pattern if sz == CHUNK else b"\xff" * sz)
                        rem -= sz
                    f.flush()
                    try:
                        os.fsync(f.fileno())
                    except Exception:
                        pass

                    f.seek(0)
                    rem = size
                    while rem > 0:
                        sz = min(rem, CHUNK)
                        f.write(zero_chunk if sz == CHUNK else b"\x00" * sz)
                        rem -= sz
                    f.flush()
                    try:
                        os.fsync(f.fileno())
                    except Exception:
                        pass

                f.truncate(0)
                f.flush()
                try:
                    os.fsync(f.fileno())
                except Exception:
                    pass

        try:
            rnd_name = p.parent / f"_shred_{os.urandom(8).hex()}.tmp"
            p = p.rename(rnd_name)
        except Exception:
            pass

        p.unlink(missing_ok=True)
        return True
    except Exception:
        try:
            p.unlink(missing_ok=True)
            return True
        except Exception:
            return False

def secure_wipe_directory(dirpath: str) -> bool:
    """
    Belirtilen dizindeki tüm dosyaları tek tek secure_wipe_file ile adli standartta sıfırlayıp
    iz bırakmadan dizini tamamen siler.
    """
    p = Path(dirpath)
    if not p.exists() or not p.is_dir():
        return False
    try:
        for f in list(p.rglob("*")):
            if f.is_file():
                secure_wipe_file(str(f), passes=1)
        shutil.rmtree(p, ignore_errors=True)
        return True
    except Exception:
        shutil.rmtree(p, ignore_errors=True)
        return False

def secure_temp_root() -> str:
    """Geçici dosyalar için en güvenli kökü döndürür: Linux'ta RAM diski, diğerlerinde sistem geçici dizini."""
    shm = Path("/dev/shm")
    if sys.platform.startswith("linux") and shm.is_dir() and os.access(shm, os.W_OK):
        return str(shm)
    return tempfile.gettempdir()

def purge_all_vault_temp_forensics() -> int:
    """
    Sistem geçici dizinlerindeki tüm kasa kalıntılarını, eski oturumlardan veya
    çökmelerden kalmış olabilecek önizleme ve simge dizinlerini sıfırlayarak temizler.
    Temizlenen dosya sayısını döndürür.
    """
    patterns = ["enclave_icons*", "vhd_vault_pro_icons*", "pvault_view_*", "pvault_drag_*", "pvault_test_*"]
    wiped_count = 0

    for temp_dir in {Path(tempfile.gettempdir()), Path(secure_temp_root())}:
        for pat in patterns:
            try:
                for item in list(temp_dir.glob(pat)):
                    if item.is_file():
                        if secure_wipe_file(str(item), passes=1):
                            wiped_count += 1
                    elif item.is_dir():
                        for f in list(item.rglob("*")):
                            if f.is_file():
                                if secure_wipe_file(str(f), passes=1):
                                    wiped_count += 1
                        shutil.rmtree(item, ignore_errors=True)
            except Exception:
                pass
    return wiped_count

class VaultFileLock:
    """
    Aynı kasanın iki pencerede aynı anda açılıp bozulmasını engelleyen işletim sistemi kilidi.
    Kilit dosyası oluşturmaz, bu yüzden diskte iz bırakmaz; süreç ölürse kendiliğinden kalkar.
    """

    _LOCK_OFFSET = 1 << 40

    def __init__(self, vault_path: str):
        self.vault_path = vault_path
        self._handle: Optional[BinaryIO] = None

    def acquire(self) -> None:
        handle = open(self.vault_path, "rb")
        try:
            if sys.platform == "win32":
                import msvcrt
                handle.seek(self._LOCK_OFFSET)
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            handle.close()
            raise CustomVaultError("Bu kasa başka bir pencerede açık.")
        self._handle = handle

    def release(self) -> None:
        handle, self._handle = self._handle, None
        if handle is None:
            return
        try:
            if sys.platform == "win32":
                import msvcrt
                handle.seek(self._LOCK_OFFSET)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
        finally:
            handle.close()

WIN_RESERVED_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
}

def _sanitize_vault_rel_path(rel_path: str) -> str:
    """Yol atlama (Path Traversal), Windows ayrılmış aygıt adları ve ADS engellemesi."""
    raw_input = rel_path.strip()
    if raw_input.startswith("/") or raw_input.startswith("\\"):
        raise CustomVaultError("Güvenlik ihlali: Dosya yolu mutlak kök dizin ('/' veya '\\') ile başlayamaz!")
    raw = raw_input.replace("\\", "/")
    parts = [p.strip() for p in raw.split("/") if p.strip() and p.strip() != "."]
    if ".." in parts:
        raise CustomVaultError("Güvenlik ihlali: Dosya yolu '..' (Path Traversal) içeremez!")
    for part in parts:
        if ":" in part or any(c in part for c in '<>"|?*'):
            raise CustomVaultError(f"Güvenlik ihlali: Dosya yolunda geçersiz karakter veya ADS akışı tespit edildi: '{part}'")
        stem = part.split(".")[0].upper()
        if stem in WIN_RESERVED_NAMES:
            raise CustomVaultError(f"Güvenlik ihlali: '{part}' Windows ayrılmış aygıt adıdır!")
    cleaned = "/".join(parts)
    if not cleaned:
        raise CustomVaultError("Geçersiz hedef dosya adı.")
    return cleaned

def safe_vault_name(name: str) -> str:
    """
    Dış dosya adını kasada ve üç işletim sisteminde geçerli olacak hale getirir.
    Linux ve macOS'ta geçerli olan ':' veya '?' gibi karakterler Windows'ta dışa aktarılamaz.
    """
    cleaned = "".join("_" if c in '<>:"|?*/\\' or ord(c) < 32 else c for c in name).strip().rstrip(".")
    if not cleaned or cleaned == "..":
        return "adsiz"
    if cleaned.split(".")[0].upper() in WIN_RESERVED_NAMES:
        return f"_{cleaned}"
    return cleaned

class CustomVaultEngine:
    """
    Bağımsız AES-256-GCM Şifreli Kasa Yönetim Motoru.
    """

    @staticmethod
    def create_vault(
        vault_path: str,
        password: str,
        label: str = "Güvenli Kasa",
        decoy_password: Optional[str] = None,
        max_size_gb: int = 10,
        max_size_mb: Optional[int] = None,
        decoy_size_gb: int = 1,
        decoy_size_mb: Optional[int] = None,
        is_dynamic: bool = True,
        two_factor_secret: Optional[str] = None,
        two_factor_backup_codes: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Yeni bir .pvault şifreli konteyner oluşturur.
        is_dynamic=False seçilirse (Sabit Boyut), konteyner boyutu önceden tam kapasiteye
        ayrılır (Plausible Deniability / Sabit Tahsis).
        """
        target = Path(vault_path).resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            raise CustomVaultError("Bu isimde bir kasa dosyası zaten mevcut.")
        if decoy_password and decoy_password == password:
            raise CustomVaultError("İkinci bölme parolası ana paroladan farklı olmalıdır.")

        salt = os.urandom(SALT_SIZE)
        kdf_params = (ARGON2_TIME_COST, ARGON2_LANES, ARGON2_MEMORY_LOG2)
        
        real_master_key = os.urandom(32)
        real_toc_offset = HEADER_TOTAL_SIZE
        main_mb = max_size_mb if (max_size_mb and max_size_mb > 0) else (max_size_gb * 1024)
        has_decoy = bool(decoy_password and len(decoy_password) >= 6)
        d_mb = decoy_size_mb if (decoy_size_mb and decoy_size_mb > 0) else (decoy_size_gb * 1024)

        real_toc = {
            "label": label,
            "created_at": int(time.time()),
            "updated_at": int(time.time()),
            "has_decoy": has_decoy,
            "is_dynamic": is_dynamic,
            "max_size_gb": max_size_gb,
            "max_size_mb": main_mb,
            "base_offset": HEADER_TOTAL_SIZE,
            "files": []
        }

        has_2fa = bool(two_factor_secret and len(two_factor_secret.strip()) >= 16)
        if has_2fa:
            import totp_engine
            hashed_backups = []
            if two_factor_backup_codes:
                hashed_backups = [totp_engine.hash_backup_code(c) for c in two_factor_backup_codes]
            real_toc["two_factor"] = {
                "enabled": True,
                "type": "totp",
                "secret": two_factor_secret.strip().replace(" ", "").upper(),
                "backup_codes": hashed_backups,
                "created_at": int(time.time())
            }

        real_toc_bytes = zlib.compress(json.dumps(real_toc).encode("utf-8"), level=6)
        real_toc_nonce = os.urandom(12)
        toc_ad = _toc_ad(VERSION, False)
        real_toc_cipher = AESGCM(real_master_key).encrypt(real_toc_nonce, real_toc_bytes, toc_ad)
        real_toc_len = len(real_toc_cipher)

        decoy_master_key = os.urandom(32) if has_decoy else os.urandom(32)
        if not is_dynamic and has_decoy:
            decoy_base_offset = HEADER_TOTAL_SIZE + (main_mb * 1024 * 1024)
            decoy_toc_offset = decoy_base_offset
        else:
            decoy_base_offset = real_toc_offset + real_toc_len
            decoy_toc_offset = decoy_base_offset

        decoy_toc = {
            "label": label,
            "created_at": int(time.time()),
            "updated_at": int(time.time()),
            "is_dynamic": is_dynamic,
            "max_size_gb": decoy_size_gb,
            "max_size_mb": d_mb,
            "base_offset": decoy_base_offset,
            "files": []
        }
        decoy_toc_bytes = zlib.compress(json.dumps(decoy_toc).encode("utf-8"), level=6)
        decoy_toc_nonce = os.urandom(12)
        decoy_toc_cipher = AESGCM(decoy_master_key).encrypt(decoy_toc_nonce, decoy_toc_bytes, toc_ad)
        decoy_toc_len = len(decoy_toc_cipher) if has_decoy else 0

        def seal_slot(slot_pw: str, master_key: bytes, toc_offset: int, toc_len: int, toc_nonce: bytes) -> bytes:
            payload = master_key + struct.pack("<QQ", toc_offset, toc_len) + toc_nonce
            nonce = os.urandom(SLOT_NONCE_SIZE)
            key = _derive_key(slot_pw, salt, kdf_params)
            return nonce + AESGCM(key).encrypt(nonce, payload, _slot_ad(VERSION, 0, salt))

        real_block = seal_slot(password, real_master_key, real_toc_offset, real_toc_len, real_toc_nonce)
        if has_decoy:
            other_block = seal_slot(decoy_password, decoy_master_key, decoy_toc_offset, decoy_toc_len, decoy_toc_nonce)
        else:
            other_block = os.urandom(SLOT_TOTAL_SIZE)

        slot1_block, slot2_block = (real_block, other_block) if secrets.randbelow(2) else (other_block, real_block)

        public_header_size = decoy_size_gb if has_decoy else max_size_gb
        reserved_padding = (
            struct.pack("<I", public_header_size) + b"\x00\x00\x00" + os.urandom(25) +
            bytes((KDF_ID_ARGON2ID, ARGON2_TIME_COST, ARGON2_LANES, ARGON2_MEMORY_LOG2))
        )
        header = (
            MAGIC_HEADER +
            struct.pack("<I", VERSION) +
            salt +
            slot1_block +
            slot2_block +
            reserved_padding
        )
        assert len(header) == HEADER_TOTAL_SIZE, f"Header boyutu {len(header)} bayt, 256 olmalı!"

        temp_file = target.parent / f".tmp_{target.name}_{os.urandom(4).hex()}"
        try:
            with open(temp_file, "wb") as f:
                f.write(header)
                f.write(real_toc_cipher)
                if has_decoy:
                    if not is_dynamic:
                        f.seek(decoy_base_offset)
                        f.write(decoy_toc_cipher)
                    else:
                        f.write(decoy_toc_cipher)
                
                if not is_dynamic:
                    tot_mb = main_mb + (d_mb if has_decoy else 0)
                    fixed_bytes = tot_mb * 1024 * 1024 + HEADER_TOTAL_SIZE
                    if fixed_bytes > f.tell():
                        f.truncate(fixed_bytes)
                
                f.flush()
                os.fsync(f.fileno())

            os.replace(str(temp_file), str(target))
        except Exception as e:
            if temp_file.exists():
                temp_file.unlink(missing_ok=True)
            raise CustomVaultError(f"Kasa dosyası oluşturulamadı: {e}")

        return {
            "success": True,
            "path": str(target),
            "label": label,
            "has_decoy": has_decoy,
            "has_2fa": has_2fa,
            "max_size_gb": max_size_gb,
            "size_bytes": target.stat().st_size
        }

    @staticmethod
    def authenticate(vault_path: str, password: str, key_digest: Optional[bytes] = None) -> Dict[str, Any]:
        """
        Kasa parolasını doğrular. Bölmede anahtar dosyası varsa özeti key_digest ile verilmelidir.
        Parola doğruysa master_key, TOC konumu ve kasanın gerçek mi yoksa tuzak mı olduğunu döndürür.
        Parola yanlışsa InvalidPasswordError fırlatır.
        """
        p = Path(vault_path)
        if not p.exists() or not p.is_file():
            raise CustomVaultError("Kasa dosyası bulunamadı.")

        if p.stat().st_size < HEADER_TOTAL_SIZE:
            raise CustomVaultError("Kasa dosyası geçersiz veya bozulmuş (Çok küçük).")

        with open(p, "rb") as f:
            header_bytes = f.read(HEADER_TOTAL_SIZE)

        magic = header_bytes[:8]
        carrier_offset = 0
        header_mask = None
        is_stego = False
        anchor_block = None

        if magic != MAGIC_HEADER:
            try:
                from stego_enclave import inspect_stego_anchor, mask_header_bytes, STEGO_ANCHOR_SIZE
                stego_info = inspect_stego_anchor(vault_path, password, key_digest)
            except Exception:
                stego_info = None

            if stego_info:
                carrier_offset = stego_info["carrier_offset"]
                header_mask = stego_info["header_mask"]
                is_stego = True
                with open(p, "rb") as f:
                    f.seek(carrier_offset)
                    raw_header = f.read(HEADER_TOTAL_SIZE)
                    f.seek(-STEGO_ANCHOR_SIZE, os.SEEK_END)
                    anchor_block = f.read(STEGO_ANCHOR_SIZE)
                header_bytes = mask_header_bytes(raw_header, header_mask)
                magic = header_bytes[:8]

        if magic != MAGIC_HEADER:
            raise CustomVaultError("Bu dosya geçerli bir PVAULT şifreli kasa formatında değil.")

        version = struct.unpack("<I", header_bytes[8:12])[0]
        if version not in SUPPORTED_VERSIONS:
            raise CustomVaultError(f"Desteklenmeyen kasa sürümü: {version}. Uygulamayı güncelleyin.")
        salt = header_bytes[12:44]
        kdf_params = _read_kdf_params(header_bytes, version)

        kdf_key = _apply_key_file(_derive_key(password, salt, kdf_params), key_digest)

        for slot_idx in (1, 2):
            start = 44 + (slot_idx - 1) * SLOT_TOTAL_SIZE
            block = header_bytes[start:start + SLOT_TOTAL_SIZE]
            try:
                plain = AESGCM(kdf_key).decrypt(
                    block[:SLOT_NONCE_SIZE], block[SLOT_NONCE_SIZE:], _slot_ad(version, slot_idx, salt)
                )
            except InvalidTag:
                continue

            toc_offset, toc_len = struct.unpack("<QQ", plain[32:48])
            return {
                "authenticated": True,
                "is_decoy": version == LEGACY_VERSION and slot_idx == 2,
                "master_key": plain[:32],
                "toc_offset": toc_offset,
                "toc_len": toc_len,
                "toc_nonce": plain[48:60],
                "salt": salt,
                "slot_idx": slot_idx,
                "kdf_key": kdf_key,
                "key_digest": key_digest,
                "version": version,
                "kdf_params": kdf_params,
                "is_stego": is_stego,
                "carrier_offset": carrier_offset,
                "header_mask": header_mask,
                "anchor_block": anchor_block
            }

        raise InvalidPasswordError("Girdiğiniz parola hatalı! Şifre çözülemedi.")

    @staticmethod
    def get_recovery_key(auth_info: Dict[str, Any]) -> str:
        """
        Açık bölmenin kurtarma anahtarı: parolayla türetilen yuva anahtarının okunabilir hali.
        Kasaya ek veri yazılmaz, eski kasalarda da çalışır. Parola değişince eski anahtar geçersiz olur.
        """
        encoded = base64.b32encode(auth_info["kdf_key"]).decode("ascii").rstrip("=")
        return "-".join(encoded[i:i + 4] for i in range(0, len(encoded), 4))

    @staticmethod
    def authenticate_with_recovery_key(vault_path: str, recovery_key: str) -> Dict[str, Any]:
        """Kurtarma anahtarıyla bölmeyi açar. Kullanıcı ardından yeni parola belirlemelidir."""
        clean = recovery_key.strip().replace("-", "").replace(" ", "").upper()
        try:
            kdf_key = base64.b32decode(clean + "=" * (-len(clean) % 8))
        except ValueError:
            raise InvalidPasswordError("Kurtarma anahtarı hatalı.")
        if len(kdf_key) != 32:
            raise InvalidPasswordError("Kurtarma anahtarı hatalı.")
        with open(vault_path, "rb") as f:
            header_bytes = f.read(HEADER_TOTAL_SIZE)
        if len(header_bytes) < HEADER_TOTAL_SIZE or header_bytes[:8] != MAGIC_HEADER:
            raise CustomVaultError("Bu dosya geçerli bir kasa değil.")
        version = struct.unpack("<I", header_bytes[8:12])[0]
        if version not in SUPPORTED_VERSIONS:
            raise CustomVaultError(f"Desteklenmeyen kasa sürümü: {version}.")
        salt = header_bytes[12:44]
        for slot_idx in (1, 2):
            start = 44 + (slot_idx - 1) * SLOT_TOTAL_SIZE
            block = header_bytes[start:start + SLOT_TOTAL_SIZE]
            try:
                plain = AESGCM(kdf_key).decrypt(
                    block[:SLOT_NONCE_SIZE], block[SLOT_NONCE_SIZE:], _slot_ad(version, slot_idx, salt)
                )
            except InvalidTag:
                continue
            toc_offset, toc_len = struct.unpack("<QQ", plain[32:48])
            return {
                "authenticated": True, "is_decoy": version == LEGACY_VERSION and slot_idx == 2,
                "master_key": plain[:32], "toc_offset": toc_offset, "toc_len": toc_len, "toc_nonce": plain[48:60],
                "salt": salt, "slot_idx": slot_idx, "kdf_key": kdf_key, "version": version,
                "kdf_params": _read_kdf_params(header_bytes, version)
            }
        raise InvalidPasswordError("Kurtarma anahtarı hatalı.")

    @staticmethod
    def load_catalog(vault_path: str, auth_info: Dict[str, Any]) -> Dict[str, Any]:
        """Kasa içindeki şifreli dosya listesini (TOC) okur ve doğrular."""
        p = Path(vault_path)
        offset = auth_info["toc_offset"]
        length = auth_info["toc_len"]
        nonce = auth_info["toc_nonce"]
        master_key = auth_info["master_key"]
        ad = _toc_ad(auth_info.get("version", LEGACY_VERSION), auth_info["is_decoy"])

        with open(p, "rb") as f:
            f.seek(offset)
            cipher_bytes = f.read(length)

        try:
            plain_bytes = AESGCM(master_key).decrypt(nonce, cipher_bytes, ad)
            decompressed = zlib.decompress(plain_bytes)
            catalog = json.loads(decompressed.decode("utf-8"))
            catalog.setdefault("files", [])
            catalog.setdefault("folders", [])
            return catalog
        except InvalidTag:
            raise VaultTamperedError("Kasa kataloğu doğrulanamadı! Dosya tahrif edilmiş olabilir.")
        except Exception as e:
            raise CustomVaultError(f"Katalog okunurken hata: {e}")

    @staticmethod
    def _check_capacity(catalog: Dict[str, Any], rel_name: str, file_size: int) -> None:
        max_bytes = _quota_bytes(catalog)
        if not max_bytes:
            return
        current_total = sum(item.get("size", 0) for item in catalog.get("files", []) if item.get("path") != rel_name)
        if current_total + file_size > max_bytes:
            raise CustomVaultError(f"Kasa kapasitesi yetersiz! Belirlenen kota: {max_bytes // (1024 * 1024)} MB.")

    @staticmethod
    def _commit_entry(catalog: Dict[str, Any], entry: Dict[str, Any]) -> None:
        """Yeni kaydı kataloğa işler; üzerine yazılan sürümün alanını boş listesine alır."""
        files = catalog.setdefault("files", [])
        for idx, item in enumerate(files):
            if item.get("path") == entry["path"]:
                CustomVaultEngine._release_entries(catalog, [item])
                files[idx] = entry
                return
        files.append(entry)

    @staticmethod
    def write_file_bytes(
        vault_path: str,
        auth_info: Dict[str, Any],
        dest_rel_path: str,
        raw_data: bytes,
        mtime: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Doğrudan bellekten gelen ikili veriyi (bytes) şifreleyerek kasaya kaydeder/günceller.
        Diske hiçbir geçici dosya yazılmaz (Zero-Disk Trace).
        """
        vault_p = Path(vault_path)
        catalog = CustomVaultEngine.load_catalog(vault_path, auth_info)

        rel_name = _sanitize_vault_rel_path(dest_rel_path)

        file_sha256 = hashlib.sha256(raw_data).hexdigest()
        file_size = len(raw_data)
        file_mtime = mtime if mtime is not None else int(time.time())

        CustomVaultEngine._check_capacity(catalog, rel_name, file_size)

        existing_file_id = next((i.get("id") for i in catalog.get("files", []) if i.get("path") == rel_name), None)

        ext_lower = Path(rel_name).suffix.lower()
        PRECOMPRESSED_EXTS = {
            ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".iso", ".vhd", ".vhdx",
            ".mp4", ".mkv", ".avi", ".mov", ".wmv", ".webm", ".flv", ".m4v",
            ".mp3", ".flac", ".aac", ".ogg", ".wma", ".m4a", ".opus",
            ".jpg", ".jpeg", ".png", ".webp", ".gif",
            ".exe", ".msi", ".dll", ".bin", ".dat"
        }
        if ext_lower in PRECOMPRESSED_EXTS or file_size > 25 * 1024 * 1024:
            compressed = zlib.compress(raw_data, level=0)
        elif file_size > 1 * 1024 * 1024:
            compressed = zlib.compress(raw_data, level=1)
        else:
            compressed = zlib.compress(raw_data, level=6)

        file_id = existing_file_id or f"f_{hashlib.sha256(os.urandom(16) + rel_name.encode()).hexdigest()[:12]}"
        file_nonce = os.urandom(12)
        encrypted_data = AESGCM(auth_info["master_key"]).encrypt(file_nonce, compressed, file_id.encode("ascii"))

        with open(vault_p, "r+b") as vf:
            new_file_offset = _allocate(vf, catalog, auth_info, len(encrypted_data))
            vf.seek(new_file_offset)
            vf.write(encrypted_data)

        entry = {
            "id": file_id,
            "path": rel_name,
            "size": file_size,
            "comp_size": len(compressed),
            "mtime": file_mtime,
            "sha256": file_sha256,
            "offset": new_file_offset,
            "len": len(encrypted_data),
            "nonce": file_nonce.hex()
        }
        CustomVaultEngine._commit_entry(catalog, entry)
        CustomVaultEngine._save_catalog(vault_path, auth_info, catalog)

        return {
            "success": True,
            "entry": entry,
            "total_files": len(catalog["files"])
        }

    @staticmethod
    def _stream_nonce(prefix: bytes, index: int, is_last: bool) -> bytes:
        """STREAM yapısı: parçaların sırası değiştirilemez, dosya sondan kesilemez."""
        return prefix + struct.pack(">I", index) + (b"\x01" if is_last else b"\x00")

    @staticmethod
    def _write_stream(
        vault_path: str,
        auth_info: Dict[str, Any],
        catalog: Dict[str, Any],
        source: BinaryIO,
        file_size: int,
        rel_name: str,
        mtime: int,
        on_bytes: Optional[Callable[[int], None]] = None,
        should_cancel: Optional[Callable[[], bool]] = None
    ) -> Dict[str, Any]:
        """Dosyayı belleğe almadan 4 MiB parçalar halinde şifreler. Katalog kaydını çağıran yapar."""
        chunks = max(1, (file_size + STREAM_CHUNK_SIZE - 1) // STREAM_CHUNK_SIZE)
        total_len = file_size + chunks * 16
        existing_file_id = next((i.get("id") for i in catalog.get("files", []) if i.get("path") == rel_name), None)
        file_id = existing_file_id or f"f_{hashlib.sha256(os.urandom(16) + rel_name.encode()).hexdigest()[:12]}"
        aad = file_id.encode("ascii")
        prefix = os.urandom(7)
        cipher = AESGCM(auth_info["master_key"])
        digest = hashlib.sha256()

        with open(vault_path, "r+b") as vf:
            offset = _allocate(vf, catalog, auth_info, total_len)
            vf.seek(offset)
            for index in range(chunks):
                if should_cancel and should_cancel():
                    raise CustomVaultError("İşlem iptal edildi.")
                is_last = index == chunks - 1
                want = file_size - index * STREAM_CHUNK_SIZE if is_last else STREAM_CHUNK_SIZE
                chunk = source.read(want)
                if len(chunk) != want:
                    raise CustomVaultError("Kaynak dosya okunurken değişti.")
                digest.update(chunk)
                vf.write(cipher.encrypt(CustomVaultEngine._stream_nonce(prefix, index, is_last), chunk, aad))
                if on_bytes:
                    on_bytes(len(chunk))

        return {
            "id": file_id,
            "path": rel_name,
            "size": file_size,
            "comp_size": file_size,
            "mtime": mtime,
            "sha256": digest.hexdigest(),
            "offset": offset,
            "len": total_len,
            "nonce": prefix.hex(),
            "chunk_size": STREAM_CHUNK_SIZE
        }

    @staticmethod
    def add_file(
        vault_path: str,
        auth_info: Dict[str, Any],
        source_path: str,
        dest_rel_path: str = ""
    ) -> Dict[str, Any]:
        """
        Yerel bir dosyayı şifreleyerek kasaya ekler.
        Atomik olarak güncellenir ve bütünlük etiketleri kaydedilir.
        """
        src = Path(source_path)
        if not src.exists() or not src.is_file():
            raise CustomVaultError("Eklenecek kaynak dosya bulunamadı.")

        raw_rel = dest_rel_path.strip() or src.name
        if src.stat().st_size > STREAM_THRESHOLD:
            result = CustomVaultEngine.add_files(vault_path, auth_info, [(str(src), raw_rel)])
            return {"success": True, "entry": result["entries"][0], "total_files": result["total_files"]}

        with open(src, "rb") as sf:
            raw_data = sf.read()

        return CustomVaultEngine.write_file_bytes(
            vault_path, auth_info, raw_rel, raw_data, mtime=int(src.stat().st_mtime)
        )

    @staticmethod
    def add_files(
        vault_path: str,
        auth_info: Dict[str, Any],
        items: List[Tuple[str, str]],
        on_bytes: Optional[Callable[[int], None]] = None,
        should_cancel: Optional[Callable[[], bool]] = None
    ) -> Dict[str, Any]:
        """
        Birden çok dosyayı (kaynak, kasa yolu) tek katalog kaydıyla ekler.
        Hata veya iptal olursa o ana kadar biten dosyalar korunur, hata sonra yükseltilir.
        """
        catalog = CustomVaultEngine.load_catalog(vault_path, auth_info)
        entries: List[Dict[str, Any]] = []
        error: Optional[Exception] = None

        for source_path, dest_rel in items:
            if should_cancel and should_cancel():
                break
            try:
                src = Path(source_path)
                stat = src.stat()
                rel_name = _sanitize_vault_rel_path(dest_rel)
                CustomVaultEngine._check_capacity(catalog, rel_name, stat.st_size)
                with open(src, "rb") as source:
                    entry = CustomVaultEngine._write_stream(
                        vault_path, auth_info, catalog, source, stat.st_size, rel_name, int(stat.st_mtime),
                        on_bytes, should_cancel
                    )
                CustomVaultEngine._commit_entry(catalog, entry)
                entries.append(entry)
            except (OSError, CustomVaultError) as e:
                error = e
                break

        if entries:
            CustomVaultEngine._save_catalog(vault_path, auth_info, catalog)
        if error:
            if isinstance(error, CustomVaultError):
                raise error
            raise CustomVaultError(f"Dosya eklenemedi: {error}")
        return {"success": True, "entries": entries, "total_files": len(catalog["files"])}

    @staticmethod
    def duplicate_file(
        vault_path: str,
        auth_info: Dict[str, Any],
        file_id: str,
        dest_rel_path: str
    ) -> Dict[str, Any]:
        """Kasa içindeki bir dosyayı doğrudan bellekte çoğaltır."""
        raw_data, _ = CustomVaultEngine.extract_file_bytes(vault_path, auth_info, file_id)
        return CustomVaultEngine.write_file_bytes(vault_path, auth_info, dest_rel_path, raw_data)

    @staticmethod
    def verify_file_integrity(
        vault_path: str,
        auth_info: Dict[str, Any],
        file_id: str
    ) -> Dict[str, Any]:
        """Dosyanın hem AEAD (GCM Tag) hem de SHA-256 bütünlüğünü canlı test eder."""
        try:
            catalog = CustomVaultEngine.load_catalog(vault_path, auth_info)
            target = next((f for f in catalog.get("files", []) if f["id"] == file_id or f["path"] == file_id), None)
            if not target:
                return {"valid": False, "error": "Dosya katalogda bulunamadı."}
            raw, _ = CustomVaultEngine.extract_file_bytes(vault_path, auth_info, file_id)
            calc_sha = hashlib.sha256(raw).hexdigest()
            if calc_sha.lower() != target.get("sha256", "").lower():
                return {"valid": False, "error": "SHA-256 özeti eşleşmiyor (Veri bozulmuş)."}
            return {
                "valid": True,
                "sha256": calc_sha,
                "size": len(raw),
                "comp_size": target.get("comp_size", 0)
            }
        except Exception as e:
            return {"valid": False, "error": str(e)}

    @staticmethod
    def _seal_catalog(auth_info: Dict[str, Any], catalog: Dict[str, Any]) -> Tuple[bytes, bytes]:
        data = zlib.compress(json.dumps(catalog).encode("utf-8"), level=6)
        nonce = os.urandom(12)
        ad = _toc_ad(auth_info.get("version", LEGACY_VERSION), auth_info["is_decoy"])
        return AESGCM(auth_info["master_key"]).encrypt(nonce, data, ad), nonce

    @staticmethod
    def _seal_slot(auth_info: Dict[str, Any], toc_offset: int, toc_len: int, toc_nonce: bytes) -> Tuple[int, bytes]:
        """(Yuvanın dosyadaki konumu, 88 baytlık yuva bloğu) döndürür."""
        kdf_key = auth_info.get("kdf_key")
        if not kdf_key:
            raise CustomVaultError("Oturumda yuva anahtarı yok; kasayı yeniden açın.")
        slot_idx = auth_info["slot_idx"]
        version = auth_info.get("version", LEGACY_VERSION)
        payload = auth_info["master_key"] + struct.pack("<QQ", toc_offset, toc_len) + toc_nonce
        nonce = os.urandom(SLOT_NONCE_SIZE)
        block = nonce + AESGCM(kdf_key).encrypt(nonce, payload, _slot_ad(version, slot_idx, auth_info["salt"]))
        slot_pos = 44 + (slot_idx - 1) * SLOT_TOTAL_SIZE
        carrier_offset = auth_info.get("carrier_offset", 0)
        header_mask = auth_info.get("header_mask")
        if header_mask:
            block = bytes(b ^ header_mask[(slot_pos + i) % 32] for i, b in enumerate(block))
        return carrier_offset + slot_pos, block

    @staticmethod
    def _save_catalog(vault_path: str, auth_info: Dict[str, Any], catalog: Dict[str, Any]):
        """
        Kataloğu kesintiye dayanıklı olarak kaydeder. Sıra önemlidir:
        1) Yeni katalog boş bir alana yazılır ve diske zorlanır; bu sırada eski katalog sağlamdır.
        2) Başlık yuvası yeni kataloğu gösterecek şekilde çevrilir. 88 bayt tek sektörde olduğundan bu adım
           ya tamamen olur ya hiç olmaz.
        3) Eski katalog ve silinen dosyalar ancak bundan sonra sıfırlanır.
        Herhangi bir adımda elektrik kesilirse kasa son tutarlı haliyle açılır.
        """
        catalog["updated_at"] = int(time.time())
        catalog.setdefault("files", [])
        catalog.setdefault("folders", [])
        catalog.pop("data_end_offset", None)
        released = catalog.pop("_zero", [])
        old_extent = (auth_info["toc_offset"], catalog.get("toc_extent", auth_info["toc_len"]))
        vault_p = Path(vault_path)

        with open(vault_p, "r+b") as vf:
            catalog["free"] = _coalesce_free(catalog.get("free", []))
            draft, _ = CustomVaultEngine._seal_catalog(auth_info, catalog)
            slack = 256
            while True:
                extent = -(-(len(draft) + slack) // TOC_EXTENT_ALIGN) * TOC_EXTENT_ALIGN
                new_toc_offset = _allocate(vf, catalog, auth_info, extent, released)
                candidate = dict(catalog)
                candidate["free"] = _coalesce_free(catalog["free"] + [list(old_extent)] + released)
                candidate["toc_extent"] = extent
                new_toc_cipher, new_toc_nonce = CustomVaultEngine._seal_catalog(auth_info, candidate)
                if len(new_toc_cipher) <= extent:
                    break
                catalog["free"] = _coalesce_free(catalog["free"] + [[new_toc_offset, extent]])
                draft, slack = new_toc_cipher, slack * 4

            vf.seek(new_toc_offset)
            vf.write(new_toc_cipher)
            if vf.tell() < new_toc_offset + extent:
                vf.write(b"\x00" * (new_toc_offset + extent - vf.tell()))
            vf.flush()
            os.fsync(vf.fileno())

            slot_start, slot_block = CustomVaultEngine._seal_slot(
                auth_info, new_toc_offset, len(new_toc_cipher), new_toc_nonce
            )
            vf.seek(slot_start)
            vf.write(slot_block)

            if auth_info.get("is_stego") and auth_info.get("anchor_block"):
                vf.seek(0, os.SEEK_END)
                vf.write(auth_info["anchor_block"])

            vf.flush()
            os.fsync(vf.fileno())

        catalog.update(free=candidate["free"], toc_extent=extent)
        auth_info["toc_offset"] = new_toc_offset
        auth_info["toc_len"] = len(new_toc_cipher)
        auth_info["toc_nonce"] = new_toc_nonce

        _zero_extents(vault_path, [old_extent] + [tuple(e) for e in released])

    @staticmethod
    def change_password(
        vault_path: str,
        auth_info: Dict[str, Any],
        new_password: str,
        on_bytes: Optional[Callable[[int], None]] = None,
        should_cancel: Optional[Callable[[], bool]] = None,
        key_digest: Any = _KEEP_KEY_FILE
    ) -> Dict[str, Any]:
        """
        Açık bölmenin parolasını ve ana anahtarını değiştirir. Parola sızmış olabileceği için yalnızca yuvayı
        yeniden kapatmak yetmez: eski başlığı ve eski parolayı bilen biri ana anahtara ulaşır. Bu yüzden tüm
        dosyalar yeni anahtarla yeniden yazılır; eski şifreli alanlar kayıttan sonra sıfırlanır.

        Yeni kopyalar eski verinin yanına yazılır, geçiş tek bir yuva yazımıyla olur. İşlem yarıda kalırsa kasa eski
        parolayla sağlam açılır. Bu sırada bölmenin kapladığı kadar boş alan gerekir; sabit boyutlu kasada yer
        yetmezse işlem hiçbir şey değiştirmeden reddedilir. Diğer bölme etkilenmez.

        key_digest verilirse anahtar dosyası eklenir, None verilirse kaldırılır. Oturum kurtarma anahtarıyla
        açıldıysa anahtar dosyası bilinmez; yeni parola onsuz çalışır, çünkü dosya kaybolmuş olabilir.
        """
        if not new_password:
            raise CustomVaultError("Yeni parola boş olamaz.")
        catalog = CustomVaultEngine.load_catalog(vault_path, auth_info)
        if key_digest is _KEEP_KEY_FILE:
            key_digest = auth_info.get("key_digest")
        rekeyed = dict(auth_info)
        rekeyed["master_key"] = os.urandom(32)
        rekeyed["key_digest"] = key_digest
        rekeyed["kdf_key"] = _apply_key_file(
            _derive_key(new_password, auth_info["salt"], auth_info.get("kdf_params")), key_digest
        )
        catalog["key_file"] = bool(key_digest)
        old_entries = list(catalog.get("files", []))
        original_size = os.path.getsize(vault_path)
        new_entries: List[Dict[str, Any]] = []

        try:
            for entry in old_entries:
                chunks = CustomVaultEngine.iter_file_chunks(vault_path, auth_info, entry)
                try:
                    new_entry = CustomVaultEngine._write_stream(
                        vault_path, rekeyed, catalog, _ChunkReader(chunks), entry["size"], entry["path"],
                        entry.get("mtime", int(time.time())), on_bytes, should_cancel
                    )
                finally:
                    chunks.close()
                if new_entry["sha256"] != entry["sha256"]:
                    raise VaultTamperedError(f"Bütünlük uyuşmazlığı! Dosya bozulmuş: {entry['path']}")
                new_entries.append(new_entry)
                catalog["files"] = old_entries + new_entries
        except BaseException:
            if catalog.get("is_dynamic", True):
                try:
                    with open(vault_path, "r+b") as vf:
                        vf.truncate(original_size)
                except OSError:
                    pass
            raise

        catalog["files"] = new_entries
        CustomVaultEngine._release_entries(catalog, old_entries)
        if auth_info.get("is_stego"):
            from stego_enclave import build_stego_anchor
            rekeyed["anchor_block"] = build_stego_anchor(
                carrier_offset=auth_info["carrier_offset"],
                header_mask=auth_info["header_mask"],
                password=new_password,
                salt=auth_info.get("anchor_salt"),
                key_digest=key_digest
            )
        CustomVaultEngine._save_catalog(vault_path, rekeyed, catalog)
        auth_info.update(rekeyed)
        return {"success": True}

    @staticmethod
    def iter_file_chunks(vault_path: str, auth_info: Dict[str, Any], entry: Dict[str, Any]) -> Iterator[bytes]:
        """Dosyanın düz metnini parça parça üretir; AEAD doğrulaması her parçada yapılır."""
        cipher = AESGCM(auth_info["master_key"])
        aad = entry["id"].encode("ascii")
        chunk_size = entry.get("chunk_size")
        with open(vault_path, "rb") as vf:
            vf.seek(entry["offset"])
            if not chunk_size:
                sealed = vf.read(entry["len"])
                try:
                    yield zlib.decompress(cipher.decrypt(bytes.fromhex(entry["nonce"]), sealed, aad))
                except InvalidTag:
                    raise VaultTamperedError(f"Dosya şifresi çözülemedi! '{entry['path']}' tahrif edilmiş.")
                except zlib.error as e:
                    raise CustomVaultError(f"Dosya açılırken hata: {e}")
                return

            prefix = bytes.fromhex(entry["nonce"])
            chunks = max(1, (entry["size"] + chunk_size - 1) // chunk_size)
            for index in range(chunks):
                is_last = index == chunks - 1
                plain_len = entry["size"] - index * chunk_size if is_last else chunk_size
                sealed = vf.read(plain_len + 16)
                try:
                    yield cipher.decrypt(CustomVaultEngine._stream_nonce(prefix, index, is_last), sealed, aad)
                except InvalidTag:
                    raise VaultTamperedError(f"Dosya şifresi çözülemedi! '{entry['path']}' tahrif edilmiş.")

    @staticmethod
    def extract_file_bytes(
        vault_path: str,
        auth_info: Dict[str, Any],
        file_id: str
    ) -> Tuple[bytes, Dict[str, Any]]:
        """
        Kasada depolanan şifreli dosyayı belleğe çözer, bütünlüğünü (AEAD + SHA-256)
        doğrular ve (plain_data, target_entry) döndürür. Disk yazımı yapmaz.
        """
        catalog = CustomVaultEngine.load_catalog(vault_path, auth_info)
        target_entry = None
        for item in catalog.get("files", []):
            if item["id"] == file_id or item["path"] == file_id:
                target_entry = item
                break

        if not target_entry:
            raise CustomVaultError("İstenen dosya kasa içinde bulunamadı.")

        digest = hashlib.sha256()
        parts = []
        for chunk in CustomVaultEngine.iter_file_chunks(vault_path, auth_info, target_entry):
            digest.update(chunk)
            parts.append(chunk)
        plain_data = b"".join(parts)

        if digest.hexdigest() != target_entry["sha256"]:
            raise VaultTamperedError(f"Bütünlük uyuşmazlığı! Dosya bozulmuş: {target_entry['path']}")

        return plain_data, target_entry

    @staticmethod
    def find_entry(catalog: Dict[str, Any], file_id: str) -> Optional[Dict[str, Any]]:
        return next((f for f in catalog.get("files", []) if f["id"] == file_id or f["path"] == file_id), None)

    @staticmethod
    def extract_file(
        vault_path: str,
        auth_info: Dict[str, Any],
        file_id: str,
        dest_filepath: str,
        on_bytes: Optional[Callable[[int], None]] = None,
        should_cancel: Optional[Callable[[], bool]] = None
    ) -> Dict[str, Any]:
        """
        Kasada depolanan şifreli dosyayı çözer, bütünlüğünü (AEAD + SHA-256)
        doğrular ve hedef konuma yazar. Bellek kullanımı dosya boyutundan bağımsızdır;
        doğrulanamayan veya iptal edilen çıktı diskte bırakılmaz.
        """
        catalog = CustomVaultEngine.load_catalog(vault_path, auth_info)
        target_entry = CustomVaultEngine.find_entry(catalog, file_id)
        if not target_entry:
            raise CustomVaultError("İstenen dosya kasa içinde bulunamadı.")

        dest_p = Path(dest_filepath).resolve()
        dest_p.parent.mkdir(parents=True, exist_ok=True)
        partial = dest_p.parent / f".{dest_p.name}.{os.urandom(4).hex()}.part"
        digest = hashlib.sha256()
        size = 0
        try:
            with open(partial, "wb") as df:
                for chunk in CustomVaultEngine.iter_file_chunks(vault_path, auth_info, target_entry):
                    if should_cancel and should_cancel():
                        raise CustomVaultError("İşlem iptal edildi.")
                    digest.update(chunk)
                    df.write(chunk)
                    size += len(chunk)
                    if on_bytes:
                        on_bytes(len(chunk))
            if digest.hexdigest() != target_entry["sha256"]:
                raise VaultTamperedError(f"Bütünlük uyuşmazlığı! Dosya bozulmuş: {target_entry['path']}")
            os.replace(str(partial), str(dest_p))
        except BaseException:
            secure_wipe_file(str(partial))
            raise

        try:
            mtime = target_entry.get("mtime", int(time.time()))
            os.utime(dest_p, (mtime, mtime))
        except Exception:
            pass

        return {
            "success": True,
            "path": str(dest_p),
            "size": size,
            "sha256": target_entry["sha256"]
        }

    @staticmethod
    def extract_to_temp_for_viewing(
        vault_path: str,
        auth_info: Dict[str, Any],
        file_id: str
    ) -> Tuple[str, Dict[str, Any]]:
        """
        Dosyayı güvenli bir geçici klasöre çıkartır.
        (Dosya yolu, dosya bilgisi) döndürür.
        """
        catalog = CustomVaultEngine.load_catalog(vault_path, auth_info)
        target_entry = None
        for item in catalog.get("files", []):
            if item["id"] == file_id or item["path"] == file_id:
                target_entry = item
                break

        if not target_entry:
            raise CustomVaultError("Dosya bulunamadı.")

        temp_dir = Path(tempfile.mkdtemp(prefix="pvault_view_", dir=secure_temp_root()))
        file_name = Path(target_entry["path"]).name
        dest_file = temp_dir / file_name

        CustomVaultEngine.extract_file(vault_path, auth_info, target_entry["id"], str(dest_file))

        if sys.platform == "win32":
            try:
                zone_path = str(dest_file) + ":Zone.Identifier"
                with open(zone_path, "w", encoding="utf-8") as zf:
                    zf.write("[ZoneTransfer]\nZoneId=3\nReferrerUrl=about:internet\nHostUrl=about:internet\n")
            except Exception:
                pass

        return str(dest_file), target_entry

    @staticmethod
    def delete_file(
        vault_path: str,
        auth_info: Dict[str, Any],
        file_id: str
    ) -> Dict[str, Any]:
        """
        Dosyayı katalogdan kaldırır ve güncellenmiş kataloğu kaydeder.
        """
        catalog = CustomVaultEngine.load_catalog(vault_path, auth_info)

        target_entry = None
        for f in catalog.get("files", []):
            if f["id"] == file_id or f["path"] == file_id:
                target_entry = f
                break

        if not target_entry:
            raise CustomVaultError("Silinecek dosya bulunamadı.")

        catalog["files"] = [f for f in catalog.get("files", []) if f["id"] != target_entry["id"]]
        CustomVaultEngine._release_entries(catalog, [target_entry])
        CustomVaultEngine._save_catalog(vault_path, auth_info, catalog)
        return {"success": True, "remaining_files": len(catalog["files"])}

    @staticmethod
    def _release_entries(catalog: Dict[str, Any], entries: List[Dict[str, Any]]) -> None:
        """
        Silinen dosyaların alanını işaretler. Eski katalog bu alanları hâlâ gösterdiği için alan,
        yeni katalog kaydedilene kadar yeniden kullanılmaz; sıfırlama da kayıttan sonra yapılır.
        """
        catalog.setdefault("_zero", []).extend([e["offset"], e["len"]] for e in entries)

    @staticmethod
    def _path_exists(catalog: Dict[str, Any], path: str) -> bool:
        return path in catalog.get("folders", []) or any(f.get("path") == path for f in catalog.get("files", []))

    @staticmethod
    def add_folder(
        vault_path: str,
        auth_info: Dict[str, Any],
        folder_rel_path: str
    ) -> Dict[str, Any]:
        """Kasa içerisine boş bir sanal klasör ekler."""
        try:
            clean_path = _sanitize_vault_rel_path(folder_rel_path)
        except CustomVaultError as e:
            return {"success": False, "error": str(e)}
        catalog = CustomVaultEngine.load_catalog(vault_path, auth_info)
        folders = catalog.setdefault("folders", [])
        if clean_path not in folders:
            folders.append(clean_path)
            folders.sort()
            CustomVaultEngine._save_catalog(vault_path, auth_info, catalog)
        return {"success": True, "path": clean_path}

    @staticmethod
    def rename_file(
        vault_path: str,
        auth_info: Dict[str, Any],
        file_id: str,
        new_rel_path: str
    ) -> Dict[str, Any]:
        """Kasadaki bir dosyanın sanal yolunu ve adını günceller."""
        clean_new = _sanitize_vault_rel_path(new_rel_path)
        catalog = CustomVaultEngine.load_catalog(vault_path, auth_info)
        if CustomVaultEngine._path_exists(catalog, clean_new):
            raise CustomVaultError(f"Bu adda bir öğe zaten var: {clean_new}")
        found = False
        for item in catalog.get("files", []):
            if item["id"] == file_id or item["path"] == file_id:
                item["path"] = clean_new
                found = True
                break
        if not found:
            raise CustomVaultError("Yeniden adlandırılacak dosya bulunamadı.")
        CustomVaultEngine._save_catalog(vault_path, auth_info, catalog)
        return {"success": True, "new_path": clean_new}

    @staticmethod
    def rename_folder(
        vault_path: str,
        auth_info: Dict[str, Any],
        old_folder_path: str,
        new_folder_path: str
    ) -> Dict[str, Any]:
        """Kasadaki bir klasörü ve altındaki tüm dosyaların yollarını günceller."""
        old_p = old_folder_path.replace("\\", "/").strip("/ ")
        new_p = _sanitize_vault_rel_path(new_folder_path.replace("\\", "/").strip("/ "))
        if not old_p:
            raise CustomVaultError("Geçersiz klasör yolu.")
        if new_p == old_p or new_p.startswith(old_p + "/"):
            raise CustomVaultError("Klasör kendi içine taşınamaz.")
        catalog = CustomVaultEngine.load_catalog(vault_path, auth_info)
        if CustomVaultEngine._path_exists(catalog, new_p):
            raise CustomVaultError(f"Bu adda bir öğe zaten var: {new_p}")

        for item in catalog.get("files", []):
            p = item.get("path", "")
            if p == old_p:
                item["path"] = new_p
            elif p.startswith(old_p + "/"):
                item["path"] = new_p + "/" + p[len(old_p) + 1:]

        folders = catalog.setdefault("folders", [])
        new_folders = []
        for f in folders:
            if f == old_p:
                new_folders.append(new_p)
            elif f.startswith(old_p + "/"):
                new_folders.append(new_p + "/" + f[len(old_p) + 1:])
            else:
                new_folders.append(f)
        if new_p not in new_folders:
            new_folders.append(new_p)
        catalog["folders"] = sorted(list(set(new_folders)))

        CustomVaultEngine._save_catalog(vault_path, auth_info, catalog)
        return {"success": True, "old_path": old_p, "new_path": new_p}

    @staticmethod
    def delete_folder(
        vault_path: str,
        auth_info: Dict[str, Any],
        folder_path: str
    ) -> Dict[str, Any]:
        """Kasadaki bir klasörü ve altındaki tüm dosyaları siler."""
        clean_p = folder_path.replace("\\", "/").strip("/ ")
        catalog = CustomVaultEngine.load_catalog(vault_path, auth_info)

        prefix = clean_p + "/"
        removed = [
            f for f in catalog.get("files", [])
            if f.get("path") == clean_p or f.get("path", "").startswith(prefix)
        ]
        removed_ids = {f["id"] for f in removed}
        catalog["files"] = [f for f in catalog.get("files", []) if f["id"] not in removed_ids]
        CustomVaultEngine._release_entries(catalog, removed)

        folders = catalog.setdefault("folders", [])
        catalog["folders"] = [
            f for f in folders
            if f != clean_p and not f.startswith(prefix)
        ]

        CustomVaultEngine._save_catalog(vault_path, auth_info, catalog)
        return {"success": True, "remaining_files": len(catalog["files"])}

    @staticmethod
    def compact_vault(
        vault_path: str,
        auth_info: Dict[str, Any],
        discard_other_compartment: bool = False
    ) -> Dict[str, Any]:
        """
        Silinmiş dosyaların kapladığı boş alanı tamamen temizler, yalnızca
        aktif dosyaları peş peşe yeniden paketleyerek dosya boyutunu küçültür.

        Yeni dosya yalnızca açık bölmenin verisini içerir; dosyada başka bir parolayla açılan bölme varsa
        KALICI OLARAK SİLİNİR. Bir bölme diğerinin varlığını bilemez, bu yüzden çağıran bunu
        discard_other_compartment=True ile açıkça kabul etmelidir.
        """
        if auth_info.get("is_decoy"):
            raise CustomVaultError("Tuzak kasa oturumundayken gizli verilerin güvenliği ve bütünlüğü için kasa sıkıştırma / birleştirme yapılamaz.")

        if not discard_other_compartment:
            raise CustomVaultError("Sıkıştırma başka bir parolayla açılan bölmeyi siler; işlem açıkça onaylanmalıdır.")

        vault_p = Path(vault_path)
        catalog = CustomVaultEngine.load_catalog(vault_path, auth_info)
        if not catalog.get("is_dynamic", True):
            raise CustomVaultError("Sabit boyutlu kasalarda Plausible Deniability güvenliğini korumak için sıkıştırma yapılamaz.")

        active_files = catalog.get("files", [])

        temp_v = vault_p.parent / f".compact_{vault_p.name}_{os.urandom(4).hex()}"

        with open(vault_p, "rb") as old_f, open(temp_v, "wb") as new_f:
            old_f.seek(0)
            header_bytes = bytearray(old_f.read(HEADER_TOTAL_SIZE))
            new_f.write(header_bytes)

            new_entries = []
            CHUNK_SIZE = 4 * 1024 * 1024
            for item in active_files:
                old_f.seek(item["offset"])
                new_offset = new_f.tell()
                remaining = item["len"]
                while remaining > 0:
                    chunk = old_f.read(min(remaining, CHUNK_SIZE))
                    if not chunk:
                        break
                    new_f.write(chunk)
                    remaining -= len(chunk)

                new_item = dict(item)
                new_item["offset"] = new_offset
                new_entries.append(new_item)

            catalog["files"] = new_entries
            catalog["updated_at"] = int(time.time())
            catalog["free"] = []
            catalog.pop("toc_extent", None)
            catalog.pop("_zero", None)

            new_toc_offset = new_f.tell()
            new_toc_cipher, new_toc_nonce = CustomVaultEngine._seal_catalog(auth_info, catalog)
            new_f.write(new_toc_cipher)
            new_toc_len = len(new_toc_cipher)

            slot_start, new_slot_block = CustomVaultEngine._seal_slot(
                auth_info, new_toc_offset, new_toc_len, new_toc_nonce
            )
            header_bytes[slot_start:slot_start + len(new_slot_block)] = new_slot_block
            new_f.seek(0)
            new_f.write(header_bytes)

            new_f.flush()
            os.fsync(new_f.fileno())

        old_size = vault_p.stat().st_size
        new_size = temp_v.stat().st_size

        os.replace(str(temp_v), str(vault_p))

        auth_info["toc_offset"] = new_toc_offset
        auth_info["toc_len"] = new_toc_len
        auth_info["toc_nonce"] = new_toc_nonce

        return {
            "success": True,
            "old_size": old_size,
            "new_size": new_size,
            "saved_bytes": max(0, old_size - new_size)
        }

    @staticmethod
    def verify_header(vault_path: str) -> Dict[str, Any]:
        """
        Kasa başlığının bütünlüğünü ve imzasını denetler.
        Başlık bozuksa hasarlı olduğunu ve nedenini bildirir.
        """
        p = Path(vault_path)
        if not p.exists() or not p.is_file():
            return {"valid": False, "error": "Kasa dosyası bulunamadı."}

        file_size = p.stat().st_size
        if file_size < HEADER_TOTAL_SIZE:
            return {
                "valid": False,
                "error": f"Kasa dosyası boyutu ({file_size} bayt) minimum başlık boyutundan ({HEADER_TOTAL_SIZE} bayt) küçük. Başlık hasarlı!"
            }

        with open(p, "rb") as f:
            header_bytes = f.read(HEADER_TOTAL_SIZE)

        if len(header_bytes) < HEADER_TOTAL_SIZE:
            return {"valid": False, "error": "Kasa başlığı okunamadı veya dosya kesintiye uğramış."}

        magic = header_bytes[:8]
        if magic != MAGIC_HEADER:
            return {
                "valid": False,
                "error": f"Geçersiz başlık imzası (Magic: {magic!r}). Başlık zarar görmüş veya dosya PVAULT formatında değil!"
            }

        version = struct.unpack("<I", header_bytes[8:12])[0]
        if version not in SUPPORTED_VERSIONS:
            return {"valid": False, "error": f"Desteklenmeyen kasa sürümü: {version}"}

        header_sha = hashlib.sha256(header_bytes).hexdigest()
        return {
            "valid": True,
            "header_size": HEADER_TOTAL_SIZE,
            "header_sha256": header_sha,
            "file_size": file_size,
            "version": version
        }

    @staticmethod
    def export_header_backup(
        vault_path: str,
        backup_path: str,
        backup_password: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Kasanın kritik 256 baytlık başlık ve anahtar yuvalarını (Slots) ayrılmış bir yedek dosyasına (.vheader / .key) aktarır.
        Başlık, kataloğun o anki konumunu tutar: kasa değiştikçe yedek eskir, her değişiklikten sonra yeniden alınmalıdır.
        - backup_password verilirse: AES-256-GCM + PBKDF2 (600,000 tur) ile parola korumalı şifreler.
        - backup_password verilmezse: Cryptographic AEAD doğrulama etiketi ve SHA-256 sağlama ile tahrifata karşı mühürler.
        """
        v_path = Path(vault_path).resolve()
        if not v_path.exists() or not v_path.is_file():
            raise CustomVaultError("Kasa dosyası bulunamadı.")

        if v_path.stat().st_size < HEADER_TOTAL_SIZE:
            raise CustomVaultError("Kasa dosyası başlık okumak için çok küçük veya hasarlı.")

        with open(v_path, "rb") as f:
            header_bytes = f.read(HEADER_TOTAL_SIZE)

        magic = header_bytes[:8]
        if magic != MAGIC_HEADER:
            raise CustomVaultError("Bu dosya geçerli bir PVAULT kasa başlığı içermiyor.")

        header_sha256 = hashlib.sha256(header_bytes).hexdigest()
        salt = os.urandom(SALT_SIZE)
        nonce = os.urandom(12)

        is_protected = bool(backup_password and len(backup_password.strip()) > 0)
        mode = 1 if is_protected else 0

        if is_protected:
            enc_key = _derive_key(backup_password.strip(), salt)
        else:
            domain_salt = b"VAULT_PRO_DETACHED_HEADER_BACKUP_INTEGRITY_SALT_2026"
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000
            )
            enc_key = kdf.derive(domain_salt)

        payload_dict = {
            "magic_header": "PVAULT01",
            "version": VERSION,
            "header_b64": base64.b64encode(header_bytes).decode("ascii"),
            "header_sha256": header_sha256,
            "header_size": len(header_bytes),
            "vault_filename": v_path.name,
            "vault_size": v_path.stat().st_size,
            "created_at": int(time.time()),
            "mode": mode
        }
        payload_bytes = zlib.compress(json.dumps(payload_dict).encode("utf-8"), level=9)
        ad = b"PVAULT_DETACHED_HEADER_BACKUP_V1"
        cipher = AESGCM(enc_key).encrypt(nonce, payload_bytes, ad)

        b_path = Path(backup_path).resolve()
        b_path.parent.mkdir(parents=True, exist_ok=True)

        header_block = (
            HEADER_BACKUP_MAGIC +
            struct.pack("<III", HEADER_BACKUP_VERSION, mode, len(cipher)) +
            salt +
            nonce
        )

        temp_bak = b_path.parent / f".tmp_bak_{os.urandom(4).hex()}"
        try:
            with open(temp_bak, "wb") as bf:
                bf.write(header_block)
                bf.write(cipher)
                bf.flush()
                os.fsync(bf.fileno())
            os.replace(str(temp_bak), str(b_path))
        except Exception as e:
            if temp_bak.exists():
                temp_bak.unlink(missing_ok=True)
            raise CustomVaultError(f"Başlık yedeği yazılamadı: {e}")

        return {
            "success": True,
            "backup_path": str(b_path),
            "vault_filename": v_path.name,
            "header_sha256": header_sha256,
            "is_protected": is_protected,
            "mode": mode,
            "backup_size": b_path.stat().st_size
        }

    @staticmethod
    def inspect_header_backup(
        backup_path: str,
        backup_password: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Ayrılmış başlık yedeğini (.vheader / .key) inceler, bütünlüğünü doğrular ve metaverilerini döndürür.
        """
        b_path = Path(backup_path)
        if not b_path.exists() or not b_path.is_file():
            return {"valid": False, "error": "Başlık yedek dosyası bulunamadı."}

        file_size = b_path.stat().st_size
        min_size = 16 + 12 + SALT_SIZE + 12 + 16
        if file_size < min_size:
            return {"valid": False, "error": "Yedek dosyası geçersiz veya hasarlı (Çok küçük)."}

        with open(b_path, "rb") as bf:
            data = bf.read()

        magic = data[:16]
        if magic != HEADER_BACKUP_MAGIC:
            return {"valid": False, "error": "Geçersiz başlık yedeği imzası (PVAULT_HDR_BAK formatı bekleniyor)."}

        version, mode, cipher_len = struct.unpack("<III", data[16:28])
        if version != HEADER_BACKUP_VERSION:
            return {"valid": False, "error": f"Desteklenmeyen yedek versiyonu: {version}"}

        if cipher_len < 16 or cipher_len > 10 * 1024 * 1024:
            return {"valid": False, "error": "Yedek dosyası hasarlı veya boyut sınırları dışı."}

        salt = data[28:28 + SALT_SIZE]
        nonce_start = 28 + SALT_SIZE
        nonce = data[nonce_start:nonce_start + 12]
        cipher_start = nonce_start + 12
        cipher = data[cipher_start:cipher_start + cipher_len]

        if len(cipher) != cipher_len:
            return {"valid": False, "error": "Yedek dosyası eksik veya kesilmiş."}

        is_protected = (mode == 1)
        if is_protected:
            if not backup_password:
                return {
                    "valid": False,
                    "requires_password": True,
                    "is_protected": True,
                    "error": "Bu başlık yedeği parola korumalıdır. Parola gereklidir."
                }
            enc_key = _derive_key(backup_password.strip(), salt)
        else:
            domain_salt = b"VAULT_PRO_DETACHED_HEADER_BACKUP_INTEGRITY_SALT_2026"
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000
            )
            enc_key = kdf.derive(domain_salt)

        try:
            ad = b"PVAULT_DETACHED_HEADER_BACKUP_V1"
            payload_bytes = AESGCM(enc_key).decrypt(nonce, cipher, ad)
            payload_dict = json.loads(zlib.decompress(payload_bytes).decode("utf-8"))
        except InvalidTag:
            if is_protected:
                return {
                    "valid": False,
                    "requires_password": True,
                    "is_protected": True,
                    "error": "Yedek parolası hatalı veya dosya tahrif edilmiş (AEAD Tag Hatası)!"
                }
            return {"valid": False, "error": "Yedek dosyası bütünlük doğrulaması başarısız (Dosya tahrif edilmiş)!"}
        except Exception as e:
            return {"valid": False, "error": f"Yedek verisi çözülemedi: {e}"}

        raw_header = base64.b64decode(payload_dict.get("header_b64", "").encode("ascii"))
        calc_sha = hashlib.sha256(raw_header).hexdigest()
        if calc_sha != payload_dict.get("header_sha256"):
            return {"valid": False, "error": "Başlık verisi SHA-256 sağlama uyuşmazlığı!"}

        return {
            "valid": True,
            "requires_password": False,
            "is_protected": is_protected,
            "header_sha256": calc_sha,
            "header_size": len(raw_header),
            "vault_filename": payload_dict.get("vault_filename"),
            "vault_size": payload_dict.get("vault_size"),
            "created_at": payload_dict.get("created_at"),
            "raw_header_bytes": raw_header
        }

    @staticmethod
    def restore_header_backup(
        vault_path: str,
        backup_path: str,
        backup_password: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Hasar görmüş bir kasa konteynerine (.pvault) ayrılmış başlık yedeğini (.vheader) güvenle enjekte eder.
        Dosyanın ilk 256 baytını orijinal sağlam başlıkla atomik olarak onarır.
        """
        insp = CustomVaultEngine.inspect_header_backup(backup_path, backup_password)
        if not insp.get("valid"):
            err = insp.get("error", "Geçersiz başlık yedeği.")
            if insp.get("requires_password"):
                raise InvalidPasswordError(err)
            raise CustomVaultError(err)

        raw_header = insp["raw_header_bytes"]
        if len(raw_header) != HEADER_TOTAL_SIZE or raw_header[:8] != MAGIC_HEADER:
            raise CustomVaultError("Yedekten çıkarılan başlık verisi geçersiz.")

        v_path = Path(vault_path).resolve()
        if not v_path.exists() or not v_path.is_file():
            raise CustomVaultError("Hedef kasa dosyası bulunamadı.")

        with open(v_path, "r+b") as vf:
            vf.seek(0)
            vf.write(raw_header)
            vf.flush()
            os.fsync(vf.fileno())

        verify_res = CustomVaultEngine.verify_header(str(v_path))
        if not verify_res.get("valid"):
            raise CustomVaultError(f"Başlık geri yüklendi ancak doğrulama başarısız oldu: {verify_res.get('error')}")

        return {
            "success": True,
            "vault_path": str(v_path),
            "header_sha256": insp["header_sha256"],
            "restored_bytes": len(raw_header),
            "vault_filename": insp.get("vault_filename")
        }

    @staticmethod
    def read_header_flags(vault_path: str) -> int:
        """Kasa basligindaki 2FA bayraklarini sifre sormadan okur."""
        p = Path(vault_path)
        if not p.exists() or not p.is_file() or p.stat().st_size < HEADER_TOTAL_SIZE:
            return 0
        try:
            with open(p, "rb") as f:
                f.seek(HEADER_FLAGS_OFFSET)
                marker = f.read(2)
                if marker == HEADER_2FA_MARKER:
                    flags_b = f.read(1)
                    if flags_b:
                        return flags_b[0]
        except Exception:
            pass
        return 0

    @staticmethod
    def set_header_flags(vault_path: str, flags: int):
        """Kasa basligindaki 2FA bayraklarini atomik olarak gunceller."""
        p = Path(vault_path)
        if not p.exists() or not p.is_file() or p.stat().st_size < HEADER_TOTAL_SIZE:
            return
        try:
            with open(p, "r+b") as f:
                f.seek(HEADER_FLAGS_OFFSET)
                if flags & FLAG_2FA_ENFORCED:
                    f.write(HEADER_2FA_MARKER + struct.pack("B", flags & 0xFF))
                else:
                    f.write(b"\x00\x00\x00")
                f.flush()
                try:
                    os.fsync(f.fileno())
                except Exception:
                    pass
        except Exception:
            pass

    @staticmethod
    def is_vault_2fa_enforced(vault_path: str) -> bool:
        """Kasanin basliginda veya yerel kayitlarda 2FA zorunlulugu olup olmadigini denetler."""
        if not vault_path:
            return False
        flags = CustomVaultEngine.read_header_flags(vault_path)
        if flags & FLAG_2FA_ENFORCED:
            return True
        try:
            import windows_hello
            return windows_hello.is_vault_2fa_enabled(vault_path)
        except Exception:
            return False

    @staticmethod
    def get_vault_2fa_config(vault_path: str, auth_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Kasanin sifreli katalogundaki 2FA (TOTP) yapilandirmasini dondurur."""
        catalog = CustomVaultEngine.load_catalog(vault_path, auth_info)
        return catalog.get("two_factor")

    @staticmethod
    def set_vault_2fa_config(
        vault_path: str,
        auth_info: Dict[str, Any],
        enabled: bool,
        totp_secret: Optional[str] = None,
        backup_codes: Optional[List[str]] = None
    ) -> bool:
        """
        Kasa kataloguna TOTP 2FA ayarlarini atomik olarak muhurler veya kaldirir.
        Basliktaki 2FA bayragini da es zamanli gunceller.
        """
        catalog = CustomVaultEngine.load_catalog(vault_path, auth_info)
        if enabled:
            if not totp_secret:
                raise CustomVaultError("2FA etkinlestirmek icin gecerli bir TOTP gizli anahtari gereklidir.")
            hashed_backups = []
            if backup_codes:
                import totp_engine
                hashed_backups = [totp_engine.hash_backup_code(c) for c in backup_codes]

            catalog["two_factor"] = {
                "enabled": True,
                "type": "totp",
                "secret": totp_secret.strip().replace(" ", "").upper(),
                "backup_codes": hashed_backups,
                "created_at": int(time.time())
            }
            CustomVaultEngine._save_catalog(vault_path, auth_info, catalog)
            if auth_info.get("version", LEGACY_VERSION) == LEGACY_VERSION:
                CustomVaultEngine.set_header_flags(vault_path, FLAG_2FA_ENFORCED | FLAG_2FA_TOTP)
        else:
            catalog.pop("two_factor", None)
            CustomVaultEngine._save_catalog(vault_path, auth_info, catalog)
            CustomVaultEngine.set_header_flags(vault_path, 0)

        try:
            import windows_hello
            windows_hello.set_vault_2fa_enabled(vault_path, enabled)
        except Exception:
            pass

        return True

    @staticmethod
    def verify_vault_2fa(
        vault_path: str,
        auth_info: Dict[str, Any],
        code: str
    ) -> Tuple[bool, str]:
        """
        Kullanicinin girdigi 6 haneli TOTP kodunu veya acil durum kurtarma kodunu dogrular.
        Kurtarma kodu kullanilmissa listeden tuketir ve katalogu gunceller.
        """
        catalog = CustomVaultEngine.load_catalog(vault_path, auth_info)
        two_factor = catalog.get("two_factor")
        if not two_factor or not two_factor.get("enabled"):
            return True, "2FA bu kasada aktif degil"

        import totp_engine
        secret = two_factor.get("secret", "")
        clean_code = code.strip().replace(" ", "").replace("-", "")

        if len(clean_code) == 6 and clean_code.isdigit():
            step = totp_engine.matching_step(secret, clean_code)
            if step is not None:
                if step <= two_factor.get("last_step", -1):
                    return False, "Bu kod zaten kullanildi, yeni kodu bekleyin"
                two_factor["last_step"] = step
                catalog["two_factor"] = two_factor
                CustomVaultEngine._save_catalog(vault_path, auth_info, catalog)
                return True, "TOTP dogrulandi"

        hashed_backups = two_factor.get("backup_codes", [])
        if hashed_backups:
            ok, remaining = totp_engine.verify_and_consume_backup_code(clean_code, hashed_backups)
            if ok:
                two_factor["backup_codes"] = remaining
                catalog["two_factor"] = two_factor
                CustomVaultEngine._save_catalog(vault_path, auth_info, catalog)
                return True, f"Kurtarma kodu kabul edildi ({len(remaining)} adet kaldi)"

        return False, "Dogrulama kodu veya kurtarma kodu gecersiz"

