"""
Enclave - Steganografik / Poliglot Kamuflaj Kasa Motoru (Stego & Polyglot Carrier Vault)

Geçerli bir medya dosyasının (MP4, MKV, PNG, JPG, FLAC, ISO vb.) içerisine şifreli bir kasa gizler.
Taşıyıcı dosya VLC, Windows Fotoğraflar veya standart medya oynatıcılarda normal bir dosya gibi
sorunsuz açılmaya ve oynatılmaya devam eder.

Güvenlik Modeli:
1. Başlıksız Çapa Bloğu (Headerless Anchor Block):
   Dosyanın son 512 baytı gizli çapa bloğudur. Çapa bloğunda hiçbir ASCII metin veya sihirli bayt
   (magic bytes) bulunmaz; dışarıdan bakıldığında yüksek entropili rastgele dolgu verisi gibi görünür.
2. Çift Yuvalı Tuzak Desteği (Dual-Slot Decoy Support):
   Çapa bloğu iki bağımsız yuva barındırır. Ana parola ana kasayı, tuzak parola tuzak kasayı açar.
   İkinci yuva kullanılmıyorsa rastgele gürültüyle doldurulur; dolu bir yuvadan ayırt edilemez.
3. Disk Maskelemesi (Zero Disk Signatures):
   Kasanın PVAULT başlığı disk üzerinde rastgele türetilen bir maske ile XOR'lanarak saklanır.
   Disk üzerinde hiçbir 'PVAULT' veya tanınabilir imza yer almaz (strings / yara taraması geçirimsiz).
4. Doğrudan Oynatma Uyumluluğu:
   Taşıyıcı medya dosyasının ilk baytından son geçerli akış baytına kadar tüm yapısı korunur.
"""

import os
import struct
import shutil
import unicodedata
from pathlib import Path
from typing import Optional, Dict, Any, Tuple, BinaryIO, List

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.exceptions import InvalidTag

STEGO_ANCHOR_SIZE = 512
STEGO_MAGIC = b"PSTG01\x00\x00"
STEGO_SALT_SIZE = 32
STEGO_NONCE_SIZE = 12
STEGO_PAYLOAD_SIZE = 48
STEGO_TAG_SIZE = 16
STEGO_SLOT_SIZE = STEGO_NONCE_SIZE + STEGO_PAYLOAD_SIZE + STEGO_TAG_SIZE
STEGO_SLOT_TOTAL = 88
STEGO_RESERVED_SIZE = STEGO_ANCHOR_SIZE - (STEGO_SALT_SIZE + 2 * STEGO_SLOT_TOTAL)

ARGON2_TIME_COST = 3
ARGON2_LANES = 4
ARGON2_MEMORY_COST = 256 * 1024

SUPPORTED_MEDIA_EXTENSIONS = {
    ".mp4", ".mkv", ".mov", ".avi", ".webm", ".wmv",
    ".mp3", ".flac", ".wav", ".m4a", ".aac", ".ogg",
    ".png", ".jpg", ".jpeg", ".webp", ".bmp",
    ".iso", ".zip", ".tar", ".bin", ".dat"
}

class StegoVaultError(Exception):
    """Steganografik kasa işlemlerinde oluşan temel hata sınıfı."""
    pass

def _derive_stego_key(password: str, salt: bytes, key_digest: Optional[bytes] = None) -> bytes:
    """Parola ve tuzdan Argon2id ile 32 baytlık çapa açma anahtarı türetir."""
    pw_bytes = unicodedata.normalize("NFC", password).encode("utf-8")
    kdf = Argon2id(
        salt=salt,
        length=32,
        iterations=ARGON2_TIME_COST,
        lanes=ARGON2_LANES,
        memory_cost=ARGON2_MEMORY_COST
    )
    key = kdf.derive(pw_bytes)
    if key_digest:
        import hmac, hashlib
        key = hmac.new(key, b"PVAULT_KEYFILE_V1" + key_digest, hashlib.sha256).digest()
    return key

def _seal_stego_slot(key: bytes, carrier_offset: int, header_mask: bytes, salt: bytes) -> bytes:
    """Çapa bloğu için 88 baytlık tek bir şifreli yuva üretir."""
    payload = STEGO_MAGIC + struct.pack("<Q", carrier_offset) + header_mask
    assert len(payload) == STEGO_PAYLOAD_SIZE, f"Payload {len(payload)} bayt olmalı!"
    nonce = os.urandom(STEGO_NONCE_SIZE)
    ad = b"PSTG_SLOT_V1" + salt
    cipher = AESGCM(key).encrypt(nonce, payload, ad)
    pad_len = STEGO_SLOT_TOTAL - (len(nonce) + len(cipher))
    padding = os.urandom(max(0, pad_len))
    return nonce + cipher + padding

def _open_stego_slot(
    block: bytes, key: bytes, salt: bytes
) -> Optional[Tuple[int, bytes]]:
    """88 baytlık yuvayı çözmeyi dener. Başarılıysa (carrier_offset, header_mask) döndürür; hatalıysa None."""
    if len(block) < STEGO_SLOT_TOTAL:
        return None
    nonce = block[:STEGO_NONCE_SIZE]
    cipher = block[STEGO_NONCE_SIZE:STEGO_NONCE_SIZE + STEGO_PAYLOAD_SIZE + STEGO_TAG_SIZE]
    ad = b"PSTG_SLOT_V1" + salt
    try:
        plain = AESGCM(key).decrypt(nonce, cipher, ad)
    except InvalidTag:
        return None
    if len(plain) != STEGO_PAYLOAD_SIZE:
        return None
    magic = plain[:8]
    if magic != STEGO_MAGIC:
        return None
    carrier_offset = struct.unpack("<Q", plain[8:16])[0]
    header_mask = plain[16:48]
    return carrier_offset, header_mask

def build_stego_anchor(
    carrier_offset: int,
    header_mask: bytes,
    password: str,
    decoy_password: Optional[str] = None,
    salt: Optional[bytes] = None,
    key_digest: Optional[bytes] = None
) -> bytes:
    """
    512 baytlık inkâr edilebilir çapa bloğu oluşturur.
    Hiçbir imza içermez; dışarıdan bakıldığında rastgele gürültüden ayırt edilemez.
    """
    salt = salt or os.urandom(STEGO_SALT_SIZE)
    real_key = _derive_stego_key(password, salt, key_digest)

    real_slot = _seal_stego_slot(real_key, carrier_offset, header_mask, salt)

    if decoy_password:
        decoy_key = _derive_stego_key(decoy_password, salt, key_digest)
        decoy_slot = _seal_stego_slot(decoy_key, carrier_offset, header_mask, salt)
    else:
        decoy_slot = os.urandom(STEGO_SLOT_TOTAL)

    slot1, slot2 = (real_slot, decoy_slot) if os.urandom(1)[0] % 2 == 0 else (decoy_slot, real_slot)

    reserved = os.urandom(STEGO_RESERVED_SIZE)
    anchor = salt + slot1 + slot2 + reserved
    assert len(anchor) == STEGO_ANCHOR_SIZE, f"Çapa bloğu {len(anchor)} bayt, 512 olmalı!"
    return anchor

def inspect_stego_anchor(
    vault_path: str, password: str, key_digest: Optional[bytes] = None
) -> Optional[Dict[str, Any]]:
    """
    Belirtilen dosyanın son 512 baytını okuyarak steganografik çapa olup olmadığını dener.
    Parola eşleşirse taşıyıcı ofseti ve başlık maskesini döndürür; eşleşmezse None döner.
    """
    p = Path(vault_path)
    if not p.is_file() or p.stat().st_size < STEGO_ANCHOR_SIZE + 256:
        return None

    try:
        with open(p, "rb") as f:
            f.seek(-STEGO_ANCHOR_SIZE, os.SEEK_END)
            anchor_bytes = f.read(STEGO_ANCHOR_SIZE)
    except OSError:
        return None

    if len(anchor_bytes) != STEGO_ANCHOR_SIZE:
        return None

    salt = anchor_bytes[:STEGO_SALT_SIZE]
    key = _derive_stego_key(password, salt, key_digest)

    slot1 = anchor_bytes[STEGO_SALT_SIZE:STEGO_SALT_SIZE + STEGO_SLOT_TOTAL]
    slot2 = anchor_bytes[STEGO_SALT_SIZE + STEGO_SLOT_TOTAL:STEGO_SALT_SIZE + 2 * STEGO_SLOT_TOTAL]

    for slot_idx, slot_bytes in ((1, slot1), (2, slot2)):
        result = _open_stego_slot(slot_bytes, key, salt)
        if result is not None:
            carrier_offset, header_mask = result
            file_size = p.stat().st_size
            if 0 < carrier_offset < file_size - STEGO_ANCHOR_SIZE:
                return {
                    "is_stego": True,
                    "carrier_offset": carrier_offset,
                    "header_mask": header_mask,
                    "anchor_salt": salt,
                    "matched_slot": slot_idx
                }
    return None

def mask_header_bytes(header: bytes, mask: bytes) -> bytes:
    """256 baytlık başlığı 32 baytlık maske ile XOR'lar (çift yönlüdür: maskeleme ve çözme aynıdır)."""
    assert len(mask) == 32, "Maske 32 bayt olmalıdır."
    return bytes(b ^ mask[i % 32] for i, b in enumerate(header))

def create_stego_vault(
    carrier_source_path: str,
    target_vault_path: str,
    password: str,
    max_size_gb: int = 10,
    is_dynamic: bool = True,
    decoy_password: Optional[str] = None,
    decoy_size_gb: int = 2,
    key_digest: Optional[bytes] = None
) -> Dict[str, Any]:
    """
    Mevcut bir medya dosyasını (MP4, PNG vb.) kılıf olarak kullanarak steganografik kasa oluşturur.
    Taşıyıcı dosya hedef konuma kopyalanır ve sonuna şifreli kasa ile çapa eklenir.
    """
    from enclave_core import CustomVaultEngine, CustomVaultError

    carrier_src = Path(carrier_source_path)
    if not carrier_src.is_file():
        raise StegoVaultError("Taşıyıcı medya dosyası bulunamadı.")

    carrier_size = carrier_src.stat().st_size
    if carrier_size == 0:
        raise StegoVaultError("Taşıyıcı medya dosyası boş olamaz.")

    target = Path(target_vault_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temp_target = target.parent / f".tmp_{target.name}_{os.urandom(4).hex()}"

    try:
        shutil.copyfile(str(carrier_src), str(temp_target))

        header_mask = os.urandom(32)
        carrier_offset = carrier_size

        anchor_block = build_stego_anchor(
            carrier_offset=carrier_offset,
            header_mask=header_mask,
            password=password,
            decoy_password=decoy_password,
            key_digest=key_digest
        )

        import json
        import zlib
        import time
        from enclave_core import (
            HEADER_TOTAL_SIZE, VERSION,
            KDF_ID_ARGON2ID, ARGON2_TIME_COST, ARGON2_LANES, ARGON2_MEMORY_LOG2,
            _toc_ad, _slot_ad, SLOT_NONCE_SIZE, SLOT_TOTAL_SIZE, _derive_key
        )

        has_decoy = bool(decoy_password)
        salt = os.urandom(32)
        real_master_key = os.urandom(32)
        decoy_master_key = os.urandom(32) if has_decoy else None

        real_base = carrier_offset + HEADER_TOTAL_SIZE
        now_ts = int(time.time())
        real_initial_catalog = {
            "version": VERSION,
            "created_at": now_ts,
            "updated_at": now_ts,
            "max_size_gb": max_size_gb,
            "is_dynamic": is_dynamic,
            "base_offset": real_base,
            "files": [],
            "folders": [],
            "free": []
        }

        real_auth = {
            "master_key": real_master_key,
            "version": VERSION,
            "is_decoy": False,
            "salt": salt,
            "carrier_offset": carrier_offset,
            "header_mask": header_mask
        }

        real_toc_bytes = zlib.compress(json.dumps(real_initial_catalog).encode("utf-8"), level=6)
        real_toc_nonce = os.urandom(12)
        real_toc_ad = _toc_ad(VERSION, False)
        real_toc_cipher = AESGCM(real_master_key).encrypt(real_toc_nonce, real_toc_bytes, real_toc_ad)
        real_toc_len = len(real_toc_cipher)
        real_toc_offset = real_base

        if has_decoy:
            d_bytes = decoy_size_gb * 1024 * 1024 * 1024
            decoy_base = real_base + d_bytes
            decoy_initial_catalog = {
                "version": VERSION,
                "created_at": now_ts,
                "updated_at": now_ts,
                "max_size_gb": decoy_size_gb,
                "is_dynamic": is_dynamic,
                "base_offset": decoy_base,
                "files": [],
                "folders": [],
                "free": []
            }
            decoy_toc_bytes = zlib.compress(json.dumps(decoy_initial_catalog).encode("utf-8"), level=6)
            decoy_toc_nonce = os.urandom(12)
            decoy_toc_ad = _toc_ad(VERSION, False)
            decoy_toc_cipher = AESGCM(decoy_master_key).encrypt(decoy_toc_nonce, decoy_toc_bytes, decoy_toc_ad)
            decoy_toc_len = len(decoy_toc_cipher)
            decoy_toc_offset = decoy_base if not is_dynamic else (real_toc_offset + real_toc_len)
        else:
            decoy_toc_cipher = None
            decoy_toc_len = 0
            decoy_toc_offset = 0
            decoy_toc_nonce = os.urandom(12)

        kdf_params = (ARGON2_TIME_COST, ARGON2_LANES, ARGON2_MEMORY_LOG2)
        def seal_slot(slot_pw, master_k, toc_off, toc_l, toc_non):
            payload = master_k + struct.pack("<QQ", toc_off, toc_l) + toc_non
            nonce = os.urandom(SLOT_NONCE_SIZE)
            key = _derive_key(slot_pw, salt, kdf_params)
            return nonce + AESGCM(key).encrypt(nonce, payload, _slot_ad(VERSION, 0, salt))

        real_block = seal_slot(password, real_master_key, real_toc_offset, real_toc_len, real_toc_nonce)
        other_block = seal_slot(decoy_password, decoy_master_key, decoy_toc_offset, decoy_toc_len, decoy_toc_nonce) if has_decoy else os.urandom(SLOT_TOTAL_SIZE)
        slot1_block, slot2_block = (real_block, other_block) if os.urandom(1)[0] % 2 == 0 else (other_block, real_block)

        public_header_size = decoy_size_gb if has_decoy else max_size_gb
        reserved_padding = (
            struct.pack("<I", public_header_size) + b"\x00\x00\x00" + os.urandom(25) +
            bytes((KDF_ID_ARGON2ID, ARGON2_TIME_COST, ARGON2_LANES, ARGON2_MEMORY_LOG2))
        )
        from enclave_core import MAGIC_HEADER
        raw_header = (
            MAGIC_HEADER +
            struct.pack("<I", VERSION) +
            salt +
            slot1_block +
            slot2_block +
            reserved_padding
        )
        assert len(raw_header) == HEADER_TOTAL_SIZE

        masked_header = mask_header_bytes(raw_header, header_mask)

        with open(temp_target, "r+b") as f:
            f.seek(carrier_offset)
            f.write(masked_header)
            f.write(real_toc_cipher)
            if has_decoy and decoy_toc_cipher:
                if not is_dynamic:
                    f.seek(decoy_base)
                f.write(decoy_toc_cipher)

            f.seek(0, os.SEEK_END)
            f.write(anchor_block)
            f.flush()
            os.fsync(f.fileno())

        os.replace(str(temp_target), str(target))
    except Exception as e:
        if temp_target.exists():
            temp_target.unlink(missing_ok=True)
        raise StegoVaultError(f"Kamuflaj kasa oluşturulamadı: {e}")

    return {
        "success": True,
        "path": str(target),
        "carrier_path": str(carrier_src),
        "carrier_size": carrier_size,
        "is_stego": True,
        "has_decoy": has_decoy,
        "size_bytes": target.stat().st_size
    }

def _transfer_vault_contents(
    src_path: str, src_auth: Dict[str, Any],
    dst_path: str, dst_auth: Dict[str, Any],
    on_progress: Optional[Any] = None
) -> int:
    """Bir kasadaki tüm dosya ve klasörleri diğer kasaya şifreli bellek akışıyla taşır."""
    import time
    from enclave_core import CustomVaultEngine, _ChunkReader
    src_catalog = CustomVaultEngine.load_catalog(src_path, src_auth)
    dst_catalog = CustomVaultEngine.load_catalog(dst_path, dst_auth)

    dst_catalog["folders"] = list(set(dst_catalog.get("folders", []) + src_catalog.get("folders", [])))
    src_files = list(src_catalog.get("files", []))
    total_bytes = sum(f.get("size", 0) for f in src_files) or 1
    transferred_bytes = 0
    new_entries = []

    for entry in src_files:
        chunks = CustomVaultEngine.iter_file_chunks(src_path, src_auth, entry)
        try:
            def on_chunk(bytes_written):
                nonlocal transferred_bytes
                transferred_bytes += bytes_written
                if on_progress:
                    on_progress(transferred_bytes, total_bytes)

            new_entry = CustomVaultEngine._write_stream(
                dst_path, dst_auth, dst_catalog, _ChunkReader(chunks),
                entry["size"], entry["path"], entry.get("mtime", int(time.time())),
                on_bytes=on_chunk
            )
        finally:
            chunks.close()
        new_entries.append(new_entry)
        dst_catalog["files"] = new_entries

    CustomVaultEngine._save_catalog(dst_path, dst_auth, dst_catalog)
    return len(new_entries)

def wrap_vault_into_carrier(
    source_vault_path: str,
    carrier_source_path: str,
    target_vault_path: str,
    password: str,
    decoy_password: Optional[str] = None,
    key_digest: Optional[bytes] = None,
    on_progress: Optional[Any] = None
) -> Dict[str, Any]:
    """Mevcut bir bağımsız .pvault kasasına medya kılıfı giydirerek kamuflaj kasaya dönüştürür."""
    from enclave_core import CustomVaultEngine

    src_auth = CustomVaultEngine.authenticate(source_vault_path, password, key_digest)
    if src_auth.get("is_stego"):
        raise StegoVaultError("Bu kasa zaten bir kılıf medyaya sahip.")

    src_cat = CustomVaultEngine.load_catalog(source_vault_path, src_auth)
    max_size_gb = max(1, src_cat.get("max_size_gb", 10))
    is_dynamic = src_cat.get("is_dynamic", True)

    src_decoy_auth = None
    decoy_size_gb = 2
    if decoy_password:
        try:
            src_decoy_auth = CustomVaultEngine.authenticate(source_vault_path, decoy_password, key_digest)
            decoy_cat = CustomVaultEngine.load_catalog(source_vault_path, src_decoy_auth)
            decoy_size_gb = max(1, decoy_cat.get("max_size_gb", 2))
        except Exception:
            src_decoy_auth = None

    create_stego_vault(
        carrier_source_path=carrier_source_path,
        target_vault_path=target_vault_path,
        password=password,
        max_size_gb=max_size_gb,
        is_dynamic=is_dynamic,
        decoy_password=decoy_password if src_decoy_auth else None,
        decoy_size_gb=decoy_size_gb,
        key_digest=key_digest
    )

    try:
        dst_auth = CustomVaultEngine.authenticate(target_vault_path, password, key_digest)
        count = _transfer_vault_contents(source_vault_path, src_auth, target_vault_path, dst_auth, on_progress)

        if src_decoy_auth:
            dst_decoy_auth = CustomVaultEngine.authenticate(target_vault_path, decoy_password, key_digest)
            _transfer_vault_contents(source_vault_path, src_decoy_auth, target_vault_path, dst_decoy_auth)
    except Exception as e:
        if Path(target_vault_path).exists():
            Path(target_vault_path).unlink(missing_ok=True)
        raise StegoVaultError(f"Kılıf giydirme sırasında hata: {e}")

    return {
        "success": True,
        "path": target_vault_path,
        "carrier_path": carrier_source_path,
        "files_transferred": count,
        "has_decoy": bool(src_decoy_auth)
    }

def strip_carrier_from_vault(
    stego_vault_path: str,
    target_vault_path: str,
    password: str,
    decoy_password: Optional[str] = None,
    key_digest: Optional[bytes] = None,
    on_progress: Optional[Any] = None
) -> Dict[str, Any]:
    """Kamuflaj kasadan medya kılıfını sıyırıp saf bağımsız .pvault kasasına dönüştürür."""
    from enclave_core import CustomVaultEngine

    src_auth = CustomVaultEngine.authenticate(stego_vault_path, password, key_digest)
    if not src_auth.get("is_stego"):
        raise StegoVaultError("Bu dosya bir kılıf kasa değil; kılıf çıkarılamaz.")

    src_cat = CustomVaultEngine.load_catalog(stego_vault_path, src_auth)
    max_size_gb = max(1, src_cat.get("max_size_gb", 10))
    is_dynamic = src_cat.get("is_dynamic", True)

    src_decoy_auth = None
    decoy_size_gb = 2
    if decoy_password:
        try:
            src_decoy_auth = CustomVaultEngine.authenticate(stego_vault_path, decoy_password, key_digest)
            decoy_cat = CustomVaultEngine.load_catalog(stego_vault_path, src_decoy_auth)
            decoy_size_gb = max(1, decoy_cat.get("max_size_gb", 2))
        except Exception:
            src_decoy_auth = None

    CustomVaultEngine.create_vault(
        vault_path=target_vault_path,
        password=password,
        label=Path(target_vault_path).stem,
        decoy_password=decoy_password if src_decoy_auth else None,
        max_size_gb=max_size_gb,
        is_dynamic=is_dynamic,
        decoy_size_gb=decoy_size_gb
    )

    try:
        dst_auth = CustomVaultEngine.authenticate(target_vault_path, password, key_digest)
        count = _transfer_vault_contents(stego_vault_path, src_auth, target_vault_path, dst_auth, on_progress)

        if src_decoy_auth:
            dst_decoy_auth = CustomVaultEngine.authenticate(target_vault_path, decoy_password, key_digest)
            _transfer_vault_contents(stego_vault_path, src_decoy_auth, target_vault_path, dst_decoy_auth)
    except Exception as e:
        if Path(target_vault_path).exists():
            Path(target_vault_path).unlink(missing_ok=True)
        raise StegoVaultError(f"Kılıf çıkarma sırasında hata: {e}")

    return {
        "success": True,
        "path": target_vault_path,
        "files_transferred": count,
        "has_decoy": bool(src_decoy_auth)
    }
