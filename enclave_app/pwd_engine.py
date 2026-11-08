"""Enclave - Entegre Şifre Yöneticisi Çekirdek Motoru (Password Engine).

Argon2id/HKDF-SHA256 tabanlı alt anahtar türetimi, AES-256-GCM AEAD şifreleme,
tuzak kasa (decoy) izolasyonu, dahili TOTP üretimi, parola üreteci ve güvenlik denetimi.
"""

import base64
import json
import math
import os
import secrets
import string
import time
import uuid
import zlib
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .i18n import tr

ENTRY_TYPES = ("login", "card", "note", "key", "identity", "server")

TYPE_LABELS = {
    "login": "Giriş Bilgisi",
    "card": "Kredi / Banka Kartı",
    "note": "Güvenli Not",
    "key": "SSH / API Anahtarı",
    "identity": "Kimlik Bilgisi",
    "server": "Sunucu / RDP",
}

TYPE_ICONS = {
    "login": "globe",
    "card": "card",
    "note": "document",
    "key": "key",
    "identity": "user",
    "server": "server",
}

MAGIC_HEADER = b"VPWD"
AAD_TAG = b"VAULT_PASSWORDS_V1"

PASSPHRASE_WORDS = [
    "kalkan", "kartal", "kaplan", "deniz", "yildiz", "gunes", "orman", "ruzgar",
    "simsek", "toprak", "nehir", "volkan", "kristal", "pusula", "fener", "safir",
    "merkur", "jupiter", "galaksi", "atom", "matris", "vektor", "kuantum", "siber",
    "zenit", "zirve", "kaya", "cınar", "kutup", "atlas", "yagmur", "safak",
    "gece", "golge", "efsane", "anıt", "dalga", "cehennem", "cennet", "hazine",
    "kripto", "kale", "zırh", "sancak", "yolcu", "gezgin", "ufuk", "kanyon"
]

@dataclass
class PasswordEntry:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    type: str = "login"
    title: str = ""
    username: str = ""
    password: str = ""
    url: str = ""
    totp_secret: str = ""
    notes: str = ""
    tags: List[str] = field(default_factory=list)
    favorite: bool = False
    custom_fields: List[Dict[str, Any]] = field(default_factory=list)
    password_history: List[Dict[str, Any]] = field(default_factory=list)
    created_at: int = field(default_factory=lambda: int(time.time()))
    updated_at: int = field(default_factory=lambda: int(time.time()))
    deleted: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PasswordEntry":
        clean = dict(data)
        valid_keys = {
            "id", "type", "title", "username", "password", "url", "totp_secret",
            "notes", "tags", "favorite", "custom_fields", "password_history",
            "created_at", "updated_at", "deleted"
        }
        filtered = {k: v for k, v in clean.items() if k in valid_keys}
        return cls(**filtered)

def derive_password_subkey(master_key: bytes, salt: bytes) -> bytes:
    """Master anahtardan bağımsız, izole parola yöneticisi alt anahtarı türetir."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt or b"Enclave_Salt_Fallback_32B",
        info=b"Enclave_PasswordStore_v1"
    )
    return hkdf.derive(master_key)

def encrypt_payload(data: dict, subkey: bytes) -> bytes:
    """Veritabanını zlib ile sıkıştırır ve AES-256-GCM ile mühürler."""
    payload_json = json.dumps(data, ensure_ascii=False).encode("utf-8")
    compressed = zlib.compress(payload_json, level=6)
    nonce = os.urandom(12)
    ciphertext = AESGCM(subkey).encrypt(nonce, compressed, AAD_TAG)
    return MAGIC_HEADER + nonce + ciphertext

def decrypt_payload(payload: bytes, subkey: bytes) -> dict:
    """Şifreli veritabanı paketini çözer ve doğrular."""
    if len(payload) < len(MAGIC_HEADER) + 12 + 16 or not payload.startswith(MAGIC_HEADER):
        raise ValueError(tr("Geçersiz şifre veritabanı biçimi."))
    nonce = payload[len(MAGIC_HEADER):len(MAGIC_HEADER) + 12]
    ciphertext = payload[len(MAGIC_HEADER) + 12:]
    try:
        compressed = AESGCM(subkey).decrypt(nonce, ciphertext, AAD_TAG)
    except Exception as e:
        raise ValueError(tr("Şifre veritabanı çözülemedi veya anahtar hatalı.")) from e
    raw = zlib.decompress(compressed)
    return json.loads(raw.decode("utf-8"))

def generate_password(
    length: int = 16,
    uppercase: bool = True,
    lowercase: bool = True,
    numbers: bool = True,
    symbols: bool = True,
    avoid_ambiguous: bool = True,
    passphrase_mode: bool = False,
    word_count: int = 4,
    separator: str = "-",
    **kwargs
) -> str:
    """Kriptografik olarak güvenli rastgele parola veya parola öbeği üretir."""
    if "passphrase" in kwargs:
        passphrase_mode = kwargs["passphrase"]
    if "use_lower" in kwargs:
        lowercase = kwargs["use_lower"]
    if "use_upper" in kwargs:
        uppercase = kwargs["use_upper"]
    if "use_digits" in kwargs:
        numbers = kwargs["use_digits"]
    if "use_symbols" in kwargs:
        symbols = kwargs["use_symbols"]
    if "separator" in kwargs:
        separator = kwargs["separator"]

    if passphrase_mode:
        count = max(2, min(8, word_count))
        chosen = [secrets.choice(PASSPHRASE_WORDS) for _ in range(count)]
        return separator.join(chosen)

    length = max(4, min(128, length))
    pool = ""
    uppers = "ABCDEFGHJKLMNPQRSTUVWXYZ" if avoid_ambiguous else string.ascii_uppercase
    lowers = "abcdefghjkmnpqrstuvwxyz" if avoid_ambiguous else string.ascii_lowercase
    digits = "23456789" if avoid_ambiguous else string.digits
    syms = "!@#$%^&*()-_=+[]{}<>?"

    required = []
    if uppercase:
        pool += uppers
        required.append(secrets.choice(uppers))
    if lowercase:
        pool += lowers
        required.append(secrets.choice(lowers))
    if numbers:
        pool += digits
        required.append(secrets.choice(digits))
    if symbols:
        pool += syms
        required.append(secrets.choice(syms))

    if not pool:
        pool = lowers + digits
        required.append(secrets.choice(lowers))

    remaining = length - len(required)
    chosen = [secrets.choice(pool) for _ in range(max(0, remaining))] + required
    for i in range(len(chosen) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        chosen[i], chosen[j] = chosen[j], chosen[i]

    return "".join(chosen)

def evaluate_password(password: str) -> Tuple[int, str]:
    """
    Parola gücünü 0-4 arasında derecelendirir ve açıklayıcı etiket döndürür.
    0: Çok Zayıf, 1: Zayıf, 2: Orta, 3: Güçlü, 4: Çok Güçlü
    """
    if not password:
        return 0, tr("Boş")
    length = len(password)
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_sym = any(not c.isalnum() for c in password)

    variety = sum([has_lower, has_upper, has_digit, has_sym])

    score = 0
    if length >= 8:
        score += 1
    if length >= 12 and variety >= 3:
        score += 1
    if length >= 16 and variety >= 3:
        score += 1
    if length >= 20 and variety == 4:
        score += 1

    labels = {
        0: tr("Çok Zayıf"),
        1: tr("Zayıf"),
        2: tr("Orta"),
        3: tr("Güçlü"),
        4: tr("Çok Güçlü"),
    }
    return score, labels[score]

def get_live_totp(secret: str) -> Tuple[str, int, float]:
    """
    Dahili TOTP kodu üretir: (6 haneli kod, kalan saniye, ilerleme oranı 0.0 - 1.0).
    Hata durumunda ("", 0, 0.0) döner.
    """
    if not secret:
        return "", 0, 0.0
    import totp_engine
    now = int(time.time())
    remaining = 30 - (now % 30)
    progress = remaining / 30.0
    try:
        token = totp_engine.get_totp_token(secret.strip().replace(" ", "").upper())
        return token, remaining, progress
    except Exception:
        return "", 0, 0.0

class PasswordStore:
    """
    Şifreli oturumla entegre, RAM-Only korumalı şifre deposu.
    Kullanıcı işlemlerini yönetir, arama ve denetim sağlar.
    """

    def __init__(self, session: Any):
        self.session = session
        self.entries: Dict[str, PasswordEntry] = {}
        self._subkey: Optional[bytes] = None
        self._init_subkey()
        self.load()

    def _init_subkey(self) -> None:
        """Kasa anahtarından HKDF ile alt anahtar oluşturur."""
        auth = getattr(self.session, "auth", None)
        if auth and "master_key" in auth:
            salt = auth.get("salt", b"\x00" * 32)
            self._subkey = derive_password_subkey(auth["master_key"], salt)

    @property
    def is_unlocked(self) -> bool:
        return self._subkey is not None

    def load(self) -> None:
        """Kasa kataloğundan veya VHD dosyasından şifreli depoyu okur."""
        self.entries.clear()
        if not self._subkey:
            return

        if hasattr(self.session, "catalog"):
            store_data = self.session.catalog.get("password_store")
            if store_data and isinstance(store_data, dict):
                raw_b64 = store_data.get("payload")
                if raw_b64:
                    try:
                        raw = base64.b64decode(raw_b64)
                        plain = decrypt_payload(raw, self._subkey)
                        for item in plain.get("items", []):
                            entry = PasswordEntry.from_dict(item)
                            self.entries[entry.id] = entry
                    except Exception:
                        pass
            return

        if hasattr(self.session, "drive_letter") and self.session.drive_letter:
            meta_file = Path(self.session.drive_letter) / ".vault_meta" / "passwords.enc"
            if meta_file.is_file():
                try:
                    raw = meta_file.read_bytes()
                    plain = decrypt_payload(raw, self._subkey)
                    for item in plain.get("items", []):
                        entry = PasswordEntry.from_dict(item)
                        self.entries[entry.id] = entry
                except Exception:
                    pass

    def save(self) -> None:
        """Kayıtları şifreleyerek kasaya kaydeder."""
        if not self._subkey:
            return

        data = {
            "version": 1,
            "updated_at": int(time.time()),
            "items": [e.to_dict() for e in self.entries.values()]
        }
        encrypted = encrypt_payload(data, self._subkey)

        if hasattr(self.session, "catalog"):
            from enclave_core import CustomVaultEngine
            self.session.catalog["password_store"] = {
                "payload": base64.b64encode(encrypted).decode("ascii"),
                "updated_at": int(time.time()),
                "count": len([e for e in self.entries.values() if not e.deleted])
            }
            if hasattr(self.session, "auth") and isinstance(self.session.auth, dict) and "toc_offset" in self.session.auth:
                CustomVaultEngine._save_catalog(self.session.path, self.session.auth, self.session.catalog)
            return

        if hasattr(self.session, "drive_letter") and self.session.drive_letter:
            meta_dir = Path(self.session.drive_letter) / ".vault_meta"
            meta_dir.mkdir(parents=True, exist_ok=True)
            meta_file = meta_dir / "passwords.enc"
            meta_file.write_bytes(encrypted)

    def add(self, entry: PasswordEntry) -> PasswordEntry:
        now = int(time.time())
        entry.created_at = now
        entry.updated_at = now
        entry._saved_password = entry.password
        self.entries[entry.id] = entry
        self.save()
        return entry

    def update(self, entry: PasswordEntry) -> PasswordEntry:
        if entry.id in self.entries:
            prev_pwd = getattr(entry, "_saved_password", None)
            if prev_pwd is None:
                old = self.entries[entry.id]
                prev_pwd = old.password if old is not entry else None
            if prev_pwd and prev_pwd != entry.password:
                entry.password_history = list(entry.password_history)
                entry.password_history.insert(0, {
                    "password": prev_pwd,
                    "changed_at": int(time.time())
                })
                entry.password_history = entry.password_history[:5]
        entry._saved_password = entry.password
        entry.updated_at = int(time.time())
        self.entries[entry.id] = entry
        self.save()
        return entry

    def delete(self, entry_id: str, permanent: bool = False, soft: Optional[bool] = None) -> None:
        if entry_id not in self.entries:
            return
        if soft is not None:
            permanent = not soft
        if permanent:
            self.entries.pop(entry_id, None)
        else:
            self.entries[entry_id].deleted = True
            self.entries[entry_id].updated_at = int(time.time())
        self.save()

    def toggle_favorite(self, entry_id: str) -> bool:
        """Kayıt için favori durumunu tersine çevirir."""
        if entry_id in self.entries:
            self.entries[entry_id].favorite = not self.entries[entry_id].favorite
            self.entries[entry_id].updated_at = int(time.time())
            self.save()
            return self.entries[entry_id].favorite
        return False

    def restore(self, entry_id: str) -> None:
        if entry_id in self.entries:
            self.entries[entry_id].deleted = False
            self.entries[entry_id].updated_at = int(time.time())
            self.save()

    def get(self, entry_id: str) -> Optional[PasswordEntry]:
        return self.entries.get(entry_id)

    def all(self, include_deleted: bool = False) -> List[PasswordEntry]:
        """Tüm kayıtları liste olarak döndürür."""
        if include_deleted:
            return list(self.entries.values())
        return [e for e in self.entries.values() if not e.deleted]

    def get_all_entries(self, include_deleted: bool = False) -> List[PasswordEntry]:
        """Tüm kayıtları liste olarak döndürür."""
        return self.all(include_deleted=include_deleted)

    def clear_all(self) -> None:
        """Tüm kayıtları temizler."""
        self.entries.clear()
        self.save()

    def add_entry(self, entry: PasswordEntry) -> PasswordEntry:
        return self.add(entry)

    def list_items(
        self,
        category: Optional[str] = None,
        tag: Optional[str] = None,
        favorite_only: bool = False,
        trash_only: bool = False,
        search: str = ""
    ) -> List[PasswordEntry]:
        """Filtrelere göre kayıtları döndürür."""
        result = []
        search_lower = search.strip().lower()

        for item in self.entries.values():
            if trash_only:
                if not item.deleted:
                    continue
            else:
                if item.deleted:
                    continue
                if favorite_only and not item.favorite:
                    continue
                if category and item.type != category:
                    continue
                if tag and tag not in item.tags:
                    continue

            if search_lower:
                match = (
                    search_lower in item.title.lower() or
                    search_lower in item.username.lower() or
                    search_lower in item.url.lower() or
                    any(search_lower in t.lower() for t in item.tags)
                )
                if not match:
                    continue

            result.append(item)

        return sorted(result, key=lambda x: (not x.favorite, x.title.casefold()))

    def search(self, query: str) -> List[PasswordEntry]:
        """Arama terimine göre eşleşen kayıtları döndürür."""
        return self.list_items(search=query)

    def all_tags(self) -> List[str]:
        tags: Set[str] = set()
        for item in self.entries.values():
            if not item.deleted:
                tags.update(item.tags)
        return sorted(list(tags), key=str.casefold)

    def counts(self) -> Dict[str, int]:
        """Kategori ve filtre bazında adetleri hesaplar."""
        res: Dict[str, int] = {
            "all": 0, "total": 0, "favorite": 0, "trash": 0, "totp": 0
        }
        for t in ENTRY_TYPES:
            res[t] = 0

        for item in self.entries.values():
            if item.deleted:
                res["trash"] += 1
                continue
            res["all"] += 1
            res["total"] += 1
            if item.favorite:
                res["favorite"] += 1
            if item.totp_secret:
                res["totp"] += 1
            if item.type in res:
                res[item.type] += 1

        return res

    def audit(self) -> Dict[str, Any]:
        """Güvenlik denetimi gerçekleştirir: zayıf ve tekrar eden parolalar."""
        weak: List[PasswordEntry] = []
        pass_map: Dict[str, List[PasswordEntry]] = {}
        stale: List[PasswordEntry] = []
        now = int(time.time())
        six_months = 180 * 86400

        for item in self.entries.values():
            if item.deleted or not item.password:
                continue

            score, _ = evaluate_password(item.password)
            if score < 3:
                weak.append(item)

            pass_map.setdefault(item.password, []).append(item)

            if now - item.updated_at > six_months:
                stale.append(item)

        reused: List[PasswordEntry] = []
        for pw, items in pass_map.items():
            if len(items) > 1:
                reused.extend(items)

        return {
            "weak": weak,
            "reused": reused,
            "stale": stale,
            "total_active": len([e for e in self.entries.values() if not e.deleted])
        }

