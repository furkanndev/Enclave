"""Enclave - Parola İçe ve Dışa Aktarma Motoru (Password Importer & Exporter).

Google Chrome, Mozilla Firefox, Bitwarden, 1Password, KeePass CSV/JSON
biçimlerini otomatik tespit edip çözer; güvenli CSV ve şifreli dışa aktarım sağlar.
"""

import csv
import io
import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from .i18n import tr
from .pwd_engine import PasswordEntry, PasswordStore

def detect_and_import_csv(content: str) -> List[PasswordEntry]:
    """Farklı tarayıcı ve yöneticilerden gelen CSV içeriğini otomatik tespit edip ayrıştırır."""
    reader = csv.reader(io.StringIO(content.strip()))
    rows = list(reader)
    if not rows:
        return []

    header = [h.strip().lower() for h in rows[0]]
    entries: List[PasswordEntry] = []

    if "title" in header and "password" in header:
        col_map = {name: idx for idx, name in enumerate(header)}
        for row in rows[1:]:
            if len(row) <= max(col_map.values(), default=0):
                continue
            title = row[col_map["title"]]
            entry_type = row[col_map.get("type", 0)].lower() if "type" in col_map else "login"
            if entry_type not in ("login", "card", "note", "key", "identity", "server"):
                entry_type = "login"
            user = row[col_map["username"]] if "username" in col_map else ""
            pw = row[col_map["password"]] if "password" in col_map else ""
            url = row[col_map["url"]] if "url" in col_map else ""
            totp = row[col_map["totp_secret"]] if "totp_secret" in col_map else ""
            notes = row[col_map["notes"]] if "notes" in col_map else ""
            tags = [t.strip() for t in row[col_map["tags"]].split(",") if t.strip()] if "tags" in col_map else []
            fav = str(row[col_map["favorite"]]).strip() in ("1", "true", "True") if "favorite" in col_map else False

            entries.append(PasswordEntry(
                type=entry_type,
                title=title or user or url or "İçe Aktarılan Kayıt",
                username=user,
                password=pw,
                url=url,
                totp_secret=totp,
                notes=notes,
                tags=tags,
                favorite=fav
            ))
        return entries

    if "login_username" in header or "login_password" in header:
        col_map = {name: idx for idx, name in enumerate(header)}
        for row in rows[1:]:
            if not row or len(row) <= max(col_map.values(), default=0):
                continue
            title = row[col_map.get("name", 0)] if "name" in col_map else "İçe Aktarılan"
            username = row[col_map["login_username"]] if "login_username" in col_map else ""
            password = row[col_map["login_password"]] if "login_password" in col_map else ""
            url = row[col_map["login_uri"]] if "login_uri" in col_map else ""
            notes = row[col_map["notes"]] if "notes" in col_map else ""
            totp = row[col_map["login_totp"]] if "login_totp" in col_map else ""
            fav = str(row[col_map.get("favorite", 0)]).strip() in ("1", "true", "True")
            entry_type = row[col_map.get("type", 0)].lower() if "type" in col_map else "login"
            if entry_type not in ("login", "card", "note", "key", "identity", "server"):
                entry_type = "login"

            entries.append(PasswordEntry(
                type=entry_type,
                title=title or url or "İçe Aktarılan Hesap",
                username=username,
                password=password,
                url=url,
                totp_secret=totp,
                notes=notes,
                favorite=fav
            ))
        return entries

    if "name" in header and "url" in header and "username" in header and "password" in header:
        col_map = {name: idx for idx, name in enumerate(header)}
        note_idx = col_map.get("note", col_map.get("notes"))
        for row in rows[1:]:
            if len(row) <= max(col_map.values(), default=0):
                continue
            notes = row[note_idx] if note_idx is not None and note_idx < len(row) else ""
            entries.append(PasswordEntry(
                type="login",
                title=row[col_map["name"]] or row[col_map["url"]] or "Chrome Girişi",
                username=row[col_map["username"]],
                password=row[col_map["password"]],
                url=row[col_map["url"]],
                notes=notes
            ))
        return entries

    if ("httprealm" in header or "formactionorigin" in header or "timecreated" in header) and "url" in header and "username" in header:
        col_map = {name: idx for idx, name in enumerate(header)}
        for row in rows[1:]:
            if len(row) <= max(col_map.values(), default=0):
                continue
            url = row[col_map["url"]]
            clean_host = url.split("://")[-1].split("/")[0] if "://" in url else url
            entries.append(PasswordEntry(
                type="login",
                title=clean_host or url or "Firefox Girişi",
                username=row[col_map["username"]],
                password=row[col_map["password"]],
                url=url
            ))
        return entries

    title_idx = _find_col(header, ["title", "başlık", "ad", "name"])
    user_idx = _find_col(header, ["username", "kullanıcı adı", "user", "login"])
    pass_idx = _find_col(header, ["password", "parola", "şifre", "pass"])
    url_idx = _find_col(header, ["url", "website", "link", "web"])
    notes_idx = _find_col(header, ["notes", "notlar", "açıklama", "comment"])

    if pass_idx is not None:
        for row in rows[1:]:
            title = row[title_idx] if title_idx is not None and title_idx < len(row) else ""
            user = row[user_idx] if user_idx is not None and user_idx < len(row) else ""
            pw = row[pass_idx] if pass_idx < len(row) else ""
            url = row[url_idx] if url_idx is not None and url_idx < len(row) else ""
            notes = row[notes_idx] if notes_idx is not None and notes_idx < len(row) else ""

            if not pw and not user and not title:
                continue

            entries.append(PasswordEntry(
                type="login",
                title=title or user or url or "İçe Aktarılan Kayıt",
                username=user,
                password=pw,
                url=url,
                notes=notes
            ))

    return entries

def detect_and_import_json(content: str) -> List[PasswordEntry]:
    """Bitwarden JSON veya standart Enclave JSON yedeğini çözer."""
    data = json.loads(content)
    entries: List[PasswordEntry] = []

    if isinstance(data, dict) and "items" in data:
        for item in data["items"]:
            login = item.get("login") or {}
            title = item.get("name") or "İçe Aktarılan"
            username = login.get("username", "")
            password = login.get("password", "")
            totp = login.get("totp", "")
            uris = login.get("uris") or []
            url = uris[0].get("uri", "") if uris and isinstance(uris[0], dict) else ""
            notes = item.get("notes") or ""
            fav = bool(item.get("favorite", False))

            entries.append(PasswordEntry(
                type="login",
                title=title,
                username=username,
                password=password,
                url=url,
                totp_secret=totp,
                notes=notes,
                favorite=fav
            ))
        return entries

    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                entries.append(PasswordEntry.from_dict(item))
        return entries

    return entries

def _find_col(header: List[str], candidates: List[str]) -> Optional[int]:
    for cand in candidates:
        if cand in header:
            return header.index(cand)
    return None

def export_to_csv(entries: List[PasswordEntry]) -> str:
    """Tüm kayıtları standart CSV formatında metin olarak döndürür."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Title", "Type", "Username", "Password", "URL", "TOTP_Secret", "Notes", "Tags", "Favorite"])
    for e in entries:
        if e.deleted:
            continue
        writer.writerow([
            e.title,
            e.type,
            e.username,
            e.password,
            e.url,
            e.totp_secret,
            e.notes,
            ",".join(e.tags),
            "1" if e.favorite else "0"
        ])
    return output.getvalue()

def export_encrypted_backup(entries: List[PasswordEntry], dest_or_password: str, password: Optional[str] = None) -> bytes:
    """Verileri kullanıcının belirlediği harici parolayla Argon2id + AES-256-GCM ile şifreler."""
    if password is not None:
        target_path = dest_or_password
        actual_password = password
    else:
        target_path = None
        actual_password = dest_or_password

    salt = os.urandom(16)
    kdf = Argon2id(
        memory_cost=64 * 1024,
        iterations=3,
        lanes=4,
        salt=salt,
        length=32
    )
    key = kdf.derive(actual_password.encode("utf-8"))
    payload = json.dumps([e.to_dict() for e in entries if not e.deleted]).encode("utf-8")
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, payload, b"ENCLAVE_EXPORT_V1")
    encrypted = b"ENCDBK" + salt + nonce + ciphertext
    if target_path:
        with open(target_path, "wb") as f:
            f.write(encrypted)
    return encrypted

def import_encrypted_backup(data_or_path: Any, password: str) -> List[PasswordEntry]:
    """Şifreli harici yedeği çözer."""
    if isinstance(data_or_path, str) and os.path.exists(data_or_path):
        with open(data_or_path, "rb") as f:
            data = f.read()
    else:
        data = data_or_path

    if len(data) < 6 + 16 + 12 + 16 or (not data.startswith(b"ENCDBK") and not data.startswith(b"VPWDBK")):
        raise ValueError(tr("Geçersiz şifreli yedek dosyası biçimi."))
    magic = data[:6]
    aad = b"ENCLAVE_EXPORT_V1" if magic == b"ENCDBK" else b"ENCLAVE_EXPORT_V1"
    salt = data[6:22]
    nonce = data[22:34]
    ciphertext = data[34:]
    kdf = Argon2id(
        memory_cost=64 * 1024,
        iterations=3,
        lanes=4,
        salt=salt,
        length=32
    )
    key = kdf.derive(password.encode("utf-8"))
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, aad)
    except Exception as e:
        raise ValueError(tr("Parola hatalı veya dosya bozulmuş.")) from e
    items = json.loads(plaintext.decode("utf-8"))
    return [PasswordEntry.from_dict(item) for item in items]

