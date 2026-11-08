"""
Enclave - RFC 6238 TOTP (Time-based One-Time Password) ve Taşınabilir 2FA Motoru
Google Authenticator, Microsoft Authenticator, Aegis ve YubiKey ile tam uyumludur.

Özellikler:
1. Sıfır Harici Kripto Bağımlılığı (Zero External Crypto Dependency):
   Tamamen Python standart kütüphanesi (hmac, hashlib, time, struct, base64, secrets)
   ile RFC 6238 ve RFC 4226 standartlarında çalışır.
2. Sıfır Adli İz (Zero Forensic Traces & Memory-Only):
   QR kodlar ve geçici anahtarlar diske KESİNLİKLE yazılmaz; doğrudan bellekte (RAM)
   üretilir ve QPixmap olarak görüntülenir.
3. Taşınabilir Yapılandırma ve Sınırı:
   2FA ayarı kasanın şifreli kataloğunda durur ve kasayla birlikte taşınır. Bu, uygulamanın açılışta kod istemesini
   sağlar; şifrelemeye katılmaz. Kod doğrulanabilmesi için sır parolayla erişilebilir olmak zorundadır, bu yüzden
   kasa dosyası ve parolası ele geçirilirse TOTP atlatılabilir. Parolayla birlikte gereken gerçek bir ikinci sır için
   anahtar dosyası kullanılmalıdır.
4. Acil Durum Kurtarma Kodları (Emergency Backup Codes):
   Kullanıcının telefonuna erişemediği acil durumlar için tek kullanımlık SHA-256
   özetli kurtarma kodları üretilir ve doğrulanır.
"""

import io
import time
import hmac
import struct
import base64
import hashlib
import secrets
from typing import List, Tuple, Optional, Dict, Any

try:
    import qrcode
    from PyQt6.QtGui import QImage, QPixmap
    HAS_QR_SUPPORT = True
except Exception:
    HAS_QR_SUPPORT = False

BASE32_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

def generate_totp_secret(length: int = 32) -> str:
    """
    Kriptografik olarak güvenli, 160-bit (32 karakter Base32) rastgele TOTP gizli anahtarı üretir.
    """
    return "".join(secrets.choice(BASE32_CHARS) for _ in range(length))

def format_secret_for_display(secret: str, chunk_size: int = 4) -> str:
    """
    Gizli anahtarı kullanıcının kolay okuyup yazabilmesi için 4'erli bloklara ayırır.
    Örnek: 'JBSW Y3DP EHPK 3PXP'
    """
    clean = secret.strip().replace(" ", "").upper()
    return " ".join(clean[i:i + chunk_size] for i in range(0, len(clean), chunk_size))

def get_totp_token(secret: str, interval: int = 30, digits: int = 6, for_time: Optional[int] = None) -> str:
    """
    RFC 6238 algoritmasına göre belirtilen zaman adımı için 6 haneli TOTP kodunu hesaplar.
    """
    t = int(time.time()) if for_time is None else int(for_time)
    counter = t // interval

    clean_secret = secret.strip().replace(" ", "").upper()
    pad = len(clean_secret) % 8
    if pad:
        clean_secret += "=" * (8 - pad)
    key = base64.b32decode(clean_secret, casefold=True)

    counter_bytes = struct.pack(">Q", counter)

    hmac_digest = hmac.new(key, counter_bytes, hashlib.sha1).digest()

    offset = hmac_digest[-1] & 0x0F
    code_binary = struct.unpack(">I", hmac_digest[offset:offset + 4])[0] & 0x7FFFFFFF
    token = code_binary % (10 ** digits)

    return f"{token:0{digits}d}"

def matching_step(secret: str, token: str, interval: int = 30, window: int = 1) -> Optional[int]:
    """
    Girilen 6 haneli TOTP kodunun ait olduğu zaman adımını döndürür; eşleşme yoksa None.
    Saat kayması (Clock Drift) toleransı için belirtilen aralıkta (window: varsayılan ±1 adım, yani 90 saniye)
    tüm kodları kontrol eder ve sabit-zamanlı karşılaştırma (compare_digest) yapar.
    """
    if not secret or not token:
        return None

    clean_token = str(token).strip().replace(" ", "")
    if len(clean_token) != 6 or not clean_token.isdigit():
        return None

    now = int(time.time())
    for step_offset in range(-window, window + 1):
        moment = now + (step_offset * interval)
        expected_token = get_totp_token(secret, interval=interval, digits=6, for_time=moment)
        if hmac.compare_digest(expected_token, clean_token):
            return moment // interval

    return None

def verify_totp_token(secret: str, token: str, interval: int = 30, window: int = 1) -> bool:
    """Kodun geçerli olup olmadığını söyler. Tek kullanımlık denetimi çağıranın işidir."""
    return matching_step(secret, token, interval, window) is not None

def get_otpauth_uri(secret: str, account_name: str = "Kasa", issuer: str = "Enclave") -> str:
    """
    Google Authenticator ve Microsoft Authenticator için standart otpauth:// URI'si oluşturur.
    """
    clean_secret = secret.strip().replace(" ", "").upper()
    clean_account = account_name.strip().replace(":", "_").replace("/", "_")
    clean_issuer = issuer.strip().replace(":", "_").replace("/", "_")
    return f"otpauth://totp/{clean_issuer}:{clean_account}?secret={clean_secret}&issuer={clean_issuer}&algorithm=SHA1&digits=6&period=30"

def generate_backup_codes(count: int = 8) -> List[str]:
    """
    Kullanıcının telefonunu kaybetmesi durumunda kullanabileceği tek kullanımlık
    acil durum kurtarma kodları (XXXX-XXXX formatında) üretir.
    """
    codes = []
    chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    for _ in range(count):
        part1 = "".join(secrets.choice(chars) for _ in range(4))
        part2 = "".join(secrets.choice(chars) for _ in range(4))
        codes.append(f"{part1}-{part2}")
    return codes

def hash_backup_code(code: str) -> str:
    """Acil durum kurtarma kodunun SHA-256 özetini alır (Düz metin saklamayı önler)."""
    norm = code.strip().replace("-", "").replace(" ", "").upper()
    return hashlib.sha256(norm.encode("utf-8")).hexdigest()

def verify_and_consume_backup_code(code: str, hashed_codes: List[str]) -> Tuple[bool, List[str]]:
    """
    Girilen acil durum kodunu kontrol eder.
    Kod geçerliyse tüketir (listeden siler) ve (True, güncel_liste) döndürür.
    Geçersizse (False, orijinal_liste) döndürür.
    """
    if not code or not hashed_codes:
        return False, hashed_codes

    code_hash = hash_backup_code(code)
    for idx, h in enumerate(hashed_codes):
        if hmac.compare_digest(h.lower(), code_hash.lower()):
            remaining = [c for i, c in enumerate(hashed_codes) if i != idx]
            return True, remaining

    return False, hashed_codes

def generate_qr_pixmap(otpauth_uri: str, size: int = 220) -> Optional[Any]:
    """
    Diske HİÇBİR DOSYA YAZMADAN (RAM-Only / Zero Disk Trace) doğrudan bellek tamponunda (BytesIO)
    QR kod üretir ve yüksek çözünürlüklü QPixmap olarak döndürür.
    """
    if not HAS_QR_SUPPORT:
        return None

    try:
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=6,
            border=2,
        )
        qr.add_data(otpauth_uri)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white").convert("RGB")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        buf.seek(0)

        qimg = QImage.fromData(buf.getvalue())
        pixmap = QPixmap.fromImage(qimg)
        if not pixmap.isNull():
            return pixmap.scaled(size, size)
        return None
    except Exception:
        return None

