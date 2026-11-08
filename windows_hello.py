"""
Enclave - Windows Hello İki Faktörlü Doğrulama (2FA) ve Biyometrik Entegrasyon
Faktör 1 (Bilgi): Kasa parolasını bilmek ve girmek zorunludur.
Faktör 2 (Sahiplik / Biyometrik): Windows Hello (Parmak İzi / Yüz Tanıma / PIN) onayı zorunludur.

Güvenlik Mimarisi:
1. Sıfır Parola Saklama (Zero Credential Storage):
   2FA modunda kasa parolası ASLA diske, belleğe veya DPAPI'ye kalıcı olarak yazılmaz.
   Kullanıcı kasanın gerçek parolasını bilmeden, bilgisayarı ele geçiren ve Windows PIN'ini
   bilen hiç kimse kasanın kilidini açamaz (Credential Downgrade koruması).
2. Windows Hello UserConsentVerifier (WinRT API):
   Kasa parolası doğrulandıktan hemen sonra Windows Hello biyometrik doğrulama
   penceresi tetiklenir. Kullanıcı biyometrik onay vermezse kasa kilitli kalır.
3. Taşınabilirlik (Plausible Deniability & Portability):
   2FA kuralı yerel cihaz bazlıdır; kasa dosyası (.pvault / .vhd) başka bilgisayara
   taşındığında ana parolasıyla açılabilir.
"""

import os
import sys
import json
import base64
import ctypes
import hashlib
import subprocess
from ctypes import wintypes
from pathlib import Path
from typing import Optional, Tuple, Dict, Any

from config import load_config, save_config

class DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_byte))
    ]

CryptProtectData = ctypes.windll.crypt32.CryptProtectData
CryptProtectData.argtypes = [
    ctypes.POINTER(DATA_BLOB),
    wintypes.LPCWSTR,
    ctypes.POINTER(DATA_BLOB),
    ctypes.c_void_p,
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.POINTER(DATA_BLOB)
]
CryptProtectData.restype = wintypes.BOOL

CryptUnprotectData = ctypes.windll.crypt32.CryptUnprotectData
CryptUnprotectData.argtypes = [
    ctypes.POINTER(DATA_BLOB),
    ctypes.POINTER(wintypes.LPWSTR),
    ctypes.POINTER(DATA_BLOB),
    ctypes.c_void_p,
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.POINTER(DATA_BLOB)
]
CryptUnprotectData.restype = wintypes.BOOL

LocalFree = ctypes.windll.kernel32.LocalFree
LocalFree.argtypes = [ctypes.c_void_p]
LocalFree.restype = ctypes.c_void_p

CRYPTPROTECT_UI_FORBIDDEN = 0x1

def dpapi_encrypt(data: bytes, entropy: bytes = b"", description: str = "Enclave_Credential") -> bytes:
    """Windows DPAPI (CryptProtectData) ile veriyi kullanıcı oturumuna özel şifreler."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("Şifrelenecek veri bytes formatında olmalıdır.")
    
    data_in = DATA_BLOB(len(data), ctypes.cast(ctypes.create_string_buffer(bytes(data)), ctypes.POINTER(ctypes.c_byte)))
    entropy_blob = None
    if entropy:
        entropy_blob = DATA_BLOB(len(entropy), ctypes.cast(ctypes.create_string_buffer(bytes(entropy)), ctypes.POINTER(ctypes.c_byte)))
    
    data_out = DATA_BLOB()
    res = CryptProtectData(
        ctypes.byref(data_in),
        description,
        ctypes.byref(entropy_blob) if entropy_blob else None,
        None,
        None,
        CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(data_out)
    )
    if not res:
        err = ctypes.GetLastError()
        raise OSError(f"CryptProtectData başarısız oldu (Hata Kodu: {err})")
    
    try:
        return ctypes.string_at(data_out.pbData, data_out.cbData)
    finally:
        LocalFree(data_out.pbData)

def dpapi_decrypt(cipher: bytes, entropy: bytes = b"") -> bytes:
    """Windows DPAPI (CryptUnprotectData) ile şifreli veriyi çözer."""
    if not isinstance(cipher, (bytes, bytearray)):
        raise TypeError("Şifreli veri bytes formatında olmalıdır.")
    
    data_in = DATA_BLOB(len(cipher), ctypes.cast(ctypes.create_string_buffer(bytes(cipher)), ctypes.POINTER(ctypes.c_byte)))
    entropy_blob = None
    if entropy:
        entropy_blob = DATA_BLOB(len(entropy), ctypes.cast(ctypes.create_string_buffer(bytes(entropy)), ctypes.POINTER(ctypes.c_byte)))
    
    data_out = DATA_BLOB()
    res = CryptUnprotectData(
        ctypes.byref(data_in),
        None,
        ctypes.byref(entropy_blob) if entropy_blob else None,
        None,
        None,
        CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(data_out)
    )
    if not res:
        err = ctypes.GetLastError()
        raise OSError(f"CryptUnprotectData başarısız oldu (Hata Kodu: {err})")
    
    try:
        return ctypes.string_at(data_out.pbData, data_out.cbData)
    finally:
        LocalFree(data_out.pbData)

def _get_vault_entropy(vault_path: str) -> bytes:
    """Kasaya özel 256-bit benzersiz entropy (tuz) üretir."""
    norm = str(Path(vault_path).resolve()).lower().strip()
    return hashlib.sha256(f"VAULT_PRO_DPAPI_SALT_2026_{norm}".encode("utf-8")).digest()

def _get_vault_key_id(vault_path: str) -> str:
    """Kasaya özel konfigürasyon anahtar kimliği."""
    norm = str(Path(vault_path).resolve()).lower().strip()
    return hashlib.sha256(norm.encode("utf-8")).hexdigest()[:24]

_HELLO_AVAILABILITY_CACHE: Optional[Tuple[bool, str, float]] = None

def is_windows_hello_available(force_refresh: bool = False) -> Tuple[bool, str]:
    """
    Windows Hello (Biyometrik veya PIN) desteğinin bu sistemde etkin ve kullanılabilir olup olmadığını sorgular.
    Dönen değer: (is_available: bool, status_reason: str)
    Olası durumlar: 'Available', 'DeviceNotPresent', 'NotConfiguredForUser', 'DisabledByPolicy', vb.
    """
    global _HELLO_AVAILABILITY_CACHE
    import time

    now = time.time()
    if not force_refresh and _HELLO_AVAILABILITY_CACHE is not None:
        avail, status, cached_at = _HELLO_AVAILABILITY_CACHE
        if now - cached_at < 60:
            return avail, status

    ps_code = """
    $ErrorActionPreference = 'Stop'
    try {
        Add-Type -AssemblyName System.Runtime.WindowsRuntime -ErrorAction Stop
        [Windows.Security.Credentials.UI.UserConsentVerifier, Windows.Security.Credentials.UI, ContentType = WindowsRuntime] | Out-Null
        $op = [Windows.Security.Credentials.UI.UserConsentVerifier]::CheckAvailabilityAsync()
        
        $asTaskGeneric = [System.WindowsRuntimeSystemExtensions].GetMethods() | 
            Where-Object { $_.Name -eq 'AsTask' -and $_.GetParameters().Length -eq 1 -and $_.IsGenericMethod } | 
            Select-Object -First 1
        $netTask = $asTaskGeneric.MakeGenericMethod([Windows.Security.Credentials.UI.UserConsentVerifierAvailability]).Invoke($null, @($op))
        $netTask.Wait(4000) | Out-Null
        $status = $netTask.Result.ToString()
        Write-Output $status
    } catch {
        Write-Output "Error: $($_.Exception.Message)"
    }
    """
    try:
        enc = base64.b64encode(ps_code.encode("utf-16le")).decode("ascii")
        CREATE_NO_WINDOW = 0x08000000
        res = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", enc],
            capture_output=True,
            text=True,
            creationflags=CREATE_NO_WINDOW,
            timeout=8
        )
        status = res.stdout.strip()
        is_avail = (status == "Available")
        _HELLO_AVAILABILITY_CACHE = (is_avail, status, now)
        return is_avail, status
    except Exception as e:
        status = f"Hata: {e}"
        _HELLO_AVAILABILITY_CACHE = (False, status, now)
        return False, status

def request_windows_hello_verification(prompt_message: str = "Enclave - Kasa Kilidi Doğrulaması") -> Tuple[bool, str]:
    """
    Kullanıcıya resmi Windows Hello istemini (Parmak izi, Windows Hello Yüz veya Windows PIN) sunar.
    Başarılı olursa (True, 'Verified'), kullanıcı iptal ederse veya hata olursa (False, reason) döndürür.
    """
    clean_prompt = prompt_message.replace('"', '\\"').replace("'", " ").replace("\n", " ").replace("\r", " ").strip()
    if not clean_prompt:
        clean_prompt = "Enclave - Kasa Kilidi Doğrulaması"

    ps_code = f"""
    $ErrorActionPreference = 'Stop'
    try {{
        Add-Type -AssemblyName System.Runtime.WindowsRuntime -ErrorAction Stop
        [Windows.Security.Credentials.UI.UserConsentVerifier, Windows.Security.Credentials.UI, ContentType = WindowsRuntime] | Out-Null
        $op = [Windows.Security.Credentials.UI.UserConsentVerifier]::RequestVerificationAsync("{clean_prompt}")
        
        $asTaskGeneric = [System.WindowsRuntimeSystemExtensions].GetMethods() | 
            Where-Object {{ $_.Name -eq 'AsTask' -and $_.GetParameters().Length -eq 1 -and $_.IsGenericMethod }} | 
            Select-Object -First 1
        $netTask = $asTaskGeneric.MakeGenericMethod([Windows.Security.Credentials.UI.UserConsentVerificationResult]).Invoke($null, @($op))
        $netTask.Wait() | Out-Null
        $result = $netTask.Result.ToString()
        Write-Output $result
    }} catch {{
        Write-Output "Error: $($_.Exception.Message)"
    }}
    """
    try:
        enc = base64.b64encode(ps_code.encode("utf-16le")).decode("ascii")
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        si.wShowWindow = 0
        CREATE_NO_WINDOW = 0x08000000
        res = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-EncodedCommand", enc],
            capture_output=True,
            text=True,
            creationflags=CREATE_NO_WINDOW,
            startupinfo=si,
            timeout=120
        )
        res_str = res.stdout.strip()
        if res_str == "Verified":
            return True, "Verified"
        return False, res_str
    except subprocess.TimeoutExpired:
        return False, "Zaman aşımı (Doğrulama süresi doldu)"
    except Exception as e:
        return False, str(e)

def is_vault_2fa_enabled(vault_path: str) -> bool:
    """
    Belirtilen kasa için İki Faktörlü Doğrulamanın (2FA) etkin olup olmadığını denetler.
    Konteyner başlığındaki kriptografik mühür (FLAG_2FA_ENFORCED) en yüksek önceliğe sahiptir.
    """
    try:
        if not vault_path:
            return False

        try:
            from enclave_core import CustomVaultEngine, FLAG_2FA_ENFORCED
            flags = CustomVaultEngine.read_header_flags(vault_path)
            if flags & FLAG_2FA_ENFORCED:
                return True
        except Exception:
            pass

        cfg = load_config()
        key_id = _get_vault_key_id(vault_path)
        vault_2fa = cfg.get("vault_2fa_enabled", {})

        if key_id in vault_2fa:
            val = vault_2fa[key_id]
            if isinstance(val, dict):
                return bool(val.get("enabled", False))
            return bool(val)

        if not cfg.get("windows_hello_enabled", True):
            return False
        return bool(cfg.get("require_2fa_all_vaults", False))
    except Exception:
        return False

def set_vault_2fa_enabled(vault_path: str, enabled: bool) -> bool:
    """
    Belirtilen kasa için İki Faktörlü Doğrulama (2FA) zorunluluğunu açar veya kapatır.
    NOT: Bu işlem diske KESİNLİKLE parola veya kriptografik anahtar yazmaz; yalnızca
    o kasanın bu bilgisayarda biyometrik onay gerektirdiği bayrağını tutar.
    """
    try:
        if not vault_path:
            return False
        key_id = _get_vault_key_id(vault_path)
        cfg = load_config()
        vault_2fa = cfg.get("vault_2fa_enabled", {})

        vault_2fa[key_id] = {
            "enabled": bool(enabled),
            "updated_at": int(__import__("time").time())
        }
        cfg["vault_2fa_enabled"] = vault_2fa

        if not enabled:
            cfg["require_2fa_all_vaults"] = False

        save_config(cfg)
        return True
    except Exception:
        return False

def clear_all_2fa_settings() -> bool:
    """Tüm kasalara ait 2FA ayarlarını ve kayıtlarını sıfırlar."""
    try:
        cfg = load_config()
        cfg["vault_2fa_enabled"] = {}
        cfg["require_2fa_all_vaults"] = False
        save_config(cfg)
        return True
    except Exception:
        return False

def purge_all_saved_passwords() -> bool:
    """
    Eski 1FA kolaylık modundan kalmış olabilecek tüm DPAPI mühürlü parolaları
    diski temizleyerek kalıcı olarak imha eder (Sıfır Parola Saklama - Zero Credential).
    """
    try:
        cfg = load_config()
        if "windows_hello_credentials" in cfg:
            cfg["windows_hello_credentials"] = {}
            save_config(cfg)
        return True
    except Exception:
        return False

def save_vault_biometric_credential(vault_path: str, password: str, vault_name: str = "") -> bool:
    """
    Kasaya ait parolayı Windows DPAPI ile şifreleyerek güvenle saklar.
    Diske asla düz metin parola ve mutlak dosya yolu yazılmaz (Sıfır Adli İz & Plausible Deniability).
    """
    try:
        if not vault_path or not password:
            return False

        key_id = _get_vault_key_id(vault_path)
        entropy = _get_vault_entropy(vault_path)
        pw_bytes = password.encode("utf-8")

        cipher = dpapi_encrypt(pw_bytes, entropy=entropy, description="Enclave_VaultKey")
        cipher_b64 = base64.b64encode(cipher).decode("ascii")

        cfg = load_config()
        hello_creds = cfg.get("windows_hello_credentials", {})
        hello_creds[key_id] = {
            "cipher": cipher_b64,
            "saved_at": int(__import__("time").time())
        }
        cfg["windows_hello_credentials"] = hello_creds
        cfg["windows_hello_enabled"] = True
        save_config(cfg)
        return True
    except Exception:
        return False

def has_vault_biometric_credential(vault_path: str) -> bool:
    """Belirtilen kasa için kayıtlı Windows Hello biyometrik kimliği var mı denetler."""
    try:
        if not vault_path:
            return False
        key_id = _get_vault_key_id(vault_path)
        cfg = load_config()
        if not cfg.get("windows_hello_enabled", True):
            return False
        hello_creds = cfg.get("windows_hello_credentials", {})
        return key_id in hello_creds
    except Exception:
        return False

def remove_vault_biometric_credential(vault_path: str) -> bool:
    """Belirtilen kasaya ait kayıtlı biyometrik kimliği siler."""
    try:
        if not vault_path:
            return False
        key_id = _get_vault_key_id(vault_path)
        cfg = load_config()
        hello_creds = cfg.get("windows_hello_credentials", {})
        if key_id in hello_creds:
            del hello_creds[key_id]
            cfg["windows_hello_credentials"] = hello_creds
            save_config(cfg)
            return True
        return False
    except Exception:
        return False

def clear_all_biometric_credentials() -> bool:
    """Tüm kasalara ait saklanan biyometrik kimlikleri güvenle temizler."""
    try:
        cfg = load_config()
        cfg["windows_hello_credentials"] = {}
        save_config(cfg)
        return True
    except Exception:
        return False

def retrieve_vault_password_with_hello(
    vault_path: str,
    prompt: Optional[str] = None
) -> Tuple[Optional[str], str]:
    """
    Windows Hello biyometrik doğrulamasını çalıştırır ve başarılıysa
    DPAPI ile şifrelenmiş kasa parolasını çözerek döndürür.
    Dönen değer: (password: Optional[str], status_msg: str)
    """
    try:
        if not vault_path:
            return None, "Kasa yolu belirtilmedi."

        key_id = _get_vault_key_id(vault_path)
        cfg = load_config()
        hello_creds = cfg.get("windows_hello_credentials", {})
        cred_info = hello_creds.get(key_id)
        if not cred_info:
            return None, "Bu kasa için kayıtlı Windows Hello kimlik bilgisi bulunamadı."

        v_name = cred_info.get("vault_name") or Path(vault_path).name
        if not prompt:
            prompt = f"Enclave - '{v_name}' kasasının kilidini açmak için kimliğinizi doğrulayın"

        is_verified, reason = request_windows_hello_verification(prompt)
        if not is_verified:
            if reason == "Canceled":
                return None, "Doğrulama kullanıcı tarafından iptal edildi."
            return None, f"Windows Hello doğrulaması başarısız oldu: {reason}"

        cipher_b64 = cred_info.get("cipher", "")
        if not cipher_b64:
            return None, "Kayıtlı kimlik verisi bozuk."

        cipher = base64.b64decode(cipher_b64.encode("ascii"))
        entropy = _get_vault_entropy(vault_path)
        plain_bytes = dpapi_decrypt(cipher, entropy=entropy)
        password = plain_bytes.decode("utf-8")

        return password, "Verified"
    except Exception as e:
        return None, f"Kimlik çözme hatası: {e}"
