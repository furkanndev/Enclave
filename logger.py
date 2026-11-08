"""
Enclave - Günlük (Log) ve Sistem Bilgisi Yöneticisi
Uygulama işlemlerini, bağlanan bilgisayar adı, kullanıcı ve IP bilgisiyle logs/ klasöründeki günlük dosyalara kaydeder.
"""

import os
import sys
import time
import socket
import platform
import getpass
from pathlib import Path
from typing import Optional, Dict, Any

def get_base_dir() -> Path:
    """Uygulamanın ana dizinini döndürür (.exe veya .py durumuna göre)."""
    if getattr(sys, "frozen", False):
        exe_dir = Path(sys.executable).parent
        if exe_dir.name.lower() == "dist" and (exe_dir.parent / "vaults").exists():
            return exe_dir.parent
        return exe_dir
    return Path(__file__).resolve().parent

def _newest_profile_dir(own: Path) -> Path:
    """
    Başka hesapla yönetici olarak açılınca ayarlar ayrışmasın: en son kullanılan Enclave ayarı ortak kaynaktır.
    Aynı hesapta bu dizin zaten kendi dizinidir.
    """
    try:
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            return own
        users = Path(os.environ.get("SystemDrive", "C:") + "\\") / "Users"
        found = [p for p in users.glob("*/AppData/Roaming/Enclave/config.json") if p.is_file()]
        if not found:
            found = [p for p in users.glob("*/AppData/Roaming/VaultPro/config.json") if p.is_file()]
        return max(found, key=lambda p: p.stat().st_mtime).parent if found else own
    except OSError:
        return own

def get_user_data_dir() -> Path:
    """
    Kullanıcıya özel ayar dizini. Kurulu uygulama klasörleri macOS ve Linux'ta yazılabilir değildir.
    Uygulama farklı bir hesapla yönetici olarak yeniden açılırsa ayarlar kaybolmasın diye
    ilk oturumun dizini ENCLAVE_DATA_DIR veya VAULTPRO_DATA_DIR ile aktarılır.
    """
    inherited = os.environ.get("ENCLAVE_DATA_DIR") or os.environ.get("VAULTPRO_DATA_DIR")
    if inherited:
        return Path(inherited)
    if sys.platform == "win32":
        root = Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming")
        enclave_dir = root / "Enclave"
        legacy_dir = root / "VaultPro"
        if not enclave_dir.exists() and legacy_dir.exists():
            return _newest_profile_dir(legacy_dir)
        return _newest_profile_dir(enclave_dir)
    if sys.platform == "darwin":
        enclave_dir = Path.home() / "Library" / "Application Support" / "Enclave"
        legacy_dir = Path.home() / "Library" / "Application Support" / "VaultPro"
        return legacy_dir if not enclave_dir.exists() and legacy_dir.exists() else enclave_dir
    enclave_dir = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "enclave"
    legacy_dir = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "vaultpro"
    return legacy_dir if not enclave_dir.exists() and legacy_dir.exists() else enclave_dir

BASE_DIR = get_base_dir()
USER_DATA_DIR = get_user_data_dir()
LOGS_DIR = USER_DATA_DIR / "logs"
VAULTS_DIR = (BASE_DIR if sys.platform == "win32" else USER_DATA_DIR) / "vaults"
BACKUPS_DIR = VAULTS_DIR / "backups"

for _required_dir in (USER_DATA_DIR, LOGS_DIR, VAULTS_DIR, BACKUPS_DIR):
    try:
        _required_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass
try:
    os.chmod(USER_DATA_DIR, 0o700)
except OSError:
    pass

def open_in_file_manager(path: Path) -> None:
    """Klasör veya dosyayı işletim sisteminin dosya yöneticisinde açar."""
    if sys.platform == "win32":
        os.startfile(str(path))
    else:
        import subprocess
        subprocess.Popen(["open" if sys.platform == "darwin" else "xdg-open", str(path)])

def get_daily_log_file() -> Path:
    """Günün tarihine göre log dosyası yolunu döndürür (logs/log_YYYY-MM-DD.log)."""
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    today_str = time.strftime("%Y-%m-%d")
    return LOGS_DIR / f"log_{today_str}.log"

LOG_FILE = get_daily_log_file()

_SYS_CONTEXT: Optional[Dict[str, str]] = None

def get_system_context() -> Dict[str, str]:
    """Aktif bilgisayar adı, kullanıcı adı, IP ve işletim sistemi bilgilerini döndürür."""
    global _SYS_CONTEXT
    if _SYS_CONTEXT is not None:
        return _SYS_CONTEXT

    hostname = socket.gethostname() or os.environ.get("COMPUTERNAME", "BILINMIYOR")
    username = os.environ.get("USERNAME") or getpass.getuser() or "BILINMIYOR"

    try:
        ip = socket.gethostbyname(hostname)
    except Exception:
        ip = "127.0.0.1"

    os_release = f"{platform.system()} {platform.release()} (Derleme {platform.version().split('.')[-1]})"

    _SYS_CONTEXT = {
        "hostname": hostname,
        "username": username,
        "ip": ip,
        "os_info": os_release,
        "node_tag": f"{hostname}\\{username}"
    }
    return _SYS_CONTEXT

def log_session_start(is_admin: bool = False):
    """Uygulama başladığında bilgisayar ve oturum kimlik başlığını günün log dosyasına işler."""
    ctx = get_system_context()
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    adm_str = "Evet (Yonetici)" if is_admin else "Hayir (Standart)"
    divider = "=" * 78
    header = (
        f"\n{divider}\n"
        f"[{timestamp}] [OTURUM BASLADI]\n"
        f"Cihaz / Bilgisayar: {ctx['hostname']} (IP: {ctx['ip']})\n"
        f"Kullanici Hesabi  : {ctx['username']} | Yetki: {adm_str}\n"
        f"Isletim Sistemi   : {ctx['os_info']}\n"
        f"{divider}\n"
    )
    try:
        log_file = get_daily_log_file()
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(header)
    except Exception as e:
        print(f"Log başlığı yazılamadı: {e}")

def log_to_file(message: str, level: str = "BILGI", category: Optional[str] = None):
    """
    Mesajı günün log dosyasına zaman damgası, seviyesi ve bağlanan bilgisayar/kullanıcı kimliği ile kaydeder.
    Seviyeler: BILGI, BASARI, UYARI, HATA, GUVENLIK
    """
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    clean_level = level.upper().replace("INFO", "BILGI").replace("SUCCESS", "BASARI").replace("WARN", "UYARI").replace("ERROR", "HATA")
    ctx = get_system_context()
    node = ctx["node_tag"]
    cat_str = f" [{category.upper()}]" if category else ""

    line = f"[{timestamp}] [{clean_level}]{cat_str} [{node}] {message}\n"

    try:
        log_file = get_daily_log_file()
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(line)
    except Exception as e:
        print(f"Log yazılamadı: {e}")

def open_log_file():
    """Günün log dosyasını varsayılan metin düzenleyicide (Notepad) açar."""
    try:
        log_file = get_daily_log_file()
        if not log_file.exists():
            log_session_start()
            log_to_file("Log dosyası oluşturuldu.", "BILGI")
        os.startfile(str(log_file))
    except Exception as e:
        print(f"Log dosyası açılamadı: {e}")

def open_logs_folder():
    """logs klasörünü Dosya Gezgini'nde açar."""
    try:
        LOGS_DIR.mkdir(parents=True, exist_ok=True)
        open_in_file_manager(LOGS_DIR)
    except Exception as e:
        print(f"Logs klasörü açılamadı: {e}")

def clear_log_file():
    """Günün log dosyasını adli standartta güvenle sıfırlar ve yeni oturum başlığı başlatır."""
    try:
        from enclave_core import secure_wipe_file
        log_file = get_daily_log_file()
        if log_file.exists():
            secure_wipe_file(str(log_file), passes=1)
        log_session_start()
    except Exception as e:
        print(f"Log temizlenemedi: {e}")

def open_vaults_folder():
    """vaults klasörünü Dosya Gezgini'nde açar."""
    try:
        VAULTS_DIR.mkdir(parents=True, exist_ok=True)
        open_in_file_manager(VAULTS_DIR)
    except Exception as e:
        print(f"Vaults klasörü açılamadı: {e}")

def open_backups_folder():
    """vaults/backups klasörünü Dosya Gezgini'nde açar."""
    try:
        BACKUPS_DIR.mkdir(parents=True, exist_ok=True)
        open_in_file_manager(BACKUPS_DIR)
    except Exception as e:
        print(f"Backups klasörü açılamadı: {e}")
