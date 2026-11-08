"""
Enclave - Yapılandırma Yöneticisi
Uygulama ayarlarını, kasa tercihlerini ve kancaları JSON formatında güvenle saklar.
"""

import os
import sys
import copy
import json
from pathlib import Path
from typing import Optional
from logger import BASE_DIR, USER_DATA_DIR

APP_VERSION = "2.0"
CONFIG_FILE = USER_DATA_DIR / "config.json"
LEGACY_CONFIG_FILE = BASE_DIR / "config.json"

DEFAULT_CONFIG = {
    "search_files": ["haha.vhd", "haha.haha", "kasa.vhd", "vault.vhd", "depo.vhd"],
    "autoplay_protection": True,
    "auto_open_explorer": True,
    "minimize_to_tray_on_mount": False,
    "auto_mount_on_startup": False,
    "last_vault_path": "",
    "custom_vault_history": [],
    "theme": "apple_dark",
    
    "panic_hotkey_enabled": True,
    "panic_hotkey": "Ctrl+Alt+L",
    "auto_lock_enabled": False,
    "auto_lock_minutes": 5,
    "lock_on_screen_lock": True,
    "auto_dismount_on_close": True,
    "preferred_drive_letters": {},
    "auto_run_hooks": {},
    
    "cache_clean_on_dismount": True,
    
    "auto_backup_enabled": False,
    "auto_backup_dir": "",
    "backup_keep_count": 3,
    
    
    "decoy_vault_enabled": False,
    "decoy_vault_path": "",
    "decoy_vault_password_hash": "",
    
    "audit_log_enabled": True,
    "vault_profiles": [],

    "cloud_sync_warning_enabled": True,
    "anti_forensics_deep_clean": True,
    "toast_notifications_enabled": True,
    "anti_brute_force_delay": True,

    "windows_hello_enabled": True,
    "windows_hello_auto_prompt": True,
    "windows_hello_credentials": {}
}

def _other_profile_config() -> Optional[Path]:
    """
    Uygulama başka bir Windows hesabıyla yönetici olarak açılınca kendi ayar dizini boştur.
    Aynı makinedeki en son kullanılan Enclave ayarı bulunur ve ilk açılışta oradan alınır.
    """
    if sys.platform != "win32" or os.environ.get("ENCLAVE_DATA_DIR"):
        return None
    try:
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            return None
    except Exception:
        return None
    users =Path(os.environ.get("SystemDrive", "C:") + "\\") / "Users"
    try:
        found = [p for p in users.glob("*/AppData/Roaming/VaultPro/config.json") if p != CONFIG_FILE]
        return max(found, key=lambda p: p.stat().st_mtime) if found else None
    except OSError:
        return None

def load_config() -> dict:
    """Yapılandırma dosyasını yükler, yoksa varsayılanları (veya eski konumdaki ayarları) kullanır."""
    source = CONFIG_FILE if CONFIG_FILE.exists() else (_other_profile_config() or LEGACY_CONFIG_FILE)
    if not source.exists():
        save_config(DEFAULT_CONFIG)
        return copy.deepcopy(DEFAULT_CONFIG)
    try:
        with open(source, "r", encoding="utf-8") as f:
            data = json.load(f)
            merged = copy.deepcopy(DEFAULT_CONFIG)
            merged.update(data)
            return merged
    except Exception as e:
        print(f"Yapılandırma yüklenirken hata oluştu: {e}")
        return copy.deepcopy(DEFAULT_CONFIG)

def save_config(config: dict) -> bool:
    """Yapılandırmayı atomik olarak kaydeder; dosya yalnızca kullanıcıya açıktır."""
    temp_file = CONFIG_FILE.with_name(f".{CONFIG_FILE.name}.{os.getpid()}.tmp")
    try:
        with open(temp_file, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=4, ensure_ascii=False)
        os.chmod(temp_file, 0o600)
        os.replace(temp_file, CONFIG_FILE)
        return True
    except Exception as e:
        print(f"Yapılandırma kaydedilirken hata oluştu: {e}")
        return False
