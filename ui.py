"""
Enclave - Modern Windows 11 Fluent Kullanıcı Arayüzü (PyQt6)
Gelişmiş VHD/VHDX ve BitLocker yönetim merkezi.
Özellikler: Panik Tuşu, Hareketsizlik/Kilit Koruması, Yeni Kasa Sihirbazı,
Compact VHD, SHA-256 Bütünlük, Otomatik Yedekleme, Özel Sürücü Harfi ve Kancalar.
"""

import os
import sys
import time
import threading
import ctypes
from ctypes import wintypes
import struct

_C_UINT_FROM_ADDR = ctypes.c_uint.from_address
_MSG_OFFSET_MESSAGE = 8 if struct.calcsize("P") == 8 else 4
import winreg
import re
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QPushButton, QComboBox, QLineEdit, QCheckBox,
    QProgressBar, QTextEdit, QFileDialog, QMessageBox, QFrame,
    QSystemTrayIcon, QMenu, QSizePolicy, QScrollArea, QDialog,
    QSpinBox, QFormLayout, QDialogButtonBox, QStackedWidget, QButtonGroup
)
import math
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer, QSize, QEvent, QUrl
from PyQt6.QtGui import QIcon, QColor, QPainter, QPixmap, QAction, QPen, QBrush, QFontDatabase, QFont

import hashlib
import audit_logger
from extra_dialogs import (
    BitLockerRecoveryDialog,
    BitLockerPasswordDialog,
    BitLockerUnlockRecoveryDialog,
    VaultPasswordRecoveryDialog,
    DecoyVaultDialog,
    AuditLogDialog,
    VaultProfilesDialog,
    ShredConfirmDialog,
    ExpandVaultDialog,
    DiskHealthDialog,
    CloudSyncWarningDialog,
    ShellIntegrationDialog,
    HeaderBackupRestoreDialog,
    get_dialog_palette,
    get_dialog_button_stylesheet,
    set_dialog_dark_mode,
    apply_dynamic_geometry
)
import windows_hello
from enclave_custom_ui import get_svg_icon, get_svg_pixmap
from engine import VHDEngine
from config import load_config, save_config
from logger import (
    log_to_file, open_log_file, clear_log_file, open_vaults_folder,
    open_backups_folder, get_system_context, log_session_start,
    open_logs_folder, LOGS_DIR, LOG_FILE, VAULTS_DIR, BACKUPS_DIR
)

class POINT(ctypes.Structure):
    _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long)]

ACTIVE_KEY_CODES = (
    0x01, 0x02, 0x04, 0x05, 0x06,
    0x08, 0x09, 0x0C, 0x0D, 0x10, 0x11, 0x12, 0x13, 0x14, 0x1B, 0x20, 0x2E,
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x2C, 0x2D,
    *range(0x30, 0x3A),
    *range(0x41, 0x5B),
    0x5B, 0x5C, 0x5D,
    *range(0x60, 0x70),
    *range(0x70, 0x7C),
    0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xE2
)

def get_resource_path(relative_path: str) -> Path:
    """PyInstaller bundle ve normal çalışma ortamında dosya yolunu çözer."""
    base_path = getattr(sys, '_MEIPASS', Path(__file__).resolve().parent)
    return Path(base_path) / relative_path

def init_pixel_fonts():
    """Uygulama genelinde kullanılan retro piksel ve okunaklı yazı tiplerini sisteme kaydeder."""
    for fn in [
        "JetBrainsMono-Bold.ttf",
        "JetBrainsMono-Regular.ttf",
        "ChakraPetch-Bold.ttf",
        "ChakraPetch-Regular.ttf",
        "Silkscreen.ttf",
        "PressStart2P.ttf",
        "VT323.ttf"
    ]:
        p = get_resource_path(f"assets/fonts/{fn}")
        if p.exists():
            QFontDatabase.addApplicationFont(str(p))

def create_vault_icon(state_or_color: str = "closed", size: int = 64) -> QIcon:
    """Kasa simgesini döndürür ('closed' / 'open' veya dosya/renk)."""
    state = "open" if str(state_or_color).lower() == "open" else "closed"
    icon_file = "enclave_open.png" if state == "open" else "enclave_closed.png"
    asset_path = get_resource_path(f"assets/{icon_file}")
    if asset_path.exists():
        return QIcon(str(asset_path))
    
    ico_path = get_resource_path("app_icon.ico")
    if ico_path.exists():
        return QIcon(str(ico_path))

    color_hex = state_or_color if str(state_or_color).startswith("#") else ("#10B981" if state == "open" else "#6366F1")
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.GlobalColor.transparent)
    
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    
    rect = pixmap.rect().adjusted(4, 4, -4, -4)
    brush = QBrush(QColor(color_hex))
    painter.setBrush(brush)
    painter.setPen(Qt.PenStyle.NoPen)
    painter.drawRoundedRect(rect, 14, 14)
    
    painter.setPen(QPen(QColor("#FFFFFF"), 3))
    painter.setBrush(Qt.BrushStyle.NoBrush)
    
    cx = size // 2
    cy = size // 2
    painter.drawArc(cx - 8, cy - 14, 16, 16, 0, 180 * 16)
    
    painter.setBrush(QBrush(QColor("#FFFFFF")))
    painter.drawRoundedRect(cx - 11, cy - 6, 22, 16, 4, 4)
    
    painter.setBrush(QBrush(QColor(color_hex)))
    painter.setPen(Qt.PenStyle.NoPen)
    painter.drawEllipse(cx - 2, cy - 2, 4, 4)
    painter.drawRect(cx - 1, cy, 2, 5)
    
    painter.end()
    return QIcon(pixmap)

class GlobalPanicHotkeyListener(QThread):
    """
    Sistem genelinde (tüm pencereler, arka plan, tam ekran, görev çubuğu veya sistem tepsisi)
    panik kısayollarını Windows kernel düzeyinde anlık (<35ms) tarayan global donanım dinleyicisi.
    
    Desteklenen Kısayollar:
    1. Ctrl + Alt + L (Standart Panik Tuşu)
    2. Ctrl + Alt + P (Yedek/Alternatif Panik Tuşu - Başka programlar L'yi bloke etse dahi garanti çalışır)
    """
    panic_signal = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._running = True

    def run(self):
        user32 = ctypes.windll.user32
        try:
            user32.GetAsyncKeyState.argtypes = [ctypes.c_int]
            user32.GetAsyncKeyState.restype = ctypes.c_short
        except Exception:
            pass

        VK_CONTROL = 0x11
        VK_LCONTROL = 0xA2
        VK_RCONTROL = 0xA3
        VK_SHIFT = 0x10
        VK_LSHIFT = 0xA0
        VK_RSHIFT = 0xA1
        VK_MENU = 0x12
        VK_LMENU = 0xA4
        VK_RMENU = 0xA5
        VK_L = 0x4C
        VK_P = 0x50
        VK_K = 0x4B
        VK_PAUSE = 0x13
        VK_SCROLL = 0x91

        def is_down(vk):
            try:
                state = user32.GetAsyncKeyState(vk)
                return bool(state & 0x8000) or state < 0
            except Exception:
                return False

        while self._running:
            try:
                if is_down(VK_PAUSE) or is_down(VK_SCROLL):
                    self.panic_signal.emit()
                    time.sleep(1.2)
                    continue

                ctrl_down = is_down(VK_CONTROL) or is_down(VK_LCONTROL) or is_down(VK_RCONTROL)
                alt_down = is_down(VK_MENU) or is_down(VK_LMENU) or is_down(VK_RMENU)
                shift_down = is_down(VK_SHIFT) or is_down(VK_LSHIFT) or is_down(VK_RSHIFT)

                key_down = is_down(VK_L) or is_down(VK_P) or is_down(VK_K)

                if (ctrl_down and alt_down and key_down) or (ctrl_down and shift_down and key_down):
                    self.panic_signal.emit()
                    time.sleep(1.2)
            except Exception:
                pass
            time.sleep(0.015)

    def stop(self):
        self._running = False
        self.wait(500)

class VaultWorker(QThread):
    """Ağır disk, hash ve şifreleme işlemlerini UI'ı dondurmadan çalıştırır."""
    log_signal = pyqtSignal(str, str, str)
    progress_signal = pyqtSignal(int)
    finished_signal = pyqtSignal(dict)
    
    def __init__(self, action: str, engine: VHDEngine, params: Optional[dict] = None):
        super().__init__()
        self.action = action
        self.engine = engine
        self.params = params or {}

    def run(self):
        result = {"action": self.action, "success": False}
        try:
            if self.action == "mount":
                target_file = self.params.get("file_path")
                pref_letter = self.params.get("preferred_letter")
                autoplay_protect = self.params.get("autoplay_protection", True)
                t_start = time.time()
                if autoplay_protect:
                    self.log_signal.emit("Autoplay koruması uygulanıyor...", "info", "GUVENLIK")
                    self.engine.backup_and_disable_autoplay()
                
                self.log_signal.emit(f"Sanal disk bağlanıyor: {Path(target_file).name}", "info", "BAGLANTI")
                mount_res = self.engine.mount_vhd(target_file, preferred_letter=pref_letter)
                duration = round(time.time() - t_start, 2)
                
                if mount_res.get("success"):
                    self.log_signal.emit(
                        f"Sanal disk başarıyla bağlandı: {mount_res.get('drive_letter')} ({duration} saniyede tamamlandı)",
                        "success",
                        "BAGLANTI"
                    )
                    result.update(mount_res)
                    result["success"] = True
                else:
                    self.log_signal.emit(f"Bağlama başarısız ({duration}s): {mount_res.get('error')}", "error", "HATA")
                    result["error"] = mount_res.get("error")

            elif self.action == "dismount":
                autoplay_protect = self.params.get("autoplay_protection", True)
                force = self.params.get("force", False)
                target = self.params.get("file_path")
                letter = self.params.get("drive_letter")
                clean_traces = self.params.get("clean_traces", True)
                self.log_signal.emit("Sanal disk sistemden ayrılıyor...", "info", "AYIRMA")
                dismount_res = self.engine.dismount_vhd(mount_target=target, drive_letter=letter, force=force)
                
                cleaned_traces_count = 0
                if clean_traces and letter:
                    try:
                        self.log_signal.emit("Sistem izleri temizleniyor...", "info", "GUVENLIK")
                        t_res = self.engine.wipe_system_traces(letter)
                        cleaned_traces_count = t_res.get("cleaned_count", 0)
                    except Exception:
                        pass
                dismount_res["cleaned_traces"] = cleaned_traces_count

                if autoplay_protect or self.engine.autoplay_was_disabled_by_us:
                    self.log_signal.emit("Autoplay ayarları geri yükleniyor...", "info", "GUVENLIK")
                    self.engine.restore_autoplay()

                self.log_signal.emit("Sanal disk güvenle ayrıldı.", "success", "AYIRMA")
                result.update(dismount_res)
                result["success"] = True

            elif self.action == "unlock":
                drive_letter = self.params.get("drive_letter")
                password = self.params.get("password")
                self.log_signal.emit(f"BitLocker parolası doğrulanıyor ({drive_letter})...", "info", "GUVENLIK")
                t_start = time.time()
                unlock_res = self.engine.unlock_bitlocker_password(drive_letter, password)
                duration = round(time.time() - t_start, 2)
                
                if unlock_res.get("success"):
                    self.log_signal.emit(f"BitLocker kilidi başarıyla açıldı ({duration}s).", "success", "GUVENLIK")
                    result.update(unlock_res)
                    result["success"] = True
                else:
                    user_msg = unlock_res.get("error", "Girilen parola hatalı veya kilit açılamadı.")
                    self.log_signal.emit(user_msg, "warn", "GUVENLIK")
                    raw_err = unlock_res.get("raw_error", "")
                    if raw_err:
                        log_to_file(f"Kilit açma başarısız ({drive_letter}): {user_msg} | Detay: {raw_err.strip()}", "UYARI", "GUVENLIK")
                    result.update(unlock_res)

            elif self.action == "change_letter":
                old_letter = self.params.get("old_letter")
                new_letter = self.params.get("new_letter")
                remember = self.params.get("remember", True)
                vault_file = self.params.get("vault_file")
                self.log_signal.emit(f"Sürücü harfi değiştiriliyor: {old_letter} -> {new_letter}...", "info", "SURUCU")
                t_start = time.time()
                res = self.engine.change_drive_letter(new_letter=new_letter, old_letter=old_letter)
                duration = round(time.time() - t_start, 2)
                if res.get("success"):
                    self.log_signal.emit(
                        f"Sürücü harfi başarıyla değiştirildi: {res.get('drive_letter')} ({duration}s)",
                        "success",
                        "SURUCU"
                    )
                    result.update(res)
                    result["remember"] = remember
                    result["vault_file"] = vault_file
                    result["success"] = True
                else:
                    self.log_signal.emit(f"Sürücü harfi değiştirilemedi: {res.get('error')}", "error", "HATA")
                    result["error"] = res.get("error")

            elif self.action == "create_vault":
                v_path = self.params.get("vault_path")
                v_arch = self.params.get("architecture", "vhd")
                v_size = self.params.get("size_gb", 10)
                v_dynamic = self.params.get("is_dynamic", True)
                v_label = self.params.get("label", "Kasa")
                v_pw = self.params.get("password")
                v_has_decoy = self.params.get("has_decoy", False)
                v_decoy_size = self.params.get("decoy_size_gb", 1)
                v_decoy_size_mb = self.params.get("decoy_size_mb", 0)
                v_decoy_pw = self.params.get("decoy_password")

                if v_arch == "pvault" or str(v_path).lower().endswith(".pvault"):
                    from enclave_core import CustomVaultEngine
                    decoy_msg = " (Tuzak Kasa Korumalı)" if v_has_decoy else ""
                    self.log_signal.emit(f"Yeni bağımsız AES-256-GCM kasa oluşturuluyor: {Path(v_path).name}{decoy_msg}...", "info", "YENI KASA")
                    try:
                        v_2fa_secret = self.params.get("two_factor_secret")
                        v_2fa_backups = self.params.get("two_factor_backup_codes")
                        create_res = CustomVaultEngine.create_vault(
                            vault_path=v_path,
                            password=v_pw,
                            label=v_label,
                            decoy_password=v_decoy_pw if v_has_decoy else None,
                            max_size_gb=self.params.get("main_size_gb", v_size),
                            max_size_mb=self.params.get("main_size_mb"),
                            decoy_size_gb=v_decoy_size,
                            decoy_size_mb=v_decoy_size_mb,
                            is_dynamic=v_dynamic,
                            two_factor_secret=v_2fa_secret,
                            two_factor_backup_codes=v_2fa_backups
                        )
                        create_res["vault_type"] = "pvault"
                        self.log_signal.emit(f"Yeni bağımsız AES-256 kasa başarıyla oluşturuldu: {Path(v_path).name}", "success", "YENI KASA")
                        result.update(create_res)
                        result["success"] = True
                    except Exception as e:
                        self.log_signal.emit(f"Bağımsız kasa oluşturulamadı: {e}", "error", "HATA")
                        result["error"] = str(e)
                else:
                    decoy_label = f"{v_decoy_size_mb} MB" if v_decoy_size_mb else f"{v_decoy_size} GB"
                    main_label = f"{self.params.get('main_size_gb', v_size)} GB"
                    decoy_msg = f" (Ana: {main_label}, Tuzak: {decoy_label})" if v_has_decoy else ""
                    self.log_signal.emit(f"Yeni sanal disk oluşturuluyor: {Path(v_path).name} ({v_size} GB){decoy_msg}...", "info", "YENI KASA")
                    create_res = self.engine.create_new_vault(
                        vault_path=v_path,
                        size_gb=v_size,
                        is_dynamic=v_dynamic,
                        label=v_label,
                        bitlocker_password=v_pw,
                        has_decoy=v_has_decoy,
                        decoy_size_gb=v_decoy_size,
                        decoy_size_mb=v_decoy_size_mb,
                        decoy_password=v_decoy_pw
                    )
                    if create_res.get("success"):
                        self.log_signal.emit(f"Yeni kasa başarıyla oluşturuldu: {Path(v_path).name}", "success", "YENI KASA")
                        result.update(create_res)
                        result["success"] = True
                    else:
                        self.log_signal.emit(f"Kasa oluşturulamadı: {create_res.get('error')}", "error", "HATA")
                        result["error"] = create_res.get("error")

            elif self.action == "compact":
                v_path = self.params.get("vault_path")
                self.log_signal.emit(f"Kasa sıkıştırılıyor (Diskpart Compact): {Path(v_path).name}...", "info", "OPTIMIZE")
                compact_res = self.engine.compact_vdisk(v_path)
                if compact_res.get("success"):
                    pct = compact_res.get('saved_pct', 0)
                    saved = compact_res.get('saved_mb', 0)
                    init_mb = compact_res.get('initial_size_mb', 0)
                    fin_mb = compact_res.get('final_size_mb', 0)
                    msg = f"Sıkıştırma tamamlandı. Geri kazanılan alan: {saved} MB (%{pct}) | Eski: {init_mb} MB -> Yeni: {fin_mb} MB"
                    self.log_signal.emit(msg, "success", "OPTIMIZE")
                    result.update(compact_res)
                    result["success"] = True
                else:
                    self.log_signal.emit(f"Sıkıştırma hatası: {compact_res.get('error')}", "error", "HATA")
                    result["error"] = compact_res.get("error")

            elif self.action == "backup":
                v_path = self.params.get("vault_path")
                self.log_signal.emit(f"Kasa yedeği alınıyor: {Path(v_path).name}...", "info", "YEDEK")
                backup_res = self.engine.backup_vault(v_path)
                if backup_res.get("success"):
                    self.log_signal.emit(f"Yedekleme başarılı: {backup_res['backup_name']} ({backup_res['file_size_mb']} MB)", "success", "YEDEK")
                    result.update(backup_res)
                    result["success"] = True
                else:
                    self.log_signal.emit(f"Yedekleme hatası: {backup_res.get('error')}", "error", "HATA")
                    result["error"] = backup_res.get("error")

            elif self.action == "hash":
                v_path = self.params.get("vault_path")
                self.log_signal.emit(f"SHA-256 hash hesaplanıyor: {Path(v_path).name}...", "info", "BUTUNLUK")
                hash_res = self.engine.calculate_file_hash(
                    v_path,
                    progress_callback=lambda pct: self.progress_signal.emit(pct)
                )
                if hash_res.get("success"):
                    self.log_signal.emit(f"SHA-256 doğrulandı: {hash_res['sha256']}", "success", "BUTUNLUK")
                    result.update(hash_res)
                    result["success"] = True
                else:
                    self.log_signal.emit(f"Bütünlük kontrolü hatası: {hash_res.get('error')}", "error", "HATA")
                    result["error"] = hash_res.get("error")

            elif self.action == "windows_hello":
                target_vault = self.params.get("vault_path")
                prompt = self.params.get("prompt")
                self.log_signal.emit("Windows Hello biyometrik doğrulama bekleniyor...", "info", "BIYOMETRIK")
                pw, status = windows_hello.retrieve_vault_password_with_hello(target_vault, prompt=prompt)
                result["password"] = pw
                result["status"] = status
                result["success"] = (pw is not None and status == "Verified")

            elif self.action == "2fa_verify":
                target_vault = self.params.get("vault_path", "")
                prompt = self.params.get("prompt", "Enclave - 2FA Biyometrik Doğrulama")
                self.log_signal.emit("İki Faktörlü Doğrulama (2FA): Windows Hello biyometrik onayı bekleniyor...", "info", "2FA")
                is_verified, status = windows_hello.request_windows_hello_verification(prompt)
                result["verified"] = is_verified
                result["status"] = status
                result["success"] = is_verified

        except Exception as e:
            try:
                self.log_signal.emit(f"Beklenmeyen işlem hatası: {e}", "error", "HATA")
            except Exception:
                pass
            result["error"] = str(e)
            
        self.finished_signal.emit(result)

DWMWA_USE_IMMERSIVE_DARK_MODE = 20

def set_window_dark_mode(hwnd: int, is_dark: bool):
    """Windows 10/11 pencere başlık çubuğunun (Titlebar / Caption) koyu/açık temasını senkronize eder."""
    try:
        val = ctypes.c_int(1 if is_dark else 0)
        ctypes.windll.dwmapi.DwmSetWindowAttribute(
            int(hwnd),
            DWMWA_USE_IMMERSIVE_DARK_MODE,
            ctypes.byref(val),
            ctypes.sizeof(val)
        )
    except Exception:
        pass

class CreateVaultDialog(QDialog):
    """Yeni VHD/VHDX oluşturma ve BitLocker biçimlendirme sihirbazı."""
    def __init__(self, parent=None, theme: str = "dark"):
        super().__init__(parent)
        self.theme = theme
        self.setWindowTitle("Yeni Kasa Oluşturma Sihirbazı")
        self.setSizeGripEnabled(True)
        self.setModal(True)
        self.setWindowIcon(create_vault_icon("closed"))
        is_dark = self.theme in ("dark", "apple_dark")
        set_window_dark_mode(int(self.winId()), is_dark)
        set_dialog_dark_mode(self, is_dark)
        apply_dynamic_geometry(self, default_w=600, default_h=640, min_w=520, min_h=520)
        self.init_ui()

    def init_ui(self):
        pal = get_dialog_palette(self.theme)
        is_dark = pal["is_dark"]
        bg_col = pal["bg_col"]
        card_bg = pal["card_bg"]
        card_border = pal.get("card_border", "#3A3A3E" if is_dark else "#D1D1D6")
        inp_bg = pal.get("inp_bg", "#2C2C2E" if is_dark else "#FFFFFF")
        inp_border = pal.get("inp_border", "#48484A" if is_dark else "#CBD5E1")
        border_col = pal["border_col"]
        text_col = pal["text_col"]
        text_muted = pal["text_muted"]
        label_col = pal.get("label_col", "#E5E5EA" if is_dark else "#0F172A")
        placeholder_col = pal.get("placeholder_col", "#8E8E93" if is_dark else "#94A3B8")
        accent_col = pal["accent_col"]
        accent_hover = pal.get("accent_hover", "#0071E3")
        decoy_card_bg = "#2A2A2E" if self.theme == "apple_dark" else ("#111C2E" if is_dark else "#F0F4F8")

        self.setStyleSheet(f"""
            QDialog {{
                background-color: {bg_col};
                color: {text_col};
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
            }}
            QLabel {{
                color: {label_col};
                font-weight: 600;
                font-size: 12px;
            }}
            QScrollArea {{
                background: transparent;
                border: none;
            }}
            QScrollArea > QWidget > QWidget {{
                background: transparent;
            }}
            QFrame#form-card {{
                background-color: {card_bg};
                border: 1px solid {card_border};
                border-radius: 12px;
            }}
            QLineEdit, QSpinBox, QComboBox {{
                background-color: {inp_bg};
                border: 1px solid {inp_border};
                border-radius: 8px;
                padding: 7px 12px;
                color: {text_col};
                font-size: 12px;
                min-height: 18px;
                selection-background-color: {accent_col};
                selection-color: #FFFFFF;
            }}
            QLineEdit:hover, QSpinBox:hover, QComboBox:hover {{
                border: 1px solid {'#636366' if is_dark else '#94A3B8'};
            }}
            QLineEdit:focus, QSpinBox:focus, QComboBox:focus {{
                border: 2px solid {accent_col};
                background-color: {'#323236' if self.theme == 'apple_dark' else ('#111827' if is_dark else '#FFFFFF')};
            }}
            QComboBox::drop-down {{
                border: none;
                width: 24px;
                padding-right: 6px;
            }}
            QComboBox QAbstractItemView {{
                background-color: {card_bg};
                border: 1px solid {inp_border};
                border-radius: 6px;
                color: {text_col};
                selection-background-color: {accent_col};
                selection-color: #FFFFFF;
                padding: 4px;
            }}
            QSpinBox::up-button, QSpinBox::down-button {{
                border: none;
                width: 18px;
                background: transparent;
            }}
            QCheckBox {{
                color: {label_col};
                font-size: 11.5px;
                font-weight: 600;
                spacing: 8px;
            }}
            QCheckBox::indicator {{
                width: 18px;
                height: 18px;
                border-radius: 5px;
                border: 1px solid {inp_border};
                background-color: {inp_bg};
            }}
            QCheckBox::indicator:hover {{
                border: 1px solid {accent_col};
            }}
            QCheckBox::indicator:checked {{
                background-color: {accent_col};
                border: 1px solid {accent_col};
            }}
            {get_dialog_button_stylesheet(self.theme)}
        """)

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(22, 20, 22, 18)
        main_layout.setSpacing(12)

        title_box = QHBoxLayout()
        title_box.setSpacing(10)
        title_icon = QLabel()
        title_icon.setPixmap(get_svg_pixmap("plus_circle", accent_col, 22))
        title_box.addWidget(title_icon)

        title = QLabel("Yeni Güvenli Sanal Kasa Oluştur")
        title.setStyleSheet(f"font-size: 14px; font-weight: 800; color: {accent_col};")
        title_box.addWidget(title)
        title_box.addStretch()
        main_layout.addLayout(title_box)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        scroll_content = QWidget()
        content_layout = QVBoxLayout(scroll_content)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(10)

        form_card = QFrame()
        form_card.setObjectName("form-card")
        form_card_layout = QVBoxLayout(form_card)
        form_card_layout.setContentsMargins(18, 16, 18, 16)
        form_card_layout.setSpacing(12)

        form = QFormLayout()
        form.setSpacing(12)

        self.combo_arch = QComboBox()
        self.combo_arch.addItems([
            "BitLocker Sanal Disk (VHD / VHDX - Yerel Sürücü)",
            "Bağımsız AES-256-GCM Kasa (.pvault - Sürücüsüz, Taşınabilir)"
        ])
        self.combo_arch.setToolTip("Kasa mimarisini seçin: Windows BitLocker sanal disk veya bağımsız taşınabilir dosya yöneticisi.")
        self.combo_arch.currentIndexChanged.connect(self.on_architecture_changed)
        form.addRow("Kasa Mimarisi:", self.combo_arch)
        self.combo_architecture = self.combo_arch

        self.txt_name = QLineEdit("ozel_kasa.vhd")
        form.addRow("Kasa Dosya Adı:", self.txt_name)

        self.lbl_type_row = QLabel("Disk Türü:")
        self.combo_type = QComboBox()
        self.combo_type.addItems(["VHD (Evrensel Uyumlu)", "VHDX (Gelişmiş - Win8+)"])
        self.combo_type.currentIndexChanged.connect(self.on_type_changed)

        self.lbl_pvault_type_info = QLabel("Bağımsız AES-256-GCM Şifreli Dosya Kapsayıcısı (.pvault)")
        self.lbl_pvault_type_info.setWordWrap(True)
        self.lbl_pvault_type_info.setStyleSheet(f"color: {accent_col}; font-weight: 700; font-size: 11px;")
        self.lbl_pvault_type_info.hide()

        type_widget = QWidget()
        type_layout = QHBoxLayout(type_widget)
        type_layout.setContentsMargins(0, 0, 0, 0)
        type_layout.setSpacing(0)
        type_layout.addWidget(self.combo_type)
        type_layout.addWidget(self.lbl_pvault_type_info)
        form.addRow(self.lbl_type_row, type_widget)

        self.spin_size = QSpinBox()
        self.spin_size.setRange(1, 2048)
        self.spin_size.setValue(10)
        self.spin_size.setSuffix(" GB")
        self.spin_size.valueChanged.connect(self.update_decoy_limits)

        self.lbl_size_row = QLabel("Ana Kasa Boyutu:")
        form.addRow(self.lbl_size_row, self.spin_size)

        self.combo_alloc = QComboBox()
        self.combo_alloc.addItems(["Dinamik (Kullanıldıkça Büyüyen - Önerilen)", "Sabit Boyut (Maksimum Performans)"])
        form.addRow("Tahsis Formatı:", self.combo_alloc)

        self.txt_label = QLineEdit("Kasa")
        form.addRow("Birim Adı (Etiket):", self.txt_label)

        self.txt_pw = QLineEdit()
        self.txt_pw.setEchoMode(QLineEdit.EchoMode.Password)
        self.txt_pw.setPlaceholderText("Ana Kasa Parolası (Min 6-8 karakter)")
        self.lbl_pw_title = QLabel("BitLocker Parolası:")
        form.addRow(self.lbl_pw_title, self.txt_pw)

        self.txt_pw_confirm = QLineEdit()
        self.txt_pw_confirm.setEchoMode(QLineEdit.EchoMode.Password)
        self.txt_pw_confirm.setPlaceholderText("Parolayı tekrar girin")
        form.addRow("Parola Doğrulama:", self.txt_pw_confirm)

        self.chk_decoy = QCheckBox("Gömülü Tuzak Kasa (Decoy Vault / Kamuflaj) Ekle")
        self.chk_decoy.setCursor(Qt.CursorShape.PointingHandCursor)
        self.chk_decoy.setToolTip("Ana kasanın yanına tamamen bağımsız ikinci bir tuzak kasa açar. Tehdit ve zorlama anında sahte parola verilerek ana kasa gizlenir.")
        self.chk_decoy.stateChanged.connect(self.on_decoy_toggled)
        form.addRow("", self.chk_decoy)

        self.frame_decoy = QFrame()
        self.frame_decoy.setObjectName("decoy-frame")
        self.frame_decoy_layout = QVBoxLayout(self.frame_decoy)
        self.frame_decoy_layout.setContentsMargins(14, 12, 14, 12)
        self.frame_decoy_layout.setSpacing(8)

        self.lbl_decoy_hint = QLabel("<b>Gömülü Tuzak Kasa:</b> Sanal disk içine gizli 2. bir bölüm açılır. Zorlama anında bu parolayı verirseniz sadece yem veriler açılır, ana verileriniz asla görünmez.")
        self.lbl_decoy_hint.setWordWrap(True)
        self.lbl_decoy_hint.setStyleSheet(f"color: {accent_col}; font-size: 10.5px; font-weight: normal; margin-bottom: 4px;")
        self.frame_decoy_layout.addWidget(self.lbl_decoy_hint)

        decoy_form = QFormLayout()
        decoy_form.setSpacing(8)

        decoy_size_row = QHBoxLayout()
        decoy_size_row.setSpacing(6)

        self.spin_decoy_size = QSpinBox()
        self.spin_decoy_size.setRange(50, 512000)
        self.spin_decoy_size.setValue(500)
        self.spin_decoy_size.setSingleStep(50)
        self.spin_decoy_size.setSuffix(" MB")
        self.spin_decoy_size.valueChanged.connect(self.update_decoy_summary)

        self.combo_decoy_unit = QComboBox()
        self.combo_decoy_unit.addItems(["MB", "GB"])
        self.combo_decoy_unit.setMinimumWidth(65)
        self.combo_decoy_unit.currentIndexChanged.connect(self.on_decoy_unit_changed)

        decoy_size_row.addWidget(self.spin_decoy_size, 1)
        decoy_size_row.addWidget(self.combo_decoy_unit)
        decoy_form.addRow("Tuzak Kasa Boyutu:", decoy_size_row)

        self.lbl_decoy_summary = QLabel("")
        self.lbl_decoy_summary.setWordWrap(True)
        self.lbl_decoy_summary.setStyleSheet(f"color: {accent_col}; font-size: 10.5px; font-weight: 700;")
        decoy_form.addRow("Kapasite Dağılımı:", self.lbl_decoy_summary)

        self.txt_decoy_pw = QLineEdit()
        self.txt_decoy_pw.setEchoMode(QLineEdit.EchoMode.Password)
        self.txt_decoy_pw.setPlaceholderText("Tuzak Kasa Parolası (Min 6-8 karakter)")
        decoy_form.addRow("Tuzak Parolası:", self.txt_decoy_pw)

        self.txt_decoy_pw_confirm = QLineEdit()
        self.txt_decoy_pw_confirm.setEchoMode(QLineEdit.EchoMode.Password)
        self.txt_decoy_pw_confirm.setPlaceholderText("Tuzak parolasını tekrar girin")
        decoy_form.addRow("Tuzak Parola Tekrar:", self.txt_decoy_pw_confirm)

        self.frame_decoy_layout.addLayout(decoy_form)
        self.frame_decoy.hide()

        self.frame_decoy.setStyleSheet(f"""
            QFrame#decoy-frame {{
                background-color: {decoy_card_bg};
                border: 1.5px solid {accent_col};
                border-radius: 10px;
            }}
        """)

        form.addRow("", self.frame_decoy)

        self.chk_show_pw = QCheckBox("Parolaları Göster")
        self.chk_show_pw.setCursor(Qt.CursorShape.PointingHandCursor)
        self.chk_show_pw.stateChanged.connect(self.toggle_show_passwords)
        form.addRow("", self.chk_show_pw)

        self.chk_create_2fa = QCheckBox("Bu kasayı İki Faktörlü Doğrulama (TOTP: Şifre + Authenticator) ile mühürle [TAVSİYE EDİLEN]")
        self.chk_create_2fa.setChecked(False)
        self.chk_create_2fa.setCursor(Qt.CursorShape.PointingHandCursor)
        self.chk_create_2fa.setToolTip("Kasa oluşturulurken telefonunuzdaki Google/Microsoft Authenticator ile mühürlenir. Sandbox veya başka cihazlarda dahi 2FA asla atlatılamaz.")
        self.chk_create_2fa.hide()
        form.addRow("", self.chk_create_2fa)

        self.spin_size.valueChanged.connect(self.update_decoy_limits)
        self.combo_alloc.currentIndexChanged.connect(self.update_decoy_summary)

        form_card_layout.addLayout(form)
        content_layout.addWidget(form_card)
        scroll.setWidget(scroll_content)
        main_layout.addWidget(scroll, 1)

        footer_box = QVBoxLayout()
        footer_box.setSpacing(8)
        footer_box.setContentsMargins(0, 4, 0, 0)

        err_col = "#EF4444" if is_dark else "#DC2626"
        self.lbl_error = QLabel("")
        self.lbl_error.setWordWrap(True)
        self.lbl_error.setStyleSheet(f"color: {err_col}; font-size: 11.5px; font-weight: 600;")
        self.lbl_error.hide()
        footer_box.addWidget(self.lbl_error)

        btn_box = QHBoxLayout()
        btn_box.setSpacing(10)
        btn_box.addStretch()

        btn_cancel = QPushButton("İptal")
        btn_cancel.setMinimumWidth(80)
        btn_cancel.setMinimumHeight(36)
        btn_cancel.clicked.connect(self.reject)
        btn_box.addWidget(btn_cancel)

        self.btn_submit = QPushButton("Oluştur ve Biçimlendir")
        self.btn_submit.setObjectName("btn-create")
        self.btn_submit.setMinimumWidth(140)
        self.btn_submit.setMinimumHeight(36)
        self.btn_submit.setStyleSheet(f"""
            QPushButton#btn-create {{
                background-color: {accent_col};
                color: #FFFFFF;
                border: 1px solid {accent_col};
                border-radius: 8px;
                font-family: -apple-system, 'SF Pro Text', 'Segoe UI Variable', sans-serif;
                font-weight: 700;
                font-size: 11.5px;
                padding: 6px 18px;
            }}
            QPushButton#btn-create:hover {{
                background-color: {'#38BDF8' if is_dark else '#0284C7'};
                border-color: {'#38BDF8' if is_dark else '#0284C7'};
            }}
            QPushButton#btn-create:pressed {{
                padding-top: 8px;
            }}
        """)
        self.btn_submit.clicked.connect(self.validate_and_accept)
        btn_box.addWidget(self.btn_submit)

        footer_box.addLayout(btn_box)
        main_layout.addLayout(footer_box)

    @property
    def selected_architecture(self) -> int:
        return self.combo_arch.currentIndex()

    def on_decoy_unit_changed(self, index):
        unit = self.combo_decoy_unit.currentText()
        cur_val = self.spin_decoy_size.value()
        self.spin_decoy_size.blockSignals(True)
        if unit == "MB":
            self.spin_decoy_size.setSuffix(" MB")
            self.spin_decoy_size.setSingleStep(50)
            self.spin_decoy_size.setRange(50, 512000)
            new_val = cur_val * 1024 if cur_val < 50 else cur_val
            self.spin_decoy_size.setValue(min(512000, max(50, new_val)))
        else:
            self.spin_decoy_size.setSuffix(" GB")
            self.spin_decoy_size.setSingleStep(1)
            self.spin_decoy_size.setRange(1, 500)
            new_val = max(1, cur_val // 1024 if cur_val >= 50 else cur_val)
            self.spin_decoy_size.setValue(min(500, new_val))
        self.spin_decoy_size.blockSignals(False)
        self.update_decoy_summary()

    def on_decoy_toggled(self, state):
        checked = self.chk_decoy.isChecked()
        if checked:
            self.frame_decoy.show()
            self.update_decoy_limits()
        else:
            self.frame_decoy.hide()
        self.adjustSize()

    def update_decoy_limits(self):
        self.update_decoy_summary()

    def update_decoy_summary(self):
        if not self.chk_decoy.isChecked():
            return
        main_gb = self.spin_size.value()
        main_mb = main_gb * 1024
        unit = self.combo_decoy_unit.currentText() if hasattr(self, "combo_decoy_unit") else "MB"
        val = self.spin_decoy_size.value()
        decoy_mb = val if unit == "MB" else (val * 1024)
        decoy_gb = decoy_mb / 1024.0

        total_mb = main_mb + decoy_mb
        total_gb = total_mb / 1024.0

        main_str = f"{main_gb} GB"
        decoy_str = f"{decoy_gb:.1f} GB" if decoy_mb >= 1024 else f"{decoy_mb} MB"
        total_str = f"{total_gb:.1f} GB" if total_gb >= 1 else f"{total_mb} MB"

        is_pvault = (self.selected_architecture == 1)
        alloc = "Dinamik" if self.combo_alloc.currentIndex() == 0 else "Sabit"
        if is_pvault:
            self.lbl_decoy_summary.setText(f"Ana: {main_str} | Tuzak: {decoy_str} -> Toplam Kota: {total_str} ({alloc})")
        else:
            self.lbl_decoy_summary.setText(f"Ana: {main_str} | Tuzak: {decoy_str} -> Toplam Disk: {total_str} ({alloc})")

    def toggle_show_passwords(self, state):
        mode = QLineEdit.EchoMode.Normal if self.chk_show_pw.isChecked() else QLineEdit.EchoMode.Password
        self.txt_pw.setEchoMode(mode)
        self.txt_pw_confirm.setEchoMode(mode)
        if hasattr(self, "txt_decoy_pw"):
            self.txt_decoy_pw.setEchoMode(mode)
        if hasattr(self, "txt_decoy_pw_confirm"):
            self.txt_decoy_pw_confirm.setEchoMode(mode)

    def on_architecture_changed(self, index):
        is_pvault = (index == 1)
        cur = self.txt_name.text()
        base = Path(cur).stem

        self.combo_alloc.blockSignals(True)
        self.combo_alloc.clear()
        if is_pvault:
            self.combo_alloc.addItems([
                "Dinamik (Dosya Eklendikçe Büyüyen - Önerilen)",
                "Sabit Boyut (Maksimum Gizlilik / Ön Tahsisli)"
            ])
        else:
            self.combo_alloc.addItems([
                "Dinamik (Kullanıldıkça Büyüyen - Önerilen)",
                "Sabit Boyut (Maksimum Performans)"
            ])
        self.combo_alloc.setEnabled(True)
        self.combo_alloc.blockSignals(False)

        if is_pvault:
            self.txt_name.setText(f"{base}.pvault")
            self.lbl_type_row.setText("Konteyner:")
            self.combo_type.hide()
            self.lbl_pvault_type_info.show()
            self.lbl_pw_title.setText("AES-256 Parolası:")
            self.lbl_decoy_hint.setText("<b>Plausible Deniability:</b> Bağımsız kasada tuzak parola girildiğinde sahte dosyalar açılır. Matematiksel olarak kasanın içinde tuzak kasa olup olmadığı adli bilişim araçlarıyla kanıtlanamaz.")
            if hasattr(self, "chk_create_2fa"):
                self.chk_create_2fa.show()
                self.chk_create_2fa.setChecked(True)
            self.update_decoy_limits()
        else:
            ext = ".vhd" if self.combo_type.currentIndex() == 0 else ".vhdx"
            self.txt_name.setText(f"{base}{ext}")
            self.lbl_type_row.setText("Disk Türü:")
            self.lbl_pvault_type_info.hide()
            self.combo_type.show()
            self.lbl_pw_title.setText("BitLocker Parolası:")
            self.lbl_decoy_hint.setText("<b>Gömülü Tuzak Kasa:</b> Sanal disk içine gizli 2. bir NTFS bölümü açılır. Girişte tuzak şifresi yazılırsa yalnızca bu bölüm açılır; ana kasa Gezgin'de tamamen gizlenir.")
            if hasattr(self, "chk_create_2fa"):
                self.chk_create_2fa.hide()
                self.chk_create_2fa.setChecked(False)
            self.update_decoy_limits()

    def on_type_changed(self, index):
        if self.selected_architecture == 1:
            return
        ext = ".vhd" if index == 0 else ".vhdx"
        cur = self.txt_name.text()
        base = Path(cur).stem
        self.txt_name.setText(f"{base}{ext}")

    def validate_and_accept(self):
        name = self.txt_name.text().strip()
        if not name:
            self.lbl_error.setText("Lütfen geçerli bir dosya adı girin.")
            self.lbl_error.show()
            return

        is_pvault = (self.selected_architecture == 1)
        has_decoy = self.chk_decoy.isChecked()
        pw = self.txt_pw.text().strip()
        pw_c = self.txt_pw_confirm.text().strip()

        if is_pvault:
            if not pw:
                self.lbl_error.setText("Lütfen kasa parolasını girin.")
                self.lbl_error.show()
                return
            if len(pw) < 8:
                self.lbl_error.setText("Kasa parolası en az 8 karakter olmalıdır.")
                self.lbl_error.show()
                return
            if pw != pw_c:
                self.lbl_error.setText("Kasa parolaları birbiriyle eşleşmiyor.")
                self.lbl_error.show()
                return
            if has_decoy:
                decoy_pw = self.txt_decoy_pw.text().strip()
                decoy_pw_c = self.txt_decoy_pw_confirm.text().strip()
                if not decoy_pw:
                    self.lbl_error.setText("Lütfen tuzak kasa için bir parola belirleyin.")
                    self.lbl_error.show()
                    return
                if len(decoy_pw) < 8:
                    self.lbl_error.setText("Tuzak kasa parolası en az 8 karakter olmalıdır.")
                    self.lbl_error.show()
                    return
                if decoy_pw != decoy_pw_c:
                    self.lbl_error.setText("Tuzak kasa parolaları birbiriyle eşleşmiyor.")
                    self.lbl_error.show()
                    return
                if pw == decoy_pw:
                    self.lbl_error.setText("Ana kasa parolası ile tuzak kasa parolası AYNI OLAMAZ! Farklı bir şifre girin.")
                    self.lbl_error.show()
                    return

            if is_pvault and getattr(self, "chk_create_2fa", None) and self.chk_create_2fa.isChecked():
                from extra_dialogs import TOTPSetupDialog
                v_name = self.txt_name.text().strip()
                totp_dlg = TOTPSetupDialog(
                    parent=self,
                    vault_path=str(VAULTS_DIR / v_name),
                    theme=self.theme,
                    initial_password=pw,
                    is_creation_mode=True
                )
                if totp_dlg.exec() == QDialog.DialogCode.Accepted:
                    self.totp_secret = totp_dlg.totp_secret
                    self.backup_codes = totp_dlg.backup_codes
                else:
                    self.lbl_error.setText("2FA kurulumu tamamlanmadı. Kasa oluşturmak için lütfen 2FA'yı doğrulayın veya 2FA onay kutusunun işaretini kaldırın.")
                    self.lbl_error.show()
                    return
            else:
                self.totp_secret = None
                self.backup_codes = None

            self.lbl_error.hide()
            self.accept()
            return

        if has_decoy:
            if not pw:
                self.lbl_error.setText("Tuzak kasa özelliği için ana kasaya BitLocker parolası zorunludur.")
                self.lbl_error.show()
                return
            if len(pw) < 8:
                self.lbl_error.setText("Ana kasa BitLocker parolası en az 8 karakter olmalıdır.")
                self.lbl_error.show()
                return
            if pw != pw_c:
                self.lbl_error.setText("Ana kasa parolaları birbiriyle eşleşmiyor.")
                self.lbl_error.show()
                return

            decoy_pw = self.txt_decoy_pw.text().strip()
            decoy_pw_c = self.txt_decoy_pw_confirm.text().strip()
            if not decoy_pw:
                self.lbl_error.setText("Lütfen tuzak kasa için bir BitLocker parolası belirleyin.")
                self.lbl_error.show()
                return
            if len(decoy_pw) < 8:
                self.lbl_error.setText("Tuzak kasa parolası en az 8 karakter olmalıdır.")
                self.lbl_error.show()
                return
            if decoy_pw != decoy_pw_c:
                self.lbl_error.setText("Tuzak kasa parolaları birbiriyle eşleşmiyor.")
                self.lbl_error.show()
                return
            if pw == decoy_pw:
                self.lbl_error.setText("Ana kasa parolası ile tuzak kasa parolası AYNI OLAMAZ! Farklı bir şifre girin.")
                self.lbl_error.show()
                return
        else:
            if pw or pw_c:
                if pw != pw_c:
                    self.lbl_error.setText("BitLocker parolaları birbiriyle eşleşmiyor.")
                    self.lbl_error.show()
                    return
                if len(pw) < 8:
                    self.lbl_error.setText("BitLocker parolası en az 8 karakter olmalıdır.")
                    self.lbl_error.show()
                    return

        self.lbl_error.hide()
        self.accept()

    def get_vault_params(self) -> dict:
        name = self.txt_name.text().strip()
        is_pvault = (self.selected_architecture == 1)
        if is_pvault and not name.lower().endswith(".pvault"):
            name = f"{Path(name).stem}.pvault"
        target_path = VAULTS_DIR / name

        has_decoy = self.chk_decoy.isChecked()
        unit = self.combo_decoy_unit.currentText() if has_decoy else "MB"
        val = self.spin_decoy_size.value() if has_decoy else 0
        decoy_mb = val if unit == "MB" else (val * 1024)
        decoy_gb = max(1, int(math.ceil(decoy_mb / 1024.0))) if has_decoy else 0

        main_gb = self.spin_size.value()
        main_mb = main_gb * 1024

        if has_decoy:
            total_mb = main_mb + decoy_mb
            total_gb = int(math.ceil(total_mb / 1024.0))
        else:
            total_mb = main_mb
            total_gb = main_gb

        has_2fa = is_pvault and getattr(self, "chk_create_2fa", None) and self.chk_create_2fa.isChecked() and bool(getattr(self, "totp_secret", None))
        return {
            "architecture": "pvault" if is_pvault else "vhd",
            "vault_path": str(target_path),
            "size_gb": total_gb,
            "main_size_gb": main_gb,
            "main_size_mb": main_mb,
            "is_dynamic": (self.combo_alloc.currentIndex() == 0),
            "label": self.txt_label.text().strip() or "Kasa",
            "password": self.txt_pw.text().strip() or None,
            "has_decoy": has_decoy,
            "decoy_size_gb": decoy_gb,
            "decoy_size_mb": decoy_mb,
            "decoy_password": self.txt_decoy_pw.text().strip() if has_decoy else None,
            "has_2fa": has_2fa,
            "two_factor_secret": getattr(self, "totp_secret", None) if has_2fa else None,
            "two_factor_backup_codes": getattr(self, "backup_codes", None) if has_2fa else None
        }

def get_apple_dark_qss() -> str:
    """Apple macOS Space Gray Minimalist Koyu Tema (Sade, Goz Yormayan, Rafine)."""
    return """
        QMainWindow {
            background-color: #121214;
        }
        QWidget {
            color: #F5F5F7;
            font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
            font-size: 12px;
        }
        QDialog {
            background-color: #161618;
            color: #F5F5F7;
        }
        QScrollArea {
            background-color: transparent;
            border: none;
        }
        QFrame.card {
            background-color: #1C1C1F;
            border: 1px solid rgba(255, 255, 255, 0.12);
            border-radius: 14px;
        }
        QFrame.card-bitlocker {
            background-color: #161D2B;
            border: 1px solid rgba(41, 151, 255, 0.35);
            border-radius: 14px;
        }
        QLabel {
            background: transparent;
            color: #F5F5F7;
            font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
        }
        QPushButton {
            background-color: #26262A;
            color: #F5F5F7;
            font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
            font-size: 11.5px;
            font-weight: 600;
            padding: 5px 14px;
            border: 1px solid rgba(255, 255, 255, 0.14);
            border-radius: 7px;
            min-height: 20px;
        }
        QPushButton:hover {
            background-color: #323238;
            border-color: #2997FF;
            color: #2997FF;
            cursor: pointer;
        }
        QPushButton:pressed {
            background-color: #1C1C1E;
            border-color: #2997FF;
            padding-top: 8px;
            padding-left: 17px;
        }
        QPushButton:disabled {
            background-color: #1C1C1E;
            color: #636366;
            border-color: rgba(255, 255, 255, 0.05);
        }
        QPushButton#btn-toolbar {
            background-color: #26262A;
            color: #D1D1D6;
            font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
            font-size: 11px;
            font-weight: 600;
            padding: 4px 10px;
            border: 1px solid rgba(255, 255, 255, 0.12);
            border-radius: 6px;
            min-height: 18px;
        }
        QPushButton#btn-toolbar:hover {
            background-color: #323238;
            border-color: #2997FF;
            color: #2997FF;
            cursor: pointer;
        }
        QPushButton#btn-toolbar:pressed {
            background-color: #1C1C1E;
        }
        QPushButton#btn-toolbar:disabled {
            background-color: #1C1C1E;
            color: #636366;
            border-color: rgba(255, 255, 255, 0.05);
        }
        QPushButton#btn-browse {
            background-color: #2C2C30;
            color: #F5F5F7;
            font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
            font-size: 11px;
            font-weight: 600;
            padding: 4px 12px;
            border: 1px solid rgba(255, 255, 255, 0.16);
            border-radius: 6px;
            min-height: 18px;
        }
        QPushButton#btn-browse:hover {
            background-color: #383840;
            border-color: #2997FF;
            color: #2997FF;
            cursor: pointer;
        }
        QPushButton#btn-browse:pressed {
            background-color: #1C1C1E;
        }
        QPushButton#btn-browse:disabled {
            background-color: #1C1C1E;
            color: #636366;
            border-color: rgba(255, 255, 255, 0.05);
        }
        QPushButton#btn-mount, QPushButton#btn-primary, QPushButton#btn-mount {
            background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #0077ED, stop:1 #0062CC);
            color: #FFFFFF;
            font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
            font-size: 12px;
            font-weight: 600;
            padding: 6px 16px;
            border: 1px solid #2997FF;
            border-radius: 7px;
            min-height: 22px;
        }
        QPushButton#btn-mount:hover, QPushButton#btn-primary:hover, QPushButton#btn-mount:hover {
            background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #1E88E5, stop:1 #0077ED);
            border-color: #58A6FF;
            cursor: pointer;
        }
        QPushButton#btn-mount:pressed, QPushButton#btn-primary:pressed, QPushButton#btn-mount:pressed {
            background: #005BB5;
            padding-top: 10px;
            padding-left: 25px;
        }
        QPushButton#btn-mount:disabled, QPushButton#btn-primary:disabled {
            background-color: #2C2C2E;
            color: #636366;
            border: 1px solid rgba(255, 255, 255, 0.08);
        }
        QPushButton#btn-open-explorer, QPushButton#btn-success, QPushButton#btn-open-explorer {
            background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #30D158, stop:1 #248A3D);
            color: #FFFFFF;
            font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
            font-size: 12px;
            font-weight: 600;
            padding: 6px 16px;
            border: 1px solid #30D158;
            border-radius: 7px;
            min-height: 22px;
        }
        QPushButton#btn-open-explorer:hover, QPushButton#btn-success:hover, QPushButton#btn-open-explorer:hover {
            background-color: #34C759;
            border-color: #4CD964;
            cursor: pointer;
        }
        QPushButton#btn-open-explorer:pressed, QPushButton#btn-success:pressed, QPushButton#btn-open-explorer:pressed {
            background-color: #1E7A34;
            padding-top: 10px;
            padding-left: 23px;
        }
        QPushButton#btn-open-explorer:disabled, QPushButton#btn-success:disabled {
            background-color: #2C2C2E;
            color: #636366;
            border: 1px solid rgba(255, 255, 255, 0.08);
        }
        QPushButton#btn-dismount, QPushButton#btn-danger, QPushButton#btn-dismount {
            background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #FF453A, stop:1 #D70015);
            color: #FFFFFF;
            font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
            font-size: 12px;
            font-weight: 600;
            padding: 6px 16px;
            border: 1px solid #FF453A;
            border-radius: 7px;
            min-height: 22px;
        }
        QPushButton#btn-dismount:hover, QPushButton#btn-danger:hover, QPushButton#btn-dismount:hover {
            background-color: #FF5B52;
            border-color: #FF857E;
            cursor: pointer;
        }
        QPushButton#btn-dismount:pressed, QPushButton#btn-danger:pressed, QPushButton#btn-dismount:pressed {
            background-color: #B31D14;
            padding-top: 10px;
            padding-left: 23px;
        }
        QPushButton#btn-dismount:disabled, QPushButton#btn-danger:disabled {
            background-color: #2C2C2E;
            color: #636366;
            border: 1px solid rgba(255, 255, 255, 0.08);
        }
        QPushButton#btn-accent {
            background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #0077ED, stop:1 #0062CC);
            color: #FFFFFF;
            font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
            font-size: 12.5px;
            font-weight: 700;
            padding: 7px 18px;
            border: 1px solid #2997FF;
            border-radius: 8px;
            min-height: 32px;
        }
        QPushButton#btn-accent:hover {
            background: #0077ED;
            border-color: #58A6FF;
            cursor: pointer;
        }
        QPushButton#btn-accent:pressed {
            background: #005BB5;
            padding-top: 8px;
            padding-left: 19px;
        }
        QComboBox {
            background-color: #1C1C1F;
            border: 1px solid rgba(255, 255, 255, 0.14);
            border-radius: 8px;
            padding: 7px 12px;
            color: #F5F5F7;
            font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
            font-size: 12px;
            font-weight: 600;
            min-height: 32px;
        }
        QComboBox:hover {
            border: 1px solid #2997FF;
        }
        QComboBox:focus {
            border: 1px solid #2997FF;
            background-color: #242428;
        }
        QComboBox:disabled {
            background-color: #1C1C1E;
            color: #636366;
            border-color: rgba(255, 255, 255, 0.06);
        }
        QComboBox::drop-down {
            subcontrol-origin: padding;
            subcontrol-position: top right;
            width: 24px;
            border-left: none;
            border-top-right-radius: 8px;
            border-bottom-right-radius: 8px;
        }
        QComboBox QAbstractItemView {
            background-color: #212124;
            color: #F5F5F7;
            font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
            font-size: 11.5px;
            border: 1px solid rgba(255, 255, 255, 0.15);
            border-radius: 8px;
            selection-background-color: #2997FF;
            selection-color: #FFFFFF;
            padding: 4px;
            outline: none;
        }
        QLineEdit, QSpinBox {
            background-color: #1C1C1E;
            border: 1px solid rgba(255, 255, 255, 0.14);
            border-radius: 8px;
            padding: 7px 12px;
            color: #F5F5F7;
            font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
            font-size: 12px;
            font-weight: 600;
            min-height: 32px;
        }
        QLineEdit:focus, QSpinBox:focus {
            border: 1px solid #2997FF;
            background-color: #262629;
        }
        QLineEdit:disabled, QSpinBox:disabled {
            background-color: #161618;
            color: #636366;
            border-color: rgba(255, 255, 255, 0.06);
        }
        QCheckBox {
            color: #F5F5F7;
            font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
            font-size: 12px;
            font-weight: 500;
            spacing: 10px;
        }
        QCheckBox:disabled {
            color: #636366;
        }
        QCheckBox::indicator {
            width: 18px;
            height: 18px;
            border-radius: 5px;
            border: 1px solid #636366;
            background-color: #1C1C1E;
        }
        QCheckBox::indicator:hover {
            border-color: #2997FF;
        }
        QCheckBox::indicator:checked {
            background-color: #2997FF;
            border: 1px solid #2997FF;
        }
        QProgressBar {
            background-color: #242428;
            border: 1px solid rgba(255, 255, 255, 0.10);
            border-radius: 6px;
            height: 12px;
            text-align: center;
            color: transparent;
        }
        QProgressBar::chunk {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #2997FF, stop:1 #30D158);
            border-radius: 5px;
        }
        QTextEdit {
            background-color: #101012;
            border: 1px solid rgba(255, 255, 255, 0.10);
            border-radius: 10px;
            color: #30D158;
            font-family: 'SF Mono', 'JetBrains Mono', 'Cascadia Code', 'Consolas', monospace;
            font-size: 11.5px;
            padding: 10px;
        }
        QMenu {
            background-color: #212124;
            border: 1px solid rgba(255, 255, 255, 0.14);
            border-radius: 10px;
            padding: 5px;
            color: #F5F5F7;
            font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
            font-size: 11.5px;
        }
        QMenu::item {
            padding: 7px 16px;
            border-radius: 6px;
            color: #F5F5F7;
            font-weight: 600;
        }
        QMenu::item:selected {
            background-color: #2C2C30;
            color: #2997FF;
        }
        QMenu::item:disabled {
            color: #636366;
        }
        QMenu::separator {
            height: 1px;
            background-color: rgba(255, 255, 255, 0.10);
            margin: 4px 6px;
        }
        QDialog QLabel {
            color: #F5F5F7;
            font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
            font-size: 12px;
            font-weight: 600;
        }
        QDialog QPushButton, QDialogButtonBox QPushButton {
            background-color: #26262A;
            color: #F5F5F7;
            font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
            border: 1px solid rgba(255, 255, 255, 0.14);
            border-radius: 8px;
            padding: 7px 18px;
            min-width: 76px;
            font-weight: 600;
            font-size: 11.5px;
        }
        QDialog QPushButton:hover, QDialogButtonBox QPushButton:hover {
            background-color: #323238;
            border-color: #2997FF;
            color: #2997FF;
            cursor: pointer;
        }
        QDialog QPushButton:pressed, QDialogButtonBox QPushButton:pressed {
            background-color: #1C1C1E;
            padding-top: 8px;
            padding-left: 19px;
        }
        QMessageBox {
            background-color: #161618;
            color: #F5F5F7;
            font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
        }
        QMessageBox QLabel {
            color: #F5F5F7;
            font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
            font-size: 12px;
            font-weight: 600;
        }
        QMessageBox QPushButton {
            background-color: #26262A;
            color: #F5F5F7;
            font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
            border: 1px solid rgba(255, 255, 255, 0.14);
            border-radius: 8px;
            padding: 7px 18px;
            min-width: 76px;
            font-weight: 600;
            font-size: 11.5px;
        }
        QMessageBox QPushButton:hover {
            background-color: #323238;
            border-color: #2997FF;
            color: #2997FF;
            cursor: pointer;
        }
        QToolTip {
            background-color: #262629;
            color: #F5F5F7;
            border: 1px solid rgba(255, 255, 255, 0.15);
            padding: 6px 12px;
            border-radius: 6px;
            font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
            font-size: 11px;
        }
        QScrollBar:vertical {
            background-color: transparent;
            width: 6px;
            border-radius: 3px;
            margin: 2px;
        }
        QScrollBar::handle:vertical {
            background-color: #3A3A3C;
            min-height: 18px;
            border-radius: 3px;
        }
        QScrollBar::handle:vertical:hover {
            background-color: #48484A;
        }
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
            height: 0px;
        }
    """
def get_apple_light_qss() -> str:
    """Apple macOS Cupertino Minimalist Acik Tema (Ferah, Sade, Yalin)."""
    return """
        QMainWindow {
            background-color: #F2F2F7;
        }
        QWidget {
            color: #1D1D1F;
            font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
            font-size: 12px;
        }
        QDialog {
            background-color: #F2F2F7;
            color: #1D1D1F;
        }
        QScrollArea {
            background-color: transparent;
            border: none;
        }
        QFrame.card {
            background-color: #FFFFFF;
            border: 1px solid #E5E5EA;
            border-radius: 14px;
        }
        QFrame.card-bitlocker {
            background-color: #F0F6FF;
            border: 1px solid rgba(0, 113, 227, 0.35);
            border-radius: 14px;
        }
        QLabel {
            background: transparent;
            color: #1D1D1F;
            font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
        }
        QPushButton {
            background-color: #FFFFFF;
            color: #1D1D1F;
            font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
            font-size: 11.5px;
            font-weight: 600;
            padding: 5px 14px;
            border: 1px solid #D2D2D7;
            border-radius: 7px;
            min-height: 20px;
        }
        QPushButton:hover {
            background-color: #F5F5F7;
            border-color: #0071E3;
            color: #0071E3;
            cursor: pointer;
        }
        QPushButton:pressed {
            background-color: #E5E5EA;
            border-color: #0071E3;
            padding-top: 8px;
            padding-left: 17px;
        }
        QPushButton:disabled {
            background-color: #F2F2F7;
            color: #A1A1A6;
            border-color: rgba(0, 0, 0, 0.08);
        }
        QPushButton#btn-toolbar {
            background-color: #FFFFFF;
            color: #424245;
            font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
            font-size: 11px;
            font-weight: 600;
            padding: 4px 10px;
            border: 1px solid #D2D2D7;
            border-radius: 6px;
            min-height: 18px;
        }
        QPushButton#btn-toolbar:hover {
            background-color: #F5F5F7;
            border-color: #0071E3;
            color: #0071E3;
            cursor: pointer;
        }
        QPushButton#btn-toolbar:pressed {
            background-color: #E5E5EA;
        }
        QPushButton#btn-toolbar:disabled {
            background-color: #F2F2F7;
            color: #A1A1A6;
            border-color: rgba(0, 0, 0, 0.06);
        }
        QPushButton#btn-browse {
            background-color: #FFFFFF;
            color: #1D1D1F;
            font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
            font-size: 11px;
            font-weight: 600;
            padding: 4px 12px;
            border: 1px solid #D2D2D7;
            border-radius: 6px;
            min-height: 18px;
        }
        QPushButton#btn-browse:hover {
            background-color: #F5F5F7;
            border-color: #0071E3;
            color: #0071E3;
            cursor: pointer;
        }
        QPushButton#btn-browse:pressed {
            background-color: #E5E5EA;
        }
        QPushButton#btn-browse:disabled {
            background-color: #F2F2F7;
            color: #A1A1A6;
            border-color: rgba(0, 0, 0, 0.06);
        }
        QPushButton#btn-mount, QPushButton#btn-primary, QPushButton#btn-mount {
            background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #0077ED, stop:1 #0062CC);
            color: #FFFFFF;
            font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
            font-size: 12px;
            font-weight: 600;
            padding: 6px 16px;
            border: 1px solid #0071E3;
            border-radius: 7px;
            min-height: 22px;
        }
        QPushButton#btn-mount:hover, QPushButton#btn-primary:hover, QPushButton#btn-mount:hover {
            background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #1E88E5, stop:1 #0077ED);
            border-color: #0071E3;
            cursor: pointer;
        }
        QPushButton#btn-mount:pressed, QPushButton#btn-primary:pressed, QPushButton#btn-mount:pressed {
            background: #005BB5;
            padding-top: 10px;
            padding-left: 25px;
        }
        QPushButton#btn-mount:disabled, QPushButton#btn-primary:disabled {
            background-color: #E5E5EA;
            color: #A1A1A6;
            border: 1px solid rgba(0, 0, 0, 0.08);
        }
        QPushButton#btn-open-explorer, QPushButton#btn-success, QPushButton#btn-open-explorer {
            background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #34C759, stop:1 #28A745);
            color: #FFFFFF;
            font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
            font-size: 12px;
            font-weight: 600;
            padding: 6px 16px;
            border: 1px solid #30D158;
            border-radius: 7px;
            min-height: 22px;
        }
        QPushButton#btn-open-explorer:hover, QPushButton#btn-success:hover, QPushButton#btn-open-explorer:hover {
            background-color: #3CD061;
            border-color: #34C759;
            cursor: pointer;
        }
        QPushButton#btn-open-explorer:pressed, QPushButton#btn-success:pressed, QPushButton#btn-open-explorer:pressed {
            background-color: #248A3D;
            padding-top: 10px;
            padding-left: 23px;
        }
        QPushButton#btn-open-explorer:disabled, QPushButton#btn-success:disabled {
            background-color: #E5E5EA;
            color: #A1A1A6;
            border: 1px solid rgba(0, 0, 0, 0.08);
        }
        QPushButton#btn-dismount, QPushButton#btn-danger, QPushButton#btn-dismount {
            background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #FF3B30, stop:1 #D70015);
            color: #FFFFFF;
            font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
            font-size: 12px;
            font-weight: 600;
            padding: 6px 16px;
            border: 1px solid #FF3B30;
            border-radius: 7px;
            min-height: 22px;
        }
        QPushButton#btn-dismount:hover, QPushButton#btn-danger:hover, QPushButton#btn-dismount:hover {
            background-color: #E03228;
            border-color: #FF3B30;
            cursor: pointer;
        }
        QPushButton#btn-dismount:pressed, QPushButton#btn-danger:pressed, QPushButton#btn-dismount:pressed {
            background-color: #C02920;
            padding-top: 10px;
            padding-left: 23px;
        }
        QPushButton#btn-dismount:disabled, QPushButton#btn-danger:disabled {
            background-color: #E5E5EA;
            color: #A1A1A6;
            border: 1px solid rgba(0, 0, 0, 0.08);
        }
        QPushButton#btn-accent {
            background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #0077ED, stop:1 #0062CC);
            color: #FFFFFF;
            font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
            font-size: 12.5px;
            font-weight: 700;
            padding: 7px 18px;
            border: 1px solid #0071E3;
            border-radius: 8px;
            min-height: 32px;
        }
        QPushButton#btn-accent:hover {
            background: #0077ED;
            border-color: #005BB5;
            cursor: pointer;
        }
        QPushButton#btn-accent:pressed {
            background: #005BB5;
            padding-top: 8px;
            padding-left: 19px;
        }
        QComboBox {
            background-color: #FFFFFF;
            border: 1px solid #D2D2D7;
            border-radius: 8px;
            padding: 7px 12px;
            color: #1D1D1F;
            font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
            font-size: 12px;
            font-weight: 600;
            min-height: 32px;
        }
        QComboBox:hover {
            border: 1px solid #0071E3;
        }
        QComboBox:focus {
            border: 1px solid #0071E3;
            background-color: #FFFFFF;
        }
        QComboBox:disabled {
            background-color: #F2F2F7;
            color: #A1A1A6;
            border-color: rgba(0, 0, 0, 0.06);
        }
        QComboBox::drop-down {
            subcontrol-origin: padding;
            subcontrol-position: top right;
            width: 24px;
            border-left: none;
            border-top-right-radius: 8px;
            border-bottom-right-radius: 8px;
        }
        QComboBox QAbstractItemView {
            background-color: #FFFFFF;
            color: #1D1D1F;
            font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
            font-size: 11.5px;
            border: 1px solid #D2D2D7;
            border-radius: 8px;
            selection-background-color: #0071E3;
            selection-color: #FFFFFF;
            padding: 4px;
            outline: none;
        }
        QLineEdit, QSpinBox {
            background-color: #FFFFFF;
            border: 1px solid #D2D2D7;
            border-radius: 8px;
            padding: 7px 12px;
            color: #1D1D1F;
            font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
            font-size: 12px;
            font-weight: 600;
            min-height: 32px;
        }
        QLineEdit:focus, QSpinBox:focus {
            border: 1px solid #0071E3;
            background-color: #FFFFFF;
        }
        QLineEdit:disabled, QSpinBox:disabled {
            background-color: #F2F2F7;
            color: #A1A1A6;
            border-color: rgba(0, 0, 0, 0.06);
        }
        QCheckBox {
            color: #1D1D1F;
            font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
            font-size: 12px;
            font-weight: 500;
            spacing: 10px;
        }
        QCheckBox:disabled {
            color: #A1A1A6;
        }
        QCheckBox::indicator {
            width: 18px;
            height: 18px;
            border-radius: 5px;
            border: 1px solid #C7C7CC;
            background-color: #FFFFFF;
        }
        QCheckBox::indicator:hover {
            border-color: #0071E3;
        }
        QCheckBox::indicator:checked {
            background-color: #0071E3;
            border: 1px solid #0071E3;
        }
        QProgressBar {
            background-color: #E5E5EA;
            border: 1px solid #D2D2D7;
            border-radius: 6px;
            height: 12px;
            text-align: center;
            color: transparent;
        }
        QProgressBar::chunk {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #0071E3, stop:1 #34C759);
            border-radius: 5px;
        }
        QTextEdit {
            background-color: #FFFFFF;
            border: 1px solid #D2D2D7;
            border-radius: 10px;
            color: #1D1D1F;
            font-family: 'SF Mono', 'JetBrains Mono', 'Cascadia Code', 'Consolas', monospace;
            font-size: 11.5px;
            padding: 10px;
        }
        QMenu {
            background-color: #FFFFFF;
            border: 1px solid #D2D2D7;
            border-radius: 10px;
            padding: 5px;
            color: #1D1D1F;
            font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
            font-size: 11.5px;
        }
        QMenu::item {
            padding: 7px 16px;
            border-radius: 6px;
            color: #1D1D1F;
            font-weight: 600;
        }
        QMenu::item:selected {
            background-color: #F2F2F7;
            color: #0071E3;
        }
        QMenu::item:disabled {
            color: #A1A1A6;
        }
        QMenu::separator {
            height: 1px;
            background-color: #E5E5EA;
            margin: 4px 6px;
        }
        QDialog QLabel {
            color: #1D1D1F;
            font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
            font-size: 12px;
            font-weight: 600;
        }
        QDialog QPushButton, QDialogButtonBox QPushButton {
            background-color: #FFFFFF;
            color: #1D1D1F;
            font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
            border: 1px solid #D2D2D7;
            border-radius: 8px;
            padding: 7px 18px;
            min-width: 76px;
            font-weight: 600;
            font-size: 11.5px;
        }
        QDialog QPushButton:hover, QDialogButtonBox QPushButton:hover {
            background-color: #F5F5F7;
            border-color: #0071E3;
            color: #0071E3;
            cursor: pointer;
        }
        QDialog QPushButton:pressed, QDialogButtonBox QPushButton:pressed {
            background-color: #E5E5EA;
            padding-top: 8px;
            padding-left: 19px;
        }
        QMessageBox {
            background-color: #F2F2F7;
            color: #1D1D1F;
            font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
        }
        QMessageBox QLabel {
            color: #1D1D1F;
            font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
            font-size: 12px;
            font-weight: 600;
        }
        QMessageBox QPushButton {
            background-color: #FFFFFF;
            color: #1D1D1F;
            font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
            border: 1px solid #D2D2D7;
            border-radius: 8px;
            padding: 7px 18px;
            min-width: 76px;
            font-weight: 600;
            font-size: 11.5px;
        }
        QMessageBox QPushButton:hover {
            background-color: #F5F5F7;
            border-color: #0071E3;
            color: #0071E3;
            cursor: pointer;
        }
        QToolTip {
            background-color: #FFFFFF;
            color: #1D1D1F;
            border: 1px solid #D2D2D7;
            padding: 6px 12px;
            border-radius: 6px;
            font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
            font-size: 11px;
        }
        QScrollBar:vertical {
            background-color: transparent;
            width: 6px;
            border-radius: 3px;
            margin: 2px;
        }
        QScrollBar::handle:vertical {
            background-color: #C7C7CC;
            min-height: 18px;
            border-radius: 3px;
        }
        QScrollBar::handle:vertical:hover {
            background-color: #AEAEB2;
        }
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
            height: 0px;
        }
    """
def get_theme_qss(theme: str = "apple_dark") -> str:
    """Uygulama geneli icin Apple Minimal Koyu QSS temasini dondurur."""
    return get_apple_dark_qss()

def _get_fluent_light_qss() -> str:
        return """
            QMainWindow {
                background-color: #F1F4F9;
            }
            QWidget {
                color: #0F172A;
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
                font-size: 11.5px;
            }
            QDialog {
                background-color: #F1F4F9;
                color: #0F172A;
            }
            QScrollArea {
                background-color: transparent;
                border: none;
            }
            QFrame.card {
                background-color: #FFFFFF;
                border: 1px solid #CBD5E1;
                border-radius: 14px;
            }
            QFrame.card-bitlocker {
                background-color: #F8FAFD;
                border: 1px solid rgba(2, 132, 199, 0.25);
                border-radius: 14px;
            }
            QLabel {
                background: transparent;
                color: #0F172A;
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
            }
            QPushButton {
                background-color: #FFFFFF;
                color: #1E293B;
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
                font-size: 11.5px;
                font-weight: 600;
                padding: 6px 14px;
                border: 1px solid #CBD5E1;
                border-radius: 8px;
                min-height: 28px;
            }
            QPushButton:hover {
                background-color: #F8FAFC;
                border-color: #0C5478;
                color: #0C5478;
                cursor: pointer;
            }
            QPushButton:pressed {
                background-color: #E2E8F0;
                border-color: #0C5478;
                padding-top: 7px;
                padding-left: 15px;
            }
            QPushButton:disabled {
                background-color: #F1F5F9;
                color: #94A3B8;
                border-color: #E2E8F0;
            }
            QPushButton#btn-toolbar {
                background-color: #FFFFFF;
                color: #334155;
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
                font-size: 10.5px;
                font-weight: 600;
                padding: 5px 12px;
                border: 1px solid #CBD5E1;
                border-radius: 8px;
                min-height: 18px;
            }
            QPushButton#btn-toolbar:hover {
                background-color: #F1F5F9;
                border-color: #0C5478;
                color: #0C5478;
                cursor: pointer;
            }
            QPushButton#btn-toolbar:pressed {
                background-color: #E2E8F0;
            }
            QPushButton#btn-toolbar:disabled {
                background-color: #F8FAFC;
                color: #94A3B8;
                border-color: #E2E8F0;
            }
            QPushButton#btn-new-vault {
                background-color: #F1F5F9;
                color: #0F172A;
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
                font-size: 10.5px;
                font-weight: 600;
                padding: 5px 12px;
                border: 1px solid #CBD5E1;
                border-radius: 8px;
                min-height: 18px;
            }
            QPushButton#btn-new-vault:hover {
                background-color: #E2E8F0;
                border-color: #0C5478;
                color: #0C5478;
            }
            QPushButton#btn-new-vault:pressed {
                background-color: #CBD5E1;
            }
            QPushButton#btn-vaults-folder {
                background-color: #ECFDF5;
                color: #065F46;
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
                font-size: 10.5px;
                font-weight: 600;
                padding: 5px 12px;
                border: 1px solid #A7F3D0;
                border-radius: 8px;
                min-height: 18px;
            }
            QPushButton#btn-vaults-folder:hover {
                background-color: #D1FAE5;
                border-color: #10B981;
                color: #064E3B;
            }
            QPushButton#btn-vaults-folder:pressed {
                background-color: #A7F3D0;
            }
            QPushButton#btn-browse {
                background-color: #F0F9FF;
                color: #0369A1;
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
                font-size: 10.5px;
                font-weight: 600;
                padding: 5px 12px;
                border: 1px solid #BAE6FD;
                border-radius: 8px;
                min-height: 18px;
            }
            QPushButton#btn-browse:hover {
                background-color: #E0F2FE;
                border-color: #0284C7;
                color: #0C4A6E;
            }
            QPushButton#btn-browse:pressed {
                background-color: #BAE6FD;
            }
            QFrame#vault-path-bar {
                background-color: #FFFFFF;
                border: 1px solid #CBD5E1;
                border-radius: 8px;
            }
            QPushButton#btn-path-action {
                background-color: #F1F5F9;
                color: #334155;
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
                font-size: 10px;
                font-weight: 600;
                padding: 4px 8px;
                border: 1px solid #CBD5E1;
                border-radius: 6px;
                min-height: 18px;
            }
            QPushButton#btn-path-action:hover {
                background-color: #E2E8F0;
                color: #0C5478;
                border-color: #0C5478;
            }
            QPushButton#btn-path-action:pressed {
                background-color: #CBD5E1;
            }
            QPushButton#btn-primary, QPushButton#btn-mount {
                background-color: #2563EB;
                color: #FFFFFF;
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
                font-size: 12.5px;
                font-weight: 700;
                padding: 8px 18px;
                border: 1px solid #1D4ED8;
                border-radius: 8px;
                min-height: 20px;
            }
            QPushButton#btn-primary:hover, QPushButton#btn-mount:hover {
                background-color: #1D4ED8;
                border-color: #1E40AF;
            }
            QPushButton#btn-primary:pressed, QPushButton#btn-mount:pressed {
                background-color: #1E40AF;
                padding-top: 9px;
                padding-left: 19px;
            }
            QPushButton#btn-success, QPushButton#btn-open-explorer {
                background-color: #16A34A;
                color: #FFFFFF;
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
                font-size: 12.5px;
                font-weight: 700;
                padding: 8px 18px;
                border: 1px solid #15803D;
                border-radius: 8px;
                min-height: 20px;
            }
            QPushButton#btn-success:hover, QPushButton#btn-open-explorer:hover {
                background-color: #15803D;
                border-color: #166534;
            }
            QPushButton#btn-success:pressed, QPushButton#btn-open-explorer:pressed {
                background-color: #166534;
                padding-top: 9px;
                padding-left: 19px;
            }
            QPushButton#btn-accent {
                background-color: #0284C7;
                color: #FFFFFF;
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
                font-size: 11.5px;
                font-weight: 700;
                padding: 8px 16px;
                border: 1px solid #0369A1;
                border-radius: 8px;
                min-height: 18px;
            }
            QPushButton#btn-accent:hover {
                background-color: #0369A1;
                border-color: #075985;
            }
            QPushButton#btn-accent:pressed {
                background-color: #075985;
                padding-top: 9px;
                padding-left: 17px;
            }
            QPushButton#btn-danger, QPushButton#btn-dismount {
                background-color: #DC2626;
                color: #FFFFFF;
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
                font-size: 11.5px;
                font-weight: 700;
                padding: 8px 16px;
                border: 1px solid #B91C1C;
                border-radius: 8px;
                min-height: 18px;
            }
            QPushButton#btn-danger:hover, QPushButton#btn-dismount:hover {
                background-color: #B91C1C;
                border-color: #991B1B;
            }
            QPushButton#btn-danger:pressed, QPushButton#btn-dismount:pressed {
                background-color: #991B1B;
                padding-top: 9px;
                padding-left: 17px;
            }
            QComboBox {
                background-color: #FFFFFF;
                border: 1px solid #CBD5E1;
                border-radius: 8px;
                padding: 6px 12px;
                color: #0F172A;
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
                font-size: 11.5px;
                font-weight: 600;
                min-height: 28px;
            }
            QComboBox:hover, QComboBox:focus {
                border: 1px solid #2563EB;
            }
            QComboBox:disabled {
                background-color: #F1F5F9;
                color: #94A3B8;
                border-color: #E2E8F0;
            }
            QComboBox::drop-down {
                subcontrol-origin: padding;
                subcontrol-position: top right;
                width: 24px;
                border: none;
            }
            QComboBox QAbstractItemView {
                background-color: #FFFFFF;
                border: 1px solid #CBD5E1;
                border-radius: 8px;
                selection-background-color: #EFF6FF;
                selection-color: #1D4ED8;
                color: #0F172A;
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
                font-size: 11px;
                padding: 4px;
                outline: none;
            }
            QLineEdit, QSpinBox {
                background-color: #FFFFFF;
                border: 1px solid #CBD5E1;
                border-radius: 8px;
                padding: 6px 12px;
                color: #0F172A;
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
                font-size: 11.5px;
                font-weight: 600;
                min-height: 28px;
            }
            QLineEdit:focus, QSpinBox:focus {
                border: 1px solid #2563EB;
                background-color: #FFFFFF;
            }
            QLineEdit:disabled, QSpinBox:disabled {
                background-color: #F1F5F9;
                color: #94A3B8;
                border-color: #E2E8F0;
            }
            QCheckBox {
                color: #0F172A;
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
                font-size: 11px;
                font-weight: 600;
                spacing: 8px;
            }
            QCheckBox:disabled {
                color: #94A3B8;
            }
            QCheckBox::indicator {
                width: 16px;
                height: 16px;
                border-radius: 4px;
                border: 1px solid #94A3B8;
                background-color: #FFFFFF;
            }
            QCheckBox::indicator:hover {
                border-color: #2563EB;
            }
            QCheckBox::indicator:checked {
                background-color: #2563EB;
                border: 1px solid #1D4ED8;
            }
            QProgressBar {
                background-color: #E2E8F0;
                border: 1px solid #CBD5E1;
                border-radius: 6px;
                height: 12px;
                text-align: center;
                color: transparent;
            }
            QProgressBar::chunk {
                background-color: #16A34A;
                border-radius: 5px;
            }
            QTextEdit {
                background-color: #0F172A;
                border: 1px solid #334155;
                border-radius: 10px;
                color: #4ADE80;
                font-family: 'JetBrains Mono', 'Cascadia Code', 'Consolas', monospace;
                font-size: 11px;
                padding: 8px;
            }
            QMenu {
                background-color: #FFFFFF;
                border: 1px solid #E2E8F0;
                border-radius: 10px;
                padding: 4px;
                color: #0F172A;
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
                font-size: 11px;
            }
            QMenu::item {
                padding: 6px 14px;
                border-radius: 6px;
                color: #0F172A;
                font-weight: 600;
            }
            QMenu::item:selected {
                background-color: #EFF6FF;
                color: #2563EB;
            }
            QMenu::item:disabled {
                color: #94A3B8;
            }
            QMenu::separator {
                height: 1px;
                background-color: #E2E8F0;
                margin: 4px 6px;
            }
            QDialog QLabel {
                color: #0F172A;
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
                font-size: 11.5px;
                font-weight: 600;
            }
            QDialog QPushButton, QDialogButtonBox QPushButton {
                background-color: #F1F5F9;
                color: #1E293B;
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
                border: 1px solid #CBD5E1;
                border-radius: 8px;
                padding: 6px 16px;
                min-width: 72px;
                font-weight: 600;
                font-size: 11px;
            }
            QDialog QPushButton:hover, QDialogButtonBox QPushButton:hover {
                background-color: #E2E8F0;
                border-color: #0C5478;
                color: #0C5478;
                cursor: pointer;
            }
            QDialog QPushButton:pressed, QDialogButtonBox QPushButton:pressed {
                background-color: #CBD5E1;
                padding-top: 7px;
                padding-left: 17px;
            }
            QMessageBox {
                background-color: #F1F4F9;
                color: #0F172A;
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
            }
            QMessageBox QLabel {
                color: #0F172A;
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
                font-size: 11.5px;
                font-weight: 600;
            }
            QMessageBox QPushButton {
                background-color: #F1F5F9;
                color: #1E293B;
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
                border: 1px solid #CBD5E1;
                border-radius: 8px;
                padding: 6px 16px;
                min-width: 72px;
                font-weight: 600;
                font-size: 11px;
            }
            QMessageBox QPushButton:hover {
                background-color: #E2E8F0;
                border-color: #0C5478;
                color: #0C5478;
                cursor: pointer;
            }
            QToolTip {
                background-color: #0F172A;
                color: #F8FAFC;
                border: 1px solid #334155;
                padding: 5px 10px;
                border-radius: 6px;
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
                font-size: 10.5px;
            }
            QScrollBar:vertical {
                background-color: transparent;
                width: 8px;
                border-radius: 4px;
                margin: 2px;
            }
            QScrollBar::handle:vertical {
                background-color: #CBD5E1;
                min-height: 18px;
                border-radius: 4px;
            }
            QScrollBar::handle:vertical:hover {
                background-color: #94A3B8;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0px;
            }
        """

def _get_cyber_dark_qss() -> str:
    return """
            QMainWindow {
                background-color: #0B0F19;
            }
            QWidget {
                color: #F1F5F9;
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
                font-size: 11.5px;
            }
            QDialog {
                background-color: #0E1320;
                color: #F1F5F9;
            }
            QScrollArea {
                background-color: transparent;
                border: none;
            }
            QFrame.card {
                background-color: #131B2E;
                border: 1px solid #23304A;
                border-radius: 14px;
            }
            QFrame.card-bitlocker {
                background-color: #0D1527;
                border: 1px solid rgba(56, 189, 248, 0.25);
                border-radius: 14px;
            }
            QLabel {
                background: transparent;
                color: #F1F5F9;
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
            }
            QPushButton {
                background-color: #1A2338;
                color: #E2ECF8;
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
                font-size: 11.5px;
                font-weight: 600;
                padding: 6px 14px;
                border: 1px solid #283754;
                border-radius: 8px;
                min-height: 28px;
            }
            QPushButton:hover {
                background-color: #24314E;
                border-color: #38BDF8;
                color: #38BDF8;
                cursor: pointer;
            }
            QPushButton:pressed {
                background-color: #131A2B;
                border-color: #38BDF8;
                padding-top: 7px;
                padding-left: 15px;
            }
            QPushButton:disabled {
                background-color: #121724;
                color: #4B5A76;
                border-color: #1C2436;
            }
            QPushButton#btn-toolbar {
                background-color: #161F33;
                color: #CAD6E8;
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
                font-size: 10.5px;
                font-weight: 600;
                padding: 5px 12px;
                border: 1px solid #263552;
                border-radius: 8px;
                min-height: 18px;
            }
            QPushButton#btn-toolbar:hover {
                background-color: #212E4A;
                border-color: #38BDF8;
                color: #38BDF8;
                cursor: pointer;
            }
            QPushButton#btn-toolbar:pressed {
                background-color: #101625;
            }
            QPushButton#btn-toolbar:disabled {
                background-color: #121724;
                color: #4B5A76;
                border-color: #1C2436;
            }
            QPushButton#btn-new-vault {
                background-color: #1C263A;
                color: #E2ECF8;
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
                font-size: 10.5px;
                font-weight: 600;
                padding: 5px 12px;
                border: 1px solid #2F4060;
                border-radius: 8px;
                min-height: 18px;
            }
            QPushButton#btn-new-vault:hover {
                background-color: #263550;
                border-color: #38BDF8;
                color: #38BDF8;
            }
            QPushButton#btn-new-vault:pressed {
                background-color: #141C2C;
            }
            QPushButton#btn-vaults-folder {
                background-color: #064E3B;
                color: #A7F3D0;
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
                font-size: 10.5px;
                font-weight: 600;
                padding: 5px 12px;
                border: 1px solid #059669;
                border-radius: 8px;
                min-height: 18px;
            }
            QPushButton#btn-vaults-folder:hover {
                background-color: #047857;
                color: #FFFFFF;
                border-color: #34D399;
            }
            QPushButton#btn-vaults-folder:pressed {
                background-color: #064E3B;
            }
            QPushButton#btn-browse {
                background-color: #0C4A6E;
                color: #BAE6FD;
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
                font-size: 10.5px;
                font-weight: 600;
                padding: 5px 12px;
                border: 1px solid #0284C7;
                border-radius: 8px;
                min-height: 18px;
            }
            QPushButton#btn-browse:hover {
                background-color: #0369A1;
                color: #FFFFFF;
                border-color: #38BDF8;
            }
            QPushButton#btn-browse:pressed {
                background-color: #0C4A6E;
            }
            QFrame#vault-path-bar {
                background-color: #0B111E;
                border: 1px solid #1E2B45;
                border-radius: 8px;
            }
            QPushButton#btn-path-action {
                background-color: #151D2F;
                color: #94A3B8;
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
                font-size: 10px;
                font-weight: 600;
                padding: 4px 8px;
                border: 1px solid #23314B;
                border-radius: 6px;
                min-height: 18px;
            }
            QPushButton#btn-path-action:hover {
                background-color: #1F2B45;
                color: #38BDF8;
                border-color: #38BDF8;
            }
            QPushButton#btn-path-action:pressed {
                background-color: #0F1522;
            }
            QPushButton#btn-primary, QPushButton#btn-mount {
                background-color: #4F46E5;
                color: #FFFFFF;
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
                font-size: 12.5px;
                font-weight: 700;
                padding: 8px 18px;
                border: 1px solid #6366F1;
                border-radius: 8px;
                min-height: 20px;
            }
            QPushButton#btn-primary:hover, QPushButton#btn-mount:hover {
                background-color: #4338CA;
                border-color: #818CF8;
            }
            QPushButton#btn-primary:pressed, QPushButton#btn-mount:pressed {
                background-color: #3730A3;
                padding-top: 9px;
                padding-left: 19px;
            }
            QPushButton#btn-success, QPushButton#btn-open-explorer {
                background-color: #059669;
                color: #FFFFFF;
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
                font-size: 12.5px;
                font-weight: 700;
                padding: 8px 18px;
                border: 1px solid #10B981;
                border-radius: 8px;
                min-height: 20px;
            }
            QPushButton#btn-success:hover, QPushButton#btn-open-explorer:hover {
                background-color: #047857;
                border-color: #34D399;
            }
            QPushButton#btn-success:pressed, QPushButton#btn-open-explorer:pressed {
                background-color: #064E3B;
                padding-top: 9px;
                padding-left: 19px;
            }
            QPushButton#btn-accent {
                background-color: #0284C7;
                color: #FFFFFF;
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
                font-size: 11.5px;
                font-weight: 700;
                padding: 8px 16px;
                border: 1px solid #0369A1;
                border-radius: 8px;
                min-height: 18px;
            }
            QPushButton#btn-accent:hover {
                background-color: #0369A1;
                border-color: #38BDF8;
            }
            QPushButton#btn-accent:pressed {
                background-color: #075985;
                padding-top: 9px;
                padding-left: 17px;
            }
            QPushButton#btn-danger, QPushButton#btn-dismount {
                background-color: #DC2626;
                color: #FFFFFF;
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
                font-size: 11.5px;
                font-weight: 700;
                padding: 8px 16px;
                border: 1px solid #EF4444;
                border-radius: 8px;
                min-height: 18px;
            }
            QPushButton#btn-danger:hover, QPushButton#btn-dismount:hover {
                background-color: #B91C1C;
                border-color: #F87171;
            }
            QPushButton#btn-danger:pressed, QPushButton#btn-dismount:pressed {
                background-color: #991B1B;
                padding-top: 9px;
                padding-left: 17px;
            }
            QComboBox {
                background-color: #0B111E;
                border: 1px solid #23314B;
                border-radius: 8px;
                padding: 6px 12px;
                color: #F1F5F9;
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
                font-size: 11.5px;
                font-weight: 600;
                min-height: 28px;
            }
            QComboBox:hover, QComboBox:focus {
                border: 1px solid #38BDF8;
            }
            QComboBox:disabled {
                background-color: #121724;
                color: #4B5A76;
                border-color: #1C2436;
            }
            QComboBox::drop-down {
                subcontrol-origin: padding;
                subcontrol-position: top right;
                width: 24px;
                border: none;
            }
            QComboBox QAbstractItemView {
                background-color: #111827;
                border: 1px solid #2B3852;
                border-radius: 8px;
                selection-background-color: #1E293B;
                selection-color: #F1F5F9;
                color: #E2ECF8;
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
                font-size: 11px;
                padding: 4px;
                outline: none;
            }
            QLineEdit, QSpinBox {
                background-color: #0B111E;
                border: 1px solid #23314B;
                border-radius: 8px;
                padding: 6px 12px;
                color: #F1F5F9;
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
                font-size: 11.5px;
                font-weight: 600;
                min-height: 28px;
            }
            QLineEdit:focus, QSpinBox:focus {
                border: 1px solid #38BDF8;
                background-color: #0D1525;
            }
            QLineEdit:disabled, QSpinBox:disabled {
                background-color: #121724;
                color: #4B5A76;
                border-color: #1C2436;
            }
            QCheckBox {
                color: #E2ECF8;
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
                font-size: 11px;
                font-weight: 600;
                spacing: 8px;
            }
            QCheckBox:disabled {
                color: #4B5A76;
            }
            QCheckBox::indicator {
                width: 16px;
                height: 16px;
                border-radius: 4px;
                border: 1px solid #364768;
                background-color: #0B111E;
            }
            QCheckBox::indicator:hover {
                border-color: #38BDF8;
            }
            QCheckBox::indicator:checked {
                background-color: #F1F5F9;
                border: 1px solid #38BDF8;
            }
            QProgressBar {
                background-color: #0B111E;
                border: 1px solid #23314B;
                border-radius: 6px;
                height: 12px;
                text-align: center;
                color: transparent;
            }
            QProgressBar::chunk {
                background-color: #F1F5F9;
                border-radius: 5px;
            }
            QTextEdit {
                background-color: #070B14;
                border: 1px solid #1E2B45;
                border-radius: 10px;
                color: #F1F5F9;
                font-family: 'JetBrains Mono', 'Cascadia Code', 'Consolas', monospace;
                font-size: 11px;
                padding: 8px;
            }
            QMenu {
                background-color: #111827;
                border: 1px solid #283754;
                border-radius: 10px;
                padding: 4px;
                color: #E2ECF8;
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
                font-size: 11px;
            }
            QMenu::item {
                padding: 6px 14px;
                border-radius: 6px;
                color: #E2ECF8;
                font-weight: 600;
            }
            QMenu::item:selected {
                background-color: #1E293B;
                color: #F1F5F9;
            }
            QMenu::item:disabled {
                color: #4B5A76;
            }
            QMenu::separator {
                height: 1px;
                background-color: #23314B;
                margin: 4px 6px;
            }
            QDialog QLabel {
                color: #E2ECF8;
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
                font-size: 11.5px;
                font-weight: 600;
            }
            QDialog QPushButton, QDialogButtonBox QPushButton {
                background-color: #161F33;
                color: #CAD6E8;
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
                border: 1px solid #263552;
                border-radius: 8px;
                padding: 6px 16px;
                min-width: 72px;
                font-weight: 600;
                font-size: 11px;
            }
            QDialog QPushButton:hover, QDialogButtonBox QPushButton:hover {
                background-color: #212E4A;
                border-color: #38BDF8;
                color: #38BDF8;
                cursor: pointer;
            }
            QDialog QPushButton:pressed, QDialogButtonBox QPushButton:pressed {
                background-color: #101625;
                padding-top: 7px;
                padding-left: 17px;
            }
            QMessageBox {
                background-color: #0E1320;
                color: #F1F5F9;
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
            }
            QMessageBox QLabel {
                color: #F1F5F9;
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
                font-size: 11.5px;
                font-weight: 600;
            }
            QMessageBox QPushButton {
                background-color: #161F33;
                color: #CAD6E8;
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
                border: 1px solid #263552;
                border-radius: 8px;
                padding: 6px 16px;
                min-width: 72px;
                font-weight: 600;
                font-size: 11px;
            }
            QMessageBox QPushButton:hover {
                background-color: #212E4A;
                border-color: #38BDF8;
                color: #38BDF8;
                cursor: pointer;
            }
            QToolTip {
                background-color: #0B111E;
                color: #F1F5F9;
                border: 1px solid #23314B;
                padding: 5px 10px;
                border-radius: 6px;
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
                font-size: 10.5px;
            }
            QScrollBar:vertical {
                background-color: transparent;
                width: 8px;
                border-radius: 4px;
                margin: 2px;
            }
            QScrollBar::handle:vertical {
                background-color: #23314B;
                min-height: 18px;
                border-radius: 4px;
            }
            QScrollBar::handle:vertical:hover {
                background-color: #374A6E;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0px;
            }
        """

class MainWindow(QMainWindow):
    def __init__(self, cli_file: Optional[str] = None, auto_mount: bool = False):
        super().__init__()
        init_pixel_fonts()
        self.config = load_config()
        self.engine = VHDEngine()
        cli_clean = (cli_file or self.config.get("last_vault_path", "") or "").strip(' "\'')
        self.current_vault_file = cli_clean
        self.auto_mount_requested = auto_mount
        self.worker: Optional[VaultWorker] = None
        self.hook_processes: List[Any] = []
        self.current_theme = "apple_dark"
        
        self.drive_letter = ""
        self.is_mounted = False
        self.is_mounting = False
        self.is_dismounting = False
        self.is_locked = False
        self.hook_ran_for_mount = False
        self.hotkey_registered = False
        self.HOTKEY_ID = 0xBADC
        self.log_entries: List[Tuple[str, str, str, str]] = []
        self.last_vault_activity_time = time.time()
        self.last_cursor_pos: Optional[Tuple[int, int]] = None
        self.last_fg_hwnd: Optional[int] = None
        self.vault_label = ""
        self.active_disk_number: Optional[int] = None
        
        self.is_decoy_active = False
        self.active_decoy_path: Optional[str] = None
        self.disguise_vault_file: Optional[str] = None
        self.disguise_vault_name = ""
        self.decoy_original_label = ""
        self.decoy_volume_renamed = False
        self.is_switching_decoy = False
        self.decoy_registry_letter = ""
        
        self.sys_ctx = get_system_context()
        log_session_start(self.engine.is_admin())
        self.engine.suppress_bdeunlock()
        
        self.status_timer = QTimer(self)
        self.status_timer.setInterval(2000)
        self.status_timer.timeout.connect(self.poll_volume_status)

        self.security_timer = QTimer(self)
        self.security_timer.setInterval(1000)
        self.security_timer.timeout.connect(self.check_security_conditions)
        self.security_timer.start()

        self.activity_sensor_timer = QTimer(self)
        self.activity_sensor_timer.setInterval(200)
        self.activity_sensor_timer.timeout.connect(self.poll_global_activity)
        self.activity_sensor_timer.start()

        app_inst = QApplication.instance()
        if app_inst:
            app_inst.installEventFilter(self)

        if self.config.get("audit_log_enabled", True):
            audit_logger.log_security_event("APP_START", "INFO", "Enclave başlatıldı.")

        self.init_ui()
        self.init_tray()

        self.panic_listener = GlobalPanicHotkeyListener(self)
        self.panic_listener.panic_signal.connect(self.trigger_panic_kill_switch)
        self.panic_listener.start()

        self.setup_global_hotkey()
        self.wts_registered = False
        self.setup_session_notification()
        self.refresh_vault_list()
        
        if self.current_vault_file:
            self.check_if_already_attached(self.current_vault_file)

        if (self.auto_mount_requested or self.config.get("auto_mount_on_startup")) and not self.is_mounted:
            QTimer.singleShot(500, self.on_mount_clicked)

    def eventFilter(self, obj, event):
        """Kullanıcının etkileşimini yakalar, hareketsizlik süresini sıfırlar ve tüm pencere genelinde sürükle-bırak olaylarını garanti eder."""
        ev_type = event.type()
        if ev_type in (
            QEvent.Type.MouseButtonPress,
            QEvent.Type.MouseButtonRelease,
            QEvent.Type.KeyPress,
            QEvent.Type.KeyRelease,
            QEvent.Type.Wheel
        ):
            self.reset_inactivity_timer()
        elif ev_type == QEvent.Type.MouseMove:
            now = time.time()
            if (now - getattr(self, "_last_mouse_activity_check", 0)) > 1.0:
                self._last_mouse_activity_check = now
                self.reset_inactivity_timer()
        elif event.type() in (QEvent.Type.DragEnter, QEvent.Type.DragMove):
            if event.mimeData().hasUrls():
                event.setDropAction(Qt.DropAction.CopyAction)
                event.acceptProposedAction()
                event.accept()
                return True
        elif event.type() == QEvent.Type.Drop:
            if event.mimeData().hasUrls():
                event.setDropAction(Qt.DropAction.CopyAction)
                event.acceptProposedAction()
                event.accept()
                explorer = getattr(self, "current_custom_explorer", None)
                if explorer and (obj == explorer or (isinstance(obj, QWidget) and explorer.isAncestorOf(obj))):
                    return False
                urls = event.mimeData().urls()
                if urls:
                    if getattr(self, "is_custom_vault_open", False) and explorer:
                        explorer.handle_dropped_urls(urls)
                    else:
                        self.process_dropped_urls(urls)
                return True
        return super().eventFilter(obj, event)

    def get_badge_style(self, badge_type: str) -> str:
        """Modern yuvarlak hatlı ve kristal netliğinde rozet stillerini döndürür."""
        theme = getattr(self, "current_theme", "dark")
        font_style = "font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif; font-size: 11px; font-weight: 700; padding: 5px 14px; border-radius: 14px;"
        font_drive = "font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif; font-size: 13px; font-weight: 700; padding: 5px 14px; border-radius: 14px;"

        if theme == "apple_dark":
            if badge_type == "not_mounted":
                return f"background-color: #212124; color: #86868B; {font_style} border: 1px solid #3A3A3C;"
            elif badge_type == "locked":
                return f"background-color: #2D2010; color: #FF9F0A; {font_style} border: 1px solid rgba(255, 159, 10, 0.4);"
            elif badge_type == "ready":
                return f"background-color: #102616; color: #30D158; {font_style} border: 1px solid rgba(48, 209, 88, 0.4);"
            elif badge_type == "drive":
                return f"background-color: #1A2436; color: #2997FF; {font_drive} border: 1px solid rgba(41, 151, 255, 0.4);"
            elif badge_type == "panic":
                return f"background-color: #2C1618; color: #FF453A; {font_style} border: 1px solid rgba(255, 69, 58, 0.4);"
        elif theme == "apple_light":
            if badge_type == "not_mounted":
                return f"background-color: #FFFFFF; color: #6E6E73; {font_style} border: 1px solid #D2D2D7;"
            elif badge_type == "locked":
                return f"background-color: #FFF8EB; color: #B25E00; {font_style} border: 1px solid rgba(255, 149, 0, 0.4);"
            elif badge_type == "ready":
                return f"background-color: #EDFAF1; color: #248A3D; {font_style} border: 1px solid rgba(52, 199, 89, 0.4);"
            elif badge_type == "drive":
                return f"background-color: #F0F6FF; color: #0071E3; {font_drive} border: 1px solid rgba(0, 113, 227, 0.35);"
            elif badge_type == "panic":
                return f"background-color: #FFF0F0; color: #D70015; {font_style} border: 1px solid rgba(255, 59, 48, 0.4);"
        elif theme == "light":
            if badge_type == "not_mounted":
                return f"background-color: #F1F5F9; color: #475569; {font_style} border: 1px solid #CBD5E1;"
            elif badge_type == "locked":
                return f"background-color: #FEF3C7; color: #92400E; {font_style} border: 1px solid #F59E0B;"
            elif badge_type == "ready":
                return f"background-color: #DCFCE7; color: #166534; {font_style} border: 1px solid #22C55E;"
            elif badge_type == "drive":
                return f"background-color: #EFF6FF; color: #1D4ED8; {font_drive} border: 1px solid #3B82F6;"
            elif badge_type == "panic":
                return f"background-color: #FEE2E2; color: #991B1B; {font_style} border: 1px solid #EF4444;"
        else:
            if badge_type == "not_mounted":
                return f"background-color: #111827; color: #94A3B8; {font_style} border: 1px solid #283754;"
            elif badge_type == "locked":
                return f"background-color: #2D1A05; color: #FBBF24; {font_style} border: 1px solid #D97706;"
            elif badge_type == "ready":
                return f"background-color: #064E3B; color: #34D399; {font_style} border: 1px solid #10B981;"
            elif badge_type == "drive":
                return f"background-color: #0B172B; color: #38BDF8; {font_drive} border: 1px solid #38BDF8;"
            elif badge_type == "panic":
                return f"background-color: #2D0B0B; color: #EF4444; {font_style} border: 1px solid #EF4444;"
        return ""

    def update_vault_state_icon(self):
        """Kasanin durumuna gore (Acik / Kapali) piksel sanat simgeleri dinamik olarak gunceller."""
        is_open = (self.is_mounted and not self.is_locked)
        state = "open" if is_open else "closed"
        icon = create_vault_icon(state)
        self.setWindowIcon(icon)
        if hasattr(self, "tray_icon"):
            self.tray_icon.setIcon(icon)

        icon_file = "enclave_open.png" if is_open else "enclave_closed.png"
        icon_path = get_resource_path(f"assets/{icon_file}")
        if icon_path.exists() and hasattr(self, "header_icon_lbl"):
            pix = QPixmap(str(icon_path))
            if not pix.isNull():
                self.header_icon_lbl.setPixmap(pix.scaled(44, 44, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation))

    def apply_theme(self, theme: str):
        """Secilen temayi tum uygulama ve alt bilesenlere uygular."""
        self.current_theme = theme
        is_dark = (theme in ("dark", "apple_dark"))
        set_window_dark_mode(int(self.winId()), is_dark)
        qss = get_theme_qss(theme)
        app = QApplication.instance()
        if app:
            app.setStyleSheet(qss)
        else:
            self.setStyleSheet(qss)

        font_main = "-apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif"
        if theme == "apple_dark":
            title_col = "#2997FF"
            sub_col = "#86868B"
            vault_lbl_col = "#F5F5F7"
            hint_col = "#86868B"
            unlock_title_col = "#2997FF"
            unlock_desc_col = "#F5F5F7"
            err_col = "#FF453A"
            log_lbl_col = "#F5F5F7"
            cap_unmounted = "#86868B"
            cap_locked = "#FF9F0A"
            cap_mounted = "#30D158"
            s_col = "#2997FF"
            btn_bg = "#2C2C2E"
            btn_border = "#3A3A3C"
            btn_text = "#F5F5F7"
            btn_hover = "#3A3A3C"
            toggle_text = "Gündüz Modu"
        elif theme == "apple_light":
            title_col = "#1D1D1F"
            sub_col = "#6E6E73"
            vault_lbl_col = "#1D1D1F"
            hint_col = "#6E6E73"
            unlock_title_col = "#0071E3"
            unlock_desc_col = "#1D1D1F"
            err_col = "#FF3B30"
            log_lbl_col = "#1D1D1F"
            cap_unmounted = "#6E6E73"
            cap_locked = "#FF9500"
            cap_mounted = "#34C759"
            s_col = "#0071E3"
            btn_bg = "#FFFFFF"
            btn_border = "#D2D2D7"
            btn_text = "#1D1D1F"
            btn_hover = "#F0F0F2"
            toggle_text = "Gece Modu"
        elif not is_dark:
            title_col = "#164E63"
            sub_col = "#475569"
            vault_lbl_col = "#3E4D3A"
            hint_col = "#4B5E45"
            unlock_title_col = "#164875"
            unlock_desc_col = "#1A2416"
            err_col = "#B52222"
            log_lbl_col = "#3E4D3A"
            cap_unmounted = "#586B54"
            cap_locked = "#A66500"
            cap_mounted = "#1A2416"
            s_col = "#0C5478"
            btn_bg = "#FFFFFF"
            btn_border = "#CBD5E1"
            btn_text = "#0F172A"
            btn_hover = "#F8FAFC"
            toggle_text = "Gece Modu"
        else:
            title_col = "#38BDF8"
            sub_col = "#94A3B8"
            vault_lbl_col = "#8FA4C4"
            hint_col = "#8FA4C4"
            unlock_title_col = "#38BDF8"
            unlock_desc_col = "#CBD5E1"
            err_col = "#EF4444"
            log_lbl_col = "#8FA4C4"
            cap_unmounted = "#6C82A3"
            cap_locked = "#FFCC00"
            cap_mounted = "#38BDF8"
            s_col = "#38BDF8"
            btn_bg = "#161F33"
            btn_border = "#263552"
            btn_text = "#CAD6E8"
            btn_hover = "#212E4A"
            toggle_text = "Gündüz Modu"

        header_tag_style = f"font-family: {font_main}; font-size: 11px; font-weight: 700; color: {s_col}; letter-spacing: 0.8px;"
        if hasattr(self, "app_title"):
            self.app_title.setStyleSheet(f"font-family: {font_main}; font-size: 20px; font-weight: 800; color: {title_col}; letter-spacing: -0.3px;")
        if hasattr(self, "app_sub"):
            self.app_sub.setStyleSheet(f"font-family: {font_main}; font-size: 12px; color: {sub_col}; font-weight: 500;")
        if hasattr(self, "vault_lbl"):
            self.vault_lbl.setStyleSheet(header_tag_style)
        if hasattr(self, "status_lbl"):
            self.status_lbl.setStyleSheet(header_tag_style)
        if hasattr(self, "settings_lbl"):
            self.settings_lbl.setStyleSheet(header_tag_style)
        if hasattr(self, "log_lbl"):
            self.log_lbl.setStyleSheet(header_tag_style)
        if hasattr(self, "dnd_hint"):
            self.dnd_hint.setStyleSheet(f"font-family: {font_main}; font-size: 11px; color: {hint_col};")
        if hasattr(self, "unlock_title"):
            self.unlock_title.setStyleSheet(f"font-family: {font_main}; font-size: 13px; font-weight: 700; color: {unlock_title_col};")
        if hasattr(self, "unlock_desc"):
            self.unlock_desc.setStyleSheet(f"font-family: {font_main}; font-size: 12px; color: {unlock_desc_col}; font-weight: 500;")
        if hasattr(self, "lbl_unlock_error"):
            self.lbl_unlock_error.setStyleSheet(f"font-family: {font_main}; font-size: 11px; color: {err_col}; font-weight: 700; padding-top: 2px;")
        if hasattr(self, "capacity_text"):
            if not self.is_mounted:
                self.capacity_text.setStyleSheet(f"font-family: {font_main}; font-size: 11px; font-weight: 600; color: {cap_unmounted};")
            elif self.is_locked:
                self.capacity_text.setStyleSheet(f"font-family: {font_main}; font-size: 11px; font-weight: 600; color: {cap_locked};")
            else:
                self.capacity_text.setStyleSheet(f"font-family: {font_main}; font-size: 11px; font-weight: 600; color: {cap_mounted};")

        if hasattr(self, "btn_settings"):
            self.btn_settings.setIcon(get_svg_icon("settings", s_col, 14))
            self.btn_settings.setStyleSheet(f"""
                QPushButton {{
                    background-color: {btn_bg};
                    color: {btn_text};
                    border: 1px solid {btn_border};
                    font-family: {font_main};
                    font-size: 10.5px;
                    font-weight: 600;
                    padding: 5px 12px;
                    border-radius: 8px;
                }}
                QPushButton:hover {{
                    background-color: {btn_hover};
                    border-color: {s_col};
                    color: {s_col};
                }}
            """)

        if hasattr(self, "btn_theme_toggle"):
            self.btn_theme_toggle.setText(toggle_text)
            self.btn_theme_toggle.setStyleSheet(f"""
                QPushButton {{
                    background-color: {btn_bg};
                    color: {btn_text};
                    border: 1px solid {btn_border};
                    font-family: {font_main};
                    font-size: 10.5px;
                    font-weight: 600;
                    padding: 5px 12px;
                    border-radius: 8px;
                }}
                QPushButton:hover {{
                    background-color: {btn_hover};
                    border-color: {s_col};
                    color: {s_col};
                    cursor: pointer;
                }}
            """)

        if hasattr(self, "lbl_panic_badge"):
            self.lbl_panic_badge.setStyleSheet(self.get_badge_style("panic"))
        if hasattr(self, "drive_badge"):
            self.drive_badge.setStyleSheet(self.get_badge_style("drive"))
        self.update_admin_badge()
        if hasattr(self, "status_badge"):
            if not self.is_mounted:
                self.status_badge.setStyleSheet(self.get_badge_style("not_mounted"))
            elif self.is_locked:
                self.status_badge.setStyleSheet(self.get_badge_style("locked"))
            else:
                self.status_badge.setStyleSheet(self.get_badge_style("ready"))

        if hasattr(self, "bridge_tag"):
            self.update_bridge_tag()

        if hasattr(self, "update_vault_path_display"):
            self.update_vault_path_display()

        if hasattr(self, "update_unmounted_capacity_display") and not self.is_mounted:
            self.update_unmounted_capacity_display(self.current_vault_file)

        if hasattr(self, "refresh_log_display"):
            self.refresh_log_display()

        if hasattr(self, "update_vault_state_icon"):
            self.update_vault_state_icon()

    def showEvent(self, event):
        super().showEvent(event)
        set_window_dark_mode(int(self.winId()), self.current_theme == "dark")

    def toggle_theme(self):
        """Kullanıcının Gece ve Gündüz teması arasında geçiş yapmasını sağlar."""
        if self.current_theme == "apple_dark":
            new_theme = "apple_light"
        elif self.current_theme == "apple_light":
            new_theme = "apple_dark"
        elif self.current_theme == "light":
            new_theme = "dark"
        else:
            new_theme = "light"
        self.current_theme = new_theme
        self.config["theme"] = new_theme
        save_config(self.config)
        self.apply_theme(new_theme)
        mode_str = "Gündüz (Açık)" if new_theme in ("light", "apple_light") else "Gece (Koyu)"
        self.log(f"Tema değiştirildi: {mode_str} ({new_theme})", "info", "TEMA")

    def open_settings_dialog(self):
        """Uygulama ve tema ayarları penceresini açar."""
        from extra_dialogs import AppSettingsDialog
        dlg = AppSettingsDialog(self, config=self.config, current_theme=self.current_theme)
        dlg.exec()

    def init_ui(self):
        self.setWindowTitle("Enclave")
        apply_dynamic_geometry(self, default_w=720, default_h=760, min_w=640, min_h=600)
        self.setWindowIcon(create_vault_icon("closed"))
        
        self.setAcceptDrops(True)
        if sys.platform == "win32":
            try:
                import ctypes
                user32 = ctypes.windll.user32
                shell32 = ctypes.windll.shell32
                hwnd = int(self.winId())
                shell32.DragAcceptFiles(hwnd, True)
                WM_DROPFILES = 0x0233
                WM_COPYGLOBALDATA = 0x0049
                MSGFLT_ALLOW = 1
                if hasattr(user32, "ChangeWindowMessageFilterEx"):
                    user32.ChangeWindowMessageFilterEx(hwnd, WM_DROPFILES, MSGFLT_ALLOW, None)
                    user32.ChangeWindowMessageFilterEx(hwnd, WM_COPYGLOBALDATA, MSGFLT_ALLOW, None)
            except Exception:
                pass

        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll_area.setAcceptDrops(True)
        if scroll_area.viewport():
            scroll_area.viewport().setAcceptDrops(True)
        from PyQt6.QtGui import QKeySequence, QShortcut
        self.fs_shortcut = QShortcut(QKeySequence(Qt.Key.Key_F11), self)
        self.fs_shortcut.setContext(Qt.ShortcutContext.WindowShortcut)
        self.fs_shortcut.activated.connect(self.toggle_fullscreen)
        self.esc_shortcut = QShortcut(QKeySequence(Qt.Key.Key_Escape), self)
        self.esc_shortcut.setContext(Qt.ShortcutContext.WindowShortcut)
        self.esc_shortcut.activated.connect(self._exit_fullscreen_if_active)
        self.setCentralWidget(scroll_area)

        content_widget = QWidget()
        content_widget.setAcceptDrops(True)
        scroll_area.setWidget(content_widget)

        main_layout = QVBoxLayout(content_widget)
        main_layout.setContentsMargins(24, 22, 24, 22)
        main_layout.setSpacing(16)

        header_card = QFrame()
        header_card.setProperty("class", "card")
        header_card_layout = QHBoxLayout(header_card)
        header_card_layout.setContentsMargins(18, 14, 18, 14)
        header_card_layout.setSpacing(14)

        self.header_icon_lbl = QLabel()
        self.header_icon_lbl.setFixedSize(48, 48)
        self.header_icon_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header_card_layout.addWidget(self.header_icon_lbl)

        title_box = QVBoxLayout()
        title_box.setSpacing(2)
        self.app_title = QLabel("Enclave")
        self.app_sub = QLabel("Sanal Disk ve BitLocker Yönetim Merkezi")
        title_box.addWidget(self.app_title)
        title_box.addWidget(self.app_sub)
        header_card_layout.addLayout(title_box)

        badges_box = QHBoxLayout()
        badges_box.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        badges_box.setSpacing(8)

        self.btn_settings = QPushButton(" Ayarlar")
        self.btn_settings.setObjectName("btn-settings")
        s_col = "#2997FF"
        self.btn_settings.setIcon(get_svg_icon("settings", s_col, 14))
        self.btn_settings.setToolTip("Görünüm ve Uygulama Ayarları")
        self.btn_settings.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_settings.clicked.connect(self.open_settings_dialog)
        badges_box.addWidget(self.btn_settings)

        header_card_layout.addLayout(badges_box)

        main_layout.addWidget(header_card)

        vault_card = QFrame()
        vault_card.setProperty("class", "card")
        vault_card_layout = QVBoxLayout(vault_card)
        vault_card_layout.setContentsMargins(18, 16, 18, 16)
        vault_card_layout.setSpacing(10)

        vault_lbl_row = QHBoxLayout()
        self.vault_lbl = QLabel("KASA DOSYASI")
        vault_lbl_row.addWidget(self.vault_lbl)
        
        self.bridge_tag = QLabel()
        self.bridge_tag.hide()
        vault_lbl_row.addWidget(self.bridge_tag)

        self.pref_letter_tag = QLabel()
        self.pref_letter_tag.hide()
        vault_lbl_row.addWidget(self.pref_letter_tag)

        self.capacity_badge = QLabel()
        self.capacity_badge.hide()
        vault_lbl_row.addWidget(self.capacity_badge)

        vault_lbl_row.addStretch()

        self.btn_vault_tools = QPushButton("Kasa Araçları")
        self.btn_vault_tools.setObjectName("btn-toolbar")
        self.init_vault_tools_menu()
        vault_lbl_row.addWidget(self.btn_vault_tools)

        vault_card_layout.addLayout(vault_lbl_row)

        selector_row = QHBoxLayout()
        self.combo_vaults = QComboBox()
        self.combo_vaults.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.combo_vaults.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon)
        self.combo_vaults.setMinimumContentsLength(16)
        self.combo_vaults.currentIndexChanged.connect(self.on_vault_selection_changed)
        selector_row.addWidget(self.combo_vaults)

        btn_browse = QPushButton("Gözat...")
        btn_browse.setObjectName("btn-browse")
        btn_browse.clicked.connect(self.on_browse_file)
        selector_row.addWidget(btn_browse)

        btn_refresh = QPushButton("Yenile")
        btn_refresh.setObjectName("btn-toolbar")
        btn_refresh.clicked.connect(self.refresh_vault_list)
        selector_row.addWidget(btn_refresh)
        vault_card_layout.addLayout(selector_row)

        self.dnd_hint = QLabel("İpucu: VHD dosyalarınızı doğrudan bu pencereye sürükleyip bırakabilir veya 'Gözat...' ile seçebilirsiniz.")
        self.dnd_hint.setWordWrap(True)
        vault_card_layout.addWidget(self.dnd_hint)

        info_row = QHBoxLayout()
        info_row.setSpacing(8)
        self.vault_path_info = QLabel()
        self.vault_path_info.setTextFormat(Qt.TextFormat.RichText)
        self.vault_path_info.setWordWrap(True)
        info_row.addWidget(self.vault_path_info, 1)

        vault_card_layout.addLayout(info_row)

        main_layout.addWidget(vault_card)

        status_card = QFrame()
        status_card.setProperty("class", "card")
        status_card_layout = QVBoxLayout(status_card)
        status_card_layout.setContentsMargins(18, 16, 18, 16)
        status_card_layout.setSpacing(12)

        status_lbl_row = QHBoxLayout()
        self.status_lbl = QLabel("DURUM & SÜRÜCÜ")
        status_lbl_row.addWidget(self.status_lbl)
        status_lbl_row.addStretch()
        status_card_layout.addLayout(status_lbl_row)

        status_top_row = QHBoxLayout()
        self.status_badge = QLabel("DİSK BAĞLI DEĞİL")
        self.status_badge.setStyleSheet(self.get_badge_style("not_mounted"))
        status_top_row.addWidget(self.status_badge)
        status_top_row.addStretch()

        self.drive_badge = QLabel("SÜRÜCÜ: -")
        self.drive_badge.setCursor(Qt.CursorShape.PointingHandCursor)
        self.drive_badge.setToolTip("Sürücü harfini değiştirmek veya sabitlemek için tıklayın")
        self.drive_badge.mousePressEvent = lambda e: self.on_drive_badge_clicked(e)
        self.drive_badge.setStyleSheet(self.get_badge_style("drive"))
        status_top_row.addWidget(self.drive_badge)
        status_card_layout.addLayout(status_top_row)

        capacity_box = QVBoxLayout()
        capacity_box.setSpacing(6)
        self.capacity_text = QLabel("Sanal disk bağlı değil")
        self.capacity_text.setWordWrap(True)
        self.capacity_bar = QProgressBar()
        self.capacity_bar.setValue(0)
        capacity_box.addWidget(self.capacity_text)
        capacity_box.addWidget(self.capacity_bar)
        status_card_layout.addLayout(capacity_box)

        self.actions_stack = QStackedWidget()
        self.actions_stack.setMinimumHeight(34)

        self.page_unmounted = QWidget()
        page_unmounted_layout = QHBoxLayout(self.page_unmounted)
        page_unmounted_layout.setContentsMargins(0, 0, 0, 0)
        page_unmounted_layout.setSpacing(0)

        self.btn_mount = QPushButton("Diski Bağla")
        self.btn_mount.setObjectName("btn-primary")
        self.btn_mount.setMinimumHeight(32)
        self.btn_mount.clicked.connect(self.on_mount_clicked)
        page_unmounted_layout.addWidget(self.btn_mount)
        self.actions_stack.addWidget(self.page_unmounted)

        self.page_mounted = QWidget()
        page_mounted_layout = QHBoxLayout(self.page_mounted)
        page_mounted_layout.setContentsMargins(0, 0, 0, 0)
        page_mounted_layout.setSpacing(10)

        self.btn_open_explorer = QPushButton("Dosya Gezgininde Aç")
        self.btn_open_explorer.setObjectName("btn-success")
        self.btn_open_explorer.setMinimumHeight(32)
        self.btn_open_explorer.clicked.connect(self.on_open_explorer_clicked)
        self.btn_open_explorer.hide()
        page_mounted_layout.addWidget(self.btn_open_explorer)

        self.btn_manage_password = QPushButton("Parola Yönet")
        self.btn_manage_password.setObjectName("btn-toolbar")
        self.btn_manage_password.setMinimumHeight(32)
        self.btn_manage_password.setToolTip("Kasanın BitLocker parolasını belirleyin, değiştirin veya şifrelemeyi yönetin")
        self.btn_manage_password.clicked.connect(self.on_manage_bitlocker_password)
        self.btn_manage_password.hide()
        page_mounted_layout.addWidget(self.btn_manage_password)

        self.btn_dismount = QPushButton("Diski Güvenle Ayır")
        self.btn_dismount.setObjectName("btn-danger")
        self.btn_dismount.setMinimumHeight(32)
        self.btn_dismount.clicked.connect(self.on_dismount_clicked)
        page_mounted_layout.addWidget(self.btn_dismount)
        self.actions_stack.addWidget(self.page_mounted)

        self.actions_stack.setCurrentIndex(0)
        status_card_layout.addWidget(self.actions_stack)
        main_layout.addWidget(status_card)

        self.unlock_card = QFrame()
        self.unlock_card.setProperty("class", "card-bitlocker")
        unlock_layout = QVBoxLayout(self.unlock_card)
        unlock_layout.setContentsMargins(18, 16, 18, 16)
        unlock_layout.setSpacing(12)

        unlock_header_row = QHBoxLayout()
        unlock_title_box = QVBoxLayout()
        unlock_title_box.setSpacing(4)
        
        self.unlock_title = QLabel("Kasa Güvenlik & Kilit Açma Paneli")
        self.unlock_desc = QLabel("Kasa şifreli durumda. Erişmek için parolanızı girin:")
        self.unlock_desc.setWordWrap(True)
        
        unlock_title_box.addWidget(self.unlock_title)
        unlock_title_box.addWidget(self.unlock_desc)
        unlock_header_row.addLayout(unlock_title_box)
        unlock_header_row.addStretch()

        self.btn_unlock_recovery = QPushButton("Kurtarma Anahtarı ile Aç")
        self.btn_unlock_recovery.setObjectName("btn-toolbar")
        self.btn_unlock_recovery.clicked.connect(self.on_unlock_with_recovery_key)
        unlock_header_row.addWidget(self.btn_unlock_recovery)

        self.btn_forgot_password = QPushButton("Şifremi Unuttum / Kurtar")
        self.btn_forgot_password.setObjectName("btn-toolbar")
        self.btn_forgot_password.setToolTip("Unutulan parolayı 48 haneli BitLocker kurtarma anahtarı ile sıfırlar ve kasayı açar")
        self.btn_forgot_password.clicked.connect(self.on_vault_password_recovery)
        unlock_header_row.addWidget(self.btn_forgot_password)

        self.btn_bdeunlock = QPushButton("Win Şifresi")
        self.btn_bdeunlock.setObjectName("btn-toolbar")
        self.btn_bdeunlock.clicked.connect(self.on_trigger_bdeunlock)
        unlock_header_row.addWidget(self.btn_bdeunlock)

        self.lbl_2fa_badge = QLabel("[2FA KORUMALI]")
        self.lbl_2fa_badge.setObjectName("badge-2fa")
        self.lbl_2fa_badge.setStyleSheet(
            "font-size: 11px; font-weight: 700; color: #38BDF8; "
            "background: rgba(56, 189, 248, 0.12); border: 1px solid rgba(56, 189, 248, 0.35); "
            "border-radius: 4px; padding: 3px 8px;"
        )
        self.lbl_2fa_badge.setToolTip("İki Faktörlü Doğrulama Aktif: Kasa kilidini açmak için hem parola hem de Windows Hello biyometrik onayı zorunludur.")
        self.lbl_2fa_badge.hide()
        unlock_header_row.addWidget(self.lbl_2fa_badge)

        unlock_layout.addLayout(unlock_header_row)

        pw_row = QHBoxLayout()
        pw_row.setSpacing(8)
        self.txt_password = QLineEdit()
        self.txt_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.txt_password.setPlaceholderText("BitLocker parolasını buraya yazın ve Enter'a basın...")
        self.txt_password.setMinimumHeight(32)
        self.txt_password.returnPressed.connect(self.on_unlock_with_password)
        pw_row.addWidget(self.txt_password)

        self.btn_show_pw = QPushButton("Göster")
        self.btn_show_pw.setMinimumWidth(65)
        self.btn_show_pw.setMinimumHeight(32)
        self.btn_show_pw.setCheckable(True)
        self.btn_show_pw.toggled.connect(self.toggle_password_visibility)
        pw_row.addWidget(self.btn_show_pw)

        self.btn_unlock_pw = QPushButton("Kilidi Aç")
        self.btn_unlock_pw.setObjectName("btn-accent")
        self.btn_unlock_pw.setMinimumWidth(100)
        self.btn_unlock_pw.setMinimumHeight(32)
        self.btn_unlock_pw.clicked.connect(self.on_unlock_with_password)
        pw_row.addWidget(self.btn_unlock_pw)

        unlock_layout.addLayout(pw_row)

        opt_row = QHBoxLayout()
        opt_row.setSpacing(10)
        self.chk_vault_2fa = QCheckBox("Bu kasa için İki Faktörlü Doğrulamayı (2FA: Şifre + Biyometrik) zorunlu kıl")
        self.chk_vault_2fa.setStyleSheet("font-size: 11px;")
        self.chk_vault_2fa.setToolTip("Açıldığında kasa kilidi açılırken önce kasa parolasının girilmesi, ardından Windows Hello biyometrik onayı verilmesi şart koşulur.")
        self.chk_vault_2fa.clicked.connect(self.on_vault_2fa_clicked)
        opt_row.addWidget(self.chk_vault_2fa)
        opt_row.addStretch()

        self.btn_header_restore_hint = QPushButton("Ayrılmış Başlık Yedeği & Kurtar...")
        self.btn_header_restore_hint.setObjectName("btn-toolbar")
        self.btn_header_restore_hint.setIcon(get_svg_icon("header_restore", "#38BDF8", 13))
        self.btn_header_restore_hint.setStyleSheet("font-size: 11px; padding: 2px 8px;")
        self.btn_header_restore_hint.setToolTip("Hasarlı kasa başlığını ayrılmış bir yedekten (.vheader / .vhdheader) kurtarır veya yedek alır")
        self.btn_header_restore_hint.clicked.connect(self.on_open_header_backup_restore)
        opt_row.addWidget(self.btn_header_restore_hint)
        unlock_layout.addLayout(opt_row)

        self.lbl_unlock_error = QLabel("")
        self.lbl_unlock_error.setWordWrap(True)
        self.lbl_unlock_error.hide()
        unlock_layout.addWidget(self.lbl_unlock_error)

        main_layout.addWidget(self.unlock_card)
        self.unlock_card.hide()

        settings_card = QFrame()
        settings_card.setProperty("class", "card")
        settings_layout = QVBoxLayout(settings_card)
        settings_layout.setContentsMargins(18, 16, 18, 16)
        settings_layout.setSpacing(12)

        settings_lbl_row = QHBoxLayout()
        self.settings_lbl = QLabel("GÜVENLİK VE SEÇENEKLER")
        settings_lbl_row.addWidget(self.settings_lbl)
        settings_lbl_row.addStretch()
        settings_layout.addLayout(settings_lbl_row)

        grid_settings = QGridLayout()
        grid_settings.setHorizontalSpacing(28)
        grid_settings.setVerticalSpacing(12)
        grid_settings.setContentsMargins(0, 0, 0, 0)
        grid_settings.setColumnStretch(0, 1)
        grid_settings.setColumnStretch(1, 1)

        self.chk_autoplay = QCheckBox("Autoplay Koruması")
        self.chk_autoplay.setChecked(self.config.get("autoplay_protection", True))
        self.chk_autoplay.stateChanged.connect(self.save_preferences)
        grid_settings.addWidget(self.chk_autoplay, 0, 0, Qt.AlignmentFlag.AlignVCenter)

        self.chk_auto_explorer = QCheckBox("Kilit Açılınca Gezgini Aç")
        self.chk_auto_explorer.setChecked(self.config.get("auto_open_explorer", True))
        self.chk_auto_explorer.stateChanged.connect(self.save_preferences)
        grid_settings.addWidget(self.chk_auto_explorer, 0, 1, Qt.AlignmentFlag.AlignVCenter)

        self.chk_close_dismount = QCheckBox("Kapatılınca Diski Otomatik Ayır")
        self.chk_close_dismount.setChecked(self.config.get("auto_dismount_on_close", True))
        self.chk_close_dismount.stateChanged.connect(self.save_preferences)
        grid_settings.addWidget(self.chk_close_dismount, 1, 0, Qt.AlignmentFlag.AlignVCenter)

        self.chk_lock_screen = QCheckBox("Windows Kilitlenince Diski Güvenle Ayır")
        self.chk_lock_screen.setChecked(self.config.get("lock_on_screen_lock", True))
        self.chk_lock_screen.stateChanged.connect(self.save_preferences)
        grid_settings.addWidget(self.chk_lock_screen, 1, 1, Qt.AlignmentFlag.AlignVCenter)

        self.chk_clean_traces = QCheckBox("İzleri ve Recent Temizle")
        self.chk_clean_traces.setChecked(self.config.get("cache_clean_on_dismount", True))
        self.chk_clean_traces.stateChanged.connect(self.save_preferences)
        grid_settings.addWidget(self.chk_clean_traces, 2, 0, Qt.AlignmentFlag.AlignVCenter)

        self.chk_auto_backup = QCheckBox("Çıkışta Otomatik Yedekle")
        self.chk_auto_backup.setChecked(self.config.get("auto_backup_enabled", False))
        self.chk_auto_backup.stateChanged.connect(self.save_preferences)
        grid_settings.addWidget(self.chk_auto_backup, 2, 1, Qt.AlignmentFlag.AlignVCenter)

        row_inactivity = QHBoxLayout()
        row_inactivity.setContentsMargins(0, 0, 0, 0)
        row_inactivity.setSpacing(8)
        row_inactivity.setAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)

        self.chk_inactivity = QCheckBox("Hareketsizlikte Kilitle:")
        self.chk_inactivity.setChecked(self.config.get("auto_lock_enabled", False))
        self.chk_inactivity.stateChanged.connect(self.on_inactivity_toggled)
        row_inactivity.addWidget(self.chk_inactivity)

        self.combo_inactivity_mins = QComboBox()
        self.combo_inactivity_mins.setMinimumWidth(70)
        self.combo_inactivity_mins.setMinimumHeight(24)
        self.combo_inactivity_mins.addItems(["30 sn", "1 dk", "2 dk", "5 dk", "10 dk", "15 dk", "30 dk"])
        mins_map = {0.5: 0, 1: 1, 2: 2, 5: 3, 10: 4, 15: 5, 30: 6}
        self.combo_inactivity_mins.setCurrentIndex(mins_map.get(self.config.get("auto_lock_minutes", 5), 3))
        self.combo_inactivity_mins.currentIndexChanged.connect(self.on_inactivity_mins_changed)
        row_inactivity.addWidget(self.combo_inactivity_mins)

        self.lbl_inactivity_countdown = QLabel("")
        self.lbl_inactivity_countdown.hide()
        row_inactivity.addWidget(self.lbl_inactivity_countdown)
        row_inactivity.addStretch()

        grid_settings.addLayout(row_inactivity, 3, 0)

        self.chk_tray = QCheckBox("Tepsiye Küçült")
        self.chk_tray.setChecked(self.config.get("minimize_to_tray_on_mount", False))
        self.chk_tray.stateChanged.connect(self.save_preferences)
        grid_settings.addWidget(self.chk_tray, 3, 1, Qt.AlignmentFlag.AlignVCenter)

        settings_layout.addLayout(grid_settings)

        main_layout.addWidget(settings_card)

        log_header = QHBoxLayout()
        self.log_lbl = QLabel("İŞLEM GÜNLÜĞÜ")
        log_header.addWidget(self.log_lbl)
        log_header.addStretch()

        btn_open_log = QPushButton("Bugünkü Logu Aç")
        btn_open_log.setObjectName("btn-toolbar")
        btn_open_log.clicked.connect(open_log_file)
        log_header.addWidget(btn_open_log)

        btn_open_logs_dir = QPushButton("Log Klasörü")
        btn_open_logs_dir.setObjectName("btn-toolbar")
        btn_open_logs_dir.clicked.connect(open_logs_folder)
        log_header.addWidget(btn_open_logs_dir)

        self.btn_clear_log = QPushButton("Temizle")
        self.btn_clear_log.setObjectName("btn-toolbar")
        self.btn_clear_log.clicked.connect(self.on_clear_log_clicked)
        log_header.addWidget(self.btn_clear_log)
        main_layout.addLayout(log_header)

        self.log_console = QTextEdit()
        self.log_console.setReadOnly(True)
        self.log_console.setMinimumHeight(120)
        self.log_console.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        main_layout.addWidget(self.log_console, 1)

        self.apply_theme(self.current_theme)
        self.update_vault_state_icon()
        self.log("Enclave hazır.", "info", "BASLANGIC")

    def init_vault_tools_menu(self):
        tools_menu = QMenu(self)

        action_new_vault = QAction("Yeni Kasa Oluştur...", self)
        action_new_vault.triggered.connect(self.on_create_vault_clicked)
        tools_menu.addAction(action_new_vault)

        tools_menu.addSeparator()

        action_compact = QAction("Diski Sıkıştır (Compact VHD)", self)
        action_compact.triggered.connect(self.on_compact_vault)
        tools_menu.addAction(action_compact)

        action_backup = QAction("Kasanın Yedeğini Al (Snapshot)", self)
        action_backup.triggered.connect(self.on_backup_vault)
        tools_menu.addAction(action_backup)

        action_header_backup = QAction("Ayrılmış Başlık Yedeği & Kurtarma (Header Backup)...", self)
        action_header_backup.setIcon(get_svg_icon("header_backup", "#38BDF8", 16))
        action_header_backup.triggered.connect(self.on_open_header_backup_restore)
        tools_menu.addAction(action_header_backup)

        action_hash = QAction("SHA-256 Bütünlük Doğrulaması", self)
        action_hash.triggered.connect(self.on_hash_vault)
        tools_menu.addAction(action_hash)

        tools_menu.addSeparator()

        action_pref_letter = QAction("Sabit Sürücü Harfi Ata...", self)
        action_pref_letter.triggered.connect(self.on_set_preferred_letter)
        tools_menu.addAction(action_pref_letter)

        action_change_letter = QAction("Bağlı Sürücü Harfini Değiştir...", self)
        action_change_letter.triggered.connect(self.on_change_drive_letter_clicked)
        tools_menu.addAction(action_change_letter)

        action_hook = QAction("Otomatik Başlatma Kancası (Hook)...", self)
        action_hook.triggered.connect(self.on_set_hook)
        tools_menu.addAction(action_hook)

        tools_menu.addSeparator()

        action_decoy = QAction("Tuzak (Decoy) Kasa Ayarla...", self)
        action_decoy.triggered.connect(self.on_configure_decoy)
        tools_menu.addAction(action_decoy)

        action_audit = QAction("Güvenlik Denetim Raporu (Audit)...", self)
        action_audit.triggered.connect(self.on_show_audit_log)
        tools_menu.addAction(action_audit)

        action_profiles = QAction("Çoklu Kasa Profilleri (Favoriler)...", self)
        action_profiles.triggered.connect(self.on_manage_profiles)
        tools_menu.addAction(action_profiles)

        action_mount_all = QAction("Tüm Profil Kasalarını Bağla (Çoklu Aç)...", self)
        action_mount_all.triggered.connect(self.on_mount_all_vaults)
        tools_menu.addAction(action_mount_all)

        action_dismount_all = QAction("Tüm Açık Kasaları Ayır...", self)
        action_dismount_all.triggered.connect(self.on_dismount_all_vaults)
        tools_menu.addAction(action_dismount_all)

        tools_menu.addSeparator()

        action_expand = QAction("Kasa Boyutunu Genişlet (Expand VHD)...", self)
        action_expand.triggered.connect(self.on_expand_vault)
        tools_menu.addAction(action_expand)

        action_health = QAction("Disk Sağlığı & Bütünlük Kontrolü (chkdsk)...", self)
        action_health.triggered.connect(self.on_disk_health)
        tools_menu.addAction(action_health)

        action_shell = QAction("Windows Gezgini Sağ Tık Menüsü...", self)
        action_shell.triggered.connect(self.on_shell_integration)
        tools_menu.addAction(action_shell)

        self.btn_vault_tools.setMenu(tools_menu)

    def setup_global_hotkey(self):
        """Windows API RegisterHotKey ile Ctrl+Alt+L kısayolunu kaydeder."""
        try:
            hwnd = int(self.winId())
            ret = ctypes.windll.user32.RegisterHotKey(hwnd, self.HOTKEY_ID, 0x0003, 0x4C)
            if ret:
                self.hotkey_registered = True
                self.log("Global panik tuşu aktif: Ctrl + Alt + L", "info", "PANIK")
            else:
                self.log("Panik tuşu kaydedilemedi (Kısayol başka bir programda kullanımda olabilir).", "warn", "PANIK")
        except Exception as e:
            self.log(f"Panik tuşu başlatma hatası: {e}", "error", "PANIK")

    def setup_session_notification(self):
        """Windows oturum kilitlenme (Win+L) olaylarını anlık yakalamak için WTS kaydı yapar."""
        try:
            hwnd = int(self.winId())
            if ctypes.windll.wtsapi32.WTSRegisterSessionNotification(hwnd, 0):
                self.wts_registered = True
        except Exception:
            self.wts_registered = False

    def nativeEvent(self, eventType, message):
        """Windows mesaj kuyruğundan WM_HOTKEY, WM_WTSSESSION_CHANGE, WM_DEVICECHANGE ve WM_DROPFILES yakalar."""
        try:
            if eventType in (b"windows_generic_MSG", "windows_generic_MSG"):
                msg_id = _C_UINT_FROM_ADDR(int(message) + _MSG_OFFSET_MESSAGE).value
                if msg_id not in (0x0312, 0x02B1, 0x0219, 0x0233):
                    return False, 0
                msg = wintypes.MSG.from_address(int(message))
                if msg.message == 0x0312 and msg.wParam == self.HOTKEY_ID:
                    self.trigger_panic_kill_switch()
                    return True, 0

                elif msg.message == 0x02B1:
                    if msg.wParam in (0x7, 0x6):
                        has_vault_active = (
                            self.is_mounted or 
                            getattr(self, "is_custom_vault_open", False) or 
                            (getattr(self, "current_custom_explorer", None) is not None)
                        )
                        if self.chk_lock_screen.isChecked() and has_vault_active:
                            self.trigger_screen_lock_dismount()
                            return True, 0

                elif msg.message == 0x0219:
                    if getattr(self, "is_switching_decoy", False):
                        return False, 0
                    if self.is_mounted and not getattr(self, "is_dismounting", False) and not getattr(self, "is_changing_letter", False):
                        self.check_external_dismount()
                        QTimer.singleShot(150, self.check_external_dismount)

                elif msg.message == 0x0233:
                    hDrop = msg.wParam
                    num = ctypes.windll.shell32.DragQueryFileW(hDrop, 0xFFFFFFFF, None, 0)
                    file_paths = []
                    for i in range(num):
                        buf = ctypes.create_unicode_buffer(1024)
                        ctypes.windll.shell32.DragQueryFileW(hDrop, i, buf, 1024)
                        if buf.value:
                            file_paths.append(buf.value)
                    ctypes.windll.shell32.DragFinish(hDrop)
                    if file_paths:
                        if getattr(self, "is_custom_vault_open", False) and getattr(self, "current_custom_explorer", None):
                            self.current_custom_explorer.handle_dropped_paths(file_paths)
                        else:
                            urls = [QUrl.fromLocalFile(fp) for fp in file_paths]
                            self.process_dropped_urls(urls)
                    return True, 0
        except Exception:
            pass
        res = super().nativeEvent(eventType, message)
        if isinstance(res, tuple) and len(res) == 2:
            handled, val = res
            return handled, (0 if val is None else val)
        return False, 0

    def trigger_screen_lock_dismount(self):
        """Windows oturumu kilitlendiğinde diski veya bağımsız kasayı derhal ve zorla ayırır / kilitler."""
        has_mounted_vhd = self.is_mounted
        has_custom = getattr(self, "is_custom_vault_open", False) or (getattr(self, "current_custom_explorer", None) is not None)

        if not has_mounted_vhd and not has_custom:
            return
        if getattr(self, "is_dismounting", False):
            return

        self.log("Windows kilitlendiği algılandı (Win+L). Kasa güvenlik amacıyla derhal kapatılıyor / ayrılıyor...", "warn", "GUVENLIK")

        if getattr(self, "current_custom_explorer", None):
            try:
                self.current_custom_explorer.lock_and_close()
            except Exception:
                pass
            self.current_custom_explorer = None
        self.is_custom_vault_open = False

        if has_mounted_vhd:
            self.is_dismounting = True
            self.is_mounted = False

            self.terminate_hook_processes()

            drive_to_close = self.drive_letter or self.engine.active_drive_letter
            if drive_to_close:
                self.engine.close_explorer_windows(drive_to_close)

            self.status_timer.stop()

            target = (self.active_decoy_path if getattr(self, "is_decoy_active", False) and getattr(self, "active_decoy_path", None)
                      else (self.current_vault_file or self.engine.active_mount_target))
            self.engine.dismount_vhd(mount_target=target, drive_letter=drive_to_close, force=True)

            if self.chk_autoplay.isChecked():
                self.engine.restore_autoplay()

            self.on_dismount_finished({"success": True})
        else:
            self.reset_to_unmounted_state(show_tray_message=False)

        if hasattr(self, "tray_icon"):
            self.tray_icon.showMessage(
                "Enclave",
                "Windows kilitlendiği için açık kasa güvenle kapatıldı / ayrıldı.",
                QSystemTrayIcon.MessageIcon.Warning,
                2000
            )

    def trigger_panic_kill_switch(self):
        """Panik tuşu tetiklendiğinde pencereyi derhal gizler, diski zorla ayırır, gezgini kapatır ve izleri siler."""
        self.hide()
        if getattr(self, "current_custom_explorer", None):
            try:
                self.current_custom_explorer.lock_and_close()
            except Exception:
                pass
            self.current_custom_explorer = None
        for child in self.findChildren(QDialog):
            try:
                child.reject()
            except Exception:
                try:
                    child.hide()
                except Exception:
                    pass

        audit_logger.log_security_event("PANIC_TRIGGERED", "DANGER", "Panik kısayolu tetiklendi, disk zorla ayrıldı.", self.current_vault_file, self.drive_letter)
        self.log("Acil durum panik tuşu tetiklendi! Disk zorla ayrılıyor ve izler temizleniyor...", "warn", "PANIK")
        
        self.terminate_hook_processes()

        drive_to_close = self.drive_letter or self.engine.active_drive_letter
        if drive_to_close:
            self.engine.close_explorer_windows(drive_to_close)

        self.status_timer.stop()
        self.is_dismounting = True
        self.is_mounted = False

        target = (self.active_decoy_path if getattr(self, "is_decoy_active", False) and getattr(self, "active_decoy_path", None)
                  else (self.current_vault_file or self.engine.active_mount_target))
        try:
            self.engine.dismount_vhd(mount_target=target, drive_letter=drive_to_close, force=True)
        except Exception as e:
            self.log(f"Panik ayırma hatası: {e}", "error", "PANIK")

        if self.chk_autoplay.isChecked():
            self.engine.restore_autoplay()

        try:
            self.engine.wipe_system_traces(drive_to_close)
        except Exception:
            pass

        self.reset_to_unmounted_state(show_tray_message=False)

        if hasattr(self, "tray_icon") and self.tray_icon.isVisible():
            self.tray_icon.showMessage(
                "Enclave - Güvenlik",
                "Acil durum panik modu devrede: Sanal disk ayrıldı ve sistem izleri temizlendi.",
                QSystemTrayIcon.MessageIcon.Warning,
                3000
            )

    def on_inactivity_toggled(self, state: int):
        """Hareketsizlik onay kutusu değiştirildiğinde tetiklenir."""
        if not self.chk_inactivity.isChecked():
            if hasattr(self, "lbl_inactivity_countdown"):
                self.lbl_inactivity_countdown.hide()
        else:
            self.reset_inactivity_timer()
        self.save_preferences()

    def on_inactivity_mins_changed(self):
        """Hareketsizlik süresi açılır menüsü değiştiğinde tetiklenir."""
        self.reset_inactivity_timer()
        self.save_preferences()

    def reset_inactivity_timer(self):
        """Kullanıcı bilgisayarı aktif kullandığında hareketsizlik sayacını sıfırlar ve göstergeyi tazeler."""
        now = time.time()
        was_idle = (now - getattr(self, "last_vault_activity_time", now)) >= 1.0
        self.last_vault_activity_time = now
        if was_idle and hasattr(self, "combo_inactivity_mins"):
            sec_list = [30, 60, 120, 300, 600, 900, 1800]
            idx = self.combo_inactivity_mins.currentIndex()
            threshold_sec = sec_list[idx] if (0 <= idx < len(sec_list)) else 300
            self.update_countdown_display(threshold_sec)

    def update_countdown_display(self, remaining_sec: int):
        """Hareketsizlik geri sayım etiketini şık bir biçimde günceller."""
        if hasattr(self, "lbl_inactivity_countdown"):
            if not self.chk_inactivity.isChecked() or not self.is_mounted:
                self.lbl_inactivity_countdown.hide()
                return
            rem_m = remaining_sec // 60
            rem_s = remaining_sec % 60
            is_light = (getattr(self, "current_theme", "dark") == "light")
            txt_col = "#4F46E5" if is_light else "#818CF8"
            self.lbl_inactivity_countdown.setStyleSheet(f"font-size: 11px; font-weight: 700; color: {txt_col}; padding-left: 2px;")
            self.lbl_inactivity_countdown.setText(f"({rem_m:02d}:{rem_s:02d})")
            self.lbl_inactivity_countdown.show()

    def poll_global_activity(self):
        """Sistem genelindeki (tüm pencereler, arka plan, masaüstü) kullanıcı etkileşimini tarar."""
        has_active = self.is_mounted or getattr(self, "is_custom_vault_open", False) or (getattr(self, "current_custom_explorer", None) is not None)
        if not has_active or not self.chk_inactivity.isChecked():
            return

        now = time.time()
        user32 = ctypes.windll.user32

        pt = POINT()
        if user32.GetCursorPos(ctypes.byref(pt)):
            cur_pos = (pt.x, pt.y)
            if self.last_cursor_pos is not None:
                if cur_pos != self.last_cursor_pos:
                    self.reset_inactivity_timer()
            self.last_cursor_pos = cur_pos

        gas = user32.GetAsyncKeyState
        for vk in ACTIVE_KEY_CODES:
            if gas(vk) & 0x8000:
                self.reset_inactivity_timer()
                return

        fg_hwnd = user32.GetForegroundWindow()
        if fg_hwnd:
            if self.last_fg_hwnd is not None and fg_hwnd != self.last_fg_hwnd:
                self.reset_inactivity_timer()
            self.last_fg_hwnd = fg_hwnd

    def check_security_conditions(self):
        """Hareketsizlik ve Windows kilitlenme durumlarını periyodik denetler."""
        has_mounted_vhd = self.is_mounted
        has_custom = getattr(self, "is_custom_vault_open", False) or (getattr(self, "current_custom_explorer", None) is not None)

        if not has_mounted_vhd and not has_custom:
            if hasattr(self, "lbl_inactivity_countdown"):
                self.lbl_inactivity_countdown.hide()
            return

        if getattr(self, "is_dismounting", False) or (self.worker and self.worker.isRunning()):
            return

        if self.chk_lock_screen.isChecked():
            if self.engine.is_workstation_locked():
                self.trigger_screen_lock_dismount()
                return

        if not (has_mounted_vhd or has_custom):
            return

        if self.chk_inactivity.isChecked():
            sec_list = [30, 60, 120, 300, 600, 900, 1800]
            idx = self.combo_inactivity_mins.currentIndex()
            threshold_sec = sec_list[idx] if (0 <= idx < len(sec_list)) else 300

            now = time.time()

            sys_idle_sec = self.engine.get_system_idle_seconds()
            if sys_idle_sec < 1.5:
                self.last_vault_activity_time = now

            if self.is_mounted and self.drive_letter:
                dl = self.drive_letter.rstrip(":").upper()
                fg_hwnd = ctypes.windll.user32.GetForegroundWindow()
                if fg_hwnd:
                    buf = ctypes.create_unicode_buffer(512)
                    ctypes.windll.user32.GetWindowTextW(fg_hwnd, buf, 512)
                    title_upper = buf.value.upper()
                    if f"({dl}:)" in title_upper or f"{dl}:\\" in title_upper or f" {dl}:" in title_upper or title_upper.startswith(f"{dl}:"):
                        self.last_vault_activity_time = now

            if has_custom and getattr(self, "current_custom_explorer", None) is not None:
                try:
                    fg_hwnd = ctypes.windll.user32.GetForegroundWindow()
                    if fg_hwnd and int(self.current_custom_explorer.winId()) == fg_hwnd:
                        self.last_vault_activity_time = now
                except Exception:
                    pass

            effective_idle_sec = max(0.0, now - getattr(self, "last_vault_activity_time", now))
            remaining_sec = max(0, int(threshold_sec - effective_idle_sec))

            self.update_countdown_display(remaining_sec)

            if effective_idle_sec >= threshold_sec:
                self.trigger_inactivity_dismount()
                return
        else:
            if hasattr(self, "lbl_inactivity_countdown"):
                self.lbl_inactivity_countdown.hide()

    def trigger_inactivity_dismount(self):
        """Hareketsizlik süresi dolduğunda kasayı (VHD veya Bağımsız Kasa) güvenle ve kesin olarak ayırır/kilitler."""
        if getattr(self, "is_dismounting", False) or (self.worker and self.worker.isRunning()):
            return

        lbl_text = self.combo_inactivity_mins.currentText()
        if hasattr(self, "lbl_inactivity_countdown"):
            self.lbl_inactivity_countdown.setText("")
            self.lbl_inactivity_countdown.hide()

        if getattr(self, "current_custom_explorer", None) is not None:
            try:
                self.log(f"Hareketsizlik süresi ({lbl_text}) doldu. Bağımsız kasa güvenlik amacıyla kilitleniyor...", "warn", "GUVENLIK")
                self.current_custom_explorer.lock_and_close()
            except Exception:
                pass

        if self.is_mounted:
            self.log(f"Hareketsizlik süresi ({lbl_text}) doldu. Sanal disk güvenlik amacıyla güvenle ayrılıyor...", "warn", "GUVENLIK")
            self.on_dismount_clicked(force=True)

    def on_create_vault_clicked(self):
        dlg = CreateVaultDialog(self, theme=self.current_theme)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            params = dlg.get_vault_params()
            self.set_ui_busy(True, "Yeni kasa oluşturuluyor...")
            self.worker = VaultWorker("create_vault", self.engine, params)
            self.worker.log_signal.connect(self.log)
            self.worker.finished_signal.connect(self.on_create_vault_finished)
            self.worker.start()

    def on_create_vault_finished(self, result: dict):
        self.set_ui_busy(False)
        if result.get("success"):
            new_path = result.get("path")
            self.current_vault_file = new_path

            if result.get("vault_type") == "pvault" or str(new_path).lower().endswith(".pvault"):
                audit_logger.log_security_event("VAULT_CREATED", "SUCCESS", f"Yeni bağımsız AES-256 kasası oluşturuldu: {Path(new_path).name}", new_path)
                self.refresh_vault_list()
                for i in range(self.combo_vaults.count()):
                    if self.combo_vaults.itemData(i) == new_path:
                        self.combo_vaults.setCurrentIndex(i)
                        break
                self.update_vault_path_display()
                decoy_txt = "\n• Plausible Deniability Tuzak Kasa Yuvası Aktif" if result.get("has_decoy") else ""
                mfa_txt = "\n• İki Faktörlü Doğrulama (2FA - TOTP): Aktif ve Mühürlü" if result.get("has_2fa") else ""
                QMessageBox.information(
                    self,
                    "Kasa Oluşturuldu",
                    f"Yeni Bağımsız AES-256-GCM Kasa Başarıyla Oluşturuldu!\n\n"
                    f"• Dosya: {Path(new_path).name}\n"
                    f"• Şifreleme: AES-256-GCM (600.000 Tur PBKDF2)\n"
                    f"• Bütünlük: AEAD Doğrulamalı{mfa_txt}{decoy_txt}\n\n"
                    "Bu kasa Windows BitLocker veya sürücü gerektirmez. 'Kasa Gezginini Aç' butonu ile doğrudan yönetebilirsiniz."
                )
                return

            self.refresh_vault_list()
            for i in range(self.combo_vaults.count()):
                if self.combo_vaults.itemData(i) == new_path:
                    self.combo_vaults.setCurrentIndex(i)
                    break
            self.check_if_already_attached(new_path)
            self.update_vault_path_display()
            
            rec_key = result.get("recovery_key", "")
            decoy_rec_key = result.get("decoy_recovery_key", "")
            if rec_key or decoy_rec_key:
                audit_logger.log_security_event("VAULT_CREATED", "SUCCESS", f"Yeni BitLocker kasası oluşturuldu: {Path(new_path).name}", new_path)
                try:
                    display_key = rec_key
                    if decoy_rec_key and decoy_rec_key != rec_key:
                        display_key += f"\n\n--- [GÖMÜLÜ TUZAK KASA KURTARMA ANAHTARI] ---\n{decoy_rec_key}"
                    rec_dlg = BitLockerRecoveryDialog(self, recovery_key=display_key, drive_letter="Yeni Kasa", theme=self.current_theme, vault_name=Path(new_path).name, vault_path=new_path)
                    rec_dlg.exec()
                except Exception as e:
                    self.log(f"Kurtarma sertifikası gösterilemedi: {e}", "warn", "HATA")
            else:
                QMessageBox.information(self, "Başarılı", f"Yeni sanal kasa başarıyla oluşturuldu:\n{Path(new_path).name}")
        else:
            QMessageBox.critical(self, "Hata", f"Kasa oluşturulamadı:\n{result.get('error')}")

    def on_compact_vault(self):
        if self.is_mounted:
            QMessageBox.warning(self, "Uyarı", "Diski sıkıştırmak için önce diski güvenle ayırmalısınız.")
            return
        if not self.current_vault_file or not Path(self.current_vault_file).exists():
            QMessageBox.warning(self, "Hata", "Lütfen geçerli bir kasa dosyası seçin.")
            return

        self.set_ui_busy(True, "Disk sıkıştırılıyor (Diskpart Compact)...")
        self.worker = VaultWorker("compact", self.engine, {"vault_path": self.current_vault_file})
        self.worker.log_signal.connect(self.log)
        self.worker.finished_signal.connect(self.on_compact_finished)
        self.worker.start()

    def on_compact_finished(self, result: dict):
        self.set_ui_busy(False)
        if result.get("success"):
            saved = result.get("saved_mb", 0)
            initial = result.get("initial_size_mb", result.get("initial_mb", 0))
            final = result.get("final_size_mb", result.get("final_mb", 0))
            pct = result.get("saved_pct", 0)
            audit_logger.log_security_event("VHD_COMPACT", "SUCCESS", f"Kasa sıkıştırıldı. Geri kazanılan: {saved} MB (%{pct})", self.current_vault_file)
            QMessageBox.information(
                self,
                "Sıkıştırma Tamamlandı",
                f"Sanal disk başarıyla sıkıştırıldı!\n\n"
                f"• Önceki Boyut: {initial} MB\n"
                f"• Yeni Boyut: {final} MB\n"
                f"• Geri Kazanılan Boş Alan: {saved} MB (%{pct})"
            )
        else:
            QMessageBox.warning(self, "Hata", f"Sıkıştırma başarısız:\n{result.get('error')}")

    def on_backup_vault(self):
        if self.is_mounted:
            QMessageBox.warning(self, "Uyarı", "Bütünlüğü korumak için yedek almadan önce diski ayırın.")
            return
        if not self.current_vault_file or not Path(self.current_vault_file).exists():
            QMessageBox.warning(self, "Hata", "Lütfen geçerli bir kasa dosyası seçin.")
            return

        self.set_ui_busy(True, "Kasa yedeği alınıyor...")
        self.worker = VaultWorker("backup", self.engine, {"vault_path": self.current_vault_file})
        self.worker.log_signal.connect(self.log)
        self.worker.finished_signal.connect(lambda res: self.set_ui_busy(False))
        self.worker.start()

    def on_hash_vault(self):
        if not self.current_vault_file or not Path(self.current_vault_file).exists():
            QMessageBox.warning(self, "Hata", "Lütfen geçerli bir kasa dosyası seçin.")
            return

        self.set_ui_busy(True, "SHA-256 hash hesaplanıyor...")
        self.worker = VaultWorker("hash", self.engine, {"vault_path": self.current_vault_file})
        self.worker.log_signal.connect(self.log)
        self.worker.finished_signal.connect(self.on_hash_finished)
        self.worker.start()

    def on_hash_finished(self, result: dict):
        self.set_ui_busy(False)
        if result.get("success"):
            h = result.get("sha256")
            name = result.get("file_name")
            QMessageBox.information(self, "SHA-256 Bütünlük Özeti", f"Dosya: {name}\n\nSHA-256 Hash:\n{h}")

    def on_set_preferred_letter(self):
        if not self.current_vault_file:
            return
        
        pref_letters = self.config.get("preferred_drive_letters", {})
        cur_pref = pref_letters.get(self.current_vault_file, "")

        dlg = QDialog(self)
        dlg.setWindowTitle("Sabit Sürücü Harfi Ata")
        dlg.resize(400, 190)
        dlg.setMinimumSize(360, 170)
        set_window_dark_mode(int(dlg.winId()), self.current_theme == "dark")
        dlg.setStyleSheet(get_theme_qss(self.current_theme))
        l = QVBoxLayout(dlg)
        
        info = QLabel(f"Kasa: {Path(self.current_vault_file).name}\nBu kasa bağlandığında öncelikli olarak hangi harf atansın?")
        l.addWidget(info)

        combo = QComboBox()
        combo.addItem("Otomatik (Windows Belirlesin)", "")
        for ch in "DEFGHIJKLMNOPQRSTUVWXYZ":
            combo.addItem(f"{ch}: Sürücüsü", ch)
            if cur_pref == ch:
                combo.setCurrentIndex(combo.count() - 1)
        l.addWidget(combo)

        btn_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        btn_box.accepted.connect(dlg.accept)
        btn_box.rejected.connect(dlg.reject)
        l.addWidget(btn_box)

        if dlg.exec() == QDialog.DialogCode.Accepted:
            sel = combo.currentData()
            if sel:
                pref_letters[self.current_vault_file] = sel
            else:
                pref_letters.pop(self.current_vault_file, None)
            self.config["preferred_drive_letters"] = pref_letters
            save_config(self.config)
            self.update_bridge_tag()
            self.log(f"Tercih edilen sürücü harfi güncellendi: {sel or 'Otomatik'}", "info", "AYAR")

            if self.is_mounted and self.drive_letter and sel:
                cur_clean = self.drive_letter.rstrip(":").upper()
                if cur_clean != sel:
                    reply = QMessageBox.question(
                        self,
                        "Sürücü Harfini Şimdi Değiştir",
                        f"Bu sanal disk şu anda '{self.drive_letter}' harfiyle sisteme bağlı.\n\n"
                        f"Sürücü harfi şimdi anında '{sel}:' olarak güncellensin mi?",
                        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                    )
                    if reply == QMessageBox.StandardButton.Yes:
                        self.execute_change_drive_letter(f"{sel}:", remember=True)

    def on_drive_badge_clicked(self, event):
        if self.is_mounted and self.drive_letter:
            self.on_change_drive_letter_clicked()
        elif self.current_vault_file:
            self.on_set_preferred_letter()

    def on_change_drive_letter_clicked(self):
        if not self.is_mounted or not self.drive_letter:
            QMessageBox.information(self, "Bilgi", "Sürücü harfini değiştirmek için diskin bağlı olması gerekir.")
            return

        cur_letter = self.drive_letter.rstrip(":").upper()
        avail = self.engine.get_available_drive_letters()
        if not avail:
            QMessageBox.warning(self, "Hata", "Sistemde atanabilecek boş sürücü harfi bulunamadı.")
            return

        pal = get_dialog_palette(self.current_theme)
        is_dark = pal["is_dark"]
        dlg = QDialog(self)
        dlg.setWindowTitle("Bağlı Sürücü Harfini Değiştir")
        set_window_dark_mode(int(dlg.winId()), is_dark)
        set_dialog_dark_mode(dlg, is_dark)
        apply_dynamic_geometry(dlg, default_w=460, default_h=240, min_w=400, min_h=200)
        dlg.setStyleSheet(f"""
            QDialog {{
                background-color: {pal['bg_col']};
                color: {pal['text_col']};
                font-family: -apple-system, 'SF Pro Text', 'Segoe UI Variable', sans-serif;
            }}
            {get_dialog_button_stylesheet(self.current_theme)}
        """)
        
        layout = QVBoxLayout(dlg)
        layout.setSpacing(12)

        vault_name = Path(self.current_vault_file).name if self.current_vault_file else "Sanal Kasa"
        info_lbl = QLabel(f"<b>Kasa:</b> {vault_name}<br><b>Mevcut Harf:</b> {self.drive_letter}")
        info_lbl.setStyleSheet("font-family: 'Segoe UI', 'Inter', 'Arial', sans-serif; font-size: 11px; line-height: 1.4;")
        layout.addWidget(info_lbl)

        label_select = QLabel("Yeni atanacak boş sürücü harfini seçin:")
        label_select.setStyleSheet("font-family: 'Segoe UI', 'Inter', 'Arial', sans-serif; font-size: 11px; font-weight: 700; color: #38BDF8;" if is_dark else "font-family: 'Segoe UI', 'Inter', 'Arial', sans-serif; font-size: 11px; font-weight: 700; color: #0284C7;")
        layout.addWidget(label_select)

        combo = QComboBox()
        for ch in avail:
            combo.addItem(f"{ch}: (Boş Sürücü)", ch)
        layout.addWidget(combo)

        chk_remember = QCheckBox("Bu kasanın sabit tercih edilen harfi olarak da kaydet")
        chk_remember.setChecked(True)
        layout.addWidget(chk_remember)

        btn_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        btn_box.button(QDialogButtonBox.StandardButton.Ok).setText("Harfi Değiştir")
        btn_box.button(QDialogButtonBox.StandardButton.Cancel).setText("İptal")
        btn_box.accepted.connect(dlg.accept)
        btn_box.rejected.connect(dlg.reject)
        layout.addWidget(btn_box)

        if dlg.exec() == QDialog.DialogCode.Accepted:
            selected_letter = combo.currentData()
            remember = chk_remember.isChecked()
            if selected_letter:
                self.execute_change_drive_letter(selected_letter, remember=remember)

    def execute_change_drive_letter(self, new_letter: str, remember: bool = True):
        if getattr(self, "is_changing_letter", False) or getattr(self, "is_mounting", False) or getattr(self, "is_dismounting", False) or (self.worker and self.worker.isRunning()):
            return
        
        old_letter = self.drive_letter
        new_clean = new_letter.rstrip(":").upper()
        if old_letter.rstrip(":").upper() == new_clean:
            return

        self.is_changing_letter = True
        self.set_ui_busy(True, f"Sürücü harfi {old_letter} -> {new_clean}: olarak değiştiriliyor...")
        
        self.worker = VaultWorker(
            "change_letter",
            self.engine,
            {
                "old_letter": old_letter,
                "new_letter": f"{new_clean}:",
                "remember": remember,
                "vault_file": self.current_vault_file
            }
        )
        self.worker.log_signal.connect(self.log)
        self.worker.finished_signal.connect(self.on_change_letter_finished)
        self.worker.start()

    def on_change_letter_finished(self, result: dict):
        self.is_changing_letter = False
        self.set_ui_busy(False)
        if result.get("success"):
            new_letter = result.get("drive_letter", "")
            self.drive_letter = new_letter
            self.drive_badge.setText(f"SÜRÜCÜ: {new_letter}")
            self.drive_badge.setStyleSheet(self.get_badge_style("drive"))

            if result.get("remember") and result.get("vault_file"):
                v_file = result.get("vault_file")
                pref = self.config.get("preferred_drive_letters", {})
                pref[v_file] = new_letter.rstrip(":").upper()
                self.config["preferred_drive_letters"] = pref
                save_config(self.config)
                self.update_bridge_tag()

            if hasattr(self, "tray_icon"):
                lock_text = "Kilitli" if self.is_locked else "Açık"
                self.action_tray_status.setText(f"Durum: {self.drive_letter} ({lock_text})")
            
            self.poll_volume_status()
            self.log(f"Sürücü harfi başarıyla güncellendi: {new_letter}", "success", "SURUCU")
        else:
            QMessageBox.critical(self, "Harf Değiştirme Hatası", f"Sürücü harfi değiştirilemedi:\n{result.get('error')}")

    def on_set_hook(self):
        if not self.current_vault_file:
            return

        hooks = self.config.get("auto_run_hooks", {})
        cur_hook = hooks.get(self.current_vault_file, {})

        dlg = QDialog(self)
        dlg.setWindowTitle("Otomatik Başlatma Kancası (Hook)")
        dlg.resize(500, 240)
        dlg.setMinimumSize(460, 210)
        set_window_dark_mode(int(dlg.winId()), self.current_theme == "dark")
        dlg.setStyleSheet(get_theme_qss(self.current_theme))
        l = QVBoxLayout(dlg)

        info = QLabel(f"Kasa ({Path(self.current_vault_file).name}) kilidi açıldığında otomatik başlatılacak program:")
        l.addWidget(info)

        row = QHBoxLayout()
        txt_path = QLineEdit(cur_hook.get("startup_path", ""))
        btn_browse = QPushButton("Gözat...")
        btn_browse.clicked.connect(lambda: txt_path.setText(QFileDialog.getOpenFileName(dlg, "Başlatılacak Dosyayı Seçin")[0] or txt_path.text()))
        row.addWidget(txt_path)
        row.addWidget(btn_browse)
        l.addLayout(row)

        chk_kill = QCheckBox("Kasa kapatılırken başlatılan programı otomatik sonlandır")
        chk_kill.setChecked(cur_hook.get("kill_on_close", True))
        l.addWidget(chk_kill)

        btn_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        btn_box.accepted.connect(dlg.accept)
        btn_box.rejected.connect(dlg.reject)
        l.addWidget(btn_box)

        if dlg.exec() == QDialog.DialogCode.Accepted:
            p = txt_path.text().strip()
            if p:
                hooks[self.current_vault_file] = {"startup_path": p, "kill_on_close": chk_kill.isChecked()}
            else:
                hooks.pop(self.current_vault_file, None)
            self.config["auto_run_hooks"] = hooks
            save_config(self.config)
            self.log(f"Otomatik başlatma kancası güncellendi: {Path(p).name if p else 'Kaldırıldı'}", "info", "AYAR")

    def run_hook_for_vault(self):
        hooks = self.config.get("auto_run_hooks", {})
        hook_info = hooks.get(self.current_vault_file)
        if hook_info:
            target = hook_info.get("startup_path")
            if target and Path(target).exists():
                try:
                    import subprocess
                    proc = subprocess.Popen([target])
                    self.hook_processes.append(proc)
                    self.log(f"Kanca programı başlatıldı: {Path(target).name}", "success", "KANCA")
                except Exception as e:
                    self.log(f"Kanca programı başlatılamadı: {e}", "error", "HATA")

    def terminate_hook_processes(self):
        for proc in self.hook_processes:
            try:
                proc.terminate()
            except Exception:
                pass
        self.hook_processes.clear()

    def init_tray(self):
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return
        
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(create_vault_icon("closed"))
        self.tray_icon.setToolTip("Enclave")

        tray_menu = QMenu()

        self.action_tray_status = QAction("Durum: Bağlı Değil", self)
        self.action_tray_status.setEnabled(False)
        tray_menu.addAction(self.action_tray_status)
        tray_menu.addSeparator()

        self.action_tray_open = QAction("Dosya Gezgininde Aç", self)
        self.action_tray_open.triggered.connect(self.on_open_explorer_clicked)
        self.action_tray_open.setEnabled(False)
        tray_menu.addAction(self.action_tray_open)

        self.action_tray_dismount = QAction("Diski Güvenle Ayır", self)
        self.action_tray_dismount.triggered.connect(self.on_dismount_clicked)
        self.action_tray_dismount.setEnabled(False)
        tray_menu.addAction(self.action_tray_dismount)
        tray_menu.addSeparator()

        action_show = QAction("Pencereyi Göster / Gizle", self)
        action_show.triggered.connect(self.toggle_window_visibility)
        tray_menu.addAction(action_show)

        action_exit = QAction("Çıkış", self)
        action_exit.triggered.connect(self.safe_exit)
        tray_menu.addAction(action_exit)

        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.activated.connect(self.on_tray_activated)
        self.tray_icon.show()

    def on_tray_activated(self, reason):
        if reason == QSystemTrayIcon.ActivationReason.Trigger:
            self.toggle_window_visibility()

    def toggle_window_visibility(self):
        if self.isVisible():
            self.hide()
        else:
            self.showNormal()
            self.activateWindow()

    def update_admin_badge(self):
        if not getattr(self, "admin_badge", None):
            return
        is_adm = self.engine.is_admin()
        theme = getattr(self, "current_theme", "dark")
        font_style = "font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif; font-size: 11px; font-weight: 700; padding: 5px 14px; border-radius: 12px;"
        if is_adm:
            self.admin_badge.setText("YÖNETİCİ: AKTİF")
            if theme == "apple_dark":
                self.admin_badge.setStyleSheet(f"background-color: #102616; color: #30D158; border: 1px solid rgba(48, 209, 88, 0.4); {font_style}")
            elif theme == "apple_light":
                self.admin_badge.setStyleSheet(f"background-color: #EDFAF1; color: #248A3D; border: 1px solid rgba(52, 199, 89, 0.4); {font_style}")
            elif theme == "light":
                self.admin_badge.setStyleSheet(f"background-color: #DCFCE7; color: #166534; border: 1px solid #22C55E; {font_style}")
            else:
                self.admin_badge.setStyleSheet(f"background-color: #064E3B; color: #34D399; border: 1px solid #10B981; {font_style}")
        else:
            self.admin_badge.setText("YÖNETİCİ İSTE")
            if theme == "apple_dark":
                self.admin_badge.setStyleSheet(f"background-color: #2C1618; color: #FF453A; border: 1px solid rgba(255, 69, 58, 0.4); cursor: pointer; {font_style}")
            elif theme == "apple_light":
                self.admin_badge.setStyleSheet(f"background-color: #FFF0F0; color: #D70015; border: 1px solid rgba(255, 59, 48, 0.4); cursor: pointer; {font_style}")
            elif theme == "light":
                self.admin_badge.setStyleSheet(f"background-color: #FEE2E2; color: #991B1B; border: 1px solid #EF4444; cursor: pointer; {font_style}")
            else:
                self.admin_badge.setStyleSheet(f"background-color: #2D0B0B; color: #EF4444; border: 1px solid #EF4444; cursor: pointer; {font_style}")
        self.admin_badge.mousePressEvent = lambda e: self.request_admin_elevation()

    def request_admin_elevation(self):
        extra = ["--file", self.current_vault_file] if getattr(self, "current_vault_file", None) else None
        elevated = self.engine.elevate_process(extra_args=extra)
        if elevated:
            QApplication.quit()

    def refresh_vault_list(self):
        self.combo_vaults.blockSignals(True)
        try:
            found_vaults = self.engine.scan_for_vaults()

            self.combo_vaults.clear()

            clean_curr_norm = os.path.normcase(os.path.normpath(str(Path(self.current_vault_file).resolve()))) if self.current_vault_file else ""
            found_paths_norm = {os.path.normcase(os.path.normpath(v["path"])) for v in found_vaults}

            if self.current_vault_file and clean_curr_norm not in found_paths_norm:
                p_obj = Path(self.current_vault_file).resolve()
                if p_obj.exists() and p_obj.is_file():
                    v_info = self.engine.get_vhd_virtual_size(str(p_obj)) if self.engine else {}
                    virt_mb = v_info.get("virtual_mb", round(p_obj.stat().st_size / (1024 * 1024), 2))
                    is_pv = self.is_custom_vault(str(p_obj))
                    dtype = "pvault" if is_pv else v_info.get("disk_type", "unknown")
                    found_vaults.insert(0, {
                        "name": p_obj.name,
                        "path": str(p_obj),
                        "size_mb": round(p_obj.stat().st_size / (1024 * 1024), 2),
                        "virtual_mb": round(virt_mb, 2),
                        "disk_type": dtype,
                        "needs_bridge": (not is_pv) and (p_obj.suffix.lower() not in [".vhd", ".vhdx"]),
                        "priority": True
                    })

            if not found_vaults:
                self.combo_vaults.addItem("Dosya bulunamadı - Yeni Kasa Oluştur veya Gözat ile seçin", "")
                self.current_vault_file = ""
                self.btn_mount.setEnabled(False)
                self.bridge_tag.hide()
                self.pref_letter_tag.hide()
                if hasattr(self, "capacity_badge"):
                    self.capacity_badge.hide()
                self.update_vault_path_display()
                self.update_unmounted_capacity_display("")
                return

            self.btn_mount.setEnabled(True)
            selected_index = 0
            v_dir_resolved = str(VAULTS_DIR.resolve()).lower()

            for i, vault in enumerate(found_vaults):
                att = self.engine.check_vault_attached(vault["path"])
                if getattr(self, "is_decoy_active", False):
                    if getattr(self, "active_decoy_path", None) and os.path.normcase(os.path.normpath(vault["path"])) == os.path.normcase(os.path.normpath(self.active_decoy_path)):
                        att = {"Attached": False}
                    elif getattr(self, "disguise_vault_file", None) and os.path.normcase(os.path.normpath(vault["path"])) == os.path.normcase(os.path.normpath(self.disguise_vault_file)):
                        att = {"Attached": True, "DriveLetter": self.drive_letter}
                status_tag = ""
                if att and att.get("Attached"):
                    dl = att.get("DriveLetter", "")
                    status_tag = f" [● BAĞLI: {dl}]" if dl else " [● BAĞLI]"

                v_path_obj = Path(vault["path"]).resolve()
                is_in_vaults = (str(v_path_obj.parent).lower() == v_dir_resolved or v_dir_resolved in str(v_path_obj).lower())

                virt_mb = vault.get("virtual_mb")
                if virt_mb is None or virt_mb <= 0:
                    v_info = self.engine.get_vhd_virtual_size(vault["path"]) if self.engine else {}
                    virt_mb = v_info.get("virtual_mb", vault.get("size_mb", 0))
                    vault["disk_type"] = v_info.get("disk_type", "unknown")

                dtype = vault.get("disk_type", "")
                is_pv = (dtype == "pvault" or self.is_custom_vault(vault["path"]))
                bridge_str = " (Köprü)" if (vault.get("needs_bridge", False) and not is_pv) else ""

                if virt_mb >= 1024:
                    cap_val = round(virt_mb / 1024.0, 1)
                    cap_str = f"{int(cap_val) if cap_val.is_integer() else cap_val} GB"
                else:
                    cap_str = f"{int(virt_mb)} MB"

                type_tag = ""
                if is_pv:
                    type_tag = " - Bağımsız Kasa"
                elif dtype == "fixed":
                    type_tag = " - Sabit"
                elif dtype == "dynamic":
                    type_tag = " - Dinamik"
                elif dtype == "vhdx":
                    type_tag = " - VHDX"

                if is_pv:
                    label = f"{vault['name']} [{cap_str} Kapasite - Bağımsız Kasa]{status_tag}"
                elif is_in_vaults:
                    label = f"{vault['name']} [{cap_str} Kapasite{type_tag}]{bridge_str}{status_tag}"
                else:
                    label = f"{vault['name']} [{cap_str} Kapasite{type_tag}]{bridge_str}{status_tag} — {v_path_obj.parent}"

                self.combo_vaults.addItem(label, vault["path"])
                item_idx = self.combo_vaults.count() - 1
                type_display_name = "Bağımsız Kasa (AES-256-GCM)" if is_pv else dtype.capitalize()
                self.combo_vaults.setItemData(
                    item_idx,
                    f"Dosya: {vault['name']}\nSanal Kapasite: {cap_str} ({int(virt_mb)} MB)\nFiziksel Alan: {vault.get('size_mb', 0)} MB\nTip: {type_display_name}\nDizin: {v_path_obj.parent}\nTam Yol: {vault['path']}",
                    Qt.ItemDataRole.ToolTipRole
                )
                
                if clean_curr_norm and os.path.normcase(os.path.normpath(vault["path"])) == clean_curr_norm:
                    selected_index = i

            self.combo_vaults.setCurrentIndex(selected_index)
            curr_data = self.combo_vaults.currentData()
            if curr_data:
                self.current_vault_file = str(curr_data).strip(' "\'')
            self.update_bridge_tag()
            self.update_capacity_badge()
            self.update_vault_path_display()
            if not self.is_mounted and self.current_vault_file:
                self.update_unmounted_capacity_display(self.current_vault_file)
        finally:
            self.combo_vaults.blockSignals(False)

    def on_vault_selection_changed(self, index):
        if index < 0:
            return
        path = self.combo_vaults.currentData()
        if path and Path(str(path).strip(' "\'')).exists():
            clean_path = str(path).strip(' "\'')
            self.current_vault_file = clean_path
            self.config["last_vault_path"] = clean_path
            save_config(self.config)
            self.btn_mount.setEnabled(True)

            if self.is_custom_vault(clean_path):
                self.btn_mount.setText("Kasa Gezginini Aç")
                self.update_bridge_tag()
                self.pref_letter_tag.hide()
                v_info = self.engine.get_vhd_virtual_size(clean_path) if self.engine else {}
                virt_mb = v_info.get("virtual_mb", 0)
                cap_str = f"{int(virt_mb / 1024)} GB" if virt_mb >= 1024 else f"{int(virt_mb)} MB"
                if hasattr(self, "capacity_badge"):
                    self.capacity_badge.setText(f"[AES-256-GCM] {cap_str} Kapasite" if virt_mb > 0 else "[AES-256-GCM] Bağımsız Kasa")
                    self.capacity_badge.setStyleSheet("color: #38BDF8; font-weight: 700;")
                    self.capacity_badge.show()
                self.update_vault_path_display()
                v_size = Path(clean_path).stat().st_size
                from enclave_custom_ui import format_size
                pv_cap_str = f" | Kapasite: {cap_str}" if virt_mb > 0 else ""
                self.capacity_text.setText(f"Bağımsız Şifreli Kasa: {Path(clean_path).name} | Fiziksel Boyut: {format_size(v_size)}{pv_cap_str}")
                self.capacity_bar.setValue(100)
                
                self.unlock_title.setText("Bağımsız Kasa Koruması (AES-256-GCM)")
                self.unlock_desc.setText(f"Bağımsız Kasa: {Path(clean_path).name}\nErişmek için kasa parolasını girin:")
                self.unlock_card.show()
                self.btn_bdeunlock.hide()
                self.btn_forgot_password.hide()
                self.txt_password.setPlaceholderText("Kasa parolasını (veya Tuzak parolayı) yazın ve Enter'a basın...")
                self.update_unlock_card_hello_state()
                return

            self.unlock_title.setText("Sanal Disk Güvenlik Koruması (BitLocker)")
            self.unlock_desc.setText("Sanal sürücü şifreli durumda. Erişmek için parolanızı girin:")
            self.btn_mount.setText("Kasayı Bağla (Mount)")
            self.btn_bdeunlock.show()
            self.btn_forgot_password.show()
            self.txt_password.setPlaceholderText("BitLocker parolasını buraya yazın ve Enter'a basın...")
            self.btn_unlock_pw.setText("Kilidi Aç")
            self.update_bridge_tag()
            self.update_capacity_badge()
            self.update_vault_path_display()
            self.check_if_already_attached(clean_path)
        else:
            self.bridge_tag.hide()
            self.pref_letter_tag.hide()
            if hasattr(self, "capacity_badge"):
                self.capacity_badge.hide()
            self.update_vault_path_display()

    def show_unmounted_actions(self):
        """Diskin bağlı olmadığı durumda 'Diski Bağla' butonunu tek başına tam genişlikte gösterir."""
        if hasattr(self, "actions_stack"):
            self.actions_stack.setCurrentIndex(0)
        self.btn_open_explorer.hide()
        if hasattr(self, "btn_manage_password"):
            self.btn_manage_password.hide()
        self.btn_dismount.hide()
        self.btn_mount.show()
        self.btn_mount.update()
        if hasattr(self, "actions_stack"):
            self.actions_stack.update()

    def show_mounted_actions(self, show_explorer: bool = False):
        """Disk bağlı olduğunda Gezgin, Parola Yönet ve Güvenle Ayır butonlarını gösterir."""
        if hasattr(self, "actions_stack"):
            self.actions_stack.setCurrentIndex(1)
        self.btn_mount.hide()
        self.btn_dismount.show()
        if hasattr(self, "btn_manage_password"):
            if show_explorer:
                self.btn_manage_password.show()
            else:
                self.btn_manage_password.hide()
        if show_explorer:
            self.btn_open_explorer.show()
        else:
            self.btn_open_explorer.hide()
        if hasattr(self, "actions_stack"):
            self.actions_stack.update()

    def check_if_already_attached(self, file_path: str):
        """Diskin zaten Windows'ta bağlı olup olmadığını kontrol eder ve çoklu kasa durumunu yönetir."""
        if getattr(self, "is_decoy_active", False) and getattr(self, "disguise_vault_file", None):
            if os.path.normcase(os.path.normpath(file_path)) == os.path.normcase(os.path.normpath(self.disguise_vault_file)):
                attached_info = {"Attached": True, "DriveLetter": self.drive_letter}
            else:
                attached_info = self.engine.check_vault_attached(file_path)
        else:
            attached_info = self.engine.check_vault_attached(file_path)
        if attached_info and attached_info.get("Attached"):
            self.is_mounted = True
            self.last_vault_activity_time = time.time()
            self.drive_letter = attached_info.get("DriveLetter", "")
            self.show_mounted_actions(show_explorer=False)
            self.drive_badge.setText(f"SÜRÜCÜ: {self.drive_letter}" if self.drive_letter else "SÜRÜCÜ: ?")
            self.drive_badge.setStyleSheet(self.get_badge_style("drive"))
            self.log(f"Bu kasa halihazırda sisteme bağlı: {self.drive_letter}", "info", "DURUM")
            self.status_timer.start()
            self.poll_volume_status()
        else:
            self.is_mounted = False
            self.drive_letter = ""
            self.is_locked = False
            self.status_timer.stop()
            self.show_unmounted_actions()
            self.unlock_card.hide()
            self.status_badge.setText("DİSK BAĞLI DEĞİL")
            self.status_badge.setStyleSheet(self.get_badge_style("not_mounted"))
            self.drive_badge.setText("SÜRÜCÜ: -")
            self.update_unmounted_capacity_display(file_path)
            self.update_vault_state_icon()

    def update_unmounted_capacity_display(self, file_path: str = ""):
        """Kasa bağlı değilken de sanal kapasitesini, disk tipini ve fiziksel boyutunu ana ekranda görüntüler."""
        target = file_path or self.current_vault_file or (self.combo_vaults.currentData() if hasattr(self, "combo_vaults") else "")
        is_light = (getattr(self, "current_theme", "dark") == "light")
        cap_col = "#586B54" if is_light else "#6C82A3"
        accent_col = "#0284C7" if is_light else "#38BDF8"

        if target:
            clean_p = str(target).strip(' "\'')
            p = Path(clean_p)
            if p.exists() and p.is_file():
                v_info = self.engine.get_vhd_virtual_size(str(p.resolve())) if self.engine else {}
                virt_mb = v_info.get("virtual_mb", round(p.stat().st_size / (1024 * 1024), 1))
                phys_mb = v_info.get("physical_mb", round(p.stat().st_size / (1024 * 1024), 1))
                dtype = v_info.get("disk_type", "")
                
                if virt_mb >= 1024:
                    cap_val = round(virt_mb / 1024.0, 1)
                    cap_str = f"{int(cap_val) if cap_val.is_integer() else cap_val} GB"
                else:
                    cap_str = f"{int(virt_mb)} MB"
                
                is_pv = (dtype == "pvault" or self.is_custom_vault(clean_p))
                if is_pv:
                    type_str = "Bağımsız Kasa (AES-256-GCM)"
                    text = f"Kasa Kapasitesi: {cap_str} ({int(virt_mb)} MB) | Diskteki Alan: {phys_mb} MB ({type_str}) | Kapalı"
                elif dtype == "dynamic":
                    type_str = "Dinamik VHD"
                    text = f"Sanal Kapasite: {cap_str} ({int(virt_mb)} MB) | Diskteki Alan: {phys_mb} MB ({type_str}) | Bağlı Değil"
                elif dtype == "fixed":
                    type_str = "Sabit VHD"
                    text = f"Sanal Kapasite: {cap_str} ({int(virt_mb)} MB) | {type_str} | Bağlı Değil"
                elif dtype == "vhdx":
                    type_str = "VHDX"
                    text = f"Sanal Kapasite: {cap_str} ({int(virt_mb)} MB) | {type_str} | Bağlı Değil"
                else:
                    type_str = "Sanal Disk"
                    text = f"Sanal Kapasite: {cap_str} ({int(virt_mb)} MB) | {type_str} | Bağlı Değil"
                
                self.capacity_text.setText(text)
                self.capacity_text.setStyleSheet(f"font-family: 'Segoe UI', 'Inter', 'Arial', sans-serif; color: {accent_col}; font-size: 11.5px; font-weight: 700;")
                self.capacity_bar.setValue(0)
                self.capacity_bar.setToolTip("Kasa bağlandığında ve kilidi açıldığında dosya sistemi doluluk oranı görüntülenecektir.")
                return

        self.capacity_text.setText("Sanal disk bağlı değil")
        self.capacity_text.setStyleSheet(f"font-family: 'Segoe UI', 'Inter', 'Arial', sans-serif; color: {cap_col}; font-size: 11.5px; font-weight: 600;")
        self.capacity_bar.setValue(0)

    def update_capacity_badge(self):
        """Seçili kasanın sanal kapasitesini üst başlıkta belirgin bir rozet olarak gösterir."""
        if not hasattr(self, "capacity_badge"):
            return
        if not self.current_vault_file:
            self.capacity_badge.hide()
            return

        p = Path(str(self.current_vault_file).strip(' "\''))
        if not p.exists() or not p.is_file():
            self.capacity_badge.hide()
            return

        v_info = self.engine.get_vhd_virtual_size(str(p.resolve())) if self.engine else {}
        virt_mb = v_info.get("virtual_mb", round(p.stat().st_size / (1024 * 1024), 1))
        dtype = v_info.get("disk_type", "")
        
        if virt_mb >= 1024:
            cap_val = round(virt_mb / 1024.0, 1)
            cap_str = f"{int(cap_val) if cap_val.is_integer() else cap_val} GB"
        else:
            cap_str = f"{int(virt_mb)} MB"

        type_tag = ""
        if dtype == "pvault" or self.is_custom_vault(str(p)):
            type_tag = " - Bağımsız Kasa"
        elif dtype == "fixed":
            type_tag = " - Sabit"
        elif dtype == "dynamic":
            type_tag = " - Dinamik"
        elif dtype == "vhdx":
            type_tag = " - VHDX"

        is_light = (getattr(self, "current_theme", "dark") == "light")
        if is_light:
            c_style = "font-family: 'Segoe UI', 'Inter', 'Arial', sans-serif; font-size: 11px; font-weight: 700; color: #065F46; background-color: #D1FAE5; border: 1px solid #10B981; padding: 4px 12px; border-radius: 12px;"
        else:
            c_style = "font-family: -apple-system, 'SF Pro Text', 'Segoe UI Variable', sans-serif; font-size: 11px; font-weight: 700; color: #38BDF8; background-color: #0B192E; border: 1px solid #0284C7; padding: 4px 12px; border-radius: 12px;"

        self.capacity_badge.setStyleSheet(c_style)
        self.capacity_badge.setText(f"[ KAPASİTE: {cap_str}{type_tag} ]")
        self.capacity_badge.show()

    def update_bridge_tag(self):
        self.update_capacity_badge()
        if not self.current_vault_file:
            self.bridge_tag.hide()
            self.pref_letter_tag.hide()
            if hasattr(self, "capacity_badge"):
                self.capacity_badge.hide()
            return

        is_light = (getattr(self, "current_theme", "dark") == "light")
        if is_light:
            b_style = "font-family: 'Segoe UI', 'Inter', 'Arial', sans-serif; font-size: 11px; font-weight: 700; color: #0C5478; background-color: #D5EAF7; border: 1px solid #0284C7; padding: 4px 12px; border-radius: 12px;"
            p_style = "font-family: 'Segoe UI', 'Inter', 'Arial', sans-serif; font-size: 11px; font-weight: 700; color: #531DAB; background-color: #E8E0FA; border: 1px solid #8B5CF6; padding: 4px 12px; border-radius: 12px;"
        else:
            b_style = "font-family: 'Segoe UI', 'Inter', 'Arial', sans-serif; font-size: 11px; font-weight: 700; color: #38BDF8; background-color: #071926; border: 1px solid #38BDF8; padding: 4px 12px; border-radius: 12px;"
            p_style = "font-family: 'Segoe UI', 'Inter', 'Arial', sans-serif; font-size: 11px; font-weight: 700; color: #C4B5FD; background-color: #18122B; border: 1px solid #A78BFA; padding: 4px 12px; border-radius: 12px;"

        self.bridge_tag.setStyleSheet(b_style)
        self.pref_letter_tag.setStyleSheet(p_style)

        if self.is_custom_vault(self.current_vault_file):
            self.bridge_tag.setText("[ BAĞIMSIZ KASA (AES-256) ]")
            self.bridge_tag.show()
        else:
            ext = Path(self.current_vault_file).suffix.lower()
            if ext not in [".vhd", ".vhdx"]:
                self.bridge_tag.setText(f"[ KÖPRÜ: {ext} -> .vhd ]")
                self.bridge_tag.show()
            else:
                self.bridge_tag.setText("[ DOĞRUDAN VHD ]")
                self.bridge_tag.show()

        pref_letters = self.config.get("preferred_drive_letters", {})
        pref = pref_letters.get(self.current_vault_file)
        if pref:
            self.pref_letter_tag.setText(f"[ HARF: {pref}: ]")
            self.pref_letter_tag.show()
        else:
            self.pref_letter_tag.hide()

    def update_vault_path_display(self):
        """Seçili kasanın bulunduğu klasör dizinini ve tam yolunu arayüzde günceller."""
        if not hasattr(self, "vault_path_info"):
            return
        
        target = self.current_vault_file or (self.combo_vaults.currentData() if hasattr(self, "combo_vaults") else "")
        is_light = (getattr(self, "current_theme", "dark") == "light")
        if target:
            target_str = str(target).strip(' "\'')
            p = Path(target_str)
            if p.exists() and p.is_file():
                parent_dir = str(p.parent)
                file_name = p.name
                dir_color = "#0369A1" if is_light else "#38BDF8"
                lbl_color = "#1E293B" if is_light else "#E2E8F0"
                v_info = self.engine.get_vhd_virtual_size(str(p.resolve())) if self.engine else {}
                virt_mb = v_info.get("virtual_mb", round(p.stat().st_size / (1024 * 1024), 1))
                if virt_mb >= 1024:
                    c_val = round(virt_mb / 1024.0, 1)
                    c_str = f"{int(c_val) if c_val.is_integer() else c_val} GB"
                else:
                    c_str = f"{int(virt_mb)} MB"
                cap_color = "#059669" if is_light else "#38BDF8"
                self.vault_path_info.setText(
                    f"<span style='color: {lbl_color}; font-weight: 700;'>Dizin:</span> "
                    f"<span style='color: {dir_color}; font-family: Segoe UI, Consolas, monospace; font-weight: 600;'>{parent_dir}</span>"
                    f" &nbsp;|&nbsp; <span style='color: {lbl_color}; font-weight: 700;'>Kapasite:</span> "
                    f"<span style='color: {cap_color}; font-weight: 800;'>{c_str}</span>"
                )
                self.vault_path_info.setToolTip(f"Dosya Adı: {file_name}\nKapasite: {c_str} ({int(virt_mb)} MB)\nTam Dizin: {parent_dir}\nTam Yol: {str(p.resolve())}\n\n(Tıklayarak veya 'Klasörü Aç' butonuyla konumu açabilirsiniz)")
                if hasattr(self, "btn_open_vault_dir"):
                    self.btn_open_vault_dir.setEnabled(True)
                if hasattr(self, "btn_copy_vault_dir"):
                    self.btn_copy_vault_dir.setEnabled(True)
                return

        dim_color = "#64748B"
        self.vault_path_info.setText(f"<span style='color: {dim_color}; font-style: italic;'>Kasa seçilmedi veya dosya mevcut değil</span>")
        self.vault_path_info.setToolTip("Henüz bir kasa dosyası seçilmedi.")
        if hasattr(self, "btn_open_vault_dir"):
            self.btn_open_vault_dir.setEnabled(False)
        if hasattr(self, "btn_copy_vault_dir"):
            self.btn_copy_vault_dir.setEnabled(False)

    def open_current_vault_dir(self):
        """Seçili kasanın bulunduğu klasörü Windows Gezgini'nde açar ve dosyayı vurgular."""
        target = self.current_vault_file or (self.combo_vaults.currentData() if hasattr(self, "combo_vaults") else "")
        if not target:
            return
        target_str = str(target).strip(' "\'')
        p = Path(target_str)
        if p.exists():
            try:
                subprocess.Popen(["explorer.exe", f'/select,{p.resolve()}'])
            except Exception as e:
                print(f"Klasör açma hatası: {e}")
        elif p.parent.exists():
            try:
                os.startfile(str(p.parent.resolve()))
            except Exception as e:
                print(f"Dizin açma hatası: {e}")

    def copy_current_vault_dir(self):
        """Seçili kasanın bulunduğu dizin yolunu panoya kopyalar."""
        target = self.current_vault_file or (self.combo_vaults.currentData() if hasattr(self, "combo_vaults") else "")
        if not target:
            return
        target_str = str(target).strip(' "\'')
        p = Path(target_str)
        parent_dir = str(p.parent.resolve()) if p.exists() else str(p.parent)
        clipboard = QApplication.clipboard()
        if clipboard:
            clipboard.setText(parent_dir)
            self.log(f"Kasa dizini panoya kopyalandı: {parent_dir}", "info", "PANO")
            if hasattr(self, "btn_copy_vault_dir"):
                old_text = self.btn_copy_vault_dir.text()
                self.btn_copy_vault_dir.setText("Kopyalandı!")
                QTimer.singleShot(1500, lambda: self.btn_copy_vault_dir.setText(old_text))

    def on_browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Sanal Disk veya Kasa Dosyası Seçin",
            str(Path.cwd()),
            "Tüm Kasa Dosyaları (*.vhd *.vhdx *.*);;VHD Dosyaları (*.vhd *.vhdx);;Tüm Dosyalar (*.*)"
        )
        if file_path:
            self.add_custom_vault(file_path)

    def add_custom_vault(self, file_path: str):
        clean_path = str(file_path).strip(' "\'')
        try:
            ctypes.windll.kernel32.SetFileAttributesW(str(Path(clean_path).resolve()), 0x80)
        except Exception:
            pass
        history = self.config.get("custom_vault_history", [])
        if clean_path not in history:
            history.insert(0, clean_path)
            self.config["custom_vault_history"] = history[:10]
        self.current_vault_file = clean_path
        self.config["last_vault_path"] = clean_path
        save_config(self.config)
        self.refresh_vault_list()

    def resolve_shortcut(self, lnk_path: str) -> str:
        """Windows .lnk kısayol dosyasının işaret ettiği gerçek hedef yolunu çözer."""
        try:
            import win32com.client
            shell = win32com.client.Dispatch("WScript.Shell")
            shortcut = shell.CreateShortCut(lnk_path)
            target = shortcut.Targetpath
            if target:
                return target
        except Exception:
            pass
        return lnk_path

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.setDropAction(Qt.DropAction.CopyAction)
            event.acceptProposedAction()
            event.accept()
        else:
            event.ignore()

    def dragMoveEvent(self, event):
        if event.mimeData().hasUrls():
            event.setDropAction(Qt.DropAction.CopyAction)
            event.acceptProposedAction()
            event.accept()
        else:
            event.ignore()

    def dropEvent(self, event):
        if not event.mimeData().hasUrls():
            event.ignore()
            return

        event.setDropAction(Qt.DropAction.CopyAction)
        event.acceptProposedAction()
        event.accept()
        urls = event.mimeData().urls()
        if not urls:
            return

        if getattr(self, "is_custom_vault_open", False) and getattr(self, "current_custom_explorer", None):
            self.current_custom_explorer.handle_dropped_urls(urls)
            return

        self.process_dropped_urls(urls)

    def process_dropped_urls(self, urls: List[QUrl]):
        import urllib.parse
        paths = []
        for u in urls:
            lf = u.toLocalFile()
            if not lf and u.toString().startswith("file:///"):
                raw_u = u.toString()[8:]
                raw_u = urllib.parse.unquote(raw_u)
                if len(raw_u) >= 2 and raw_u[1] == ':':
                    lf = raw_u.replace('/', '\\')
            if lf and os.path.exists(lf):
                if lf.lower().endswith(".lnk"):
                    try:
                        resolved = self.resolve_shortcut(lf)
                        if resolved and os.path.exists(resolved):
                            lf = resolved
                    except Exception:
                        pass
                paths.append(lf)

        if not paths:
            return

        if self.is_mounted and not self.is_locked and self.drive_letter:
            first = Path(paths[0])
            if len(paths) == 1 and first.suffix.lower() in [".vhd", ".vhdx", ".pvault"]:
                self.add_custom_vault(str(first))
                return

            clean_letter = self.drive_letter.rstrip(":\\/ ").upper()
            target_dir = f"{clean_letter}:\\"
            dlg = ShredConfirmDialog(self, files=paths, target_drive=clean_letter, theme=self.current_theme)
            if dlg.exec() == QDialog.DialogCode.Accepted and dlg.choice in ["shred", "copy"]:
                shred_orig = (dlg.choice == "shred")
                self.set_ui_busy(True, "Dosyalar kasaya aktarılıyor...")
                res = self.engine.copy_and_shred(paths, target_dir, shred_original=shred_orig)
                self.set_ui_busy(False)
                if res.get("success"):
                    if shred_orig:
                        self.log(f"{res['copied_count']} adet dosya kasaya taşındı ve orijinal sektörler parçalandı.", "success", "GUVENLIK")
                        audit_logger.log_security_event("SHRED_FILES", "SUCCESS", f"{res['copied_count']} dosya parçalandı.", self.current_vault_file, self.drive_letter)
                        QMessageBox.information(self, "Başarılı", f"{res['copied_count']} adet dosya/klasör kasaya taşındı ve orijinal konumundan güvenle parçalandı.")
                    else:
                        self.log(f"{res['copied_count']} adet dosya kasaya kopyalandı.", "success", "DOSYA")
                        QMessageBox.information(self, "Başarılı", f"{res['copied_count']} adet dosya kasaya kopyalandı.")
                else:
                    QMessageBox.warning(self, "Hata", f"İşlem tamamlanamadı: {res.get('error')}")
            return

        if getattr(self, "is_custom_vault_open", False) and getattr(self, "current_custom_explorer", None):
            self.current_custom_explorer.handle_dropped_paths(paths)
            return

        vault_files = [p for p in paths if Path(p).suffix.lower() in [".vhd", ".vhdx", ".pvault"]]
        if vault_files:
            self.log(f"Kasa dosyası seçildi: {Path(vault_files[0]).name}", "info", "KASA")
            self.add_custom_vault(vault_files[0])
            return

        QMessageBox.information(
            self,
            "Kasa Açık Değil",
            "Masaüstünden sürüklediğiniz dosyaları kasaya aktarabilmek için lütfen önce kasanızı açın / bağlayın.\n\n"
            "• Sanal Disk Kasa için: 'Diski Bağla' butonuna basın.\n"
            "• Bağımsız Kasa (.pvault) için: Parolanızı girip 'Kasa Gezginini Aç' butonuna basın.\n\n"
            "Kasa açıldıktan sonra dosyalarınızı doğrudan buraya veya Kasa Gezginine sürükleyip bırakabilirsiniz."
        )

    def on_mount_clicked(self):
        if getattr(self, "is_mounting", False) or getattr(self, "is_dismounting", False):
            if self.worker and self.worker.isRunning():
                self.log("Şu anda devam eden bir disk işlemi var, lütfen bekleyin...", "warn")
                return
            self.is_mounting = False
            self.is_dismounting = False

        combo_path = self.combo_vaults.currentData()
        if combo_path and os.path.exists(str(combo_path).strip(' "\'')):
            self.current_vault_file = str(combo_path).strip(' "\'')
        elif self.current_vault_file:
            self.current_vault_file = str(self.current_vault_file).strip(' "\'')

        if not self.current_vault_file or not Path(self.current_vault_file).exists():
            self.log("Geçersiz kasa yolu. Lütfen geçerli bir kasa dosyası seçin.", "warn")
            QMessageBox.warning(self, "Kasa Seçilmedi", "Lütfen bağlamak için geçerli bir kasa dosyası seçin veya 'Gözat' ile ekleyin.")
            return

        if self.is_custom_vault(self.current_vault_file):
            pw = self.txt_password.text().strip()
            if pw:
                self.on_unlock_with_password()
            else:
                self.unlock_title.setText("Bağımsız Kasa Koruması (AES-256-GCM)")
                self.unlock_desc.setText(f"Bağımsız Kasa: {Path(self.current_vault_file).name}\nErişmek için kasa parolasını girin:")
                self.unlock_card.show()
                self.btn_bdeunlock.hide()
                self.btn_forgot_password.hide()
                self.txt_password.setPlaceholderText("Kasa parolasını (veya Tuzak parolayı) yazın ve Enter'a basın...")
                self.update_unlock_card_hello_state()
                self.txt_password.setFocus()
            return

        if not self.engine.is_admin():
            self.log("Sanal disk bağlamak için Windows yönetici yetkisi gereklidir.", "warn", "GUVENLIK")
            reply = QMessageBox.question(
                self,
                "Yönetici Yetkisi Gerekli",
                "Sanal diskleri bağlamak ve BitLocker sürücüsünü yönetmek için Windows yönetici yetkisi gereklidir.\n\n"
                "Uygulama yönetici (Administrator) olarak yeniden başlatılsın mı?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.Yes
            )
            if reply == QMessageBox.StandardButton.Yes:
                extra = ["--file", self.current_vault_file] if getattr(self, "current_vault_file", None) else None
                elevated = self.engine.elevate_process(extra_args=extra)
                if elevated:
                    QApplication.quit()
                else:
                    self.log("Yönetici yetkisi yükseltilemedi. Lütfen uygulamayı sağ tıklayıp 'Yönetici olarak çalıştır' ile başlatın.", "error", "GUVENLIK")
                    QMessageBox.critical(self, "Yetki Hatası", "Yönetici yetkisi yükseltilemedi.\nLütfen uygulamayı sağ tıklayıp 'Yönetici olarak çalıştır' ile başlatın.")
            return

        if self.config.get("cloud_sync_warning_enabled", True):
            conflict = self.engine.check_cloud_sync_conflict(self.current_vault_file)
            if conflict.get("conflict"):
                dlg = CloudSyncWarningDialog(
                    self,
                    provider=conflict.get("provider", "Bulut"),
                    path=self.current_vault_file,
                    theme=self.current_theme
                )
                if dlg.exec() != QDialog.DialogCode.Accepted:
                    return
                if dlg.dont_show_again:
                    self.config["cloud_sync_warning_enabled"] = False
                    save_config(self.config)

        try:
            self.is_mounting = True
            pref_letter = self.config.get("preferred_drive_letters", {}).get(self.current_vault_file)
            self.hook_ran_for_mount = False

            self.engine.suppress_bdeunlock()
            self.set_ui_busy(True, "Sanal disk bağlanıyor...")
            self.log(f"Bağlama isteği başlatıldı: {Path(self.current_vault_file).name}", "info", "BAGLANTI")
            self.worker = VaultWorker(
                "mount",
                self.engine,
                {
                    "file_path": self.current_vault_file,
                    "preferred_letter": pref_letter,
                    "autoplay_protection": self.chk_autoplay.isChecked()
                }
            )
            self.worker.log_signal.connect(self.log)
            self.worker.finished_signal.connect(self.on_mount_finished)
            self.worker.start()
        except Exception as e:
            self.is_mounting = False
            self.set_ui_busy(False)
            self.log(f"Bağlama başlatılırken beklenmedik hata: {e}", "error", "HATA")
            QMessageBox.critical(self, "Hata", f"Bağlama işlemi başlatılamadı:\n{e}")

    def on_mount_finished(self, result: dict):
        self.is_mounting = False
        self.set_ui_busy(False)
        if result.get("success"):
            self.drive_letter = result.get("drive_letter", "")
            self.is_mounted = True
            if result.get("disk_number") is not None and result.get("disk_number") >= 0:
                self.active_disk_number = result.get("disk_number")
                self.engine.active_disk_number = result.get("disk_number")
            
            if self.engine.check_embedded_decoy_vault(self.current_vault_file):
                swap_res = self.engine.swap_embedded_partitions(self.current_vault_file, target_part=2, letter=self.drive_letter)
                if swap_res.get("success") and swap_res.get("drive_letter"):
                    self.drive_letter = swap_res.get("drive_letter")
            
            QTimer.singleShot(300, self.clean_lingering_partition_letters)
            QTimer.singleShot(1000, self.clean_lingering_partition_letters)

            audit_logger.log_security_event("VAULT_MOUNT", "SUCCESS", f"Disk bağlandı ({self.drive_letter})", self.current_vault_file, self.drive_letter)
            self.reset_inactivity_timer()
            self.show_mounted_actions(show_explorer=False)
            self.drive_badge.setText(f"SÜRÜCÜ: {self.drive_letter}" if self.drive_letter else "SÜRÜCÜ: ?")
            self.drive_badge.setStyleSheet(self.get_badge_style("drive"))

            self.engine.suppress_bdeunlock()
            self.raise_()
            self.activateWindow()

            self.status_timer.start()
            self.poll_volume_status()
            self.refresh_vault_list()
            self.update_bridge_tag()

        else:
            err = result.get('error', '')
            audit_logger.log_security_event("VAULT_MOUNT_FAIL", "WARNING", f"Bağlama hatası: {err}", self.current_vault_file)
            if "0x80070570" in err or "corrupted and unreadable" in err.lower():
                user_msg = (
                    "Sanal disk dosyası okunamadı veya başlık doğrulaması başarısız oldu (0x80070570).\n\n"
                    "Olası Nedenler:\n"
                    "• Kasa dosyasının başka bir program tarafından kilitlenmediğinden emin olun.\n"
                    "• Kasa dosyasının bütünlüğünü menüdeki 'Bütünlük Kontrolü' ile test edebilirsiniz."
                )
            else:
                user_msg = f"Disk bağlanamadı:\n{err}"
            QMessageBox.critical(self, "Bağlama Hatası", user_msg)

    def on_dismount_clicked(self, force: bool = False):
        if getattr(self, "is_dismounting", False):
            if self.worker and self.worker.isRunning():
                return
            self.is_dismounting = False
        try:
            self.is_dismounting = True
            self.is_mounted = False
            self.status_timer.stop()
            if hasattr(self, "lbl_inactivity_countdown"):
                self.lbl_inactivity_countdown.hide()
            self.terminate_hook_processes()
            self.set_ui_busy(True, "Sanal disk ayrılıyor...")
            target = (self.active_decoy_path if getattr(self, "is_decoy_active", False) and getattr(self, "active_decoy_path", None)
                      else (self.current_vault_file or self.engine.active_vault_file or self.engine.active_mount_target))
            self._cleanup_decoy_volume_label()
            self.worker = VaultWorker(
                "dismount",
                self.engine,
                {
                    "file_path": target,
                    "drive_letter": self.drive_letter,
                    "force": force,
                    "autoplay_protection": self.chk_autoplay.isChecked(),
                    "clean_traces": self.config.get("cache_clean_on_dismount", True)
                }
            )
            self.worker.log_signal.connect(self.log)
            self.worker.finished_signal.connect(self.on_dismount_finished)
            self.worker.start()
        except Exception as e:
            self.is_dismounting = False
            self.set_ui_busy(False)
            self.log(f"Ayırma başlatılırken hata oluştu: {e}", "error", "HATA")
            QMessageBox.critical(self, "Hata", f"Ayırma işlemi başlatılamadı:\n{e}")

    def on_dismount_finished(self, result: dict):
        old_letter = self.drive_letter
        audit_logger.log_security_event("VAULT_DISMOUNT", "INFO", "Sanal disk güvenle ayrıldı.", self.current_vault_file, old_letter)

        cleaned_cnt = result.get("cleaned_traces", 0)
        if cleaned_cnt > 0:
            self.log(f"Sistem izleri temizlendi ({cleaned_cnt} adet Recent/LNK kaydı silindi).", "info", "GUVENLIK")
            audit_logger.log_security_event("TRACE_WIPE", "SUCCESS", f"{cleaned_cnt} adet Recent izi silindi.", drive_letter=old_letter)

        if self.config.get("auto_backup_enabled", False) and self.current_vault_file and not getattr(self, "is_decoy_active", False):
            vault_to_bk = self.current_vault_file
            b_dir = self.config.get("auto_backup_dir", "")
            k_cnt = self.config.get("backup_keep_count", 3)

            def _async_backup():
                try:
                    b_res = self.engine.auto_backup_vault(vault_to_bk, custom_backup_dir=b_dir, max_backups=k_cnt)
                    if b_res.get("success"):
                        self.log(f"Otomatik kasa yedeği alındı: {b_res['backup_name']} ({b_res['size_mb']} MB)", "success", "YEDEK")
                        audit_logger.log_security_event("AUTO_BACKUP", "SUCCESS", f"Yedek: {b_res['backup_name']}", vault_path=vault_to_bk)
                except Exception as ex:
                    self.log(f"Otomatik yedekleme hatası: {ex}", "error", "HATA")

            t = threading.Thread(target=_async_backup, daemon=True)
            t.start()

        self.reset_to_unmounted_state(show_tray_message=True, custom_tray_msg="Sanal disk güvenle ayrıldı.")
        self.refresh_vault_list()

    def check_external_dismount(self):
        """Dosya Gezgini veya harici bir araçla sürücü çıkarıldığında anında algılar."""
        if not self.is_mounted or getattr(self, "is_dismounting", False) or getattr(self, "is_changing_letter", False) or getattr(self, "is_switching_decoy", False):
            return

        clean_l = self.drive_letter.rstrip(":\\/ ").upper() if self.drive_letter else ""
        if clean_l and len(clean_l) == 1:
            bitmask = ctypes.windll.kernel32.GetLogicalDrives()
            if not (bitmask & (1 << (ord(clean_l) - ord('A')))):
                self.on_external_dismount_detected()
                return

        vhd_check_target = (self.active_decoy_path if getattr(self, "is_decoy_active", False) and getattr(self, "active_decoy_path", None)
                            else self.current_vault_file)
        if vhd_check_target and not self.engine.is_vhd_attached(vhd_check_target):
            self.on_external_dismount_detected()

    def on_external_dismount_detected(self):
        """Dosya Gezgini'nden veya dışarıdan sürücü ayrıldığında UI durumunu otomatik senkronize eder."""
        if getattr(self, "is_dismounting", False) or getattr(self, "is_changing_letter", False):
            return

        old_letter = self.drive_letter or "?"
        self.log(f"Sanal disk Dosya Gezgini üzerinden ayrıldı ({old_letter}).", "info", "AYIRMA")
        audit_logger.log_security_event("EXTERNAL_DISMOUNT", "INFO", f"Dosya Gezgini'nden çıkarıldı ({old_letter})", self.current_vault_file, old_letter)

        self.terminate_hook_processes()

        if self.config.get("cache_clean_on_dismount", True) and old_letter and old_letter != "?":
            t_res = self.engine.wipe_system_traces(old_letter)
            if t_res.get("cleaned_count", 0) > 0:
                self.log(f"Sistem izleri temizlendi ({t_res['cleaned_count']} adet Recent/LNK kaydı silindi).", "info", "GUVENLIK")

        self.reset_to_unmounted_state(show_tray_message=True, custom_tray_msg=f"Sürücü ({old_letter}) Dosya Gezgini'nden ayrıldı.")

    def reset_to_unmounted_state(self, show_tray_message: bool = True, custom_tray_msg: str = "Sanal disk güvenle ayrıldı."):
        """Diskin takılı olmadığı varsayılan arayüz durumuna anında ve temiz şekilde döndürür."""
        if getattr(self, "is_switching_decoy", False):
            return
        self._cleanup_decoy_volume_label()
        self.is_dismounting = False
        self.set_ui_busy(False)
        self.is_mounted = False
        self.is_locked = False
        self.hook_ran_for_mount = False
        self.drive_letter = ""
        self.last_unlocked_password = ""
        self._last_entered_password = ""
        self.status_timer.stop()
        
        self.is_decoy_active = False
        self.active_decoy_path = None
        self.disguise_vault_file = None
        self.disguise_vault_name = ""
        self.decoy_original_label = ""
        self.decoy_volume_renamed = False

        self.unlock_card.hide()
        self.lbl_unlock_error.hide()
        if hasattr(self, "lbl_inactivity_countdown"):
            self.lbl_inactivity_countdown.hide()
        self.show_unmounted_actions()
        
        is_light = (getattr(self, "current_theme", "dark") == "light")
        cap_col = "#586B54" if is_light else "#6C82A3"
        self.status_badge.setText("DİSK BAĞLI DEĞİL")
        self.status_badge.setStyleSheet(self.get_badge_style("not_mounted"))
        self.drive_badge.setText("SÜRÜCÜ: -")
        self.drive_badge.setStyleSheet(self.get_badge_style("drive"))
        self.update_unmounted_capacity_display(self.current_vault_file)
        self.update_capacity_badge()
        self.update_vault_path_display()
        self.update_vault_state_icon()

        if hasattr(self, "tray_icon"):
            self.action_tray_status.setText("Durum: Bağlı Değil")
            self.action_tray_open.setEnabled(False)
            self.action_tray_dismount.setEnabled(False)
            if show_tray_message:
                self.tray_icon.showMessage(
                    "Enclave",
                    custom_tray_msg,
                    QSystemTrayIcon.MessageIcon.Information,
                    2000
                )

    def clean_lingering_partition_letters(self):
        """Çift bölümlü gömülü kasalarda gizli olması gereken bölümün Windows tarafından harf almasını engeller."""
        try:
            if not getattr(self, "is_mounted", False):
                return
            disk_num = getattr(self.engine, "active_disk_number", None) or getattr(self, "active_disk_number", None)
            if disk_num is None or disk_num < 0:
                if self.drive_letter:
                    from engine import get_disk_number_for_drive_letter
                    disk_num = get_disk_number_for_drive_letter(self.drive_letter)
            if disk_num is not None and disk_num >= 0:
                from engine import get_disk_volumes, remove_drive_letter_mount_point
                parts = get_disk_volumes(disk_num)
                if len(parts) >= 2:
                    hidden_part = 2 if getattr(self, "is_decoy_active", False) else 1
                    hidden_info = parts.get(hidden_part, {})
                    if hidden_info.get("letter"):
                        remove_drive_letter_mount_point(hidden_info["letter"])
        except Exception:
            pass

    def poll_volume_status(self):
        if getattr(self, "suppress_poll", False) or getattr(self, "is_switching_decoy", False):
            return
        try:
            self.clean_lingering_partition_letters()
            clean_l = self.drive_letter.rstrip(":\\/ ").upper() if self.drive_letter else ""
            if clean_l and len(clean_l) == 1:
                bitmask = ctypes.windll.kernel32.GetLogicalDrives()
                if not (bitmask & (1 << (ord(clean_l) - ord('A')))):
                    self.on_external_dismount_detected()
                    return

            if not self.drive_letter:
                self.drive_letter = self.engine.ensure_drive_letter_assigned(target=self.current_vault_file)
                if self.drive_letter:
                    self.drive_badge.setText(f"SÜRÜCÜ: {self.drive_letter}")
                    self.drive_badge.setStyleSheet(self.get_badge_style("drive"))

            if self.drive_letter and hasattr(self, "drive_badge"):
                expected_badge = f"SÜRÜCÜ: {self.drive_letter}"
                if self.drive_badge.text() != expected_badge:
                    self.drive_badge.setText(expected_badge)
                    self.drive_badge.setStyleSheet(self.get_badge_style("drive"))

            if not self.drive_letter:
                self.status_badge.setText("HARF BEKLENİYOR")
                self.status_badge.setStyleSheet(self.get_badge_style("locked"))
                self.capacity_text.setText("Disk sisteme bağlandı, sürücü harfi tahsis ediliyor...")
                self.show_mounted_actions(show_explorer=False)
                self.unlock_card.hide()
                return

            status = self.engine.get_drive_status(self.drive_letter)
            if not status.get("is_valid"):
                self.on_external_dismount_detected()
                return

            was_locked = self.is_locked
            self.is_locked = status.get("is_locked", False)

            is_light = (getattr(self, "current_theme", "dark") == "light")
            cap_col = "#0F172A" if is_light else "#38BDF8"

            if self.is_locked:
                self.status_badge.setText("BİTLOCKER KİLİTLİ")
                self.status_badge.setStyleSheet(self.get_badge_style("locked"))
                self.capacity_text.setText("Sürücü BitLocker ile şifrelenmiş. Erişmek için kilidi açın.")
                self.capacity_text.setStyleSheet(f"font-family: 'Segoe UI', 'Inter', 'Arial', sans-serif; color: {'#A66500' if is_light else '#FFCC00'}; font-size: 11.5px; font-weight: 600;")
                self.capacity_bar.setValue(0)
                self.update_vault_state_icon()
                
                if not was_locked and (time.time() - getattr(self, "bdeunlock_manually_opened", 0) > 15):
                    self.engine.suppress_bdeunlock()

                self.unlock_title.setText("Sanal Disk Güvenlik Koruması (BitLocker)")
                self.unlock_desc.setText(f"Sürücü ({self.drive_letter}) şifreli durumda. Erişmek için parolanızı girin:")
                if not self.unlock_card.isVisible():
                    self.unlock_card.show()
                    self.update_unlock_card_hello_state()
                    self.txt_password.setFocus()
                    self.txt_password.selectAll()
                    self.raise_()
                    self.activateWindow()

                self.show_mounted_actions(show_explorer=False)

                if hasattr(self, "tray_icon"):
                    self.action_tray_status.setText(f"Durum: {self.drive_letter} (Kilitli)")
                    self.action_tray_open.setEnabled(False)
                    self.action_tray_dismount.setEnabled(True)

            else:
                self.status_badge.setText("KULLANIMA HAZIR")
                self.status_badge.setStyleSheet(self.get_badge_style("ready"))
                self.unlock_card.hide()
                self.lbl_unlock_error.hide()
                self.show_mounted_actions(show_explorer=True)
                self.update_vault_state_icon()

                tot_gb = status.get("total_bytes", 0) / (1024**3)
                free_gb = status.get("free_bytes", 0) / (1024**3)
                used_gb = tot_gb - free_gb
                pct_used = int((used_gb / tot_gb * 100)) if tot_gb > 0 else 0
                
                if getattr(self, "is_decoy_active", False) and getattr(self, "disguise_vault_name", ""):
                    lbl_name = self.disguise_vault_name
                    if not getattr(self, "decoy_volume_renamed", False) and status.get("is_accessible", False) and self.drive_letter:
                        self._apply_decoy_volume_label(self.drive_letter)
                else:
                    lbl_name = status.get("label", "Kasa")
                self.vault_label = lbl_name
                self.capacity_text.setText(f"Birim: {lbl_name} | {used_gb:.1f} GB / {tot_gb:.1f} GB Dolu ({free_gb:.1f} GB Boş)")
                self.capacity_text.setStyleSheet(f"font-family: 'Segoe UI', 'Inter', 'Arial', sans-serif; color: {cap_col}; font-size: 11.5px; font-weight: 600;")
                self.capacity_bar.setValue(pct_used)

                if hasattr(self, "tray_icon"):
                    self.action_tray_status.setText(f"Durum: {self.drive_letter} (Açık)")
                    self.action_tray_open.setEnabled(True)
                    self.action_tray_dismount.setEnabled(True)

                if was_locked or not getattr(self, "hook_ran_for_mount", False):
                    self.hook_ran_for_mount = True
                    if was_locked:
                        self.log(f"BitLocker açıldı. Sürücü kullanıma hazır: {self.drive_letter}", "success", "GUVENLIK")
                    else:
                        self.log(f"Sanal disk kullanıma hazır: {self.drive_letter}", "success", "BAGLANTI")
                    self.run_hook_for_vault()
                    if self.chk_auto_explorer.isChecked():
                        self.on_open_explorer_clicked()
                    if self.chk_tray.isChecked():
                        self.hide()
                        if hasattr(self, "tray_icon"):
                            self.tray_icon.showMessage(
                                "Enclave",
                                f"Kasa açıldı ve kullanıma hazır ({self.drive_letter})",
                                QSystemTrayIcon.MessageIcon.Information,
                                2500
                            )
        except Exception as e:
            self.log(f"Durum kontrol hatası: {e}", "warn", "DURUM")

    def on_trigger_bdeunlock(self):
        self.log("Windows BitLocker şifre istemcisi (bdeunlock) başlatılıyor...", "info", "GUVENLIK")
        self.bdeunlock_manually_opened = time.time()
        self.engine.trigger_bdeunlock(self.drive_letter)

    def is_custom_vault(self, file_path: Optional[str] = None) -> bool:
        """Belirtilen dosyanın bağımsız AES-256 (.pvault) formatında olup olmadığını tespit eder."""
        target = file_path or self.current_vault_file
        if not target:
            return False
        clean_target = str(target).strip(' "\'')
        p = Path(clean_target)
        if not p.exists() or not p.is_file():
            return False
        if p.suffix.lower() == ".pvault":
            return True
        if p.stat().st_size >= 8:
            try:
                with open(p, "rb") as f:
                    return f.read(8) == b"PVAULT01"
            except Exception:
                pass
        return False

    def unlock_custom_vault(self, pw: str, auth_info: dict = None):
        """Bağımsız AES-256 kasasını doğrular ve dahili Kasa Gezginini açar."""
        if not self.current_vault_file or not Path(self.current_vault_file).exists():
            return
        try:
            from enclave_core import CustomVaultEngine, _derive_key, InvalidPasswordError
            from enclave_custom_ui import CustomVaultExplorerDialog

            if auth_info is None:
                auth_info = CustomVaultEngine.authenticate(self.current_vault_file, pw)

            self.is_custom_vault_open = True
            is_decoy = auth_info.get("is_decoy", False)
            mode_str = "TUZAK KASA KAMUFLAJI" if is_decoy else "ANA KASA"
            self.log(f"Bağımsız AES-256 kasa kilidi başarıyla açıldı ({mode_str}).", "success", "GUVENLIK")
            audit_logger.log_security_event("UNLOCK_SUCCESS", "SUCCESS", f"Bağımsız kasa açıldı ({mode_str}).", self.current_vault_file)
            if getattr(self, "chk_vault_2fa", None) and self.current_vault_file:
                if self.chk_vault_2fa.isChecked():
                    windows_hello.set_vault_2fa_enabled(self.current_vault_file, True)
            self.txt_password.clear()
            self.lbl_unlock_error.hide()

            dlg = CustomVaultExplorerDialog(self, vault_path=self.current_vault_file, auth_info=auth_info, theme=self.current_theme)
            self.current_custom_explorer = dlg
            dlg.vault_locked_signal.connect(self.on_custom_vault_locked)
            dlg.exec()
        except InvalidPasswordError:
            self.lbl_unlock_error.setText("Hatalı parola! Şifre çözülemedi.")
            self.lbl_unlock_error.show()
            self.log("Bağımsız kasa için girilen parola geçersiz.", "warn", "GUVENLIK")
            audit_logger.log_security_event("UNLOCK_FAILED", "WARNING", "Bağımsız kasa için hatalı parola girildi.", self.current_vault_file)
        except Exception as e:
            err_str = str(e)
            if "başlık" in err_str.lower() or "magic" in err_str.lower() or "bozulmuş" in err_str.lower():
                self.lbl_unlock_error.setText(f"Kasa başlığı hasarlı: {err_str}\n(Ayrılmış Başlık Yedeği & Kurtar butonunu kullanarak onarabilirsiniz.)")
            else:
                self.lbl_unlock_error.setText(f"Kilit açma hatası: {err_str}")
            self.lbl_unlock_error.show()
            self.log(f"Bağımsız kasa açılamadı: {err_str}", "error", "HATA")

    def on_custom_vault_locked(self):
        """Bağımsız kasa gezgini kapatıldığında veya kilitlendiğinde UI durumunu sıfırlar."""
        self.is_custom_vault_open = False
        self.current_custom_explorer = None
        self.log("Bağımsız AES-256 kasa kilitlendi ve geçici izler güvenle imha edildi.", "info", "KASA")
        self.reset_to_unmounted_state(show_tray_message=False)

    def on_open_header_backup_restore(self):
        """Ayrılmış Başlık Yedeği & Kurtarma sihirbazını açar."""
        target_vault = self.current_vault_file or self.engine.active_vault_file or ""
        dlg = HeaderBackupRestoreDialog(
            parent=self,
            vault_path=target_vault,
            theme=self.current_theme,
            engine=self.engine
        )
        dlg.exec()

    def on_vault_2fa_clicked(self):
        """Kullanıcı 2FA onay kutusuna tıkladığında yetkisiz kapatmayı önler ve 2FA doğrulama penceresini açar."""
        target = self.current_vault_file or ""
        if not target:
            return

        is_custom = self.is_custom_vault(target)
        if is_custom:
            from enclave_core import CustomVaultEngine
            is_currently_2fa = CustomVaultEngine.is_vault_2fa_enforced(target)
        else:
            is_currently_2fa = windows_hello.is_vault_2fa_enabled(target)

        if is_currently_2fa and not self.chk_vault_2fa.isChecked():
            self.chk_vault_2fa.blockSignals(True)
            self.chk_vault_2fa.setChecked(True)
            self.chk_vault_2fa.blockSignals(False)

            from extra_dialogs import Disable2FADialog
            current_typed_pw = self.txt_password.text().strip()
            dlg = Disable2FADialog(
                parent=self,
                vault_path=target,
                theme=self.current_theme,
                engine=self.engine,
                drive_letter=getattr(self, "drive_letter", ""),
                initial_password=current_typed_pw
            )
            if dlg.exec() == QDialog.DialogCode.Accepted:
                self.config = load_config()
                self.chk_vault_2fa.blockSignals(True)
                self.chk_vault_2fa.setChecked(False)
                self.chk_vault_2fa.blockSignals(False)
                self.lbl_2fa_badge.hide()
                self.btn_unlock_pw.setText("Kasa Gezginini Aç" if is_custom else "Kilidi Aç")
                self.update_unlock_card_hello_state()
                self.log(f"'{Path(target).name}' kasası için 2FA koruması başarıyla kaldırıldı.", "warn", "2FA")
            else:
                self.log(f"'{Path(target).name}' için 2FA kapatma işlemi iptal edildi; 2FA koruması aktif tutuldu.", "info", "2FA")

        elif not is_currently_2fa and self.chk_vault_2fa.isChecked():
            if is_custom:
                from extra_dialogs import TOTPSetupDialog
                current_typed_pw = self.txt_password.text().strip()
                dlg = TOTPSetupDialog(
                    parent=self,
                    vault_path=target,
                    theme=self.current_theme,
                    initial_password=current_typed_pw
                )
                if dlg.exec() == QDialog.DialogCode.Accepted:
                    self.lbl_2fa_badge.setText("[2FA KORUMALI]")
                    self.lbl_2fa_badge.show()
                    self.btn_unlock_pw.setText("2FA ile Kasa Gezginini Aç")
                    self.chk_vault_2fa.blockSignals(True)
                    self.chk_vault_2fa.setChecked(True)
                    self.chk_vault_2fa.blockSignals(False)
                    self.log(f"'{Path(target).name}' için TOTP İki Faktörlü Doğrulama başarıyla kasaya mühürlendi.", "success", "2FA")
                else:
                    self.chk_vault_2fa.blockSignals(True)
                    self.chk_vault_2fa.setChecked(False)
                    self.chk_vault_2fa.blockSignals(False)
                    self.lbl_2fa_badge.hide()
                    self.btn_unlock_pw.setText("Kasa Gezginini Aç")
            else:
                self.lbl_2fa_badge.setText("[2FA KORUMALI]")
                self.lbl_2fa_badge.show()
                self.btn_unlock_pw.setText("2FA ile Kilidi Aç")
                self.log(f"'{Path(target).name}' için 2FA seçildi.", "info", "2FA")

        elif not is_currently_2fa and not self.chk_vault_2fa.isChecked():
            self.lbl_2fa_badge.hide()
            self.btn_unlock_pw.setText("Kasa Gezginini Aç" if is_custom else "Kilidi Aç")

    def update_unlock_card_hello_state(self):
        """Kasa seçildiğinde 2FA durumu ve onay kutusu durumunu günceller."""
        self.config = load_config()
        target = self.current_vault_file or ""
        is_avail, _ = windows_hello.is_windows_hello_available()
        is_custom = self.is_custom_vault(target) if target else False
        is_2fa = False
        if target:
            if is_custom:
                from enclave_core import CustomVaultEngine
                is_2fa = CustomVaultEngine.is_vault_2fa_enforced(target)
            else:
                is_2fa = windows_hello.is_vault_2fa_enabled(target)

        can_support_2fa = is_custom or (is_avail and self.config.get("windows_hello_enabled", True))

        if can_support_2fa:
            self.chk_vault_2fa.show()
            self.chk_vault_2fa.blockSignals(True)
            self.chk_vault_2fa.setChecked(is_2fa)
            self.chk_vault_2fa.blockSignals(False)
            if is_2fa:
                self.lbl_2fa_badge.setText("[2FA KORUMALI]")
                self.lbl_2fa_badge.show()
                self.btn_unlock_pw.setText("2FA ile Kasa Gezginini Aç" if is_custom else "2FA ile Kilidi Aç")
            else:
                self.lbl_2fa_badge.hide()
                self.btn_unlock_pw.setText("Kasa Gezginini Aç" if is_custom else "Kilidi Aç")
        else:
            if is_2fa:
                self.lbl_2fa_badge.setText("[2FA KORUMALI]")
                self.lbl_2fa_badge.show()
                self.btn_unlock_pw.setText("2FA ile Kilidi Aç")
            else:
                self.chk_vault_2fa.hide()
                self.lbl_2fa_badge.hide()
                self.btn_unlock_pw.setText("Kasa Gezginini Aç" if is_custom else "Kilidi Aç")

    def on_unlock_with_password(self):
        pw = self.txt_password.text().strip()
        if not pw:
            self.lbl_unlock_error.setText("Lütfen kasa parolasını girin.")
            self.lbl_unlock_error.show()
            self.txt_password.setFocus()
            return

        is_custom = self.is_custom_vault(self.current_vault_file)
        if is_custom:
            from enclave_core import CustomVaultEngine, _derive_key, InvalidPasswordError
            try:
                auth_info = CustomVaultEngine.authenticate(self.current_vault_file, pw)
            except InvalidPasswordError:
                self.lbl_unlock_error.setText("Hatalı parola! Kasa kilidi açılamadı.")
                self.lbl_unlock_error.show()
                self.log("Bağımsız kasa için girilen parola geçersiz.", "warn", "GUVENLIK")
                audit_logger.log_security_event("UNLOCK_FAILED", "WARNING", "Hatalı parola girildi.", self.current_vault_file)
                return
            except Exception as e:
                self.lbl_unlock_error.setText(f"Kasa açma hatası: {e}")
                self.lbl_unlock_error.show()
                return

            is_enforced = CustomVaultEngine.is_vault_2fa_enforced(self.current_vault_file)
            catalog = CustomVaultEngine.load_catalog(self.current_vault_file, auth_info)
            two_factor = catalog.get("two_factor")
            if two_factor and two_factor.get("enabled"):
                is_enforced = True

            if is_enforced:
                from extra_dialogs import TOTPVerificationDialog
                dlg = TOTPVerificationDialog(
                    parent=self,
                    vault_path=self.current_vault_file,
                    auth_info=auth_info,
                    theme=self.current_theme
                )
                if dlg.exec() != QDialog.DialogCode.Accepted:
                    self.log("İki Faktörlü Doğrulama (2FA) onaylanmadı veya iptal edildi; kasa kilitli tutuldu.", "warn", "2FA")
                    self.lbl_unlock_error.setText("İki Faktörlü Doğrulama (2FA) onaylanmadı veya iptal edildi.")
                    self.lbl_unlock_error.show()
                    auth_info.clear()
                    return

            self.unlock_custom_vault(pw, auth_info=auth_info)
            return

        is_avail, _ = windows_hello.is_windows_hello_available()
        req_2fa = (
            is_avail and
            self.config.get("windows_hello_enabled", True) and
            (
                (hasattr(self, "chk_vault_2fa") and self.chk_vault_2fa.isChecked()) or
                windows_hello.is_vault_2fa_enabled(self.current_vault_file)
            )
        )

        if req_2fa:
            self.start_2fa_unlock_workflow(pw)
            return

        self._tested_decoy_fallback = False
        self.execute_unlock(pw)

    def start_2fa_unlock_workflow(self, pw: str):
        """İki Faktörlü Doğrulama (2FA) sürecini başlatır: 1. Şifre Doğrulaması -> 2. Windows Hello Biyometriği."""
        if not self.current_vault_file or not Path(self.current_vault_file).exists():
            return

        v_name = Path(self.current_vault_file).name
        is_custom = self.is_custom_vault(self.current_vault_file)

        auth_info = None
        if is_custom:
            try:
                from enclave_core import CustomVaultEngine, _derive_key, InvalidPasswordError
                auth_info = CustomVaultEngine.authenticate(self.current_vault_file, pw)
            except InvalidPasswordError:
                self.lbl_unlock_error.setText("Hatalı parola! Kasa kilidi açılamadı.")
                self.lbl_unlock_error.show()
                self.log("Bağımsız kasa için girilen parola geçersiz.", "warn", "GUVENLIK")
                audit_logger.log_security_event("UNLOCK_FAILED", "WARNING", "2FA öncesi hatalı parola girildi.", self.current_vault_file)
                return
            except Exception as e:
                self.lbl_unlock_error.setText(f"Kasa açma hatası: {e}")
                self.lbl_unlock_error.show()
                return

        self._pending_2fa = {
            "pw": pw,
            "is_custom": is_custom,
            "auth_info": auth_info
        }
        self.lbl_unlock_error.hide()
        self.btn_unlock_pw.setEnabled(False)
        self.btn_unlock_pw.setText("2. Faktör Doğrulanıyor...")
        self.log(f"İki Faktörlü Doğrulama (2FA): '{v_name}' için Windows Hello biyometrik onayı bekleniyor...", "info", "2FA")

        self.worker_2fa = VaultWorker(
            "2fa_verify",
            self.engine,
            {
                "vault_path": self.current_vault_file,
                "prompt": f"Enclave 2FA Doğrulaması: '{v_name}' kilidini açmak için parmak izinizi okutun"
            }
        )
        self.worker_2fa.log_signal.connect(self.log)
        self.worker_2fa.finished_signal.connect(self.on_2fa_finished)
        self.worker_2fa.start()

    def on_2fa_finished(self, result: dict):
        """Windows Hello 2FA biyometrik yanıtı geldiğinde çalışır."""
        self.btn_unlock_pw.setEnabled(True)
        pending = getattr(self, "_pending_2fa", None)
        self._pending_2fa = None

        is_custom = self.is_custom_vault(self.current_vault_file)
        is_2fa = windows_hello.is_vault_2fa_enabled(self.current_vault_file) if self.current_vault_file else False
        if is_2fa:
            self.btn_unlock_pw.setText("2FA ile Kasa Gezginini Aç" if is_custom else "2FA ile Kilidi Aç")
        else:
            self.btn_unlock_pw.setText("Kasa Gezginini Aç" if is_custom else "Kilidi Aç")

        if not pending:
            return

        pw = pending.get("pw")
        auth_info = pending.get("auth_info")
        v_name = Path(self.current_vault_file).name if self.current_vault_file else "Kasa"

        if result.get("success") and result.get("verified"):
            self.log(f"İki Faktörlü Doğrulama (2FA) ONAYLANDI! '{v_name}' açılıyor...", "success", "2FA")
            audit_logger.log_security_event("2FA_VERIFIED", "SUCCESS", f"2FA doğrulaması başarıyla onaylandı: {v_name}", self.current_vault_file)

            if getattr(self, "chk_vault_2fa", None) and self.chk_vault_2fa.isChecked():
                windows_hello.set_vault_2fa_enabled(self.current_vault_file, True)

            if is_custom and auth_info:
                self.unlock_custom_vault(pw, auth_info=auth_info)
            else:
                self.execute_unlock(pw)
        else:
            status = result.get("status", "İptal edildi")
            self.log(f"İki Faktörlü Doğrulama (2FA) BAŞARISIZ: {status}", "warn", "2FA")
            audit_logger.log_security_event("2FA_FAILED", "WARNING", f"2FA biyometrik onayı reddedildi: {status}", self.current_vault_file)
            self.lbl_unlock_error.setText("İki Faktörlü Biyometrik Doğrulama (2FA) reddedildi veya iptal edildi.\nKasa güvenli şekilde kilitli tutuldu.")
            self.lbl_unlock_error.show()

    def execute_unlock(self, pw: str, skip_usb_check: bool = False):
        if not pw or not self.drive_letter:
            return

        entered_hash = hashlib.sha256(pw.encode("utf-8")).hexdigest()

        if self.engine.check_embedded_decoy_vault(self.current_vault_file):
            self.is_switching_decoy = True
            swap_res = self.engine.swap_embedded_partitions(self.current_vault_file, target_part=2, letter=self.drive_letter)
            if swap_res.get("success") and swap_res.get("drive_letter"):
                self.drive_letter = swap_res.get("drive_letter")
            self.is_decoy_active = False
            self.disguise_vault_name = ""
            self.is_switching_decoy = False

        if self.config.get("decoy_vault_enabled", False):
            saved_hash = self.config.get("decoy_vault_password_hash", "")
            decoy_path = self.config.get("decoy_vault_path", "")
            if entered_hash == saved_hash and decoy_path and Path(decoy_path).exists():
                audit_logger.log_security_event("DECOY_TRIGGERED", "WARNING", "Tuzak parola girildi, sahte kasa açılıyor.", decoy_path)
                self.execute_decoy_switch(decoy_path, pw)
                return

        self._last_entered_password = pw
        self.lbl_unlock_error.hide()
        self.btn_unlock_pw.setEnabled(False)
        self.btn_unlock_pw.setText("Açılıyor...")
        self.worker = VaultWorker(
            "unlock",
            self.engine,
            {"drive_letter": self.drive_letter, "password": pw}
        )
        self.worker.log_signal.connect(self.log)
        self.worker.finished_signal.connect(self.on_unlock_finished)
        self.worker.start()

    def on_unlock_finished(self, result: dict):
        self.btn_unlock_pw.setEnabled(True)
        self.btn_unlock_pw.setText("Kilidi Aç")
        if result.get("success"):
            self.last_unlocked_password = getattr(self, "_last_entered_password", "")
            self.failed_login_count = 0
            audit_logger.log_security_event("UNLOCK_SUCCESS", "SUCCESS", "BitLocker kilidi açıldı.", self.current_vault_file, self.drive_letter)
            if getattr(self, "chk_vault_2fa", None) and self.current_vault_file:
                if self.chk_vault_2fa.isChecked():
                    windows_hello.set_vault_2fa_enabled(self.current_vault_file, True)
            self.txt_password.clear()
            self.lbl_unlock_error.hide()
            self.last_vault_activity_time = time.time()
            if getattr(self, "is_decoy_active", False) and self.drive_letter:
                self._apply_decoy_volume_label(self.drive_letter)
            self.poll_volume_status()
            self.notify_user("Enclave", f"BitLocker kilidi açıldı ({self.drive_letter})", "info")
            if self.drive_letter:
                self.auto_extend_filesystem_async(self.drive_letter)
        else:
            if not getattr(self, "_tested_decoy_fallback", False) and self.current_vault_file:
                if self.engine.check_embedded_decoy_vault(self.current_vault_file):
                    self._tested_decoy_fallback = True
                    self.is_switching_decoy = True
                    swap_1 = self.engine.swap_embedded_partitions(self.current_vault_file, target_part=1, letter=self.drive_letter)
                    t_letter = swap_1.get("drive_letter", self.drive_letter)
                    pw_try = getattr(self, "_last_entered_password", "")
                    res_decoy = self.engine.unlock_bitlocker_password(t_letter, pw_try)
                    self.is_switching_decoy = False
                    if res_decoy.get("success"):
                        self._tested_decoy_fallback = False
                        self.drive_letter = t_letter
                        self.is_decoy_active = True
                        self.disguise_vault_name = Path(self.current_vault_file).stem
                        audit_logger.log_security_event("DECOY_TRIGGERED", "WARNING", "Gömülü tuzak kasa parolası doğrulandı. Tuzak bölümü bağlandı.", self.current_vault_file)
                        self.log("Gömülü tuzak kasa parolası doğrulandı. Tuzak bölümü açılıyor...", "warn", "TUZAK KASA")
                        self.on_unlock_finished(res_decoy)
                        return
                    else:
                        self.is_switching_decoy = True
                        self.engine.swap_embedded_partitions(self.current_vault_file, target_part=2, letter=self.drive_letter)
                        self.is_switching_decoy = False
                        self._tested_decoy_fallback = False

            self.failed_login_count = getattr(self, "failed_login_count", 0) + 1
            audit_logger.log_security_event("UNLOCK_FAIL", "WARNING", f"Hatalı BitLocker parolası (Deneme #{self.failed_login_count}).", self.current_vault_file, self.drive_letter)
            err = result.get("error", "Girilen parola hatalı veya kilit açılamadı.")
            if self.config.get("anti_brute_force_delay", True) and self.failed_login_count > 1:
                delay = min(16, 2 ** (self.failed_login_count - 1))
                err += f"\n(Kaba kuvvet koruması: {delay} saniye sonra tekrar deneyin)"
                self.btn_unlock_pw.setEnabled(False)
                QTimer.singleShot(delay * 1000, lambda: self.btn_unlock_pw.setEnabled(True))
            self.lbl_unlock_error.setText(err)
            self.lbl_unlock_error.show()
            self.txt_password.selectAll()
            self.txt_password.setFocus()

    def auto_extend_filesystem_async(self, drive_letter: str):
        """Kasa bağlandığında/açıldığında dosya sistemi bölümünü arka planda maksimum disk alanına genişletir."""
        if not drive_letter:
            return
        clean_dl = drive_letter.rstrip(":\\/ ").upper()
        import threading
        def _worker():
            try:
                res = self.engine.extend_filesystem_volume(clean_dl)
                if res.get("resized"):
                    self.log(f"Bölüm boyutu yeni kasa kapasitesine otomatik uyarlandı ({clean_dl}:).", "success", "SURUCU")
            except Exception:
                pass
        threading.Thread(target=_worker, daemon=True).start()

    def toggle_password_visibility(self, checked: bool):
        if checked:
            self.txt_password.setEchoMode(QLineEdit.EchoMode.Normal)
            self.btn_show_pw.setText("Gizle")
        else:
            self.txt_password.setEchoMode(QLineEdit.EchoMode.Password)
            self.btn_show_pw.setText("Göster")

    def on_open_explorer_clicked(self):
        if self.drive_letter:
            self.last_vault_activity_time = time.time()
            self.engine.open_explorer(self.drive_letter)

    def set_ui_busy(self, is_busy: bool, message: str = ""):
        if hasattr(self, "btn_mount") and self.btn_mount is not None:
            self.btn_mount.setEnabled(not is_busy)
        if hasattr(self, "btn_dismount") and self.btn_dismount is not None:
            self.btn_dismount.setEnabled(not is_busy)
        if hasattr(self, "btn_open_explorer") and self.btn_open_explorer is not None:
            self.btn_open_explorer.setEnabled(not is_busy)
        if hasattr(self, "combo_vaults") and self.combo_vaults is not None:
            self.combo_vaults.setEnabled(not is_busy)
        
        if is_busy:
            self.status_badge.setText(f"[ {message.upper()} ]")
            is_light = (getattr(self, "current_theme", "dark") == "light")
            bg = "#D4E2FA" if is_light else "#111833"
            fg = "#1F4294" if is_light else "#38BDF8"
            border = "1px solid #3B82F6" if is_light else "1px solid #38BDF8"
            self.status_badge.setStyleSheet(f"""
                background-color: {bg};
                color: {fg};
                font-family: 'Segoe UI', 'Inter', 'Arial', sans-serif;
                font-size: 11px;
                font-weight: 700;
                padding: 5px 10px;
                border-radius: 12px;
                border: {border};
            """)
        else:
            if hasattr(self, "status_badge") and self.status_badge is not None:
                if not getattr(self, "is_mounted", False):
                    self.status_badge.setText("DİSK BAĞLI DEĞİL")
                    self.status_badge.setStyleSheet(self.get_badge_style("not_mounted"))
                elif getattr(self, "is_locked", False):
                    self.status_badge.setText("BİTLOCKER KİLİTLİ")
                    self.status_badge.setStyleSheet(self.get_badge_style("locked"))
                else:
                    self.status_badge.setText("KULLANIMA HAZIR")
                    self.status_badge.setStyleSheet(self.get_badge_style("ready"))

    def refresh_log_display(self):
        if not hasattr(self, "log_console") or not hasattr(self, "log_entries"):
            return
        is_light = (getattr(self, "current_theme", "dark") == "light")
        if is_light:
            color_map = {
                "info": "#7EE787",
                "success": "#56D364",
                "warn": "#E3B341",
                "error": "#FFA198",
                "security": "#79C0FF"
            }
            cat_color = "#D2A8FF"
            time_color = "#8B949E"
        else:
            color_map = {
                "info": "#8BE9FD",
                "success": "#10B981",
                "warn": "#FFCC00",
                "error": "#FF5555",
                "security": "#BD93F9"
            }
            cat_color = "#FF79C6"
            time_color = "#6272A4"

        html_lines = []
        for ts, cat, msg, lvl in self.log_entries[-300:]:
            col = color_map.get(lvl.lower(), color_map["info"])
            c_tag = f'<span style="color: {cat_color}; font-weight: 700;">[{cat.upper()}]</span> ' if cat else ''
            t_tag = f'<span style="color: {time_color};">[{ts}]</span> '
            html_lines.append(f'{t_tag}{c_tag}<span style="color: {col};">{msg}</span>')

        self.log_console.setHtml("<br>".join(html_lines))
        sb = self.log_console.verticalScrollBar()
        if sb:
            sb.setValue(sb.maximum())

    def log(self, message: str, level: str = "info", category: str = "BILGI"):
        timestamp = time.strftime("%H:%M:%S")
        if not hasattr(self, "log_entries"):
            self.log_entries = []
        self.log_entries.append((timestamp, category, message, level))
        if len(self.log_entries) > 500:
            self.log_entries = self.log_entries[-300:]

        is_light = (getattr(self, "current_theme", "dark") == "light")
        if is_light:
            color_map = {
                "info": "#7EE787",
                "success": "#56D364",
                "warn": "#E3B341",
                "error": "#FFA198",
                "security": "#79C0FF"
            }
            cat_color = "#D2A8FF"
            time_color = "#8B949E"
        else:
            color_map = {
                "info": "#8BE9FD",
                "success": "#10B981",
                "warn": "#FFCC00",
                "error": "#FF5555",
                "security": "#BD93F9"
            }
            cat_color = "#FF79C6"
            time_color = "#6272A4"

        color = color_map.get(level.lower(), color_map["info"])
        cat_tag = f'<span style="color: {cat_color}; font-weight: 700;">[{category.upper()}]</span> ' if category else ''
        time_tag = f'<span style="color: {time_color};">[{timestamp}]</span> '

        html_msg = f'{time_tag}{cat_tag}<span style="color: {color};">{message}</span>'
        self.log_console.append(html_msg)

        log_to_file(message, level=level, category=category)

    def on_clear_log_clicked(self):
        reply = QMessageBox.question(
            self,
            "Günlüğü Temizle",
            "Günlük nasıl temizlensin?\n\n"
            "Evet: Hem ekrandaki günlüğü hem bugünkü log dosyasını sıfırla\n"
            "Hayır: Yalnızca ekrandaki günlüğü temizle",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No | QMessageBox.StandardButton.Cancel
        )
        if reply == QMessageBox.StandardButton.Yes:
            self.log_entries = []
            self.log_console.clear()
            clear_log_file()
            self.log("Olay günlüğü ve bugünkü log dosyası sıfırlandı.", "info", "SISTEM")
        elif reply == QMessageBox.StandardButton.No:
            self.log_entries = []
            self.log_console.clear()

    def save_preferences(self):
        self.config["autoplay_protection"] = self.chk_autoplay.isChecked()
        self.config["auto_open_explorer"] = self.chk_auto_explorer.isChecked()
        self.config["minimize_to_tray_on_mount"] = self.chk_tray.isChecked()
        self.config["auto_dismount_on_close"] = self.chk_close_dismount.isChecked()
        self.config["lock_on_screen_lock"] = self.chk_lock_screen.isChecked()
        self.config["auto_lock_enabled"] = self.chk_inactivity.isChecked()
        if hasattr(self, "chk_clean_traces"):
            self.config["cache_clean_on_dismount"] = self.chk_clean_traces.isChecked()
        if hasattr(self, "chk_auto_backup"):
            self.config["auto_backup_enabled"] = self.chk_auto_backup.isChecked()
        
        mins_list = [0.5, 1, 2, 5, 10, 15, 30]
        idx = self.combo_inactivity_mins.currentIndex()
        if 0 <= idx < len(mins_list):
            self.config["auto_lock_minutes"] = mins_list[idx]
        save_config(self.config)

    def get_vault_usb_credentials(self, vault_path: Optional[str] = None) -> Tuple[str, str]:
        return ("", "")

    def is_vault_usb_protected(self, vault_path: Optional[str] = None) -> bool:
        return False

    def on_manage_bitlocker_password(self, reset_mode: bool = False):
        """Kasaya sonradan BitLocker şifresi koyma, mevcut şifreyi değiştirme veya şifrelemeyi kaldırma penceresini açar."""
        target_vault = (self.active_decoy_path if getattr(self, "is_decoy_active", False) and getattr(self, "active_decoy_path", None)
                        else (self.current_vault_file or self.engine.active_vault_file))
        v_title = self.disguise_vault_name if getattr(self, "is_decoy_active", False) and getattr(self, "disguise_vault_name", "") else (Path(target_vault).name if target_vault else "Sanal Kasa")
        if not target_vault or not Path(target_vault).exists():
            QMessageBox.warning(self, "Kasa Seçilmedi", "Lütfen önce bir kasa dosyası seçin veya oluşturun.")
            return

        if not self.engine.is_admin():
            reply = QMessageBox.question(
                self,
                "Yönetici Yetkisi Gerekli",
                "BitLocker şifrelemesini yönetmek ve parola belirlemek için Windows yönetici yetkisi gereklidir.\n\n"
                "Uygulama yönetici (Administrator) olarak yeniden başlatılsın mı?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.Yes
            )
            if reply == QMessageBox.StandardButton.Yes:
                extra = ["--file", target_vault] if target_vault else None
                if self.engine.elevate_process(extra_args=extra):
                    QApplication.quit()
            return

        if not self.is_mounted or not self.drive_letter:
            reply = QMessageBox.question(
                self,
                "Kasa Bağlı Değil",
                f"'{Path(target_vault).name}' kasasının BitLocker parolasını belirlemek veya değiştirmek için kasanın sisteme bağlı olması gerekir.\n\n"
                "Kasa şimdi bağlansın mı?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.Yes
            )
            if reply == QMessageBox.StandardButton.Yes:
                self.on_mount_clicked()
            return

        if not reset_mode and getattr(self, "is_locked", False):
            QMessageBox.warning(
                self,
                "Kasa Kilitli",
                "Kasanın parolasını değiştirmek, yeni şifre belirlemek veya şifrelemeyi kaldırmak için önce mevcut parolanızı (veya kurtarma anahtarınızı) girerek kilidi açmalısınız."
            )
            return

        try:
            dlg = BitLockerPasswordDialog(
                self,
                engine=self.engine,
                drive_letter=self.drive_letter,
                vault_name=v_title,
                theme=self.current_theme,
                reset_mode=reset_mode,
                vault_path=target_vault
            )
            if dlg.exec() == QDialog.DialogCode.Accepted:
                self.poll_volume_status()
                self.refresh_vault_list()
        except Exception as e:
            QMessageBox.critical(self, "Hata", f"Parola yönetimi penceresi açılamadı: {e}")

    def on_unlock_with_recovery_key(self):
        """Kilitli olan BitLocker kasasını 48 haneli kurtarma anahtarı ile açar."""
        if not self.drive_letter:
            QMessageBox.warning(self, "Uyarı", "Bağlı bir sürücü tespit edilemedi.")
            return

        try:
            dlg = BitLockerUnlockRecoveryDialog(
                self,
                engine=self.engine,
                drive_letter=self.drive_letter,
                theme=self.current_theme
            )
            if dlg.exec() == QDialog.DialogCode.Accepted:
                self.log(f"Kasa kurtarma anahtarı ile açıldı: {self.drive_letter}", "success", "GUVENLIK")
                self.poll_volume_status()
        except Exception as e:
            QMessageBox.critical(self, "Hata", f"Kurtarma ile kilit açma penceresi açılamadı: {e}")

    def on_show_recovery_key(self):
        """Bağlı sürücünün 48 haneli BitLocker kurtarma anahtarını çeker ve gösterir."""
        if not self.is_mounted or not self.drive_letter:
            QMessageBox.warning(self, "Uyarı", "Kurtarma anahtarını görüntülemek için kasanın bağlı olması gerekir.")
            return

        self.set_ui_busy(True, "BitLocker kurtarma anahtarı alınıyor...")
        try:
            res = self.engine.get_bitlocker_recovery_key(self.drive_letter)
        except Exception as e:
            res = {"success": False, "error": f"Kurtarma anahtarı okunurken hata oluştu: {e}"}
        finally:
            self.set_ui_busy(False)

        target_vault = self.current_vault_file or self.engine.active_vault_file
        v_name = Path(target_vault).name if target_vault else ""
        if res.get("success"):
            try:
                dlg = BitLockerRecoveryDialog(
                    self,
                    recovery_key=res.get("recovery_key", ""),
                    drive_letter=self.drive_letter,
                    theme=self.current_theme,
                    vault_name=v_name,
                    vault_path=target_vault
                )
                dlg.exec()
            except Exception as e:
                QMessageBox.warning(self, "Hata", f"Kurtarma penceresi açılamadı: {e}")
        else:
            QMessageBox.warning(self, "Hata", f"Kurtarma anahtarı alınamadı:\n{res.get('error')}")

    def on_vault_password_recovery(self):
        """
        Unutulan parolayı 48 haneli BitLocker kurtarma anahtarı ile sıfırlayıp kasayı açan kurtarma sihirbazı.
        """
        target_vault = self.current_vault_file or getattr(self.engine, "active_vault_file", None)
        if not target_vault or not Path(target_vault).exists():
            selected, _ = QFileDialog.getOpenFileName(
                self,
                "Kurtarılacak Kasa Dosyasını (VHD/VHDX) Seçin",
                str(VAULTS_DIR),
                "Sanal Disk Dosyaları (*.vhd *.vhdx)"
            )
            if not selected:
                return
            target_vault = selected
            self.add_custom_vault(target_vault)

        try:
            dlg = VaultPasswordRecoveryDialog(
                self,
                engine=self.engine,
                config=self.config,
                vault_file=target_vault,
                drive_letter=self.drive_letter,
                theme=self.current_theme
            )
            if dlg.exec() == QDialog.DialogCode.Accepted:
                save_config(self.config)
                self.log(f"Kasa başarıyla kurtarıldı ve yeni parola tanımlandı: {Path(target_vault).name}", "success", "GUVENLIK")
                self.poll_volume_status()
                self.refresh_vault_list()
        except Exception as e:
            QMessageBox.critical(self, "Hata", f"Kasa kurtarma sihirbazı açılamadı: {e}")

    def on_configure_decoy(self):
        """Tuzak (Decoy) Kasa yapılandırma penceresini açar."""
        dlg = DecoyVaultDialog(self, config=self.config, theme=self.current_theme)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            save_config(self.config)
            self.log("Tuzak Kasa (Decoy) ayarları güncellendi.", "info", "GUVENLIK")

    def on_show_audit_log(self):
        """Güvenlik Denetim Günlüğü raporunu açar."""
        dlg = AuditLogDialog(self, theme=self.current_theme)
        dlg.exec()

    def on_manage_profiles(self):
        """Çoklu kasa profilleri yönetim penceresini açar."""
        dlg = VaultProfilesDialog(self, engine=self.engine, config=self.config, current_vault=self.current_vault_file, theme=self.current_theme)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            save_config(self.config)
            if dlg.selected_path:
                self.add_custom_vault(dlg.selected_path)
                self.log(f"Profil kasası yüklendi: {Path(dlg.selected_path).name}", "info", "KASA")

    def on_mount_all_vaults(self):
        """Kayıtlı tüm profil kasalarını toplu olarak bağlar."""
        profiles = self.config.get("vault_profiles", [])
        if not profiles:
            QMessageBox.information(
                self,
                "Profil Bulunamadı",
                "Henüz kaydedilmiş çoklu kasa profili bulunamadı.\n"
                "Önce 'Çoklu Kasa Profilleri' penceresinden kasalarınızı profile ekleyin."
            )
            return

        mounted_count = 0
        for p in profiles:
            v_path = p.get("path", "")
            if not v_path or not Path(v_path).exists():
                continue
            att = self.engine.check_vault_attached(v_path)
            if att and att.get("Attached"):
                continue

            pref = p.get("letter")
            res = self.engine.mount_vhd(v_path, preferred_letter=pref)
            if res.get("success"):
                mounted_count += 1

        self.refresh_vault_list()
        self.notify_user("Enclave", f"{mounted_count} adet kasa sisteme bağlandı.", "info")
        QMessageBox.information(self, "Toplu Bağlama", f"{mounted_count} adet kasa başarıyla sisteme bağlandı.")

    def on_dismount_all_vaults(self):
        """Sistemde açık bulunan tüm profil kasalarını toplu ve güvenli şekilde ayırır."""
        profiles = self.config.get("vault_profiles", [])
        vaults_to_check = set()
        for p in profiles:
            if p.get("path"):
                vaults_to_check.add(p["path"])
        if self.current_vault_file:
            vaults_to_check.add(self.current_vault_file)
        if getattr(self, "is_decoy_active", False) and getattr(self, "active_decoy_path", None):
            vaults_to_check.add(self.active_decoy_path)

        dismounted_count = 0
        for v_path in vaults_to_check:
            att = self.engine.check_vault_attached(v_path)
            if att and att.get("Attached"):
                dl = att.get("DriveLetter", "")
                if dl:
                    self.engine.close_explorer_windows(dl)
                self.engine.dismount_vhd(mount_target=v_path, drive_letter=dl, force=True)
                dismounted_count += 1

        self.refresh_vault_list()
        self.reset_to_unmounted_state(show_tray_message=False)
        self.notify_user("Enclave", f"{dismounted_count} adet kasa güvenle ayrıldı.", "info")
        QMessageBox.information(self, "Toplu Ayırma", f"{dismounted_count} adet kasa başarıyla ayrıldı.")

    def on_expand_vault(self):
        """Kasa boyutunu genişletme sihirbazını açar."""
        target_path = str(self.current_vault_file).strip(' "\'') if self.current_vault_file else ""
        if not target_path or not Path(target_path).exists():
            QMessageBox.warning(self, "Uyarı", "Lütfen önce geçerli bir kasa dosyası seçin.")
            return

        if self.is_mounted:
            QMessageBox.warning(self, "Uyarı", "Kasa şu anda bağlı durumda.\nBoyut genişletmek için lütfen önce kasayı güvenle ayırın.")
            return

        dlg = ExpandVaultDialog(self, engine=self.engine, vault_path=target_path, theme=self.current_theme)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self.refresh_vault_list()
            self.check_if_already_attached(target_path)
            self.update_unmounted_capacity_display(target_path)
            self.update_capacity_badge()
            self.update_vault_path_display()
            new_gb = getattr(dlg, "target_new_gb", "")
            gb_str = f" -> Yeni Kapasite: {new_gb} GB" if new_gb else ""
            self.log(f"Kasa boyutu başarıyla genişletildi: {Path(target_path).name}{gb_str}", "success", "KASA")

    def on_disk_health(self):
        """Disk sağlığı ve bütünlük kontrolü penceresini açar."""
        if not self.current_vault_file or not Path(self.current_vault_file).exists():
            QMessageBox.warning(self, "Uyarı", "Lütfen önce geçerli bir kasa dosyası seçin.")
            return

        drive = self.drive_letter if self.is_mounted else ""
        dlg = DiskHealthDialog(self, engine=self.engine, vault_path=self.current_vault_file, drive_letter=drive, theme=self.current_theme)
        dlg.exec()

    def on_shell_integration(self):
        """Windows Gezgini sağ tık entegrasyonu yönetim penceresini açar."""
        dlg = ShellIntegrationDialog(self, engine=self.engine, theme=self.current_theme)
        dlg.exec()

    def notify_user(self, title: str, message: str, icon_type: str = "info"):
        """Kullanıcıya Windows 10/11 yerel bildirimi (Toast) gönderir."""
        if not self.config.get("toast_notifications_enabled", True):
            return
        try:
            if hasattr(self, "tray_icon") and self.tray_icon.isVisible():
                icon = QSystemTrayIcon.MessageIcon.Information
                if icon_type == "warn":
                    icon = QSystemTrayIcon.MessageIcon.Warning
                elif icon_type == "error":
                    icon = QSystemTrayIcon.MessageIcon.Critical
                self.tray_icon.showMessage(title, message, icon, 4000)
            else:
                self.engine.send_toast_notification(title, message, icon_type)
        except Exception:
            pass

    def _apply_decoy_volume_label(self, drive_letter: str):
        """Tuzak kasanın Windows Gezginindeki birim adını gerçek kasanın adıyla kamufle eder."""
        if not drive_letter or not getattr(self, "disguise_vault_name", ""):
            return
        clean_letter = drive_letter.rstrip(":\\/ ").upper()
        if not clean_letter:
            return
        clean_root = f"{clean_letter}:\\"
        clean_label = re.sub(r'[\*\?\/\\\|\.,;:\+=\[\]<>"~]', '', str(self.disguise_vault_name)).strip()[:32]
        if not clean_label:
            clean_label = "Kasa"

        try:
            res = ctypes.windll.kernel32.SetVolumeLabelW(clean_root, clean_label)
            if res != 0:
                self.decoy_volume_renamed = True
        except Exception:
            pass

        try:
            reg_path = f"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\DriveIcons\\{clean_letter}\\DefaultLabel"
            key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, reg_path)
            winreg.SetValueEx(key, "", 0, winreg.REG_SZ, clean_label)
            winreg.CloseKey(key)
            self.decoy_registry_letter = clean_letter
        except Exception:
            pass

        try:
            ctypes.windll.shell32.SHChangeNotify(0x00080000, 0x0000, None, None)
        except Exception:
            pass

    def _cleanup_decoy_volume_label(self):
        """Tuzak kasanın Explorer üzerindeki kamuflaj kayıtlarını temizler."""
        reg_letter = getattr(self, "decoy_registry_letter", "") or (self.drive_letter.rstrip(":\\/ ").upper() if self.drive_letter else "")
        if reg_letter:
            try:
                base_path = f"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\DriveIcons\\{reg_letter}"
                try:
                    winreg.DeleteKey(winreg.HKEY_CURRENT_USER, f"{base_path}\\DefaultLabel")
                except Exception:
                    pass
                try:
                    winreg.DeleteKey(winreg.HKEY_CURRENT_USER, base_path)
                except Exception:
                    pass
            except Exception:
                pass
            try:
                ctypes.windll.shell32.SHChangeNotify(0x00080000, 0x0000, None, None)
            except Exception:
                pass
            self.decoy_registry_letter = ""

        if getattr(self, "decoy_original_label", "") and self.drive_letter:
            try:
                clean_root = f"{self.drive_letter.rstrip(':\\/ ')[0]}:\\"
                clean_orig = re.sub(r'[\*\?\/\\\|\.,;:\+=\[\]<>"~]', '', str(self.decoy_original_label)).strip()[:32]
                if clean_orig:
                    ctypes.windll.kernel32.SetVolumeLabelW(clean_root, clean_orig)
            except Exception:
                pass

    def execute_decoy_switch(self, decoy_path: str, password: str):
        """Tuzak kasa tetiklendiğinde gerçek kasayı bırakıp sahte kasayı açar."""
        self.is_switching_decoy = True
        self.is_dismounting = True
        self.status_timer.stop()
        self.set_ui_busy(True, "BitLocker kilidi açılıyor...")
        
        real_vault = self.current_vault_file or self.engine.active_mount_target
        real_drive = self.drive_letter or self.engine.active_drive_letter
        disguise_name = Path(real_vault).stem if real_vault else "Kasa"
        
        self.is_decoy_active = True
        self.active_decoy_path = decoy_path
        self.disguise_vault_file = real_vault
        self.disguise_vault_name = disguise_name
        self.decoy_original_label = ""
        self.decoy_volume_renamed = False

        if real_drive:
            self.engine.close_explorer_windows(real_drive)
        if real_vault or real_drive:
            try:
                self.engine.dismount_vhd(mount_target=real_vault, drive_letter=real_drive, force=True)
            except Exception:
                pass
        self.is_dismounting = False

        
        preferred_letter = real_drive.rstrip("\\").rstrip(":") if real_drive else ""
        self.worker = VaultWorker("mount", self.engine, {
            "file_path": decoy_path,
            "preferred_letter": preferred_letter,
            "autoplay_protection": True
        })
        self.worker.log_signal.connect(self.log)
        self.worker.finished_signal.connect(lambda res: self.on_decoy_mount_finished(res, password))
        self.worker.start()

    def on_decoy_mount_finished(self, mount_res: dict, password: str):
        if not mount_res.get("success"):
            self.is_switching_decoy = False
            self.is_decoy_active = False
            self.active_decoy_path = None
            self.set_ui_busy(False)
            self.lbl_unlock_error.setText("Kasa açılamadı.")
            self.lbl_unlock_error.show()
            self.reset_to_unmounted_state(show_tray_message=False)
            return

        dl = mount_res.get("drive_letter", "")
        self.drive_letter = dl
        self.is_mounted = True
        self.is_locked = False
        self.reset_inactivity_timer()

        self.drive_badge.setText(f"SÜRÜCÜ: {self.drive_letter}" if self.drive_letter else "SÜRÜCÜ: ?")
        self.drive_badge.setStyleSheet(self.get_badge_style("drive"))
        self.status_badge.setText("KULLANIMA HAZIR")
        self.status_badge.setStyleSheet(self.get_badge_style("ready"))

        self.unlock_card.hide()
        self.lbl_unlock_error.hide()
        self.show_mounted_actions(show_explorer=True)
        self.update_vault_state_icon()

        self.engine.suppress_bdeunlock()
        self.raise_()
        self.activateWindow()

        status = self.engine.get_drive_status(dl)
        self.decoy_original_label = status.get("label", "")
        b_status = status.get("bitlocker_status", "unknown")
        is_locked = status.get("is_locked", False)
        
        if b_status in ("not_bitlocker", "unlocked") or status.get("protection_status") == "OFF" or not is_locked:
            self._apply_decoy_volume_label(dl)
            self.is_switching_decoy = False
            self.set_ui_busy(False)
            self.status_timer.start()
            self.poll_volume_status()
            self.refresh_vault_list()
            self.notify_user("Enclave", f"BitLocker kilidi açıldı ({self.drive_letter})", "info")
            if self.chk_auto_explorer.isChecked():
                self.on_open_explorer_clicked()
            return

        self.worker = VaultWorker("unlock", self.engine, {"drive_letter": dl, "password": password})
        self.worker.log_signal.connect(self.log)
        def _on_decoy_unlocked(res):
            self.is_switching_decoy = False
            self.set_ui_busy(False)
            if res.get("success"):
                self._apply_decoy_volume_label(self.drive_letter)
                self.status_timer.start()
                self.on_unlock_finished(res)
            else:
                self.status_timer.start()
                self.on_unlock_finished(res)
        self.worker.finished_signal.connect(_on_decoy_unlocked)
        self.worker.start()

    def closeEvent(self, event):
        """Kullanıcı pencereyi kapattığında güvenli ayrılma kontrolü yapar."""
        if hasattr(self, "chk_tray") and self.chk_tray.isChecked():
            event.ignore()
            self.hide()
            if hasattr(self, "tray_icon") and self.tray_icon.isVisible():
                self.tray_icon.showMessage(
                    "Enclave",
                    "Uygulama arka planda sistem tepsisinde çalışmaya devam ediyor.",
                    QSystemTrayIcon.MessageIcon.Information,
                    2000
                )
            return

        if hasattr(self, "panic_listener") and self.panic_listener.isRunning():
            try:
                self.panic_listener.stop()
            except Exception:
                pass

        if self.hotkey_registered:
            try:
                ctypes.windll.user32.UnregisterHotKey(int(self.winId()), self.HOTKEY_ID)
            except Exception:
                pass

        if getattr(self, "wts_registered", False):
            try:
                ctypes.windll.wtsapi32.WTSUnRegisterSessionNotification(int(self.winId()))
            except Exception:
                pass

        self.terminate_hook_processes()

        if self.config.get("cache_clean_on_dismount", True):
            try:
                self.engine.wipe_system_traces(self.drive_letter or self.engine.active_drive_letter)
            except Exception:
                pass

        if self.is_mounted:
            auto_dismount = self.config.get("auto_dismount_on_close", True)
            if auto_dismount:
                target = (self.active_decoy_path if getattr(self, "is_decoy_active", False) and getattr(self, "active_decoy_path", None)
                          else (self.current_vault_file or self.engine.active_mount_target))
                self.engine.dismount_vhd(mount_target=target, drive_letter=self.drive_letter, force=True)
                self._cleanup_decoy_volume_label()
                if self.chk_autoplay.isChecked():
                    self.engine.restore_autoplay()
                event.accept()
                QApplication.quit()
            else:
                reply = QMessageBox.question(
                    self,
                    "Sanal Sürücü Halen Bağlı",
                    f"Sanal sürücü ({self.drive_letter}) sistemde halen açık.\n\n"
                    "Çıkış yaparken diski güvenle ayırmak istiyor musunuz?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No | QMessageBox.StandardButton.Cancel
                )
                if reply == QMessageBox.StandardButton.Yes:
                    target = (self.active_decoy_path if getattr(self, "is_decoy_active", False) and getattr(self, "active_decoy_path", None)
                              else (self.current_vault_file or self.engine.active_mount_target))
                    self.engine.dismount_vhd(mount_target=target, drive_letter=self.drive_letter, force=True)
                    if self.chk_autoplay.isChecked():
                        self.engine.restore_autoplay()
                    event.accept()
                    QApplication.quit()
                elif reply == QMessageBox.StandardButton.No:
                    event.accept()
                    QApplication.quit()
                else:
                    event.ignore()
        else:
            if self.chk_autoplay.isChecked():
                self.engine.restore_autoplay()
            event.accept()
            QApplication.quit()

    def safe_exit(self):
        if hasattr(self, "panic_listener") and self.panic_listener.isRunning():
            try:
                self.panic_listener.stop()
            except Exception:
                pass
        if self.hotkey_registered:
            try:
                ctypes.windll.user32.UnregisterHotKey(int(self.winId()), self.HOTKEY_ID)
            except Exception:
                pass
        if getattr(self, "wts_registered", False):
            try:
                ctypes.windll.wtsapi32.WTSUnRegisterSessionNotification(int(self.winId()))
            except Exception:
                pass
        self.terminate_hook_processes()
        if self.config.get("cache_clean_on_dismount", True):
            try:
                self.engine.wipe_system_traces(self.drive_letter or self.engine.active_drive_letter)
            except Exception:
                pass
        if self.is_mounted:
            target = self.current_vault_file or self.engine.active_mount_target
            self.engine.dismount_vhd(mount_target=target, drive_letter=self.drive_letter, force=True)
        if self.chk_autoplay.isChecked():
            self.engine.restore_autoplay()
        QApplication.quit()

    def toggle_fullscreen(self):
        """Ana pencereyi kenarlıksız tam ekran veya pencere modu arasında geçirir."""
        now = time.time()
        if hasattr(self, "_last_fs_toggle") and now - self._last_fs_toggle < 0.4:
            return
        self._last_fs_toggle = now
        if self.isFullScreen():
            self.showNormal()
        else:
            self.showFullScreen()
        self.update_fullscreen_ui()

    def _exit_fullscreen_if_active(self):
        if self.isFullScreen():
            self.showNormal()
            self.update_fullscreen_ui()

    def update_fullscreen_ui(self):
        if not hasattr(self, "btn_fullscreen"):
            return
        is_fs = self.isFullScreen()
        s_col = "#2997FF" if self.current_theme == "apple_dark" else ("#0071E3" if self.current_theme == "apple_light" else ("#38BDF8" if self.current_theme == "dark" else "#0284C7"))
        if is_fs:
            self.btn_fullscreen.setText(" Pencere")
            self.btn_fullscreen.setIcon(get_svg_icon("collapse", s_col, 14))
            self.btn_fullscreen.setToolTip("Pencere Moduna Dön (F11 / Esc)")
        else:
            self.btn_fullscreen.setText(" Tam Ekran")
            self.btn_fullscreen.setIcon(get_svg_icon("expand", s_col, 14))
            self.btn_fullscreen.setToolTip("Tam Ekran Modunu Aç (F11)")

    def keyPressEvent(self, event):
        """Klavye olaylarını üst sınıfa iletir (QShortcut çift tetikleme önlendi)."""
        super().keyPressEvent(event)

