"""
Enclave - Gelişmiş Güvenlik ve Yardımcı Diyaloglar Modülü (Extra Dialogs)
BitLocker Kurtarma Anahtarı, Tuzak Kasa,
Güvenlik Denetim Günlüğü ve Dosya Parçalama (Shred) pencerelerini içerir.
"""

import sys
import hashlib
from pathlib import Path
from typing import Optional, List, Dict, Any

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QLineEdit, QCheckBox, QComboBox, QFileDialog, QMessageBox,
    QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView,
    QFrame, QSpinBox, QTextEdit, QProgressBar, QInputDialog, QApplication,
    QScrollArea, QWidget, QGridLayout, QTabWidget, QGroupBox
)
from PyQt6.QtCore import Qt, QTimer, QThread, pyqtSignal
from PyQt6.QtGui import QIcon, QFont

import audit_logger
from config import save_config
from enclave_custom_ui import get_svg_icon, get_svg_pixmap, apply_dynamic_geometry
from enclave_core import CustomVaultEngine, CustomVaultError, InvalidPasswordError
import windows_hello
import totp_engine
from PyQt6.QtGui import QPixmap, QImage

def set_dialog_dark_mode(dialog, is_dark: bool = True):
    """Windows 10/11 DWM baslik cubugu gece/gunduz rengini esitler."""
    if sys.platform != "win32":
        return
    try:
        import ctypes
        hwnd = int(dialog.winId())
        DWMWA_USE_IMMERSIVE_DARK_MODE = 20
        val = ctypes.c_int(1 if is_dark else 0)
        ctypes.windll.dwmapi.DwmSetWindowAttribute(
            hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, ctypes.byref(val), ctypes.sizeof(val)
        )
    except Exception:
        pass

def apply_dynamic_geometry(
    dialog: QDialog,
    default_w: int = 500,
    default_h: int = 360,
    min_w: int = 420,
    min_h: int = 260,
    w_ratio: float = 0.0,
    h_ratio: float = 0.0,
    max_w: int = 1400,
    max_h: int = 950
):
    """
    Pencereyi olabilecek en minimal, ergonomik ve kompakt boyutta açar;
    kullanıcının ekran çözünürlüğüne, çalışma alanına ve Windows DPI ölçeğine
    göre dinamik olarak ayarlar ve ekranın tam merkezine yerleştirir.
    Gereksiz devasa ekran kaplamalarını önler, serbestçe yeniden boyutlandırılabilir.
    """
    try:
        from PyQt6.QtGui import QGuiApplication
        screen = dialog.screen() or QGuiApplication.primaryScreen()
        if screen:
            avail = screen.availableGeometry()
            dpi_factor = max(1.0, screen.logicalDotsPerInch() / 96.0)

            scaled_min_w = int(min_w * dpi_factor)
            scaled_min_h = int(min_h * dpi_factor)

            target_w = int(default_w * dpi_factor)
            target_h = int(default_h * dpi_factor)

            if w_ratio > 0.0:
                target_w = max(target_w, int(avail.width() * w_ratio))
            if h_ratio > 0.0:
                target_h = max(target_h, int(avail.height() * h_ratio))

            limit_max_w = min(max_w if max_w else avail.width() - 40, avail.width() - 30)
            limit_max_h = min(max_h if max_h else avail.height() - 60, avail.height() - 40)

            final_w = min(limit_max_w, max(scaled_min_w, target_w))
            final_h = min(limit_max_h, max(scaled_min_h, target_h))

            dialog.setMinimumSize(scaled_min_w, scaled_min_h)
            dialog.resize(final_w, final_h)

            x = avail.x() + (avail.width() - final_w) // 2
            y = avail.y() + (avail.height() - final_h) // 2
            dialog.move(x, y)
    except Exception:
        dialog.resize(default_w, default_h)
        dialog.setMinimumSize(min_w, min_h)

def get_dialog_palette(theme: str = "apple_dark") -> dict:
    """
    Tum diyalog pencereleri icin Apple Minimal Koyu estetik palet dondurur.
    """
    theme = "apple_dark"
    is_apple_dark = True
    is_apple_light = (theme == "apple_light")
    is_dark = (theme in ("dark", "apple_dark"))

    if is_apple_dark:
        return {
            "is_dark": True,
            "bg_col": "#161618",
            "card_bg": "#212124",
            "card_border": "#3A3A3E",
            "inp_bg": "#2C2C2E",
            "inp_border": "#48484A",
            "border_col": "#3A3A3E",
            "text_col": "#F5F5F7",
            "text_muted": "#86868B",
            "label_col": "#F5F5F7",
            "placeholder_col": "#86868B",
            "accent_col": "#2997FF",
            "accent_hover": "#0071E3",
            "btn_bg": "#2C2C2E",
            "btn_hover": "#3A3A3C",
            "btn_text": "#F5F5F7",
            "btn_border": "#3A3A3C",
            "key_col": "#2997FF",
            "table_bg": "#1A1A1D",
            "table_header": "#212124",
            "danger_col": "#FF453A",
            "danger_hover": "#D73A30",
            "success_col": "#30D158",
            "warning_col": "#FF9F0A",
        }
    elif is_apple_light:
        return {
            "is_dark": False,
            "bg_col": "#F5F5F7",
            "card_bg": "#FFFFFF",
            "card_border": "#D2D2D7",
            "inp_bg": "#FFFFFF",
            "inp_border": "#86868B",
            "border_col": "#D2D2D7",
            "text_col": "#1D1D1F",
            "text_muted": "#6E6E73",
            "label_col": "#1D1D1F",
            "placeholder_col": "#86868B",
            "accent_col": "#0071E3",
            "accent_hover": "#0077ED",
            "btn_bg": "#FFFFFF",
            "btn_hover": "#F0F0F2",
            "btn_text": "#1D1D1F",
            "btn_border": "#D2D2D7",
            "key_col": "#0071E3",
            "table_bg": "#FFFFFF",
            "table_header": "#F5F5F7",
            "danger_col": "#FF3B30",
            "danger_hover": "#D70015",
            "success_col": "#34C759",
            "warning_col": "#FF9500",
        }
    elif is_dark:
        return {
            "is_dark": True,
            "bg_col": "#0B0F19",
            "card_bg": "#131B2E",
            "card_border": "#23304A",
            "inp_bg": "#0A0E17",
            "inp_border": "#2C3D5E",
            "border_col": "#23304A",
            "text_col": "#F8FAFC",
            "text_muted": "#94A3B8",
            "label_col": "#F1F5F9",
            "placeholder_col": "#64748B",
            "accent_col": "#38BDF8",
            "accent_hover": "#0284C7",
            "btn_bg": "#1E283D",
            "btn_hover": "#2B3854",
            "btn_text": "#F8FAFC",
            "btn_border": "#283754",
            "key_col": "#38BDF8",
            "table_bg": "#0E1422",
            "table_header": "#182238",
            "danger_col": "#EF4444",
            "danger_hover": "#DC2626",
            "success_col": "#10B981",
            "warning_col": "#F59E0B",
        }
    else:
        return {
            "is_dark": False,
            "bg_col": "#F8FAFC",
            "card_bg": "#FFFFFF",
            "card_border": "#CBD5E1",
            "inp_bg": "#FFFFFF",
            "inp_border": "#CBD5E1",
            "border_col": "#CBD5E1",
            "text_col": "#0F172A",
            "text_muted": "#64748B",
            "label_col": "#0F172A",
            "placeholder_col": "#94A3B8",
            "accent_col": "#0284C7",
            "accent_hover": "#0369A1",
            "btn_bg": "#F1F5F9",
            "btn_hover": "#E2E8F0",
            "btn_text": "#0F172A",
            "btn_border": "#CBD5E1",
            "key_col": "#0284C7",
            "table_bg": "#FFFFFF",
            "table_header": "#F1F5F9",
            "danger_col": "#DC2626",
            "danger_hover": "#B91C1C",
            "success_col": "#16A34A",
            "warning_col": "#D97706",
        }

def get_dialog_button_stylesheet(theme_or_is_dark = True) -> str:
    """
    Tum diyalog pencerelerindeki butonlar, girdiler, tablolar ve kapsayicilar icin
    Open Design Apple HIG ve Linear App standartlarinda kusursuz tema stili dondurur.
    """
    if isinstance(theme_or_is_dark, str):
        theme = theme_or_is_dark
    else:
        theme = "dark" if theme_or_is_dark else "light"
    pal = get_dialog_palette(theme)
    font_stack = "-apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif"
    
    return f"""
        QPushButton {{
            background-color: {pal['btn_bg']};
            color: {pal['btn_text']};
            font-family: {font_stack};
            font-size: 11.5px;
            font-weight: 600;
            padding: 8px 18px;
            border: 1px solid {pal['btn_border']};
            border-radius: 8px;
            min-height: 34px;
        }}
        QPushButton:hover {{
            background-color: {pal['btn_hover']};
            border-color: {pal['accent_col']};
            color: {pal['accent_col']};
            cursor: pointer;
        }}
        QPushButton:pressed {{
            background-color: {pal['card_bg']};
            border-color: {pal['accent_col']};
            padding-top: 8px;
            padding-left: 19px;
        }}
        QPushButton:disabled {{
            opacity: 0.45;
            color: {pal['text_muted']};
            border-color: {pal['card_border']};
        }}
        QPushButton#btn-accent, QPushButton.btn-accent, QPushButton#btn-primary, QPushButton#btn-save-settings, QPushButton#btn-unlock, QPushButton#btn-ok, QPushButton.btn-primary {{
            background-color: {pal['accent_col']};
            color: #FFFFFF;
            font-weight: 700;
            border: 1px solid {pal['accent_hover']};
            border-radius: 8px;
            min-height: 36px;
            padding: 8px 22px;
        }}
        QPushButton#btn-accent:hover, QPushButton.btn-accent:hover, QPushButton#btn-primary:hover, QPushButton#btn-save-settings:hover, QPushButton#btn-unlock:hover, QPushButton#btn-ok:hover, QPushButton.btn-primary:hover {{
            background-color: {pal['accent_hover']};
            border-color: {pal['accent_hover']};
            color: #FFFFFF;
        }}
        QPushButton#btn-danger, QPushButton#btn-shred, QPushButton#btn-delete, QPushButton#btn-wipe, QPushButton.btn-danger {{
            background-color: {pal.get('danger_col', '#DC2626')};
            color: #FFFFFF;
            font-weight: 700;
            border: 1px solid {pal.get('danger_hover', '#B91C1C')};
            border-radius: 8px;
            min-height: 36px;
            padding: 8px 22px;
        }}
        QPushButton#btn-danger:hover, QPushButton#btn-shred:hover, QPushButton#btn-delete:hover, QPushButton#btn-wipe:hover, QPushButton.btn-danger:hover {{
            background-color: {pal.get('danger_hover', '#B91C1C')};
            border-color: {pal.get('danger_hover', '#B91C1C')};
            color: #FFFFFF;
        }}
        QPushButton#btn-secondary, QPushButton#btn-cancel, QPushButton.btn-secondary, QPushButton.btn-cancel {{
            background-color: {pal['btn_bg']};
            color: {pal['btn_text']};
            font-weight: 600;
            border: 1px solid {pal['btn_border']};
            border-radius: 8px;
            min-height: 28px;
            padding: 7px 18px;
        }}
        QPushButton#btn-secondary:hover, QPushButton#btn-cancel:hover, QPushButton.btn-secondary:hover, QPushButton.btn-cancel:hover {{
            background-color: {pal['btn_hover']};
            border-color: {pal['card_border']};
            color: {pal['text_col']};
        }}
        QLineEdit, QSpinBox {{
            background-color: {pal['inp_bg']};
            color: {pal['text_col']};
            font-family: {font_stack};
            font-size: 12px;
            font-weight: 500;
            border: 1px solid {pal.get('inp_border', pal['border_col'])};
            border-radius: 8px;
            padding: 7px 12px;
            min-height: 28px;
            selection-background-color: {pal['accent_col']};
            selection-color: #FFFFFF;
        }}
        QLineEdit:focus, QSpinBox:focus {{
            border: 1.5px solid {pal['accent_col']};
        }}
        QComboBox {{
            background-color: {pal['inp_bg']};
            color: {pal['text_col']};
            font-family: {font_stack};
            font-size: 12px;
            font-weight: 600;
            border: 1px solid {pal.get('inp_border', pal['border_col'])};
            border-radius: 8px;
            padding: 6px 12px;
            min-height: 28px;
        }}
        QComboBox:focus {{
            border: 1.5px solid {pal['accent_col']};
        }}
        QComboBox::drop-down {{
            border: none;
            width: 24px;
        }}
        QComboBox QAbstractItemView {{
            background-color: {pal['card_bg']};
            color: {pal['text_col']};
            border: 1px solid {pal['border_col']};
            border-radius: 8px;
            padding: 4px;
            selection-background-color: {pal['accent_col']};
            selection-color: #FFFFFF;
            font-size: 12px;
        }}
        QCheckBox {{
            color: {pal['text_col']};
            font-family: {font_stack};
            font-size: 12px;
            font-weight: 500;
            spacing: 8px;
        }}
        QCheckBox::indicator {{
            width: 16px;
            height: 16px;
            border-radius: 4px;
            border: 1px solid {pal.get('inp_border', pal['border_col'])};
            background-color: {pal['inp_bg']};
        }}
        QCheckBox::indicator:hover {{
            border-color: {pal['accent_col']};
        }}
        QCheckBox::indicator:checked {{
            background-color: {pal['accent_col']};
            border-color: {pal['accent_col']};
        }}
        QTableWidget, QTreeWidget, QListWidget {{
            background-color: {pal['table_bg']};
            color: {pal['text_col']};
            border: 1px solid {pal['border_col']};
            border-radius: 10px;
            gridline-color: transparent;
            outline: none;
            font-size: 11.5px;
        }}
        QTableWidget::item, QTreeWidget::item, QListWidget::item {{
            padding: 6px 10px;
            border-radius: 4px;
        }}
        QTableWidget::item:hover, QTreeWidget::item:hover, QListWidget::item:hover {{
            background-color: {pal['btn_hover']};
        }}
        QTableWidget::item:selected, QTreeWidget::item:selected, QListWidget::item:selected {{
            background-color: {pal['accent_col']};
            color: #FFFFFF;
        }}
        QHeaderView::section {{
            background-color: {pal['table_header']};
            color: {pal['text_muted']};
            font-family: {font_stack};
            font-weight: 700;
            font-size: 11px;
            padding: 7px 12px;
            border: none;
            border-bottom: 1px solid {pal['border_col']};
        }}
        QScrollBar:vertical {{
            background: transparent;
            width: 6px;
            border-radius: 3px;
            margin: 2px;
        }}
        QScrollBar::handle:vertical {{
            background-color: {pal['btn_hover']};
            min-height: 24px;
            border-radius: 3px;
        }}
        QScrollBar::handle:vertical:hover {{
            background-color: {pal['accent_col']};
        }}
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
            height: 0px;
        }}
        QGroupBox {{
            background-color: {pal['card_bg']};
            border: 1px solid {pal['border_col']};
            border-radius: 12px;
            margin-top: 14px;
            padding-top: 14px;
            font-weight: 700;
            font-size: 12px;
            color: {pal['text_col']};
        }}
        QGroupBox::title {{
            subcontrol-origin: margin;
            subcontrol-position: top left;
            left: 14px;
            padding: 0 6px;
            color: {pal['accent_col']};
        }}
        QFrame#card, QFrame.card {{
            background-color: {pal['card_bg']};
            border: 1px solid {pal['border_col']};
            border-radius: 14px;
        }}
    """

class BitLockerRecoveryDialog(QDialog):
    """48 haneli BitLocker kurtarma parolasını gösterir ve dışa aktarır."""
    def __init__(self, parent=None, recovery_key: str = "", drive_letter: str = "", theme: str = "dark", vault_name: str = "", vault_path: str = ""):
        super().__init__(parent)
        self.recovery_key = recovery_key
        self.drive_letter = drive_letter
        self.theme = theme
        self.vault_name = vault_name or (Path(vault_path).name if vault_path else "")
        self.vault_path = vault_path
        self.vault_hash = ""

        if self.vault_path and Path(self.vault_path).is_file():
            try:
                from engine import VHDEngine
                h_res = VHDEngine.calculate_file_hash(self.vault_path)
                if h_res.get("success"):
                    self.vault_hash = h_res.get("sha256", "")
            except Exception:
                pass

        disp_title = self.vault_name or self.drive_letter or "Sanal Kasa"
        self.setWindowTitle(f"BitLocker Kurtarma Anahtarı — {disp_title}")
        apply_dynamic_geometry(self, default_w=540, default_h=320, min_w=480, min_h=260)
        self.setSizeGripEnabled(True)
        self.setModal(True)
        self.init_ui()

    def init_ui(self):
        pal = get_dialog_palette(self.theme)
        is_dark = pal["is_dark"]
        bg_col = pal["bg_col"]
        text_col = pal["text_col"]
        card_bg = pal["card_bg"]
        key_col = pal["key_col"]
        border_col = pal["border_col"]
        set_dialog_dark_mode(self, is_dark)

        self.setStyleSheet(f"""
            QDialog {{
                background-color: {bg_col};
                color: {text_col};
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
            }}
            {get_dialog_button_stylesheet(self.theme)}
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)

        disp_title = self.vault_name or self.drive_letter
        title = QLabel(f"BİTLOCKER KURTARMA ANAHTARI ({disp_title})")
        title.setStyleSheet(f"font-size: 15px; font-weight: 800; color: {accent_col if 'accent_col' in locals() else pal['accent_col']}; letter-spacing: 0.5px;")
        layout.addWidget(title)

        desc = QLabel(
            "Bu 48 haneli sayısal anahtar, parolanızı unutmanız durumunda verilerinizi kurtarmanın "
            "tek yoludur. Lütfen güvenli bir yere kaydedin veya yazdırın."
        )
        desc.setWordWrap(True)
        desc.setStyleSheet(f"font-size: 13px; color: {text_muted if 'text_muted' in locals() else pal['text_muted']};")
        layout.addWidget(desc)

        if self.vault_hash:
            hash_lbl = QLabel(f"<b>Kasa SHA-256:</b> <span style='font-family: monospace; color: {'#38BDF8' if is_dark else '#0C5478'};'>{self.vault_hash}</span>")
            hash_lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            hash_lbl.setStyleSheet(f"font-size: 10px; color: {'#94A3B8' if is_dark else '#4B5E45'};")
            layout.addWidget(hash_lbl)

        key_frame = QFrame()
        key_frame.setStyleSheet(f"""
            background-color: {card_bg};
            border: 1px solid {border_col};
            border-radius: 12px;
            padding: 12px;
        """)
        key_layout = QVBoxLayout(key_frame)
        self.lbl_key = QLabel(self.recovery_key or "Kurtarma anahtarı bulunamadı.")
        self.lbl_key.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.lbl_key.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.lbl_key.setStyleSheet(f"""
            font-family: 'JetBrains Mono', 'Cascadia Code', monospace;
            font-size: 14px;
            font-weight: 700;
            color: {key_col};
            letter-spacing: 1px;
        """)
        key_layout.addWidget(self.lbl_key)
        layout.addWidget(key_frame)

        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(10)

        btn_copy = QPushButton("Panoya Kopyala")
        btn_copy.clicked.connect(self.copy_to_clipboard)
        btn_layout.addWidget(btn_copy)

        btn_save = QPushButton("Metin Olarak Kaydet (.txt)")
        btn_save.clicked.connect(self.save_to_txt)
        btn_layout.addWidget(btn_save)

        btn_layout.addStretch()

        btn_close = QPushButton("Kapat")
        btn_close.clicked.connect(self.accept)
        btn_layout.addWidget(btn_close)

        layout.addLayout(btn_layout)

    def copy_to_clipboard(self):
        from PyQt6.QtWidgets import QApplication
        from PyQt6.QtCore import QMimeData, QTimer
        import ctypes
        import sys
        clipboard = QApplication.clipboard()
        if clipboard:
            mime = QMimeData()
            mime.setText(self.recovery_key)
            mime.setData("ExcludeClipboardContentFromMonitorProcessing", b"")
            mime.setData("CanIncludeInClipboardHistory", b"\x00")
            mime.setData("CanUploadToCloudClipboard", b"\x00")
            clipboard.setMimeData(mime)

            if sys.platform == "win32":
                try:
                    user32 = ctypes.windll.user32
                    if user32.OpenClipboard(0):
                        try:
                            cf_exclude = user32.RegisterClipboardFormatW("ExcludeClipboardContentFromMonitorProcessing")
                            if cf_exclude:
                                user32.SetClipboardData(cf_exclude, 0)
                            cf_history = user32.RegisterClipboardFormatW("CanIncludeInClipboardHistory")
                            if cf_history:
                                user32.SetClipboardData(cf_history, 0)
                            cf_cloud = user32.RegisterClipboardFormatW("CanUploadToCloudClipboard")
                            if cf_cloud:
                                user32.SetClipboardData(cf_cloud, 0)
                        finally:
                            user32.CloseClipboard()
                except Exception:
                    pass

            copied_key = self.recovery_key
            def _clear_cb():
                try:
                    cb = QApplication.clipboard()
                    if cb and cb.text() == copied_key:
                        cb.clear()
                except Exception:
                    pass

            QTimer.singleShot(30000, _clear_cb)
            QMessageBox.information(
                self,
                "Bilgi",
                "Kurtarma anahtarı panoya kopyalandı.\n\n"
                "Güvenlik amacıyla pano içeriği 30 saniye sonra otomatik olarak temizlenecektir."
            )

    def save_to_txt(self):
        import re
        base_name = self.vault_name or (Path(self.vault_path).name if self.vault_path else self.drive_letter.rstrip(':'))
        safe_name = re.sub(r'[\\/*?:"<>| ]', '_', base_name.strip())
        default_filename = f"BitLocker_Kurtarma_Anahtari_{safe_name}.txt"

        path, _ = QFileDialog.getSaveFileName(
            self,
            "Kurtarma Anahtarını Kaydet",
            default_filename,
            "Metin Dosyası (*.txt)"
        )
        if path:
            try:
                vault_disp = self.vault_name or (Path(self.vault_path).name if self.vault_path else "Bilinmiyor")
                content = (
                    "================================================================================\n"
                    "               ENCLAVE - BİTLOCKER KURTARMA ANAHTARI SERTİFİKASI\n"
                    "================================================================================\n\n"
                    f"Kasa Adı            : {vault_disp}\n"
                    f"Kasa Dosya Yolu     : {self.vault_path or 'Bilinmiyor'}\n"
                    f"Kasa SHA-256 Hash   : {self.vault_hash or '(Hesaplanamadı veya dosya kilitli)'}\n"
                    f"Sürücü Harfi        : {self.drive_letter}\n"
                    f"Oluşturulma Tarihi  : {import_time_str()}\n\n"
                    "--------------------------------------------------------------------------------\n"
                    "BİTLOCKER KURTARMA ANAHTARI:\n"
                    f"{self.recovery_key}\n"
                    "--------------------------------------------------------------------------------\n\n"
                    "GÜVENLİK VE KURTARMA TALİMATI:\n"
                    "1. Bu 48 haneli sayısal kurtarma anahtarı, parolanızı unutmanız durumunda\n"
                    "   verilerinize erişebilmeniz için TEK yoldur.\n"
                    "2. Bu dosyayı kasanın içinde veya şifresiz kolay erişilebilir yerlerde bırakmayınız.\n"
                    "3. Çevrimdışı güvenli bir USB sürücüde veya fiziksel bir çıktı olarak saklayınız.\n"
                    "================================================================================\n"
                )
                Path(path).write_text(content, encoding="utf-8")
                QMessageBox.information(self, "Başarılı", "Kurtarma anahtarı dosyaya kaydedildi.")
            except Exception as e:
                QMessageBox.warning(self, "Hata", f"Dosya kaydedilemedi: {e}")

class BitLockerPasswordDialog(QDialog):
    """
    Kasaya sonradan BitLocker şifresi ekleme, mevcut şifreyi değiştirme
    veya şifrelemeyi kaldırma işlemlerini modern bir arayüzde yönetir.
    """
    def __init__(self, parent=None, engine=None, drive_letter: str = "", vault_name: str = "", theme: str = "dark", reset_mode: bool = False, vault_path: str = ""):
        super().__init__(parent)
        self.engine = engine
        self.drive_letter = (drive_letter or "").rstrip("\\/ ")
        self.vault_name = vault_name or "Sanal Kasa"
        self.theme = theme
        self.reset_mode = reset_mode
        self.vault_path = vault_path or (getattr(self.engine, "active_vault_file", "") if self.engine else "")
        self.setWindowTitle(
            f"BitLocker Parola Sıfırlama — {self.vault_name}" if reset_mode
            else f"BitLocker Parola Yönetimi — {self.vault_name}"
        )
        apply_dynamic_geometry(self, default_w=480, default_h=340 if not reset_mode else 380, min_w=420, min_h=260 if not reset_mode else 300)
        self.setSizeGripEnabled(True)
        self.setModal(True)

        self.bitlocker_status = {}
        if self.engine and self.drive_letter:
            try:
                self.bitlocker_status = self.engine.get_bitlocker_status(self.drive_letter)
            except Exception:
                self.bitlocker_status = {}

        self.init_ui()

    def init_ui(self):
        pal = get_dialog_palette(self.theme)
        is_dark = pal["is_dark"]
        bg_col = pal["bg_col"]
        text_col = pal["text_col"]
        card_bg = pal["card_bg"]
        inp_bg = pal["inp_bg"]
        border_col = pal["border_col"]
        accent_col = pal["accent_col"]
        is_encrypted = self.bitlocker_status.get("is_encrypted", False)
        set_dialog_dark_mode(self, is_dark)

        self.setStyleSheet(f"""
            QDialog {{
                background-color: {bg_col};
                color: {text_col};
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
            }}
            QLabel {{
                color: {text_col};
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
            }}
            QLineEdit {{
                background-color: {inp_bg};
                color: {text_col};
                border: 1px solid {border_col};
                border-radius: 8px;
                padding: 7px 12px;
                font-size: 11.5px;
                min-height: 24px;
            }}
            QLineEdit:focus {{
                border-color: {accent_col};
            }}
            {get_dialog_button_stylesheet(self.theme)}
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 20, 22, 20)
        layout.setSpacing(12)

        if self.reset_mode:
            title_txt = "BİTLOCKER PAROLA SIFIRLAMA (YENİ PAROLA BELİRLE)"
        elif is_encrypted:
            title_txt = "BİTLOCKER PAROLA YÖNETİMİ & ŞİFRE DEĞİŞTİRME"
        else:
            title_txt = "KASAYA BİTLOCKER ŞİFRESİ EKLE"
        title = QLabel(title_txt)
        title.setStyleSheet(f"font-size: 15px; font-weight: 800; color: {accent_col if 'accent_col' in locals() else pal['accent_col']}; letter-spacing: 0.5px;")
        layout.addWidget(title)

        status_frame = QFrame()
        status_frame.setStyleSheet(f"""
            background-color: {card_bg};
            border: 1px solid {border_col};
            border-radius: 12px;
            padding: 10px 14px;
        """)
        sf_layout = QVBoxLayout(status_frame)
        sf_layout.setSpacing(4)
        sf_layout.setContentsMargins(0, 0, 0, 0)

        if is_encrypted:
            badge_txt = "● KORUMA DURUMU: ŞİFRELİ (BitLocker Aktif)"
            badge_col = "#10B981" if is_dark else "#0B6623"
            sub_txt = f"Sürücü: {self.drive_letter}  |  Kasa: {self.vault_name}  |  Algoritma: XTS-AES 256"
        else:
            badge_txt = "○ KORUMA DURUMU: ŞİFRESİZ DİSK (BitLocker Yok)"
            badge_col = pal["accent_col"]
            sub_txt = f"Sürücü: {self.drive_letter}  |  Kasa: {self.vault_name}  |  Disk şu an şifresizdir."

        lbl_badge = QLabel(badge_txt)
        lbl_badge.setStyleSheet(f"font-size: 11.5px; font-weight: 800; color: {badge_col};")
        sf_layout.addWidget(lbl_badge)

        lbl_sub = QLabel(sub_txt)
        lbl_sub.setStyleSheet(f"font-size: 12.5px; color: {text_muted if 'text_muted' in locals() else pal['text_muted']};")
        sf_layout.addWidget(lbl_sub)
        layout.addWidget(status_frame)

        if self.reset_mode:
            desc = QLabel("Kasanız kurtarma anahtarı ile açıldı. Eski parolanızı bilmenize gerek yoktur. Aşağıdan yeni bir BitLocker parolası belirleyerek unutulan eski parolayı sıfırlayabilirsiniz.")
        elif is_encrypted:
            desc = QLabel("Mevcut BitLocker parolanızı yenisiyle güvenle değiştirebilir veya kasanın şifrelemesini kaldırabilirsiniz.")
        else:
            desc = QLabel("Bu kasa şifresiz oluşturulmuş. Aşağıdan bir parola belirleyerek diski BitLocker ile tam şifreli hale getirebilirsiniz.")
        desc.setWordWrap(True)
        desc.setStyleSheet(f"font-size: 13px; color: {text_muted if 'text_muted' in locals() else pal['text_muted']};")
        layout.addWidget(desc)

        if is_encrypted and not self.reset_mode:
            lbl_p0 = QLabel("Mevcut (Eski) BitLocker Parolası:")
            lbl_p0.setStyleSheet("font-weight: 700; font-size: 11px;")
            layout.addWidget(lbl_p0)

            self.txt_old_pw = QLineEdit()
            self.txt_old_pw.setEchoMode(QLineEdit.EchoMode.Password)
            self.txt_old_pw.setPlaceholderText("Kasanın şu anki mevcut parolasını girin...")
            layout.addWidget(self.txt_old_pw)

        lbl_p1 = QLabel("Yeni BitLocker Parolası (En az 8 karakter):" if (is_encrypted or self.reset_mode) else "BitLocker Parolası (En az 8 karakter):")
        lbl_p1.setStyleSheet("font-weight: 700; font-size: 11px;")
        layout.addWidget(lbl_p1)

        self.txt_new_pw = QLineEdit()
        self.txt_new_pw.setEchoMode(QLineEdit.EchoMode.Password)
        self.txt_new_pw.setPlaceholderText("Yeni parolayı yazın...")
        layout.addWidget(self.txt_new_pw)

        lbl_p2 = QLabel("Yeni Parolayı Tekrar Girin:" if (is_encrypted or self.reset_mode) else "Parolayı Tekrar Girin:")
        lbl_p2.setStyleSheet("font-weight: 700; font-size: 11px;")
        layout.addWidget(lbl_p2)

        self.txt_confirm_pw = QLineEdit()
        self.txt_confirm_pw.setEchoMode(QLineEdit.EchoMode.Password)
        self.txt_confirm_pw.setPlaceholderText("Yeni parolayı doğrulayın...")
        layout.addWidget(self.txt_confirm_pw)

        self.chk_show_pw = QCheckBox("Parolaları Göster")
        self.chk_show_pw.stateChanged.connect(self.toggle_show_passwords)
        layout.addWidget(self.chk_show_pw)

        self.lbl_error = QLabel("")
        self.lbl_error.setStyleSheet("color: #EF4444; font-size: 11px; font-weight: 700;")
        self.lbl_error.hide()
        layout.addWidget(self.lbl_error)

        btn_container = QVBoxLayout()
        btn_container.setSpacing(10)

        if is_encrypted or self.reset_mode:
            row_actions = QHBoxLayout()
            row_actions.setSpacing(10)
            btn_txt = "Parolayı Sıfırla ve Kaydet" if self.reset_mode else "Parolayı Güncelle"
            self.btn_submit = QPushButton(btn_txt)
            self.btn_submit.setObjectName("btn-accent")
            self.btn_submit.clicked.connect(self.do_change_password)
            row_actions.addWidget(self.btn_submit)

            btn_show_rec = QPushButton("Kurtarma Anahtarı")
            btn_show_rec.clicked.connect(self.do_show_recovery)
            row_actions.addWidget(btn_show_rec)
            row_actions.addStretch()
            btn_container.addLayout(row_actions)

            row_sub = QHBoxLayout()
            row_sub.setSpacing(10)
            if not self.reset_mode:
                btn_remove = QPushButton("Şifrelemeyi Kaldır")
                btn_remove.setObjectName("btn-danger")
                btn_remove.clicked.connect(self.do_remove_encryption)
                row_sub.addWidget(btn_remove)
            row_sub.addStretch()

            btn_cancel = QPushButton("İptal" if self.reset_mode else "Kapat")
            btn_cancel.clicked.connect(self.reject)
            row_sub.addWidget(btn_cancel)
            btn_container.addLayout(row_sub)
        else:
            row_enc = QHBoxLayout()
            row_enc.setSpacing(10)
            self.btn_submit = QPushButton("Kasayı Şifrele ve Koru")
            self.btn_submit.setObjectName("btn-accent")
            self.btn_submit.clicked.connect(self.do_enable_encryption)
            row_enc.addWidget(self.btn_submit)
            row_enc.addStretch()

            btn_cancel = QPushButton("İptal")
            btn_cancel.clicked.connect(self.reject)
            row_enc.addWidget(btn_cancel)
            btn_container.addLayout(row_enc)

        layout.addLayout(btn_container)

    def toggle_show_passwords(self, state):
        mode = QLineEdit.EchoMode.Normal if self.chk_show_pw.isChecked() else QLineEdit.EchoMode.Password
        if hasattr(self, "txt_old_pw"):
            self.txt_old_pw.setEchoMode(mode)
        self.txt_new_pw.setEchoMode(mode)
        self.txt_confirm_pw.setEchoMode(mode)

    def validate_inputs(self) -> Optional[str]:
        is_encrypted = self.bitlocker_status.get("is_encrypted", False)
        
        if is_encrypted and not self.reset_mode and hasattr(self, "txt_old_pw"):
            old_pw = self.txt_old_pw.text()
            if not old_pw:
                return "Lütfen kasanın mevcut (eski) parolasını girin."

        p1 = self.txt_new_pw.text()
        p2 = self.txt_confirm_pw.text()
        if not p1:
            return "Lütfen yeni bir parola girin.\n(Şifreyi tamamen kaldırmak için 'Şifrelemeyi Kaldır' butonunu kullanabilirsiniz.)" if not self.reset_mode else "Lütfen yeni bir parola girin."
        if len(p1) < 8:
            return "Yeni BitLocker parolası en az 8 karakter uzunluğunda olmalıdır."
        if p1 != p2:
            return "Yeni parolalar birbiriyle eşleşmiyor. Lütfen kontrol edin."

        if is_encrypted and not self.reset_mode and hasattr(self, "txt_old_pw"):
            old_pw = self.txt_old_pw.text()
            if p1 == old_pw:
                return "Yeni parola, eski parola ile aynı olamaz. Lütfen farklı ve güvenli bir parola belirleyin."

        return None

    def do_enable_encryption(self):
        err = self.validate_inputs()
        if err:
            self.lbl_error.setText(err)
            self.lbl_error.show()
            return

        pw = self.txt_new_pw.text()
        self.btn_submit.setEnabled(False)
        self.btn_submit.setText("Şifreleniyor...")
        self.lbl_error.hide()
        QApplication.processEvents()

        try:
            res = self.engine.enable_bitlocker(self.drive_letter, pw)
            if res.get("success"):
                audit_logger.log_security_event("VAULT_ENCRYPTED", "SUCCESS", f"Kasaya BitLocker şifrelemesi eklendi ({self.drive_letter})", self.vault_name, self.drive_letter)
                rec_key = res.get("recovery_key", "")
                if not rec_key:
                    try:
                        rk_res = self.engine.get_bitlocker_recovery_key(self.drive_letter)
                        if rk_res.get("success"):
                            rec_key = rk_res.get("recovery_key", "")
                    except Exception:
                        pass

                QMessageBox.information(
                    self,
                    "Başarılı",
                    f"Kasa başarıyla BitLocker ile şifrelendi!\nSürücü: {self.drive_letter}\n\n"
                    "Lütfen açılacak ekrandaki 48 haneli kurtarma anahtarını güvenli bir yere kaydedin."
                )
                try:
                    dlg = BitLockerRecoveryDialog(self, recovery_key=rec_key, drive_letter=self.drive_letter, theme=self.theme, vault_name=self.vault_name, vault_path=self.vault_path)
                    dlg.exec()
                except Exception as e:
                    print(f"Kurtarma penceresi açma hatası: {e}")
                self.accept()
            else:
                err_msg = res.get("error", "Şifreleme başarısız oldu.")
                self.lbl_error.setText(err_msg)
                self.lbl_error.show()
                QMessageBox.critical(self, "Şifreleme Başarısız", f"Kasaya BitLocker şifresi eklenemedi:\n\n{err_msg}")
        except Exception as e:
            self.lbl_error.setText(f"İşlem hatası: {e}")
            self.lbl_error.show()
            QMessageBox.critical(self, "Hata", f"İşlem hatası: {e}")
        finally:
            self.btn_submit.setEnabled(True)
            self.btn_submit.setText("Kasayı Şifrele ve Koru")

    def do_change_password(self):
        err = self.validate_inputs()
        if err:
            self.lbl_error.setText(err)
            self.lbl_error.show()
            return

        old_pw = self.txt_old_pw.text() if (hasattr(self, "txt_old_pw") and not self.reset_mode) else ""
        new_pw = self.txt_new_pw.text()

        self.btn_submit.setEnabled(False)
        self.btn_submit.setText("Sıfırlanıyor..." if self.reset_mode else "Güncelleniyor...")
        self.lbl_error.hide()
        QApplication.processEvents()

        try:
            parent = self.parent()
            known_pw = getattr(parent, "last_unlocked_password", "") if parent else ""

            if not self.reset_mode and old_pw and known_pw:
                if old_pw != known_pw:
                    self.lbl_error.setText("Mevcut (eski) parolanız hatalı! Lütfen kontrol edin.")
                    self.lbl_error.show()
                    QMessageBox.warning(self, "Hatalı Parola", "Girdiğiniz mevcut (eski) parola hatalı. Lütfen kontrol edip tekrar deneyin.")
                    return

            if not self.reset_mode and old_pw and old_pw == new_pw:
                self.lbl_error.setText("Yeni parola, mevcut (eski) parola ile aynı olamaz. Lütfen farklı bir parola belirleyin.")
                self.lbl_error.show()
                QMessageBox.warning(self, "Parola Değiştirilemedi", "Yeni parola, mevcut (eski) parola ile aynı olamaz. Lütfen farklı ve güvenli bir parola belirleyin.")
                return

            res = self.engine.change_bitlocker_password(self.drive_letter, new_pw, old_password=(old_pw if not self.reset_mode else None))
            if res.get("success"):
                audit_logger.log_security_event(
                    "VAULT_PASSWORD_RESET" if self.reset_mode else "VAULT_PASSWORD_CHANGED",
                    "SUCCESS",
                    f"BitLocker parolası sıfırlandı/güncellendi ({self.drive_letter})",
                    self.vault_name,
                    self.drive_letter
                )
                if parent:
                    if hasattr(parent, "last_unlocked_password"):
                        parent.last_unlocked_password = new_pw
                    if hasattr(parent, "txt_password") and parent.txt_password:
                        parent.txt_password.clear()
                    if hasattr(parent, "poll_volume_status"):
                        parent.poll_volume_status()
                    if hasattr(parent, "refresh_vault_list"):
                        parent.refresh_vault_list()
                
                msg_txt = "BitLocker parolası başarıyla sıfırlandı ve yeni parolanız kaydedildi!" if self.reset_mode else "BitLocker parolası başarıyla değiştirildi!"
                QMessageBox.information(
                    self,
                    "Başarılı",
                    f"{msg_txt}\nSürücü: {self.drive_letter}"
                )
                self.accept()
            else:
                err_msg = res.get("error", "Parola değiştirilemedi.")
                self.lbl_error.setText(err_msg)
                self.lbl_error.show()
                QMessageBox.critical(self, "Parola Değiştirilemedi", f"BitLocker parolası güncellenemedi:\n\n{err_msg}")
        except Exception as e:
            self.lbl_error.setText(f"İşlem hatası: {e}")
            self.lbl_error.show()
            QMessageBox.critical(self, "Hata", f"İşlem hatası: {e}")
        finally:
            self.btn_submit.setEnabled(True)
            self.btn_submit.setText("Parolayı Sıfırla ve Kaydet" if self.reset_mode else "Parolayı Güncelle")

    def do_remove_encryption(self):
        reply = QMessageBox.question(
            self,
            "Şifrelemeyi Kaldır Onayı",
            f"DİKKAT: '{self.vault_name}' kasasındaki tüm BitLocker şifrelemesi kaldırılacak ve disk tamamen şifresiz hale getirilecektir.\n\n"
            "Bu işlemi onaylıyor musunuz?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        if hasattr(self, "btn_submit"):
            self.btn_submit.setEnabled(False)
        self.lbl_error.hide()
        QApplication.processEvents()

        try:
            res = self.engine.disable_bitlocker(self.drive_letter)
            if res.get("success"):
                audit_logger.log_security_event("VAULT_DECRYPTED", "WARNING", f"Kasadan BitLocker şifrelemesi kaldırıldı ({self.drive_letter})", self.vault_name, self.drive_letter)
                parent = self.parent()
                if parent:
                    parent.is_locked = False
                    if hasattr(parent, "txt_password") and parent.txt_password:
                        parent.txt_password.clear()
                    if hasattr(parent, "unlock_card"):
                        parent.unlock_card.hide()
                    if hasattr(parent, "lbl_unlock_error"):
                        parent.lbl_unlock_error.hide()
                    if hasattr(parent, "poll_volume_status"):
                        parent.poll_volume_status()
                    if hasattr(parent, "refresh_vault_list"):
                        parent.refresh_vault_list()

                QMessageBox.information(
                    self,
                    "Başarılı",
                    f"BitLocker şifrelemesi başarıyla kaldırıldı.\nSürücü: {self.drive_letter}\nKasa artık tamamen şifresizdir ve doğrudan açılabilir."
                )
                self.accept()
            else:
                err_msg = res.get("error", "Şifreleme devre dışı bırakılamadı.")
                self.lbl_error.setText(err_msg)
                self.lbl_error.show()
                QMessageBox.warning(self, "Hata", f"Şifreleme kaldırılamadı:\n\n{err_msg}")
        except Exception as e:
            self.lbl_error.setText(f"Beklenmedik hata: {e}")
            self.lbl_error.show()
            QMessageBox.critical(self, "Hata", f"Beklenmedik hata: {e}")
        finally:
            if hasattr(self, "btn_submit"):
                self.btn_submit.setEnabled(True)

    def do_show_recovery(self):
        try:
            res = self.engine.get_bitlocker_recovery_key(self.drive_letter)
            if res.get("success"):
                dlg = BitLockerRecoveryDialog(self, recovery_key=res.get("recovery_key", ""), drive_letter=self.drive_letter, theme=self.theme, vault_name=self.vault_name, vault_path=self.vault_path)
                dlg.exec()
            else:
                QMessageBox.warning(self, "Hata", f"Kurtarma anahtarı alınamadı:\n{res.get('error')}")
        except Exception as e:
            QMessageBox.warning(self, "Hata", f"Hata: {e}")

class BitLockerUnlockRecoveryDialog(QDialog):
    """
    BitLocker parolasını unutan kullanıcıların kasayı 48 haneli kurtarma anahtarı ile açmasını sağlar.
    """
    def __init__(self, parent=None, engine=None, drive_letter: str = "", theme: str = "dark"):
        super().__init__(parent)
        self.engine = engine
        self.drive_letter = (drive_letter or "").rstrip("\\/ ")
        self.theme = theme
        self.setWindowTitle(f"Kurtarma Anahtarı ile Kilit Aç — {self.drive_letter}")
        apply_dynamic_geometry(self, default_w=460, default_h=240, min_w=400, min_h=200)
        self.setSizeGripEnabled(True)
        self.setModal(True)
        self.init_ui()

    def init_ui(self):
        pal = get_dialog_palette(self.theme)
        is_dark = pal["is_dark"]
        bg_col = pal["bg_col"]
        text_col = pal["text_col"]
        inp_bg = pal["inp_bg"]
        border_col = pal["border_col"]
        accent_col = pal["accent_col"]
        key_col = pal["key_col"]
        set_dialog_dark_mode(self, is_dark)

        self.setStyleSheet(f"""
            QDialog {{
                background-color: {bg_col};
                color: {text_col};
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
            }}
            QLabel {{
                color: {text_col};
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
            }}
            QLineEdit {{
                background-color: {inp_bg};
                color: {key_col};
                border: 1px solid {border_col};
                border-radius: 8px;
                padding: 7px 12px;
                font-family: 'JetBrains Mono', 'Cascadia Code', monospace;
                font-size: 12px;
                font-weight: 700;
                letter-spacing: 0.5px;
                min-height: 24px;
            }}
            QLineEdit:focus {{
                border-color: {accent_col};
            }}
            {get_dialog_button_stylesheet(self.theme)}
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 20, 22, 20)
        layout.setSpacing(12)

        title = QLabel(f"BİTLOCKER KURTARMA ANAHTARI İLE AÇ ({self.drive_letter})")
        title.setStyleSheet(f"font-size: 15px; font-weight: 800; color: {accent_col if 'accent_col' in locals() else pal['accent_col']};")
        layout.addWidget(title)

        desc = QLabel(
            "Parolanızı unuttuysanız, kasa oluşturulurken verilen 48 haneli sayısal kurtarma anahtarını "
            "girerek kasanın kilidini açabilirsiniz."
        )
        desc.setWordWrap(True)
        desc.setStyleSheet(f"font-size: 13px; color: {text_muted if 'text_muted' in locals() else pal['text_muted']};")
        layout.addWidget(desc)

        layout.addWidget(QLabel("48 Haneli Kurtarma Anahtarı:"))
        input_box = QHBoxLayout()
        input_box.setSpacing(8)

        self.txt_key = QLineEdit()
        self.txt_key.setPlaceholderText("123456-123456-123456-123456-123456-123456-123456-123456")
        input_box.addWidget(self.txt_key)

        btn_paste = QPushButton("Yapıştır")
        btn_paste.clicked.connect(self.paste_from_clipboard)
        input_box.addWidget(btn_paste)
        layout.addLayout(input_box)

        self.lbl_error = QLabel("")
        self.lbl_error.setStyleSheet("color: #EF4444; font-size: 11px; font-weight: 700;")
        self.lbl_error.hide()
        layout.addWidget(self.lbl_error)

        btn_box = QHBoxLayout()
        btn_box.setSpacing(10)
        btn_box.addStretch()

        btn_cancel = QPushButton("İptal")
        btn_cancel.clicked.connect(self.reject)
        btn_box.addWidget(btn_cancel)

        self.btn_unlock = QPushButton("Kilidi Kurtarma Anahtarı ile Aç")
        self.btn_unlock.setObjectName("btn-accent")
        self.btn_unlock.clicked.connect(self.do_unlock)
        btn_box.addWidget(self.btn_unlock)

        layout.addLayout(btn_box)

    def paste_from_clipboard(self):
        clipboard = QApplication.clipboard()
        if clipboard:
            text = clipboard.text().strip()
            if text:
                self.txt_key.setText(text)

    def do_unlock(self):
        key = self.txt_key.text().strip()
        if not key:
            self.lbl_error.setText("Lütfen kurtarma anahtarını girin.")
            self.lbl_error.show()
            return

        self.btn_unlock.setEnabled(False)
        self.btn_unlock.setText("Kilit Açılıyor...")
        self.lbl_error.hide()
        QApplication.processEvents()

        try:
            res = self.engine.unlock_bitlocker_recovery_key(self.drive_letter, key)
            if res.get("success"):
                audit_logger.log_security_event("RECOVERY_KEY_UNLOCK", "SUCCESS", f"Kasa kurtarma anahtarı ile açıldı ({self.drive_letter})", drive_letter=self.drive_letter)
                parent = self.parent()
                if parent and hasattr(parent, "poll_volume_status"):
                    parent.poll_volume_status()
                self.accept()
                reply = QMessageBox.question(
                    parent or self,
                    "Yeni Parola Belirleme",
                    f"'{self.drive_letter}' sürücüsünün kilidi kurtarma anahtarı ile başarıyla açıldı!\n\n"
                    "Unutulan eski parolanızı sıfırlayıp şimdi yeni bir BitLocker parolası belirlemek ister misiniz?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.Yes
                )
                if reply == QMessageBox.StandardButton.Yes and parent and hasattr(parent, "on_manage_bitlocker_password"):
                    parent.on_manage_bitlocker_password(reset_mode=True)
            else:
                self.lbl_error.setText(res.get("error", "Kilit açılamadı."))
                self.lbl_error.show()
        except Exception as e:
            self.lbl_error.setText(f"İşlem hatası: {e}")
            self.lbl_error.show()
        finally:
            self.btn_unlock.setEnabled(True)
            self.btn_unlock.setText("Kilidi Kurtarma Anahtarı ile Aç")

class RecoveryKeyVerifyWorker(QThread):
    finished_signal = pyqtSignal(dict)

    def __init__(self, engine, drive_letter: str, vault_file: str, key_text: str):
        super().__init__()
        self.engine = engine
        self.drive_letter = drive_letter
        self.vault_file = vault_file
        self.key_text = key_text

    def run(self):
        try:
            if self.engine:
                res = self.engine.verify_recovery_key(
                    drive_letter=self.drive_letter,
                    vault_file=self.vault_file,
                    recovery_key=self.key_text
                )
                self.finished_signal.emit(res)
            else:
                self.finished_signal.emit({
                    "success": False,
                    "checksum_valid": False,
                    "matched": False,
                    "error": "Motor başlatılamadı."
                })
        except Exception as e:
            self.finished_signal.emit({
                "success": False,
                "checksum_valid": False,
                "matched": False,
                "error": str(e)
            })

class VaultPasswordRecoveryDialog(QDialog):
    """
    Parolasını veya USB donanım anahtarını kaybeden kullanıcıların kasayı
    48 haneli BitLocker Kurtarma Anahtarı ile açmasını, yeni bir parola tanımlamasını
    ve kayıp USB korumasını kaldırmasını sağlayan kapsamlı kurtarma sihirbazı.
    """
    def __init__(self, parent=None, engine=None, config: dict = None, vault_file: str = "", drive_letter: str = "", theme: str = "dark"):
        super().__init__(parent)
        self.engine = engine
        self.config = config or {}
        self.vault_file = vault_file
        self.drive_letter = (drive_letter or "").rstrip("\\/ ")
        self.theme = theme
        self.setWindowTitle("Kasa ve Parola Kurtarma Sihirbazı")
        apply_dynamic_geometry(self, default_w=520, default_h=440, min_w=460, min_h=360)
        self.setSizeGripEnabled(True)
        self.setModal(True)
        self.is_key_verified = False
        self.verify_worker = None
        self.verify_timer = QTimer(self)
        self.verify_timer.setSingleShot(True)
        self.verify_timer.setInterval(350)
        self.verify_timer.timeout.connect(self._start_key_verification)
        self.init_ui()

    def init_ui(self):
        pal = get_dialog_palette(self.theme)
        is_dark = pal["is_dark"]
        bg_col = pal["bg_col"]
        text_col = pal["text_col"]
        card_bg = pal["card_bg"]
        inp_bg = pal["inp_bg"]
        border_col = pal["border_col"]
        accent_col = pal["accent_col"]
        key_col = pal["key_col"]
        set_dialog_dark_mode(self, is_dark)

        self.setStyleSheet(f"""
            QDialog {{
                background-color: {bg_col};
                color: {text_col};
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
            }}
            QLabel {{
                color: {text_col};
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
            }}
            QLineEdit {{
                background-color: {inp_bg};
                color: {text_col};
                border: 1px solid {border_col};
                border-radius: 8px;
                padding: 7px 12px;
                font-size: 11.5px;
                min-height: 24px;
            }}
            QLineEdit:focus {{
                border-color: {accent_col};
            }}
            {get_dialog_button_stylesheet(self.theme)}
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 20, 22, 20)
        layout.setSpacing(12)

        title = QLabel("KASA VE PAROLA KURTARMA SİHİRBAZI")
        title.setStyleSheet(f"font-size: 15px; font-weight: 800; color: {accent_col if 'accent_col' in locals() else pal['accent_col']}; letter-spacing: 0.5px;")
        layout.addWidget(title)

        v_name = Path(self.vault_file).name if self.vault_file else "Sanal Kasa"
        dl_str = f" ({self.drive_letter})" if self.drive_letter else ""
        desc = QLabel(
            f"'{v_name}'{dl_str} kasasının parolasını unuttuysanız, "
            f"48 haneli resmi BitLocker Kurtarma Anahtarınızı kullanarak kasanıza erişebilir, "
            f"eski parolayı sıfırlayıp yeni bir parola belirleyebilirsiniz."
        )
        desc.setWordWrap(True)
        desc.setStyleSheet(f"font-size: 13px; color: {text_muted if 'text_muted' in locals() else pal['text_muted']};")
        layout.addWidget(desc)

        lbl_k = QLabel("1. 48 Haneli BitLocker Kurtarma Anahtarını Girin:")
        lbl_k.setStyleSheet("font-weight: 700; font-size: 11px;")
        layout.addWidget(lbl_k)

        key_box = QHBoxLayout()
        key_box.setSpacing(8)
        self.txt_key = QLineEdit()
        self.txt_key.setStyleSheet(f"font-family: 'JetBrains Mono', 'Consolas', monospace; font-weight: 700; font-size: 11.5px; color: {pal['accent_col']};")
        self.txt_key.setPlaceholderText("123456-123456-123456-123456-123456-123456-123456-123456")
        self.txt_key.textChanged.connect(self.on_key_text_changed)
        key_box.addWidget(self.txt_key)

        btn_paste = QPushButton("Panodan Yapıştır")
        btn_paste.clicked.connect(self.paste_recovery_key)
        key_box.addWidget(btn_paste)
        layout.addLayout(key_box)

        self.lbl_key_status = QLabel("[BEKLENİYOR] Kurtarma anahtarı bekleniyor... (0/48 hane)")
        self.lbl_key_status.setStyleSheet(f"font-size: 10px; color: {'#8E9DB2' if is_dark else '#6B7280'};")
        layout.addWidget(self.lbl_key_status)

        lbl_pw = QLabel("2. Yeni Kasa Parolası (En az 8 karakter):")
        lbl_pw.setStyleSheet("font-weight: 700; font-size: 11px; margin-top: 6px;")
        layout.addWidget(lbl_pw)

        self.txt_new_pw = QLineEdit()
        self.txt_new_pw.setEchoMode(QLineEdit.EchoMode.Password)
        self.txt_new_pw.setPlaceholderText("Yeni BitLocker parolanızı yazın...")
        layout.addWidget(self.txt_new_pw)

        lbl_pw2 = QLabel("Yeni Parolayı Doğrulayın:")
        lbl_pw2.setStyleSheet("font-weight: 700; font-size: 11px;")
        layout.addWidget(lbl_pw2)

        self.txt_confirm_pw = QLineEdit()
        self.txt_confirm_pw.setEchoMode(QLineEdit.EchoMode.Password)
        self.txt_confirm_pw.setPlaceholderText("Yeni parolayı tekrar girin...")
        layout.addWidget(self.txt_confirm_pw)

        self.chk_show_pw = QCheckBox("Parolaları Göster")
        self.chk_show_pw.stateChanged.connect(self.toggle_show_passwords)
        layout.addWidget(self.chk_show_pw)

        self.lbl_error = QLabel("")
        self.lbl_error.setStyleSheet("color: #EF4444; font-size: 11px; font-weight: 700;")
        self.lbl_error.setWordWrap(True)
        self.lbl_error.hide()
        layout.addWidget(self.lbl_error)

        layout.addStretch()

        btn_box = QHBoxLayout()
        btn_box.setSpacing(10)

        self.btn_submit = QPushButton("Kasayı Kurtar ve Sıfırla")
        self.btn_submit.setIcon(get_svg_icon("unlock", pal["accent_col"], 16))
        self.btn_submit.setObjectName("btn-accent")
        self.btn_submit.setEnabled(False)
        self.btn_submit.clicked.connect(self.do_recover)
        btn_box.addWidget(self.btn_submit)

        btn_cancel = QPushButton("İptal")
        btn_cancel.clicked.connect(self.reject)
        btn_box.addWidget(btn_cancel)

        layout.addLayout(btn_box)

    def on_key_text_changed(self, text: str):
        self.is_key_verified = False
        self.btn_submit.setEnabled(False)
        self.lbl_error.hide()
        if hasattr(self, "verify_timer") and self.verify_timer.isActive():
            self.verify_timer.stop()

        digits = "".join([c for c in text if c.isdigit()])
        count = len(digits)
        is_dark = (self.theme == "dark")

        if count < 48:
            self.lbl_key_status.setText(f"[GİRİLİYOR] Kurtarma anahtarı giriliyor: {count}/48 hane")
            self.lbl_key_status.setStyleSheet(f"font-size: 10.5px; font-weight: 600; color: {'#8E9DB2' if is_dark else '#6B7280'};")
            return

        checksum_ok = True
        for i in range(0, 48, 6):
            blk = digits[i:i+6]
            try:
                if int(blk) % 11 != 0:
                    checksum_ok = False
                    break
            except ValueError:
                checksum_ok = False
                break

        if not checksum_ok:
            self.lbl_key_status.setText("[GEÇERSİZ] Kurtarma anahtarı formatı (Sağlama toplamı eşleşmiyor)")
            self.lbl_key_status.setStyleSheet("font-size: 10.5px; font-weight: 700; color: #EF4444;")
            return

        self.is_key_verified = True
        self.lbl_key_status.setText("[ONAYLANDI] Kurtarma anahtarı formatı ve sağlama toplamı geçerli (48 hane)")
        self.lbl_key_status.setStyleSheet("font-size: 10.5px; font-weight: 700; color: #10B981;")
        self.btn_submit.setEnabled(True)

    def _start_key_verification(self):
        pass

    def _on_key_verification_finished(self, res: dict):
        pass

    def paste_recovery_key(self):
        cb = QApplication.clipboard()
        if cb:
            t = cb.text().strip()
            if t:
                self.txt_key.setText(t)

    def toggle_show_passwords(self, state):
        mode = QLineEdit.EchoMode.Normal if self.chk_show_pw.isChecked() else QLineEdit.EchoMode.Password
        self.txt_new_pw.setEchoMode(mode)
        self.txt_confirm_pw.setEchoMode(mode)

    def do_recover(self):
        if not self.is_key_verified:
            self.lbl_error.setText("Kurtarma işlemi için önce geçerli bir 48 haneli kurtarma anahtarı girilmelidir.")
            self.lbl_error.show()
            return

        raw_key = self.txt_key.text().strip()
        digits = "".join([c for c in raw_key if c.isdigit()])
        if len(digits) != 48:
            self.lbl_error.setText("Lütfen geçerli bir 48 haneli BitLocker kurtarma anahtarı girin (Örnek: 123456-123456-...).")
            self.lbl_error.show()
            return

        p1 = self.txt_new_pw.text()
        p2 = self.txt_confirm_pw.text()
        if not p1:
            self.lbl_error.setText("Lütfen kasa için yeni bir parola girin.")
            self.lbl_error.show()
            return
        if len(p1) < 8:
            self.lbl_error.setText("Yeni BitLocker parolası en az 8 karakter olmalıdır.")
            self.lbl_error.show()
            return
        if p1 != p2:
            self.lbl_error.setText("Girilen yeni parolalar birbiriyle eşleşmiyor.")
            self.lbl_error.show()
            return

        self.btn_submit.setEnabled(False)
        self.btn_submit.setText("Kurtarma İşlemi Yapılıyor...")
        self.lbl_error.hide()
        QApplication.processEvents()

        parent = self.parent()
        if parent:
            parent.suppress_poll = True

        try:
            if self.vault_file and Path(self.vault_file).exists() and self.engine.is_vault_shielded(self.vault_file):
                unshield_res = self.engine.remove_usb_protection_from_vault(self.vault_file)
                if not unshield_res.get("success") and self.engine.is_vault_shielded(self.vault_file):
                    self.lbl_error.setText(f"Kasa USB mührü çözülemedi:\n{unshield_res.get('error')}")
                    self.lbl_error.show()
                    self.btn_submit.setEnabled(True)
                    self.btn_submit.setText("Kasayı Kurtar ve Yeni Parolayı Belirle")
                    return

            target_dl = self.drive_letter or getattr(parent, "drive_letter", "")
            if not target_dl or not getattr(parent, "is_mounted", False):
                mount_res = self.engine.mount_vhd(self.vault_file)
                if not mount_res.get("success"):
                    self.lbl_error.setText(f"Kasa sisteme bağlanamadı:\n{mount_res.get('error')}")
                    self.lbl_error.show()
                    self.btn_submit.setEnabled(True)
                    self.btn_submit.setText("Kasayı Kurtar ve Yeni Parolayı Belirle")
                    return
                target_dl = mount_res.get("drive_letter", "")

            if not target_dl:
                target_dl = self.engine.ensure_drive_letter_assigned(target=self.vault_file)

            if not target_dl:
                self.lbl_error.setText("Sanal disk sisteme bağlandı ancak bir sürücü harfi atanamadı.")
                self.lbl_error.show()
                self.btn_submit.setEnabled(True)
                self.btn_submit.setText("Kasayı Kurtar ve Yeni Parolayı Belirle")
                return

            self.drive_letter = target_dl

            formatted_key = "-".join([digits[i:i+6] for i in range(0, 48, 6)])
            unlock_res = self.engine.unlock_bitlocker_recovery_key(self.drive_letter, formatted_key)
            if not unlock_res.get("success"):
                err_msg = unlock_res.get('error', 'Kurtarma anahtarı bu kasa ile eşleşmiyor.')
                self.lbl_error.setText(f"Kurtarma anahtarı doğrulanamadı:\n{err_msg}")
                self.lbl_error.show()
                self.btn_submit.setEnabled(True)
                self.btn_submit.setText("Kasayı Kurtar ve Yeni Parolayı Belirle")
                return

            change_res = self.engine.change_bitlocker_password(self.drive_letter, p1, old_password=None)
            if not change_res.get("success"):
                self.lbl_error.setText(f"Kilit açıldı ancak yeni parola uygulanamadı:\n{change_res.get('error')}")
                self.lbl_error.show()
                self.btn_submit.setEnabled(True)
                self.btn_submit.setText("Kasayı Kurtar ve Yeni Parolayı Belirle")
                return

            self.engine.lock_bitlocker(self.drive_letter)

            audit_logger.log_security_event(
                "VAULT_RECOVERED",
                "SUCCESS",
                f"Kasa 48 haneli kurtarma anahtarı ile sıfırlandı ve yeni parola tanımlandı: {self.drive_letter}",
                Path(self.vault_file).name,
                self.drive_letter
            )

            if parent:
                parent.suppress_poll = False
                if hasattr(parent, "txt_password") and parent.txt_password:
                    parent.txt_password.clear()
                    parent.txt_password.setFocus()
                if hasattr(parent, "poll_volume_status"):
                    parent.poll_volume_status()
                if hasattr(parent, "refresh_vault_list"):
                    parent.refresh_vault_list()

            QMessageBox.information(
                self,
                "Parola Başarıyla Kaydedildi",
                f"Kasanızın BitLocker parolası başarıyla sıfırlandı ve yeni parolanız kaydedildi!\n\n"
                f"• Sürücü: {self.drive_letter}\n"
                f"• Yeni parolanız başarıyla tanımlandı.\n\n"
                f"Güvenliğiniz için kasa kilitlendi. Lütfen yeni belirlediğiniz parola ile giriş yapın."
            )
            self.accept()

        except Exception as e:
            self.lbl_error.setText(f"Kurtarma sırasında beklenmedik hata: {e}")
            self.lbl_error.show()
        finally:
            if parent:
                parent.suppress_poll = False
            self.btn_submit.setEnabled(True)
            self.btn_submit.setText("Kasayı Kurtar ve Yeni Parolayı Belirle")

class DecoyVaultDialog(QDialog):
    """Baskı/zorlama anında açılacak sahte tuzak kasa ayarları."""
    def __init__(self, parent=None, config: dict = None, theme: str = "dark"):
        super().__init__(parent)
        self.config = config or {}
        self.theme = theme
        self.setWindowTitle("Tuzak Kasa (Decoy Vault) Yapılandırması")
        apply_dynamic_geometry(self, default_w=520, default_h=380, min_w=460, min_h=300)
        self.setSizeGripEnabled(True)
        self.setModal(True)
        self.init_ui()

    def init_ui(self):
        pal = get_dialog_palette(self.theme)
        is_dark = pal["is_dark"]
        bg_col = pal["bg_col"]
        text_col = pal["text_col"]
        inp_bg = pal["inp_bg"]
        border_col = pal["border_col"]
        accent_col = pal["accent_col"]
        set_dialog_dark_mode(self, is_dark)

        self.setStyleSheet(f"""
            QDialog {{
                background-color: {bg_col};
                color: {text_col};
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
            }}
            QLabel {{
                color: {text_col};
            }}
            QLineEdit {{
                background-color: {inp_bg};
                color: {text_col};
                border: 1px solid {border_col};
                border-radius: 8px;
                padding: 7px 12px;
                font-size: 11px;
            }}
            QLineEdit:focus {{
                border-color: {accent_col};
            }}
            {get_dialog_button_stylesheet(self.theme)}
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        title = QLabel("TUZAK KASA (DENIABLE ENCRYPTION)")
        title.setStyleSheet(f"font-size: 15px; font-weight: 800; color: {accent_col if 'accent_col' in locals() else pal['accent_col']};")
        layout.addWidget(title)

        desc = QLabel(
            "Biri sizi şifreyi vermeye zorlarsa girilecek 'ikinci şifre'. "
            "Bu şifre girildiğinde gerçek kasa yerine sahte/zararsız dosyalar içeren tuzak kasa açılır "
            "ve şüphe uyandırmadan sistem kilitli değil gibi davranır."
        )
        desc.setWordWrap(True)
        desc.setStyleSheet(f"font-size: 13px; color: {text_muted if 'text_muted' in locals() else pal['text_muted']};")
        layout.addWidget(desc)

        self.chk_enable = QCheckBox("Tuzak Kasa Korumasını Etkinleştir")
        self.chk_enable.setChecked(self.config.get("decoy_vault_enabled", False))
        layout.addWidget(self.chk_enable)

        layout.addWidget(QLabel("Tuzak VHD/VHDX Dosyası:"))
        path_box = QHBoxLayout()
        self.txt_path = QLineEdit(self.config.get("decoy_vault_path", ""))
        self.txt_path.setPlaceholderText("Örn: D:\\Career\\Coding\\Projects\\VHD\\vaults\\decoy.vhd")
        path_box.addWidget(self.txt_path)

        btn_browse = QPushButton("Gözat...")
        btn_browse.clicked.connect(self.browse_decoy)
        path_box.addWidget(btn_browse)
        layout.addLayout(path_box)

        layout.addWidget(QLabel("Tuzak Kasa Parolası (Acil Durum Şifresi):"))
        self.txt_pw = QLineEdit()
        self.txt_pw.setEchoMode(QLineEdit.EchoMode.Password)
        self.txt_pw.setPlaceholderText("Tetikleyici tuzak parolayı yazın...")
        layout.addWidget(self.txt_pw)

        layout.addStretch()

        btn_box = QHBoxLayout()
        btn_save = QPushButton("Ayarları Kaydet")
        btn_save.clicked.connect(self.save_settings)
        btn_box.addWidget(btn_save)

        btn_cancel = QPushButton("İptal")
        btn_cancel.clicked.connect(self.reject)
        btn_box.addWidget(btn_cancel)
        layout.addLayout(btn_box)

    def browse_decoy(self):
        f, _ = QFileDialog.getOpenFileName(self, "Tuzak Kasa Dosyası Seç", "", "VHD Dosyaları (*.vhd *.vhdx)")
        if f:
            self.txt_path.setText(f)

    def save_settings(self):
        enabled = self.chk_enable.isChecked()
        path = self.txt_path.text().strip()
        pw = self.txt_pw.text().strip()

        if enabled:
            if not path or not Path(path).exists():
                QMessageBox.warning(self, "Hata", "Lütfen geçerli bir tuzak VHD dosyası seçin.")
                return
            if pw:
                self.config["decoy_vault_password_hash"] = hashlib.sha256(pw.encode("utf-8")).hexdigest()
            elif not self.config.get("decoy_vault_password_hash"):
                QMessageBox.warning(self, "Hata", "Lütfen tuzak bir parola belirleyin.")
                return

        self.config["decoy_vault_enabled"] = enabled
        self.config["decoy_vault_path"] = path
        audit_logger.log_security_event(
            "DECOY_CONFIG_UPDATE",
            "INFO",
            f"Tuzak kasa ayarları güncellendi. Etkin: {enabled}"
        )
        self.accept()

class USBKeyDialog(QDialog):
    """Eski referanslar için boş uyumluluk sınıfı."""
    def __init__(self, *args, **kwargs):
        super().__init__()

class AuditLogDialog(QDialog):
    """Güvenlik denetim günlüğü kayıtlarını tablo halinde listeler ve dışa aktarır."""
    def __init__(self, parent=None, theme: str = "dark"):
        super().__init__(parent)
        self.theme = theme
        self.setWindowTitle("Güvenlik Denetim Günlüğü (Security Audit Log)")
        apply_dynamic_geometry(self, default_w=720, default_h=460, min_w=580, min_h=340)
        self.setSizeGripEnabled(True)
        self.setModal(True)
        self.init_ui()

    def init_ui(self):
        pal = get_dialog_palette(self.theme)
        is_dark = pal["is_dark"]
        bg_col = pal["bg_col"]
        text_col = pal["text_col"]
        table_bg = pal["table_bg"]
        table_header = pal["table_header"]
        border_col = pal["border_col"]
        set_dialog_dark_mode(self, is_dark)

        self.setStyleSheet(f"""
            QDialog {{
                background-color: {bg_col};
                color: {text_col};
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
            }}
            QTableWidget {{
                background-color: {table_bg};
                color: {text_col};
                gridline-color: {border_col};
                border: 1px solid {border_col};
                border-radius: 8px;
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
                font-size: 11px;
            }}
            QHeaderView::section {{
                background-color: {table_header};
                color: {text_col};
                font-weight: 700;
                border: 1px solid {border_col};
                padding: 6px;
            }}
            {get_dialog_button_stylesheet(self.theme)}
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)

        header = QLabel("GÜVENLİK DENETİM GÜNLÜĞÜ (AUDIT REPORT)")
        header.setStyleSheet(f"font-size: 15px; font-weight: 800; color: {accent_col if 'accent_col' in locals() else pal['accent_col']};")
        layout.addWidget(header)

        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(["Zaman", "Olay", "Seviye", "Kasa", "Sürücü", "Detay"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        layout.addWidget(self.table)

        btn_box = QHBoxLayout()
        btn_export = QPushButton("CSV Olarak Dışa Aktar")
        btn_export.clicked.connect(self.export_csv)
        btn_box.addWidget(btn_export)

        btn_clear = QPushButton("Kayıtları Temizle")
        btn_clear.clicked.connect(self.clear_logs)
        btn_box.addWidget(btn_clear)

        btn_refresh = QPushButton("Yenile")
        btn_refresh.clicked.connect(self.load_data)
        btn_box.addWidget(btn_refresh)

        btn_close = QPushButton("Kapat")
        btn_close.clicked.connect(self.accept)
        btn_box.addWidget(btn_close)

        layout.addLayout(btn_box)
        self.load_data()

    def load_data(self):
        events = audit_logger.get_audit_events(limit=200)
        self.table.setRowCount(len(events))
        is_dark = (self.theme == "dark")

        for row, e in enumerate(events):
            t_item = QTableWidgetItem(e.get("timestamp", ""))
            ev_item = QTableWidgetItem(e.get("event_type", ""))
            sev_item = QTableWidgetItem(e.get("severity", ""))
            v_item = QTableWidgetItem(e.get("vault_name", ""))
            d_item = QTableWidgetItem(e.get("drive_letter", ""))
            det_item = QTableWidgetItem(e.get("details", ""))

            sev = e.get("severity", "").upper()
            if sev == "DANGER":
                col = Qt.GlobalColor.red
            elif sev == "WARNING":
                col = Qt.GlobalColor.yellow if is_dark else Qt.GlobalColor.darkYellow
            elif sev == "SUCCESS":
                col = Qt.GlobalColor.green if is_dark else Qt.GlobalColor.darkGreen
            else:
                col = Qt.GlobalColor.cyan if is_dark else Qt.GlobalColor.darkBlue

            sev_item.setForeground(col)
            ev_item.setForeground(col)

            self.table.setItem(row, 0, t_item)
            self.table.setItem(row, 1, ev_item)
            self.table.setItem(row, 2, sev_item)
            self.table.setItem(row, 3, v_item)
            self.table.setItem(row, 4, d_item)
            self.table.setItem(row, 5, det_item)

        self.table.resizeColumnsToContents()

    def export_csv(self):
        p, _ = QFileDialog.getSaveFileName(self, "Denetim Günlüğünü Kaydet", "guvenlik_denetim_gunlugu.csv", "CSV Dosyası (*.csv)")
        if p:
            if audit_logger.export_audit_csv(p):
                QMessageBox.information(self, "Başarılı", "Denetim günlüğü CSV dosyasına kaydedildi.")
            else:
                QMessageBox.warning(self, "Hata", "Dışa aktarma başarısız.")

    def clear_logs(self):
        if QMessageBox.question(self, "Onay", "Tüm güvenlik denetim kayıtları silinsin mi?") == QMessageBox.StandardButton.Yes:
            audit_logger.clear_audit_events()
            self.load_data()

class ShredConfirmDialog(QDialog):
    """Sürüklenen dosyaların kasaya taşınıp güvenle parçalanması için onay diyaloğu."""
    def __init__(self, parent=None, files: List[str] = None, target_drive: str = "", theme: str = "dark"):
        super().__init__(parent)
        self.files = files or []
        self.target_drive = target_drive
        self.theme = theme
        self.choice = None
        self.setWindowTitle("Güvenli Dosya Şifreleme ve Parçalama")
        apply_dynamic_geometry(self, default_w=460, default_h=280, min_w=400, min_h=220)
        self.setSizeGripEnabled(True)
        self.setModal(True)
        self.init_ui()

    def init_ui(self):
        pal = get_dialog_palette(self.theme)
        is_dark = pal["is_dark"]
        bg_col = pal["bg_col"]
        text_col = pal["text_col"]
        card_bg = pal["card_bg"]
        border_col = pal["border_col"]
        set_dialog_dark_mode(self, is_dark)

        self.setStyleSheet(f"""
            QDialog {{
                background-color: {bg_col};
                color: {text_col};
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
            }}
            {get_dialog_button_stylesheet(self.theme)}
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)

        title = QLabel(f"{len(self.files)} ADET ÖĞE SÜRÜKLENDİ")
        title.setStyleSheet(f"font-size: 15px; font-weight: 800; color: {accent_col if 'accent_col' in locals() else pal['accent_col']};")
        layout.addWidget(title)

        info = QLabel(
            f"Seçilen dosyalar kasanıza (<b>{self.target_drive}</b>) kopyalanacaktır.<br><br>"
            "<b>Orijinal dosyalar ne yapılsın?</b><br>"
            "• <b>Kasaya Taşı & Parçala:</b> Orijinal disk sektörlerinin üzeri sıfırlanır ve DoD standardında geri getirilemez şekilde parçalanır.<br>"
            "• <b>Yalnızca Kasaya Kopyala:</b> Orijinal dosyalar yerinde bırakılır."
        )
        info.setWordWrap(True)
        info.setStyleSheet(f"font-size: 11px; line-height: 1.4;")
        layout.addWidget(info)

        layout.addStretch()

        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(10)

        btn_shred = QPushButton("Kasaya Taşı & Güvenle Parçala (Shred)")
        btn_shred.setObjectName("btn-shred")
        btn_shred.clicked.connect(self.select_shred)
        btn_layout.addWidget(btn_shred)

        btn_copy = QPushButton("Yalnızca Kopyala")
        btn_copy.clicked.connect(self.select_copy)
        btn_layout.addWidget(btn_copy)

        btn_cancel = QPushButton("İptal")
        btn_cancel.clicked.connect(self.reject)
        btn_layout.addWidget(btn_cancel)

        layout.addLayout(btn_layout)

    def select_shred(self):
        self.choice = "shred"
        self.accept()

    def select_copy(self):
        self.choice = "copy"
        self.accept()

class VaultProfilesDialog(QDialog):
    """Birden fazla kasa profilini yönetir ve aralarında hızlı geçiş / çoklu açma sağlar."""
    def __init__(self, parent=None, engine=None, config: dict = None, current_vault: str = "", theme: str = "dark"):
        super().__init__(parent)
        self.engine = engine or (getattr(parent, "engine", None))
        self.config = config or {}
        self.current_vault = current_vault
        self.theme = theme
        self.selected_path = None
        self.setWindowTitle("Çoklu Kasa Profilleri & Toplu Açma")
        apply_dynamic_geometry(self, default_w=560, default_h=420, min_w=480, min_h=340)
        self.setSizeGripEnabled(True)
        self.setModal(True)
        self.init_ui()

    def init_ui(self):
        pal = get_dialog_palette(self.theme)
        is_dark = pal["is_dark"]
        bg_col = pal["bg_col"]
        text_col = pal["text_col"]
        tbl_bg = pal["table_bg"]
        border_col = pal["border_col"]
        set_dialog_dark_mode(self, is_dark)

        self.setStyleSheet(f"""
            QDialog {{
                background-color: {bg_col};
                color: {text_col};
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
            }}
            QTableWidget {{
                background-color: {tbl_bg};
                color: {text_col};
                border: 1px solid {border_col};
                border-radius: 8px;
                font-size: 11px;
            }}
            {get_dialog_button_stylesheet(self.theme)}
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)

        title = QLabel("ÇOKLU KASA PROFİLLERİ & YÖNETİMİ")
        title.setStyleSheet(f"font-size: 15px; font-weight: 800; color: {accent_col if 'accent_col' in locals() else pal['accent_col']};")
        layout.addWidget(title)

        desc = QLabel("Birden fazla kasanızı burada listeleyebilir, aralarında tek tıkla geçiş yapabilir veya aynı anda hepsini açabilirsiniz:")
        desc.setWordWrap(True)
        desc.setStyleSheet(f"font-size: 13px; color: {text_muted if 'text_muted' in locals() else pal['text_muted']};")
        layout.addWidget(desc)

        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["Profil Adı", "Kasa Yolu", "Sabit Harf", "Durum"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        layout.addWidget(self.table)

        multi_row = QHBoxLayout()
        btn_mount_all = QPushButton("Tüm Kasaları Bağla (Çoklu Aç)")
        btn_mount_all.setIcon(get_svg_icon("bolt", pal["accent_col"], 16))
        btn_mount_all.setToolTip("Listedeki bağlı olmayan tüm kasaları sisteme bağlar ve USB anahtarı takılıysa kilitlerini açar")
        btn_mount_all.clicked.connect(self.mount_all_profiles)
        multi_row.addWidget(btn_mount_all)

        btn_dismount_all = QPushButton("Tüm Açık Kasaları Ayır")
        btn_dismount_all.setIcon(get_svg_icon("stop", "#EF4444" if is_dark else "#991B1B", 16))
        btn_dismount_all.setToolTip("Sistemde bağlı bulunan tüm açık profil kasalarını güvenle ayırır")
        btn_dismount_all.clicked.connect(self.dismount_all_profiles)
        multi_row.addWidget(btn_dismount_all)
        layout.addLayout(multi_row)

        btn_row = QHBoxLayout()
        btn_select = QPushButton("Seçili Kasaya Geç")
        btn_select.clicked.connect(self.select_vault)
        btn_row.addWidget(btn_select)

        btn_add_cur = QPushButton("Mevcut Kasayı Ekle...")
        btn_add_cur.clicked.connect(self.add_current_vault)
        btn_row.addWidget(btn_add_cur)

        btn_delete = QPushButton("Sil")
        btn_delete.clicked.connect(self.delete_profile)
        btn_row.addWidget(btn_delete)

        btn_close = QPushButton("Kapat")
        btn_close.clicked.connect(self.accept)
        btn_row.addWidget(btn_close)

        layout.addLayout(btn_row)
        self.load_profiles()

    def load_profiles(self):
        profiles = self.config.get("vault_profiles", [])
        self.table.setRowCount(len(profiles))
        for row, p in enumerate(profiles):
            self.table.setItem(row, 0, QTableWidgetItem(p.get("name", "")))
            self.table.setItem(row, 1, QTableWidgetItem(p.get("path", "")))
            self.table.setItem(row, 2, QTableWidgetItem(p.get("letter", "-")))
            
            status_txt = "Bağlı Değil"
            if self.engine and p.get("path"):
                att = self.engine.check_vault_attached(p.get("path"))
                if att and att.get("Attached"):
                    dl = att.get("DriveLetter", "")
                    status_txt = f"● Bağlı ({dl})" if dl else "● Bağlı"
            
            item_status = QTableWidgetItem(status_txt)
            if "Bağlı (" in status_txt or status_txt == "● Bağlı":
                item_status.setForeground(QColor("#10B981"))
            self.table.setItem(row, 3, item_status)

        self.table.resizeColumnsToContents()

    def _is_profile_usb_protected(self, v_path: str, profile: dict) -> bool:
        return False

    def mount_all_profiles(self):
        profiles = self.config.get("vault_profiles", [])
        if not profiles:
            QMessageBox.information(self, "Bilgi", "Kayıtlı profil kasası bulunamadı.")
            return

        if not self.engine:
            return

        usb_tok = self.config.get("usb_key_token", "") if self.config.get("usb_key_enabled", False) else ""
        usb_ser = self.config.get("usb_key_serial", "") if self.config.get("usb_key_enabled", False) else ""

        mounted_count = 0
        for p in profiles:
            v_path = p.get("path", "")
            if not v_path or not Path(v_path).exists():
                continue

            att = self.engine.check_vault_attached(v_path)
            if att and att.get("Attached"):
                continue

            pref = p.get("letter")
            tok = usb_tok if self._is_profile_usb_protected(v_path, p) else ""
            res = self.engine.mount_vhd(v_path, preferred_letter=pref, usb_token=tok)
            if res.get("success"):
                mounted_count += 1
                dl = res.get("drive_letter", "")
                if dl and tok:
                    try:
                        v_name = Path(v_path).name
                        usb_pw = self.engine.get_connected_usb_unlock_password(tok, usb_ser, vault_name=v_name)
                        if usb_pw:
                            self.engine.unlock_drive(dl, usb_pw)
                    except Exception:
                        pass

        self.load_profiles()
        parent = self.parent()
        if parent and hasattr(parent, "refresh_vault_list"):
            parent.refresh_vault_list()

        QMessageBox.information(
            self,
            "Çoklu Kasa Bağlandı",
            f"{mounted_count} adet kasa başarıyla sisteme bağlandı.\n\n"
            "Ana ekrandaki kasa listesinden veya Dosya Gezgini'nden tüm kasalarınıza erişebilirsiniz."
        )

    def dismount_all_profiles(self):
        profiles = self.config.get("vault_profiles", [])
        if not self.engine:
            return

        dismounted_count = 0
        usb_tok = self.config.get("usb_key_token", "") if self.config.get("usb_key_enabled", False) else ""
        for p in profiles:
            v_path = p.get("path", "")
            if not v_path:
                continue
            att = self.engine.check_vault_attached(v_path)
            if att and att.get("Attached"):
                dl = att.get("DriveLetter", "")
                tok = usb_tok if self._is_profile_usb_protected(v_path, p) else ""
                self.engine.dismount_vhd(mount_target=v_path, drive_letter=dl, force=True, usb_token=tok)
                dismounted_count += 1

        self.load_profiles()
        parent = self.parent()
        if parent and hasattr(parent, "refresh_vault_list"):
            parent.refresh_vault_list()

        QMessageBox.information(self, "Kasalar Ayrıldı", f"{dismounted_count} adet açık kasa güvenle ayrıldı.")

    def select_vault(self):
        cur_row = self.table.currentRow()
        if cur_row >= 0:
            profiles = self.config.get("vault_profiles", [])
            if cur_row < len(profiles):
                self.selected_path = profiles[cur_row].get("path")
                self.accept()

    def add_current_vault(self):
        if not self.current_vault or not Path(self.current_vault).exists():
            QMessageBox.warning(self, "Hata", "Geçerli bir kasa seçili değil.")
            return

        from PyQt6.QtWidgets import QInputDialog
        name, ok = QInputDialog.getText(self, "Profil Adı", "Bu kasa için bir profil adı girin:", text=Path(self.current_vault).stem)
        if ok and name.strip():
            profiles = self.config.get("vault_profiles", [])
            profiles.append({
                "name": name.strip(),
                "path": self.current_vault,
                "letter": self.config.get("preferred_drive_letters", {}).get(self.current_vault, "")
            })
            self.config["vault_profiles"] = profiles
            self.load_profiles()

    def delete_profile(self):
        cur_row = self.table.currentRow()
        if cur_row >= 0:
            profiles = self.config.get("vault_profiles", [])
            if cur_row < len(profiles):
                del profiles[cur_row]
                self.config["vault_profiles"] = profiles
                self.load_profiles()

def import_time_str():
    import time
    return time.strftime("%Y-%m-%d %H:%M:%S")

class ExpandVaultWorker(QThread):
    finished_signal = pyqtSignal(dict)

    def __init__(self, engine, vault_path: str, new_mb: int):
        super().__init__()
        self.engine = engine
        self.vault_path = vault_path
        self.new_mb = new_mb

    def run(self):
        try:
            if self.engine:
                res = self.engine.expand_vdisk(self.vault_path, self.new_mb)
                self.finished_signal.emit(res)
            else:
                self.finished_signal.emit({"success": False, "error": "Motor başlatılamadı."})
        except Exception as e:
            self.finished_signal.emit({"success": False, "error": str(e)})

class ExpandVaultDialog(QDialog):
    """Sanal diskin boyutunu büyütmek için kullanıcı dostu arayüz."""
    def __init__(self, parent=None, engine=None, vault_path: str = "", theme: str = "dark"):
        super().__init__(parent)
        self.engine = engine
        self.vault_path = vault_path
        self.theme = theme
        self.worker = None
        self.preset_btns = []
        self.setWindowTitle("Kasa Boyutunu Genişlet (Expand VHD)")
        apply_dynamic_geometry(self, default_w=480, default_h=340, min_w=420, min_h=280)
        self.setSizeGripEnabled(True)
        self.setModal(True)
        self.init_ui()

    def init_ui(self):
        pal = get_dialog_palette(self.theme)
        is_dark = pal["is_dark"]
        bg_col = pal["bg_col"]
        text_col = pal["text_col"]
        card_bg = pal["card_bg"]
        accent_col = pal["accent_col"]
        border_col = pal["border_col"]
        set_dialog_dark_mode(self, is_dark)

        self.setStyleSheet(f"""
            QDialog {{
                background-color: {bg_col};
                color: {text_col};
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
            }}
            {get_dialog_button_stylesheet(self.theme)}
            QPushButton#btn-stepper {{
                min-width: 36px;
                max-width: 36px;
                min-height: 32px;
                max-height: 32px;
                padding: 0px;
                font-family: 'Segoe UI', 'Arial', sans-serif;
                font-size: 16px;
                font-weight: 800;
            }}
            QPushButton#btn-preset {{
                min-height: 26px;
                max-height: 26px;
                padding: 3px 10px;
                font-family: 'Segoe UI', 'Inter', 'Arial', sans-serif;
                font-size: 11px;
                font-weight: 700;
            }}
            QFrame#infoCard {{
                background-color: {card_bg};
                border: 1px solid {border_col};
                border-radius: 8px;
            }}
            QFrame#infoCard QLabel {{
                background: transparent;
                border: none;
                padding: 1px 0px;
                font-size: 12px;
                color: {text_col};
            }}
            QSpinBox {{
                background-color: {card_bg};
                color: {accent_col};
                border: 1px solid {border_col};
                border-radius: 8px;
                padding: 2px 6px;
                font-family: 'Segoe UI', 'Consolas', monospace;
                font-size: 15px;
                font-weight: 800;
                min-height: 32px;
                max-height: 32px;
                selection-background-color: {'#0E3547' if is_dark else '#D5EAF7'};
                selection-color: {pal['accent_col']};
            }}
            QSpinBox:focus {{
                border-color: {pal['accent_col']};
            }}
            QProgressBar {{
                border: 1px solid {border_col};
                border-radius: 8px;
                text-align: center;
                background-color: {card_bg};
                color: {accent_col};
                height: 14px;
            }}
            QProgressBar::chunk {{
                background-color: {'#38BDF8' if is_dark else '#2E56BA'};
            }}
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        title = QLabel("KASA KAPASİTESİNİ GENİŞLET")
        title.setStyleSheet(f"font-size: 15px; font-weight: 800; color: {accent_col if 'accent_col' in locals() else pal['accent_col']}; letter-spacing: 0.5px;")
        layout.addWidget(title)

        import math
        clean_path = str(self.vault_path).strip(' "\'') if self.vault_path else ""
        v_path = Path(clean_path).resolve() if clean_path else None
        v_info = self.engine.get_vhd_virtual_size(str(v_path)) if (self.engine and v_path and v_path.exists()) else {}
        current_virt_mb = v_info.get("virtual_mb", round((v_path.stat().st_size if (v_path and v_path.exists()) else 0) / (1024 * 1024), 1))
        current_gb = max(1, int(math.ceil(current_virt_mb / 1024.0)))
        current_phys_mb = v_info.get("physical_mb", current_virt_mb)
        is_vhdx = (v_info.get("disk_type") == "vhdx")
        self.is_fixed = (v_info.get("disk_type") == "fixed")
        
        disk_type_str = "VHDX (Gelişmiş Sanal Disk)" if is_vhdx else ("Sabit Boyutlu VHD (Ön Tahsisli)" if self.is_fixed else "Dinamik VHD (Kullanıldıkça Büyüyen)")
        max_limit_gb = 65536 if is_vhdx else 2040

        self.current_virt_mb = current_virt_mb
        self.current_gb = current_gb

        info_box = QFrame()
        info_box.setObjectName("infoCard")
        ib_layout = QVBoxLayout(info_box)
        ib_layout.setContentsMargins(14, 12, 14, 12)
        ib_layout.setSpacing(6)
        
        lbl_target = QLabel(f"<b>Hedef Kasa:</b> {v_path.name if v_path else 'Bilinmiyor'} <span style='color: {'#38BDF8' if is_dark else '#0C5478'}; font-weight: 600;'>({disk_type_str})</span>")
        lbl_target.setTextFormat(Qt.TextFormat.RichText)
        if v_path:
            lbl_target.setToolTip(str(v_path))
        ib_layout.addWidget(lbl_target)

        lbl_virt = QLabel(f"<b>Mevcut Sanal Kapasite:</b> <span style='color: {accent_col}; font-weight: 800; font-size: 13px;'>{current_gb} GB</span> <span style='color: {'#94A3B8' if is_dark else '#64748B'};'>({int(current_virt_mb)} MB)</span>")
        lbl_virt.setTextFormat(Qt.TextFormat.RichText)
        ib_layout.addWidget(lbl_virt)

        lbl_phys = QLabel(f"<b>Diskte Kaplanan Alan (Fiziksel):</b> <span style='font-weight: 700;'>{current_phys_mb} MB</span>")
        lbl_phys.setTextFormat(Qt.TextFormat.RichText)
        ib_layout.addWidget(lbl_phys)
        layout.addWidget(info_box)

        limit_info = "Standart VHD en fazla 2040 GB (yaklaşık 2 TB) destekler." if not is_vhdx else "VHDX 64 TB'a kadar destekler."
        fixed_note = " Sabit kasalarda yeni alan diske fiziksel olarak yazıldığı için işlem biraz daha uzun sürebilir." if self.is_fixed else ""
        lbl_desc = QLabel(
            "Kasanın maksimum sanal kapasitesi bu işlemle büyütülür. Kasa bağlıyken genişletme yapılamaz. "
            f"{limit_info}{fixed_note}"
        )
        lbl_desc.setWordWrap(True)
        lbl_desc.setStyleSheet(f"font-size: 13px; line-height: 1.4; color: {text_muted if 'text_muted' in locals() else pal['text_muted']};")
        layout.addWidget(lbl_desc)

        size_group = QVBoxLayout()
        size_group.setSpacing(8)

        lbl_new_size = QLabel("Yeni Maksimum Kapasite:")
        lbl_new_size.setStyleSheet("font-weight: 700; font-size: 12px;")
        size_group.addWidget(lbl_new_size)

        stepper_row = QHBoxLayout()
        stepper_row.setSpacing(6)

        self.btn_step_plus = QPushButton("+")
        self.btn_step_plus.setObjectName("btn-stepper")
        self.btn_step_plus.setToolTip("Kapasiteyi 1 GB arttır")
        self.btn_step_plus.clicked.connect(self.increment_size)
        stepper_row.addWidget(self.btn_step_plus)

        self.spin_size = QSpinBox()
        self.spin_size.setRange(current_gb + 1, max_limit_gb)
        self.spin_size.setValue(max(current_gb + 1, int(current_gb * 1.5)))
        self.spin_size.setSuffix(" GB")
        self.spin_size.setMinimumWidth(90)
        self.spin_size.setMinimumHeight(28)
        self.spin_size.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.spin_size.setButtonSymbols(QSpinBox.ButtonSymbols.NoButtons)
        self.spin_size.valueChanged.connect(self.on_size_value_changed)
        stepper_row.addWidget(self.spin_size)

        self.btn_step_minus = QPushButton("-")
        self.btn_step_minus.setObjectName("btn-stepper")
        self.btn_step_minus.setToolTip("Kapasiteyi 1 GB azalt")
        self.btn_step_minus.clicked.connect(self.decrement_size)
        stepper_row.addWidget(self.btn_step_minus)

        stepper_row.addStretch()
        size_group.addLayout(stepper_row)

        preset_row = QHBoxLayout()
        preset_row.setSpacing(6)
        
        lbl_quick = QLabel("Hızlı Ekle:")
        lbl_quick.setStyleSheet(f"font-size: 13px; font-weight: 600; color: {text_muted if 'text_muted' in locals() else pal['text_muted']};")
        preset_row.addWidget(lbl_quick)

        self.preset_btns = []
        for delta_gb, p_label in [(1, "+1 GB"), (2, "+2 GB"), (5, "+5 GB"), (10, "+10 GB")]:
            btn_p = QPushButton(p_label)
            btn_p.setObjectName("btn-preset")
            btn_p.setToolTip(f"Kapasiteye {p_label} ekle")
            btn_p.clicked.connect(lambda _, d=delta_gb: self.add_delta_size(d))
            preset_row.addWidget(btn_p)
            self.preset_btns.append(btn_p)

        btn_2x = QPushButton("2 Katı (2x)")
        btn_2x.setObjectName("btn-preset")
        btn_2x.setToolTip("Kapasiteyi mevcut boyutun 2 katına çıkar")
        btn_2x.clicked.connect(self.set_double_size)
        preset_row.addWidget(btn_2x)
        self.preset_btns.append(btn_2x)

        preset_row.addStretch()
        size_group.addLayout(preset_row)

        self.lbl_delta = QLabel("")
        self.lbl_delta.setStyleSheet(f"font-size: 11.5px; font-weight: 600; color: {'#38BDF8' if is_dark else '#0A3D59'};")
        size_group.addWidget(self.lbl_delta)

        layout.addLayout(size_group)

        self.lbl_status = QLabel("")
        self.lbl_status.setStyleSheet("font-size: 11px; font-weight: 700; color: #38BDF8;")
        layout.addWidget(self.lbl_status)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)
        self.progress_bar.hide()
        layout.addWidget(self.progress_bar)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(10)
        self.btn_expand = QPushButton("Kapasiteyi Genişlet")
        self.btn_expand.setObjectName("btn-accent")
        self.btn_expand.setMinimumHeight(28)
        self.btn_expand.clicked.connect(self.do_expand)
        btn_row.addWidget(self.btn_expand)

        self.btn_cancel = QPushButton("Kapat")
        self.btn_cancel.setMinimumHeight(28)
        self.btn_cancel.clicked.connect(self.reject)
        btn_row.addWidget(self.btn_cancel)
        layout.addLayout(btn_row)

        self.on_size_value_changed(self.spin_size.value())

    def on_size_value_changed(self, val):
        min_val = self.spin_size.minimum()
        max_val = self.spin_size.maximum()
        self.btn_step_minus.setEnabled(val > min_val)
        self.btn_step_plus.setEnabled(val < max_val)
        
        diff = val - self.current_gb
        total_mb = val * 1024
        if diff > 0:
            self.lbl_delta.setText(f"Genişletme Özeti: {self.current_gb} GB -> {val} GB (+{diff} GB artış, Toplam: {total_mb} MB)")
        else:
            self.lbl_delta.setText(f"Seçilen Kapasite: {val} GB ({total_mb} MB)")

    def increment_size(self):
        cur = self.spin_size.value()
        if cur < self.spin_size.maximum():
            self.spin_size.setValue(cur + 1)

    def decrement_size(self):
        cur = self.spin_size.value()
        if cur > self.spin_size.minimum():
            self.spin_size.setValue(cur - 1)

    def add_delta_size(self, delta: int):
        cur = self.spin_size.value()
        new_val = min(self.spin_size.maximum(), cur + delta)
        self.spin_size.setValue(new_val)

    def set_double_size(self):
        new_val = min(self.spin_size.maximum(), max(self.spin_size.minimum(), self.current_gb * 2))
        self.spin_size.setValue(new_val)

    def do_expand(self):
        new_gb = self.spin_size.value()
        new_mb = new_gb * 1024

        if hasattr(self, "current_virt_mb") and new_mb <= self.current_virt_mb:
            QMessageBox.warning(
                self, "Geçersiz Boyut",
                f"Yeni boyut ({new_gb} GB), kasanın mevcut boyutundan ({int(self.current_virt_mb)} MB) daha büyük olmalıdır."
            )
            return

        status_msg = "Sabit kasa genişletiliyor, disk blokları yazılıyor (15-45 saniye sürebilir)..." if getattr(self, "is_fixed", False) else "Sanal disk genişletiliyor, lütfen bekleyin..."
        self.lbl_status.setText(status_msg)
        self.progress_bar.show()
        self.btn_expand.setEnabled(False)
        self.btn_cancel.setEnabled(False)
        self.spin_size.setEnabled(False)
        self.btn_step_minus.setEnabled(False)
        self.btn_step_plus.setEnabled(False)
        for b in getattr(self, "preset_btns", []):
            b.setEnabled(False)

        clean_target = str(self.vault_path).strip(' "\'') if self.vault_path else ""
        self.target_new_gb = new_gb
        self.target_new_mb = new_mb
        self.target_clean_path = clean_target

        self.worker = ExpandVaultWorker(self.engine, clean_target, new_mb)
        self.worker.finished_signal.connect(self.on_expand_finished)
        self.worker.start()

    def on_expand_finished(self, res: dict):
        self.progress_bar.hide()
        self.btn_expand.setEnabled(True)
        self.btn_cancel.setEnabled(True)
        self.spin_size.setEnabled(True)
        self.btn_step_minus.setEnabled(True)
        self.btn_step_plus.setEnabled(True)
        for b in getattr(self, "preset_btns", []):
            b.setEnabled(True)

        if res.get("success"):
            new_gb = getattr(self, "target_new_gb", 0)
            new_mb = getattr(self, "target_new_mb", 0)
            clean_target = getattr(self, "target_clean_path", "")
            audit_logger.log_event("VAULT_EXPAND", f"Kasa boyutu {new_gb} GB yapıldı: {clean_target}", level="INFO")
            QMessageBox.information(
                self, "Başarılı",
                f"Kasa boyutu başarıyla {new_gb} GB ({new_mb} MB) kapasitesine genişletildi!\n\n"
                "Kasa bağlandığında ve kilidi açıldığında dosya sistemi bölümü otomatik olarak yeni boyuta uyarlanacaktır."
            )
            self.accept()
        else:
            self.lbl_status.setText("")
            QMessageBox.critical(self, "Hata", res.get("error", "Genişletme işlemi başarısız oldu."))

class DiskHealthDialog(QDialog):
    """VHD başlık doğrulaması ve dosya sistemi (chkdsk) kontrol arayüzü."""
    def __init__(self, parent=None, engine=None, vault_path: str = "", drive_letter: str = "", theme: str = "dark"):
        super().__init__(parent)
        self.engine = engine
        self.vault_path = vault_path
        self.drive_letter = drive_letter
        self.theme = theme
        self.setWindowTitle("Disk Sağlığı & Bütünlük Kontrolü")
        apply_dynamic_geometry(self, default_w=580, default_h=420, min_w=500, min_h=340)
        self.setSizeGripEnabled(True)
        self.setModal(True)
        self.init_ui()

    def init_ui(self):
        pal = get_dialog_palette(self.theme)
        is_dark = pal["is_dark"]
        bg_col = pal["bg_col"]
        text_col = pal["text_col"]
        card_bg = pal["card_bg"]
        border_col = pal["border_col"]
        set_dialog_dark_mode(self, is_dark)

        self.setStyleSheet(f"""
            QDialog {{
                background-color: {bg_col};
                color: {text_col};
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
            }}
            {get_dialog_button_stylesheet(self.theme)}
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        title = QLabel("DİSK SAĞLIĞI & BÜTÜNLÜK DENETİMİ")
        title.setStyleSheet(f"font-size: 15px; font-weight: 800; color: {accent_col if 'accent_col' in locals() else pal['accent_col']};")
        layout.addWidget(title)

        h_res = self.engine.check_vhd_health(self.vault_path) if self.vault_path else {}
        is_healthy = h_res.get("healthy", False)

        status_frame = QFrame()
        status_frame.setStyleSheet(f"background-color: {card_bg}; border: 1px solid {border_col}; padding: 10px;")
        sf_layout = QVBoxLayout(status_frame)

        v_name = Path(self.vault_path).name if self.vault_path else "-"
        lbl_vhd = QLabel(f"Kasa Dosyası: {v_name}")
        sf_layout.addWidget(lbl_vhd)

        health_text = "BAŞLIK SAĞLAM (GEÇERLİ)" if is_healthy else "DİKKAT: BAŞLIK GEÇERSİZ VEYA HASARLI"
        health_color = ("#10B981" if is_dark else "#059669") if is_healthy else "#EF4444"
        lbl_h = QLabel(f"Kapsayıcı Durumu: <span style='color:{health_color}; font-weight:bold;'>{health_text}</span>")
        lbl_h.setTextFormat(Qt.TextFormat.RichText)
        sf_layout.addWidget(lbl_h)

        if h_res.get("type"):
            sf_layout.addWidget(QLabel(f"Format Türü: {h_res.get('type')}"))
        if h_res.get("size_mb"):
            sf_layout.addWidget(QLabel(f"Dosya Boyutu: {h_res.get('size_mb')} MB"))

        layout.addWidget(status_frame)

        layout.addWidget(QLabel("Tanılama & chkdsk Çıktısı:"))
        self.txt_log = QTextEdit()
        self.txt_log.setReadOnly(True)
        self.txt_log.append(f">> VHD Kapsayıcı Sağlık Kontrolü:\n>> {h_res.get('message', h_res.get('error', 'Bilgi yok'))}\n")
        layout.addWidget(self.txt_log)

        btn_row = QHBoxLayout()
        if self.drive_letter:
            self.btn_chkdsk = QPushButton(f"Dosya Sistemini Tara ({self.drive_letter})")
            self.btn_chkdsk.clicked.connect(self.run_chkdsk)
            btn_row.addWidget(self.btn_chkdsk)

            self.btn_extend = QPushButton("Bölümü Genişlet (Extend Volume)")
            self.btn_extend.clicked.connect(self.run_extend)
            btn_row.addWidget(self.btn_extend)

        btn_close = QPushButton("Kapat")
        btn_close.clicked.connect(self.accept)
        btn_row.addWidget(btn_close)
        layout.addLayout(btn_row)

    def run_chkdsk(self):
        self.txt_log.append(f">> chkdsk.exe {self.drive_letter} /scan başlatıldı...")
        if hasattr(self, 'btn_chkdsk'):
            self.btn_chkdsk.setEnabled(False)
        self.repaint()

        res = self.engine.repair_volume_filesystem(self.drive_letter)
        self.txt_log.append(res.get("output", ""))
        self.txt_log.append(f">> Sonuç: {res.get('message')}\n")
        if hasattr(self, 'btn_chkdsk'):
            self.btn_chkdsk.setEnabled(True)

    def run_extend(self):
        self.txt_log.append(f">> Bölüm genişletme işlemi başlatıldı ({self.drive_letter})...")
        self.repaint()
        res = self.engine.extend_filesystem_volume(self.drive_letter)
        if res.get("success"):
            self.txt_log.append(f">> Başarılı: {res.get('message')}\n")
            QMessageBox.information(self, "Başarılı", res.get("message"))
        else:
            self.txt_log.append(f">> Hata: {res.get('error')}\n")
            QMessageBox.warning(self, "Uyarı", res.get("error"))

class CloudSyncWarningDialog(QDialog):
    """Kasa bulut klasöründe açılmak istendiğinde kullanıcıyı uyaran pencere."""
    def __init__(self, parent=None, provider: str = "", path: str = "", theme: str = "dark"):
        super().__init__(parent)
        self.provider = provider
        self.vault_path = path
        self.theme = theme
        self.setWindowTitle("Bulut Senkronizasyon Uyarısı")
        apply_dynamic_geometry(self, default_w=460, default_h=260, min_w=400, min_h=200)
        self.setSizeGripEnabled(True)
        self.setModal(True)
        self.init_ui()

    def init_ui(self):
        pal = get_dialog_palette(self.theme)
        is_dark = pal["is_dark"]
        bg_col = pal["bg_col"]
        text_col = pal["text_col"]
        card_bg = pal["card_bg"]
        border_col = pal["border_col"]
        set_dialog_dark_mode(self, is_dark)

        self.setStyleSheet(f"""
            QDialog {{
                background-color: {bg_col};
                color: {text_col};
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
            }}
            {get_dialog_button_stylesheet(self.theme)}
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)

        title = QLabel(f"DİKKAT: BULUT SENKRONİZASYON KLASÖRÜ ({self.provider.upper()})")
        title.setStyleSheet("font-size: 13px; font-weight: 800; color: #FFB86C;")
        layout.addWidget(title)

        desc = QLabel(
            f"Seçilen kasa dosyası <b>{self.provider}</b> senkronizasyon klasöründe yer almaktadır.<br><br>"
            "Sanal disk bağlıyken bulut motorunun arka planda dosyayı eşitlemeye çalışması "
            "<b>dosya sistemi çakışmalarına ve geri getirilemez veri bozulmalarına (corruption)</b> "
            "yol açabilir.<br><br>"
            "<i>Tavsiye:</i> Kasayı yerel bir sürücüye taşıyın veya disk açıkken senkronizasyonu duraklatın."
        )
        desc.setTextFormat(Qt.TextFormat.RichText)
        desc.setWordWrap(True)
        desc.setStyleSheet(f"font-size: 11.5px; color: {'#D1DAE8' if is_dark else '#1A2416'};")
        layout.addWidget(desc)

        self.chk_suppress = QCheckBox("Bu uyarıyı bir daha gösterme")
        layout.addWidget(self.chk_suppress)

        btn_row = QHBoxLayout()
        btn_proceed = QPushButton("Riskleri Anladım, Yine de Aç")
        btn_proceed.clicked.connect(self.on_proceed)
        btn_row.addWidget(btn_proceed)

        btn_cancel = QPushButton("İptal")
        btn_cancel.clicked.connect(self.reject)
        btn_row.addWidget(btn_cancel)
        layout.addLayout(btn_row)

    def on_proceed(self):
        self.dont_show_again = self.chk_suppress.isChecked()
        self.accept()

class ShellIntegrationDialog(QDialog):
    """Windows Explorer sağ tık menüsüne Enclave seçeneklerini kurma/kaldırma penceresi."""
    def __init__(self, parent=None, engine=None, theme: str = "dark"):
        super().__init__(parent)
        self.engine = engine
        self.theme = theme
        self.setWindowTitle("Windows Gezgini Sağ Tık Menü Entegrasyonu")
        apply_dynamic_geometry(self, default_w=480, default_h=300, min_w=420, min_h=220)
        self.setSizeGripEnabled(True)
        self.setModal(True)
        self.init_ui()

    def init_ui(self):
        pal = get_dialog_palette(self.theme)
        is_dark = pal["is_dark"]
        bg_col = pal["bg_col"]
        text_col = pal["text_col"]
        card_bg = pal["card_bg"]
        border_col = pal["border_col"]
        set_dialog_dark_mode(self, is_dark)

        self.setStyleSheet(f"""
            QDialog {{
                background-color: {bg_col};
                color: {text_col};
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
            }}
            {get_dialog_button_stylesheet(self.theme)}
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)

        title = QLabel("WINDOWS GEZGİNİ SAĞ TIK ENTEGRASYONU")
        title.setStyleSheet(f"font-size: 15px; font-weight: 800; color: {accent_col if 'accent_col' in locals() else pal['accent_col']};")
        layout.addWidget(title)

        desc = QLabel(
            "Bu özellik Windows Dosya Gezgini sağ tık içerik menüsüne aşağıdaki kısayolları ekler:\n\n"
            "• .vhd / .vhdx dosyalarına sağ tıklandığında: 'Enclave ile Aç'\n"
            "• Tüm dosya ve klasörlerde: 'Enclave ile Güvenle Parçala (DoD Shred)'\n\n"
            "Ayarlar doğrudan mevcut kullanıcı (HKCU) kayıt defterine yazılır ve anında aktif olur."
        )
        desc.setWordWrap(True)
        desc.setStyleSheet(f"font-size: 13px; color: {text_muted if 'text_muted' in locals() else pal['text_muted']};")
        layout.addWidget(desc)

        self.lbl_status = QLabel("")
        self.update_status_display()
        layout.addWidget(self.lbl_status)

        btn_row = QHBoxLayout()
        self.btn_install = QPushButton("Sağ Tık Menüsüne Ekle")
        self.btn_install.clicked.connect(self.install_menu)
        btn_row.addWidget(self.btn_install)

        self.btn_remove = QPushButton("Menüden Kaldır")
        self.btn_remove.clicked.connect(self.remove_menu)
        btn_row.addWidget(self.btn_remove)

        btn_close = QPushButton("Kapat")
        btn_close.clicked.connect(self.accept)
        btn_row.addWidget(btn_close)
        layout.addLayout(btn_row)

    def update_status_display(self):
        is_reg = self.engine.is_shell_context_menu_registered() if (self.engine and hasattr(self.engine, "is_shell_context_menu_registered")) else False
        is_dark = self.theme in ("dark", "apple_dark")
        status_text = "AKTİF / YÜKLÜ" if is_reg else "YÜKLÜ DEĞİL"
        status_color = ("#10B981" if is_dark else "#059669") if is_reg else "#94A3B8"
        self.lbl_status.setText(f"Mevcut Durum: <span style='color:{status_color}; font-weight:bold;'>{status_text}</span>")
        self.lbl_status.setTextFormat(Qt.TextFormat.RichText)

    def install_menu(self):
        res = self.engine.register_shell_context_menu()
        if res.get("success"):
            audit_logger.log_event("SHELL_INTEGRATION", "Sağ tık menü seçenekleri kuruldu.", level="INFO")
            QMessageBox.information(self, "Başarılı", res.get("message"))
            self.update_status_display()
        else:
            QMessageBox.critical(self, "Hata", res.get("error", "Kurulum başarısız oldu."))

    def remove_menu(self):
        res = self.engine.unregister_shell_context_menu()
        if res.get("success"):
            audit_logger.log_event("SHELL_INTEGRATION", "Sağ tık menü seçenekleri kaldırıldı.", level="INFO")
            QMessageBox.information(self, "Başarılı", res.get("message"))
            self.update_status_display()
        else:
            QMessageBox.critical(self, "Hata", res.get("error", "Kaldırma işlemi başarısız oldu."))

class AppSettingsDialog(QDialog):
    """
    Enclave - Modern Apple macOS Stili Uygulama ve Tema Ayarları Penceresi.
    - Gece / Gündüz modu hızlı geçişi
    - Minimal Apple (macOS Space Gray & Cupertino) ve Siber temalar
    - Canlı anında tema önizlemesi
    - Kasa ve güvenlik tercihleri
    """
    theme_changed = pyqtSignal(str)

    THEMES_INFO = [
        {
            "id": "apple_dark",
            "name": "Apple Minimal Koyu (macOS Space Gray)",
            "desc": "Sade, göz yormayan minimalist Apple koyu gri tonları ve zarif Pro Blue vurgusu.",
            "is_dark": True,
            "swatches": ["#161618", "#212124", "#2997FF", "#F5F5F7"]
        }
    ]

    def __init__(self, parent=None, config: dict = None, current_theme: str = "dark", theme: str = None):
        super().__init__(parent)
        self.main_window = parent
        self.config = config or {}
        chosen_th = theme or current_theme
        self.current_theme = chosen_th
        self.selected_theme = chosen_th
        self.theme_card_frames = {}
        self.theme_check_labels = {}

        self.setWindowTitle("Enclave - Ayarlar")
        self.setSizeGripEnabled(True)
        apply_dynamic_geometry(self, default_w=640, default_h=620, min_w=560, min_h=480)
        self.setup_ui()
        self.apply_card_highlights()

    def setup_ui(self):
        pal = get_dialog_palette(self.selected_theme)
        is_dark = pal["is_dark"]
        accent_col = pal["accent_col"]
        text_muted = pal["text_muted"]
        text_col = pal["text_col"]
        card_bg = pal["card_bg"]
        card_border = pal["card_border"]
        bg_col = pal["bg_col"]

        set_dialog_dark_mode(self, is_dark)
        self.setStyleSheet(f"""
            QDialog {{
                background-color: {bg_col};
                color: {text_col};
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
            }}
            QScrollArea {{
                background: transparent;
                border: none;
            }}
            QFrame.card, QFrame[class="card"] {{
                background-color: {card_bg};
                border: 1px solid {card_border};
                border-radius: 12px;
            }}
            QLabel {{
                color: {text_col};
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
            }}
            {get_dialog_button_stylesheet(self.selected_theme)}
        """)

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20, 18, 20, 18)
        main_layout.setSpacing(14)

        header_row = QHBoxLayout()
        header_row.setSpacing(12)

        lbl_icon = QLabel()
        lbl_icon.setPixmap(get_svg_pixmap("settings", accent_col, 28))
        header_row.addWidget(lbl_icon)

        title_box = QVBoxLayout()
        title_box.setSpacing(2)
        lbl_title = QLabel("Uygulama Ayarları")
        lbl_title.setStyleSheet("font-size: 20px; font-weight: 800; letter-spacing: -0.3px;")
        lbl_sub = QLabel("Görünüm, Gece/Gündüz Temaları ve Güvenlik Tercihleri")
        lbl_sub.setStyleSheet("font-size: 13px; color: " + text_muted + ";")
        title_box.addWidget(lbl_title)
        title_box.addWidget(lbl_sub)
        header_row.addLayout(title_box)

        header_row.addStretch()

        btn_top_close = QPushButton()
        btn_top_close.setIcon(get_svg_icon("close", "#86868B", 14))
        btn_top_close.setStyleSheet("background: transparent; border: none; padding: 4px;")
        btn_top_close.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_top_close.clicked.connect(self.close)
        header_row.addWidget(btn_top_close)

        main_layout.addLayout(header_row)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { background: transparent; border: none; } QScrollArea > QWidget > QWidget { background: transparent; }")
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        content = QWidget()
        c_layout = QVBoxLayout(content)
        c_layout.setContentsMargins(2, 4, 2, 8)
        c_layout.setSpacing(14)

        card_theme = QFrame()
        card_theme.setProperty("class", "card")
        ct_layout = QVBoxLayout(card_theme)
        ct_layout.setContentsMargins(16, 14, 16, 14)
        ct_layout.setSpacing(12)

        ct_header_row = QHBoxLayout()
        lbl_ct_title = QLabel("GÖRÜNÜM VE TEMA SEÇİMİ")
        lbl_ct_title.setStyleSheet("font-size: 13px; font-weight: 700; letter-spacing: 0.5px; color: " + accent_col + ";")
        ct_header_row.addWidget(lbl_ct_title)
        ct_header_row.addStretch()
        ct_layout.addLayout(ct_header_row)

        theme_grid = QVBoxLayout()
        theme_grid.setSpacing(8)

        for t_info in self.THEMES_INFO:
            t_id = t_info["id"]
            card_f = QFrame()
            card_f.setCursor(Qt.CursorShape.PointingHandCursor)
            card_f.setObjectName(f"theme-card-{t_id}")

            cf_layout = QHBoxLayout(card_f)
            cf_layout.setContentsMargins(12, 10, 12, 10)
            cf_layout.setSpacing(12)

            t_text_box = QVBoxLayout()
            t_text_box.setSpacing(2)
            lbl_name = QLabel(t_info["name"])
            lbl_name.setStyleSheet("font-size: 12.5px; font-weight: 700;")
            lbl_desc = QLabel(t_info["desc"])
            lbl_desc.setWordWrap(True)
            lbl_desc.setStyleSheet("font-size: 10.5px; opacity: 0.75;")
            t_text_box.addWidget(lbl_name)
            t_text_box.addWidget(lbl_desc)
            cf_layout.addLayout(t_text_box, stretch=1)

            swatch_layout = QHBoxLayout()
            swatch_layout.setSpacing(4)
            for hex_col in t_info["swatches"]:
                sw = QLabel()
                sw.setFixedSize(14, 14)
                sw.setStyleSheet(f"background-color: {hex_col}; border-radius: 7px; border: 1px solid rgba(128, 128, 128, 0.4);")
                swatch_layout.addWidget(sw)
            cf_layout.addLayout(swatch_layout)

            chk_lbl = QLabel()
            chk_lbl.setFixedSize(22, 22)
            chk_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.theme_check_labels[t_id] = chk_lbl
            cf_layout.addWidget(chk_lbl)

            def make_click_handler(tid):
                return lambda ev: self.select_theme(tid)
            card_f.mousePressEvent = make_click_handler(t_id)

            self.theme_card_frames[t_id] = card_f
            theme_grid.addWidget(card_f)

        ct_layout.addLayout(theme_grid)
        c_layout.addWidget(card_theme)

        card_pref = QFrame()
        card_pref.setProperty("class", "card")
        cp_layout = QVBoxLayout(card_pref)
        cp_layout.setContentsMargins(16, 14, 16, 14)
        cp_layout.setSpacing(10)

        lbl_cp_title = QLabel("KASA VE GÜVENLİK TERCİHLERİ")
        lbl_cp_title.setStyleSheet("font-size: 13px; font-weight: 700; letter-spacing: 0.5px; color: " + accent_col + ";")
        cp_layout.addWidget(lbl_cp_title)

        grid_pref = QGridLayout()
        grid_pref.setHorizontalSpacing(24)
        grid_pref.setVerticalSpacing(10)

        self.chk_auto_explorer = QCheckBox("Kasa açılınca gezgini otomatik başlat")
        self.chk_auto_explorer.setChecked(self.config.get("auto_open_explorer", True))
        grid_pref.addWidget(self.chk_auto_explorer, 0, 0)

        self.chk_autoplay = QCheckBox("Autoplay korumasını etkinleştir")
        self.chk_autoplay.setChecked(self.config.get("autoplay_protection", True))
        grid_pref.addWidget(self.chk_autoplay, 0, 1)

        self.chk_close_dismount = QCheckBox("Kapatılırken kasaları güvenle ayır")
        self.chk_close_dismount.setChecked(self.config.get("auto_dismount_on_close", True))
        grid_pref.addWidget(self.chk_close_dismount, 1, 0)

        self.chk_lock_screen = QCheckBox("Windows kilitlenince kasayı kilitle")
        self.chk_lock_screen.setChecked(self.config.get("lock_on_screen_lock", True))
        grid_pref.addWidget(self.chk_lock_screen, 1, 1)

        self.chk_clean_traces = QCheckBox("Kasayı ayırınca izleri temizle (DoD Wipe)")
        self.chk_clean_traces.setChecked(self.config.get("cache_clean_on_dismount", True))
        grid_pref.addWidget(self.chk_clean_traces, 2, 0)

        self.chk_tray = QCheckBox("Küçültüldüğünde sistem tepsisine gizle")
        self.chk_tray.setChecked(self.config.get("minimize_to_tray_on_mount", False))
        grid_pref.addWidget(self.chk_tray, 2, 1)

        row_lock = QHBoxLayout()
        row_lock.setSpacing(6)
        self.chk_auto_lock = QCheckBox("Hareketsizlikte otomatik kilitle:")
        self.chk_auto_lock.setChecked(self.config.get("auto_lock_enabled", False))
        row_lock.addWidget(self.chk_auto_lock)

        self.combo_auto_lock_mins = QComboBox()
        self.combo_auto_lock_mins.addItems(["1 dk", "3 dk", "5 dk", "10 dk", "15 dk", "30 dk"])
        cur_mins = self.config.get("auto_lock_minutes", 5)
        self.combo_auto_lock_mins.setCurrentText(f"{cur_mins} dk")
        self.combo_auto_lock_mins.setEnabled(self.chk_auto_lock.isChecked())
        self.chk_auto_lock.toggled.connect(self.combo_auto_lock_mins.setEnabled)
        row_lock.addWidget(self.combo_auto_lock_mins)
        row_lock.addStretch()

        grid_pref.addLayout(row_lock, 3, 0)

        cp_layout.addLayout(grid_pref)
        c_layout.addWidget(card_pref)

        card_hello = QFrame()
        card_hello.setProperty("class", "card")
        chello_layout = QVBoxLayout(card_hello)
        chello_layout.setContentsMargins(16, 12, 16, 12)
        chello_layout.setSpacing(10)

        hello_hdr = QHBoxLayout()
        hello_hdr.setSpacing(8)
        lbl_hello_ico = QLabel()
        lbl_hello_ico.setPixmap(get_svg_pixmap("fingerprint", accent_col, 18))
        hello_hdr.addWidget(lbl_hello_ico)
        lbl_chello_title = QLabel("WINDOWS HELLO İKİ FAKTÖRLÜ DOĞRULAMA (2FA - ŞİFRE + BİYOMETRİK)")
        lbl_chello_title.setStyleSheet("font-size: 13px; font-weight: 700; letter-spacing: 0.5px; color: " + accent_col + ";")
        hello_hdr.addWidget(lbl_chello_title)
        hello_hdr.addStretch()
        chello_layout.addLayout(hello_hdr)

        hello_grid = QGridLayout()
        hello_grid.setHorizontalSpacing(24)
        hello_grid.setVerticalSpacing(8)

        self.chk_windows_hello = QCheckBox("Windows Hello İki Faktörlü Doğrulama (2FA) altyapısını etkinleştir")
        self.chk_windows_hello.setChecked(self.config.get("windows_hello_enabled", True))
        hello_grid.addWidget(self.chk_windows_hello, 0, 0)

        self.chk_require_2fa_all = QCheckBox("Tüm kasalarda 2FA'yı zorunlu kıl (Şifre + Biyometrik)")
        self.chk_require_2fa_all.setChecked(self.config.get("require_2fa_all_vaults", False))
        self.chk_require_2fa_all.setEnabled(self.chk_windows_hello.isChecked())
        self.chk_windows_hello.toggled.connect(self.chk_require_2fa_all.setEnabled)
        hello_grid.addWidget(self.chk_require_2fa_all, 0, 1)

        chello_layout.addLayout(hello_grid)

        status_row = QHBoxLayout()
        status_row.setSpacing(10)

        avail, status_str = windows_hello.is_windows_hello_available()
        status_txt = "[DURUM: HAZIR] Biyometrik veya Windows PIN doğrulaması kullanılabilir" if avail else f"[DURUM: {status_str}] Windows Hello yapılandırılmamış"
        self.lbl_hello_status = QLabel(status_txt)
        self.lbl_hello_status.setStyleSheet("font-size: 11px; opacity: 0.85;")
        status_row.addWidget(self.lbl_hello_status)
        status_row.addStretch()

        btn_clear_hello = QPushButton("Kayıtlı 2FA Ayarlarını Sıfırla")
        btn_clear_hello.setStyleSheet("font-size: 11px; padding: 4px 10px;")
        btn_clear_hello.clicked.connect(self.on_clear_hello_credentials)
        status_row.addWidget(btn_clear_hello)
        chello_layout.addLayout(status_row)

        c_layout.addWidget(card_hello)

        card_panic = QFrame()
        card_panic.setProperty("class", "card")
        cpan_layout = QVBoxLayout(card_panic)
        cpan_layout.setContentsMargins(16, 12, 16, 12)
        cpan_layout.setSpacing(8)

        lbl_cpan_title = QLabel("ACİL DURUM PANİK TUŞLARI (GLOBAL HOTKEY)")
        lbl_cpan_title.setStyleSheet("font-size: 13px; font-weight: 700; letter-spacing: 0.5px; color: " + accent_col + ";")
        cpan_layout.addWidget(lbl_cpan_title)

        panic_row = QHBoxLayout()
        panic_row.setSpacing(8)
        for key_text in ["Ctrl + Alt + L", "Ctrl + Shift + L", "Pause / Break"]:
            p_badge = QLabel(key_text)
            p_badge.setStyleSheet("""
                background-color: rgba(239, 68, 68, 0.14);
                color: #EF4444;
                font-family: -apple-system, 'SF Mono', 'Segoe UI Variable', monospace;
                font-size: 11px;
                font-weight: 700;
                padding: 4px 10px;
                border: 1px solid rgba(239, 68, 68, 0.35);
                border-radius: 8px;
            """)
            panic_row.addWidget(p_badge)
        panic_row.addStretch()
        cpan_layout.addLayout(panic_row)

        lbl_panic_info = QLabel("Basıldığı anda tüm açık kasalar zorla güvenle ayrılır, gezgin pencereleri kapatılır ve bellek sıfırlanır.")
        lbl_panic_info.setStyleSheet("font-size: 10.5px; opacity: 0.75;")
        cpan_layout.addWidget(lbl_panic_info)

        c_layout.addWidget(card_panic)

        scroll.setWidget(content)
        main_layout.addWidget(scroll, stretch=1)

        footer_row = QHBoxLayout()
        footer_row.setSpacing(10)

        self.lbl_saved_status = QLabel("")
        self.lbl_saved_status.setStyleSheet(f"font-size: 11px; font-weight: 600; color: {accent_col};")
        footer_row.addWidget(self.lbl_saved_status)

        footer_row.addStretch()

        btn_cancel = QPushButton("Kapat")
        btn_cancel.clicked.connect(self.close)
        footer_row.addWidget(btn_cancel)

        btn_save = QPushButton("Ayarları Kaydet")
        btn_save.setObjectName("btn-save-settings")
        btn_save.setStyleSheet(f"""
            QPushButton#btn-save-settings {{
                background-color: {accent_col};
                color: #FFFFFF;
                font-weight: 700;
                border: none;
                border-radius: 8px;
                padding: 7px 18px;
                min-width: 120px;
            }}
            QPushButton#btn-save-settings:hover {{
                opacity: 0.9;
            }}
        """)
        btn_save.clicked.connect(self.save_and_close)
        footer_row.addWidget(btn_save)

        main_layout.addLayout(footer_row)

    def switch_mode(self, mode: str):
        """Gece veya Gündüz moduna göre en uygun Apple temasını seçer."""
        if mode == "dark":
            if self.selected_theme in ("apple_light", "light"):
                new_theme = "apple_dark" if self.selected_theme == "apple_light" else "dark"
            else:
                new_theme = self.selected_theme
        else:
            if self.selected_theme in ("apple_dark", "dark"):
                new_theme = "apple_light" if self.selected_theme == "apple_dark" else "light"
            else:
                new_theme = self.selected_theme

        self.select_theme(new_theme)

    def select_theme(self, theme_id: str):
        """Temayı seçer, önizlemesini uygular ve UI kartlarını günceller."""
        self.selected_theme = theme_id
        self.apply_card_highlights()

        if self.main_window and hasattr(self.main_window, "apply_theme"):
            self.main_window.apply_theme(theme_id)

        self.theme_changed.emit(theme_id)
        self.config["theme"] = theme_id
        save_config(self.config)
        self.lbl_saved_status.setText("Tema uygulandı ve kaydedildi!")

    def apply_card_highlights(self):
        """Seçili tema kartının etrafına şık bir vurgu çerçevesi ekler."""
        is_dark = (self.selected_theme in ("dark", "apple_dark"))
        accent_col = "#2997FF" if self.selected_theme == "apple_dark" else ("#0071E3" if self.selected_theme == "apple_light" else ("#38BDF8" if self.selected_theme == "dark" else "#0284C7"))

        for t_info in self.THEMES_INFO:
            tid = t_info["id"]
            card = self.theme_card_frames.get(tid)
            chk = self.theme_check_labels.get(tid)
            if not card or not chk:
                continue

            if tid == self.selected_theme:
                card.setStyleSheet(f"""
                    QFrame#theme-card-{tid} {{
                        background-color: {'rgba(41, 151, 255, 0.10)' if tid == 'apple_dark' else ('rgba(0, 113, 227, 0.08)' if tid == 'apple_light' else ('rgba(56, 189, 248, 0.10)' if tid == 'dark' else 'rgba(12, 84, 120, 0.08)'))};
                        border: 2px solid {accent_col};
                        border-radius: 10px;
                    }}
                """)
                chk.setPixmap(get_svg_pixmap("check", accent_col, 16))
            else:
                border_c = "rgba(255, 255, 255, 0.08)" if is_dark else "rgba(0, 0, 0, 0.08)"
                card.setStyleSheet(f"""
                    QFrame#theme-card-{tid} {{
                        background-color: {'rgba(255, 255, 255, 0.03)' if is_dark else '#FFFFFF'};
                        border: 1px solid {border_c};
                        border-radius: 10px;
                    }}
                    QFrame#theme-card-{tid}:hover {{
                        border-color: {accent_col};
                    }}
                """)
                chk.clear()

        if hasattr(self, "btn_mode_dark") and hasattr(self, "btn_mode_light"):
            if is_dark:
                self.btn_mode_dark.setStyleSheet(f"background-color: {accent_col}; color: #FFFFFF; font-weight: 700; border-radius: 8px; padding: 4px 12px;")
                self.btn_mode_light.setStyleSheet("background: transparent; border: 1px solid rgba(255, 255, 255, 0.14); border-radius: 8px; padding: 4px 12px;")
            else:
                self.btn_mode_light.setStyleSheet(f"background-color: {accent_col}; color: #FFFFFF; font-weight: 700; border-radius: 8px; padding: 4px 12px;")
                self.btn_mode_dark.setStyleSheet("background: transparent; border: 1px solid rgba(0, 0, 0, 0.14); border-radius: 8px; padding: 4px 12px;")

    def on_clear_hello_credentials(self):
        """Kayıtlı tüm 2FA tercihlerini ve eski biyometrik kayıtları temizler."""
        ret = QMessageBox.question(
            self,
            "2FA Ayarlarını Sıfırla",
            "Tüm kasalara ait kaydedilmiş 2FA zorunluluk tercihleri ve eski biyometrik kayıtlar silinsin mi?\n\n"
            "(Kasa şifreleriniz etkilenmez, sadece 2FA tercihleri sıfırlanır.)",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        if ret == QMessageBox.StandardButton.Yes:
            avail, _ = windows_hello.is_windows_hello_available()
            if avail:
                is_ver, reason = windows_hello.request_windows_hello_verification(
                    "Enclave - Tüm 2FA Ayarlarını Sıfırlama Yetkilendirmesi"
                )
                if not is_ver:
                    QMessageBox.warning(self, "Yetkilendirme Başarısız", f"Biyometrik doğrulama onaylanmadı ({reason}).\n2FA ayarları sıfırlanmadı.")
                    return
            windows_hello.clear_all_2fa_settings()
            windows_hello.purge_all_saved_passwords()
            audit_logger.log_security_event("2FA_RESET", "WARNING", "Tüm 2FA tercihleri biyometrik onay ardından sıfırlandı.")
            QMessageBox.information(self, "Bilgi", "Kayıtlı tüm 2FA tercihleri ve kimlik verileri başarıyla temizlendi.")

    def save_and_close(self):
        """Tüm ayarları config sözlüğüne aktarır, diske kaydeder ve pencereyi kapatır."""
        self.config["theme"] = self.selected_theme
        self.config["auto_open_explorer"] = self.chk_auto_explorer.isChecked()
        self.config["autoplay_protection"] = self.chk_autoplay.isChecked()
        self.config["auto_dismount_on_close"] = self.chk_close_dismount.isChecked()
        self.config["lock_on_screen_lock"] = self.chk_lock_screen.isChecked()
        self.config["cache_clean_on_dismount"] = self.chk_clean_traces.isChecked()
        self.config["minimize_to_tray_on_mount"] = self.chk_tray.isChecked()
        self.config["auto_lock_enabled"] = self.chk_auto_lock.isChecked()
        self.config["windows_hello_enabled"] = self.chk_windows_hello.isChecked()
        self.config["require_2fa_all_vaults"] = getattr(self, "chk_require_2fa_all", None) and self.chk_require_2fa_all.isChecked()

        txt_mins = self.combo_auto_lock_mins.currentText().replace(" dk", "").strip()
        try:
            self.config["auto_lock_minutes"] = int(txt_mins)
        except Exception:
            pass

        save_config(self.config)

        if self.main_window:
            if hasattr(self.main_window, "chk_auto_explorer"):
                self.main_window.chk_auto_explorer.setChecked(self.chk_auto_explorer.isChecked())
            if hasattr(self.main_window, "chk_autoplay"):
                self.main_window.chk_autoplay.setChecked(self.chk_autoplay.isChecked())
            if hasattr(self.main_window, "chk_close_dismount"):
                self.main_window.chk_close_dismount.setChecked(self.chk_close_dismount.isChecked())
            if hasattr(self.main_window, "chk_lock_screen"):
                self.main_window.chk_lock_screen.setChecked(self.chk_lock_screen.isChecked())
            if hasattr(self.main_window, "chk_clean_traces"):
                self.main_window.chk_clean_traces.setChecked(self.chk_clean_traces.isChecked())
            if hasattr(self.main_window, "chk_tray"):
                self.main_window.chk_tray.setChecked(self.chk_tray.isChecked())
            if hasattr(self.main_window, "chk_auto_lock"):
                self.main_window.chk_auto_lock.setChecked(self.chk_auto_lock.isChecked())
            if hasattr(self.main_window, "apply_theme"):
                self.main_window.apply_theme(self.selected_theme)

        self.accept()

class Disable2FADialog(QDialog):
    """
    Kullanıcı bir kasadan 2FA korumasını kaldırmak istediğinde yetkisiz kapatmaları
    engellemek için Kasa Parolası (Faktör 1) ve Windows Hello Biyometrik Onayını (Faktör 2)
    birlikte zorunlu kılan güvenlik yetkilendirme penceresi.
    """
    def __init__(self, parent=None, vault_path: str = "", theme: str = "dark", engine=None, drive_letter: str = "", initial_password: str = ""):
        super().__init__(parent)
        self.main_window = parent
        self.vault_path = vault_path or ""
        self.theme = theme or "dark"
        self.engine = engine
        self.drive_letter = drive_letter or ""
        self.initial_password = initial_password or ""

        self.setWindowTitle("Enclave - 2FA Korumasını Kaldırma")
        self.setSizeGripEnabled(True)
        apply_dynamic_geometry(self, default_w=520, default_h=380, min_w=460, min_h=320)
        self.setup_ui()

    def setup_ui(self):
        pal = get_dialog_palette(self.theme)
        is_dark = pal["is_dark"]
        accent_col = pal["accent_col"]
        text_muted = pal["text_muted"]
        text_col = pal["text_col"]
        card_bg = pal["card_bg"]
        card_border = pal["card_border"]
        bg_col = pal["bg_col"]

        set_dialog_dark_mode(self, is_dark)
        self.setStyleSheet(f"""
            QDialog {{
                background-color: {bg_col};
                color: {text_col};
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
            }}
            QFrame.card, QFrame[class="card"] {{
                background-color: {card_bg};
                border: 1px solid {card_border};
                border-radius: 12px;
            }}
            QLabel {{
                color: {text_col};
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
            }}
            QLineEdit {{
                background-color: {'rgba(255, 255, 255, 0.06)' if is_dark else 'rgba(0, 0, 0, 0.04)'};
                border: 1px solid {card_border};
                border-radius: 8px;
                padding: 6px 10px;
                color: {text_col};
                font-size: 13px;
            }}
            QLineEdit:focus {{
                border: 1px solid {accent_col};
            }}
            {get_dialog_button_stylesheet(self.theme)}
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 20, 22, 20)
        layout.setSpacing(14)

        header_row = QHBoxLayout()
        header_row.setSpacing(12)
        lbl_icon = QLabel()
        lbl_icon.setPixmap(get_svg_pixmap("shield", accent_col, 28))
        header_row.addWidget(lbl_icon)

        title_box = QVBoxLayout()
        title_box.setSpacing(2)
        lbl_title = QLabel("2FA Korumasını Kaldırma Doğrulaması")
        lbl_title.setStyleSheet("font-size: 17px; font-weight: 800; letter-spacing: -0.3px;")
        v_name = Path(self.vault_path).name if self.vault_path else "Kasa"
        lbl_sub = QLabel(f"Hedef Kasa: {v_name}")
        lbl_sub.setStyleSheet(f"font-size: 12px; color: {text_muted};")
        title_box.addWidget(lbl_title)
        title_box.addWidget(lbl_sub)
        header_row.addLayout(title_box)
        header_row.addStretch()
        layout.addLayout(header_row)

        info_card = QFrame()
        info_card.setProperty("class", "card")
        info_layout = QVBoxLayout(info_card)
        info_layout.setContentsMargins(14, 12, 14, 12)
        info_layout.setSpacing(6)

        lbl_warn_title = QLabel("[GÜVENLİK PROTOKOLÜ]")
        lbl_warn_title.setStyleSheet("font-size: 12px; font-weight: 700; color: #F59E0B;")
        info_layout.addWidget(lbl_warn_title)

        lbl_warn_desc = QLabel(
            "Bu kasa için İki Faktörlü Doğrulamayı (2FA) devre dışı bırakmak güvenlik seviyesini düşürür. "
            "Yetkisiz kapatmaları önlemek için önce kasanın geçerli ana parolasını girmeli, "
            "ardından Windows Hello biyometrik doğrulamasını onaylamalısınız."
        )
        lbl_warn_desc.setWordWrap(True)
        lbl_warn_desc.setStyleSheet(f"font-size: 11.5px; color: {text_muted}; line-height: 1.4;")
        info_layout.addWidget(lbl_warn_desc)
        layout.addWidget(info_card)

        form_layout = QVBoxLayout()
        form_layout.setSpacing(6)
        lbl_pw = QLabel("Kasa Parolası (Faktör 1):")
        lbl_pw.setStyleSheet("font-size: 12px; font-weight: 600;")
        form_layout.addWidget(lbl_pw)

        pw_row = QHBoxLayout()
        pw_row.setSpacing(8)
        self.txt_pw = QLineEdit()
        self.txt_pw.setEchoMode(QLineEdit.EchoMode.Password)
        self.txt_pw.setPlaceholderText("Kasa parolasını girin...")
        if self.initial_password:
            self.txt_pw.setText(self.initial_password)
        self.txt_pw.returnPressed.connect(self.on_verify_and_disable)
        pw_row.addWidget(self.txt_pw)

        self.btn_toggle_pw = QPushButton("Göster")
        self.btn_toggle_pw.setCheckable(True)
        self.btn_toggle_pw.setMinimumHeight(32)
        self.btn_toggle_pw.setStyleSheet(f"font-size: 11px; padding: 4px 10px; border: 1px solid {card_border}; border-radius: 6px;")
        self.btn_toggle_pw.toggled.connect(lambda chk: self.txt_pw.setEchoMode(QLineEdit.EchoMode.Normal if chk else QLineEdit.EchoMode.Password))
        pw_row.addWidget(self.btn_toggle_pw)
        form_layout.addLayout(pw_row)

        self.lbl_error = QLabel("")
        self.lbl_error.setWordWrap(True)
        self.lbl_error.setStyleSheet("font-size: 11.5px; font-weight: 600; color: #EF4444;")
        self.lbl_error.hide()
        form_layout.addWidget(self.lbl_error)
        layout.addLayout(form_layout)

        layout.addStretch()

        btn_row = QHBoxLayout()
        btn_row.setSpacing(10)
        btn_row.addStretch()

        self.btn_cancel = QPushButton("İptal")
        self.btn_cancel.setMinimumHeight(34)
        self.btn_cancel.setStyleSheet(f"font-size: 12px; padding: 4px 16px; border: 1px solid {card_border}; border-radius: 8px;")
        self.btn_cancel.clicked.connect(self.reject)
        btn_row.addWidget(self.btn_cancel)

        self.btn_verify = QPushButton("Doğrula ve 2FA'yı Kapat")
        self.btn_verify.setMinimumHeight(34)
        self.btn_verify.setStyleSheet(f"font-size: 12px; font-weight: 700; padding: 4px 18px; background-color: #DC2626; color: #FFFFFF; border-radius: 8px;")
        self.btn_verify.clicked.connect(self.on_verify_and_disable)
        btn_row.addWidget(self.btn_verify)
        layout.addLayout(btn_row)

    def on_verify_and_disable(self):
        pw = self.txt_pw.text().strip()
        if not pw:
            self.lbl_error.setText("Lütfen kasa parolasını girin.")
            self.lbl_error.show()
            self.txt_pw.setFocus()
            return

        is_custom = False
        try:
            if self.vault_path and self.vault_path.lower().endswith(".pvault"):
                is_custom = True
            elif self.vault_path:
                with open(self.vault_path, "rb") as f:
                    is_custom = (f.read(8) == b"PVAULT01")
        except Exception:
            pass

        if is_custom:
            try:
                from enclave_core import CustomVaultEngine, InvalidPasswordError
                CustomVaultEngine.authenticate(self.vault_path, pw)
            except InvalidPasswordError:
                self.lbl_error.setText("Hatalı kasa parolası! 2FA koruması kaldırılamadı.")
                self.lbl_error.show()
                self.txt_pw.setFocus()
                return
            except Exception as e:
                self.lbl_error.setText(f"Doğrulama hatası: {e}")
                self.lbl_error.show()
                return
        else:
            if self.engine and self.drive_letter:
                try:
                    res = self.engine.unlock_bitlocker_password(self.drive_letter, pw)
                    if not res.get("success"):
                        self.lbl_error.setText(f"Hatalı BitLocker parolası: {res.get('error', 'Kilidi açılamadı')}")
                        self.lbl_error.show()
                        return
                except Exception as e:
                    self.lbl_error.setText(f"BitLocker doğrulama hatası: {e}")
                    self.lbl_error.show()
                    return

        v_name = Path(self.vault_path).name if self.vault_path else "Kasa"
        self.btn_verify.setEnabled(False)
        self.btn_verify.setText("Biyometrik Onay Bekleniyor...")
        self.lbl_error.hide()
        QApplication.processEvents()

        is_verified, reason = windows_hello.request_windows_hello_verification(
            f"Enclave - 2FA Kaldırma Yetkilendirmesi: '{v_name}' için parmak izinizi doğrulayın"
        )
        self.btn_verify.setEnabled(True)
        self.btn_verify.setText("Doğrula ve 2FA'yı Kapat")

        if is_verified:
            windows_hello.set_vault_2fa_enabled(self.vault_path, False)
            audit_logger.log_security_event("2FA_DISABLED", "WARNING", f"2FA koruması kimlik doğrulaması ardından kaldırıldı: {v_name}", self.vault_path)
            self.accept()
        else:
            self.lbl_error.setText(f"Biyometrik doğrulama onaylanmadı: {reason}\n2FA koruması aktif kalmaya devam ediyor.")
            self.lbl_error.show()

class TOTPSetupDialog(QDialog):
    """
    Kullanıcının kasanın içine RFC 6238 TOTP (Google / Microsoft Authenticator)
    ve tek kullanımlık Acil Kurtarma Kodlarını mühürlemesini sağlayan kurulum penceresi.
    """
    def __init__(self, parent=None, vault_path: str = "", theme: str = "dark", auth_info: dict = None, initial_password: str = "", is_creation_mode: bool = False):
        super().__init__(parent)
        self.main_window = parent
        self.vault_path = vault_path or ""
        self.theme = theme or "dark"
        self.auth_info = auth_info
        self.initial_password = initial_password or ""
        self.is_creation_mode = is_creation_mode

        self.totp_secret = totp_engine.generate_totp_secret(32)
        self.backup_codes = totp_engine.generate_backup_codes(8)
        vault_name = Path(self.vault_path).stem if self.vault_path else "Kasa"
        self.otpauth_uri = totp_engine.get_otpauth_uri(self.totp_secret, account_name=vault_name)

        self.setWindowTitle("Enclave - İki Faktörlü Doğrulama (TOTP) Kurulumu")
        self.setSizeGripEnabled(True)
        apply_dynamic_geometry(self, default_w=680, default_h=620, min_w=580, min_h=500)
        self.setup_ui()

    def setup_ui(self):
        pal = get_dialog_palette(self.theme)
        is_dark = pal["is_dark"]
        accent_col = pal["accent_col"]
        text_muted = pal["text_muted"]
        text_col = pal["text_col"]
        card_bg = pal["card_bg"]
        card_border = pal["card_border"]
        bg_col = pal["bg_col"]

        set_dialog_dark_mode(self, is_dark)
        self.setStyleSheet(f"""
            QDialog {{
                background-color: {bg_col};
                color: {text_col};
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
            }}
            QFrame.card, QFrame[class="card"] {{
                background-color: {card_bg};
                border: 1px solid {card_border};
                border-radius: 12px;
            }}
            QLabel {{
                color: {text_col};
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
            }}
            QLineEdit {{
                background-color: {'rgba(255, 255, 255, 0.06)' if is_dark else 'rgba(0, 0, 0, 0.04)'};
                border: 1px solid {card_border};
                border-radius: 8px;
                padding: 6px 10px;
                color: {text_col};
                font-size: 13px;
            }}
            QLineEdit:focus {{
                border: 1px solid {accent_col};
            }}
            QTextEdit {{
                background-color: {'rgba(255, 255, 255, 0.04)' if is_dark else 'rgba(0, 0, 0, 0.03)'};
                border: 1px solid {card_border};
                border-radius: 8px;
                color: {text_col};
                font-family: 'Consolas', 'Cascadia Code', monospace;
                font-size: 11.5px;
                padding: 6px;
            }}
            {get_dialog_button_stylesheet(self.theme)}
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 18, 22, 18)
        layout.setSpacing(12)

        header_row = QHBoxLayout()
        header_row.setSpacing(12)
        lbl_icon = QLabel()
        lbl_icon.setPixmap(get_svg_pixmap("shield", accent_col, 28))
        header_row.addWidget(lbl_icon)

        title_box = QVBoxLayout()
        title_box.setSpacing(2)
        lbl_title = QLabel("İki Faktörlü Doğrulama (TOTP) Kurulumu")
        lbl_title.setStyleSheet("font-size: 17px; font-weight: 800; letter-spacing: -0.3px;")
        v_name = Path(self.vault_path).name if self.vault_path else "Kasa"
        lbl_sub = QLabel(f"Hedef Kasa: {v_name} • Taşınabilir Konteyner Mühürlemesi")
        lbl_sub.setStyleSheet(f"font-size: 12px; color: {text_muted};")
        title_box.addWidget(lbl_title)
        title_box.addWidget(lbl_sub)
        header_row.addLayout(title_box)
        header_row.addStretch()
        layout.addLayout(header_row)

        if not self.auth_info and not self.is_creation_mode:
            pw_card = QFrame()
            pw_card.setProperty("class", "card")
            pw_layout = QVBoxLayout(pw_card)
            pw_layout.setContentsMargins(12, 10, 12, 10)
            pw_layout.setSpacing(6)

            lbl_pw_info = QLabel("2FA ayarını kasaya mühürlemek için geçerli kasa parolanızı giriniz:")
            lbl_pw_info.setStyleSheet("font-size: 11.5px; font-weight: 600;")
            pw_layout.addWidget(lbl_pw_info)

            self.txt_vault_pw = QLineEdit()
            self.txt_vault_pw.setEchoMode(QLineEdit.EchoMode.Password)
            self.txt_vault_pw.setPlaceholderText("Kasa parolası...")
            if self.initial_password:
                self.txt_vault_pw.setText(self.initial_password)
            pw_layout.addWidget(self.txt_vault_pw)
            layout.addWidget(pw_card)
        else:
            self.txt_vault_pw = None

        body_row = QHBoxLayout()
        body_row.setSpacing(14)

        qr_card = QFrame()
        qr_card.setProperty("class", "card")
        qr_layout = QVBoxLayout(qr_card)
        qr_layout.setContentsMargins(14, 12, 14, 12)
        qr_layout.setSpacing(8)
        qr_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        lbl_qr_title = QLabel("1. QR Kodu Tarayın")
        lbl_qr_title.setStyleSheet("font-size: 12px; font-weight: 700; text-align: center;")
        lbl_qr_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        qr_layout.addWidget(lbl_qr_title)

        lbl_qr_img = QLabel()
        lbl_qr_img.setAlignment(Qt.AlignmentFlag.AlignCenter)
        qr_pix = totp_engine.generate_qr_pixmap(self.otpauth_uri, size=190)
        if qr_pix:
            lbl_qr_img.setPixmap(qr_pix)
        else:
            lbl_qr_img.setText("[QR Kod Desteği Bulunamadı]")
        qr_layout.addWidget(lbl_qr_img)

        lbl_qr_help = QLabel("Google Authenticator veya\nMicrosoft Authenticator ile tarayın")
        lbl_qr_help.setStyleSheet(f"font-size: 11px; color: {text_muted}; text-align: center;")
        lbl_qr_help.setAlignment(Qt.AlignmentFlag.AlignCenter)
        qr_layout.addWidget(lbl_qr_help)
        body_row.addWidget(qr_card, stretch=1)

        info_card = QFrame()
        info_card.setProperty("class", "card")
        info_layout = QVBoxLayout(info_card)
        info_layout.setContentsMargins(14, 12, 14, 12)
        info_layout.setSpacing(8)

        lbl_key_title = QLabel("2. Manuel Gizli Anahtar")
        lbl_key_title.setStyleSheet("font-size: 12px; font-weight: 700;")
        info_layout.addWidget(lbl_key_title)

        formatted_secret = totp_engine.format_secret_for_display(self.totp_secret)
        self.txt_key = QLineEdit(formatted_secret)
        self.txt_key.setReadOnly(True)
        self.txt_key.setStyleSheet(f"font-family: 'Consolas', monospace; font-size: 12px; color: {accent_col};")
        info_layout.addWidget(self.txt_key)

        btn_copy_key = QPushButton("Gizli Anahtarı Kopyala")
        btn_copy_key.setMinimumHeight(28)
        btn_copy_key.setStyleSheet(f"font-size: 11px; padding: 3px 8px; border: 1px solid {card_border}; border-radius: 6px;")
        btn_copy_key.clicked.connect(self.on_copy_secret)
        info_layout.addWidget(btn_copy_key)

        lbl_backup_title = QLabel("Acil Durum Kurtarma Kodları (Tek Kullanımlık):")
        lbl_backup_title.setStyleSheet("font-size: 11.5px; font-weight: 700; margin-top: 4px;")
        info_layout.addWidget(lbl_backup_title)

        self.txt_backups = QTextEdit()
        self.txt_backups.setReadOnly(True)
        codes_text = "\n".join(f"• {c}" for c in self.backup_codes)
        self.txt_backups.setText(codes_text)
        self.txt_backups.setMaximumHeight(85)
        info_layout.addWidget(self.txt_backups)

        btn_copy_backups = QPushButton("Yedek Kodları Kopyala")
        btn_copy_backups.setMinimumHeight(28)
        btn_copy_backups.setStyleSheet(f"font-size: 11px; padding: 3px 8px; border: 1px solid {card_border}; border-radius: 6px;")
        btn_copy_backups.clicked.connect(self.on_copy_backups)
        info_layout.addWidget(btn_copy_backups)

        body_row.addWidget(info_card, stretch=1)
        layout.addLayout(body_row)

        verify_card = QFrame()
        verify_card.setProperty("class", "card")
        verify_layout = QVBoxLayout(verify_card)
        verify_card.setStyleSheet(f"border: 1px solid {accent_col}; border-radius: 10px;")
        verify_layout.setContentsMargins(14, 10, 14, 10)
        verify_layout.setSpacing(6)

        lbl_verify_title = QLabel("3. Kurulumu Doğrulayın:")
        lbl_verify_title.setStyleSheet("font-size: 12px; font-weight: 700;")
        verify_layout.addWidget(lbl_verify_title)

        confirm_row = QHBoxLayout()
        confirm_row.setSpacing(10)

        lbl_prompt = QLabel("Telefonunuzdaki 6 haneli kod:")
        lbl_prompt.setStyleSheet("font-size: 12px;")
        confirm_row.addWidget(lbl_prompt)

        self.txt_confirm_code = QLineEdit()
        self.txt_confirm_code.setMaxLength(6)
        self.txt_confirm_code.setPlaceholderText("000000")
        self.txt_confirm_code.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.txt_confirm_code.setStyleSheet(f"font-size: 16px; font-weight: 800; letter-spacing: 4px; color: {accent_col}; padding: 4px;")
        self.txt_confirm_code.setMaximumWidth(140)
        self.txt_confirm_code.returnPressed.connect(self.on_verify_and_save)
        confirm_row.addWidget(self.txt_confirm_code)
        confirm_row.addStretch()

        verify_layout.addLayout(confirm_row)

        self.lbl_error = QLabel("")
        self.lbl_error.setWordWrap(True)
        self.lbl_error.setStyleSheet("font-size: 11.5px; font-weight: 600; color: #EF4444;")
        self.lbl_error.hide()
        verify_layout.addWidget(self.lbl_error)

        layout.addWidget(verify_card)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(10)
        btn_row.addStretch()

        self.btn_cancel = QPushButton("İptal")
        self.btn_cancel.setMinimumHeight(34)
        self.btn_cancel.setStyleSheet(f"font-size: 12px; padding: 4px 16px; border: 1px solid {card_border}; border-radius: 8px;")
        self.btn_cancel.clicked.connect(self.reject)
        btn_row.addWidget(self.btn_cancel)

        self.btn_confirm = QPushButton("2FA'yı Doğrula ve Kasaya Mühürle")
        self.btn_confirm.setMinimumHeight(34)
        self.btn_confirm.setStyleSheet(f"font-size: 12px; font-weight: 700; padding: 4px 18px; background-color: {accent_col}; color: #FFFFFF; border-radius: 8px;")
        self.btn_confirm.clicked.connect(self.on_verify_and_save)
        btn_row.addWidget(self.btn_confirm)
        layout.addLayout(btn_row)

    def on_copy_secret(self):
        QApplication.clipboard().setText(self.totp_secret)
        QMessageBox.information(self, "Kopyalandı", "TOTP gizli anahtarı panoya kopyalandı.")

    def on_copy_backups(self):
        text = "\n".join(self.backup_codes)
        QApplication.clipboard().setText(text)
        QMessageBox.information(self, "Kopyalandı", "Acil durum kurtarma kodları panoya kopyalandı.\nLütfen bu kodları güvenli bir yerde saklayın.")

    def on_verify_and_save(self):
        code = self.txt_confirm_code.text().strip().replace(" ", "")
        if len(code) != 6 or not code.isdigit():
            self.lbl_error.setText("Lütfen telefonunuzdaki 6 haneli doğrulama kodunu girin.")
            self.lbl_error.show()
            self.txt_confirm_code.setFocus()
            return

        if not totp_engine.verify_totp_token(self.totp_secret, code):
            self.lbl_error.setText("Hatalı doğrulama kodu! Lütfen uygulamanızdaki güncel kodu kontrol edip tekrar deneyin.")
            self.lbl_error.show()
            self.txt_confirm_code.setFocus()
            return

        if self.is_creation_mode:
            self.accept()
            return

        auth_info = self.auth_info
        if not auth_info:
            if not self.txt_vault_pw:
                self.lbl_error.setText("Kasa parolası gereklidir.")
                self.lbl_error.show()
                return
            pw = self.txt_vault_pw.text()
            if not pw:
                self.lbl_error.setText("Lütfen kasa parolanızı girin.")
                self.lbl_error.show()
                self.txt_vault_pw.setFocus()
                return
            try:
                from enclave_core import _derive_key
                auth_info = CustomVaultEngine.authenticate(self.vault_path, pw)
            except InvalidPasswordError:
                self.lbl_error.setText("Kasa parolası hatalı! 2FA ayarlanamadı.")
                self.lbl_error.show()
                self.txt_vault_pw.setFocus()
                return
            except Exception as e:
                self.lbl_error.setText(f"Doğrulama hatası: {e}")
                self.lbl_error.show()
                return

        try:
            CustomVaultEngine.set_vault_2fa_config(
                self.vault_path,
                auth_info,
                enabled=True,
                totp_secret=self.totp_secret,
                backup_codes=self.backup_codes
            )
            audit_logger.log_security_event(
                "2FA_CONFIGURED",
                "SUCCESS",
                f"TOTP İki Faktörlü Doğrulama kasaya başarıyla mühürlendi: {Path(self.vault_path).name}",
                self.vault_path
            )
            self.accept()
        except Exception as e:
            self.lbl_error.setText(f"2FA mühürleme hatası: {e}")
            self.lbl_error.show()

class TOTPVerificationDialog(QDialog):
    """
    Kasa kilidi açılırken kullanıcıdan Google / Microsoft Authenticator 6 haneli kodunu
    veya Acil Durum Kurtarma Kodunu isteyen doğrulama penceresi.
    """
    def __init__(self, parent=None, vault_path: str = "", auth_info: dict = None, theme: str = "dark"):
        super().__init__(parent)
        self.main_window = parent
        self.vault_path = vault_path or ""
        self.auth_info = auth_info or {}
        self.theme = theme or "dark"
        self.is_recovery_mode = False

        self.setWindowTitle("Enclave - İki Faktörlü Doğrulama (2FA)")
        self.setSizeGripEnabled(True)
        apply_dynamic_geometry(self, default_w=480, default_h=360, min_w=420, min_h=300)
        self.setup_ui()

    def setup_ui(self):
        pal = get_dialog_palette(self.theme)
        is_dark = pal["is_dark"]
        accent_col = pal["accent_col"]
        text_muted = pal["text_muted"]
        text_col = pal["text_col"]
        card_bg = pal["card_bg"]
        card_border = pal["card_border"]
        bg_col = pal["bg_col"]

        set_dialog_dark_mode(self, is_dark)
        self.setStyleSheet(f"""
            QDialog {{
                background-color: {bg_col};
                color: {text_col};
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
            }}
            QFrame.card, QFrame[class="card"] {{
                background-color: {card_bg};
                border: 1px solid {card_border};
                border-radius: 12px;
            }}
            QLabel {{
                color: {text_col};
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
            }}
            QLineEdit {{
                background-color: {'rgba(255, 255, 255, 0.06)' if is_dark else 'rgba(0, 0, 0, 0.04)'};
                border: 1px solid {card_border};
                border-radius: 8px;
                padding: 6px 10px;
                color: {text_col};
            }}
            QLineEdit:focus {{
                border: 1px solid {accent_col};
            }}
            {get_dialog_button_stylesheet(self.theme)}
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 20, 22, 20)
        layout.setSpacing(14)

        header_row = QHBoxLayout()
        header_row.setSpacing(12)
        lbl_icon = QLabel()
        lbl_icon.setPixmap(get_svg_pixmap("shield", accent_col, 28))
        header_row.addWidget(lbl_icon)

        title_box = QVBoxLayout()
        title_box.setSpacing(2)
        lbl_title = QLabel("İki Faktörlü Doğrulama (2FA)")
        lbl_title.setStyleSheet("font-size: 17px; font-weight: 800; letter-spacing: -0.3px;")
        v_name = Path(self.vault_path).name if self.vault_path else "Kasa"
        lbl_sub = QLabel(f"Kasa: {v_name} • Kasa Parolası Doğrulandı")
        lbl_sub.setStyleSheet(f"font-size: 12px; color: {text_muted};")
        title_box.addWidget(lbl_title)
        title_box.addWidget(lbl_sub)
        header_row.addLayout(title_box)
        header_row.addStretch()
        layout.addLayout(header_row)

        info_card = QFrame()
        info_card.setProperty("class", "card")
        info_layout = QVBoxLayout(info_card)
        info_layout.setContentsMargins(14, 12, 14, 12)
        info_layout.setSpacing(6)

        self.lbl_prompt = QLabel(
            "Lütfen akıllı telefonunuzdaki kimlik doğrulayıcı uygulamada (Google Authenticator, Microsoft Authenticator) "
            "görüntülenen 6 haneli tek kullanımlık kodu giriniz."
        )
        self.lbl_prompt.setWordWrap(True)
        self.lbl_prompt.setStyleSheet(f"font-size: 12px; color: {text_muted}; line-height: 1.4;")
        info_layout.addWidget(self.lbl_prompt)
        layout.addWidget(info_card)

        input_box = QVBoxLayout()
        input_box.setSpacing(8)
        input_box.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.txt_code = QLineEdit()
        self.txt_code.setMaxLength(6)
        self.txt_code.setPlaceholderText("000000")
        self.txt_code.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.txt_code.setStyleSheet(f"font-size: 22px; font-weight: 800; letter-spacing: 6px; color: {accent_col}; padding: 6px;")
        self.txt_code.setMinimumWidth(180)
        self.txt_code.setMaximumWidth(260)
        self.txt_code.returnPressed.connect(self.on_verify_code)
        input_box.addWidget(self.txt_code)

        self.lbl_error = QLabel("")
        self.lbl_error.setWordWrap(True)
        self.lbl_error.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.lbl_error.setStyleSheet("font-size: 12px; font-weight: 600; color: #EF4444;")
        self.lbl_error.hide()
        input_box.addWidget(self.lbl_error)
        layout.addLayout(input_box)

        alt_row = QHBoxLayout()
        alt_row.setSpacing(8)

        self.btn_toggle_recovery = QPushButton("Kurtarma Kodu Kullan (Acil Durum)")
        self.btn_toggle_recovery.setStyleSheet(f"font-size: 11px; color: {accent_col}; border: none; background: transparent; text-decoration: underline;")
        self.btn_toggle_recovery.clicked.connect(self.on_toggle_recovery_mode)
        alt_row.addWidget(self.btn_toggle_recovery)

        is_hello_avail, _ = windows_hello.is_windows_hello_available()
        if is_hello_avail:
            alt_row.addStretch()
            self.btn_hello = QPushButton("Windows Hello ile Onayla")
            self.btn_hello.setStyleSheet(f"font-size: 11px; padding: 3px 8px; border: 1px solid {card_border}; border-radius: 6px;")
            self.btn_hello.clicked.connect(self.on_verify_with_hello)
            alt_row.addWidget(self.btn_hello)
        else:
            self.btn_hello = None

        layout.addLayout(alt_row)
        layout.addStretch()

        btn_row = QHBoxLayout()
        btn_row.setSpacing(10)
        btn_row.addStretch()

        self.btn_cancel = QPushButton("İptal")
        self.btn_cancel.setMinimumHeight(34)
        self.btn_cancel.setStyleSheet(f"font-size: 12px; padding: 4px 16px; border: 1px solid {card_border}; border-radius: 8px;")
        self.btn_cancel.clicked.connect(self.reject)
        btn_row.addWidget(self.btn_cancel)

        self.btn_verify = QPushButton("Doğrula ve Kilidi Aç")
        self.btn_verify.setMinimumHeight(34)
        self.btn_verify.setStyleSheet(f"font-size: 12px; font-weight: 700; padding: 4px 18px; background-color: {accent_col}; color: #FFFFFF; border-radius: 8px;")
        self.btn_verify.clicked.connect(self.on_verify_code)
        btn_row.addWidget(self.btn_verify)
        layout.addLayout(btn_row)

        QTimer.singleShot(100, self.txt_code.setFocus)

    def on_toggle_recovery_mode(self):
        self.is_recovery_mode = not self.is_recovery_mode
        if self.is_recovery_mode:
            self.lbl_prompt.setText("Telefonunuza erişemiyorsanız, 2FA kurulumunda verilen 8 haneli tek kullanımlık Acil Durum Kurtarma Kodunu (XXXX-XXXX formatında) giriniz.")
            self.txt_code.setMaxLength(19)
            self.txt_code.setPlaceholderText("XXXX-XXXX")
            self.txt_code.setStyleSheet(f"font-size: 16px; font-weight: 700; letter-spacing: 2px; color: {get_dialog_palette(self.theme)['accent_col']}; padding: 6px;")
            self.btn_toggle_recovery.setText("6 Haneli TOTP Koduna Geri Dön")
        else:
            self.lbl_prompt.setText("Lütfen kimlik doğrulayıcı uygulamanızdaki 6 haneli kodu giriniz.")
            self.txt_code.setMaxLength(6)
            self.txt_code.setPlaceholderText("000000")
            self.txt_code.setStyleSheet(f"font-size: 22px; font-weight: 800; letter-spacing: 6px; color: {get_dialog_palette(self.theme)['accent_col']}; padding: 6px;")
            self.btn_toggle_recovery.setText("Kurtarma Kodu Kullan (Acil Durum)")
        self.txt_code.clear()
        self.txt_code.setFocus()

    def on_verify_with_hello(self):
        v_name = Path(self.vault_path).name if self.vault_path else "Kasa"
        is_verified, reason = windows_hello.request_windows_hello_verification(
            f"Enclave 2FA Doğrulaması: '{v_name}' kilidini açmak için parmak izinizi okutun"
        )
        if is_verified:
            audit_logger.log_security_event("2FA_VERIFIED", "SUCCESS", f"2FA Windows Hello ile onaylandı: {v_name}", self.vault_path)
            self.accept()
        else:
            self.lbl_error.setText(f"Windows Hello onayı reddedildi veya iptal edildi: {reason}")
            self.lbl_error.show()

    def on_verify_code(self):
        code = self.txt_code.text().strip()
        if not code:
            self.lbl_error.setText("Lütfen kodu giriniz.")
            self.lbl_error.show()
            self.txt_code.setFocus()
            return

        ok, msg = CustomVaultEngine.verify_vault_2fa(self.vault_path, self.auth_info, code)
        if ok:
            audit_logger.log_security_event(
                "2FA_VERIFIED",
                "SUCCESS",
                f"2FA TOTP/Kurtarma kodu başarıyla onaylandı: {Path(self.vault_path).name} ({msg})",
                self.vault_path
            )
            self.accept()
        else:
            self.lbl_error.setText("Doğrulama kodu veya kurtarma kodu hatalı! Lütfen tekrar deneyiniz.")
            self.lbl_error.show()
            self.txt_code.setFocus()

class HeaderBackupRestoreDialog(QDialog):
    """
    Ayrılmış Başlık Yedeği ve Kurtarma Penceresi (Detached Header Backup & Restore).
    - Custom Vault (.pvault) 256 baytlık anahtar ve yuva başlığını şifreli/doğrulanmış dışa aktarma ve hasarlı kasayı onarma.
    - BitLocker ve VHD sanal diskleri için VHD footer/header denetimi ve BitLocker 48 haneli kurtarma sertifikası üretimi.
    """

    def __init__(self, parent=None, vault_path: str = "", theme: str = "dark", engine=None):
        super().__init__(parent)
        self.main_window = parent
        self.vault_path = vault_path or ""
        self.current_theme = theme or "dark"
        self.engine = engine

        self.setWindowTitle("Ayrılmış Başlık Yedeği & Kurtarma (Header Backup & Restore)")
        self.setSizeGripEnabled(True)
        apply_dynamic_geometry(self, default_w=720, default_h=620, min_w=620, min_h=480)

        self.setup_ui()
        if self.vault_path:
            self.txt_export_vault.setText(self.vault_path)
            self.txt_restore_vault.setText(self.vault_path)
            self.txt_vhd_path.setText(self.vault_path)
            self.on_export_vault_changed()

    def setup_ui(self):
        pal = get_dialog_palette(self.current_theme)
        is_dark = pal["is_dark"]
        accent_col = pal["accent_col"]
        text_muted = pal["text_muted"]
        text_col = pal["text_col"]
        card_bg = pal["card_bg"]
        card_border = pal["card_border"]
        bg_col = pal["bg_col"]

        set_dialog_dark_mode(self, is_dark)
        self.setStyleSheet(f"""
            QDialog {{
                background-color: {bg_col};
                color: {text_col};
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
            }}
            QTabWidget::pane {{
                border: 1px solid {card_border};
                background: {card_bg};
                border-radius: 8px;
            }}
            QTabBar::tab {{
                background: transparent;
                color: {text_muted};
                padding: 8px 16px;
                font-weight: 600;
                font-size: 12px;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
            }}
            QTabBar::tab:selected {{
                color: {accent_col};
                border-bottom: 2px solid {accent_col};
                font-weight: 700;
            }}
            QFrame.card, QFrame[class="card"] {{
                background-color: {card_bg};
                border: 1px solid {card_border};
                border-radius: 10px;
            }}
            QLabel {{
                color: {text_col};
            }}
            QLineEdit {{
                background-color: {'rgba(255, 255, 255, 0.05)' if is_dark else '#FFFFFF'};
                color: {text_col};
                border: 1px solid {card_border};
                border-radius: 6px;
                padding: 6px 10px;
                font-size: 12px;
            }}
            QLineEdit:focus {{
                border: 1px solid {accent_col};
            }}
            QTextEdit {{
                background-color: {'#141416' if is_dark else '#F8FAFC'};
                color: {text_col};
                border: 1px solid {card_border};
                border-radius: 6px;
                font-family: 'JetBrains Mono', 'Consolas', monospace;
                font-size: 11px;
                padding: 8px;
            }}
            {get_dialog_button_stylesheet(self.current_theme)}
        """)

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(18, 16, 18, 16)
        main_layout.setSpacing(12)

        header_row = QHBoxLayout()
        header_row.setSpacing(12)
        lbl_icon = QLabel()
        lbl_icon.setPixmap(get_svg_pixmap("header_backup", accent_col, 28))
        header_row.addWidget(lbl_icon)

        title_box = QVBoxLayout()
        title_box.setSpacing(2)
        lbl_title = QLabel("Ayrılmış Başlık Yedeği & Acil Kurtarma")
        lbl_title.setStyleSheet("font-size: 18px; font-weight: 800; letter-spacing: -0.2px;")
        lbl_sub = QLabel("PVAULT (.pvault) ve VHD/BitLocker kasalarının kritik başlıklarını çevrimdışı yedekleme ve onarma")
        lbl_sub.setStyleSheet(f"font-size: 12px; color: {text_muted};")
        lbl_sub.setWordWrap(True)
        title_box.addWidget(lbl_title)
        title_box.addWidget(lbl_sub)
        header_row.addLayout(title_box)
        header_row.addStretch()
        main_layout.addLayout(header_row)

        self.tabs = QTabWidget()

        tab_export = QWidget()
        self.setup_tab_export(tab_export, pal)
        self.tabs.addTab(tab_export, "Başlık Yedeği Al (Dışa Aktar)")

        tab_restore = QWidget()
        self.setup_tab_restore(tab_restore, pal)
        self.tabs.addTab(tab_restore, "Başlık Yedeğinden Geri Yükle")

        tab_vhd = QWidget()
        self.setup_tab_vhd(tab_vhd, pal)
        self.tabs.addTab(tab_vhd, "BitLocker & VHD Kurtarma")

        main_layout.addWidget(self.tabs, stretch=1)

        footer_row = QHBoxLayout()
        footer_row.addStretch()
        btn_close = QPushButton("Kapat")
        btn_close.clicked.connect(self.close)
        footer_row.addWidget(btn_close)
        main_layout.addLayout(footer_row)

    def setup_tab_export(self, tab: QWidget, pal: dict):
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(12)

        lbl_kasa = QLabel("Kaynak Kasa Dosyası:")
        lbl_kasa.setStyleSheet("font-weight: 600; font-size: 12px;")
        layout.addWidget(lbl_kasa)

        kasa_row = QHBoxLayout()
        kasa_row.setSpacing(8)
        self.txt_export_vault = QLineEdit()
        self.txt_export_vault.setPlaceholderText("Yedeklenecek .pvault veya .vhd/.vhdx kasa dosyasını seçin...")
        self.txt_export_vault.textChanged.connect(self.on_export_vault_changed)
        kasa_row.addWidget(self.txt_export_vault, stretch=1)

        btn_browse_vault = QPushButton("Gözat...")
        btn_browse_vault.clicked.connect(self.browse_export_vault)
        kasa_row.addWidget(btn_browse_vault)
        layout.addLayout(kasa_row)

        self.lbl_export_format = QLabel("[BİLGİ] Lütfen geçerli bir kasa dosyası seçiniz.")
        self.lbl_export_format.setStyleSheet(f"font-size: 11px; color: {pal['text_muted']};")
        layout.addWidget(self.lbl_export_format)

        self.card_export_opts = QFrame()
        self.card_export_opts.setProperty("class", "card")
        c_layout = QVBoxLayout(self.card_export_opts)
        c_layout.setContentsMargins(12, 10, 12, 10)
        c_layout.setSpacing(8)

        self.chk_export_protect = QCheckBox("Başlık yedeğini parola ile şifrele (AES-256-GCM + PBKDF2)")
        self.chk_export_protect.setChecked(False)
        self.chk_export_protect.toggled.connect(self.toggle_export_password_fields)
        c_layout.addWidget(self.chk_export_protect)

        self.lbl_export_hint = QLabel("Not: Parola seçilmezse başlık yedeği kriptografik AEAD mührü ile korunur; yetkisiz değişiklik anında tespit edilir.")
        self.lbl_export_hint.setStyleSheet(f"font-size: 11px; color: {pal['text_muted']};")
        self.lbl_export_hint.setWordWrap(True)
        c_layout.addWidget(self.lbl_export_hint)

        self.box_pw_fields = QWidget()
        box_pw_layout = QGridLayout(self.box_pw_fields)
        box_pw_layout.setContentsMargins(0, 4, 0, 0)
        box_pw_layout.setHorizontalSpacing(10)
        box_pw_layout.setVerticalSpacing(6)

        lbl_p1 = QLabel("Yedek Parolası:")
        lbl_p1.setStyleSheet("font-size: 11.5px;")
        self.txt_export_p1 = QLineEdit()
        self.txt_export_p1.setEchoMode(QLineEdit.EchoMode.Password)
        self.txt_export_p1.setPlaceholderText("Yedeği şifrelemek için parola...")
        box_pw_layout.addWidget(lbl_p1, 0, 0)
        box_pw_layout.addWidget(self.txt_export_p1, 0, 1)

        lbl_p2 = QLabel("Parola (Tekrar):")
        lbl_p2.setStyleSheet("font-size: 11.5px;")
        self.txt_export_p2 = QLineEdit()
        self.txt_export_p2.setEchoMode(QLineEdit.EchoMode.Password)
        self.txt_export_p2.setPlaceholderText("Parolayı tekrar yazın...")
        box_pw_layout.addWidget(lbl_p2, 1, 0)
        box_pw_layout.addWidget(self.txt_export_p2, 1, 1)

        self.box_pw_fields.hide()
        c_layout.addWidget(self.box_pw_fields)
        layout.addWidget(self.card_export_opts)

        lbl_target = QLabel("Hedef Ayrılmış Başlık Dosyası:")
        lbl_target.setStyleSheet("font-weight: 600; font-size: 12px;")
        layout.addWidget(lbl_target)

        target_row = QHBoxLayout()
        target_row.setSpacing(8)
        self.txt_export_target = QLineEdit()
        self.txt_export_target.setPlaceholderText("Yedek dosyasının kaydedileceği konumu seçin...")
        target_row.addWidget(self.txt_export_target, stretch=1)

        btn_browse_target = QPushButton("Kaydet...")
        btn_browse_target.clicked.connect(self.browse_export_target)
        target_row.addWidget(btn_browse_target)
        layout.addLayout(target_row)

        btn_do_export = QPushButton("Başlık Yedeğini Oluştur ve Dışa Aktar")
        btn_do_export.setIcon(get_svg_icon("header_backup", "#FFFFFF", 16))
        btn_do_export.setStyleSheet(f"""
            QPushButton {{
                background-color: {pal['accent_col']};
                color: #FFFFFF;
                font-weight: 700;
                padding: 8px 16px;
                border-radius: 6px;
            }}
            QPushButton:hover {{
                opacity: 0.9;
            }}
        """)
        btn_do_export.clicked.connect(self.execute_export_header)
        layout.addWidget(btn_do_export)

        self.txt_export_log = QTextEdit()
        self.txt_export_log.setReadOnly(True)
        self.txt_export_log.setPlaceholderText("Başlık yedekleme işlem raporu ve SHA-256 sağlama özeti burada görüntülenecektir...")
        layout.addWidget(self.txt_export_log, stretch=1)

    def toggle_export_password_fields(self, checked: bool):
        self.box_pw_fields.setVisible(checked)

    def browse_export_vault(self):
        f, _ = QFileDialog.getOpenFileName(
            self,
            "Yedeklenecek Kasa Dosyasını Seçin",
            str(Path.home()),
            "Tüm Kasa Dosyaları (*.pvault *.vhd *.vhdx);;PVAULT Bağımsız Kasa (*.pvault);;VHD / VHDX Konteyner (*.vhd *.vhdx);;Tüm Dosyalar (*.*)"
        )
        if f:
            self.txt_export_vault.setText(f)

    def on_export_vault_changed(self):
        vp = self.txt_export_vault.text().strip()
        if not vp or not Path(vp).exists():
            self.lbl_export_format.setText("[BİLGİ] Lütfen geçerli bir kasa dosyası seçiniz.")
            return

        p = Path(vp)
        ext = p.suffix.lower()
        if ext == ".pvault":
            self.lbl_export_format.setText(f"[PVAULT TESPİT EDİLDİ] Bağımsız AES-256-GCM Kasa ({p.name})")
            self.txt_export_target.setText(str(p.with_suffix(".vheader")))
            self.card_export_opts.show()
        elif ext in (".vhd", ".vhdx"):
            self.lbl_export_format.setText(f"[VHD SANAL DİSK TESPİT EDİLDİ] Microsoft VHD/VHDX Konteyneri ({p.name})")
            self.txt_export_target.setText(str(p.with_suffix(".vhdheader")))
            self.card_export_opts.hide()
        else:
            self.lbl_export_format.setText(f"[ÖZEL FORMAT] {p.name}")
            self.txt_export_target.setText(str(p.with_suffix(".vheader")))
            self.card_export_opts.show()

    def browse_export_target(self):
        vp = self.txt_export_vault.text().strip()
        ext = Path(vp).suffix.lower() if vp else ".pvault"
        def_ext = ".vhdheader" if ext in (".vhd", ".vhdx") else ".vheader"
        f, _ = QFileDialog.getSaveFileName(
            self,
            "Başlık Yedeğini Kaydet",
            self.txt_export_target.text() or str(Path.home() / f"Kasa_Baslik_Yedegi{def_ext}"),
            f"Başlık Yedeği (*{def_ext});;Tüm Dosyalar (*.*)"
        )
        if f:
            self.txt_export_target.setText(f)

    def execute_export_header(self):
        vp = self.txt_export_vault.text().strip()
        target = self.txt_export_target.text().strip()

        if not vp or not Path(vp).exists():
            QMessageBox.warning(self, "Uyarı", "Lütfen geçerli bir kaynak kasa dosyası seçin.")
            return
        if not target:
            QMessageBox.warning(self, "Uyarı", "Lütfen yedeğin kaydedileceği hedef dosya yolunu belirtin.")
            return

        p = Path(vp)
        ext = p.suffix.lower()

        if ext == ".pvault" or (ext not in (".vhd", ".vhdx")):
            pwd = None
            if self.chk_export_protect.isChecked():
                p1 = self.txt_export_p1.text()
                p2 = self.txt_export_p2.text()
                if not p1:
                    QMessageBox.warning(self, "Uyarı", "Lütfen yedek için bir parola belirleyin veya parola korumasını kapatın.")
                    return
                if p1 != p2:
                    QMessageBox.warning(self, "Uyarı", "Girdiğiniz yedek parolaları birbiriyle eşleşmiyor!")
                    return
                pwd = p1

            try:
                res = CustomVaultEngine.export_header_backup(vp, target, backup_password=pwd)
                log_msg = (
                    f"[ONAYLANDI] PVAULT AYRILMIŞ BAŞLIK YEDEĞİ BAŞARIYLA OLUŞTURULDU\n"
                    f"--------------------------------------------------------------------------------\n"
                    f"Kaynak Kasa       : {res['vault_filename']}\n"
                    f"Hedef Yedek       : {res['backup_path']}\n"
                    f"Başlık SHA-256    : {res['header_sha256']}\n"
                    f"Koruma Türü       : {'Parola Korumalı (AES-256-GCM + PBKDF2)' if res['is_protected'] else 'Kriptografik AEAD Mühürlü (Tam Bütünlük)'}\n"
                    f"Yedek Dosya Boyutu: {res['backup_size']} bayt\n"
                    f"--------------------------------------------------------------------------------\n"
                    f"Bu yedek dosyasını güvenli harici bir depolama biriminde (USB bellek vb.) saklayınız.\n"
                    f"Kasa dosyanızın başlığı bozulsa veya fidye yazılımı ilk bloğu ezse dahi kasanızı tamamen kurtarabilirsiniz."
                )
                self.txt_export_log.setText(log_msg)
                audit_logger.log_security_event("HEADER_BACKUP_EXPORTED", "SUCCESS", f"Başlık yedeği alındı: {res['backup_path']}", res['vault_filename'])
                QMessageBox.information(self, "Başarılı", "Ayrılmış başlık yedeği başarıyla oluşturuldu!")
            except Exception as e:
                self.txt_export_log.setText(f"[HATA] Başlık yedeği oluşturulamadı:\n{e}")
                QMessageBox.critical(self, "Hata", f"Başlık yedeği oluşturulamadı:\n{e}")

        else:
            try:
                from engine import VHDEngine
                res = VHDEngine.backup_vhd_header_footer(vp, target)
                if res.get("success"):
                    log_msg = (
                        f"[ONAYLANDI] VHD BAŞLIK VE ALTBİLGİ YEDEĞİ OLUŞTURULDU\n"
                        f"--------------------------------------------------------------------------------\n"
                        f"VHD Dosyası       : {res['vhd_filename']}\n"
                        f"Hedef Yedek       : {res['backup_path']}\n"
                        f"Başlık SHA-256    : {res['head_sha256']}\n"
                        f"Altbilgi SHA-256  : {res['foot_sha256']}\n"
                        f"Yedek Dosya Boyutu: {res['backup_size']} bayt\n"
                        f"--------------------------------------------------------------------------------\n"
                        f"VHD footer ve dinamik disk blokları ayrılmış güvenli kapsülde yedeklendi."
                    )
                    self.txt_export_log.setText(log_msg)
                    audit_logger.log_security_event("VHD_HEADER_BACKUP_EXPORTED", "SUCCESS", f"VHD başlık yedeği alındı: {res['backup_path']}", res['vhd_filename'])
                    QMessageBox.information(self, "Başarılı", "VHD başlık ve altbilgi yedeği başarıyla oluşturuldu!")
                else:
                    self.txt_export_log.setText(f"[HATA] VHD yedeği oluşturulamadı:\n{res.get('error')}")
                    QMessageBox.critical(self, "Hata", f"Yedekleme başarısız:\n{res.get('error')}")
            except Exception as e:
                self.txt_export_log.setText(f"[HATA] {e}")
                QMessageBox.critical(self, "Hata", str(e))

    def setup_tab_restore(self, tab: QWidget, pal: dict):
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(12)

        lbl_target = QLabel("Hedef (Onarılacak / Hasarlı) Kasa Dosyası:")
        lbl_target.setStyleSheet("font-weight: 600; font-size: 12px;")
        layout.addWidget(lbl_target)

        target_row = QHBoxLayout()
        target_row.setSpacing(8)
        self.txt_restore_vault = QLineEdit()
        self.txt_restore_vault.setPlaceholderText("Onarılacak .pvault veya .vhd dosyasını seçin...")
        target_row.addWidget(self.txt_restore_vault, stretch=1)
        btn_browse_v = QPushButton("Gözat...")
        btn_browse_v.clicked.connect(self.browse_restore_vault)
        target_row.addWidget(btn_browse_v)
        layout.addLayout(target_row)

        lbl_bak = QLabel("Ayrılmış Başlık Yedek Dosyası (.vheader / .vhdheader):")
        lbl_bak.setStyleSheet("font-weight: 600; font-size: 12px;")
        layout.addWidget(lbl_bak)

        bak_row = QHBoxLayout()
        bak_row.setSpacing(8)
        self.txt_restore_backup = QLineEdit()
        self.txt_restore_backup.setPlaceholderText("Geri yüklenecek .vheader veya .vhdheader yedek dosyasını seçin...")
        bak_row.addWidget(self.txt_restore_backup, stretch=1)
        btn_browse_b = QPushButton("Gözat...")
        btn_browse_b.clicked.connect(self.browse_restore_backup)
        bak_row.addWidget(btn_browse_b)
        layout.addLayout(bak_row)

        pwd_row = QHBoxLayout()
        pwd_row.setSpacing(8)
        lbl_pwd = QLabel("Yedek Parolası (Eğer parola ile korunmuşsa):")
        lbl_pwd.setStyleSheet("font-size: 11.5px;")
        pwd_row.addWidget(lbl_pwd)
        self.txt_restore_pwd = QLineEdit()
        self.txt_restore_pwd.setEchoMode(QLineEdit.EchoMode.Password)
        self.txt_restore_pwd.setPlaceholderText("Parola korumalı yedeğin parolasını yazın...")
        pwd_row.addWidget(self.txt_restore_pwd, stretch=1)
        layout.addLayout(pwd_row)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(10)

        btn_inspect = QPushButton("Yedeği ve Kasa Başlığını İncele (Doğrula)")
        btn_inspect.setIcon(get_svg_icon("info", pal['accent_col'], 15))
        btn_inspect.clicked.connect(self.execute_inspect_backup)
        btn_row.addWidget(btn_inspect)

        btn_do_restore = QPushButton("Başlığı Kasaya Geri Yükle (Kurtar)")
        btn_do_restore.setIcon(get_svg_icon("header_restore", "#FFFFFF", 15))
        btn_do_restore.setStyleSheet("""
            QPushButton {
                background-color: #059669;
                color: #FFFFFF;
                font-weight: 700;
                padding: 7px 16px;
                border-radius: 6px;
            }
            QPushButton:hover {
                background-color: #10B981;
            }
        """)
        btn_do_restore.clicked.connect(self.execute_restore_header)
        btn_row.addWidget(btn_do_restore)

        layout.addLayout(btn_row)

        self.txt_restore_log = QTextEdit()
        self.txt_restore_log.setReadOnly(True)
        self.txt_restore_log.setPlaceholderText("Başlık analizi, bütünlük denetimi ve onarım raporu burada görüntülenecektir...")
        layout.addWidget(self.txt_restore_log, stretch=1)

    def browse_restore_vault(self):
        f, _ = QFileDialog.getOpenFileName(
            self,
            "Onarılacak Kasa Dosyasını Seçin",
            str(Path.home()),
            "Tüm Kasa Dosyaları (*.pvault *.vhd *.vhdx);;PVAULT Kasa (*.pvault);;VHD / VHDX (*.vhd *.vhdx);;Tüm Dosyalar (*.*)"
        )
        if f:
            self.txt_restore_vault.setText(f)

    def browse_restore_backup(self):
        f, _ = QFileDialog.getOpenFileName(
            self,
            "Ayrılmış Başlık Yedek Dosyasını Seçin",
            str(Path.home()),
            "Başlık Yedekleri (*.vheader *.vhdheader *.key *.vbak);;PVAULT Başlık Yedeği (*.vheader);;VHD Başlık Yedeği (*.vhdheader);;Tüm Dosyalar (*.*)"
        )
        if f:
            self.txt_restore_backup.setText(f)

    def execute_inspect_backup(self):
        bak_file = self.txt_restore_backup.text().strip(' "\'')
        vault_file = self.txt_restore_vault.text().strip(' "\'')
        pwd = self.txt_restore_pwd.text().strip() or None

        if not bak_file or not Path(bak_file).exists():
            QMessageBox.warning(self, "Uyarı", "Lütfen geçerli bir başlık yedek dosyası seçin.")
            return

        lines = ["=== BAŞLIK YEDEĞİ VE KASA İNCELEME RAPORU ==="]

        if vault_file and Path(vault_file).exists():
            v_ext = Path(vault_file).suffix.lower()
            if v_ext == ".pvault":
                v_chk = CustomVaultEngine.verify_header(vault_file)
                if v_chk["valid"]:
                    lines.append(f"[KASA BAŞLIĞI]: SAĞLAM ({v_chk['header_size']} bayt, SHA: {v_chk['header_sha256'][:16]}...)")
                else:
                    lines.append(f"[KASA BAŞLIĞI]: HASARLI VEYA BOZULMUŞ! ({v_chk['error']})")
            elif v_ext in (".vhd", ".vhdx"):
                from engine import VHDEngine
                v_chk = VHDEngine.verify_vhd_structure(vault_file)
                if v_chk["valid"]:
                    lines.append(f"[VHD YAPISI]: SAĞLAM ({v_chk.get('details')})")
                else:
                    lines.append(f"[VHD YAPISI]: HASARLI! ({v_chk.get('error')})")
        else:
            lines.append("[KASA DURUMU]: Hedef kasa henüz seçilmedi veya dosya mevcut değil.")

        bak_ext = Path(bak_file).suffix.lower()
        if bak_ext in (".vheader", ".key") or (bak_ext not in (".vhdheader", ".vbak")):
            insp = CustomVaultEngine.inspect_header_backup(bak_file, backup_password=pwd)
            if insp["valid"]:
                lines.append(f"[YEDEK DURUMU]: DOĞRULANDI (PVAULT Başlığı, {insp['header_size']} bayt)")
                lines.append(f"  • Orijinal Kasa Adı : {insp.get('vault_filename')}")
                lines.append(f"  • Başlık SHA-256     : {insp.get('header_sha256')}")
                lines.append(f"  • Koruma Türü        : {'Parola Korumalı (AES-256-GCM)' if insp.get('is_protected') else 'Kriptografik Doğrulanmış'}")
                lines.append(f"  • Bütünlük Durumu    : [KUSURSUZ] Tahrifat veya bozulma yok")
            else:
                lines.append(f"[YEDEK DURUMU]: GEÇERSİZ / AÇILAMADI ({insp.get('error')})")
        else:
            from engine import VHDEngine
            v_insp = VHDEngine.inspect_vhd_header_footer(bak_file)
            if v_insp["valid"]:
                v_mb = v_insp.get('vhd_size', 0) // (1024 * 1024)
                lines.append(f"[YEDEK DURUMU]: DOĞRULANDI (VHD/VHDX Yapısal Başlık & Altbilgi Arşivi)")
                lines.append(f"  • Orijinal Disk Adı  : {v_insp.get('vhd_filename')}")
                lines.append(f"  • Sanal Disk Boyutu  : {v_mb} MB")
                lines.append(f"  • Başlık SHA-256     : {v_insp.get('head_sha256')[:20]}...")
                lines.append(f"  • Altbilgi SHA-256   : {v_insp.get('foot_sha256')[:20]}...")
                lines.append(f"  • Bütünlük Durumu    : [KUSURSUZ] SHA-256 ve zlib sıkıştırma bütünlüğü mühürlü")
            else:
                lines.append(f"[YEDEK DURUMU]: GEÇERSİZ / HASARLI ({v_insp.get('error')})")

        self.txt_restore_log.setText("\n".join(lines))

    def execute_restore_header(self):
        bak_file = self.txt_restore_backup.text().strip(' "\'')
        vault_file = self.txt_restore_vault.text().strip(' "\'')
        pwd = self.txt_restore_pwd.text().strip() or None

        if not vault_file or not Path(vault_file).exists():
            QMessageBox.warning(self, "Uyarı", "Lütfen onarılacak hedef kasa dosyasını seçin.")
            return
        if not bak_file or not Path(bak_file).exists():
            QMessageBox.warning(self, "Uyarı", "Lütfen geçerli bir başlık yedek dosyası seçin.")
            return

        bak_ext = Path(bak_file).suffix.lower()
        v_ext = Path(vault_file).suffix.lower()

        if v_ext == ".pvault" and bak_ext in (".vhdheader", ".vbak"):
            QMessageBox.warning(self, "Biçim Uyuşmazlığı", "Hedef dosya PVAULT (.pvault) formatındadır, ancak seçilen yedek bir VHD/VHDX başlık yedeğidir.\nLütfen .vheader biçiminde bir yedek dosyası seçin.")
            return
        if v_ext in (".vhd", ".vhdx") and bak_ext in (".vheader", ".key"):
            QMessageBox.warning(self, "Biçim Uyuşmazlığı", "Hedef dosya VHD/VHDX sanal diskidir, ancak seçilen yedek bir PVAULT başlık yedeğidir.\nLütfen .vhdheader biçiminde bir yedek dosyası seçin.")
            return

        v_name = Path(vault_file).name
        confirm = QMessageBox.question(
            self,
            "Başlığı Geri Yükle",
            f"DİKKAT: '{v_name}' dosyasının mevcut başlığı ayrılmış yedek ile üzerine yazılacaktır.\n\n"
            f"Bu işlem kasayı orijinal durumuna geri döndürür.\n\n"
            f"İşlemi onaylıyor musunuz?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return

        if v_ext == ".pvault" or (bak_ext in (".vheader", ".key")):
            try:
                res = CustomVaultEngine.restore_header_backup(vault_file, bak_file, backup_password=pwd)
                log_msg = (
                    f"[BAŞARILI] PVAULT KASA BAŞLIĞI KUSURSUZ GERİ YÜKLENDİ\n"
                    f"--------------------------------------------------------------------------------\n"
                    f"Onarılan Kasa  : {res['vault_path']}\n"
                    f"Geri Yüklenen  : {res['restored_bytes']} bayt başlık\n"
                    f"Başlık SHA-256 : {res['header_sha256']}\n"
                    f"--------------------------------------------------------------------------------\n"
                    f"Kasa başlığı fiziksel diske zorlanarak (fsync) atomik olarak onarıldı.\n"
                    f"Artık kasanızı parolanızla normal şekilde açabilirsiniz."
                )
                self.txt_restore_log.setText(log_msg)
                audit_logger.log_security_event("HEADER_BACKUP_RESTORED", "SUCCESS", f"Başlık geri yüklendi: {vault_file}", v_name)
                QMessageBox.information(self, "Kurtarma Başarılı", "Kasa başlığı başarıyla geri yüklendi ve doğrulandı!\nKasayı artık açabilirsiniz.")
            except InvalidPasswordError as e:
                self.txt_restore_log.setText(f"[PAROLA HATASI] {e}")
                QMessageBox.critical(self, "Parola Hatası", str(e))
            except Exception as e:
                self.txt_restore_log.setText(f"[HATA] Kurtarma başarısız:\n{e}")
                QMessageBox.critical(self, "Hata", f"Başlık geri yüklenemedi:\n{e}")

        else:
            try:
                from engine import VHDEngine
                res = VHDEngine.restore_vhd_header_footer(vault_file, bak_file)
                if res.get("success"):
                    v_info = res.get("verification", {})
                    log_msg = (
                        f"[BAŞARILI] VHD BAŞLIK VE ALTBİLGİ GERİ YÜKLENDİ\n"
                        f"--------------------------------------------------------------------------------\n"
                        f"Onarılan VHD   : {res['vhd_path']}\n"
                        f"Yapısal Durum  : {v_info.get('details', 'Doğrulandı')}\n"
                        f"--------------------------------------------------------------------------------\n"
                        f"VHD footer ve dinamik bloklar başarıyla onarıldı."
                    )
                    self.txt_restore_log.setText(log_msg)
                    audit_logger.log_security_event("VHD_HEADER_RESTORED", "SUCCESS", f"VHD başlığı onarıldı: {vault_file}", v_name)
                    QMessageBox.information(self, "Kurtarma Başarılı", "VHD başlık ve altbilgisi başarıyla geri yüklendi!")
                else:
                    self.txt_restore_log.setText(f"[HATA] {res.get('error')}")
                    QMessageBox.critical(self, "Hata", str(res.get('error')))
            except Exception as e:
                self.txt_restore_log.setText(f"[HATA] {e}")
                QMessageBox.critical(self, "Hata", str(e))

    def setup_tab_vhd(self, tab: QWidget, pal: dict):
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(12)

        lbl_vhd_sec = QLabel("1. VHD / VHDX Sanal Disk Yapısal Doğrulama")
        lbl_vhd_sec.setStyleSheet("font-weight: 700; font-size: 13px; color: " + pal['accent_col'] + ";")
        layout.addWidget(lbl_vhd_sec)

        vhd_row = QHBoxLayout()
        vhd_row.setSpacing(8)
        self.txt_vhd_path = QLineEdit()
        self.txt_vhd_path.setPlaceholderText("Doğrulanacak .vhd veya .vhdx dosyasını seçin...")
        vhd_row.addWidget(self.txt_vhd_path, stretch=1)
        btn_browse_vhd = QPushButton("Gözat...")
        btn_browse_vhd.clicked.connect(self.browse_vhd_path)
        vhd_row.addWidget(btn_browse_vhd)
        btn_verify_vhd = QPushButton("Yapıyı Doğrula")
        btn_verify_vhd.setIcon(get_svg_icon("shield", pal['accent_col'], 14))
        btn_verify_vhd.clicked.connect(self.execute_verify_vhd)
        vhd_row.addWidget(btn_verify_vhd)
        layout.addLayout(vhd_row)

        lbl_bde_sec = QLabel("2. BitLocker 48 Haneli Kurtarma Anahtarını Dışa Aktar")
        lbl_bde_sec.setStyleSheet("font-weight: 700; font-size: 13px; color: " + pal['accent_col'] + ";")
        layout.addWidget(lbl_bde_sec)

        bde_row = QHBoxLayout()
        bde_row.setSpacing(8)
        lbl_dl = QLabel("Bağlı Sürücü:")
        lbl_dl.setStyleSheet("font-size: 11.5px;")
        bde_row.addWidget(lbl_dl)

        self.combo_bde_drive = QComboBox()
        for letter in "DEFGHIJKLMNOPQRSTUVWXYZ":
            if Path(f"{letter}:\\").exists():
                self.combo_bde_drive.addItem(f"{letter}:")
        if self.combo_bde_drive.count() == 0:
            self.combo_bde_drive.addItem("X:")

        parent_dl = getattr(self.main_window, "drive_letter", "")
        if parent_dl:
            clean_pdl = parent_dl.rstrip(":\\/ ").upper() + ":"
            idx = self.combo_bde_drive.findText(clean_pdl)
            if idx >= 0:
                self.combo_bde_drive.setCurrentIndex(idx)

        bde_row.addWidget(self.combo_bde_drive)

        btn_export_bde = QPushButton("Resmi Kurtarma Sertifikası Olarak Dışa Aktar (.txt)")
        btn_export_bde.setIcon(get_svg_icon("key", pal['accent_col'], 14))
        btn_export_bde.clicked.connect(self.execute_export_bitlocker_cert)
        bde_row.addWidget(btn_export_bde)
        bde_row.addStretch()
        layout.addLayout(bde_row)

        self.txt_vhd_log = QTextEdit()
        self.txt_vhd_log.setReadOnly(True)
        self.txt_vhd_log.setPlaceholderText("VHD/VHDX yapısal kontrol ve BitLocker işlem raporu...")
        layout.addWidget(self.txt_vhd_log, stretch=1)

    def browse_vhd_path(self):
        f, _ = QFileDialog.getOpenFileName(
            self,
            "VHD/VHDX Dosyasını Seçin",
            str(Path.home()),
            "VHD / VHDX Konteyner (*.vhd *.vhdx);;Tüm Dosyalar (*.*)"
        )
        if f:
            self.txt_vhd_path.setText(f)

    def execute_verify_vhd(self):
        vp = self.txt_vhd_path.text().strip()
        if not vp or not Path(vp).exists():
            QMessageBox.warning(self, "Uyarı", "Lütfen geçerli bir VHD/VHDX dosyası seçin.")
            return

        from engine import VHDEngine
        res = VHDEngine.verify_vhd_structure(vp)
        if res.get("valid"):
            report = (
                f"[ONAYLANDI] SANAL DİSK YAPISI GEÇERLİ VE SAĞLAM\n"
                f"--------------------------------------------------------------------------------\n"
                f"Format         : {res.get('format')}\n"
                f"Disk Türü      : {res.get('disk_type', 'N/A')}\n"
                f"Sanal Boyut    : {res.get('virtual_size', 0) // (1024*1024)} MB\n"
                f"Fiziksel Boyut : {res.get('file_size', 0) // (1024*1024)} MB\n"
                f"Sağlama Toplamı: {'[GEÇERLİ - Checksum Match]' if res.get('checksum_ok') else '[UYARI - Checksum Mismatch]'}\n"
                f"Dinamik Başlık : {'[SAĞLAM]' if res.get('dynamic_header_ok') else '[YOK / SABİT DİSK]'}\n"
                f"--------------------------------------------------------------------------------\n"
                f"Ayrıntı        : {res.get('details')}"
            )
            self.txt_vhd_log.setText(report)
        else:
            self.txt_vhd_log.setText(f"[UYARI / BOZUK] Yapısal denetim başarısız:\n{res.get('error')}")

    def execute_export_bitlocker_cert(self):
        drive = self.combo_bde_drive.currentText().strip(":\\ ")
        if not drive:
            QMessageBox.warning(self, "Uyarı", "Lütfen bir sürücü harfi seçin.")
            return

        target_f, _ = QFileDialog.getSaveFileName(
            self,
            "BitLocker Kurtarma Sertifikasını Kaydet",
            str(Path.home() / f"BitLocker_Kurtarma_Sertifikasi_{drive}.txt"),
            "Metin Belgesi (*.txt);;Tüm Dosyalar (*.*)"
        )
        if not target_f:
            return

        try:
            from engine import VHDEngine
            eng = self.engine or VHDEngine()
            res = eng.export_bitlocker_recovery_key_file(drive, target_f, vault_name=f"{drive}: Sürücüsü")
            if res.get("success"):
                log_txt = (
                    f"[ONAYLANDI] BİTLOCKER RESMİ KURTARMA SERTİFİKASI DIŞA AKTARILDI\n"
                    f"--------------------------------------------------------------------------------\n"
                    f"Sürücü         : {drive}:\n"
                    f"Dosya Yolu     : {res['export_path']}\n"
                    f"Kurtarma Parolası: {res['recovery_key']}\n"
                    f"--------------------------------------------------------------------------------\n"
                    f"Sertifika güvenle diske kaydedildi ve fsync ile yazıldı."
                )
                self.txt_vhd_log.setText(log_txt)
                audit_logger.log_security_event("BITLOCKER_CERT_EXPORTED", "SUCCESS", f"BitLocker sertifikası dışa aktarıldı ({drive}:)", f"{drive}:")
                QMessageBox.information(self, "Başarılı", f"BitLocker kurtarma sertifikası başarıyla kaydedildi:\n{res['export_path']}")
            else:
                self.txt_vhd_log.setText(f"[HATA] Kurtarma anahtarı alınamadı:\n{res.get('error')}")
                QMessageBox.critical(self, "Hata", f"Kurtarma anahtarı alınamadı:\n{res.get('error')}")
        except Exception as e:
            self.txt_vhd_log.setText(f"[HATA] {e}")
            QMessageBox.critical(self, "Hata", str(e))

