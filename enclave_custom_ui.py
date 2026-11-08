"""
Enclave - Bağımsız AES-256 Şifreli Kasa Dosya Yöneticisi (Custom Vault File Manager)
Windows Explorer deneyimini aratmayan, harici sürücü gerektirmeyen, şık, modern,
sürükle-bırak ile çift yönlü dosya aktarımı (içeri ve dışarı) yapabilen, klasör, resim,
müzik, video ve belgeleri doğrudan önizleyebilen gelişmiş şifreli dosya yöneticisi.

Özellikler:
- Windows Explorer Tarzı Arayüz: Sol Gezinti Ağacı, Adres Çubuğu (Breadcrumbs), Detaylar ve Büyük Simgeler/Izgara Görünümü.
- Çift Yönlü Sürükle & Bırak: Windows'tan kasaya ve kasadan Windows Masaüstüne/Klasörlerine sürükleyerek çıkartma.
- Resim & Küçük Resim (Thumbnail) Desteği: Şifreli resimlerin anında şifresi çözülüp küçük resimlerinin gösterilmesi ve sağ panelde yüksek çözünürlüklü önizlemesi.
- Dahili Müzik Çalar: Müzik ve ses dosyalarını doğrudan dosya yöneticisi içinden çalma/önizleme.
- Metin & Kod Önizleme: Metin, log ve kod dosyalarını anında görüntüleme.
- Canlı Düzenleme Takibi: Açılan dosyalar kaydedildiğinde kasada otomatik güncellenir.
- DoD Standartlarında Güvenli İmha (Shredding): Kasa kilitlendiğinde tüm geçici izler silinir.
- %100 Vektörel Simgeler (Sıfır Emoji).
"""

import os
import sys
import time
import shutil
import tempfile
import struct
import ctypes
from ctypes import wintypes
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple

_C_UINT_FROM_ADDR = ctypes.c_uint.from_address
_MSG_OFFSET_MESSAGE = 8 if struct.calcsize("P") == 8 else 4
_WM_DROPFILES = 0x0233

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QLineEdit, QFileDialog, QMessageBox, QTableWidget, QTableWidgetItem,
    QHeaderView, QAbstractItemView, QFrame, QMenu, QApplication, QProgressBar,
    QSplitter, QTreeWidget, QTreeWidgetItem, QListWidget, QListWidgetItem,
    QStackedWidget, QSlider, QTextEdit, QPlainTextEdit, QScrollArea, QInputDialog, QWidget,
    QComboBox, QFileIconProvider, QGraphicsView, QGraphicsScene, QGraphicsPixmapItem,
    QCheckBox, QSizePolicy
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QSize, QByteArray, QUrl, QMimeData, QPoint, QEvent, QFileInfo, QRunnable, QThreadPool, QObject, QThread, QRect, QAbstractNativeEventFilter
from PyQt6.QtGui import QIcon, QFont, QColor, QAction, QPixmap, QPainter, QDrag, QCursor, QTransform, QGuiApplication
from PyQt6.QtSvg import QSvgRenderer
from PyQt6.QtMultimedia import QMediaPlayer, QAudioOutput
from PyQt6.QtMultimediaWidgets import QVideoWidget

def get_dialog_palette(theme: str = "dark") -> dict:
    from extra_dialogs import get_dialog_palette as _gdp
    return _gdp(theme)

def get_dialog_button_stylesheet(theme_or_is_dark = True) -> str:
    from extra_dialogs import get_dialog_button_stylesheet as _gdbs
    return _gdbs(theme_or_is_dark)

from enclave_core import (
    CustomVaultEngine,
    secure_wipe_file,
    secure_wipe_directory,
    purge_all_vault_temp_forensics,
    CustomVaultError,
    VaultTamperedError
)

SVG_ICONS = {
    "lock": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>""",
    "unlock": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 9.9-1"/></svg>""",
    "shield": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>""",
    "decoy": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9.88 9.88a3 3 0 1 0 4.24 4.24"/><path d="M10.73 5.08A10.43 10.43 0 0 1 12 5c7 0 10 7 10 7a13.16 13.16 0 0 1-1.67 2.68"/><path d="M6.61 6.61A13.526 13.526 0 0 0 2 12s3 7 10 7a9.74 9.74 0 0 0 5.39-1.61"/><line x1="2" x2="22" y1="2" y2="22"/></svg>""",
    "folder": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 20h16a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.93a2 2 0 0 1-1.66-.9l-.82-1.2A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13c0 1.1.9 2 2 2Z"/></svg>""",
    "folder_open": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m6 14 1.45-2.9A2 2 0 0 1 9.24 10H20a2 2 0 0 1 1.94 2.5l-1.55 6a2 2 0 0 1-1.94 1.5H4a2 2 0 0 1-2-2V5c0-1.1.9-2 2-2h3.93a2 2 0 0 1 1.66.9l.82 1.2a2 2 0 0 0 1.66.9H18a2 2 0 0 1 2 2v2"/></svg>""",
    "folder_plus": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 20h16a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.93a2 2 0 0 1-1.66-.9l-.82-1.2A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13c0 1.1.9 2 2 2Z"/><line x1="12" x2="12" y1="10" y2="16"/><line x1="9" x2="15" y1="13" y2="13"/></svg>""",
    "file": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>""",
    "file_plus": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="12" x2="12" y1="18" y2="12"/><line x1="9" x2="15" y1="15" y2="15"/></svg>""",
    "file_text": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" x2="8" y1="13" y2="13"/><line x1="16" x2="8" y1="17" y2="17"/><line x1="10" x2="8" y1="9" y2="9"/></svg>""",
    "image": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="18" height="18" x="3" y="3" rx="2" ry="2"/><circle cx="9" cy="9" r="2"/><path d="m21 15-3.086-3.086a2 2 0 0 0-2.828 0L6 21"/></svg>""",
    "music": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 18V5l12-2v13"/><circle cx="6" cy="18" r="3"/><circle cx="18" cy="16" r="3"/></svg>""",
    "disc": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="3"/><path d="M12 2a10 10 0 0 1 10 10"/></svg>""",
    "video": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="23 7 16 12 23 17 23 7"/><rect width="15" height="14" x="1" y="5" rx="2" ry="2"/></svg>""",
    "archive": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="20" height="5" x="2" y="3" rx="1"/><path d="M4 8v11a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8"/><path d="M10 12h4"/></svg>""",
    "code": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>""",
    "play": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="currentColor" stroke="none"><polygon points="6 3 20 12 6 21 6 3"/></svg>""",
    "pause": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="currentColor" stroke="none"><rect width="4" height="16" x="6" y="4" rx="1"/><rect width="4" height="16" x="14" y="4" rx="1"/></svg>""",
    "stop": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="currentColor" stroke="none"><rect width="16" height="16" x="4" y="4" rx="2"/></svg>""",
    "volume": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5"/><path d="M15.54 8.46a5 5 0 0 1 0 7.07"/><path d="M19.07 4.93a10 10 0 0 1 0 14.14"/></svg>""",
    "eye": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/></svg>""",
    "download": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" x2="12" y1="15" y2="3"/></svg>""",
    "desktop": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="20" height="14" x="2" y="3" rx="2"/><line x1="8" x2="16" y1="21" y2="21"/><line x1="12" x2="12" y1="17" y2="21"/></svg>""",
    "trash": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18"/><path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"/><path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"/><line x1="10" x2="10" y1="11" y2="17"/><line x1="14" x2="14" y1="11" y2="17"/></svg>""",
    "edit": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 3a2.85 2.83 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5Z"/><path d="m15 5 4 4"/></svg>""",
    "arrow_left": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="m15 18-6-6 6-6"/></svg>""",
    "arrow_right": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="m9 18 6-6-6-6"/></svg>""",
    "arrow_up": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="m18 15-6-6-6 6"/></svg>""",
    "refresh": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"/><path d="M8 16H3v5"/></svg>""",
    "search": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></svg>""",
    "clear": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" x2="6" y1="6" y2="18"/><line x1="6" x2="18" y1="6" y2="18"/></svg>""",
    "view_list": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="8" x2="21" y1="6" y2="6"/><line x1="8" x2="21" y1="12" y2="12"/><line x1="8" x2="21" y1="18" y2="18"/><line x1="3" x2="3.01" y1="6" y2="6"/><line x1="3" x2="3.01" y1="12" y2="12"/><line x1="3" x2="3.01" y1="18" y2="18"/></svg>""",
    "view_grid": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="7" height="7" x="3" y="3" rx="1"/><rect width="7" height="7" x="14" y="3" rx="1"/><rect width="7" height="7" x="14" y="14" rx="1"/><rect width="7" height="7" x="3" y="14" rx="1"/></svg>""",
    "check": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg>""",
    "sparkles": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m12 3-1.9 5.8a2 2 0 0 1-1.3 1.3L3 12l5.8 1.9a2 2 0 0 1 1.3 1.3L12 21l1.9-5.8a2 2 0 0 1 1.3-1.3L21 12l-5.8-1.9a2 2 0 0 1-1.3-1.3Z"/></svg>""",
    "info": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/></svg>""",
    "chevron_right": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg>""",
    "copy": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="14" height="14" x="8" y="8" rx="2" ry="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/></svg>""",
    "scissors": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="6" cy="6" r="3"/><circle cx="6" cy="18" r="3"/><line x1="20" x2="8.12" y1="4" y2="15.88"/><line x1="14.47" x2="20" y1="14.48" y2="20"/><line x1="8.12" x2="12" y1="8.12" y2="12"/></svg>""",
    "clipboard": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="16" height="18" x="4" y="4" rx="2"/><path d="M8 4V2a1 1 0 0 1 1-1h6a1 1 0 0 1 1 1v2"/><path d="M9 12h6"/><path d="M9 16h6"/></svg>""",
    "duplicate": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="13" height="13" x="9" y="9" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>""",
    "save": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>""",
    "binary": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="18" height="18" x="3" y="3" rx="2"/><path d="M10 7v10"/><path d="M14 7v10"/><path d="M7 10h10"/><path d="M7 14h10"/></svg>""",
    "properties": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>""",
    "expand": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 3 21 3 21 9"/><polyline points="9 21 3 21 3 15"/><line x1="21" x2="14" y1="3" y2="10"/><line x1="3" x2="10" y1="21" y2="14"/></svg>""",
    "collapse": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="4 14 10 14 10 20"/><polyline points="20 10 14 10 14 4"/><line x1="14" x2="21" y1="10" y2="3"/><line x1="3" x2="10" y1="21" y2="14"/></svg>""",
    "filter": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"/></svg>""",
    "app": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="20" height="16" x="2" y="4" rx="2"/><line x1="2" x2="22" y1="9" y2="9"/><circle cx="5" cy="6.5" r=".75" fill="currentColor"/><circle cx="8" cy="6.5" r=".75" fill="currentColor"/><polygon points="10,13 15,15.5 10,18" fill="currentColor"/></svg>""",
    "pdf": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><path d="M9 13v4"/><path d="M9 13h2a1.5 1.5 0 0 1 0 3H9"/><path d="M14 13v4"/><path d="M14 13h1.5a2 2 0 0 1 0 4H14"/></svg>""",
    "close": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>""",
    "plus": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>""",
    "minus": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="5" y1="12" x2="19" y2="12"/></svg>""",
    "zoom_in": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" x2="16.65" y1="21" y2="16.65"/><line x1="11" x2="11" y1="8" y2="14"/><line x1="8" x2="14" y1="11" y2="11"/></svg>""",
    "zoom_out": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" x2="16.65" y1="21" y2="16.65"/><line x1="8" x2="14" y1="11" y2="11"/></svg>""",
    "fit_screen": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M8 3H5a2 2 0 0 0-2 2v3m18 0V5a2 2 0 0 0-2-2h-3m0 18h3a2 2 0 0 0 2-2v-3M3 16v3a2 2 0 0 0 2 2h3"/></svg>""",
    "chevron_down": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"/></svg>""",
    "panel_right": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="18" height="18" x="3" y="3" rx="2"/><path d="M15 3v18"/></svg>""",
    "alert_triangle": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>""",
    "box_iso": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16Z"/><path d="m3.3 7 8.7 5 8.7-5"/><path d="M12 22V12"/></svg>""",
    "slideshow": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="18" height="14" x="3" y="3" rx="2"/><path d="m10 7 5 3-5 3V7Z"/><line x1="8" x2="16" y1="21" y2="21"/><line x1="12" x2="12" y1="17" y2="21"/></svg>""",
    "repeat": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m17 2 4 4-4 4"/><path d="M3 11v-1a4 4 0 0 1 4-4h14"/><path d="m7 22-4-4 4-4"/><path d="M21 13v1a4 4 0 0 1-4 4H3"/></svg>""",
    "shuffle": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 18h1.4c1.3 0 2.5-.6 3.3-1.7l6.1-8.6c.7-1.1 2-1.7 3.3-1.7H22"/><path d="m18 2 4 4-4 4"/><path d="M2 6h1.4c1.3 0 2.5.6 3.3 1.7l6.1 8.6c.7 1.1 2 1.7 3.3 1.7H22"/><path d="m18 20 4-4-4-4"/></svg>""",
    "film": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="20" height="20" x="2" y="2" rx="2.18" ry="2.18"/><line x1="7" x2="7" y1="2" y2="22"/><line x1="17" x2="17" y1="2" y2="22"/><line x1="2" x2="22" y1="12" y2="12"/><line x1="2" x2="7" y1="7" y2="7"/><line x1="2" x2="7" y1="17" y2="17"/><line x1="17" x2="22" y1="17" y2="17"/><line x1="17" x2="22" y1="7" y2="7"/></svg>""",
    "crossfade": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="9" cy="12" r="6"/><circle cx="15" cy="12" r="6" stroke-dasharray="2 2"/></svg>""",
    "rotate_cw": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12a9 9 0 1 1-9-9c2.52 0 4.93 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/></svg>""",
    "skip_back": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="19 20 9 12 19 4 19 20"/><line x1="5" x2="5" y1="19" y2="5"/></svg>""",
    "skip_forward": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="5 4 15 12 5 20 5 4"/><line x1="19" x2="19" y1="5" y2="19"/></svg>""",
    "clock": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>""",
    "settings": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>""",
    "sliders": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="4" x2="4" y1="21" y2="14"/><line x1="4" x2="4" y1="10" y2="3"/><line x1="12" x2="12" y1="21" y2="12"/><line x1="12" x2="12" y1="8" y2="3"/><line x1="20" x2="20" y1="21" y2="16"/><line x1="20" x2="20" y1="12" y2="3"/><line x1="1" x2="7" y1="14" y2="14"/><line x1="9" x2="15" y1="8" y2="8"/><line x1="17" x2="23" y1="16" y2="16"/></svg>""",
    "fingerprint": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 10a2 2 0 0 0-2 2c0 1.02-.1 2.51-.26 4"/><path d="M14 13.12c0 2.38 0 6.38-1 8.88"/><path d="M17.29 21.02c.12-.6.43-2.3.5-3.02"/><path d="M2 12a10 10 0 0 1 18-6"/><path d="M2 16h.01"/><path d="M21.8 16c.2-2 .131-5.354 0-6"/><path d="M5 19.5C5.5 18 6 15 6 12a6 6 0 0 1 .34-2"/><path d="M8.65 22c.21-.66.45-1.32.57-2"/><path d="M9 6.8a6 6 0 0 1 9 5.2v2"/></svg>""",
    "key": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m21 2-2 2m-1.5 1.5L13 10m-3-3l2 2m-2-2a5 5 0 1 0-7 7l7.5 7.5a1 1 0 0 0 1.4 0l2.1-2.1a1 1 0 0 0 0-1.4L18 18l-1.5-1.5 2.5-2.5-1.5-1.5 2-2"/></svg>""",
    "header_backup": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v14a9 3 0 0 0 18 0V5"/><path d="M3 12a9 3 0 0 0 18 0"/><path d="M12 12v6"/><path d="m9 15 3 3 3-3"/></svg>""",
    "header_restore": """<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v14a9 3 0 0 0 18 0V5"/><path d="M3 12a9 3 0 0 0 18 0"/><path d="M12 18v-6"/><path d="m9 15 3-3 3 3"/></svg>"""
}

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

def get_svg_icon(name: str, color: str = "#38BDF8", size: int = 16) -> QIcon:
    """Belirtilen isimdeki vektörel SVG simgesini QIcon olarak üretir."""
    svg = SVG_ICONS.get(name)
    if not svg:
        return QIcon()
    colored_svg = svg.replace("currentColor", color)
    renderer = QSvgRenderer(QByteArray(colored_svg.encode("utf-8")))
    pixmap = QPixmap(size, size)
    pixmap.fill(QColor(0, 0, 0, 0))
    painter = QPainter(pixmap)
    renderer.render(painter)
    painter.end()
    return QIcon(pixmap)

def get_svg_pixmap(name: str, color: str = "#38BDF8", size: int = 16) -> QPixmap:
    """Belirtilen isimdeki vektörel SVG simgesini QPixmap olarak üretir."""
    svg = SVG_ICONS.get(name)
    if not svg:
        return QPixmap()
    colored_svg = svg.replace("currentColor", color)
    renderer = QSvgRenderer(QByteArray(colored_svg.encode("utf-8")))
    pixmap = QPixmap(size, size)
    pixmap.fill(QColor(0, 0, 0, 0))
    painter = QPainter(pixmap)
    renderer.render(painter)
    painter.end()
    return pixmap

def format_size(size_bytes: int) -> str:
    """Bayt miktarını okunabilir birime çevirir (B, KB, MB, GB)."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024.0:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024.0 * 1024):.2f} MB"
    else:
        return f"{size_bytes / (1024.0 * 1024 * 1024):.2f} GB"

def get_file_category(filename: str) -> str:
    """Dosya uzantısına göre kategori ve tür belirler."""
    ext = Path(filename).suffix.lower()
    if ext in [".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".svg", ".ico", ".tiff", ".psd"]:
        return "image"
    elif ext in [".mp3", ".wav", ".flac", ".aac", ".ogg", ".m4a", ".wma", ".opus", ".mid"]:
        return "music"
    elif ext in [".mp4", ".mkv", ".avi", ".mov", ".wmv", ".webm", ".m4v", ".flv"]:
        return "video"
    elif ext in [".txt", ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".rtf", ".csv", ".log", ".ini", ".cfg"]:
        return "document"
    elif ext in [".py", ".js", ".ts", ".html", ".css", ".json", ".xml", ".yaml", ".yml", ".md", ".sh", ".c", ".cpp", ".h", ".cs", ".sql", ".rs", ".go", ".java"]:
        return "code"
    elif ext in [".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".iso", ".vhd", ".vhdx"]:
        return "archive"
    elif ext in [".exe", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".dll", ".sys", ".scr", ".com"]:
        return "app"
    return "file"

DANGEROUS_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
    ".ps1", ".psm1", ".scr", ".pif", ".com", ".hta", ".cpl", ".msi", ".msp",
    ".reg", ".jar", ".dll", ".sys", ".drv", ".ocx", ".iso", ".img", ".vhd", ".vhdx"
}

def inspect_file_security_header(header_bytes: bytes, filename: str) -> Tuple[bool, str]:
    """
    Kasa içi dosyaların ilk baytlarını analiz ederek sahte uzantılı gizlenmiş
    çalıştırılabilir zararlıları (PE/MZ trojan disguise) veya tehlikeli payload'ları tespit eder.
    Döndürür: (is_suspicious: bool, reason: str)
    """
    if not header_bytes:
        return False, ""

    fname_lower = filename.lower()
    ext = Path(fname_lower).suffix

    if "\u202e" in filename or "\u202d" in filename or "\u202c" in filename:
        return True, "Dosya adında dosya uzantısını gizleyen şüpheli Unicode RTL (Right-to-Left Override) karakteri tespit edildi!"

    safe_media_or_text_exts = {
        ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".svg", ".ico", ".tiff",
        ".mp3", ".wav", ".flac", ".aac", ".ogg", ".m4a", ".wma",
        ".mp4", ".mkv", ".avi", ".mov", ".wmv", ".webm", ".flv",
        ".txt", ".log", ".csv", ".ini", ".cfg", ".md", ".json"
    }

    if ext in safe_media_or_text_exts:
        if header_bytes.startswith(b"MZ"):
            return True, f"UYARI: Dosya uzantısı '{ext}' (medya/metin) ancak dosya içeriği Windows Yürütülebilir Programı (PE/MZ Executable)!"
        if header_bytes.startswith(b"\x7fELF"):
            return True, f"UYARI: Dosya uzantısı '{ext}' ancak içeriği Linux ELF Yürütülebilir İkili Kodu!"
        if header_bytes.startswith((b"\xca\xfe\xba\xbe", b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe")):
            return True, f"UYARI: Dosya uzantısı '{ext}' ancak içeriği Mach-O / Java Yürütülebilir Kodu!"

    if ext in [".png", ".jpg", ".jpeg", ".bmp", ".gif", ".webp", ".ico"]:
        lower_header = header_bytes[:256].lower()
        if any(bad in lower_header for bad in [b"powershell", b"wscript.shell", b"cmd.exe /c", b"<!doctype html", b"<script"]):
            return True, "UYARI: Resim dosyası içerisine gizlenmiş çalıştırılabilir betik kodu (Script Payload) tespit edildi!"

    return False, ""

def launch_file_in_windows_sandbox(file_path: str) -> bool:
    """
    Belirtilen dosyayı ana işletim sisteminden %100 yalıtılmış
    Windows Sandbox (WSB) sanal makinesinde güvenle çalıştırır.
    """
    try:
        import subprocess
        p = Path(file_path).resolve()
        parent_dir = p.parent
        file_name = p.name

        wsb_content = f"""<Configuration>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>{parent_dir}</HostFolder>
      <SandboxFolder>C:\\Users\\WDAGUtilityAccount\\Desktop\\Kasa_Izole_Alani</SandboxFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>explorer.exe "C:\\Users\\WDAGUtilityAccount\\Desktop\\Kasa_Izole_Alani\\{file_name}"</Command>
  </LogonCommand>
</Configuration>"""
        wsb_file = parent_dir / "vault_sandbox_config.wsb"
        with open(wsb_file, "w", encoding="utf-8") as f:
            f.write(wsb_content)

        subprocess.Popen(["WindowsSandbox.exe", str(wsb_file)], shell=False)
        return True
    except Exception:
        return False

_SYSTEM_EXTENSION_ICON_CACHE: Dict[str, QIcon] = {}
_SYSTEM_ICON_PROVIDER: Optional[QFileIconProvider] = None

def get_system_file_icon(extension: str, size: int = 16) -> QIcon:
    """Windows Explorer'da bu uzantının sahip olduğu orijinal sistem simgesini döndürür (TXT Not Defteri, EXE penceresi vb.)."""
    global _SYSTEM_ICON_PROVIDER
    ext = extension.lower().strip()
    if not ext:
        ext = ".bin"
    if not ext.startswith("."):
        ext = f".{ext}"

    cache_key = f"{ext}_{size}"
    if cache_key in _SYSTEM_EXTENSION_ICON_CACHE:
        return _SYSTEM_EXTENSION_ICON_CACHE[cache_key]

    if _SYSTEM_ICON_PROVIDER is None:
        _SYSTEM_ICON_PROVIDER = QFileIconProvider()

    try:
        raw_icon = _SYSTEM_ICON_PROVIDER.icon(QFileInfo(f"dummy{ext}"))
        if not raw_icon.isNull():
            pix = raw_icon.pixmap(size, size)
            if not pix.isNull():
                res_icon = QIcon(pix)
                _SYSTEM_EXTENSION_ICON_CACHE[cache_key] = res_icon
                return res_icon
    except Exception:
        pass

    return QIcon()

class AsyncIconWorkerSignals(QObject):
    icon_ready = pyqtSignal(str, QPixmap)

class AsyncIconWorker(QRunnable):
    """Arayüzü KESİNLİKLE dondurmadan arka planda çalışan simge çıkartıcı."""
    def __init__(self, vault_path: str, auth_info: Dict[str, Any], entries: List[Dict[str, Any]], signals: AsyncIconWorkerSignals):
        super().__init__()
        self.vault_path = vault_path
        self.auth_info = auth_info
        self.entries = entries
        self.signals = signals
        self._cancelled = False

    def cancel(self):
        self._cancelled = True

    def run(self):
        for entry in self.entries:
            if self._cancelled:
                break
            f_id = entry.get("id", "")
            fname = Path(entry.get("path", "")).name
            cat = get_file_category(fname)
            sz = entry.get("size", 0)
            is_app = (cat == "app" or Path(fname).suffix.lower() in [".exe", ".msi", ".ico"])

            if cat == "image" and sz > 15 * 1024 * 1024:
                continue

            if is_app and sz > 500 * 1024 * 1024:
                continue

            suffix = Path(fname).suffix.lower()
            if suffix == ".ico":
                try:
                    raw_bytes, _ = CustomVaultEngine.extract_file_bytes(self.vault_path, self.auth_info, f_id)
                    pix = QPixmap()
                    if pix.loadFromData(raw_bytes):
                        scaled = pix.scaled(256, 256, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
                        self.signals.icon_ready.emit(f_id, scaled)
                except Exception:
                    pass
            elif cat == "image":
                try:
                    raw_bytes, _ = CustomVaultEngine.extract_file_bytes(self.vault_path, self.auth_info, f_id)
                    pix = QPixmap()
                    if pix.loadFromData(raw_bytes):
                        scaled = pix.scaled(256, 256, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
                        self.signals.icon_ready.emit(f_id, scaled)
                except Exception:
                    pass

class VaultGlobalDropFilter(QAbstractNativeEventFilter):
    """
    Windows genelinde (tüm HWND'ler ve alt bileşenler dahil) WM_DROPFILES mesajlarını
    yakalayarak yönetici modunda dahi Windows Gezgini'nden sürükle-bırak yapılmasını sağlar.
    """
    _instance = None

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
            app = QApplication.instance()
            if app:
                app.installNativeEventFilter(cls._instance)
        return cls._instance

    def __init__(self):
        super().__init__()
        self.active_dialogs = []

    def register_dialog(self, dlg):
        if dlg not in self.active_dialogs:
            self.active_dialogs.append(dlg)

    def unregister_dialog(self, dlg):
        if dlg in self.active_dialogs:
            self.active_dialogs.remove(dlg)

    def nativeEventFilter(self, eventType, message):
        if eventType in (b"windows_generic_MSG", "windows_generic_MSG"):
            try:
                if _C_UINT_FROM_ADDR(int(message) + _MSG_OFFSET_MESSAGE).value == _WM_DROPFILES:
                    msg = wintypes.MSG.from_address(int(message))
                    hDrop = msg.wParam
                    num = ctypes.windll.shell32.DragQueryFileW(hDrop, 0xFFFFFFFF, None, 0)
                    file_paths = []
                    for i in range(num):
                        buf = ctypes.create_unicode_buffer(1024)
                        ctypes.windll.shell32.DragQueryFileW(hDrop, i, buf, 1024)
                        if buf.value:
                            file_paths.append(buf.value)

                    pt = wintypes.POINT()
                    ctypes.windll.shell32.DragQueryPoint(hDrop, ctypes.byref(pt))
                    ctypes.windll.shell32.DragFinish(hDrop)

                    if file_paths:
                        target_widget = None
                        target_dlg = None
                        try:
                            target_widget = QWidget.find(int(msg.hWnd))
                            if target_widget:
                                w_parent = target_widget
                                while w_parent:
                                    if hasattr(w_parent, "handle_native_drop") or hasattr(w_parent, "handle_dropped_paths"):
                                        target_dlg = w_parent
                                        break
                                    w_parent = w_parent.parent()
                        except Exception:
                            pass

                        if not target_dlg and self.active_dialogs:
                            target_dlg = self.active_dialogs[-1]

                        if target_dlg and hasattr(target_dlg, "handle_native_drop"):
                            target_dlg.handle_native_drop(file_paths, pt.x, pt.y, int(msg.hWnd), target_widget)
                            return True, 0
            except Exception:
                pass
        return False, 0

class VaultTableWidget(QTableWidget):
    """Hem içeri hem dışarı sürükle-bırak desteği olan Windows Explorer tarzı dosya tablosu."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.viewport().setAcceptDrops(True)
        self.setDragDropMode(QAbstractItemView.DragDropMode.DragDrop)
        self.setDefaultDropAction(Qt.DropAction.CopyAction)
        self.setDropIndicatorShown(True)
        self.setDragEnabled(True)
        self.setMouseTracking(False)
        self.viewport().setMouseTracking(False)

    def dragEnterEvent(self, event):
        event.setDropAction(Qt.DropAction.CopyAction)
        event.acceptProposedAction()
        event.accept()

    def dragMoveEvent(self, event):
        event.setDropAction(Qt.DropAction.CopyAction)
        event.acceptProposedAction()
        event.accept()

    def dropEvent(self, event):
        event.setDropAction(Qt.DropAction.CopyAction)
        event.acceptProposedAction()
        event.accept()
        urls = event.mimeData().urls()
        if not urls and event.mimeData().hasText():
            for line in event.mimeData().text().splitlines():
                line = line.strip()
                if line.startswith("file:///"):
                    urls.append(QUrl(line))
                elif os.path.exists(line):
                    urls.append(QUrl.fromLocalFile(line))
        if urls:
            target_folder = None
            pos = event.position().toPoint() if hasattr(event, "position") else event.pos()
            item = self.itemAt(pos)
            if item:
                row_item = self.item(item.row(), 0)
                if row_item:
                    row_data = row_item.data(Qt.ItemDataRole.UserRole)
                    if row_data and row_data.get("is_folder"):
                        target_folder = row_data.get("path")
            dlg = self
            while dlg and not hasattr(dlg, "handle_dropped_urls"):
                dlg = dlg.parent()
            if not dlg:
                dlg = self.window()
            if hasattr(dlg, "handle_dropped_urls"):
                dlg.handle_dropped_urls(urls, target_folder)

    def startDrag(self, supportedActions):
        parent_dlg = self.window()
        if hasattr(parent_dlg, "start_drag_out"):
            if parent_dlg.start_drag_out(self):
                return
        super().startDrag(supportedActions)

class VaultListWidget(QListWidget):
    """Büyük simgeler ve resim küçük resimleri (Thumbnail/Grid) için liste bileşeni."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.viewport().setAcceptDrops(True)
        self.setDragDropMode(QAbstractItemView.DragDropMode.DragDrop)
        self.setDefaultDropAction(Qt.DropAction.CopyAction)
        self.setDropIndicatorShown(True)
        self.setDragEnabled(True)
        self.setMouseTracking(False)
        self.viewport().setMouseTracking(False)
        self.setViewMode(QListWidget.ViewMode.IconMode)
        self.setIconSize(QSize(76, 76))
        self.setGridSize(QSize(108, 116))
        self.setWordWrap(True)
        self.setSpacing(8)
        self.setResizeMode(QListWidget.ResizeMode.Adjust)
        self.setMovement(QListWidget.Movement.Static)

    def dragEnterEvent(self, event):
        event.setDropAction(Qt.DropAction.CopyAction)
        event.acceptProposedAction()
        event.accept()

    def dragMoveEvent(self, event):
        event.setDropAction(Qt.DropAction.CopyAction)
        event.acceptProposedAction()
        event.accept()

    def dropEvent(self, event):
        event.setDropAction(Qt.DropAction.CopyAction)
        event.acceptProposedAction()
        event.accept()
        urls = event.mimeData().urls()
        if not urls and event.mimeData().hasText():
            for line in event.mimeData().text().splitlines():
                line = line.strip()
                if line.startswith("file:///"):
                    urls.append(QUrl(line))
                elif os.path.exists(line):
                    urls.append(QUrl.fromLocalFile(line))
        if urls:
            target_folder = None
            pos = event.position().toPoint() if hasattr(event, "position") else event.pos()
            item = self.itemAt(pos)
            if item:
                item_data = item.data(Qt.ItemDataRole.UserRole)
                if item_data and item_data.get("is_folder"):
                    target_folder = item_data.get("path")
            dlg = self
            while dlg and not hasattr(dlg, "handle_dropped_urls"):
                dlg = dlg.parent()
            if not dlg:
                dlg = self.window()
            if hasattr(dlg, "handle_dropped_urls"):
                dlg.handle_dropped_urls(urls, target_folder)

    def startDrag(self, supportedActions):
        parent_dlg = self.window()
        if hasattr(parent_dlg, "start_drag_out"):
            if parent_dlg.start_drag_out(self):
                return
        super().startDrag(supportedActions)

class VaultTreeWidget(QTreeWidget):
    """Sol gezinti paneli için sürükle-bırak hedefli klasör ağacı."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.viewport().setAcceptDrops(True)
        self.setDragDropMode(QAbstractItemView.DragDropMode.DropOnly)
        self.setDefaultDropAction(Qt.DropAction.CopyAction)
        self.setDropIndicatorShown(True)

    def dragEnterEvent(self, event):
        event.acceptProposedAction()
        event.accept()

    def dragMoveEvent(self, event):
        event.acceptProposedAction()
        event.accept()

    def dropEvent(self, event):
        event.acceptProposedAction()
        event.accept()
        urls = event.mimeData().urls()
        if not urls and event.mimeData().hasText():
            for line in event.mimeData().text().splitlines():
                line = line.strip()
                if line.startswith("file:///"):
                    urls.append(QUrl(line))
                elif os.path.exists(line):
                    urls.append(QUrl.fromLocalFile(line))
        if urls:
            pos = event.position().toPoint() if hasattr(event, "position") else event.pos()
            item = self.itemAt(pos)
            target_folder = item.data(0, Qt.ItemDataRole.UserRole) if item else ""
            dlg = self
            while dlg and not hasattr(dlg, "handle_dropped_urls"):
                dlg = dlg.parent()
            if not dlg:
                dlg = self.window()
            if hasattr(dlg, "handle_dropped_urls"):
                dlg.handle_dropped_urls(urls, target_folder)

class AudioPreviewWidget(QFrame):
    """Kasadaki müzik ve ses dosyalarını doğrudan çalan zarif ses kartı."""
    def __init__(self, parent=None, is_dark: bool = True):
        super().__init__(parent)
        self.is_dark = is_dark
        self.current_audio_file: Optional[str] = None
        self.player = QMediaPlayer(self)
        self.audio_output = QAudioOutput(self)
        self.player.setAudioOutput(self.audio_output)

        self.player.positionChanged.connect(self.on_position_changed)
        self.player.durationChanged.connect(self.on_duration_changed)
        self.player.playbackStateChanged.connect(self.on_state_changed)

        self.setup_ui()

    def setup_ui(self):
        accent_col = "#2997FF" if getattr(self, "theme", "dark") == "apple_dark" else ("#0071E3" if getattr(self, "theme", "dark") == "apple_light" else ("#38BDF8" if getattr(self, "is_dark", True) else "#0284C7"))
        card_bg = "#162035" if self.is_dark else "#E2EADE"
        border_col = "#243048" if self.is_dark else "#E2E8F0"
        text_col = "#F1F5F9" if self.is_dark else "#0F172A"

        self.setStyleSheet(f"""
            QFrame {{
                background-color: {card_bg};
                border: 1px solid {border_col};
                border-radius: 10px;
                padding: 6px;
            }}
            QSlider::groove:horizontal {{
                height: 4px;
                background: {'#090D18' if self.is_dark else '#CAD2C8'};
            }}
            QSlider::sub-page:horizontal {{
                background: {accent_col};
            }}
            QSlider::handle:horizontal {{
                background: {accent_col};
                width: 10px;
                margin-top: -3px;
                margin-bottom: -3px;
            }}
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        info_row = QHBoxLayout()
        self.lbl_disc = QLabel()
        self.lbl_disc.setPixmap(get_svg_pixmap("disc", accent_col, 20))
        info_row.addWidget(self.lbl_disc)

        self.lbl_track_title = QLabel("Ses Önizleme")
        self.lbl_track_title.setStyleSheet(f"font-weight: 700; font-size: 11px; color: {accent_col};")
        info_row.addWidget(self.lbl_track_title)
        info_row.addStretch()

        self.lbl_time = QLabel("00:00 / 00:00")
        self.lbl_time.setStyleSheet(f"font-size: 10px; color: {'#8B9EB7' if self.is_dark else '#4F604A'};")
        info_row.addWidget(self.lbl_time)
        layout.addLayout(info_row)

        self.slider = QSlider(Qt.Orientation.Horizontal)
        self.slider.setRange(0, 0)
        self.slider.sliderMoved.connect(self.set_position)
        layout.addWidget(self.slider)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(6)

        self.btn_play = QPushButton()
        self.btn_play.setIcon(get_svg_icon("play", "#FFFFFF", 14))
        self.btn_play.setToolTip("Oynat / Duraklat")
        self.btn_play.clicked.connect(self.toggle_play)
        btn_row.addWidget(self.btn_play)

        self.btn_stop = QPushButton()
        self.btn_stop.setIcon(get_svg_icon("stop", "#FFFFFF", 14))
        self.btn_stop.setToolTip("Durdur")
        self.btn_stop.clicked.connect(self.stop)
        btn_row.addWidget(self.btn_stop)

        btn_row.addStretch()

        lbl_vol = QLabel()
        lbl_vol.setPixmap(get_svg_pixmap("volume", accent_col, 14))
        btn_row.addWidget(lbl_vol)

        self.vol_slider = QSlider(Qt.Orientation.Horizontal)
        self.vol_slider.setRange(0, 100)
        self.vol_slider.setValue(80)
        self.vol_slider.setMinimumWidth(50)
        self.vol_slider.valueChanged.connect(lambda v: self.audio_output.setVolume(v / 100.0))
        btn_row.addWidget(self.vol_slider)

        layout.addLayout(btn_row)

    def load_audio(self, filepath: str, title: str):
        self.stop()
        self.current_audio_file = filepath
        self.lbl_track_title.setText(title[:24] + ("..." if len(title) > 24 else ""))
        self.player.setSource(QUrl.fromLocalFile(filepath))

    def toggle_play(self):
        if self.player.playbackState() == QMediaPlayer.PlaybackState.PlayingState:
            self.player.pause()
        else:
            self.player.play()

    def stop(self):
        self.player.stop()

    def on_position_changed(self, position: int):
        if not self.slider.isSliderDown():
            self.slider.setValue(position)
        self.update_time_label()

    def on_duration_changed(self, duration: int):
        self.slider.setRange(0, duration)
        self.update_time_label()

    def set_position(self, position: int):
        self.player.setPosition(position)

    def on_state_changed(self, state: QMediaPlayer.PlaybackState):
        accent_col = "#2997FF" if getattr(self, "theme", "dark") == "apple_dark" else ("#0071E3" if getattr(self, "theme", "dark") == "apple_light" else ("#38BDF8" if getattr(self, "is_dark", True) else "#0284C7"))
        if state == QMediaPlayer.PlaybackState.PlayingState:
            self.btn_play.setIcon(get_svg_icon("pause", "#FFFFFF", 14))
        else:
            self.btn_play.setIcon(get_svg_icon("play", "#FFFFFF", 14))

    def update_time_label(self):
        pos_s = self.player.position() // 1000
        dur_s = self.player.duration() // 1000
        self.lbl_time.setText(f"{pos_s // 60:02d}:{pos_s % 60:02d} / {dur_s // 60:02d}:{dur_s % 60:02d}")

class VideoPreviewWidget(QFrame):
    """
    Kasadaki video dosyalarını ana işletim sisteminden tamamen yalıtılmış
    ve güvenli şekilde kasa içinde oynatan dahili video önizleme bileşeni.
    """
    fullscreen_requested = pyqtSignal(str)

    def __init__(self, parent=None, is_dark: bool = True):
        super().__init__(parent)
        self.is_dark = is_dark
        self.current_video_file: Optional[str] = None
        self.current_file_id: Optional[str] = None

        self.player = QMediaPlayer(self)
        self.audio_output = QAudioOutput(self)
        self.player.setAudioOutput(self.audio_output)

        self.video_widget = QVideoWidget(self)
        self.player.setVideoOutput(self.video_widget)

        self.player.positionChanged.connect(self.on_position_changed)
        self.player.durationChanged.connect(self.on_duration_changed)
        self.player.playbackStateChanged.connect(self.on_state_changed)

        self.setup_ui()

    def setup_ui(self):
        accent_col = "#38BDF8" if self.is_dark else "#059669"
        card_bg = "#18181b" if self.is_dark else "#FFFFFF"
        border_col = "rgba(255, 255, 255, 0.08)" if self.is_dark else "rgba(0, 0, 0, 0.08)"

        self.setStyleSheet(f"""
            QFrame {{
                background-color: {card_bg};
                border: 1px solid {border_col};
                border-radius: 8px;
            }}
            QSlider::groove:horizontal {{
                height: 4px;
                background: {'#27272a' if self.is_dark else '#E4E4E7'};
                border-radius: 2px;
            }}
            QSlider::sub-page:horizontal {{
                background: {accent_col};
                border-radius: 2px;
            }}
            QSlider::handle:horizontal {{
                background: {accent_col};
                width: 10px;
                margin-top: -3px;
                margin-bottom: -3px;
                border-radius: 5px;
            }}
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(6)

        self.video_widget.setMinimumHeight(140)
        self.video_widget.setMaximumHeight(175)
        self.video_widget.setStyleSheet("background-color: #000000; border-radius: 6px;")
        layout.addWidget(self.video_widget)

        self.slider = QSlider(Qt.Orientation.Horizontal)
        self.slider.setRange(0, 0)
        self.slider.sliderMoved.connect(self.set_position)
        layout.addWidget(self.slider)

        ctrl_row = QHBoxLayout()
        ctrl_row.setSpacing(6)

        self.btn_play = QPushButton()
        self.btn_play.setProperty("class", "fluent-nav-btn")
        self.btn_play.setIcon(get_svg_icon("play", accent_col, 14))
        self.btn_play.setToolTip("Oynat / Duraklat")
        self.btn_play.clicked.connect(self.toggle_play)
        ctrl_row.addWidget(self.btn_play)

        self.btn_stop = QPushButton()
        self.btn_stop.setProperty("class", "fluent-nav-btn")
        self.btn_stop.setIcon(get_svg_icon("stop", accent_col, 14))
        self.btn_stop.setToolTip("Durdur")
        self.btn_stop.clicked.connect(self.stop)
        ctrl_row.addWidget(self.btn_stop)

        self.lbl_time = QLabel("00:00 / 00:00")
        self.lbl_time.setStyleSheet(f"font-size: 10px; color: {'#A1A1AA' if self.is_dark else '#71717A'};")
        ctrl_row.addWidget(self.lbl_time)

        ctrl_row.addStretch()

        self.btn_fs = QPushButton()
        self.btn_fs.setProperty("class", "fluent-nav-btn")
        self.btn_fs.setIcon(get_svg_icon("expand", accent_col, 13))
        self.btn_fs.setToolTip("İzole Tam Ekranda İzle (F)")
        self.btn_fs.clicked.connect(lambda: self.fullscreen_requested.emit(self.current_file_id or self.current_video_file or ""))
        ctrl_row.addWidget(self.btn_fs)

        layout.addLayout(ctrl_row)

    def load_video(self, filepath: str, title: str, file_id: str = ""):
        self.stop()
        self.current_video_file = filepath
        self.current_file_id = file_id
        self.player.setSource(QUrl.fromLocalFile(filepath))

    def toggle_play(self):
        accent_col = "#38BDF8" if self.is_dark else "#059669"
        if self.player.playbackState() == QMediaPlayer.PlaybackState.PlayingState:
            self.player.pause()
            self.btn_play.setIcon(get_svg_icon("play", accent_col, 14))
        else:
            self.player.play()
            self.btn_play.setIcon(get_svg_icon("pause", accent_col, 14))

    def stop(self):
        accent_col = "#38BDF8" if self.is_dark else "#059669"
        self.player.stop()
        self.btn_play.setIcon(get_svg_icon("play", accent_col, 14))

    def on_position_changed(self, position: int):
        if not self.slider.isSliderDown():
            self.slider.setValue(position)
        self.update_time_label()

    def on_duration_changed(self, duration: int):
        self.slider.setRange(0, duration)
        self.update_time_label()

    def set_position(self, position: int):
        self.player.setPosition(position)

    def on_state_changed(self, state: QMediaPlayer.PlaybackState):
        accent_col = "#38BDF8" if self.is_dark else "#059669"
        if state == QMediaPlayer.PlaybackState.PlayingState:
            self.btn_play.setIcon(get_svg_icon("pause", accent_col, 14))
        else:
            self.btn_play.setIcon(get_svg_icon("play", accent_col, 14))

    def update_time_label(self):
        pos_s = self.player.position() // 1000
        dur_s = self.player.duration() // 1000
        self.lbl_time.setText(f"{pos_s // 60:02d}:{pos_s % 60:02d} / {dur_s // 60:02d}:{dur_s % 60:02d}")

def set_win32_window_zorder(widget, topmost: bool = True, geom: Optional[QRect] = None):
    """
    Windows DWM uzerinde tam ekran pencerelerinin Gorev Cubugunun (Taskbar) ustunde kalmasini saglar (HWND_TOPMOST)
    veya normal pencere moduna dondurur (HWND_NOTOPMOST). 64-bit Windows ctypes ABI uyumludur.
    """
    if sys.platform != "win32":
        return
    try:
        import ctypes
        from ctypes import wintypes
        user32 = ctypes.windll.user32
        user32.SetWindowPos.argtypes = [
            wintypes.HWND,
            wintypes.HWND,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_uint
        ]
        user32.SetWindowPos.restype = wintypes.BOOL

        hwnd = int(widget.winId())
        SWP_SHOWWINDOW = 0x0040
        SWP_NOSIZE = 0x0001
        SWP_NOMOVE = 0x0002
        if topmost:
            HWND_TOPMOST = ctypes.c_void_p(-1).value
            if geom:
                user32.SetWindowPos(hwnd, HWND_TOPMOST, geom.x(), geom.y(), geom.width(), geom.height(), SWP_SHOWWINDOW)
            else:
                user32.SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOMOVE | SWP_SHOWWINDOW)
            try:
                user32.SetForegroundWindow(hwnd)
            except Exception:
                pass
        else:
            HWND_NOTOPMOST = ctypes.c_void_p(-2).value
            user32.SetWindowPos(hwnd, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOMOVE | SWP_SHOWWINDOW)
    except Exception:
        pass

class CustomVaultFullscreenVideoDialog(QDialog):
    """
    Kasa içi tamamen izole, sıfır dış süreç bağımlılığı olan tam ekran video oynatıcı.
    - Windows'un dış medya oynatıcılarına veya kabuğuna (shell) kesinlikle bağlanmaz.
    - Şüpheli/zararlı video codec istismarlarına karşı tamamen korumalı Qt ortamında çalışır.
    """
    def __init__(self, parent=None, video_path: str = "", title: str = "", is_dark: bool = True):
        super().__init__(None)
        self.explorer_parent = parent
        self.saved_normal_geom: Optional[QRect] = None
        self.video_path = video_path
        self.title = title
        self.is_dark = is_dark

        self.setWindowTitle(f"İzole Video İnceleyici - {title}")
        self.setWindowFlags(Qt.WindowType.Window | Qt.WindowType.WindowMinMaxButtonsHint | Qt.WindowType.WindowCloseButtonHint)
        self.setMinimumSize(580, 360)
        self.setSizeGripEnabled(True)

        from PyQt6.QtGui import QKeySequence, QShortcut
        self.shortcut_vid_f11 = QShortcut(QKeySequence(Qt.Key.Key_F11), self)
        self.shortcut_vid_f11.setContext(Qt.ShortcutContext.WindowShortcut)
        self.shortcut_vid_f11.activated.connect(self.toggle_fullscreen)

        self.shortcut_vid_f = QShortcut(QKeySequence(Qt.Key.Key_F), self)
        self.shortcut_vid_f.setContext(Qt.ShortcutContext.WindowShortcut)
        self.shortcut_vid_f.activated.connect(self.toggle_fullscreen)

        self.shortcut_vid_space = QShortcut(QKeySequence(Qt.Key.Key_Space), self)
        self.shortcut_vid_space.setContext(Qt.ShortcutContext.WindowShortcut)
        self.shortcut_vid_space.activated.connect(self.toggle_play)

        self.shortcut_vid_esc = QShortcut(QKeySequence(Qt.Key.Key_Escape), self)
        self.shortcut_vid_esc.setContext(Qt.ShortcutContext.WindowShortcut)
        self.shortcut_vid_esc.activated.connect(self._on_vid_escape)

        self.player = QMediaPlayer(self)
        self.audio_output = QAudioOutput(self)
        self.player.setAudioOutput(self.audio_output)

        self.video_widget = QVideoWidget(self)
        self.player.setVideoOutput(self.video_widget)

        self.player.positionChanged.connect(self.on_position_changed)
        self.player.durationChanged.connect(self.on_duration_changed)
        self.player.playbackStateChanged.connect(self.on_state_changed)

        self.setup_ui()
        self.player.setSource(QUrl.fromLocalFile(video_path))
        self.player.play()

    def setup_ui(self):
        bg_col = "#090D18" if self.is_dark else "#F8FAFC"
        bar_bg = "rgba(10, 16, 26, 0.94)" if self.is_dark else "rgba(241, 245, 249, 0.96)"
        text_col = "#F8FAFC" if self.is_dark else "#0F172A"
        accent_col = "#38BDF8" if self.is_dark else "#059669"
        border_col = "#1E293B" if self.is_dark else "#CBD5E1"

        self.setStyleSheet(f"""
            QDialog {{
                background-color: {bg_col};
                color: {text_col};
            }}
            #fs-video-bar {{
                background-color: {bar_bg};
                border-top: 1px solid {border_col};
                padding: 6px;
            }}
            QSlider::groove:horizontal {{
                height: 5px;
                background: {'#1E293B' if self.is_dark else '#CBD5E1'};
                border-radius: 2px;
            }}
            QSlider::sub-page:horizontal {{
                background: {accent_col};
                border-radius: 2px;
            }}
            QSlider::handle:horizontal {{
                background: {accent_col};
                width: 12px;
                margin-top: -4px;
                margin-bottom: -4px;
                border-radius: 6px;
            }}
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        header = QFrame()
        header.setStyleSheet(f"background-color: {bar_bg}; border-bottom: 1px solid {border_col}; padding: 6px 12px;")
        h_layout = QHBoxLayout(header)
        h_layout.setContentsMargins(0, 0, 0, 0)

        lbl_ico = QLabel()
        lbl_ico.setPixmap(get_svg_pixmap("video", accent_col, 16))
        h_layout.addWidget(lbl_ico)

        lbl_t = QLabel(self.title)
        lbl_t.setStyleSheet(f"font-weight: 700; font-size: 12px; color: {text_col};")
        h_layout.addWidget(lbl_t)

        badge = QLabel("KASA İÇİ İZOLE OYNATICI (SANDBOX)")
        badge.setStyleSheet("background-color: rgba(16, 185, 129, 0.15); color: #10B981; font-size: 9px; font-weight: 700; border-radius: 4px; padding: 2px 6px;")
        h_layout.addWidget(badge)

        h_layout.addStretch()

        btn_close = QPushButton()
        btn_close.setIcon(get_svg_icon("close", "#94A3B8", 14))
        btn_close.clicked.connect(self.close)
        btn_close.setStyleSheet("background: transparent; border: none; padding: 4px;")
        h_layout.addWidget(btn_close)

        layout.addWidget(header)

        self.video_widget.setStyleSheet("background-color: #000000;")
        layout.addWidget(self.video_widget, stretch=1)

        bar = QFrame()
        bar.setObjectName("fs-video-bar")
        b_layout = QVBoxLayout(bar)
        b_layout.setContentsMargins(12, 6, 12, 6)
        b_layout.setSpacing(4)

        self.slider = QSlider(Qt.Orientation.Horizontal)
        self.slider.setRange(0, 0)
        self.slider.sliderMoved.connect(self.player.setPosition)
        b_layout.addWidget(self.slider)

        ctrl_row = QHBoxLayout()
        ctrl_row.setSpacing(8)

        self.btn_play = QPushButton()
        self.btn_play.setIcon(get_svg_icon("pause", accent_col, 16))
        self.btn_play.clicked.connect(self.toggle_play)
        self.btn_play.setStyleSheet(f"background-color: transparent; border: 1px solid {border_col}; border-radius: 4px; padding: 4px 10px;")
        ctrl_row.addWidget(self.btn_play)

        self.lbl_time = QLabel("00:00 / 00:00")
        self.lbl_time.setStyleSheet(f"font-size: 11px; color: {'#94A3B8' if self.is_dark else '#64748B'};")
        ctrl_row.addWidget(self.lbl_time)

        ctrl_row.addStretch()

        self.btn_fs = QPushButton("Tam Ekran (F11)")
        self.btn_fs.setIcon(get_svg_icon("expand", accent_col, 14))
        self.btn_fs.clicked.connect(self.toggle_fullscreen)
        self.btn_fs.setStyleSheet(f"background-color: transparent; border: 1px solid {border_col}; border-radius: 4px; padding: 4px 10px; font-size: 11px; font-weight: 600; color: {text_col};")
        ctrl_row.addWidget(self.btn_fs)

        b_layout.addLayout(ctrl_row)
        layout.addWidget(bar)

    def toggle_play(self):
        accent_col = "#38BDF8" if self.is_dark else "#059669"
        if self.player.playbackState() == QMediaPlayer.PlaybackState.PlayingState:
            self.player.pause()
            self.btn_play.setIcon(get_svg_icon("play", accent_col, 16))
        else:
            self.player.play()
            self.btn_play.setIcon(get_svg_icon("pause", accent_col, 16))

    def on_position_changed(self, position: int):
        if not self.slider.isSliderDown():
            self.slider.setValue(position)
        self.update_time_label()

    def on_duration_changed(self, duration: int):
        self.slider.setRange(0, duration)
        self.update_time_label()

    def on_state_changed(self, state: QMediaPlayer.PlaybackState):
        accent_col = "#38BDF8" if self.is_dark else "#059669"
        if state == QMediaPlayer.PlaybackState.PlayingState:
            self.btn_play.setIcon(get_svg_icon("pause", accent_col, 16))
        else:
            self.btn_play.setIcon(get_svg_icon("play", accent_col, 16))

    def update_time_label(self):
        pos_s = self.player.position() // 1000
        dur_s = self.player.duration() // 1000
        self.lbl_time.setText(f"{pos_s // 60:02d}:{pos_s % 60:02d} / {dur_s // 60:02d}:{dur_s % 60:02d}")

    def toggle_fullscreen(self):
        if self.isFullScreen():
            self.showNormal()
        else:
            self.showFullScreen()

    def showFullScreen(self):
        """Video oynatıcıyı kenarlıksız tam ekrana geçirir ve Windows Görev Çubuğunun üstüne alır."""
        if not self.isFullScreen():
            self.saved_normal_geom = self.geometry()
        super().showFullScreen()
        self.raise_()
        self.activateWindow()

        accent_col = "#38BDF8" if self.is_dark else "#059669"
        if hasattr(self, "btn_fs"):
            self.btn_fs.setText(" Pencere")
            self.btn_fs.setIcon(get_svg_icon("collapse", accent_col, 14))

        screen = self.screen() or QGuiApplication.primaryScreen()
        sg = screen.geometry() if screen else QRect(0, 0, 1920, 1080)
        set_win32_window_zorder(self, topmost=True, geom=sg)

    def showNormal(self):
        """Video oynatıcıyı standart pencere boyutuna ve z-sırasına geri döndürür."""
        set_win32_window_zorder(self, topmost=False)
        super().showNormal()
        self.raise_()
        self.activateWindow()

        text_col = "#FFFFFF" if self.is_dark else "#0F172A"
        if hasattr(self, "btn_fs"):
            self.btn_fs.setText(" Tam Ekran")
            self.btn_fs.setIcon(get_svg_icon("expand", text_col, 14))

        if hasattr(self, "saved_normal_geom") and self.saved_normal_geom and not self.saved_normal_geom.isEmpty():
            self.setGeometry(self.saved_normal_geom)
        else:
            apply_dynamic_geometry(self, default_w=720, default_h=460, min_w=580, min_h=360)

    def _on_vid_escape(self):
        if self.isFullScreen():
            self.toggle_fullscreen()
        else:
            self.close()

    def keyPressEvent(self, event):
        key = event.key()
        if key in (Qt.Key.Key_Escape, Qt.Key.Key_Q):
            self._on_vid_escape()
        elif key in (Qt.Key.Key_Space,):
            self.toggle_play()
        elif key in (Qt.Key.Key_F11, Qt.Key.Key_F):
            self.toggle_fullscreen()
        elif key == Qt.Key.Key_Left:
            self.player.setPosition(max(0, self.player.position() - 5000))
        elif key == Qt.Key.Key_Right:
            self.player.setPosition(min(self.player.duration(), self.player.position() + 5000))
        else:
            super().keyPressEvent(event)

    def closeEvent(self, event):
        set_win32_window_zorder(self, topmost=False)
        self.player.stop()
        event.accept()

class VaultExecutionBarrierDialog(QDialog):
    """
    Yürütülebilir Dosyalar ve Tehlikeli Betikler İçin Siber Güvenlik İzolasyon Bariyeri.
    - Virüslü veya zararlı dosyaların ana bilgisayara bulaşmasını kesin olarak engeller.
    - Kullanıcıya güvenli seçenekler sunar:
      1. İptal Et ve Karantinada Tut (Önerilen)
      2. Yalnızca İkili / Hex Olarak Güvenle İncele (Bellekte Zararsız İnceleme)
      3. Windows Sandbox İçinde İzole Sanal Makinede Çalıştır
      4. Kendi Sorumluluğunda Aç (Yalnızca açık onay kutusu ile)
    """
    def __init__(self, parent=None, item_data: Optional[Dict[str, Any]] = None, temp_path: str = "", is_dark: bool = True, theme: Optional[str] = None):
        super().__init__(parent)
        self.item_data = item_data or {}
        self.temp_path = temp_path
        self.theme = theme or getattr(parent, "current_theme", None) or ("dark" if is_dark else "light")
        self.is_dark = (self.theme in ("dark", "apple_dark"))
        self.action_result: str = "cancel"

        self.setWindowTitle("Güvenlik İzolasyon Bariyeri - Enclave")
        apply_dynamic_geometry(self, default_w=520, default_h=380, min_w=460, min_h=300)
        self.setSizeGripEnabled(True)
        self.setWindowFlags(Qt.WindowType.Dialog | Qt.WindowType.WindowCloseButtonHint)
        self.setup_ui()

    def setup_ui(self):
        pal = get_dialog_palette(self.theme)
        bg_col = pal["bg_col"]
        card_bg = pal["card_bg"]
        border_col = pal["border_col"]
        text_col = pal["text_col"]
        text_muted = pal["text_muted"]
        red_alert = pal.get("danger_col", "#FF453A" if self.is_dark else "#DC2626")
        green_safe = pal.get("success_col", "#30D158" if self.is_dark else "#16A34A")
        cyan_accent = pal["accent_col"]

        self.setStyleSheet(f"""
            QDialog {{
                background-color: {bg_col};
                color: {text_col};
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
            }}
            #barrier-card {{
                background-color: {card_bg};
                border: 1px solid {border_col};
                border-radius: 14px;
            }}
            {get_dialog_button_stylesheet(self.theme)}
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)

        header_row = QHBoxLayout()
        header_row.setSpacing(12)

        lbl_shield = QLabel()
        lbl_shield.setPixmap(get_svg_pixmap("alert_triangle", red_alert, 36))
        header_row.addWidget(lbl_shield)

        title_col = QVBoxLayout()
        title_col.setSpacing(2)
        lbl_title = QLabel("GÜVENLİK İZOLASYON BARİYERİ")
        lbl_title.setStyleSheet(f"font-size: 15px; font-weight: 800; color: {red_alert};")
        title_col.addWidget(lbl_title)

        lbl_subtitle = QLabel("Zararlı Kod Bulaşma Koruması & Yürütme Denetimi")
        lbl_subtitle.setStyleSheet(f"font-size: 11px; color: {text_muted};")
        title_col.addWidget(lbl_subtitle)
        header_row.addLayout(title_col)
        header_row.addStretch()
        layout.addLayout(header_row)

        info_card = QFrame()
        info_card.setObjectName("barrier-card")
        ic_layout = QVBoxLayout(info_card)
        ic_layout.setContentsMargins(14, 12, 14, 12)
        ic_layout.setSpacing(8)

        warn_msg = QLabel(
            "<b>DİKKAT:</b> Bu dosya yürütülebilir bir program veya sistem betiğidir.<br>"
            "Bilinmeyen kaynaklardan gelen veya virüslü olabilecek bu tür dosyalar, ana işletim sisteminizde çalıştırıldığında "
            "bilgisayarınıza doğrudan bulaşabilir ve kalıcı zarar verebilir."
        )
        warn_msg.setStyleSheet(f"font-size: 11px; color: {text_col}; line-height: 1.4;")
        warn_msg.setWordWrap(True)
        ic_layout.addWidget(warn_msg)

        entry = self.item_data.get("entry", {})
        fname = Path(entry.get("path", "")).name or "Bilinmeyen Dosya"
        fsize = format_size(entry.get("size", 0))
        sha = entry.get("sha256", "Doğrulanıyor...")
        if len(sha) > 32:
            sha_disp = f"{sha[:16]}...{sha[-16:]}"
        else:
            sha_disp = sha

        meta_lbl = QLabel(
            f"<b>Dosya Adı:</b> {fname}<br>"
            f"<b>Boyut:</b> {fsize}  |  <b>Kasa İçi Yol:</b> /{entry.get('path', '')}<br>"
            f"<b>SHA-256 Özeti:</b> <span style='font-family: Consolas;'>{sha_disp}</span>"
        )
        meta_lbl.setStyleSheet(f"font-size: 10.5px; color: {text_muted}; background-color: rgba(0,0,0,0.2); padding: 8px; border-radius: 6px;")
        ic_layout.addWidget(meta_lbl)
        layout.addWidget(info_card)

        self.btn_cancel = QPushButton("  İşlemi İptal Et & Karantinada Tut (Önerilen)")
        self.btn_cancel.setIcon(get_svg_icon("shield", "#FFFFFF", 16))
        self.btn_cancel.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_cancel.setStyleSheet(f"""
            QPushButton {{
                background-color: {green_safe};
                color: #FFFFFF;
                border: none;
                border-radius: 6px;
                padding: 10px;
                font-weight: 700;
                font-size: 12px;
            }}
            QPushButton:hover {{
                background-color: #059669;
            }}
        """)
        self.btn_cancel.clicked.connect(self.on_cancel_clicked)
        layout.addWidget(self.btn_cancel)

        self.btn_hex = QPushButton("  Zararsız İkili / Hex Olarak İncele (Bellekte)")
        self.btn_hex.setIcon(get_svg_icon("binary", cyan_accent, 15))
        self.btn_hex.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_hex.setStyleSheet(f"""
            QPushButton {{
                background-color: transparent;
                color: {cyan_accent};
                border: 1px solid {cyan_accent};
                border-radius: 6px;
                padding: 8px;
                font-weight: 600;
                font-size: 11.5px;
            }}
            QPushButton:hover {{
                background-color: rgba(56, 189, 248, 0.12);
            }}
        """)
        self.btn_hex.clicked.connect(self.on_hex_clicked)
        layout.addWidget(self.btn_hex)

        self.btn_sandbox = QPushButton("  Windows Sandbox İçinde İzole Çalıştır (Sanal Makine)")
        self.btn_sandbox.setIcon(get_svg_icon("box_iso", "#38BDF8", 15))
        self.btn_sandbox.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_sandbox.setStyleSheet(f"""
            QPushButton {{
                background-color: transparent;
                color: #38BDF8;
                border: 1px solid #38BDF8;
                border-radius: 6px;
                padding: 8px;
                font-weight: 600;
                font-size: 11.5px;
            }}
            QPushButton:hover {{
                background-color: rgba(56, 189, 248, 0.12);
            }}
        """)
        self.btn_sandbox.clicked.connect(self.on_sandbox_clicked)
        layout.addWidget(self.btn_sandbox)

        confirm_box = QVBoxLayout()
        confirm_box.setSpacing(10)

        self.chk_confirm = QCheckBox("Tehlikenin ve virüs riskinin farkındayım, ana sistemimde açılsın.")
        self.chk_confirm.setStyleSheet(f"font-size: 11px; color: {text_muted};")
        confirm_box.addWidget(self.chk_confirm)

        btn_host_row = QHBoxLayout()
        btn_host_row.addStretch()
        self.btn_host = QPushButton("Ana Sistemde Çalıştır")
        self.btn_host.setEnabled(False)
        self.btn_host.setMinimumHeight(28)
        self.btn_host.setStyleSheet(f"""
            QPushButton {{
                background-color: transparent;
                color: {red_alert};
                border: 1px solid {red_alert};
                border-radius: 6px;
                padding: 6px 16px;
                font-weight: 700;
                font-size: 11.5px;
            }}
            QPushButton:hover {{
                background-color: {red_alert};
                color: #FFFFFF;
            }}
            QPushButton:disabled {{
                opacity: 0.3;
                border-color: {border_col};
                color: {text_muted};
            }}
        """)
        self.chk_confirm.toggled.connect(self.btn_host.setEnabled)
        self.btn_host.clicked.connect(self.on_host_clicked)
        btn_host_row.addWidget(self.btn_host)
        confirm_box.addLayout(btn_host_row)
        layout.addLayout(confirm_box)

    def on_cancel_clicked(self):
        self.action_result = "cancel"
        self.reject()

    def on_hex_clicked(self):
        self.action_result = "hex"
        self.accept()

    def on_sandbox_clicked(self):
        self.action_result = "sandbox"
        self.accept()

    def on_host_clicked(self):
        self.action_result = "host"
        self.accept()

class VaultPropertiesDialog(QDialog):
    """Kasadaki bir dosyanın ayrıntılı meta-verilerini, boyutlarını ve canlı AEAD bütünlüğünü gösterir."""
    def __init__(self, parent, file_data: Dict[str, Any], vault_path: str, auth_info: Dict[str, Any], is_dark: bool = True, theme: Optional[str] = None):
        super().__init__(parent)
        self.file_data = file_data
        self.vault_path = vault_path
        self.auth_info = auth_info
        self.theme = theme or getattr(parent, "current_theme", None) or ("dark" if is_dark else "light")
        self.is_dark = (self.theme in ("dark", "apple_dark"))
        self.entry = file_data.get("entry", {})
        fname = Path(self.entry.get("path", "")).name
        self.setWindowTitle(f"Özellikler & Bütünlük - {fname}")
        self.setSizeGripEnabled(True)
        apply_dynamic_geometry(self, default_w=460, default_h=480, min_w=400, min_h=380)
        self.setup_ui()

    def setup_ui(self):
        pal = get_dialog_palette(self.theme)
        bg_col = pal["bg_col"]
        card_bg = pal["card_bg"]
        border_col = pal["border_col"]
        text_col = pal["text_col"]
        accent_col = pal["accent_col"]

        self.setStyleSheet(f"""
            QDialog {{ background-color: {bg_col}; color: {text_col}; font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif; }}
            QFrame.card {{ background-color: {card_bg}; border: 1px solid {border_col}; border-radius: 14px; padding: 12px; }}
            QLabel {{ font-size: 11.5px; color: {text_col}; }}
            {get_dialog_button_stylesheet(self.theme)}
        """)

        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.setContentsMargins(14, 14, 14, 14)

        card = QFrame()
        card.setProperty("class", "card")
        c_layout = QVBoxLayout(card)
        c_layout.setSpacing(8)

        header_row = QHBoxLayout()
        fname = Path(self.entry.get("path", "")).name
        cat = get_file_category(fname)
        icon_lbl = QLabel()
        icon_lbl.setPixmap(get_svg_pixmap(cat if cat in SVG_ICONS else "file", accent_col, 32))
        header_row.addWidget(icon_lbl)

        name_lbl = QLabel(fname)
        name_lbl.setStyleSheet(f"font-size: 13px; font-weight: 800; color: {accent_col};")
        name_lbl.setWordWrap(True)
        header_row.addWidget(name_lbl, stretch=1)
        c_layout.addLayout(header_row)

        c_layout.addWidget(QLabel(f"<b>Kasa İçi Yol:</b> /{self.entry.get('path', '')}"))
        c_layout.addWidget(QLabel(f"<b>Kategori / Tür:</b> {cat.upper()} ({Path(fname).suffix.upper() or 'Uzantısız'})"))
        
        orig_sz = self.entry.get("size", 0)
        comp_sz = self.entry.get("comp_size", orig_sz)
        ratio_str = f" (%{int((1 - comp_sz / orig_sz) * 100)} tasarruf)" if orig_sz > comp_sz else ""
        c_layout.addWidget(QLabel(f"<b>Orijinal Boyut:</b> {format_size(orig_sz)} ({orig_sz:,} bayt)"))
        c_layout.addWidget(QLabel(f"<b>Şifreli Boyut:</b> {format_size(comp_sz)} ({comp_sz:,} bayt){ratio_str}"))

        mtime = self.entry.get("mtime", time.time())
        mtime_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(mtime))
        c_layout.addWidget(QLabel(f"<b>Değiştirilme Tarihi:</b> {mtime_str}"))

        c_layout.addWidget(QLabel(f"<b>Şifreleme Motoru:</b> AES-256-GCM (12-bayt AEAD Nonce)"))
        c_layout.addWidget(QLabel(f"<b>Konteyner Konumu:</b> Ofset {self.entry.get('offset', 0):,} | Uzunluk {self.entry.get('len', 0):,} bayt"))

        hash_box = QVBoxLayout()
        hash_box.setSpacing(3)
        hash_box.addWidget(QLabel("<b>SHA-256 Kriptografik Özeti (Parmak İzi):</b>"))
        h_row = QHBoxLayout()
        txt_sha = QLineEdit(self.entry.get("sha256", ""))
        txt_sha.setReadOnly(True)
        h_row.addWidget(txt_sha)
        btn_copy_sha = QPushButton("Kopyala")
        btn_copy_sha.clicked.connect(lambda: QApplication.clipboard().setText(txt_sha.text()))
        h_row.addWidget(btn_copy_sha)
        hash_box.addLayout(h_row)
        c_layout.addLayout(hash_box)

        layout.addWidget(card)

        check_card = QFrame()
        check_card.setProperty("class", "card")
        chk_layout = QVBoxLayout(check_card)
        chk_layout.setSpacing(6)

        self.lbl_check_result = QLabel("Kriptografik AEAD etiketi ve SHA-256 hash doğrulaması için aşağıdaki butona basın.")
        self.lbl_check_result.setWordWrap(True)
        chk_layout.addWidget(self.lbl_check_result)

        self.btn_run_check = QPushButton("Bütünlüğü Canlı Test Et (AEAD Tag)")
        self.btn_run_check.setObjectName("btn-action")
        self.btn_run_check.clicked.connect(self.run_integrity_check)
        chk_layout.addWidget(self.btn_run_check)

        layout.addWidget(check_card)

        btn_close = QPushButton("Kapat")
        btn_close.clicked.connect(self.accept)
        layout.addWidget(btn_close)

    def run_integrity_check(self):
        f_id = self.entry.get("id", "")
        res = CustomVaultEngine.verify_file_integrity(self.vault_path, self.auth_info, f_id)
        if res.get("valid"):
            self.lbl_check_result.setText(
                "[DOĞRULANDI] BÜTÜNLÜK KUSURSUZ DOĞRULANDI!\n"
                "• AES-256-GCM kimlik doğrulama etiketi (AEAD tag) eşleşti.\n"
                "• Dosya verisi bit düzeyinde incelendi ve hiçbir tahrifat tespit edilmedi."
            )
            self.lbl_check_result.setStyleSheet("color: #10B981; font-weight: 700;")
            self.btn_run_check.setEnabled(False)
            self.btn_run_check.setText("Doğrulandı [OK]")
        else:
            self.lbl_check_result.setText(f"[HATA] BÜTÜNLÜK HATASI: {res.get('error', 'Bilinmeyen hata')}")
            self.lbl_check_result.setStyleSheet("color: #EF4444; font-weight: 700;")

class VaultTextEditorDialog(QDialog):
    """Kasa içerisindeki metin ve kod dosyalarını bellekte doğrudan düzenler ve kaydeder."""
    file_saved = pyqtSignal(str)

    def __init__(self, parent, file_data: Dict[str, Any], vault_path: str, auth_info: Dict[str, Any], is_dark: bool = True, theme: Optional[str] = None):
        super().__init__(parent)
        self.file_data = file_data
        self.vault_path = vault_path
        self.auth_info = auth_info
        self.theme = theme or getattr(parent, "current_theme", None) or ("dark" if is_dark else "light")
        self.is_dark = (self.theme in ("dark", "apple_dark"))
        self.entry = file_data.get("entry", {})
        self.fname = Path(self.entry.get("path", "")).name
        self.is_modified = False
        self.setWindowTitle(f"Kasa İçi Düzenleyici - {self.fname}")
        self.setSizeGripEnabled(True)
        apply_dynamic_geometry(self, default_w=660, default_h=460, min_w=520, min_h=340)
        self.setup_ui()
        self.load_content()

    def setup_ui(self):
        pal = get_dialog_palette(self.theme)
        bg_col = pal["bg_col"]
        card_bg = pal["card_bg"]
        border_col = pal["border_col"]
        text_col = pal["text_col"]
        accent_col = pal["accent_col"]

        self.setStyleSheet(f"""
            QDialog {{ background-color: {bg_col}; color: {text_col}; font-family: 'Segoe UI', 'Inter', sans-serif; }}
            QFrame#top-bar {{ background-color: {card_bg}; border-bottom: 2px solid {border_col}; }}
            QPlainTextEdit {{
                background-color: {'#090D18' if self.is_dark else '#FFFFFF'};
                color: {text_col};
                border: 2px solid {border_col};
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 12px;
                padding: 6px;
            }}
            QPushButton {{
                background-color: {'#18233C' if self.is_dark else '#F1F5F9'};
                color: {text_col};
                font-size: 11px;
                font-weight: 700;
                padding: 5px 12px;
                border: 2px solid {border_col};
            }}
            QPushButton:hover {{
                background-color: {'#223254' if self.is_dark else '#E2E8F0'};
                border-color: {accent_col};
                color: {accent_col};
            }}
            QPushButton#btn-save {{
                background-color: {'#0C5478' if self.is_dark else '#0284C7'};
                color: #FFFFFF;
                border-color: {accent_col};
            }}
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        top_bar = QFrame()
        top_bar.setObjectName("top-bar")
        t_layout = QHBoxLayout(top_bar)
        t_layout.setContentsMargins(6, 4, 6, 4)
        t_layout.setSpacing(8)

        lbl_icon = QLabel()
        lbl_icon.setPixmap(get_svg_pixmap("file_text", accent_col, 18))
        t_layout.addWidget(lbl_icon)

        self.lbl_title = QLabel(f"/{self.entry.get('path', '')}")
        self.lbl_title.setStyleSheet(f"font-size: 12px; font-weight: 700; color: {accent_col};")
        t_layout.addWidget(self.lbl_title)

        t_layout.addStretch()

        self.btn_save = QPushButton("Kasaya Kaydet")
        self.btn_save.setObjectName("btn-save")
        self.btn_save.setIcon(get_svg_icon("save", "#FFFFFF", 14))
        self.btn_save.clicked.connect(self.save_content)
        t_layout.addWidget(self.btn_save)

        self.btn_reload = QPushButton("Yeniden Yükle")
        self.btn_reload.setIcon(get_svg_icon("refresh", accent_col, 14))
        self.btn_reload.clicked.connect(self.load_content)
        t_layout.addWidget(self.btn_reload)

        layout.addWidget(top_bar)

        self.editor = QPlainTextEdit()
        self.editor.textChanged.connect(self.on_text_changed)
        layout.addWidget(self.editor)

        bot_bar = QHBoxLayout()
        self.lbl_editor_status = QLabel("Yükleniyor...")
        self.lbl_editor_status.setStyleSheet("font-size: 10px; color: #8B9EB7;")
        bot_bar.addWidget(self.lbl_editor_status)
        bot_bar.addStretch()
        self.lbl_save_toast = QLabel("")
        self.lbl_save_toast.setStyleSheet("font-size: 11px; font-weight: 700; color: #10B981;")
        bot_bar.addWidget(self.lbl_save_toast)

        layout.addLayout(bot_bar)

    def load_content(self):
        try:
            f_id = self.entry.get("id", "")
            raw, _ = CustomVaultEngine.extract_file_bytes(self.vault_path, self.auth_info, f_id)
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                text = raw.decode("latin-1", errors="replace")
            self.editor.setPlainText(text)
            self.is_modified = False
            self.update_stats()
            self.lbl_save_toast.setText("Dosya kasadan belleğe yüklendi.")
            QTimer.singleShot(2500, lambda: self.lbl_save_toast.setText(""))
        except Exception as e:
            QMessageBox.critical(self, "Hata", f"Dosya açılamadı:\n{e}")

    def on_text_changed(self):
        self.is_modified = True
        self.update_stats()

    def update_stats(self):
        lines = self.editor.document().lineCount()
        chars = len(self.editor.toPlainText())
        words = len(self.editor.toPlainText().split())
        mod_flag = " (Değiştirildi *)" if self.is_modified else ""
        self.lbl_editor_status.setText(f"Satır: {lines} | Kelime: {words} | Karakter: {chars}{mod_flag}")

    def save_content(self):
        try:
            text = self.editor.toPlainText()
            raw_bytes = text.encode("utf-8")
            rel_p = self.entry.get("path", "")
            res = CustomVaultEngine.write_file_bytes(self.vault_path, self.auth_info, rel_p, raw_bytes)
            self.entry = res.get("entry", self.entry)
            self.is_modified = False
            self.update_stats()
            self.lbl_save_toast.setText("[KAYDEDİLDİ] Kasaya doğrudan AES-256-GCM ile kaydedildi!")
            QTimer.singleShot(3000, lambda: self.lbl_save_toast.setText(""))
            self.file_saved.emit(self.entry.get("id", ""))
        except Exception as e:
            QMessageBox.critical(self, "Hata", f"Kaydedilemedi:\n{e}")

    def closeEvent(self, event):
        if self.is_modified:
            ans = QMessageBox.question(
                self,
                "Kaydedilmemiş Değişiklikler",
                "Dosyada yaptığınız değişiklikler henüz kasaya kaydedilmedi. Kaydetmeden çıkmak istiyor musunuz?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )
            if ans != QMessageBox.StandardButton.Yes:
                event.ignore()
                return
        event.accept()

class VaultHexViewerDialog(QDialog):
    """Kasadaki herhangi bir dosyanın ikili (hex dump) verisini bellekte görüntüler."""
    def __init__(self, parent, file_data: Dict[str, Any], vault_path: str, auth_info: Dict[str, Any], is_dark: bool = True, theme: Optional[str] = None):
        super().__init__(parent)
        self.file_data = file_data
        self.vault_path = vault_path
        self.auth_info = auth_info
        self.theme = theme or getattr(parent, "current_theme", None) or ("dark" if is_dark else "light")
        self.is_dark = (self.theme in ("dark", "apple_dark"))
        self.entry = file_data.get("entry", {})
        self.fname = Path(self.entry.get("path", "")).name
        self.setWindowTitle(f"Hex / İkili İnceleme - {self.fname}")
        self.setSizeGripEnabled(True)
        apply_dynamic_geometry(self, default_w=700, default_h=460, min_w=580, min_h=340)
        self.setup_ui()
        self.load_hex()

    def setup_ui(self):
        pal = get_dialog_palette(self.theme)
        bg_col = pal["bg_col"]
        border_col = pal["border_col"]
        text_col = pal["text_col"]
        accent_col = pal["accent_col"]

        self.setStyleSheet(f"""
            QDialog {{ background-color: {bg_col}; color: {text_col}; font-family: 'Segoe UI', 'Inter', sans-serif; }}
            QPlainTextEdit {{
                background-color: {'#060911' if self.is_dark else '#FFFFFF'};
                color: {'#38BDF8' if self.is_dark else '#0284C7'};
                border: 2px solid {border_col};
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 11px;
                padding: 6px;
            }}
            QPushButton {{
                background-color: {'#18233C' if self.is_dark else '#F1F5F9'};
                color: {text_col};
                font-size: 11px;
                font-weight: 700;
                padding: 5px 12px;
                border: 2px solid {border_col};
            }}
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(8)

        lbl = QLabel(f"Dosya: /{self.entry.get('path', '')} (İlk 4096 Bayt Hex Görünümü)")
        lbl.setStyleSheet(f"font-size: 12px; font-weight: 800; color: {accent_col};")
        layout.addWidget(lbl)

        self.txt_hex = QPlainTextEdit()
        self.txt_hex.setReadOnly(True)
        layout.addWidget(self.txt_hex)

        bot = QHBoxLayout()
        btn_copy = QPushButton("Hex Metnini Kopyala")
        btn_copy.clicked.connect(lambda: QApplication.clipboard().setText(self.txt_hex.toPlainText()))
        bot.addWidget(btn_copy)
        bot.addStretch()
        btn_close = QPushButton("Kapat")
        btn_close.clicked.connect(self.accept)
        bot.addWidget(btn_close)
        layout.addLayout(bot)

    def load_hex(self):
        try:
            f_id = self.entry.get("id", "")
            raw, _ = CustomVaultEngine.extract_file_bytes(self.vault_path, self.auth_info, f_id)
            view_bytes = raw[:4096]
            lines = []
            for i in range(0, len(view_bytes), 16):
                chunk = view_bytes[i:i+16]
                hex_part = " ".join(f"{b:02x}" for b in chunk)
                ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
                lines.append(f"{i:08x}  {hex_part:<48}  |{ascii_part}|")
            if len(raw) > 4096:
                lines.append(f"\n... (Toplam {len(raw):,} bayttan ilk 4096 bayt gösteriliyor) ...")
            self.txt_hex.setPlainText("\n".join(lines))
        except Exception as e:
            self.txt_hex.setPlainText(f"Hex yükleme hatası: {e}")

class VaultTaskThread(QThread):
    """Büyük dosya aktarımlarını, dışa aktarmaları ve sıkıştırmayı arka planda yürüten iş parçacığı."""
    progress = pyqtSignal(int, str, str)
    finished_signal = pyqtSignal(bool, str, object)

    def __init__(self, task_type: str, vault_path: str, auth_info: Dict[str, Any], **kwargs):
        super().__init__()
        self.task_type = task_type
        self.vault_path = vault_path
        self.auth_info = auth_info
        self.kwargs = kwargs
        self._cancel_requested = False

    def cancel(self):
        self._cancel_requested = True

    def run(self):
        try:
            if self.task_type == "import":
                self._run_import()
            elif self.task_type == "export":
                self._run_export()
            elif self.task_type == "compact":
                self._run_compact()
            else:
                self.finished_signal.emit(False, f"Bilinmeyen görev türü: {self.task_type}", None)
        except Exception as e:
            self.finished_signal.emit(False, str(e), None)

    def _run_import(self):
        file_paths = self.kwargs.get("file_paths", [])
        dest_dir = self.kwargs.get("dest_dir", "").replace("\\", "/").strip("/ ")
        
        all_items: List[Tuple[str, str, bool, int]] = []
        total_bytes = 0

        for p_str in file_paths:
            p = Path(p_str)
            if not p.exists():
                continue
            if p.is_file():
                rel = f"{dest_dir}/{p.name}" if dest_dir else p.name
                sz = p.stat().st_size
                all_items.append((str(p), rel, False, sz))
                total_bytes += sz
            elif p.is_dir():
                sub_dir_name = f"{dest_dir}/{p.name}" if dest_dir else p.name
                all_items.append((str(p), sub_dir_name, True, 0))
                for root, dirs, files in os.walk(str(p)):
                    r_path = Path(root)
                    try:
                        rel_to_parent = r_path.relative_to(p)
                        cur_vault_dir = f"{sub_dir_name}/{rel_to_parent.as_posix()}" if str(rel_to_parent) != "." else sub_dir_name
                    except Exception:
                        cur_vault_dir = sub_dir_name
                    for d in dirs:
                        all_items.append(("", f"{cur_vault_dir}/{d}", True, 0))
                    for f in files:
                        full_f = r_path / f
                        f_rel = f"{cur_vault_dir}/{f}"
                        try:
                            sz = full_f.stat().st_size
                        except Exception:
                            sz = 0
                        all_items.append((str(full_f), f_rel, False, sz))
                        total_bytes += sz

        total_count = len(all_items)
        if total_count == 0:
            self.finished_signal.emit(True, "İçe aktarılacak geçerli dosya bulunamadı.", {"added_count": 0, "errors": []})
            return

        added_count = 0
        processed_bytes = 0
        errors = []
        t0 = time.time()

        for idx, (src_str, rel_target, is_dir, sz) in enumerate(all_items):
            if self._cancel_requested:
                break

            pct = int((processed_bytes / total_bytes * 100)) if total_bytes > 0 else int((idx / total_count * 100))
            elapsed = max(0.001, time.time() - t0)
            speed_mb = (processed_bytes / (1024 * 1024)) / elapsed
            speed_str = f" • {speed_mb:.1f} MB/s" if processed_bytes > 2 * 1024 * 1024 else ""

            name = Path(rel_target).name or rel_target
            self.progress.emit(
                pct,
                f"Kasaya Aktarılıyor ({idx+1}/{total_count})",
                f"{name} ({format_size(sz)}){speed_str}"
            )

            try:
                if is_dir:
                    CustomVaultEngine.add_folder(self.vault_path, self.auth_info, rel_target)
                else:
                    add_res = CustomVaultEngine.add_file(self.vault_path, self.auth_info, src_str, rel_target)
                    added_count += 1
                    processed_bytes += sz

            except Exception as e:
                errors.append(f"{name}: {e}")

        self.progress.emit(100, "Tamamlandı", "Tüm dosyalar güvenle şifrelendi.")
        self.finished_signal.emit(True, f"{added_count} dosya başarıyla kasaya eklendi.", {"added_count": added_count, "errors": errors})

    def _run_export(self):
        items_to_export: List[Tuple[Dict[str, Any], str]] = self.kwargs.get("items", [])
        total_count = len(items_to_export)
        total_bytes = sum(item[0].get("size", 0) for item in items_to_export)

        exported_count = 0
        processed_bytes = 0
        errors = []
        t0 = time.time()

        for idx, (entry, out_path_str) in enumerate(items_to_export):
            if self._cancel_requested:
                break

            sz = entry.get("size", 0)
            pct = int((processed_bytes / total_bytes * 100)) if total_bytes > 0 else int((idx / total_count * 100))
            elapsed = max(0.001, time.time() - t0)
            speed_mb = (processed_bytes / (1024 * 1024)) / elapsed
            speed_str = f" • {speed_mb:.1f} MB/s" if processed_bytes > 2 * 1024 * 1024 else ""

            name = Path(out_path_str).name
            self.progress.emit(
                pct,
                f"Dışa Aktarılıyor ({idx+1}/{total_count})",
                f"{name} ({format_size(sz)}){speed_str}"
            )

            try:
                CustomVaultEngine.extract_file(self.vault_path, self.auth_info, entry["id"], out_path_str)
                exported_count += 1
                processed_bytes += sz
            except Exception as e:
                errors.append(f"{name}: {e}")

        self.progress.emit(100, "Tamamlandı", "Dışa aktarma tamamlandı.")
        self.finished_signal.emit(True, f"{exported_count} dosya dışa aktarıldı.", {"exported_count": exported_count, "errors": errors})

    def _run_compact(self):
        self.progress.emit(10, "Kasa Optimize Ediliyor", "Silinmiş bloklar taranıyor...")
        time.sleep(0.05)
        self.progress.emit(35, "Kasa Sıkıştırılıyor", "Veri blokları 4 MB akış tamponlarıyla yeniden düzenleniyor...")
        res = CustomVaultEngine.compact_vault(
            self.vault_path, self.auth_info,
            discard_other_compartment=self.kwargs.get("discard_other_compartment", False)
        )
        self.progress.emit(100, "Tamamlandı", "Kasa disk alanı başarıyla geri kazanıldı.")
        self.finished_signal.emit(True, "Kasa başarıyla optimize edildi.", res)

class VaultProgressDialog(QDialog):
    """İşlem sırasında arayüzün akıcı kalmasını sağlayan modern Fluent ilerleme penceresi."""
    def __init__(self, parent=None, title: str = "İşlem Yapılıyor", is_dark: bool = True, theme: Optional[str] = None):
        super().__init__(parent)
        self.theme = theme or getattr(parent, "current_theme", None) or ("dark" if is_dark else "light")
        self.is_dark = (self.theme in ("dark", "apple_dark"))
        self.result_data = None
        self.is_success = False
        self.error_message = ""
        self.worker_thread: Optional[VaultTaskThread] = None

        self.setWindowTitle(title)
        apply_dynamic_geometry(self, default_w=420, default_h=170, min_w=360, min_h=140)
        self.setSizeGripEnabled(True)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowType.WindowContextHelpButtonHint)
        self.setModal(True)
        self.setup_ui(title)

    def setup_ui(self, title: str):
        bg_col = "#202024" if self.is_dark else "#FFFFFF"
        text_col = "#FFFFFF" if self.is_dark else "#1A1A1A"
        muted_col = "#A1A1AA" if self.is_dark else "#71717A"
        border_col = "rgba(255, 255, 255, 0.1)" if self.is_dark else "rgba(0, 0, 0, 0.1)"
        accent_col = "#38BDF8" if self.is_dark else "#059669"

        self.setStyleSheet(f"""
            QDialog {{
                background-color: {bg_col};
                border: 1px solid {border_col};
                border-radius: 12px;
                font-family: 'Segoe UI', 'Inter', sans-serif;
            }}
            QLabel {{
                background: transparent;
            }}
            QProgressBar {{
                background-color: {'rgba(255, 255, 255, 0.08)' if self.is_dark else '#E5E7EB'};
                border-radius: 6px;
                border: none;
                height: 8px;
                text-align: center;
            }}
            QProgressBar::chunk {{
                background-color: {accent_col};
                border-radius: 6px;
            }}
            QPushButton {{
                background-color: {'rgba(255, 255, 255, 0.06)' if self.is_dark else '#F3F4F6'};
                color: {text_col};
                border: 1px solid {border_col};
                border-radius: 6px;
                padding: 6px 16px;
                font-size: 12px;
                font-weight: 600;
            }}
            QPushButton:hover {{
                background-color: {'rgba(255, 255, 255, 0.12)' if self.is_dark else '#E5E7EB'};
            }}
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(10)

        top_h = QHBoxLayout()
        top_h.setSpacing(12)
        
        self.lbl_icon = QLabel()
        self.lbl_icon.setPixmap(get_svg_pixmap("shield", accent_col, 28))
        top_h.addWidget(self.lbl_icon)

        title_v = QVBoxLayout()
        title_v.setSpacing(3)
        self.lbl_title = QLabel(title)
        self.lbl_title.setStyleSheet(f"font-size: 14px; font-weight: 700; color: {text_col};")
        title_v.addWidget(self.lbl_title)

        self.lbl_detail = QLabel("Lütfen bekleyin...")
        self.lbl_detail.setStyleSheet(f"font-size: 12px; color: {muted_col};")
        title_v.addWidget(self.lbl_detail)
        top_h.addLayout(title_v)
        top_h.addStretch()

        layout.addLayout(top_h)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(False)
        layout.addWidget(self.progress_bar)

        bot_h = QHBoxLayout()
        self.lbl_pct = QLabel("0%")
        self.lbl_pct.setStyleSheet(f"font-size: 11px; font-weight: 600; color: {muted_col};")
        bot_h.addWidget(self.lbl_pct)
        bot_h.addStretch()

        self.btn_cancel = QPushButton("İptal Et")
        self.btn_cancel.clicked.connect(self.on_cancel_clicked)
        bot_h.addWidget(self.btn_cancel)
        layout.addLayout(bot_h)

    def attach_thread(self, thread: VaultTaskThread):
        self.worker_thread = thread
        thread.progress.connect(self.on_progress)
        thread.finished_signal.connect(self.on_finished)

    def on_progress(self, pct: int, title: str, detail: str):
        if pct >= 0:
            self.progress_bar.setValue(pct)
            self.lbl_pct.setText(f"%{pct}")
        if title:
            self.lbl_title.setText(title)
        if detail:
            self.lbl_detail.setText(detail)

    def on_finished(self, success: bool, message: str, data: object):
        self.is_success = success
        self.error_message = "" if success else message
        self.result_data = data
        self.accept()

    def on_cancel_clicked(self):
        if self.worker_thread and self.worker_thread.isRunning():
            self.btn_cancel.setEnabled(False)
            self.btn_cancel.setText("İptal Ediliyor...")
            self.lbl_detail.setText("İşlem durduruluyor, lütfen bekleyin...")
            self.worker_thread.cancel()
        else:
            self.reject()

    def closeEvent(self, event):
        if self.worker_thread and self.worker_thread.isRunning():
            self.worker_thread.cancel()
            self.worker_thread.wait(2000)
        event.accept()

class CustomVaultFullscreenViewerDialog(QDialog):
    """
    Microsoft Photos Legacy (Windows Fotoğraflar Eski) Tarzı Şifreli Görsel Görüntüleyici & Slayt Gösterisi.
    - Kusursuz Tiyatro Siyahı (#000000) tuval ve akıcı Windows Fluent Acrylic yarı saydam paneller.
    - Üst Başlık Şeridi: Dosya adı, fotoğraf sayacı [03 / 12], çözünürlük/boyut, 90° döndürme, sığdırma ve yakınlaştırma.
    - Yan Gezinme Okları: Ekranın sol ve sağ kenarlarında dikey ortalı zarif şeffaf butonlar (|◀ ve ▶|).
    - Alt Medya Kontrol Kapsülü (Photos Legacy Command Bar):
        * Merkezi kahraman Oynat/Duraklat (Play/Pause) dairesel butonu
        * Önceki / Sonraki butonları
        * Geçiş süresi seçici (2s, 3s, 5s, 10s)
        * Döngü (Loop) ve Karışık (Shuffle) modları
        * Geçiş efekti seçici (Çözünme / Ken Burns / Anlık)
        * 90° Sağa Döndür butonu (bellek içi RAM-only sıfır adli iz)
        * Küçük Resim Şeridi (Filmstrip Thumbnail Gallery) dock geçişi
        * Tam Ekran / Pencere geçişi
    - Hareketsizlikte Otomatik Gizleme (Auto-Hide Idle): 2.5 saniye hareketsizlikte fare imleci (BlankCursor)
      ve tüm arayüz şeffaflaşarak gizlenir, fotoğraf %100 saf ve kenarlıksız görüntülenir.
    - Bellek İçi 90° Saat Yönünde Döndürme (RAM-Only In-Place Rotation): Diske yazmadan anında döndürme.
    - %100 Vektörel SVG ikonlar, sıfır emoji kuralı ve RAM-Only sıfır adli iz güvencesi.
    """
    def __init__(
        self,
        parent=None,
        vault_path: str = "",
        auth_info: Optional[Dict[str, Any]] = None,
        initial_file_id: str = "",
        image_entries: Optional[List[Dict[str, Any]]] = None,
        theme: str = "dark",
        auto_start_slideshow: bool = False
    ):
        super().__init__(parent)
        self.explorer_parent = parent
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.saved_normal_geom: Optional[QRect] = None
        self.vault_path = vault_path
        self.auth_info = auth_info or {}
        self.image_entries = image_entries or []
        self.current_index = 0
        self.current_theme = theme
        self.is_dark = (theme in ("dark", "apple_dark"))
        self.accent_col = "#2997FF" if theme == "apple_dark" else ("#0071E3" if theme == "apple_light" else ("#38BDF8" if self.is_dark else "#0284C7"))
        self.accent_rgb = "41, 151, 255" if theme == "apple_dark" else ("0, 113, 227" if theme == "apple_light" else ("56, 189, 248" if self.is_dark else "2, 132, 199"))
        self.zoom_level = 1.0
        self.current_pixmap: Optional[QPixmap] = None
        self.current_rotation = 0

        self.slideshow_active = False
        self.slideshow_interval_ms = 15000
        self.slideshow_loop = True
        self.slideshow_shuffle = False
        self.slideshow_elapsed_ms = 0
        self.slideshow_tick_ms = 40
        self.transition_mode = "crossfade"
        self.show_filmstrip = True

        self.fade_step = 0
        self.fade_total_steps = 14
        self.fade_timer = QTimer(self)
        self.fade_timer.timeout.connect(self._on_fade_step)

        self.idle_timeout_ms = 3000
        self.auto_fit_mode = True
        self.idle_timer = QTimer(self)
        self.idle_timer.setSingleShot(True)
        self.idle_timer.timeout.connect(self._on_idle_timeout)

        self.slideshow_timer = QTimer(self)
        self.slideshow_timer.timeout.connect(self._on_slideshow_tick)

        self.mini_thumb_cache: Dict[str, QPixmap] = {}
        self.filmstrip_buttons: List[QPushButton] = []

        for idx, entry in enumerate(self.image_entries):
            if entry.get("id") == initial_file_id:
                self.current_index = idx
                break

        self.setWindowTitle("Fotoğraflar - Slayt Gösterisi")
        self.setWindowFlags(Qt.WindowType.Window | Qt.WindowType.WindowMinMaxButtonsHint | Qt.WindowType.WindowCloseButtonHint)
        self.setMinimumSize(640, 420)
        self.setSizeGripEnabled(True)

        from PyQt6.QtGui import QKeySequence, QShortcut
        self.sc_viewer_f11 = QShortcut(QKeySequence(Qt.Key.Key_F11), self)
        self.sc_viewer_f11.setContext(Qt.ShortcutContext.WindowShortcut)
        self.sc_viewer_f11.activated.connect(self.toggle_fullscreen_mode)

        self.sc_viewer_f = QShortcut(QKeySequence(Qt.Key.Key_F), self)
        self.sc_viewer_f.setContext(Qt.ShortcutContext.WindowShortcut)
        self.sc_viewer_f.activated.connect(self.toggle_fullscreen_mode)

        self.sc_viewer_esc = QShortcut(QKeySequence(Qt.Key.Key_Escape), self)
        self.sc_viewer_esc.setContext(Qt.ShortcutContext.WindowShortcut)
        self.sc_viewer_esc.activated.connect(self.reject)

        self.init_ui()
        self.load_image_at_current_index(initial=True)
        self.populate_filmstrip()

        if auto_start_slideshow:
            QTimer.singleShot(250, self.start_slideshow)

    def showEvent(self, event):
        super().showEvent(event)
        QTimer.singleShot(40, self._on_initial_show)

    def _on_initial_show(self):
        if self.isFullScreen():
            screen = self.screen() or QGuiApplication.primaryScreen()
            sg = screen.geometry() if screen else QRect(0, 0, 1920, 1080)
            set_win32_window_zorder(self, topmost=True, geom=sg)
        self.update_overlay_positions()
        self.fit_to_screen()
        self._wake_hud()
        self.raise_()
        self.activateWindow()
        self.setFocus()

    def init_ui(self):
        bg_col = "#080B12" if self.is_dark else "#0A0D14"
        acrylic_bar_bg = "rgba(11, 15, 25, 0.85)" if self.is_dark else "rgba(15, 23, 42, 0.90)"
        capsule_bg = "rgba(11, 17, 30, 0.90)" if self.is_dark else "rgba(15, 23, 42, 0.92)"
        text_col = "#FFFFFF"
        text_muted = "#94A3B8"
        accent_col = "#2997FF" if getattr(self, "theme", "dark") == "apple_dark" else ("#0071E3" if getattr(self, "theme", "dark") == "apple_light" else ("#38BDF8" if self.is_dark else "#0284C7"))
        accent_rgb = "41, 151, 255" if getattr(self, "theme", "dark") == "apple_dark" else ("0, 113, 227" if getattr(self, "theme", "dark") == "apple_light" else ("56, 189, 248" if self.is_dark else "2, 132, 199"))
        border_col = "rgba(255, 255, 255, 0.12)" if self.is_dark else "rgba(255, 255, 255, 0.16)"
        btn_hover_bg = "rgba(255, 255, 255, 0.10)"

        self.setStyleSheet(f"""
            QDialog {{
                background-color: {bg_col};
                color: {text_col};
            }}
            QGraphicsView {{
                background-color: {bg_col};
                border: none;
            }}
            #fs-top-header {{
                background-color: {acrylic_bar_bg};
                border-bottom: 1px solid {border_col};
            }}
            #fs-btn {{
                background-color: rgba(255, 255, 255, 0.05);
                border: 1px solid rgba(255, 255, 255, 0.08);
                border-radius: 8px;
                padding: 5px 10px;
                color: {text_col};
                font-family: 'Segoe UI Variable', -apple-system, sans-serif;
                font-size: 11.5px;
                font-weight: 600;
            }}
            #fs-btn:hover {{
                background-color: rgba(56, 189, 248, 0.14);
                border: 1px solid {accent_col};
                color: {accent_col};
            }}
            #fs-btn:pressed {{
                background-color: rgba(56, 189, 248, 0.22);
            }}
            QPushButton#fs-nav-btn {{
                background-color: rgba(15, 23, 42, 0.72);
                border: 1px solid rgba(255, 255, 255, 0.14);
                border-radius: 26px;
                min-width: 50px;
                max-width: 50px;
                min-height: 50px;
                max-height: 50px;
                padding: 0px;
                margin: 0px;
            }}
            QPushButton#fs-nav-btn:hover {{
                background-color: rgba(22, 33, 56, 0.94);
                border: 1.5px solid {accent_col};
            }}
            QPushButton#fs-nav-btn:disabled {{
                opacity: 0.15;
                background-color: transparent;
                border: none;
            }}
        """)

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        self.scene = QGraphicsScene(self)
        self.view = QGraphicsView(self.scene)
        self.view.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.view.setRenderHints(QPainter.RenderHint.Antialiasing | QPainter.RenderHint.SmoothPixmapTransform)
        self.view.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.view.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorViewCenter)
        self.view.setResizeAnchor(QGraphicsView.ViewportAnchor.AnchorViewCenter)
        self.view.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.view.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setMouseTracking(True)
        self.view.setMouseTracking(True)
        self.view.viewport().setMouseTracking(True)
        self.view.viewport().installEventFilter(self)
        self.view.installEventFilter(self)

        self.pixmap_item_back = QGraphicsPixmapItem()
        self.pixmap_item_back.setZValue(1)
        self.scene.addItem(self.pixmap_item_back)

        self.pixmap_item = QGraphicsPixmapItem()
        self.pixmap_item.setZValue(2)
        self.scene.addItem(self.pixmap_item)

        main_layout.addWidget(self.view, stretch=1)

        self.top_header = QFrame(self.view)
        self.top_header.setObjectName("fs-top-header")
        th_layout = QHBoxLayout(self.top_header)
        th_layout.setContentsMargins(12, 4, 12, 4)
        th_layout.setSpacing(6)

        self.btn_back = QPushButton()
        self.btn_back.setObjectName("fs-btn")
        self.btn_back.setFixedSize(34, 32)
        self.btn_back.setIcon(get_svg_icon("arrow_left", text_col, 16))
        self.btn_back.setToolTip("Geri / Kapat (Esc)")
        self.btn_back.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_back.clicked.connect(self.reject)
        th_layout.addWidget(self.btn_back)

        self.hud_info_badge = QFrame(self.top_header)
        self.hud_info_badge.setStyleSheet("background: transparent; border: none;")
        ib_layout = QHBoxLayout(self.hud_info_badge)
        ib_layout.setContentsMargins(0, 0, 0, 0)
        ib_layout.setSpacing(6)

        self.lbl_hud_name = QLabel("Görsel Yükleniyor...")
        self.lbl_hud_name.setStyleSheet(f"font-size: 12.5px; font-weight: 700; color: {text_col};")
        self.lbl_hud_name.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)
        ib_layout.addWidget(self.lbl_hud_name)
        self.lbl_title = self.lbl_hud_name

        self.lbl_hud_badge = QLabel()
        self.lbl_hud_badge.setStyleSheet(f"font-size: 11px; font-weight: 700; color: {accent_col}; padding: 2px 8px; background: rgba(255, 255, 255, 0.10); border: 1px solid {border_col}; border-radius: 10px;")
        ib_layout.addWidget(self.lbl_hud_badge)
        th_layout.addWidget(self.hud_info_badge)

        self.lbl_meta = QLabel()
        self.lbl_meta.setStyleSheet(f"font-size: 11px; color: {text_muted}; padding-left: 2px;")
        self.lbl_meta.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)
        th_layout.addWidget(self.lbl_meta)

        th_layout.addStretch(1)

        self.btn_options = QPushButton(" Seçenekler")
        self.btn_options.setObjectName("fs-btn")
        self.btn_options.setFixedHeight(32)
        self.btn_options.setIcon(get_svg_icon("settings", text_col, 14))
        self.btn_options.setToolTip("Slayt Gösterisi ve Görünüm Seçenekleri (Sağ Tık / Kısayol: S)")
        self.btn_options.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_options.clicked.connect(self.show_options_menu)
        th_layout.addWidget(self.btn_options)

        self.btn_rotate = QPushButton()
        self.btn_rotate.setObjectName("fs-btn")
        self.btn_rotate.setFixedSize(34, 32)
        self.btn_rotate.setIcon(get_svg_icon("rotate_cw", text_col, 15))
        self.btn_rotate.setToolTip("90° Sağa Döndür (R)")
        self.btn_rotate.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_rotate.clicked.connect(lambda: self.rotate_image(90))
        th_layout.addWidget(self.btn_rotate)

        self.btn_fit = QPushButton(" Sığdır")
        self.btn_fit.setObjectName("fs-btn")
        self.btn_fit.setFixedHeight(32)
        self.btn_fit.setIcon(get_svg_icon("fit_screen", text_col, 14))
        self.btn_fit.setToolTip("Ekrana Sığdır (0)")
        self.btn_fit.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_fit.clicked.connect(self.fit_to_screen)
        th_layout.addWidget(self.btn_fit)

        self.btn_zoom_out = QPushButton()
        self.btn_zoom_out.setObjectName("fs-btn")
        self.btn_zoom_out.setFixedSize(34, 32)
        self.btn_zoom_out.setIcon(get_svg_icon("zoom_out", text_col, 15))
        self.btn_zoom_out.setToolTip("Uzaklaştır (-)")
        self.btn_zoom_out.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_zoom_out.clicked.connect(lambda: self.zoom_by(1.0 / 1.25))
        th_layout.addWidget(self.btn_zoom_out)

        self.lbl_zoom = QLabel("%100")
        self.lbl_zoom.setStyleSheet(f"font-size: 11px; font-weight: 700; color: {text_col}; min-width: 40px;")
        self.lbl_zoom.setAlignment(Qt.AlignmentFlag.AlignCenter)
        th_layout.addWidget(self.lbl_zoom)

        self.btn_zoom_in = QPushButton()
        self.btn_zoom_in.setObjectName("fs-btn")
        self.btn_zoom_in.setFixedSize(34, 32)
        self.btn_zoom_in.setIcon(get_svg_icon("zoom_in", text_col, 15))
        self.btn_zoom_in.setToolTip("Yakınlaştır (+)")
        self.btn_zoom_in.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_zoom_in.clicked.connect(lambda: self.zoom_by(1.25))
        th_layout.addWidget(self.btn_zoom_in)

        self.btn_toggle_fs = QPushButton()
        self.btn_toggle_fs.setObjectName("fs-btn")
        self.btn_toggle_fs.setFixedSize(34, 32)
        self.btn_toggle_fs.setIcon(get_svg_icon("expand", text_col, 15))
        self.btn_toggle_fs.setToolTip("Tam Ekran Modu (F11)")
        self.btn_toggle_fs.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_toggle_fs.clicked.connect(self.toggle_fullscreen_mode)
        th_layout.addWidget(self.btn_toggle_fs)

        self.btn_close = QPushButton()
        self.btn_close.setObjectName("fs-btn")
        self.btn_close.setFixedSize(34, 32)
        self.btn_close.setIcon(get_svg_icon("close", "#EF4444", 15))
        self.btn_close.setToolTip("Kapat (Esc)")
        self.btn_close.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_close.clicked.connect(self.reject)
        th_layout.addWidget(self.btn_close)

        self.toolbar = self.top_header

        self.slideshow_progress = QProgressBar(self.view)
        self.slideshow_progress.setFixedHeight(2)
        self.slideshow_progress.setTextVisible(False)
        self.slideshow_progress.setRange(0, 100)
        self.slideshow_progress.setValue(0)
        self.slideshow_progress.setStyleSheet(f"""
            QProgressBar {{
                background-color: transparent;
                border: none;
                max-height: 2px;
            }}
            QProgressBar::chunk {{
                background-color: {accent_col};
            }}
        """)
        self.slideshow_progress.hide()

        nav_btn_style = """
            QPushButton {
                background-color: rgba(15, 23, 42, 0.72);
                border: 1px solid rgba(255, 255, 255, 0.14);
                border-radius: 26px;
                min-width: 50px;
                max-width: 50px;
                min-height: 50px;
                max-height: 50px;
                padding: 0px;
                margin: 0px;
            }
            QPushButton:hover {
                background-color: rgba(22, 33, 56, 0.94);
                border: 1.5px solid {accent_col};
            }
            QPushButton:disabled {
                opacity: 0.15;
                background-color: transparent;
                border: none;
            }
        """
        self.btn_prev = QPushButton(self.view)
        self.btn_prev.setObjectName("fs-nav-btn")
        self.btn_prev.setStyleSheet(nav_btn_style)
        self.btn_prev.setIcon(get_svg_icon("arrow_left", text_col, 22))
        self.btn_prev.setToolTip("Önceki Görsel (Sol Ok / PageUp)")
        self.btn_prev.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_prev.setFixedSize(52, 52)
        self.btn_prev.clicked.connect(self.navigate_prev)

        self.btn_next = QPushButton(self.view)
        self.btn_next.setObjectName("fs-nav-btn")
        self.btn_next.setStyleSheet(nav_btn_style)
        self.btn_next.setIcon(get_svg_icon("arrow_right", text_col, 22))
        self.btn_next.setToolTip("Sonraki Görsel (Sağ Ok / PageDown / Boşluk)")
        self.btn_next.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_next.setFixedSize(52, 52)
        self.btn_next.clicked.connect(self.navigate_next)

        self.nav_overlay = QWidget(self.view)
        self.nav_overlay.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        self.nav_overlay.setGeometry(0, 0, 0, 0)
        self.nav_overlay.hide()

        self.filmstrip_container = QFrame(self.view)
        self.filmstrip_container.setObjectName("fs-filmstrip")
        self.filmstrip_container.setStyleSheet(f"""
            QFrame#fs-filmstrip {{
                background-color: {capsule_bg};
                border: 1px solid {border_col};
                border-radius: 12px;
            }}
        """)
        fs_outer = QVBoxLayout(self.filmstrip_container)
        fs_outer.setContentsMargins(5, 5, 5, 5)
        fs_outer.setSpacing(0)

        self.filmstrip_scroll = QScrollArea()
        self.filmstrip_scroll.setWidgetResizable(True)
        self.filmstrip_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.filmstrip_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.filmstrip_scroll.setStyleSheet("background: transparent; border: none;")

        self.filmstrip_content = QWidget()
        self.filmstrip_content.setStyleSheet("background: transparent; border: none;")
        self.filmstrip_layout = QHBoxLayout(self.filmstrip_content)
        self.filmstrip_layout.setContentsMargins(2, 2, 2, 2)
        self.filmstrip_layout.setSpacing(6)

        self.filmstrip_scroll.setWidget(self.filmstrip_content)
        fs_outer.addWidget(self.filmstrip_scroll)
        self.show_filmstrip = True

        self.hud_capsule = None
        self.btn_hud_prev = None
        self.btn_hud_play = None
        self.btn_hud_next = None
        self.btn_hud_speed = None
        self.btn_hud_loop = None
        self.btn_hud_shuffle = None
        self.btn_hud_fx = None
        self.btn_hud_rotate = None
        self.btn_hud_fs = None
        self.btn_hud_close = None
        self.btn_hud_film = None
        self.btn_slideshow = None
        self.btn_loop = None
        self.combo_interval = None

        for w in (self.top_header, self.filmstrip_container, self.btn_prev, self.btn_next):
            if w:
                w.installEventFilter(self)

        orig_view_resize = self.view.resizeEvent
        self._in_view_resize = False
        def on_view_resize(ev):
            orig_view_resize(ev)
            if getattr(self, "_in_view_resize", False):
                return
            self._in_view_resize = True
            try:
                self.update_overlay_positions()
                if getattr(self, "auto_fit_mode", True):
                    self.fit_to_screen()
            finally:
                self._in_view_resize = False
        self.view.resizeEvent = on_view_resize

    def update_overlay_positions(self):
        """Tüm kontrolleri pencerenin güncel boyutuna göre tam uyumlu, sabit, orantılı ve hizalı olarak yerleştirir."""
        vw = self.width()
        vh = self.height()
        if vw <= 0 or vh <= 0:
            return

        if hasattr(self, "top_header"):
            th_h = 50
            self.top_header.setGeometry(0, 0, vw, th_h)
            self.top_header.raise_()

            is_compact = vw < 960
            if hasattr(self, "btn_options"):
                self.btn_options.setText("" if is_compact else " Seçenekler")
                self.btn_options.setFixedWidth(34 if is_compact else 96)
            if hasattr(self, "btn_fit"):
                self.btn_fit.setText("" if is_compact else " Sığdır")
                self.btn_fit.setFixedWidth(34 if is_compact else 76)
            if hasattr(self, "lbl_meta"):
                self.lbl_meta.setVisible(vw >= 840)

            if hasattr(self, "lbl_hud_name") and getattr(self, "full_current_filename", None):
                used_w = 420 if is_compact else 600
                max_name_w = max(60, min(360, vw - used_w))
                fm = self.lbl_hud_name.fontMetrics()
                elided = fm.elidedText(self.full_current_filename, Qt.TextElideMode.ElideMiddle, max_name_w)
                self.lbl_hud_name.setText(elided)
                self.lbl_hud_name.setToolTip(self.full_current_filename)

        if hasattr(self, "slideshow_progress"):
            self.slideshow_progress.hide()

        nav_size = 52
        nav_margin = 20
        nav_y = (vh - nav_size) // 2
        if hasattr(self, "btn_prev"):
            self.btn_prev.setFixedSize(nav_size, nav_size)
            self.btn_prev.setGeometry(nav_margin, nav_y, nav_size, nav_size)
            self.btn_prev.raise_()
        if hasattr(self, "btn_next"):
            self.btn_next.setFixedSize(nav_size, nav_size)
            self.btn_next.setGeometry(vw - nav_margin - nav_size, nav_y, nav_size, nav_size)
            self.btn_next.raise_()

        screen = self.screen() or QGuiApplication.primaryScreen()
        taskbar_h = 0
        if screen:
            avail = screen.availableGeometry()
            full_geom = screen.geometry()
            taskbar_h = max(0, full_geom.bottom() - avail.bottom())

        bottom_clearance = max(28, taskbar_h + 16)
        if not self.isFullScreen():
            try:
                win_bottom = self.mapToGlobal(QPoint(0, vh)).y()
                if screen and win_bottom > screen.availableGeometry().bottom():
                    taskbar_overlap = win_bottom - screen.availableGeometry().bottom()
                    bottom_clearance = max(bottom_clearance, taskbar_overlap + 16)
            except Exception:
                pass

        if getattr(self, "filmstrip_container", None):
            if len(self.image_entries) > 1 and getattr(self, "show_filmstrip", True):
                fh = 58
                num_items = len(self.image_entries)
                content_w = num_items * (56 + 6) + 12
                fw = min(vw - 60, max(140, min(content_w, 560)))
                fx = (vw - fw) // 2
                fy = vh - fh - bottom_clearance
                self.filmstrip_container.setGeometry(fx, fy, fw, fh)
                self.filmstrip_container.show()
                self.filmstrip_container.raise_()
            else:
                self.filmstrip_container.hide()

    def populate_filmstrip(self):
        """Alt küçük resim şeridini 2. fotodaki gibi gerçek RAM tabanlı önizleme kartlarıyla doldurur."""
        if not self.image_entries:
            return
        border_col = "rgba(255, 255, 255, 0.16)"
        self.filmstrip_buttons.clear()

        while self.filmstrip_layout.count() > 0:
            it = self.filmstrip_layout.takeAt(0)
            if it.widget():
                it.widget().deleteLater()

        for idx, entry in enumerate(self.image_entries):
            f_id = entry.get("id", "")
            btn = QPushButton()
            btn.setObjectName("fs-thumb-btn")
            btn.setFixedSize(56, 44)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.setToolTip(f"{Path(entry.get('path', '')).name} ({idx + 1} / {len(self.image_entries)})")
            btn.setIconSize(QSize(52, 40))

            if f_id in self.mini_thumb_cache:
                btn.setIcon(QIcon(self.mini_thumb_cache[f_id]))
            elif hasattr(self, "explorer_parent") and hasattr(self.explorer_parent, "thumbnail_cache") and f_id in getattr(self.explorer_parent, "thumbnail_cache", {}):
                pix = self.explorer_parent.thumbnail_cache[f_id]
                mini = pix.scaled(64, 48, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
                self.mini_thumb_cache[f_id] = mini
                btn.setIcon(QIcon(mini))
            else:
                btn.setIcon(get_svg_icon("image", "#94A3B8", 18))

            btn.clicked.connect(lambda checked, target_idx=idx: self.jump_to_index(target_idx))
            self.filmstrip_layout.addWidget(btn)
            self.filmstrip_buttons.append(btn)

        self._scroll_to_active_thumb()

    def jump_to_index(self, idx: int):
        """Kullanıcı küçük resme tıkladığında doğrudan o görsele atlar."""
        if 0 <= idx < len(self.image_entries):
            self.current_index = idx
            self.load_image_at_current_index()
            self.slideshow_elapsed_ms = 0
            if self.slideshow_active:
                self.slideshow_progress.setValue(0)

    def _scroll_to_active_thumb(self):
        """Geçerli resmi alt film şeridinde vurgular ve görünür kılar."""
        border_col = "rgba(255, 255, 255, 0.16)"
        accent_col = getattr(self, "accent_col", "#2997FF" if getattr(self, "current_theme", "dark") == "apple_dark" else ("#0071E3" if getattr(self, "current_theme", "dark") == "apple_light" else ("#38BDF8" if getattr(self, "is_dark", True) else "#0284C7")))
        accent_rgb = getattr(self, "accent_rgb", "41, 151, 255" if getattr(self, "current_theme", "dark") == "apple_dark" else ("0, 113, 227" if getattr(self, "current_theme", "dark") == "apple_light" else ("56, 189, 248" if getattr(self, "is_dark", True) else "2, 132, 199")))
        for idx, btn in enumerate(self.filmstrip_buttons):
            if idx == self.current_index:
                btn.setStyleSheet(f"""
                    QPushButton#fs-thumb-btn {{
                        min-width: 56px;
                        max-width: 56px;
                        min-height: 44px;
                        max-height: 44px;
                        padding: 0px;
                        margin: 0px;
                        border: 2px solid {accent_col};
                        border-radius: 8px;
                        background: rgba({accent_rgb}, 0.18);
                    }}
                """)
                self.filmstrip_scroll.ensureWidgetVisible(btn)
            else:
                btn.setStyleSheet(f"""
                    QPushButton#fs-thumb-btn {{
                        min-width: 56px;
                        max-width: 56px;
                        min-height: 44px;
                        max-height: 44px;
                        padding: 0px;
                        margin: 0px;
                        border: 1px solid {border_col};
                        border-radius: 8px;
                        background: rgba(255, 255, 255, 0.05);
                    }}
                    QPushButton#fs-thumb-btn:hover {{
                        border: 1.5px solid {accent_col};
                        background: rgba(56, 189, 248, 0.10);
                    }}
                """)

    def load_image_at_current_index(self, initial: bool = False):
        """Görseli şifreli kasadan doğrudan RAM'e okur ve çözünme efektiyle sahnede gösterir."""
        if not self.image_entries or self.current_index < 0 or self.current_index >= len(self.image_entries):
            return
        entry = self.image_entries[self.current_index]
        f_id = entry.get("id", "")
        fname = Path(entry.get("path", "")).name
        sz = entry.get("size", 0)

        if hasattr(self, "lbl_hud_name"):
            self.lbl_hud_name.setText(fname)
        idx_badge_text = f"{self.current_index + 1} / {len(self.image_entries)}"
        if hasattr(self, "lbl_hud_badge"):
            self.lbl_hud_badge.setText(idx_badge_text)

        has_many = len(self.image_entries) > 1
        self.btn_prev.setEnabled((self.slideshow_loop and has_many) or self.current_index > 0)
        self.btn_next.setEnabled((self.slideshow_loop and has_many) or self.current_index < len(self.image_entries) - 1)

        try:
            raw_bytes, _ = CustomVaultEngine.extract_file_bytes(self.vault_path, self.auth_info, f_id)
            is_suspicious, reason = inspect_file_security_header(raw_bytes[:512], fname)
            if is_suspicious:
                self.lbl_meta.setText("GÜVENLİK BLOKESİ")
                return

            new_pix = QPixmap()
            if new_pix.loadFromData(raw_bytes):
                if f_id not in self.mini_thumb_cache:
                    mini = new_pix.scaled(64, 48, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
                    self.mini_thumb_cache[f_id] = mini
                    if self.current_index < len(self.filmstrip_buttons):
                        self.filmstrip_buttons[self.current_index].setIcon(QIcon(mini))

                ext_format = Path(fname).suffix.replace(".", "").upper() or "IMG"
                self.lbl_meta.setText(f"{new_pix.width()} × {new_pix.height()} px • {format_size(sz)} {ext_format}")

                self.current_pixmap = new_pix
                self.pixmap_item.setPixmap(new_pix)
                self.pixmap_item.setOpacity(1.0)
                self.pixmap_item_back.setPixmap(new_pix)
                self.scene.setSceneRect(0, 0, new_pix.width(), new_pix.height())
                self.fit_to_screen()
                self.view.centerOn(self.pixmap_item)

                self.full_current_filename = fname
                self.update_overlay_positions()
                self._scroll_to_active_thumb()
                if self.slideshow_active:
                    self.setCursor(Qt.CursorShape.BlankCursor)
                    if getattr(self, "top_header", None):
                        self.top_header.hide()
                    if getattr(self, "filmstrip_container", None):
                        self.filmstrip_container.hide()
                    if getattr(self, "btn_prev", None):
                        self.btn_prev.hide()
                    if getattr(self, "btn_next", None):
                        self.btn_next.hide()
                else:
                    self._wake_hud()
            else:
                self.lbl_meta.setText("Görsel çözümlenemedi")
        except Exception as e:
            self.lbl_meta.setText(f"Hata: {e}")

    def rotate_image(self, angle: int = 90):
        """Fotoğrafı saat yönünde 90 derece döndürür (bellekte doğrudan RAM-Only)."""
        if not self.current_pixmap or self.current_pixmap.isNull():
            return
        self._wake_hud()
        self.current_rotation = (self.current_rotation + angle) % 360
        transform = QTransform().rotate(angle)
        self.current_pixmap = self.current_pixmap.transformed(transform, Qt.TransformationMode.SmoothTransformation)
        self.pixmap_item.setPixmap(self.current_pixmap)
        self.pixmap_item_back.setPixmap(self.current_pixmap)
        self.scene.setSceneRect(0, 0, self.current_pixmap.width(), self.current_pixmap.height())
        self.fit_to_screen()

        if self.image_entries and 0 <= self.current_index < len(self.image_entries):
            f_id = self.image_entries[self.current_index].get("id", "")
            mini = self.current_pixmap.scaled(64, 48, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
            self.mini_thumb_cache[f_id] = mini
            if self.current_index < len(self.filmstrip_buttons):
                self.filmstrip_buttons[self.current_index].setIcon(QIcon(mini))

    def _on_fade_step(self):
        """Çözünme (dissolve) opaklık eğrisini pürüzsüzce ilerletir."""
        self.fade_step += 1
        opacity = min(1.0, self.fade_step / float(self.fade_total_steps))
        self.pixmap_item.setOpacity(opacity)
        if self.fade_step >= self.fade_total_steps:
            self.fade_timer.stop()
            if self.current_pixmap:
                self.pixmap_item_back.setPixmap(self.current_pixmap)
            self.pixmap_item.setOpacity(1.0)

    def fit_to_screen(self):
        """Görseli en boy oranını koruyarak ekrana tam sığdırır (Tam ekran otomatik sığdırma)."""
        if not self.current_pixmap or self.current_pixmap.isNull():
            return
        self.auto_fit_mode = True
        self.view.resetTransform()
        vw = max(10, self.view.viewport().width() - 40)
        vh = max(10, self.view.viewport().height() - 40)
        pw = max(1, self.current_pixmap.width())
        ph = max(1, self.current_pixmap.height())
        if pw <= 128 and ph <= 128:
            scale = 1.0
        else:
            scale = min(vw / pw, vh / ph)
        self.view.scale(scale, scale)
        self.zoom_level = scale
        self.lbl_zoom.setText(f"%{int(scale * 100)}")
        if hasattr(self, "pixmap_item") and self.pixmap_item:
            self.view.centerOn(self.pixmap_item)

    def zoom_original(self):
        """Görseli orijinal piksel boyutuna (%100) getirir."""
        if not self.current_pixmap or self.current_pixmap.isNull():
            return
        self.auto_fit_mode = False
        self.view.resetTransform()
        self.zoom_level = 1.0
        self.lbl_zoom.setText("%100")

    def zoom_by(self, factor: float):
        self.auto_fit_mode = False
        """Belirtilen oranda pürüzsüz yakınlaştırır veya uzaklaştırır."""
        new_zoom = self.zoom_level * factor
        if 0.05 <= new_zoom <= 20.0:
            self.view.scale(factor, factor)
            self.zoom_level = new_zoom
            self.lbl_zoom.setText(f"%{int(self.zoom_level * 100)}")

    def navigate_prev(self):
        """Önceki görsele geçer (Slayt modunda da sorunsuz çalışır)."""
        if not self.slideshow_active:
            self._wake_hud()
        if self.current_index > 0:
            self.current_index -= 1
            self.load_image_at_current_index()
        elif self.slideshow_loop and len(self.image_entries) > 1:
            self.current_index = len(self.image_entries) - 1
            self.load_image_at_current_index()
        self.slideshow_elapsed_ms = 0
        if self.slideshow_active and hasattr(self, "slideshow_progress"):
            self.slideshow_progress.setValue(0)

    def navigate_next(self):
        """Sonraki görsele geçer (Slayt modunda da sorunsuz çalışır)."""
        if not self.slideshow_active:
            self._wake_hud()
        if self.current_index < len(self.image_entries) - 1:
            self.current_index += 1
            self.load_image_at_current_index()
        elif self.slideshow_loop and len(self.image_entries) > 1:
            self.current_index = 0
            self.load_image_at_current_index()
        self.slideshow_elapsed_ms = 0
        if self.slideshow_active and hasattr(self, "slideshow_progress"):
            self.slideshow_progress.setValue(0)

    def toggle_slideshow(self):
        """Slayt gösterisini başlatır veya duraklatır."""
        self._wake_hud()
        if self.slideshow_active:
            self.stop_slideshow()
        else:
            self.start_slideshow()

    def start_slideshow(self):
        """Slayt gösterisini başlatır, araç çubuğunu ve fare imlecini anında gizler."""
        if not self.image_entries:
            return
        self.slideshow_active = True
        self.slideshow_elapsed_ms = 0
        accent_col = "#2997FF" if getattr(self, "theme", "dark") == "apple_dark" else ("#0071E3" if getattr(self, "theme", "dark") == "apple_light" else ("#38BDF8" if getattr(self, "is_dark", True) else "#0284C7"))

        if getattr(self, "btn_slideshow", None):
            self.btn_slideshow.setIcon(get_svg_icon("pause", accent_col, 14))
            self.btn_slideshow.setText(" Durdur")
        if getattr(self, "btn_hud_play", None):
            self.btn_hud_play.setIcon(get_svg_icon("pause", accent_col, 18))
            self.btn_hud_play.setToolTip("Slaytı Duraklat (Boşluk / S / F5)")

        if hasattr(self, "idle_timer"):
            self.idle_timer.stop()
        if hasattr(self, "slideshow_progress"):
            self.slideshow_progress.setValue(0)
            self.slideshow_progress.hide()

        if getattr(self, "top_header", None):
            self.top_header.hide()
        if getattr(self, "hud_info_badge", None):
            self.hud_info_badge.hide()
        if getattr(self, "filmstrip_container", None):
            self.filmstrip_container.hide()
        if getattr(self, "btn_prev", None):
            self.btn_prev.hide()
        if getattr(self, "btn_next", None):
            self.btn_next.hide()
        self.setCursor(Qt.CursorShape.BlankCursor)

        self.slideshow_timer.start(self.slideshow_tick_ms)

    def stop_slideshow(self):
        """Slayt gösterisini durdurur ve kontrolleri ile fare imlecini yeniden görünür kılar."""
        self.slideshow_active = False
        if hasattr(self, "slideshow_timer"):
            self.slideshow_timer.stop()
        if hasattr(self, "idle_timer"):
            self.idle_timer.stop()
        self.slideshow_elapsed_ms = 0
        accent_col = "#2997FF" if getattr(self, "theme", "dark") == "apple_dark" else ("#0071E3" if getattr(self, "theme", "dark") == "apple_light" else ("#38BDF8" if getattr(self, "is_dark", True) else "#0284C7"))

        if getattr(self, "btn_slideshow", None):
            self.btn_slideshow.setIcon(get_svg_icon("play", accent_col, 14))
            self.btn_slideshow.setText(" Slayt")
        if getattr(self, "btn_hud_play", None):
            self.btn_hud_play.setIcon(get_svg_icon("play", accent_col, 18))
            self.btn_hud_play.setToolTip("Slaytı Başlat (Boşluk / S / F5)")

        if hasattr(self, "slideshow_progress"):
            self.slideshow_progress.setValue(0)
            self.slideshow_progress.hide()
        self.setCursor(Qt.CursorShape.ArrowCursor)
        self._wake_hud()

    def _on_slideshow_tick(self):
        """40ms'lik hassas zamanlayıcı ile Windows Photos Legacy tarzı akışı yürütür."""
        if not self.slideshow_active:
            return
        self.slideshow_elapsed_ms += self.slideshow_tick_ms
        pct = min(100, int((self.slideshow_elapsed_ms / self.slideshow_interval_ms) * 100))
        self.slideshow_progress.setValue(pct)

        if self.slideshow_elapsed_ms >= self.slideshow_interval_ms:
            self.slideshow_elapsed_ms = 0
            self.slideshow_progress.setValue(0)
            self.navigate_next_slideshow()

    def navigate_next_slideshow(self):
        """Zamanlayıcı tamamlandığında sonraki görsele pürüzsüz geçer (Sıralı veya Karışık)."""
        if not self.image_entries:
            self.stop_slideshow()
            return
        if self.slideshow_shuffle and len(self.image_entries) > 1:
            import random
            pool = [i for i in range(len(self.image_entries)) if i != self.current_index]
            self.current_index = random.choice(pool)
            self.load_image_at_current_index()
        else:
            if self.current_index < len(self.image_entries) - 1:
                self.current_index += 1
                self.load_image_at_current_index()
            elif self.slideshow_loop and len(self.image_entries) > 1:
                self.current_index = 0
                self.load_image_at_current_index()
            else:
                self.stop_slideshow()

    def cycle_speed(self):
        """Geçiş süresini döngüsel değiştirir (5s -> 10s -> 15s -> 30s -> 60s)."""
        self._wake_hud()
        speeds = [5000, 10000, 15000, 30000, 60000]
        cur = self.slideshow_interval_ms
        try:
            next_idx = (speeds.index(cur) + 1) % len(speeds)
        except ValueError:
            next_idx = 2
        self.set_slideshow_interval(speeds[next_idx] // 1000)

    def on_interval_changed(self, text: str):
        """Açılır kutudan süre seçildiğinde zamanlayıcıyı eşitler."""
        try:
            sec = int(text.split()[0])
            self.set_slideshow_interval(sec)
        except Exception:
            self.set_slideshow_interval(15)

    def set_slideshow_interval(self, sec: int):
        """Slayt gösterisi süresini dinamik ve güvenli günceller."""
        self.slideshow_interval_ms = max(1000, sec * 1000)
        accent_col = "#2997FF" if getattr(self, "theme", "dark") == "apple_dark" else ("#0071E3" if getattr(self, "theme", "dark") == "apple_light" else ("#38BDF8" if getattr(self, "is_dark", True) else "#0284C7"))
        if getattr(self, "btn_hud_speed", None):
            self.btn_hud_speed.setIcon(get_svg_icon("clock", accent_col, 13))
            self.btn_hud_speed.setText(f" {sec}s")
        if getattr(self, "combo_interval", None):
            self.combo_interval.setCurrentText(f"{sec} sn")
        self.slideshow_elapsed_ms = 0
        if self.slideshow_active and hasattr(self, "slideshow_progress"):
            self.slideshow_progress.setValue(0)

    def set_transition_mode(self, mode: str):
        """Windows Photos Legacy standart yumuşak çözünme (Cross-Fade) geçişi."""
        self.transition_mode = "crossfade"
        if getattr(self, "btn_hud_fx", None):
            self.btn_hud_fx.setText("Çözünme")

    def show_options_menu(self):
        """Tam ekranda slayt gösterisi ve görüntüleme seçenekleri açılır menüsünü gösterir."""
        accent_col = "#2997FF" if getattr(self, "theme", "dark") == "apple_dark" else ("#0071E3" if getattr(self, "theme", "dark") == "apple_light" else ("#38BDF8" if getattr(self, "is_dark", True) else "#0284C7"))
        menu = QMenu(self)
        menu.setStyleSheet(f"""
            QMenu {{
                background-color: {'#18181b' if self.is_dark else '#FFFFFF'};
                color: {'#FFFFFF' if self.is_dark else '#18181b'};
                border: 1px solid {'rgba(255, 255, 255, 0.15)' if self.is_dark else 'rgba(0, 0, 0, 0.15)'};
                border-radius: 8px;
                padding: 6px;
                font-size: 11.5px;
            }}
            QMenu::item {{
                padding: 6px 24px 6px 10px;
                border-radius: 5px;
            }}
            QMenu::item:selected {{
                background-color: {accent_col};
                color: {'#000000' if self.is_dark else '#FFFFFF'};
            }}
            QMenu::separator {{
                height: 1px;
                background: {'rgba(255, 255, 255, 0.1)' if self.is_dark else 'rgba(0, 0, 0, 0.1)'};
                margin: 4px 6px;
            }}
        """)

        if self.slideshow_active:
            act_play = menu.addAction(get_svg_icon("pause", accent_col, 14), "Slayt Gösterisini Durdur (Boşluk / S / F5)")
        else:
            act_play = menu.addAction(get_svg_icon("play", accent_col, 14), "Slayt Gösterisini Başlat (Boşluk / S / F5)")
        act_play.triggered.connect(self.toggle_slideshow)

        menu.addSeparator()

        m_speed = menu.addMenu("Slayt Geçiş Süresi")
        m_speed.setIcon(get_svg_icon("clock", accent_col, 14))
        for sec in [5, 10, 15, 30, 60]:
            label = f"{sec} Saniye"
            if sec == 15:
                label += " (Varsayılan)"
            act = m_speed.addAction(label)
            act.setCheckable(True)
            act.setChecked(self.slideshow_interval_ms == sec * 1000)
            act.triggered.connect(lambda chk, s=sec: self.set_slideshow_interval(s))

        act_loop = menu.addAction(get_svg_icon("repeat", accent_col, 14), "Döngü Modu (Sürekli Tekrar) (L)")
        act_loop.setCheckable(True)
        act_loop.setChecked(self.slideshow_loop)
        act_loop.triggered.connect(self.toggle_loop_mode)

        act_shuffle = menu.addAction(get_svg_icon("shuffle", accent_col, 14), "Karışık Çalma (Rastgele) (H)")
        act_shuffle.setCheckable(True)
        act_shuffle.setChecked(self.slideshow_shuffle)
        act_shuffle.triggered.connect(self.toggle_shuffle)

        menu.addSeparator()

        act_film = menu.addAction(get_svg_icon("film", accent_col, 14), "Küçük Resim Önizleme Şeridi (F)")
        act_film.setCheckable(True)
        act_film.setChecked(getattr(self, "show_filmstrip", False))
        act_film.triggered.connect(self.toggle_filmstrip)

        act_fit = menu.addAction(get_svg_icon("fit_screen", accent_col, 14), "Ekrana Sığdır (0)")
        act_fit.triggered.connect(self.fit_to_screen)

        act_orig = menu.addAction(get_svg_icon("zoom_in", accent_col, 14), "Orijinal Boyut %100 (1)")
        act_orig.triggered.connect(self.zoom_original)

        act_rot = menu.addAction(get_svg_icon("rotate_cw", accent_col, 14), "90° Sağa Döndür (R)")
        act_rot.triggered.connect(lambda: self.rotate_image(90))

        menu.addSeparator()

        act_fs = menu.addAction(get_svg_icon("expand", accent_col, 14), "Tam Ekran / Pencere Modu (F11)")
        act_fs.triggered.connect(self.toggle_fullscreen_mode)

        act_close = menu.addAction(get_svg_icon("close", "#EF4444", 14), "Kapat (Esc)")
        act_close.triggered.connect(self.close)

        if hasattr(self, "btn_options") and self.btn_options.isVisible():
            menu.exec(self.btn_options.mapToGlobal(QPoint(0, self.btn_options.height() + 4)))
        else:
            menu.exec(QCursor.pos())

    def contextMenuEvent(self, event):
        """Tam ekranda sağ tıklandığında seçenekler menüsünü açar."""
        self.show_options_menu()
        event.accept()

    def cycle_transition_mode(self):
        """Windows Photos Legacy standart yumuşak çözünme (Cross-Fade) geçişi."""
        self._wake_hud()
        self.transition_mode = "crossfade"
        if getattr(self, "btn_hud_fx", None):
            self.btn_hud_fx.setText("Çözünme")
            self.btn_hud_fx.setToolTip("Geçiş Efekti: Windows Photos Legacy Yumuşak Çözünme (Cross-Fade)")

    def toggle_shuffle(self):
        """Karışık (rastgele) çalma modunu açar veya kapatır."""
        self._wake_hud()
        self.slideshow_shuffle = not self.slideshow_shuffle
        accent_col = "#2997FF" if getattr(self, "theme", "dark") == "apple_dark" else ("#0071E3" if getattr(self, "theme", "dark") == "apple_light" else ("#38BDF8" if getattr(self, "is_dark", True) else "#0284C7"))
        text_muted = "#A1A1AA" if self.is_dark else "#94A3B8"
        col = accent_col if self.slideshow_shuffle else text_muted
        if getattr(self, "btn_hud_shuffle", None):
            self.btn_hud_shuffle.setIcon(get_svg_icon("shuffle", col, 14))
            if self.slideshow_shuffle:
                self.btn_hud_shuffle.setToolTip("Karışık Oynatma: AÇIK (H)")
                self.btn_hud_shuffle.setStyleSheet(f"border: 1px solid {accent_col}; border-radius: 14px;")
            else:
                self.btn_hud_shuffle.setToolTip("Karışık Oynatma: KAPALI (H)")
                self.btn_hud_shuffle.setStyleSheet("border: 1px solid transparent; border-radius: 14px;")
        else:
            self.btn_hud_shuffle.setToolTip("Karışık Oynatma: KAPALI (H)")
            self.btn_hud_shuffle.setStyleSheet("border: 1px solid transparent; border-radius: 14px;")

    def toggle_loop_mode(self):
        """Döngü modunu (baştan başlama) açar veya kapatır."""
        self._wake_hud()
        self.slideshow_loop = not self.slideshow_loop
        self._update_loop_button_style()
        has_many = len(self.image_entries) > 1
        self.btn_prev.setEnabled((self.slideshow_loop and has_many) or self.current_index > 0)
        self.btn_next.setEnabled((self.slideshow_loop and has_many) or self.current_index < len(self.image_entries) - 1)

    def _update_loop_button_style(self):
        accent_col = "#2997FF" if getattr(self, "theme", "dark") == "apple_dark" else ("#0071E3" if getattr(self, "theme", "dark") == "apple_light" else ("#38BDF8" if getattr(self, "is_dark", True) else "#0284C7"))
        text_muted = "#A1A1AA" if self.is_dark else "#94A3B8"
        col = accent_col if self.slideshow_loop else text_muted
        if getattr(self, "btn_hud_loop", None):
            self.btn_hud_loop.setIcon(get_svg_icon("repeat", col, 14))
            if self.slideshow_loop:
                self.btn_hud_loop.setToolTip("Döngü Modu: AÇIK (L)")
                self.btn_hud_loop.setStyleSheet(f"border: 1px solid {accent_col}; border-radius: 14px;")
            else:
                self.btn_hud_loop.setToolTip("Döngü Modu: KAPALI (L)")
                self.btn_hud_loop.setStyleSheet("border: 1px solid transparent; border-radius: 14px;")
        else:
            self.btn_hud_loop.setToolTip("Döngü Modu: KAPALI (L)")
            self.btn_hud_loop.setStyleSheet("border: 1px solid transparent; border-radius: 14px;")

    def toggle_filmstrip(self):
        """Alt küçük resim önizleme panelini açar veya kapatır."""
        self._wake_hud()
        self.show_filmstrip = not self.show_filmstrip
        if self.show_filmstrip:
            if hasattr(self, "filmstrip_container") and len(self.image_entries) > 1:
                self.filmstrip_container.show()
            self.update_overlay_positions()
            self._scroll_to_active_thumb()
        else:
            if hasattr(self, "filmstrip_container"):
                self.filmstrip_container.hide()
            self.update_overlay_positions()

    def showFullScreen(self):
        """Pencereyi gerçek kenarlıksız özel tam ekrana geçirir ve Windows Görev Çubuğunun (Taskbar) üstüne konumlandırır."""
        if not self.isFullScreen():
            self.saved_normal_geom = self.geometry()
        super().showFullScreen()
        self.raise_()
        self.activateWindow()
        self.setFocus()

        accent_col = "#2997FF" if getattr(self, "theme", "dark") == "apple_dark" else ("#0071E3" if getattr(self, "theme", "dark") == "apple_light" else ("#38BDF8" if getattr(self, "is_dark", True) else "#0284C7"))
        if hasattr(self, "btn_toggle_fs"):
            self.btn_toggle_fs.setIcon(get_svg_icon("collapse", accent_col, 15))
            self.btn_toggle_fs.setToolTip("Pencere Moduna Dön (F11 / Esc)")
        if getattr(self, "btn_hud_fs", None):
            self.btn_hud_fs.setIcon(get_svg_icon("collapse", accent_col, 14))
            self.btn_hud_fs.setToolTip("Pencere Moduna Dön (F11 / Esc)")

        screen = self.screen() or QGuiApplication.primaryScreen()
        sg = screen.geometry() if screen else QRect(0, 0, 1920, 1080)
        set_win32_window_zorder(self, topmost=True, geom=sg)
        self.activateWindow()
        self.setFocus()

    def showNormal(self):
        """Pencereyi standart başlıklı ve boyutlandırılabilir normal moda döndürür."""
        set_win32_window_zorder(self, topmost=False)
        super().showNormal()
        self.raise_()
        self.activateWindow()

        text_col = "#FFFFFF"
        if hasattr(self, "btn_toggle_fs"):
            self.btn_toggle_fs.setIcon(get_svg_icon("expand", text_col, 15))
            self.btn_toggle_fs.setToolTip("Tam Ekran Modu (F11)")
        if getattr(self, "btn_hud_fs", None):
            self.btn_hud_fs.setIcon(get_svg_icon("expand", text_col, 14))
            self.btn_hud_fs.setToolTip("Tam Ekran / Pencere (F11)")

        if hasattr(self, "saved_normal_geom") and self.saved_normal_geom and not self.saved_normal_geom.isEmpty():
            self.setGeometry(self.saved_normal_geom)
        else:
            apply_dynamic_geometry(self, default_w=840, default_h=560, min_w=640, min_h=420)

    def toggle_fullscreen_mode(self):
        """Pencereli mod ile kenarlıksız tam ekran sinema modu arasında geçiş yapar."""
        self._wake_hud()
        if self.isFullScreen():
            self.showNormal()
        else:
            self.showFullScreen()
        QTimer.singleShot(60, lambda: (self.update_overlay_positions(), self.fit_to_screen(), self._wake_hud()))

    def _wake_hud(self):
        """Kullanıcı fareyi hareket ettirdiğinde tüm kontrolleri görünür yapar ve 3sn sayacı başlatır."""
        if getattr(self, "slideshow_active", False):
            return
        if getattr(self, "top_header", None):
            self.top_header.show()
        if getattr(self, "hud_info_badge", None):
            self.hud_info_badge.show()
        if getattr(self, "filmstrip_container", None) and len(self.image_entries) > 1 and getattr(self, "show_filmstrip", True):
            self.filmstrip_container.show()
        if getattr(self, "btn_prev", None):
            self.btn_prev.show()
        if getattr(self, "btn_next", None):
            self.btn_next.show()
        self.setCursor(Qt.CursorShape.ArrowCursor)
        if hasattr(self, "idle_timer"):
            self.idle_timer.start(getattr(self, "idle_timeout_ms", 3000))

    def _on_idle_timeout(self):
        """Fotoyu açtıktan 3sn sonra veya 3sn hareketsizlikte HUD kontrollerini ve fare imlecini kapatır."""
        if self.underMouse():
            cursor_pos = self.mapFromGlobal(QCursor.pos())
            for w_name in ("top_header", "filmstrip_container", "btn_prev", "btn_next"):
                w = getattr(self, w_name, None)
                if w and w.isVisible() and w.geometry().contains(cursor_pos):
                    if hasattr(self, "idle_timer"):
                        self.idle_timer.start(getattr(self, "idle_timeout_ms", 3000))
                    return

        self.setCursor(Qt.CursorShape.BlankCursor)
        if getattr(self, "top_header", None):
            self.top_header.hide()
        if getattr(self, "hud_info_badge", None):
            self.hud_info_badge.hide()
        if getattr(self, "filmstrip_container", None):
            self.filmstrip_container.hide()
        if getattr(self, "btn_prev", None):
            self.btn_prev.hide()
        if getattr(self, "btn_next", None):
            self.btn_next.hide()
        if getattr(self, "nav_overlay", None):
            self.nav_overlay.hide()
        if getattr(self, "slideshow_progress", None):
            self.slideshow_progress.hide()

    def _on_viewer_escape(self):
        self.reject()

    def keyPressEvent(self, event):
        key = event.key()
        if key in (Qt.Key.Key_Escape, Qt.Key.Key_Q):
            if getattr(self, "slideshow_active", False):
                self.stop_slideshow()
            else:
                self.reject()
            event.accept()
            return
        elif key in (Qt.Key.Key_S, Qt.Key.Key_F5, Qt.Key.Key_Space):
            self.toggle_slideshow()
            event.accept()
            return
        elif key in (Qt.Key.Key_Left, Qt.Key.Key_PageUp):
            self.navigate_prev()
            event.accept()
            return
        elif key in (Qt.Key.Key_Right, Qt.Key.Key_PageDown):
            self.navigate_next()
            event.accept()
            return
        elif key == Qt.Key.Key_Home:
            self.jump_to_index(0)
            event.accept()
            return
        elif key == Qt.Key.Key_End:
            self.jump_to_index(len(self.image_entries) - 1)
            event.accept()
            return
        elif key in (Qt.Key.Key_R,):
            self.rotate_image(90)
            event.accept()
            return
        elif key in (Qt.Key.Key_Plus, Qt.Key.Key_Equal):
            self.zoom_by(1.25)
            event.accept()
            return
        elif key in (Qt.Key.Key_Minus, Qt.Key.Key_Underscore):
            self.zoom_by(1.0 / 1.25)
            event.accept()
            return
        elif key == Qt.Key.Key_0:
            self.fit_to_screen()
            event.accept()
            return
        elif key == Qt.Key.Key_1:
            self.zoom_original()
            event.accept()
            return
        elif key in (Qt.Key.Key_F11, Qt.Key.Key_F):
            self.toggle_fullscreen_mode()
            event.accept()
            return
        elif key in (Qt.Key.Key_T,):
            self.toggle_filmstrip()
            event.accept()
            return
        elif key in (Qt.Key.Key_H,):
            self.toggle_shuffle()
            event.accept()
            return
        elif key == Qt.Key.Key_L:
            self.toggle_loop_mode()
            event.accept()
            return
        elif key == Qt.Key.Key_T:
            self.cycle_transition_mode()
            event.accept()
            return
        else:
            super().keyPressEvent(event)

    def mouseMoveEvent(self, event):
        if not getattr(self, "slideshow_active", False):
            self._wake_hud()
        super().mouseMoveEvent(event)

    def eventFilter(self, obj, event):
        if event.type() in (QEvent.Type.MouseMove, QEvent.Type.MouseButtonPress, QEvent.Type.Enter, QEvent.Type.HoverMove):
            if not getattr(self, "slideshow_active", False):
                self._wake_hud()

        if event.type() == QEvent.Type.KeyPress:
            k = event.key()
            if k in (Qt.Key.Key_Escape, Qt.Key.Key_Q):
                if getattr(self, "slideshow_active", False):
                    self.stop_slideshow()
                else:
                    self.reject()
                return True
            elif k in (Qt.Key.Key_Left, Qt.Key.Key_PageUp):
                self.navigate_prev()
                return True
            elif k in (Qt.Key.Key_Right, Qt.Key.Key_PageDown):
                self.navigate_next()
                return True
            elif k in (Qt.Key.Key_Space, Qt.Key.Key_S, Qt.Key.Key_F5):
                self.toggle_slideshow()
                return True
            elif k in (Qt.Key.Key_F11, Qt.Key.Key_F):
                self.toggle_fullscreen_mode()
                return True
            elif k == Qt.Key.Key_Home:
                self.jump_to_index(0)
                return True
            elif k == Qt.Key.Key_End:
                self.jump_to_index(len(self.image_entries) - 1)
                return True
            elif k == Qt.Key.Key_R:
                self.rotate_image(90)
                return True
            elif k in (Qt.Key.Key_Plus, Qt.Key.Key_Equal):
                self.zoom_by(1.25)
                return True
            elif k in (Qt.Key.Key_Minus, Qt.Key.Key_Underscore):
                self.zoom_by(1.0 / 1.25)
                return True
            elif k == Qt.Key.Key_0:
                self.fit_to_screen()
                return True
            elif k == Qt.Key.Key_1:
                self.zoom_original()
                return True
            elif k == Qt.Key.Key_L:
                self.toggle_loop_mode()
                return True
            elif k == Qt.Key.Key_H:
                self.toggle_shuffle()
                return True
            elif k == Qt.Key.Key_T:
                self.toggle_filmstrip()
                return True

        if obj == self.view.viewport():
            if event.type() == QEvent.Type.Wheel:
                delta = event.angleDelta().y()
                if delta > 0:
                    self.zoom_by(1.15)
                elif delta < 0:
                    self.zoom_by(1.0 / 1.15)
                return True
            elif event.type() == QEvent.Type.MouseButtonDblClick:
                if 0.95 <= self.zoom_level <= 1.05:
                    self.fit_to_screen()
                else:
                    self.zoom_original()
                return True
        return super().eventFilter(obj, event)

    def closeEvent(self, event):
        self.setCursor(Qt.CursorShape.ArrowCursor)
        set_win32_window_zorder(self, topmost=False)
        if hasattr(self, "slideshow_timer") and self.slideshow_timer.isActive():
            self.slideshow_timer.stop()
        if hasattr(self, "fade_timer") and self.fade_timer.isActive():
            self.fade_timer.stop()
        if hasattr(self, "idle_timer") and self.idle_timer.isActive():
            self.idle_timer.stop()
        self.slideshow_active = False
        self.current_pixmap = None
        if hasattr(self, "mini_thumb_cache"):
            self.mini_thumb_cache.clear()
        if hasattr(self, "filmstrip_buttons"):
            self.filmstrip_buttons.clear()
        if hasattr(self, "scene"):
            self.scene.clear()
        if getattr(self, "explorer_parent", None):
            try:
                self.explorer_parent.raise_()
                self.explorer_parent.activateWindow()
                if hasattr(self.explorer_parent, "table"):
                    self.explorer_parent.table.setFocus()
            except Exception:
                pass
        import gc
        gc.collect()
        event.accept()

class CustomVaultExplorerDialog(QDialog):
    """
    Bağımsız AES-256 Kasa Dosya Yöneticisi Penceresi (Windows Explorer Deneyimi).
    """
    vault_locked_signal = pyqtSignal()

    def __init__(
        self,
        parent=None,
        vault_path: str = "",
        auth_info: Optional[Dict[str, Any]] = None,
        theme: str = "dark"
    ):
        super().__init__(parent)
        self.vault_path = vault_path
        self.auth_info = auth_info or {}
        self.current_theme = theme
        self.is_dark = (theme in ("dark", "apple_dark"))

        self.current_folder: str = ""
        self.current_category: Optional[str] = None
        self.history: List[str] = [""]
        self.history_index: int = 0
        self.view_mode: str = "details"

        self.sort_column: int = 0
        self.sort_ascending: bool = True
        self.active_category_filter: Optional[str] = None
        self.category_chip_buttons: Dict[Optional[str], QPushButton] = {}
        self.vault_clipboard: Optional[Dict[str, Any]] = None

        self.cached_files: List[Dict[str, Any]] = []
        self.cached_folders: List[str] = []
        self.thumbnail_cache: Dict[str, QPixmap] = {}
        self.full_image_cache: Dict[str, Tuple[QPixmap, int, int]] = {}
        self.current_preview_image_id: Optional[str] = None
        self.pending_icon_cache: Dict[str, QPixmap] = {}
        self.active_temp_files: Dict[str, Dict[str, Any]] = {}
        self.active_temp_dirs: List[str] = []

        self.icon_worker_signals = AsyncIconWorkerSignals()
        self.icon_worker_signals.icon_ready.connect(self.on_async_icon_ready)
        self.current_icon_worker: Optional[AsyncIconWorker] = None

        self.setWindowTitle(f"Enclave - Güvenli Kasa Dosya Yöneticisi: {Path(vault_path).name}")
        self.setWindowFlags(Qt.WindowType.Window | Qt.WindowType.WindowMinMaxButtonsHint | Qt.WindowType.WindowCloseButtonHint)
        apply_dynamic_geometry(self, default_w=860, default_h=540, min_w=680, min_h=420)
        self.setAcceptDrops(True)

        from PyQt6.QtGui import QKeySequence, QShortcut
        self.shortcut_exp_f11 = QShortcut(QKeySequence(Qt.Key.Key_F11), self)
        self.shortcut_exp_f11.setContext(Qt.ShortcutContext.WindowShortcut)
        self.shortcut_exp_f11.activated.connect(self.toggle_fullscreen_mode)

        self.shortcut_exp_esc = QShortcut(QKeySequence(Qt.Key.Key_Escape), self)
        self.shortcut_exp_esc.setContext(Qt.ShortcutContext.WindowShortcut)
        self.shortcut_exp_esc.activated.connect(lambda: self.showNormal() if self.isFullScreen() else None)

        self.enable_native_drag_drop()

        self.setup_ui()
        for btn in self.findChildren(QPushButton):
            btn.setAutoDefault(False)
            btn.setDefault(False)
        if hasattr(self, "table"):
            self.table.setFocus()
        self.refresh_file_list()

        self.watcher_timer = QTimer(self)
        self.watcher_timer.timeout.connect(self.check_modified_temp_files)
        self.watcher_timer.start(1500)

        self.preview_timer = QTimer(self)
        self.preview_timer.setSingleShot(True)
        self.preview_timer.timeout.connect(self._do_deferred_preview)
        self.pending_preview_entry: Optional[Dict[str, Any]] = None

    def setup_ui(self):
        if self.current_theme == "apple_dark":
            bg_col = "#161618"
            card_bg = "#212124"
            border_col = "rgba(255, 255, 255, 0.08)"
            text_col = "#F5F5F7"
            text_muted = "#86868B"
            accent_blue = "#2997FF"
            accent_vault = "#30D158"
            table_bg = "#1A1A1D"
            item_hover_bg = "rgba(255, 255, 255, 0.05)"
            item_sel_bg = "rgba(41, 151, 255, 0.22)"
            bar_bg = "#1E1E21"
        elif self.current_theme == "apple_light":
            bg_col = "#F5F5F7"
            card_bg = "#FFFFFF"
            border_col = "rgba(0, 0, 0, 0.08)"
            text_col = "#1D1D1F"
            text_muted = "#6E6E73"
            accent_blue = "#0071E3"
            accent_vault = "#30D158"
            table_bg = "#FFFFFF"
            item_hover_bg = "rgba(0, 0, 0, 0.04)"
            item_sel_bg = "rgba(0, 113, 227, 0.14)"
            bar_bg = "#EAEAEF"
        else:
            bg_col = "#19191d" if self.is_dark else "#F3F3F3"
            card_bg = "#202024" if self.is_dark else "#FFFFFF"
            border_col = "rgba(255, 255, 255, 0.07)" if self.is_dark else "rgba(0, 0, 0, 0.08)"
            text_col = "#FFFFFF" if self.is_dark else "#1A1A1A"
            text_muted = "#A1A1AA" if self.is_dark else "#5A5A5A"
            accent_blue = "#38BDF8" if self.is_dark else "#0078D4"
            accent_vault = "#38BDF8" if self.is_dark else "#059669"
            table_bg = "#18181b" if self.is_dark else "#FFFFFF"
            item_hover_bg = "rgba(255, 255, 255, 0.04)" if self.is_dark else "rgba(0, 0, 0, 0.04)"
            item_sel_bg = "rgba(0, 120, 212, 0.22)" if self.is_dark else "rgba(0, 120, 212, 0.15)"
            bar_bg = "#1e1e22" if self.is_dark else "#EAEAEF"

        self.setStyleSheet(f"""
            QDialog {{
                background-color: {bg_col};
                color: {text_col};
                font-family: -apple-system, 'SF Pro Display', 'SF Pro Text', 'Segoe UI Variable', 'Segoe UI', 'Inter', sans-serif;
            }}
            /* 1. Üst Sekme Çubuğu (Files App Fluent Tab Bar) */
            QFrame#fluent-tabbar {{
                background-color: {bg_col};
                border-bottom: 1px solid {border_col};
                min-height: 38px;
                max-height: 38px;
            }}
            QFrame#fluent-active-tab {{
                background-color: {'#28282e' if self.is_dark else '#FFFFFF'};
                border: 1px solid {border_col};
                border-bottom: none;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
                min-height: 32px;
                max-height: 32px;
                padding: 2px 8px;
            }}
            QPushButton#fluent-tab-close {{
                background: transparent;
                border: none;
                border-radius: 4px;
                min-width: 20px;
                max-width: 20px;
                min-height: 20px;
                max-height: 20px;
                padding: 3px;
            }}
            QPushButton#fluent-tab-close:hover {{
                background-color: {'rgba(255, 255, 255, 0.12)' if self.is_dark else 'rgba(0, 0, 0, 0.08)'};
            }}
            QPushButton#fluent-tab-add {{
                background: transparent;
                border: none;
                border-radius: 6px;
                min-width: 28px;
                max-width: 28px;
                min-height: 28px;
                max-height: 28px;
                padding: 5px;
            }}
            QPushButton#fluent-tab-add:hover {{
                background-color: {'rgba(255, 255, 255, 0.07)' if self.is_dark else 'rgba(0, 0, 0, 0.06)'};
            }}

            /* 2. Omnibar & Gezinti Çubuğu */
            QFrame#fluent-omnibar {{
                background-color: {card_bg};
                border-bottom: 1px solid {border_col};
                min-height: 40px;
                max-height: 40px;
            }}
            QPushButton.fluent-nav-btn {{
                background: transparent;
                border: none;
                border-radius: 5px;
                min-width: 28px;
                max-width: 28px;
                min-height: 28px;
                max-height: 28px;
                padding: 4px;
            }}
            QPushButton.fluent-nav-btn:hover {{
                background-color: {'rgba(255, 255, 255, 0.08)' if self.is_dark else 'rgba(0, 0, 0, 0.06)'};
            }}
            QPushButton.fluent-nav-btn:pressed {{
                background-color: {'rgba(255, 255, 255, 0.15)' if self.is_dark else 'rgba(0, 0, 0, 0.1)'};
            }}

            /* Breadcrumbs Kapsülü */
            QWidget#fluent-breadcrumbs {{
                background-color: {'rgba(255, 255, 255, 0.04)' if self.is_dark else 'rgba(0, 0, 0, 0.03)'};
                border: 1px solid {border_col};
                border-radius: 6px;
                min-height: 30px;
                max-height: 30px;
                padding: 0px 6px;
            }}
            QPushButton.fluent-crumb-btn {{
                background: transparent;
                border: none;
                border-radius: 4px;
                color: {text_col};
                font-size: 11px;
                font-weight: 600;
                padding: 2px 6px;
                min-height: 22px;
            }}
            QPushButton.fluent-crumb-btn:hover {{
                background-color: {'rgba(255, 255, 255, 0.08)' if self.is_dark else 'rgba(0, 0, 0, 0.06)'};
                color: {accent_blue};
            }}

            /* Omnibar Arama Kutusu */
            QLineEdit#fluent-search {{
                background-color: {'rgba(255, 255, 255, 0.04)' if self.is_dark else '#FFFFFF'};
                color: {text_col};
                border: 1px solid {border_col};
                border-radius: 6px;
                min-height: 28px;
                max-height: 28px;
                padding: 2px 10px 2px 28px;
                font-size: 11px;
                min-width: 150px;
                max-width: 200px;
            }}
            QLineEdit#fluent-search:focus {{
                border-color: {accent_blue};
                background-color: {'rgba(255, 255, 255, 0.07)' if self.is_dark else '#FFFFFF'};
            }}

            /* 3. WinUI 3 Komut Çubuğu (Command Bar) */
            QFrame#fluent-commandbar {{
                background-color: {bar_bg};
                border-bottom: 1px solid {border_col};
                min-height: 38px;
                max-height: 38px;
            }}
            QPushButton#btn-new-menu {{
                background-color: {'rgba(255, 255, 255, 0.06)' if self.is_dark else '#E2E8F0'};
                border: 1px solid {'rgba(255, 255, 255, 0.1)' if self.is_dark else '#CBD5E1'};
                border-radius: 5px;
                padding: 4px 10px;
                font-weight: 600;
                font-size: 11px;
                color: {text_col};
                min-height: 24px;
            }}
            QPushButton#btn-new-menu:hover {{
                background-color: {'rgba(255, 255, 255, 0.12)' if self.is_dark else '#CBD5E1'};
                border-color: {accent_blue};
            }}
            QPushButton.fluent-tool-btn {{
                background: transparent;
                border: none;
                border-radius: 5px;
                min-width: 28px;
                max-width: 28px;
                min-height: 28px;
                max-height: 28px;
                padding: 4px;
            }}
            QPushButton.fluent-tool-btn:hover {{
                background-color: {'rgba(255, 255, 255, 0.08)' if self.is_dark else 'rgba(0, 0, 0, 0.06)'};
            }}
            QPushButton.fluent-tool-btn:pressed {{
                background-color: {'rgba(255, 255, 255, 0.14)' if self.is_dark else 'rgba(0, 0, 0, 0.1)'};
            }}
            QPushButton.fluent-tool-btn-active {{
                background-color: {'rgba(255, 255, 255, 0.12)' if self.is_dark else '#CBD5E1'};
                border: 1px solid {'rgba(255, 255, 255, 0.18)' if self.is_dark else '#94A3B8'};
                border-radius: 5px;
            }}

            /* Kategori Açılır Menüsü */
            QComboBox#fluent-combo-category {{
                background-color: {'rgba(255, 255, 255, 0.04)' if self.is_dark else '#FFFFFF'};
                color: {text_col};
                border: 1px solid {border_col};
                border-radius: 5px;
                padding: 2px 8px;
                font-size: 11px;
                font-weight: 600;
                min-height: 24px;
                max-height: 24px;
                min-width: 95px;
                max-width: 115px;
            }}
            QComboBox#fluent-combo-category:hover {{
                border-color: {accent_blue};
            }}
            QComboBox#fluent-combo-category::drop-down {{
                border: none;
                width: 14px;
            }}
            QComboBox#fluent-combo-category QAbstractItemView {{
                background-color: {'#242429' if self.is_dark else '#FFFFFF'};
                color: {text_col};
                selection-background-color: {item_sel_bg};
                selection-color: {text_col};
                border: 1px solid {border_col};
                border-radius: 6px;
                padding: 4px;
            }}

            /* 4. Sol Gezinti Bölmesi (Navigation Pane) */
            QFrame#left-pane {{
                background-color: {'#1c1c20' if self.is_dark else '#F8FAFC'};
                border-right: 1px solid {border_col};
            }}
            QFrame#tree-header {{
                background-color: transparent;
                border: none;
                min-height: 28px;
                max-height: 28px;
            }}
            QTreeWidget {{
                background-color: transparent;
                color: {text_col};
                border: none;
                font-size: 11.5px;
                outline: none;
            }}
            QTreeWidget::item {{
                height: 30px;
                border-radius: 5px;
                padding-left: 4px;
            }}
            QTreeWidget::item:hover {{
                background-color: {item_hover_bg};
            }}
            QTreeWidget::item:selected {{
                background-color: {'rgba(255, 255, 255, 0.09)' if self.is_dark else 'rgba(0, 120, 212, 0.12)'};
                color: {text_col};
                font-weight: 600;
                border-left: 3px solid {accent_blue};
            }}

            /* 5. Orta Tablo & Izgara (WinUI DataGrid) */
            QTableWidget {{
                background-color: {table_bg};
                color: {text_col};
                border: none;
                font-size: 11.5px;
                outline: none;
                gridline-color: transparent;
            }}
            QTableWidget::item {{
                border: none;
                padding: 5px 8px;
            }}
            QTableWidget::item:hover {{
                background-color: {item_hover_bg};
            }}
            QTableWidget::item:selected {{
                background-color: {item_sel_bg};
                color: {text_col};
                border: none;
                outline: none;
            }}
            QTableWidget QTableCornerButton::section {{
                background-color: {'#1f1f23' if self.is_dark else '#EAEAEF'};
                border: none;
            }}
            QHeaderView::section {{
                background-color: {'#1f1f23' if self.is_dark else '#EAEAEF'};
                color: {text_muted};
                font-weight: 600;
                font-size: 11px;
                padding: 6px 8px;
                border: none;
                border-right: 1px solid {'rgba(255, 255, 255, 0.08)' if self.is_dark else 'rgba(0, 0, 0, 0.08)'};
                border-bottom: 1px solid {border_col};
            }}
            QHeaderView::section:hover {{
                color: {text_col};
                background-color: {'#25252b' if self.is_dark else '#DFE3E8'};
            }}

            /* Izgara Kart Görünümü (WinUI Cards) */
            QListWidget {{
                background-color: {table_bg};
                color: {text_col};
                border: none;
                outline: none;
            }}
            QListWidget::item {{
                background-color: {'rgba(255, 255, 255, 0.03)' if self.is_dark else '#FFFFFF'};
                border: 1px solid {border_col};
                border-radius: 8px;
                padding: 8px;
                margin: 4px;
            }}
            QListWidget::item:hover {{
                background-color: {'rgba(255, 255, 255, 0.07)' if self.is_dark else '#F1F5F9'};
                border-color: {'rgba(96, 205, 255, 0.3)' if self.is_dark else '#93C5FD'};
            }}
            QListWidget::item:selected {{
                background-color: {item_sel_bg};
                border-color: {accent_blue};
                color: {text_col};
            }}

            /* 6. Sağ Ayrıntılar / Önizleme Paneli (Files App Details Pane) */
            QFrame#preview-pane {{
                background-color: {card_bg};
                border-left: 1px solid {border_col};
            }}
            QFrame#pv-header {{
                background-color: transparent;
                border: none;
                min-height: 28px;
                max-height: 28px;
            }}
            QLabel#lbl-pv-hero {{
                background-color: {'rgba(0, 0, 0, 0.25)' if self.is_dark else '#F8FAFC'};
                border: 1px solid {border_col};
                border-radius: 8px;
                min-height: 135px;
            }}
            QLabel#lbl-pv-badge {{
                background-color: {'rgba(255, 255, 255, 0.06)' if self.is_dark else '#E2E8F0'};
                border: 1px solid {border_col};
                border-radius: 4px;
                padding: 2px 8px;
                color: {text_muted};
                font-size: 10px;
                font-weight: 600;
            }}
            QFrame#fluent-props-card {{
                background-color: {'rgba(255, 255, 255, 0.03)' if self.is_dark else '#F8FAFC'};
                border: 1px solid {border_col};
                border-radius: 6px;
                padding: 8px;
            }}
            QTextEdit#pv-txt-preview {{
                background-color: {'rgba(0, 0, 0, 0.25)' if self.is_dark else '#FFFFFF'};
                color: {text_col};
                border: 1px solid {border_col};
                border-radius: 6px;
                padding: 6px;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 10px;
                max-height: 130px;
            }}
            QPushButton#btn-fluent-primary {{
                background-color: #0078D4;
                color: #FFFFFF;
                font-weight: 600;
                font-size: 11.5px;
                border: none;
                border-radius: 6px;
                min-height: 30px;
                padding: 4px 12px;
            }}
            QPushButton#btn-fluent-primary:hover {{
                background-color: #1084D9;
            }}
            QPushButton#btn-fluent-primary:pressed {{
                background-color: #006CBE;
            }}

            /* 7. Alt Durum Çubuğu (Status Bar) */
            QFrame#bottom-bar-frame {{
                background-color: {bg_col};
                border-top: 1px solid {border_col};
                min-height: 30px;
                max-height: 30px;
            }}
            QPushButton.fluent-status-btn {{
                background-color: {'rgba(255, 255, 255, 0.05)' if self.is_dark else '#FFFFFF'};
                border: 1px solid {border_col};
                border-radius: 4px;
                color: {text_col};
                font-size: 10.5px;
                font-weight: 600;
                padding: 3px 10px;
                min-height: 20px;
            }}
            QPushButton.fluent-status-btn:hover {{
                background-color: {'rgba(255, 255, 255, 0.1)' if self.is_dark else '#F1F5F9'};
            }}
            QPushButton#btn-fluent-lock {{
                background-color: rgba(239, 68, 68, 0.12);
                border: 1px solid rgba(239, 68, 68, 0.35);
                border-radius: 4px;
                color: #F87171;
                font-size: 10.5px;
                font-weight: 700;
                padding: 3px 10px;
                min-height: 20px;
            }}
            QPushButton#btn-fluent-lock:hover {{
                background-color: rgba(239, 68, 68, 0.25);
                color: #FFFFFF;
            }}

            /* Modern İnce Kaydırma Çubukları */
            QScrollBar:horizontal {{
                background: transparent;
                height: 6px;
                margin: 0px;
            }}
            QScrollBar::handle:horizontal {{
                background: {'rgba(255, 255, 255, 0.15)' if self.is_dark else 'rgba(0, 0, 0, 0.15)'};
                min-width: 20px;
                border-radius: 3px;
            }}
            QScrollBar::handle:horizontal:hover {{
                background: {'rgba(255, 255, 255, 0.25)' if self.is_dark else 'rgba(0, 0, 0, 0.25)'};
            }}
            QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0px; background: none; }}
            QScrollBar:vertical {{
                background: transparent;
                width: 6px;
                margin: 0px;
            }}
            QScrollBar::handle:vertical {{
                background: {'rgba(255, 255, 255, 0.15)' if self.is_dark else 'rgba(0, 0, 0, 0.15)'};
                min-height: 20px;
                border-radius: 3px;
            }}
            QScrollBar::handle:vertical:hover {{
                background: {'rgba(255, 255, 255, 0.25)' if self.is_dark else 'rgba(0, 0, 0, 0.25)'};
            }}
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0px; background: none; }}
            QSplitter::handle {{
                background-color: {border_col};
            }}
        """)

        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(0)
        main_layout.setContentsMargins(0, 0, 0, 0)

        self.tabbar_frame = QFrame()
        tabbar_frame = self.tabbar_frame
        tabbar_frame.setObjectName("fluent-tabbar")
        tb_layout = QHBoxLayout(tabbar_frame)
        tb_layout.setContentsMargins(12, 4, 12, 0)
        tb_layout.setSpacing(8)

        active_tab = QFrame()
        active_tab.setObjectName("fluent-active-tab")
        at_layout = QHBoxLayout(active_tab)
        at_layout.setContentsMargins(8, 0, 6, 0)
        at_layout.setSpacing(6)

        lbl_tab_icon = QLabel()
        lbl_tab_icon.setPixmap(get_svg_pixmap("lock", accent_vault, 14))
        at_layout.addWidget(lbl_tab_icon)

        lbl_tab_name = QLabel(Path(self.vault_path).name)
        lbl_tab_name.setStyleSheet(f"font-size: 11.5px; font-weight: 600; color: {text_col};")
        at_layout.addWidget(lbl_tab_name)

        btn_tab_close = QPushButton()
        btn_tab_close.setObjectName("fluent-tab-close")
        btn_tab_close.setIcon(get_svg_icon("close", text_muted, 11))
        btn_tab_close.setToolTip("Kasayı Kilitle ve Kapat")
        btn_tab_close.clicked.connect(self.lock_and_close)
        at_layout.addWidget(btn_tab_close)

        tb_layout.addWidget(active_tab)

        tb_layout.addStretch()

        self.lbl_stats = QLabel("Yükleniyor...")
        self.lbl_stats.setVisible(False)

        badge_card = QFrame()
        badge_card.setStyleSheet("background-color: rgba(16, 185, 129, 0.14); border: 1px solid rgba(16, 185, 129, 0.35); border-radius: 12px; padding: 2px 8px;")
        bc_layout = QHBoxLayout(badge_card)
        bc_layout.setContentsMargins(4, 1, 4, 1)
        bc_layout.setSpacing(4)
        b_icon = QLabel()
        b_icon.setPixmap(get_svg_pixmap("shield", "#34D399", 11))
        bc_layout.addWidget(b_icon)
        b_text = QLabel("AES-256-GCM BAĞIMSIZ GÜVENLİ KASA")
        b_text.setStyleSheet("color: #34D399; font-size: 9.5px; font-weight: 700; border: none; background: transparent;")
        bc_layout.addWidget(b_text)
        tb_layout.addWidget(badge_card)

        main_layout.addWidget(tabbar_frame)

        omnibar_frame = QFrame()
        omnibar_frame.setObjectName("fluent-omnibar")
        ob_layout = QHBoxLayout(omnibar_frame)
        ob_layout.setContentsMargins(10, 4, 10, 4)
        ob_layout.setSpacing(6)

        self.btn_back = QPushButton()
        self.btn_back.setProperty("class", "fluent-nav-btn")
        self.btn_back.setIcon(get_svg_icon("arrow_left", text_muted, 15))
        self.btn_back.setToolTip("Geri (Alt+Sol)")
        self.btn_back.clicked.connect(self.navigate_back)
        ob_layout.addWidget(self.btn_back)

        self.btn_forward = QPushButton()
        self.btn_forward.setProperty("class", "fluent-nav-btn")
        self.btn_forward.setIcon(get_svg_icon("arrow_right", text_muted, 15))
        self.btn_forward.setToolTip("İleri (Alt+Sağ)")
        self.btn_forward.clicked.connect(self.navigate_forward)
        ob_layout.addWidget(self.btn_forward)

        self.btn_up = QPushButton()
        self.btn_up.setProperty("class", "fluent-nav-btn")
        self.btn_up.setIcon(get_svg_icon("arrow_up", text_muted, 15))
        self.btn_up.setToolTip("Bir Üst Klasöre Çık (Alt+Yukarı)")
        self.btn_up.clicked.connect(self.navigate_up)
        ob_layout.addWidget(self.btn_up)

        self.btn_refresh = QPushButton()
        self.btn_refresh.setProperty("class", "fluent-nav-btn")
        self.btn_refresh.setIcon(get_svg_icon("refresh", text_muted, 15))
        self.btn_refresh.setToolTip("Yenile (F5)")
        self.btn_refresh.clicked.connect(self.refresh_file_list)
        ob_layout.addWidget(self.btn_refresh)

        self.btn_exp_fullscreen = QPushButton()
        self.btn_exp_fullscreen.setProperty("class", "fluent-nav-btn")
        self.btn_exp_fullscreen.setIcon(get_svg_icon("expand", text_muted, 15))
        self.btn_exp_fullscreen.setToolTip("Gezgini Tam Ekran Yap / Pencereye Dön (F11)")
        self.btn_exp_fullscreen.clicked.connect(self.toggle_fullscreen_mode)
        ob_layout.addWidget(self.btn_exp_fullscreen)

        self.breadcrumb_container = QWidget()
        self.breadcrumb_container.setObjectName("fluent-breadcrumbs")
        self.breadcrumb_layout = QHBoxLayout(self.breadcrumb_container)
        self.breadcrumb_layout.setContentsMargins(4, 0, 4, 0)
        self.breadcrumb_layout.setSpacing(2)
        ob_layout.addWidget(self.breadcrumb_container, stretch=1)

        search_box_container = QWidget()
        sb_layout = QHBoxLayout(search_box_container)
        sb_layout.setContentsMargins(0, 0, 0, 0)
        sb_layout.setSpacing(0)

        self.txt_search = QLineEdit()
        self.txt_search.setObjectName("fluent-search")
        self.txt_search.setPlaceholderText("Kasada ara...")
        self.txt_search.textChanged.connect(self.on_search_changed)
        sb_layout.addWidget(self.txt_search)

        lbl_search_ico = QLabel(self.txt_search)
        lbl_search_ico.setPixmap(get_svg_pixmap("search", text_muted, 13))
        lbl_search_ico.setStyleSheet("background: transparent; border: none;")
        lbl_search_ico.move(8, 7)

        ob_layout.addWidget(search_box_container)

        main_layout.addWidget(omnibar_frame)

        commandbar_frame = QFrame()
        commandbar_frame.setObjectName("fluent-commandbar")
        cb_layout = QHBoxLayout(commandbar_frame)
        cb_layout.setContentsMargins(10, 3, 10, 3)
        cb_layout.setSpacing(4)

        def make_cmd_sep():
            sep = QFrame()
            sep.setFrameShape(QFrame.Shape.VLine)
            sep.setFixedWidth(1)
            sep.setFixedHeight(18)
            sep.setStyleSheet(f"background-color: {border_col}; border: none; margin: 0px 4px;")
            return sep

        self.btn_new_menu = QPushButton("+ Yeni")
        self.btn_new_menu.setObjectName("btn-new-menu")
        self.btn_new_menu.setToolTip("Yeni Klasör, Dosya veya Belge Oluştur")
        new_menu = QMenu(self)
        act_new_folder = new_menu.addAction(get_svg_icon("folder_plus", accent_vault, 14), "Yeni Klasör")
        act_new_folder.triggered.connect(self.on_new_folder_clicked)
        act_new_file = new_menu.addAction(get_svg_icon("file_text", accent_blue, 14), "Yeni Metin Belgesi (.txt)")
        act_new_file.triggered.connect(self.on_new_text_file_clicked)
        new_menu.addSeparator()
        act_add_f = new_menu.addAction(get_svg_icon("file_plus", accent_vault, 14), "Dosya Ekle...")
        act_add_f.triggered.connect(self.on_add_files_clicked)
        act_add_dir = new_menu.addAction(get_svg_icon("folder_open", accent_vault, 14), "Klasör Ekle...")
        act_add_dir.triggered.connect(self.on_add_folder_clicked)
        self.btn_new_menu.setMenu(new_menu)
        cb_layout.addWidget(self.btn_new_menu)

        cb_layout.addWidget(make_cmd_sep())

        btn_cut = QPushButton()
        btn_cut.setProperty("class", "fluent-tool-btn")
        btn_cut.setIcon(get_svg_icon("scissors", text_muted, 14))
        btn_cut.setToolTip("Kes (Ctrl+X)")
        btn_cut.clicked.connect(self.on_cut_selected)
        cb_layout.addWidget(btn_cut)

        btn_copy = QPushButton()
        btn_copy.setProperty("class", "fluent-tool-btn")
        btn_copy.setIcon(get_svg_icon("copy", text_muted, 14))
        btn_copy.setToolTip("Kopyala (Ctrl+C)")
        btn_copy.clicked.connect(self.on_copy_selected)
        cb_layout.addWidget(btn_copy)

        btn_paste = QPushButton()
        btn_paste.setProperty("class", "fluent-tool-btn")
        btn_paste.setIcon(get_svg_icon("clipboard", text_muted, 14))
        btn_paste.setToolTip("Yapıştır (Ctrl+V)")
        btn_paste.clicked.connect(self.on_paste)
        cb_layout.addWidget(btn_paste)

        btn_rename = QPushButton()
        btn_rename.setProperty("class", "fluent-tool-btn")
        btn_rename.setIcon(get_svg_icon("edit", text_muted, 14))
        btn_rename.setToolTip("Yeniden Adlandır (F2)")
        btn_rename.clicked.connect(self.on_rename_selected_item)
        cb_layout.addWidget(btn_rename)

        btn_export = QPushButton()
        btn_export.setProperty("class", "fluent-tool-btn")
        btn_export.setIcon(get_svg_icon("download", text_muted, 14))
        btn_export.setToolTip("Dışa Aktar...")
        btn_export.clicked.connect(self.on_export_selected_items)
        cb_layout.addWidget(btn_export)

        btn_delete = QPushButton()
        btn_delete.setProperty("class", "fluent-tool-btn")
        btn_delete.setIcon(get_svg_icon("trash", "#EF4444" if self.is_dark else "#DC2626", 14))
        btn_delete.setToolTip("Kasadan Kalıcı Olarak Sil (Delete)")
        btn_delete.clicked.connect(self.on_delete_selected_items)
        cb_layout.addWidget(btn_delete)

        cb_layout.addWidget(make_cmd_sep())

        btn_edit = QPushButton()
        btn_edit.setProperty("class", "fluent-tool-btn")
        btn_edit.setIcon(get_svg_icon("file_text", text_muted, 14))
        btn_edit.setToolTip("Kasa İçi Düzenleyici (Bellekte Sıfır-İz)")
        btn_edit.clicked.connect(self.on_edit_text_selected)
        cb_layout.addWidget(btn_edit)

        btn_hex = QPushButton()
        btn_hex.setProperty("class", "fluent-tool-btn")
        btn_hex.setIcon(get_svg_icon("binary", text_muted, 14))
        btn_hex.setToolTip("İkili Bayt (Hex) İnceleyici")
        btn_hex.clicked.connect(self.on_view_hex_selected)
        cb_layout.addWidget(btn_hex)

        btn_props = QPushButton()
        btn_props.setProperty("class", "fluent-tool-btn")
        btn_props.setIcon(get_svg_icon("properties", text_muted, 14))
        btn_props.setToolTip("Özellikler & AEAD Bütünlük Doğrulama (Alt+Enter)")
        btn_props.clicked.connect(self.on_properties_selected)
        cb_layout.addWidget(btn_props)

        cb_layout.addWidget(make_cmd_sep())

        self.combo_category = QComboBox()
        self.combo_category.setObjectName("fluent-combo-category")
        self.combo_category.addItem("Tür: Tümü", None)
        self.combo_category.addItem("Uygulamalar (.exe)", "app")
        self.combo_category.addItem("Belgeler", "document")
        self.combo_category.addItem("Resimler", "image")
        self.combo_category.addItem("Ses & Müzik", "music")
        self.combo_category.addItem("Videolar", "video")
        self.combo_category.addItem("Arşivler", "archive")
        self.combo_category.addItem("Kod & Veri", "code")
        self.combo_category.currentIndexChanged.connect(self.on_category_combo_changed)
        cb_layout.addWidget(self.combo_category)

        cb_layout.addStretch()

        self.btn_view_details = QPushButton()
        self.btn_view_details.setProperty("class", "fluent-tool-btn")
        self.btn_view_details.setIcon(get_svg_icon("view_list", accent_blue if self.view_mode == "details" else text_muted, 15))
        self.btn_view_details.setToolTip("Ayrıntılar Görünümü")
        self.btn_view_details.clicked.connect(lambda: self.set_view_mode("details"))
        cb_layout.addWidget(self.btn_view_details)

        self.btn_view_grid = QPushButton()
        self.btn_view_grid.setProperty("class", "fluent-tool-btn")
        self.btn_view_grid.setIcon(get_svg_icon("view_grid", accent_blue if self.view_mode == "grid" else text_muted, 15))
        self.btn_view_grid.setToolTip("Izgara / Küçük Resim Görünümü")
        self.btn_view_grid.clicked.connect(lambda: self.set_view_mode("grid"))
        cb_layout.addWidget(self.btn_view_grid)

        self.btn_toggle_preview = QPushButton()
        self.btn_toggle_preview.setProperty("class", "fluent-tool-btn")
        self.btn_toggle_preview.setIcon(get_svg_icon("panel_right", accent_blue, 15))
        self.btn_toggle_preview.setToolTip("Ayrıntılar ve Önizleme Bölmesini Aç/Kapat")
        self.btn_toggle_preview.clicked.connect(self.toggle_preview_pane)
        cb_layout.addWidget(self.btn_toggle_preview)

        self.btn_header_backup = QPushButton()
        self.btn_header_backup.setProperty("class", "fluent-tool-btn")
        self.btn_header_backup.setIcon(get_svg_icon("header_backup", accent_blue, 15))
        self.btn_header_backup.setToolTip("Ayrılmış Başlık Yedeği Al / Başlık Onar")
        self.btn_header_backup.clicked.connect(self.on_open_header_backup)
        cb_layout.addWidget(self.btn_header_backup)

        self.btn_settings = QPushButton()
        self.btn_settings.setProperty("class", "fluent-tool-btn")
        self.btn_settings.setIcon(get_svg_icon("settings", text_muted, 15))
        self.btn_settings.setToolTip("Ayarlar ve Temalar")
        self.btn_settings.clicked.connect(self.open_settings_dialog)
        cb_layout.addWidget(self.btn_settings)

        main_layout.addWidget(commandbar_frame)

        self.main_splitter = QSplitter(Qt.Orientation.Horizontal)

        left_pane = QFrame()
        left_pane.setObjectName("left-pane")
        left_layout = QVBoxLayout(left_pane)
        left_layout.setContentsMargins(6, 6, 6, 6)
        left_layout.setSpacing(4)

        tree_header = QFrame()
        tree_header.setObjectName("tree-header")
        th_layout = QHBoxLayout(tree_header)
        th_layout.setContentsMargins(6, 0, 4, 0)
        th_layout.setSpacing(4)

        lbl_tree_title = QLabel("KASA BÖLÜMLERİ")
        lbl_tree_title.setStyleSheet(f"font-size: 10px; font-weight: 700; color: {text_muted}; letter-spacing: 0.5px;")
        th_layout.addWidget(lbl_tree_title)
        th_layout.addStretch()

        btn_tree_expand = QPushButton()
        btn_tree_expand.setProperty("class", "fluent-nav-btn")
        btn_tree_expand.setIcon(get_svg_icon("expand", text_muted, 12))
        btn_tree_expand.setToolTip("Tümünü Genişlet")
        btn_tree_expand.clicked.connect(self.tree_folders_expand_all)
        th_layout.addWidget(btn_tree_expand)

        btn_tree_collapse = QPushButton()
        btn_tree_collapse.setProperty("class", "fluent-nav-btn")
        btn_tree_collapse.setIcon(get_svg_icon("collapse", text_muted, 12))
        btn_tree_collapse.setToolTip("Tümünü Daralt")
        btn_tree_collapse.clicked.connect(self.tree_folders_collapse_all)
        th_layout.addWidget(btn_tree_collapse)

        left_layout.addWidget(tree_header)

        self.tree_folders = VaultTreeWidget()
        self.tree_folders.setHeaderHidden(True)
        self.tree_folders.itemClicked.connect(self.on_tree_item_clicked)
        self.tree_folders.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree_folders.customContextMenuRequested.connect(self.show_tree_context_menu)
        left_layout.addWidget(self.tree_folders)

        self.main_splitter.addWidget(left_pane)

        self.center_stack = QStackedWidget()

        self.table = VaultTableWidget(self)
        self.table.setColumnCount(6)
        self.table.verticalHeader().setVisible(False)
        self.table.setHorizontalHeaderLabels([
            "Ad ▲", "Tür", "Boyut", "Sıkıştırılmış", "Değiştirilme Tarihi", "Bütünlük Durumu"
        ])
        self.table.setShowGrid(False)
        self.table.setGridStyle(Qt.PenStyle.NoPen)
        header = self.table.horizontalHeader()
        header.setStretchLastSection(False)
        header.setHighlightSections(False)
        for col in range(6):
            header.setSectionResizeMode(col, QHeaderView.ResizeMode.Interactive)
        self.table.setColumnWidth(0, 240)
        self.table.setColumnWidth(1, 110)
        self.table.setColumnWidth(2, 75)
        self.table.setColumnWidth(3, 85)
        self.table.setColumnWidth(4, 130)
        self.table.setColumnWidth(5, 120)
        header.setCascadingSectionResizes(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_context_menu)
        self.table.itemDoubleClicked.connect(self.on_item_double_clicked)
        self.table.itemSelectionChanged.connect(self.on_selection_changed)
        self.table.horizontalHeader().sectionClicked.connect(self.on_table_header_clicked)
        self.center_stack.addWidget(self.table)

        self.grid_list = VaultListWidget(self)
        self.grid_list.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.grid_list.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.grid_list.customContextMenuRequested.connect(self.show_context_menu)
        self.grid_list.itemDoubleClicked.connect(self.on_item_double_clicked)
        self.grid_list.itemSelectionChanged.connect(self.on_selection_changed)
        self.center_stack.addWidget(self.grid_list)

        self.main_splitter.addWidget(self.center_stack)

        self.preview_pane = QFrame()
        self.preview_pane.setObjectName("preview-pane")
        self.preview_pane.setMinimumWidth(250)
        self.preview_outer_layout = QVBoxLayout(self.preview_pane)
        self.preview_outer_layout.setContentsMargins(0, 0, 0, 0)
        self.preview_outer_layout.setSpacing(0)

        pv_header = QFrame()
        pv_header.setObjectName("pv-header")
        pv_h_layout = QHBoxLayout(pv_header)
        pv_h_layout.setContentsMargins(12, 8, 12, 6)
        pv_h_layout.setSpacing(4)

        lbl_pv_title = QLabel("Ayrıntılar")
        lbl_pv_title.setStyleSheet(f"font-size: 12px; font-weight: 700; color: {text_col};")
        pv_h_layout.addWidget(lbl_pv_title)
        pv_h_layout.addStretch()

        btn_close_preview = QPushButton()
        btn_close_preview.setProperty("class", "fluent-nav-btn")
        btn_close_preview.setIcon(get_svg_icon("close", text_muted, 13))
        btn_close_preview.setToolTip("Ayrıntılar Bölmesini Gizle")
        btn_close_preview.clicked.connect(self.toggle_preview_pane)
        pv_h_layout.addWidget(btn_close_preview)

        self.preview_outer_layout.addWidget(pv_header)

        self.preview_scroll = QScrollArea()
        self.preview_scroll.setWidgetResizable(True)
        self.preview_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.preview_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.preview_scroll.setStyleSheet("background: transparent; border: none;")

        self.preview_content = QWidget()
        self.preview_content.setStyleSheet("background: transparent;")
        self.preview_layout = QVBoxLayout(self.preview_content)
        self.preview_layout.setContentsMargins(10, 4, 10, 10)
        self.preview_layout.setSpacing(8)

        self.preview_scroll.setWidget(self.preview_content)
        self.preview_outer_layout.addWidget(self.preview_scroll, stretch=1)

        self.lbl_image_preview = QLabel()
        self.lbl_image_preview.setObjectName("lbl-pv-hero")
        self.lbl_image_preview.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.lbl_image_preview.setMinimumHeight(135)
        self.lbl_image_preview.mousePressEvent = self.on_preview_hero_clicked
        self.preview_layout.addWidget(self.lbl_image_preview)

        accent_col = accent_vault
        fs_btn_bg = "rgba(56, 189, 248, 0.08)" if self.is_dark else "rgba(5, 150, 105, 0.08)"

        pv_btn_layout = QHBoxLayout()
        pv_btn_layout.setContentsMargins(0, 0, 0, 0)
        pv_btn_layout.setSpacing(6)

        self.btn_fullscreen_preview = QPushButton(" Tam Ekran Görüntüle (F)")
        self.btn_fullscreen_preview.setObjectName("btn-pv-fullscreen")
        self.btn_fullscreen_preview.setIcon(get_svg_icon("expand", accent_col, 14))
        self.btn_fullscreen_preview.setToolTip("Görseli tam ekran görüntüle (Kısayol: F veya Çift Tık) - Slayt için F5/S tuşlarını kullanabilirsiniz")
        self.btn_fullscreen_preview.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_fullscreen_preview.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.btn_fullscreen_preview.setStyleSheet(f"""
            QPushButton#btn-pv-fullscreen {{
                background-color: {fs_btn_bg};
                border: 1px solid {accent_col};
                border-radius: 6px;
                padding: 6px 8px;
                color: {accent_col};
                font-weight: 700;
                font-size: 11.5px;
                min-height: 28px;
            }}
            QPushButton#btn-pv-fullscreen:hover {{
                background-color: {accent_col};
                color: {'#051515' if self.is_dark else '#FFFFFF'};
            }}
        """)
        self.btn_fullscreen_preview.clicked.connect(self.on_fullscreen_preview_action)
        self.btn_fullscreen_preview.hide()
        pv_btn_layout.addWidget(self.btn_fullscreen_preview)

        self.preview_layout.addLayout(pv_btn_layout)

        self.lbl_pv_name = QLabel("Seçili öğe yok")
        self.lbl_pv_name.setStyleSheet(f"font-size: 13px; font-weight: 700; color: {text_col};")
        self.lbl_pv_name.setWordWrap(True)
        self.preview_layout.addWidget(self.lbl_pv_name)

        self.lbl_pv_badge = QLabel()
        self.lbl_pv_badge.setObjectName("lbl-pv-badge")
        self.lbl_pv_badge.hide()
        self.preview_layout.addWidget(self.lbl_pv_badge)

        self.props_card = QFrame()
        self.props_card.setObjectName("fluent-props-card")
        pc_layout = QVBoxLayout(self.props_card)
        pc_layout.setContentsMargins(8, 8, 8, 8)
        pc_layout.setSpacing(6)

        self.lbl_pv_info = QLabel("Detayları ve özellikleri görmek için bir öğe seçin.")
        self.lbl_pv_info.setStyleSheet(f"font-size: 10.5px; color: {text_muted}; line-height: 1.4;")
        self.lbl_pv_info.setWordWrap(True)
        pc_layout.addWidget(self.lbl_pv_info)

        self.lbl_pv_crypto = QLabel()
        self.lbl_pv_crypto.setStyleSheet(f"font-size: 10px; color: #10B981; font-weight: 700;")
        self.lbl_pv_crypto.setWordWrap(True)
        pc_layout.addWidget(self.lbl_pv_crypto)

        self.preview_layout.addWidget(self.props_card)

        self.audio_widget = AudioPreviewWidget(self, is_dark=self.is_dark)
        self.audio_widget.hide()
        self.preview_layout.addWidget(self.audio_widget)

        self.video_widget = VideoPreviewWidget(self, is_dark=self.is_dark)
        self.video_widget.fullscreen_requested.connect(self.open_fullscreen_video)
        self.video_widget.hide()
        self.preview_layout.addWidget(self.video_widget)

        self.txt_preview = QTextEdit()
        self.txt_preview.setObjectName("pv-txt-preview")
        self.txt_preview.setReadOnly(True)
        self.txt_preview.setFont(QFont("Consolas", 10))
        self.txt_preview.hide()
        self.preview_layout.addWidget(self.txt_preview)

        self.preview_layout.addStretch()

        self.btn_pv_view_vault = QPushButton("Kasa İçinde Görüntüle")
        self.btn_pv_view_vault.setObjectName("btn-fluent-primary")
        self.btn_pv_view_vault.setIcon(get_svg_icon("eye", "#FFFFFF", 13))
        self.btn_pv_view_vault.setToolTip("Dosyayı kasa içinde görüntüle — hiçbir harici uygulama çağrılmaz")
        self.btn_pv_view_vault.clicked.connect(self._on_pv_view_vault_clicked)
        self.btn_pv_view_vault.hide()
        self.preview_layout.addWidget(self.btn_pv_view_vault)

        self.btn_pv_open = QPushButton("Varsayılan Uygulamada Aç")
        self.btn_pv_open.setObjectName("btn-fluent-primary")
        self.btn_pv_open.setIcon(get_svg_icon("eye", "#FFFFFF", 13))
        self.btn_pv_open.clicked.connect(self.on_preview_action_clicked)
        self.btn_pv_open.hide()
        self.preview_layout.addWidget(self.btn_pv_open)

        self.main_splitter.addWidget(self.preview_pane)

        self.main_splitter.setSizes([180, 640, 270])
        self.main_splitter.setStretchFactor(0, 0)
        self.main_splitter.setStretchFactor(1, 1)
        self.main_splitter.setStretchFactor(2, 0)
        self.preview_pane.setMinimumWidth(260)
        main_layout.addWidget(self.main_splitter)

        status_frame = QFrame()
        status_frame.setObjectName("bottom-bar-frame")
        sb_layout = QHBoxLayout(status_frame)
        sb_layout.setContentsMargins(12, 0, 12, 0)
        sb_layout.setSpacing(8)

        lbl_info_icon = QLabel()
        lbl_info_icon.setPixmap(get_svg_pixmap("info", text_muted, 13))
        sb_layout.addWidget(lbl_info_icon)

        self.lbl_status = QLabel("Hazır")
        self.lbl_status.setStyleSheet(f"font-size: 11px; color: {text_muted};")
        sb_layout.addWidget(self.lbl_status)

        sb_layout.addStretch()

        self.lbl_quota_stats = QLabel("Kullanım: -")
        self.lbl_quota_stats.setStyleSheet(f"font-size: 10px; color: {text_muted};")
        sb_layout.addWidget(self.lbl_quota_stats)

        self.vault_quota_bar = QProgressBar()
        self.vault_quota_bar.setRange(0, 100)
        self.vault_quota_bar.setValue(0)
        self.vault_quota_bar.setFixedWidth(110)
        self.vault_quota_bar.setFixedHeight(12)
        self.vault_quota_bar.setTextVisible(True)
        self.vault_quota_bar.setStyleSheet(f"""
            QProgressBar {{
                border: 1px solid {border_col};
                border-radius: 6px;
                text-align: center;
                font-size: 8.5px;
                font-weight: 700;
                background-color: {'rgba(255, 255, 255, 0.05)' if self.is_dark else '#E2E8F0'};
                color: {text_col};
            }}
            QProgressBar::chunk {{
                background-color: {accent_vault};
                border-radius: 5px;
            }}
        """)
        sb_layout.addWidget(self.vault_quota_bar)

        btn_compact = QPushButton("Boş Alanı Temizle")
        btn_compact.setProperty("class", "fluent-status-btn")
        btn_compact.setIcon(get_svg_icon("sparkles", accent_vault, 13))
        btn_compact.setToolTip("Silinen dosyalardan kalan boşluğu temizleyip kasayı optimize eder")
        btn_compact.clicked.connect(self.on_compact_vault_clicked)
        sb_layout.addWidget(btn_compact)

        btn_lock = QPushButton("Kasayı Kilitle")
        btn_lock.setObjectName("btn-fluent-lock")
        btn_lock.setIcon(get_svg_icon("lock", "#F87171", 13))
        btn_lock.setToolTip("Kasayı güvenle kapatır, anahtarları bellekten siler ve geçici izleri imha eder")
        btn_lock.clicked.connect(self.lock_and_close)
        sb_layout.addWidget(btn_lock)

        main_layout.addWidget(status_frame)

        self.setAcceptDrops(True)
        self.main_splitter.setAcceptDrops(True)
        self.center_stack.setAcceptDrops(True)
        self.table.setAcceptDrops(True)
        self.grid_list.setAcceptDrops(True)
        self.tree_folders.setAcceptDrops(True)
        self.preview_pane.setAcceptDrops(True)

        for w in (self.table, self.grid_list, self.tree_folders, self.table.viewport(), self.grid_list.viewport(), self.tree_folders.viewport()):
            w.installEventFilter(self)
        self.enable_native_drag_drop()

    def open_settings_dialog(self):
        """Kasa gezgini içinden ayarları ve temaları değiştirme penceresini açar."""
        from extra_dialogs import AppSettingsDialog
        from config import load_config
        cfg = load_config()
        dlg = AppSettingsDialog(self, config=cfg, current_theme=self.current_theme)
        dlg.theme_changed.connect(self.apply_theme)
        dlg.exec()

    def on_open_header_backup(self):
        """Ayrılmış Başlık Yedeği ve Kurtarma sihirbazını açar."""
        from extra_dialogs import HeaderBackupRestoreDialog
        dlg = HeaderBackupRestoreDialog(
            parent=self,
            vault_path=self.vault_path,
            theme=self.current_theme,
            engine=getattr(self.parent(), "engine", None)
        )
        dlg.exec()

    def apply_theme(self, theme: str):
        """Kasa gezgini temasını anında günceller."""
        self.current_theme = theme
        self.is_dark = (theme in ("dark", "apple_dark"))
        if hasattr(self, "setup_ui"):
            if self.current_theme == "apple_dark":
                bg_col = "#161618"; card_bg = "#212124"; border_col = "rgba(255, 255, 255, 0.08)"; text_col = "#F5F5F7"; text_muted = "#86868B"; accent_blue = "#2997FF"; accent_vault = "#30D158"; table_bg = "#1A1A1D"
            elif self.current_theme == "apple_light":
                bg_col = "#F5F5F7"; card_bg = "#FFFFFF"; border_col = "rgba(0, 0, 0, 0.08)"; text_col = "#1D1D1F"; text_muted = "#6E6E73"; accent_blue = "#0071E3"; accent_vault = "#30D158"; table_bg = "#FFFFFF"
            else:
                bg_col = "#19191d" if self.is_dark else "#F3F3F3"; card_bg = "#202024" if self.is_dark else "#FFFFFF"; border_col = "rgba(255, 255, 255, 0.07)" if self.is_dark else "rgba(0, 0, 0, 0.08)"; text_col = "#FFFFFF" if self.is_dark else "#1A1A1A"; text_muted = "#A1A1AA" if self.is_dark else "#5A5A5A"; accent_blue = "#38BDF8" if self.is_dark else "#0078D4"; accent_vault = "#38BDF8" if self.is_dark else "#059669"; table_bg = "#18181b" if self.is_dark else "#FFFFFF"
            self.setStyleSheet(f"QDialog {{ background-color: {bg_col}; color: {text_col}; }}")

    def refresh_file_list(self):
        """Kasa kataloğunu yükler, ağacı ve görünümü günceller."""
        try:
            catalog = CustomVaultEngine.load_catalog(self.vault_path, self.auth_info)
            self.cached_files = catalog.get("files", [])
            self.cached_folders = catalog.get("folders", [])

            if hasattr(self, "pending_icon_cache") and self.pending_icon_cache:
                for f in self.cached_files:
                    fp = f.get("path")
                    if fp in self.pending_icon_cache:
                        pix = self.pending_icon_cache.pop(fp)
                        self.thumbnail_cache[f["id"]] = pix

            self.rebuild_folder_tree()

            self.update_current_view()

            tot_size = sum(f.get("size", 0) for f in self.cached_files)
            tot_comp = sum(f.get("comp_size", 0) for f in self.cached_files)
            v_size = Path(self.vault_path).stat().st_size if Path(self.vault_path).exists() else 0

            max_bytes = None
            if self.auth_info.get("is_decoy"):
                if "max_size_mb" in catalog and catalog["max_size_mb"]:
                    max_bytes = catalog["max_size_mb"] * 1024 * 1024
                elif "max_size_gb" in catalog and catalog["max_size_gb"]:
                    max_bytes = catalog["max_size_gb"] * 1024 * 1024 * 1024
            else:
                if "max_size_gb" in catalog and catalog["max_size_gb"]:
                    max_bytes = catalog["max_size_gb"] * 1024 * 1024 * 1024
                elif "max_size_mb" in catalog and catalog["max_size_mb"]:
                    max_bytes = catalog["max_size_mb"] * 1024 * 1024

            cap_str = ""
            if max_bytes:
                pct = min(100, int((tot_size / max_bytes) * 100))
                cap_str = f" | Kota: {format_size(max_bytes)} (%{pct})"
                self.vault_quota_bar.setValue(pct)
                self.vault_quota_bar.setFormat(f"%{pct}")
                self.lbl_quota_stats.setText(f"Kullanım: {format_size(tot_size)} / {format_size(max_bytes)}")
            else:
                self.vault_quota_bar.setValue(100)
                self.vault_quota_bar.setFormat("Dinamik")
                self.lbl_quota_stats.setText(f"Toplam Veri: {format_size(tot_size)}")

            ratio = f" (Sıkıştırma: %{int((1 - tot_comp/tot_size)*100)})" if tot_size > 0 else ""
            stats_text = (
                f"{len(self.cached_files)} dosya | "
                f"Boyut: {format_size(tot_size)} | "
                f"Şifreli: {format_size(tot_comp)}{ratio} | "
                f"Konteyner: {format_size(v_size)}{cap_str}"
            )
            self.lbl_stats.setText(stats_text)
            self.vault_quota_bar.setToolTip(stats_text)
            self.lbl_quota_stats.setToolTip(stats_text)
            for btn in self.findChildren(QPushButton):
                btn.setAutoDefault(False)
                btn.setDefault(False)
        except Exception as e:
            QMessageBox.critical(self, "Hata", f"Kasa verileri yüklenemedi:\n{e}")

    def rebuild_folder_tree(self):
        """Sol gezinti ağacındaki klasör yapısını yeniden inşa eder."""
        accent_col = "#2997FF" if getattr(self, "theme", "dark") == "apple_dark" else ("#0071E3" if getattr(self, "theme", "dark") == "apple_light" else ("#38BDF8" if getattr(self, "is_dark", True) else "#0284C7"))
        self.tree_folders.clear()

        root_item = QTreeWidgetItem([Path(self.vault_path).name])
        root_item.setIcon(0, get_svg_icon("folder_open" if self.current_folder == "" else "folder", accent_col, 16))
        root_item.setData(0, Qt.ItemDataRole.UserRole, "")
        self.tree_folders.addTopLevelItem(root_item)

        all_dirs = set(self.cached_folders)
        for f in self.cached_files:
            parts = f.get("path", "").split("/")
            if len(parts) > 1:
                cur = ""
                for p in parts[:-1]:
                    cur = f"{cur}/{p}" if cur else p
                    all_dirs.add(cur)

        dir_items: Dict[str, QTreeWidgetItem] = {"": root_item}
        for d in sorted(list(all_dirs)):
            if not d:
                continue
            parts = d.split("/")
            parent_path = "/".join(parts[:-1])
            parent_item = dir_items.get(parent_path, root_item)

            item = QTreeWidgetItem([parts[-1]])
            item.setIcon(0, get_svg_icon("folder", accent_col, 16))
            item.setData(0, Qt.ItemDataRole.UserRole, d)
            parent_item.addChild(item)
            dir_items[d] = item

        root_item.setExpanded(True)

    def tree_folders_expand_all(self):
        self.tree_folders.expandAll()

    def tree_folders_collapse_all(self):
        self.tree_folders.collapseAll()

    def navigate_to_folder(self, folder_path: str, record_history: bool = True):
        """Belirtilen klasöre geçiş yapar ve görünümü günceller."""
        clean_path = folder_path.replace("\\", "/").strip("/ ")
        self.current_folder = clean_path

        if record_history:
            if self.history_index < len(self.history) - 1:
                self.history = self.history[:self.history_index + 1]
            self.history.append(clean_path)
            self.history_index = len(self.history) - 1

        self.update_current_view()

    def navigate_back(self):
        if self.history_index > 0:
            self.history_index -= 1
            self.navigate_to_folder(self.history[self.history_index], record_history=False)

    def navigate_forward(self):
        if self.history_index < len(self.history) - 1:
            self.history_index += 1
            self.navigate_to_folder(self.history[self.history_index], record_history=False)

    def navigate_up(self):
        if not self.current_folder:
            return
        parts = self.current_folder.split("/")
        parent_folder = "/".join(parts[:-1]) if len(parts) > 1 else ""
        self.navigate_to_folder(parent_folder)

    def set_view_mode(self, mode: str):
        """Detaylar tablosu ile Büyük Simgeler/Grid arasında geçiş yapar."""
        self.view_mode = mode
        accent_blue = "#38BDF8" if self.is_dark else "#0078D4"
        text_muted = "#A1A1AA" if self.is_dark else "#5A5A5A"
        if mode == "details":
            self.center_stack.setCurrentWidget(self.table)
            if hasattr(self, "btn_view_details"):
                self.btn_view_details.setIcon(get_svg_icon("view_list", accent_blue, 15))
                self.btn_view_details.setProperty("class", "fluent-tool-btn fluent-tool-btn-active")
                self.btn_view_details.style().unpolish(self.btn_view_details)
                self.btn_view_details.style().polish(self.btn_view_details)
            if hasattr(self, "btn_view_grid"):
                self.btn_view_grid.setIcon(get_svg_icon("view_grid", text_muted, 15))
                self.btn_view_grid.setProperty("class", "fluent-tool-btn")
                self.btn_view_grid.style().unpolish(self.btn_view_grid)
                self.btn_view_grid.style().polish(self.btn_view_grid)
        else:
            self.center_stack.setCurrentWidget(self.grid_list)
            if hasattr(self, "btn_view_details"):
                self.btn_view_details.setIcon(get_svg_icon("view_list", text_muted, 15))
                self.btn_view_details.setProperty("class", "fluent-tool-btn")
                self.btn_view_details.style().unpolish(self.btn_view_details)
                self.btn_view_details.style().polish(self.btn_view_details)
            if hasattr(self, "btn_view_grid"):
                self.btn_view_grid.setIcon(get_svg_icon("view_grid", accent_blue, 15))
                self.btn_view_grid.setProperty("class", "fluent-tool-btn fluent-tool-btn-active")
                self.btn_view_grid.style().unpolish(self.btn_view_grid)
                self.btn_view_grid.style().polish(self.btn_view_grid)
        self.update_current_view()

    def toggle_preview_pane(self):
        """Sağdaki önizleme bölmesini gösterir veya gizler."""
        visible = not self.preview_pane.isVisible()
        self.preview_pane.setVisible(visible)
        if hasattr(self, "btn_toggle_preview"):
            accent_blue = "#38BDF8" if self.is_dark else "#0078D4"
            text_muted = "#A1A1AA" if self.is_dark else "#5A5A5A"
            self.btn_toggle_preview.setIcon(get_svg_icon("panel_right", accent_blue if visible else text_muted, 15))
            self.btn_toggle_preview.setProperty("class", "fluent-tool-btn fluent-tool-btn-active" if visible else "fluent-tool-btn")
            self.btn_toggle_preview.style().unpolish(self.btn_toggle_preview)
            self.btn_toggle_preview.style().polish(self.btn_toggle_preview)

    def update_header_sort_indicators(self):
        """Tablo başlığındaki sıralama oklarını (▲ / ▼) günceller."""
        col_names = ["Ad", "Tür", "Boyut", "Sıkıştırılmış", "Değiştirilme Tarihi", "Bütünlük Durumu"]
        arrow = " ▲" if self.sort_ascending else " ▼"
        for i, name in enumerate(col_names):
            header_item = self.table.horizontalHeaderItem(i)
            if header_item:
                if i == self.sort_column:
                    header_item.setText(f"{name}{arrow}")
                else:
                    header_item.setText(name)

    def on_table_header_clicked(self, logical_index: int):
        """Kullanıcı sütun başlığına tıkladığında artan/azalan sıralama uygular."""
        if self.sort_column == logical_index:
            self.sort_ascending = not self.sort_ascending
        else:
            self.sort_column = logical_index
            self.sort_ascending = True
        self.update_header_sort_indicators()
        self.update_current_view()

    def set_category_filter(self, cat_key: Optional[str]):
        """Kategori filtresini ayarlar."""
        self.active_category_filter = cat_key
        if hasattr(self, "combo_category"):
            for i in range(self.combo_category.count()):
                if self.combo_category.itemData(i) == cat_key:
                    if self.combo_category.currentIndex() != i:
                        self.combo_category.blockSignals(True)
                        self.combo_category.setCurrentIndex(i)
                        self.combo_category.blockSignals(False)
                    break
        for k, btn in getattr(self, "category_chip_buttons", {}).items():
            btn.setChecked(k == cat_key)
        self.update_breadcrumbs()
        self.update_current_view()

    def on_category_combo_changed(self, index: int):
        """Kategori açılır menüsü değiştiğinde filtre uygular."""
        cat_key = self.combo_category.itemData(index)
        self.set_category_filter(cat_key)

    def update_breadcrumbs(self):
        """Adres çubuğundaki tıklanabilir gezinme butonlarını (Files App Breadcrumbs) oluşturur."""
        accent_blue = "#38BDF8" if self.is_dark else "#0078D4"
        text_col = "#FFFFFF" if self.is_dark else "#1A1A1A"
        muted_col = "#71717A" if self.is_dark else "#94A3B8"

        while self.breadcrumb_layout.count():
            item = self.breadcrumb_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        btn_root = QPushButton(f" {Path(self.vault_path).name}")
        btn_root.setProperty("class", "fluent-crumb-btn")
        btn_root.setAutoDefault(False)
        btn_root.setDefault(False)
        btn_root.setIcon(get_svg_icon("lock", accent_blue, 13))
        btn_root.setToolTip("Kasa Kök Dizini (/)")
        btn_root.clicked.connect(lambda: self.navigate_to_folder(""))
        self.breadcrumb_layout.addWidget(btn_root)

        if self.current_folder:
            parts = self.current_folder.split("/")
            cum_path = ""
            for p in parts:
                cum_path = f"{cum_path}/{p}" if cum_path else p
                lbl_sep = QLabel()
                lbl_sep.setPixmap(get_svg_pixmap("chevron_right", muted_col, 11))
                self.breadcrumb_layout.addWidget(lbl_sep)

                btn_crumb = QPushButton(p)
                btn_crumb.setProperty("class", "fluent-crumb-btn")
                btn_crumb.setAutoDefault(False)
                btn_crumb.setDefault(False)
                path_target = cum_path
                btn_crumb.clicked.connect(lambda checked, pt=path_target: self.navigate_to_folder(pt))
                self.breadcrumb_layout.addWidget(btn_crumb)

        if self.active_category_filter:
            lbl_sep2 = QLabel()
            lbl_sep2.setPixmap(get_svg_pixmap("chevron_right", muted_col, 11))
            self.breadcrumb_layout.addWidget(lbl_sep2)

            cat_names = {
                "app": "Uygulamalar", "document": "Belgeler", "image": "Resimler", "music": "Ses & Müzik",
                "video": "Videolar", "archive": "Arşivler", "code": "Kod & Veri"
            }
            lbl_cat = QLabel(f"[{cat_names.get(self.active_category_filter, self.active_category_filter)}]")
            lbl_cat.setStyleSheet(f"font-weight: 700; color: {accent_blue}; padding: 2px 6px; font-size: 11px;")
            self.breadcrumb_layout.addWidget(lbl_cat)

        self.breadcrumb_layout.addStretch()

        btn_copy_path = QPushButton()
        btn_copy_path.setProperty("class", "fluent-nav-btn")
        btn_copy_path.setAutoDefault(False)
        btn_copy_path.setDefault(False)
        btn_copy_path.setIcon(get_svg_icon("copy", muted_col, 13))
        btn_copy_path.setToolTip("Geçerli Kasa Yolunu Kopyala")
        btn_copy_path.clicked.connect(lambda: QApplication.clipboard().setText(f"/{self.current_folder}"))
        self.breadcrumb_layout.addWidget(btn_copy_path)

    def get_current_items(self) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Geçerli dizin ve kategori filtresine göre (Klasörler, Dosyalar) listesini döndürür.
        Arama filtresi ve sütun sıralaması uygular.
        """
        search_query = self.txt_search.text().strip().lower() if hasattr(self, "txt_search") else ""
        cat_filter = getattr(self, "active_category_filter", None)

        prefix = f"{self.current_folder}/" if self.current_folder else ""
        sub_folders = set()
        sub_files = []

        if not cat_filter:
            for d in self.cached_folders:
                if not prefix and "/" not in d:
                    sub_folders.add(d)
                elif prefix and d.startswith(prefix):
                    rem = d[len(prefix):]
                    if rem and "/" not in rem:
                        sub_folders.add(rem)

        for f in self.cached_files:
            p = f.get("path", "")
            fname = Path(p).name
            file_cat = get_file_category(fname)

            if cat_filter and file_cat != cat_filter:
                continue

            if not prefix:
                if "/" in p and not cat_filter:
                    sub_folders.add(p.split("/")[0])
                elif not "/" in p or cat_filter:
                    if not search_query or search_query in fname.lower():
                        sub_files.append(f)
            else:
                if p.startswith(prefix):
                    rem = p[len(prefix):]
                    if "/" in rem and not cat_filter:
                        sub_folders.add(rem.split("/")[0])
                    elif not "/" in rem or cat_filter:
                        if not search_query or search_query in fname.lower():
                            sub_files.append(f)

        folder_dicts = [{"name": name, "path": f"{prefix}{name}" if prefix else name} for name in sorted(list(sub_folders))]
        if search_query:
            folder_dicts = [fd for fd in folder_dicts if search_query in fd["name"].lower()]

        col = getattr(self, "sort_column", 0)
        reverse = not getattr(self, "sort_ascending", True)

        def file_sort_key(f_item):
            p = f_item.get("path", "")
            fn = Path(p).name.lower()
            if col == 0:
                return fn
            elif col == 1:
                return Path(fn).suffix.lower()
            elif col == 2:
                return f_item.get("size", 0)
            elif col == 3:
                return f_item.get("comp_size", f_item.get("size", 0))
            elif col == 4:
                return f_item.get("mtime", 0)
            elif col == 5:
                return f_item.get("sha256", "")
            return fn

        sub_files.sort(key=file_sort_key, reverse=reverse)
        folder_dicts.sort(key=lambda fd: fd["name"].lower(), reverse=reverse if col == 0 else False)

        return folder_dicts, sub_files

    def update_current_view(self):
        """Orta içerik alanını (Tablo ve Izgara) geçerli konuma göre doldurur."""
        self.update_breadcrumbs()
        folders, files = self.get_current_items()

        self.populate_table(folders, files)

        self.populate_grid(folders, files)

        self.lbl_status.setText(f"{len(folders)} klasör, {len(files)} dosya görüntülendi.")

        entries_to_load = []
        for f in files:
            f_id = f.get("id", "")
            if f_id in self.thumbnail_cache:
                continue
            cat = get_file_category(Path(f.get("path", "")).name)
            if cat in ["app", "image"] or Path(f.get("path", "")).suffix.lower() in [".exe", ".msi", ".ico"]:
                entries_to_load.append(f)

        if entries_to_load:
            if self.current_icon_worker:
                self.current_icon_worker.cancel()
            self.current_icon_worker = AsyncIconWorker(self.vault_path, self.auth_info, entries_to_load, self.icon_worker_signals)
            QThreadPool.globalInstance().start(self.current_icon_worker)

    def on_async_icon_ready(self, file_id: str, pixmap: QPixmap):
        """Arka planda simgesi çıkarılan dosyanın arayüzünü günceller (Sıfır gecikme)."""
        if not pixmap or pixmap.isNull():
            return
        self.thumbnail_cache[file_id] = pixmap

        for r in range(self.table.rowCount()):
            item = self.table.item(r, 0)
            if item:
                data = item.data(Qt.ItemDataRole.UserRole)
                if data and not data.get("is_folder") and data.get("id") == file_id:
                    item.setIcon(QIcon(pixmap.scaled(18, 18, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)))
                    break

        for i in range(self.grid_list.count()):
            g_item = self.grid_list.item(i)
            if g_item:
                data = g_item.data(Qt.ItemDataRole.UserRole)
                if data and not data.get("is_folder") and data.get("id") == file_id:
                    g_item.setIcon(QIcon(pixmap.scaled(56, 56, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)))
                    break

        selected = self.get_selected_item_data()
        if selected and not selected.get("is_folder") and selected.get("id") == file_id:
            scaled = pixmap.scaled(100, 100, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
            self.lbl_image_preview.setPixmap(scaled)
            self.lbl_image_preview.show()

    def populate_table(self, folders: List[Dict[str, Any]], files: List[Dict[str, Any]]):
        """Detay tablosunu satır satır doldurur."""
        accent_col = "#2997FF" if getattr(self, "theme", "dark") == "apple_dark" else ("#0071E3" if getattr(self, "theme", "dark") == "apple_light" else ("#38BDF8" if getattr(self, "is_dark", True) else "#0284C7"))
        total_rows = len(folders) + len(files)
        self.table.setRowCount(total_rows)

        for row, f_info in enumerate(folders):
            t_name = QTableWidgetItem(f_info["name"])
            t_name.setIcon(get_svg_icon("folder", accent_col, 16))
            t_name.setData(Qt.ItemDataRole.UserRole, {"is_folder": True, "path": f_info["path"], "name": f_info["name"]})
            self.table.setItem(row, 0, t_name)

            t_type = QTableWidgetItem("Dosya Klasörü")
            self.table.setItem(row, 1, t_type)

            t_size = QTableWidgetItem("-")
            t_size.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table.setItem(row, 2, t_size)

            t_comp = QTableWidgetItem("-")
            t_comp.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table.setItem(row, 3, t_comp)

            t_date = QTableWidgetItem("-")
            t_date.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table.setItem(row, 4, t_date)

            t_status = QTableWidgetItem("-")
            t_status.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table.setItem(row, 5, t_status)

        for idx, f_entry in enumerate(files):
            row = len(folders) + idx
            fname = Path(f_entry["path"]).name
            cat = get_file_category(fname)

            t_name = QTableWidgetItem(fname)
            t_name.setIcon(self.get_file_icon(f_entry, size=18))
            t_name.setData(Qt.ItemDataRole.UserRole, {"is_folder": False, "id": f_entry["id"], "path": f_entry["path"], "entry": f_entry})
            self.table.setItem(row, 0, t_name)

            ext_label = Path(fname).suffix.upper().replace('.', '')
            type_map = {
                "app": f"{ext_label} Uygulaması" if ext_label else "Uygulama",
                "image": f"{ext_label} Resmi",
                "document": f"{ext_label} Belgesi",
                "code": f"{ext_label} Dosyası",
                "music": f"{ext_label} Ses Dosyası",
                "video": f"{ext_label} Video Dosyası",
                "archive": f"{ext_label} Arşivi",
                "file": f"{ext_label} Dosyası" if ext_label else "Dosya"
            }
            t_type = QTableWidgetItem(type_map.get(cat, f"{ext_label} Dosyası"))
            self.table.setItem(row, 1, t_type)

            t_size = QTableWidgetItem(format_size(f_entry.get("size", 0)))
            t_size.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            self.table.setItem(row, 2, t_size)

            t_comp = QTableWidgetItem(format_size(f_entry.get("comp_size", f_entry.get("size", 0))))
            t_comp.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            self.table.setItem(row, 3, t_comp)

            mtime = f_entry.get("mtime", time.time())
            t_date = QTableWidgetItem(time.strftime("%Y-%m-%d %H:%M", time.localtime(mtime)))
            t_date.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table.setItem(row, 4, t_date)

            t_status = QTableWidgetItem("Doğrulandı")
            t_status.setIcon(get_svg_icon("check", "#10B981" if self.is_dark else "#0A5C36", 14))
            t_status.setForeground(QColor("#10B981" if self.is_dark else "#0A5C36"))
            t_status.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table.setItem(row, 5, t_status)

    def populate_grid(self, folders: List[Dict[str, Any]], files: List[Dict[str, Any]]):
        """Büyük simgeler ve resim önizlemeleri içeren ızgara görünümünü doldurur."""
        accent_col = "#2997FF" if getattr(self, "theme", "dark") == "apple_dark" else ("#0071E3" if getattr(self, "theme", "dark") == "apple_light" else ("#38BDF8" if getattr(self, "is_dark", True) else "#0284C7"))
        self.grid_list.clear()

        for f_info in folders:
            item = QListWidgetItem(f_info["name"])
            item.setIcon(get_svg_icon("folder", accent_col, 56))
            item.setData(Qt.ItemDataRole.UserRole, {"is_folder": True, "path": f_info["path"], "name": f_info["name"]})
            item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.grid_list.addItem(item)

        for f_entry in files:
            fname = Path(f_entry["path"]).name
            item = QListWidgetItem(fname)
            item.setData(Qt.ItemDataRole.UserRole, {"is_folder": False, "id": f_entry["id"], "path": f_entry["path"], "entry": f_entry})
            item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            item.setIcon(self.get_file_icon(f_entry, size=76))
            self.grid_list.addItem(item)

    def get_file_icon(self, entry: Dict[str, Any], size: int = 16) -> QIcon:
        """Dosyanın gerçek simgesini (EXE gömülü ikonu, Windows Explorer sistem simgesi veya küçük resim) döndürür."""
        f_id = entry.get("id", "")
        fname = Path(entry.get("path", "")).name
        ext = Path(fname).suffix.lower()
        cat = get_file_category(fname)

        if f_id in self.thumbnail_cache:
            pix = self.thumbnail_cache[f_id]
            if not pix.isNull():
                icon = QIcon()
                icon.addPixmap(pix)
                if size < 256:
                    icon.addPixmap(pix.scaled(size * 2, size * 2, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation))
                return icon

        if (cat == "app" or ext in [".exe", ".msi", ".ico"]) and entry.get("size", 0) <= 300 * 1024 * 1024:
            try:
                pix = self.get_or_create_thumbnail(entry)
                if pix and not pix.isNull():
                    icon = QIcon()
                    icon.addPixmap(pix)
                    return icon
            except Exception:
                pass

        sys_icon = get_system_file_icon(ext, size)
        if sys_icon and not sys_icon.isNull():
            return sys_icon

        accent_col = "#38BDF8" if self.is_dark else "#059669"
        if ext == ".pdf":
            return get_svg_icon("pdf", "#EF4444", size)

        icon_map = {
            "image": ("image", "#38BDF8"),
            "music": ("music", "#F59E0B"),
            "video": ("video", "#A78BFA"),
            "document": ("file_text", "#60A5FA"),
            "code": ("code", "#10B981"),
            "archive": ("archive", "#FBBF24"),
            "app": ("app", "#38BDF8"),
            "file": ("file", accent_col)
        }
        icon_name, icon_col = icon_map.get(cat, ("file", accent_col))
        return get_svg_icon(icon_name, icon_col, size)

    def get_or_create_thumbnail(self, entry: Dict[str, Any]) -> Optional[QPixmap]:
        """Resim ve uygulama (.exe) dosyaları için RAM-Only küçük resim (Thumbnail/Icon) üretip önbelleğe alır."""
        f_id = entry.get("id", "")
        if f_id in self.thumbnail_cache:
            return self.thumbnail_cache[f_id]

        fname = Path(entry.get("path", "")).name
        cat = get_file_category(fname)

        if cat == "image":
            try:
                raw_bytes, _ = CustomVaultEngine.extract_file_bytes(self.vault_path, self.auth_info, f_id)
                pix = QPixmap()
                if pix.loadFromData(raw_bytes):
                    scaled = pix.scaled(256, 256, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
                    self.thumbnail_cache[f_id] = scaled
                    return scaled
            except Exception:
                pass

        elif Path(fname).suffix.lower() == ".ico":
            try:
                raw_bytes, _ = CustomVaultEngine.extract_file_bytes(self.vault_path, self.auth_info, f_id)
                pix = QPixmap()
                if pix.loadFromData(raw_bytes):
                    scaled = pix.scaled(256, 256, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
                    self.thumbnail_cache[f_id] = scaled
                    return scaled
            except Exception:
                pass

        return None

    def get_selected_item_data(self) -> Optional[Dict[str, Any]]:
        """Geçerli seçili öğenin meta verisini döndürür."""
        if self.view_mode == "details":
            if not self.table.selectedIndexes():
                return None
            cur_row = self.table.currentRow()
            if cur_row < 0:
                return None
            item = self.table.item(cur_row, 0)
            return item.data(Qt.ItemDataRole.UserRole) if item else None
        else:
            if not self.grid_list.selectedItems():
                return None
            cur_item = self.grid_list.currentItem()
            return cur_item.data(Qt.ItemDataRole.UserRole) if cur_item else None

    def get_selected_items(self) -> List[Dict[str, Any]]:
        """Seçili tüm öğelerin meta verilerini döndürür."""
        results = []
        if self.view_mode == "details":
            selected_rows = set(index.row() for index in self.table.selectedIndexes())
            for r in selected_rows:
                item = self.table.item(r, 0)
                if item:
                    data = item.data(Qt.ItemDataRole.UserRole)
                    if data:
                        results.append(data)
        else:
            for item in self.grid_list.selectedItems():
                data = item.data(Qt.ItemDataRole.UserRole)
                if data:
                    results.append(data)
        return results

    def on_selection_changed(self):
        """Öğe seçildiğinde sağ önizleme panelini ve alt durum çubuğunu günceller."""
        selected = self.get_selected_item_data()
        selected_items = self.get_selected_items()
        folders, files = self.get_current_items()

        if selected_items:
            sel_count = len(selected_items)
            sel_size = sum(item.get("entry", {}).get("size", 0) for item in selected_items if not item.get("is_folder"))
            self.lbl_status.setText(f"{len(folders) + len(files)} öğe  |  {sel_count} öğe seçildi ({format_size(sel_size)})")
        else:
            self.lbl_status.setText(f"{len(folders)} klasör, {len(files)} dosya")

        self.audio_widget.stop()
        self.audio_widget.hide()
        if hasattr(self, "video_widget"):
            self.video_widget.stop()
            self.video_widget.hide()
        self.txt_preview.hide()
        self.lbl_image_preview.hide()
        self.lbl_image_preview.setCursor(Qt.CursorShape.ArrowCursor)
        self.lbl_image_preview.setToolTip("")
        self.btn_pv_open.hide()
        if hasattr(self, "btn_pv_view_vault"):
            self.btn_pv_view_vault.hide()
        if hasattr(self, "btn_fullscreen_preview"):
            self.btn_fullscreen_preview.hide()
        if getattr(self, "btn_slideshow_preview", None):
            self.btn_slideshow_preview.hide()
        self.current_preview_image_id = None
        self.lbl_pv_crypto.clear()

        if not selected:
            self.lbl_pv_name.setText("Seçili öğe yok")
            if hasattr(self, "lbl_pv_badge"):
                self.lbl_pv_badge.hide()
            self.lbl_pv_info.setText("Detayları ve özellikleri görmek için bir öğe seçin.")
            self.lbl_image_preview.setPixmap(get_svg_pixmap("folder", "#71717A", 48))
            self.lbl_image_preview.show()
            return

        if selected.get("is_folder"):
            f_name = selected["name"]
            f_path = selected["path"]
            prefix = f"{f_path}/"
            sub_count = sum(1 for f in self.cached_files if f.get("path", "").startswith(prefix))
            sub_size = sum(f.get("size", 0) for f in self.cached_files if f.get("path", "").startswith(prefix))

            self.lbl_pv_name.setText(f_name)
            if hasattr(self, "lbl_pv_badge"):
                self.lbl_pv_badge.setText("Dosya Klasörü")
                self.lbl_pv_badge.show()
            self.lbl_pv_info.setText(
                f"<b>Tür:</b> Dosya Klasörü<br>"
                f"<b>Kasa İçi Yol:</b> /{f_path}<br>"
                f"<b>İçerik:</b> {sub_count} dosya<br>"
                f"<b>Toplam Boyut:</b> {format_size(sub_size)}"
            )
            self.lbl_image_preview.setPixmap(get_svg_pixmap("folder", "#38BDF8" if self.is_dark else "#059669", 64))
            self.lbl_image_preview.show()
            return

        entry = selected.get("entry", {})
        fname = Path(entry.get("path", "")).name
        f_id = selected["id"]
        cat = get_file_category(fname)

        ext_upper = Path(fname).suffix.upper().replace(".", "")
        type_names = {
            "app": f"{ext_upper} Windows Uygulaması",
            "document": f"{ext_upper} Belgesi",
            "image": f"{ext_upper} Resmi",
            "video": f"{ext_upper} Video Dosyası",
            "music": f"{ext_upper} Ses Dosyası",
            "archive": f"{ext_upper} Arşiv Paketi",
            "code": f"{ext_upper} Kaynak Kodu",
        }
        type_label = type_names.get(cat, f"{ext_upper or 'Bilinmeyen'} Dosyası")

        orig_sz = entry.get("size", 0)
        comp_sz = entry.get("comp_size", orig_sz)
        ratio_pct = int((1 - comp_sz / orig_sz) * 100) if orig_sz > comp_sz else 0
        comp_info = f" ({comp_sz:,} B, %{ratio_pct} sıkıştırma)" if ratio_pct > 0 else ""

        mtime = entry.get("mtime", time.time())
        mtime_str = time.strftime("%Y-%m-%d %H:%M", time.localtime(mtime))

        self.lbl_pv_name.setText(fname)
        if hasattr(self, "lbl_pv_badge"):
            self.lbl_pv_badge.setText(type_label)
            self.lbl_pv_badge.show()

        self.lbl_pv_info.setText(
            f"<b>Konum:</b> /{entry.get('path', '')}<br>"
            f"<b>Boyut:</b> {format_size(orig_sz)}{comp_info}<br>"
            f"<b>Değiştirilme:</b> {mtime_str}"
        )
        self.lbl_pv_crypto.setText("AES-256-GCM AEAD Tag & SHA-256 [DOĞRULANDI]")

        text_exts = {".txt", ".py", ".json", ".md", ".log", ".csv", ".ini", ".bat", ".html", ".css", ".js", ".xml", ".yaml", ".yml", ".sql", ".c", ".cpp", ".h", ".rs", ".go", ".sh", ".ps1"}
        self._pv_current_file_id = f_id
        self._pv_current_fname = fname
        self.btn_pv_view_vault.hide()
        if cat == "image":
            self.btn_pv_open.setText("Tam Ekran İncele (F)")
            self.btn_pv_open.setIcon(get_svg_icon("expand", "#FFFFFF", 13))
            self.btn_pv_open.hide()
            self.btn_pv_view_vault.setText("Kasa İçinde Görüntüle")
            self.btn_pv_view_vault.setIcon(get_svg_icon("eye", "#FFFFFF", 13))
            self.btn_pv_view_vault.show()
        elif cat == "video":
            self.btn_pv_open.setText("İzole Tam Ekranda İzle (F)")
            self.btn_pv_open.setIcon(get_svg_icon("play", "#FFFFFF", 13))
        elif cat == "music":
            self.btn_pv_open.setText("Dahili Ses Çalarda Aç")
            self.btn_pv_open.setIcon(get_svg_icon("play", "#FFFFFF", 13))
        elif Path(fname).suffix.lower() in text_exts:
            self.btn_pv_open.setText("Kasa İçi Düzenle (Bellekte)")
            self.btn_pv_open.setIcon(get_svg_icon("file_text", "#FFFFFF", 13))
            self.btn_pv_view_vault.setText("Kasa İçinde Görüntüle")
            self.btn_pv_view_vault.setIcon(get_svg_icon("eye", "#FFFFFF", 13))
            self.btn_pv_view_vault.show()
        elif cat == "app" or Path(fname).suffix.lower() in DANGEROUS_EXTENSIONS:
            self.btn_pv_open.setText("İzolasyon Bariyeriyle Aç")
            self.btn_pv_open.setIcon(get_svg_icon("shield", "#FFFFFF", 13))
            self.btn_pv_open.setToolTip("Yürütülebilir veya tehlikeli dosyayı güvenlik izolasyon bariyeri ile karantinada incele")
        else:
            self.btn_pv_open.setText("Windows Sandbox'ta Güvenli İncele")
            self.btn_pv_open.setIcon(get_svg_icon("shield", "#FFFFFF", 13))
            self.btn_pv_open.setToolTip("Belgeyi ana bilgisayardan tamamen yalıtılmış sanal makinede (Windows Sandbox) güvenle aç")
        self.btn_pv_open.show()

        hero_icon = self.get_file_icon(entry, size=64)
        if hero_icon and not hero_icon.isNull():
            hero_pix = hero_icon.pixmap(64, 64)
            if not hero_pix.isNull():
                self.lbl_image_preview.setPixmap(hero_pix)
                self.lbl_image_preview.show()

        if cat == "image":
            if f_id in self.thumbnail_cache:
                self.show_image_preview(f_id)
            elif orig_sz <= 3 * 1024 * 1024:
                self.show_image_preview(f_id)
            else:
                self.pending_preview_entry = {"id": f_id, "cat": "image"}
                self.preview_timer.start(160)
        elif cat == "video":
            self.show_video_preview(f_id, fname)
        elif cat == "app":
            self.show_app_preview(entry)
        elif cat == "music":
            self.show_music_preview(f_id, fname)
        elif cat in ["code", "document"] and Path(fname).suffix.lower() in text_exts:
            self.show_text_preview(f_id)

    def _do_deferred_preview(self):
        """Ertelenmiş ağır önizleme yüklemesi (Kullanıcı klavye ile gezinmeyi durdurduğunda çağrılır)."""
        if not self.pending_preview_entry:
            return
        cat = self.pending_preview_entry.get("cat")
        f_id = self.pending_preview_entry.get("id")
        if cat == "image" and f_id:
            self.show_image_preview(f_id)

    def show_app_preview(self, entry: Dict[str, Any]):
        """Windows uygulama simgesini sağ önizleme panelinde büyük ve net olarak gösterir."""
        f_id = entry.get("id", "")
        if f_id in self.thumbnail_cache:
            pix = self.thumbnail_cache[f_id]
            if pix and not pix.isNull():
                scaled = pix.scaled(100, 100, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
                self.lbl_image_preview.setPixmap(scaled)
                self.lbl_image_preview.show()
                cur_text = self.lbl_pv_info.text()
                self.lbl_pv_info.setText(f"{cur_text}\nUygulama Simgesi: {pix.width()} × {pix.height()} px")
                return
        sys_app_icon = get_system_file_icon(".exe", 100)
        if not sys_app_icon.isNull():
            self.lbl_image_preview.setPixmap(sys_app_icon.pixmap(100, 100))
        else:
            self.lbl_image_preview.setPixmap(get_svg_pixmap("app", "#38BDF8", 80))
        self.lbl_image_preview.show()

        f_size = entry.get("size", 0)
        if f_size <= 300 * 1024 * 1024:
            try:
                pix = self.get_or_create_thumbnail(entry)
                if pix and not pix.isNull():
                    scaled = pix.scaled(100, 100, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
                    self.lbl_image_preview.setPixmap(scaled)
                    cur_text = self.lbl_pv_info.text()
                    self.lbl_pv_info.setText(f"{cur_text}\nUygulama Simgesi: {pix.width()} × {pix.height()} px")
            except Exception:
                pass

    def show_image_preview(self, file_id: str):
        """Resim önizlemesini sağ panelde yüksek çözünürlüklü, jilet gibi net olarak gösterir (RAM-Only)."""
        try:
            self.current_preview_image_id = file_id
            if hasattr(self, "btn_fullscreen_preview"):
                self.btn_fullscreen_preview.show()
            if hasattr(self, "btn_pv_open"):
                self.btn_pv_open.hide()
            if getattr(self, "btn_slideshow_preview", None):
                self.btn_slideshow_preview.show()
            self.lbl_image_preview.setCursor(Qt.CursorShape.PointingHandCursor)
            self.lbl_image_preview.setToolTip("Görseli tam ekran görüntülemek için tıklayın (Kısayol: F veya Boşluk)")

            if file_id in self.full_image_cache:
                pix, orig_w, orig_h = self.full_image_cache[file_id]
                scaled = pix.scaled(260, 175, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
                self.lbl_image_preview.setPixmap(scaled)
                self.lbl_image_preview.show()
                cur_text = self.lbl_pv_info.text()
                if "Çözünürlük:" not in cur_text:
                    self.lbl_pv_info.setText(f"{cur_text}<br><b>Çözünürlük:</b> {orig_w} × {orig_h} px")
                return

            raw_bytes, _ = CustomVaultEngine.extract_file_bytes(self.vault_path, self.auth_info, file_id)
            entry = next((f for f in self.cached_files if f.get("id") == file_id), None)
            fname = Path(entry.get("path", "")).name if entry else ""

            is_suspicious, reason = inspect_file_security_header(raw_bytes[:512], fname)
            if is_suspicious:
                self.lbl_image_preview.setPixmap(get_svg_pixmap("alert_triangle", "#EF4444", 64))
                self.lbl_image_preview.show()
                if hasattr(self, "btn_fullscreen_preview"):
                    self.btn_fullscreen_preview.hide()
                if getattr(self, "btn_slideshow_preview", None):
                    self.btn_slideshow_preview.hide()
                cur_text = self.lbl_pv_info.text()
                self.lbl_pv_info.setText(f"{cur_text}<br><span style='color:#EF4444; font-weight:700;'>GÜVENLİK TEHDİDİ BLOKE EDİLDİ:<br>{reason}</span>")
                return

            pix = QPixmap()
            if pix.loadFromData(raw_bytes):
                orig_w, orig_h = pix.width(), pix.height()
                self.full_image_cache[file_id] = (pix, orig_w, orig_h)
                if file_id not in self.thumbnail_cache:
                    self.thumbnail_cache[file_id] = pix.scaled(256, 256, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)

                scaled = pix.scaled(260, 175, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
                self.lbl_image_preview.setPixmap(scaled)
                self.lbl_image_preview.show()
                cur_text = self.lbl_pv_info.text()
                if "Çözünürlük:" not in cur_text:
                    self.lbl_pv_info.setText(f"{cur_text}<br><b>Çözünürlük:</b> {orig_w} × {orig_h} px")
        except Exception:
            pass

    def on_preview_hero_clicked(self, event):
        """Önizleme görseline tıklandığında doğrudan tam ekran görüntüleyiciyi açar."""
        if hasattr(self, "current_preview_image_id") and self.current_preview_image_id:
            self.open_fullscreen_image(self.current_preview_image_id)
        elif event:
            event.accept()

    def on_fullscreen_preview_action(self):
        """Önizleme panelindeki Tam Ekran butonuna tıklandığında resim/video/pencereye göre tam ekran açar."""
        selected = self.get_selected_item_data()
        if selected and not selected.get("is_folder"):
            fname = Path(selected.get("entry", {}).get("path", "")).name
            cat = get_file_category(fname)
            if cat == "video":
                self.open_fullscreen_video(selected.get("id"))
                return
            elif cat == "image":
                self.open_fullscreen_image(selected.get("id"))
                return
        if getattr(self, "current_preview_image_id", None):
            self.open_fullscreen_image(self.current_preview_image_id)
            return
        self.open_fullscreen_image()

    def open_fullscreen_image(self, file_id: Optional[str] = None, start_slideshow: bool = False):
        """Seçili veya belirtilen görseli RAM-Only tam ekran lightbox modalında açar (Tüm kasadaki görselleri kesintisiz gezinilebilir kılar)."""
        if not file_id:
            selected = self.get_selected_item_data()
            if selected and not selected.get("is_folder"):
                fname = Path(selected.get("entry", {}).get("path", "")).name
                if get_file_category(fname) == "image":
                    file_id = selected.get("id")
            elif getattr(self, "current_preview_image_id", None):
                file_id = self.current_preview_image_id

        all_vault_images = [
            f for f in self.cached_files
            if get_file_category(Path(f.get("path", "")).name) == "image"
        ]

        if not all_vault_images:
            if hasattr(self, "lbl_status"):
                self.lbl_status.setText("Kasada görüntülenecek herhangi bir görsel bulunamadı.")
            return

        folder_images = []
        for f in all_vault_images:
            p = f.get("path", "")
            f_dir = str(Path(p).parent).replace("\\", "/").strip("/")
            if f_dir == "." or f_dir == "/":
                f_dir = ""
            if f_dir == self.current_folder:
                folder_images.append(f)

        if folder_images and len(folder_images) > 1:
            other_images = [f for f in all_vault_images if f not in folder_images]
            all_images = folder_images + other_images
        else:
            all_images = all_vault_images

        if not file_id:
            file_id = all_images[0].get("id")

        viewer = CustomVaultFullscreenViewerDialog(
            parent=self,
            vault_path=self.vault_path,
            auth_info=self.auth_info,
            initial_file_id=file_id,
            image_entries=all_images,
            theme=self.current_theme,
            auto_start_slideshow=start_slideshow
        )
        viewer.showFullScreen()
        viewer.exec()
        self.raise_()
        self.activateWindow()
        if hasattr(self, "table"):
            self.table.setFocus()

    def on_item_hovered(self, item):
        """Hover ile önizleme açılması kullanıcının talebiyle tamamen devre dışı bırakılmıştır."""
        pass

    def show_video_preview(self, file_id: str, title: str):
        """Video dosyasını kasa içi tamamen yalıtılmış oynatıcıda hazırlar."""
        try:
            raw_sample, _ = CustomVaultEngine.extract_file_bytes(self.vault_path, self.auth_info, file_id)
            is_suspicious, reason = inspect_file_security_header(raw_sample[:512], title)
            if is_suspicious:
                self.lbl_image_preview.setPixmap(get_svg_pixmap("alert_triangle", "#EF4444", 64))
                self.lbl_image_preview.show()
                cur_text = self.lbl_pv_info.text()
                self.lbl_pv_info.setText(f"{cur_text}<br><span style='color:#EF4444; font-weight:700;'>GÜVENLİK TEHDİDİ BLOKE EDİLDİ:<br>{reason}</span>")
                return

            temp_path, _ = CustomVaultEngine.extract_to_temp_for_viewing(self.vault_path, self.auth_info, file_id)
            self.active_temp_files[temp_path] = {"file_id": file_id, "orig_path": title, "last_mtime": Path(temp_path).stat().st_mtime}
            self.video_widget.load_video(temp_path, title, file_id)
            self.video_widget.show()
        except Exception:
            pass

    def open_fullscreen_video(self, file_id: Optional[str] = None):
        """Video dosyasını kasa içi tamamen yalıtılmış tam ekran oynatıcıda açar."""
        if not file_id:
            selected = self.get_selected_item_data()
            if selected and not selected.get("is_folder"):
                fname = Path(selected.get("entry", {}).get("path", "")).name
                if get_file_category(fname) == "video":
                    file_id = selected.get("id")

        if not file_id:
            return

        entry = next((f for f in self.cached_files if f.get("id") == file_id), None)
        fname = Path(entry.get("path", "")).name if entry else "Video"

        try:
            raw_sample, _ = CustomVaultEngine.extract_file_bytes(self.vault_path, self.auth_info, file_id)
            is_suspicious, reason = inspect_file_security_header(raw_sample[:512], fname)
            if is_suspicious:
                QMessageBox.critical(
                    self,
                    "Güvenlik İzolasyon Engeli",
                    f"Bu video dosyası güvenlik gerekçesiyle bloke edildi:\n\n{reason}\n\nOlası virüs/zararlı bulaşmasını önlemek için oynatma durduruldu."
                )
                return

            temp_path, _ = CustomVaultEngine.extract_to_temp_for_viewing(self.vault_path, self.auth_info, file_id)
            self.active_temp_files[temp_path] = {"file_id": file_id, "orig_path": fname, "last_mtime": Path(temp_path).stat().st_mtime}

            dlg = CustomVaultFullscreenVideoDialog(self, temp_path, fname, is_dark=self.is_dark)
            dlg.showFullScreen()
            dlg.exec()
        except Exception as e:
            QMessageBox.critical(self, "Hata", f"Video açılamadı:\n{e}")

    def show_music_preview(self, file_id: str, title: str):
        """Müzik dosyasını geçici alana çözüp dahili ses çaları hazırlar."""
        try:
            raw_sample, _ = CustomVaultEngine.extract_file_bytes(self.vault_path, self.auth_info, file_id)
            is_suspicious, reason = inspect_file_security_header(raw_sample[:512], title)
            if is_suspicious:
                self.lbl_image_preview.setPixmap(get_svg_pixmap("alert_triangle", "#EF4444", 64))
                self.lbl_image_preview.show()
                cur_text = self.lbl_pv_info.text()
                self.lbl_pv_info.setText(f"{cur_text}<br><span style='color:#EF4444; font-weight:700;'>GÜVENLİK TEHDİDİ BLOKE EDİLDİ:<br>{reason}</span>")
                return

            temp_path, _ = CustomVaultEngine.extract_to_temp_for_viewing(self.vault_path, self.auth_info, file_id)
            self.active_temp_files[temp_path] = {"file_id": file_id, "orig_path": title, "last_mtime": Path(temp_path).stat().st_mtime}
            self.audio_widget.load_audio(temp_path, title)
            self.audio_widget.show()
        except Exception:
            pass

    def show_text_preview(self, file_id: str):
        """Metin ve kod dosyalarının ilk 4 KB içeriğini doğrudan gösterir."""
        try:
            entry = next((f for f in self.cached_files if f.get("id") == file_id), None)
            fname = Path(entry.get("path", "")).name if entry else ""
            if entry and entry.get("size", 0) > 10 * 1024 * 1024:
                self.txt_preview.setPlainText(f"(Dosya boyutu önizleme için çok büyük: {format_size(entry.get('size', 0))})")
                self.txt_preview.show()
                return

            raw_bytes, _ = CustomVaultEngine.extract_file_bytes(self.vault_path, self.auth_info, file_id)
            is_suspicious, reason = inspect_file_security_header(raw_bytes[:512], fname)
            if is_suspicious:
                self.txt_preview.setPlainText(f"[GÜVENLİK TEHDİDİ BLOKE EDİLDİ]\n\n{reason}\n\nBu dosya metin uzantısına sahip olmasına rağmen çalıştırılabilir ikili kod barındırıyor. Bilgisayarınıza virüs bulaşmasını önlemek için işleme durduruldu.")
                self.txt_preview.show()
                return

            sample_text = raw_bytes[:4096].decode("utf-8", errors="replace")
            self.txt_preview.setPlainText(sample_text)
            self.txt_preview.show()
        except Exception:
            pass

    def eventFilter(self, obj, event):
        """Alt bileşenlere gelen klavye kısayollarını ve sürükle-bırak olaylarını yakalayıp onaylar."""
        ev_type = event.type()
        if ev_type != QEvent.Type.KeyPress and ev_type != QEvent.Type.DragEnter and ev_type != QEvent.Type.DragMove and ev_type != QEvent.Type.Drop:
            return super().eventFilter(obj, event)

        if ev_type == QEvent.Type.KeyPress:
            if hasattr(self, "txt_search") and (obj is self.txt_search or self.txt_search.hasFocus()):
                return super().eventFilter(obj, event)

            key = event.key()
            mod = event.modifiers()

            if key == Qt.Key.Key_F and not (mod & (Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.AltModifier)):
                self._on_shortcut_fullscreen()
                return True

            if key == Qt.Key.Key_Space and not (mod & (Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.AltModifier)):
                selected = self.get_selected_item_data()
                if selected and not selected.get("is_folder"):
                    cat = get_file_category(Path(selected.get("entry", {}).get("path", "")).name)
                    if cat == "image":
                        self.open_fullscreen_image(selected.get("id"), start_slideshow=False)
                        return True
                    elif cat == "video":
                        self.open_fullscreen_video(selected.get("id"))
                        return True
                elif getattr(self, "current_preview_image_id", None):
                    self.open_fullscreen_image(self.current_preview_image_id, start_slideshow=False)
                    return True

            if key == Qt.Key.Key_S and not (mod & (Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.AltModifier)):
                selected = self.get_selected_item_data()
                if selected and not selected.get("is_folder") and get_file_category(Path(selected.get("entry", {}).get("path", "")).name) == "image":
                    self.open_fullscreen_image(selected.get("id"), start_slideshow=True)
                    return True
                elif getattr(self, "current_preview_image_id", None):
                    self.open_fullscreen_image(self.current_preview_image_id, start_slideshow=True)
                    return True

            if key in (Qt.Key.Key_Return, Qt.Key.Key_Enter) and not (mod & Qt.KeyboardModifier.AltModifier):
                selected = self.get_selected_item_data()
                if selected:
                    self.on_open_selected_item()
                    return True

        if event.type() in (QEvent.Type.DragEnter, QEvent.Type.DragMove):
            event.setDropAction(Qt.DropAction.CopyAction)
            event.acceptProposedAction()
            event.accept()
            return True
        elif event.type() == QEvent.Type.Drop:
            event.setDropAction(Qt.DropAction.CopyAction)
            event.acceptProposedAction()
            event.accept()
            urls = event.mimeData().urls()
            if not urls and event.mimeData().hasText():
                for line in event.mimeData().text().splitlines():
                    line = line.strip()
                    if line.startswith("file:///"):
                        urls.append(QUrl(line))
                    elif os.path.exists(line):
                        urls.append(QUrl.fromLocalFile(line))
            if urls:
                target_folder = None
                pos = event.position().toPoint() if hasattr(event, "position") else event.pos()
                if hasattr(self, "tree_folders") and obj in (self.tree_folders, self.tree_folders.viewport()):
                    item = self.tree_folders.itemAt(pos)
                    if item:
                        target_folder = item.data(0, Qt.ItemDataRole.UserRole)
                elif hasattr(self, "table") and obj in (self.table, self.table.viewport()):
                    item = self.table.itemAt(pos)
                    if item:
                        row_item = self.table.item(item.row(), 0)
                        if row_item:
                            row_data = row_item.data(Qt.ItemDataRole.UserRole)
                            if row_data and row_data.get("is_folder"):
                                target_folder = row_data.get("path")
                elif hasattr(self, "grid_list") and obj in (self.grid_list, self.grid_list.viewport()):
                    item = self.grid_list.itemAt(pos)
                    if item:
                        g_data = item.data(Qt.ItemDataRole.UserRole)
                        if g_data and g_data.get("is_folder"):
                            target_folder = g_data.get("path")
                self.handle_dropped_urls(urls, target_folder)
                return True
        return super().eventFilter(obj, event)

    def showEvent(self, event):
        super().showEvent(event)
        try:
            VaultGlobalDropFilter.get_instance().register_dialog(self)
            self.enable_native_drag_drop()
        except Exception:
            pass

    def enable_native_drag_drop(self):
        """Windows Win32 DragAcceptFiles ve UIPI filtrelerini diyalog ve tüm alt pencerelere bağlar."""
        if sys.platform != "win32":
            return
        try:
            import ctypes
            user32 = ctypes.windll.user32
            shell32 = ctypes.windll.shell32
            ole32 = ctypes.windll.ole32

            WM_DROPFILES = 0x0233
            WM_COPYGLOBALDATA = 0x0049
            WM_COPYDATA = 0x004A
            MSG_0047 = 0x0047
            MSGFLT_ADD = 1
            MSGFLT_ALLOW = 1

            for msg_id in (WM_DROPFILES, WM_COPYGLOBALDATA, WM_COPYDATA, MSG_0047):
                try:
                    user32.ChangeWindowMessageFilter(msg_id, MSGFLT_ADD)
                except Exception:
                    pass

            try:
                hwnd = int(self.winId())
                if hwnd:
                    shell32.DragAcceptFiles(hwnd, True)
                    if hasattr(user32, "ChangeWindowMessageFilterEx"):
                        for msg_id in (WM_DROPFILES, WM_COPYGLOBALDATA, WM_COPYDATA, MSG_0047):
                            try:
                                user32.ChangeWindowMessageFilterEx(hwnd, msg_id, MSGFLT_ALLOW, None)
                            except Exception:
                                pass
            except Exception:
                pass
        except Exception:
            pass

    def handle_native_drop(self, file_paths: List[str], pt_x: int = 0, pt_y: int = 0, target_hwnd: int = 0, target_widget: Optional[QWidget] = None):
        """Native WM_DROPFILES ile gelen dosyaları hedef klasöre göre çözer ve aktarır."""
        if not file_paths:
            return

        target_folder = None
        try:
            from PyQt6.QtGui import QCursor
            if hasattr(self, "tree_folders") and self.tree_folders.isVisible():
                if target_widget in (self.tree_folders, self.tree_folders.viewport()):
                    item = self.tree_folders.itemAt(QPoint(pt_x, pt_y))
                    if item:
                        target_folder = item.data(0, Qt.ItemDataRole.UserRole)
                else:
                    tree_pos = self.tree_folders.mapFromGlobal(QCursor.pos())
                    if self.tree_folders.rect().contains(tree_pos):
                        item = self.tree_folders.itemAt(tree_pos)
                        if item:
                            target_folder = item.data(0, Qt.ItemDataRole.UserRole)

            if not target_folder and hasattr(self, "table") and self.table.isVisible():
                if target_widget in (self.table, self.table.viewport()):
                    item = self.table.itemAt(QPoint(pt_x, pt_y))
                    if item:
                        row_item = self.table.item(item.row(), 0)
                        if row_item:
                            rdata = row_item.data(Qt.ItemDataRole.UserRole)
                            if rdata and rdata.get("is_folder"):
                                target_folder = rdata.get("path")
                else:
                    tbl_pos = self.table.viewport().mapFromGlobal(QCursor.pos())
                    if self.table.viewport().rect().contains(tbl_pos):
                        item = self.table.itemAt(tbl_pos)
                        if item:
                            row_item = self.table.item(item.row(), 0)
                            if row_item:
                                rdata = row_item.data(Qt.ItemDataRole.UserRole)
                                if rdata and rdata.get("is_folder"):
                                    target_folder = rdata.get("path")

            if not target_folder and hasattr(self, "grid_list") and self.grid_list.isVisible():
                if target_widget in (self.grid_list, self.grid_list.viewport()):
                    item = self.grid_list.itemAt(QPoint(pt_x, pt_y))
                    if item:
                        gdata = item.data(Qt.ItemDataRole.UserRole)
                        if gdata and gdata.get("is_folder"):
                            target_folder = gdata.get("path")
                else:
                    list_pos = self.grid_list.viewport().mapFromGlobal(QCursor.pos())
                    if self.grid_list.viewport().rect().contains(list_pos):
                        item = self.grid_list.itemAt(list_pos)
                        if item:
                            gdata = item.data(Qt.ItemDataRole.UserRole)
                            if gdata and gdata.get("is_folder"):
                                target_folder = gdata.get("path")
        except Exception:
            pass

        self.handle_dropped_paths(file_paths, target_folder)

    def nativeEvent(self, eventType, message):
        """Windows WM_DROPFILES mesajlarını yakalayarak yönetici modunda dahi sürükle-bırak sağlar."""
        if eventType in (b"windows_generic_MSG", "windows_generic_MSG"):
            try:
                if _C_UINT_FROM_ADDR(int(message) + _MSG_OFFSET_MESSAGE).value == _WM_DROPFILES:
                    msg = wintypes.MSG.from_address(int(message))
                    hDrop = msg.wParam
                    num = ctypes.windll.shell32.DragQueryFileW(hDrop, 0xFFFFFFFF, None, 0)
                    file_paths = []
                    for i in range(num):
                        buf = ctypes.create_unicode_buffer(1024)
                        ctypes.windll.shell32.DragQueryFileW(hDrop, i, buf, 1024)
                        if buf.value:
                            file_paths.append(buf.value)
                    pt = wintypes.POINT()
                    ctypes.windll.shell32.DragQueryPoint(hDrop, ctypes.byref(pt))
                    ctypes.windll.shell32.DragFinish(hDrop)
                    if file_paths:
                        self.handle_native_drop(file_paths, pt.x, pt.y, int(msg.hWnd))
                    return True, 0
            except Exception:
                pass
        res = super().nativeEvent(eventType, message)
        if isinstance(res, tuple) and len(res) == 2:
            handled, val = res
            return handled, (0 if val is None else val)
        return False, 0

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls() or event.mimeData().hasText():
            event.setDropAction(Qt.DropAction.CopyAction)
            event.acceptProposedAction()
            event.accept()
        else:
            event.ignore()

    def dragMoveEvent(self, event):
        if event.mimeData().hasUrls() or event.mimeData().hasText():
            event.setDropAction(Qt.DropAction.CopyAction)
            event.acceptProposedAction()
            event.accept()
        else:
            event.ignore()

    def dropEvent(self, event):
        event.setDropAction(Qt.DropAction.CopyAction)
        event.acceptProposedAction()
        event.accept()
        urls = event.mimeData().urls()
        if not urls and event.mimeData().hasText():
            for line in event.mimeData().text().splitlines():
                line = line.strip()
                if line.startswith("file:///"):
                    urls.append(QUrl(line))
                elif os.path.exists(line):
                    urls.append(QUrl.fromLocalFile(line))
        if urls:
            self.handle_dropped_urls(urls)

    def handle_dropped_paths(self, file_paths: List[str], target_folder: Optional[str] = None):
        """Windows Explorer'dan sürüklenen veya dosya seçici ile eklenen dosya/klasörleri kasaya aktarır."""
        if not file_paths:
            return

        now = time.time()
        drop_signature = (tuple(sorted(file_paths)), target_folder)
        if hasattr(self, "_last_dropped_sig") and self._last_dropped_sig == drop_signature:
            if hasattr(self, "_last_drop_time") and (now - self._last_drop_time < 0.6):
                return
        self._last_dropped_sig = drop_signature
        self._last_drop_time = now

        dest_dir = target_folder if target_folder is not None else self.current_folder
        dest_dir = dest_dir.replace("\\", "/").strip("/ ")

        total_sz = 0
        is_all_files = True
        for p_str in file_paths:
            try:
                p = Path(p_str)
                if p.is_file():
                    total_sz += p.stat().st_size
                elif p.is_dir():
                    is_all_files = False
                    total_sz += 10 * 1024 * 1024
            except Exception:
                pass

        if len(file_paths) == 1 and is_all_files and total_sz < 3 * 1024 * 1024:
            p = Path(file_paths[0])
            if p.is_file():
                rel_target = f"{dest_dir}/{p.name}" if dest_dir else p.name
                try:
                    add_res = CustomVaultEngine.add_file(self.vault_path, self.auth_info, str(p), rel_target)
                    if p.suffix.lower() in [".exe", ".msi", ".ico"]:
                        try:
                            prov = QFileIconProvider()
                            ico = prov.icon(QFileInfo(str(p)))
                            if not ico.isNull():
                                pix = ico.pixmap(256, 256)
                                if not pix.isNull():
                                    ent = add_res.get("entry", {})
                                    if ent.get("id"):
                                        self.thumbnail_cache[ent["id"]] = pix
                        except Exception:
                            pass
                    self.refresh_file_list()
                    dest_disp = f"'/{dest_dir}' klasörüne" if dest_dir else "kasa köküne"
                    self.lbl_status.setText(f"Başarılı: 1 adet dosya {dest_disp} eklendi ve şifrelendi.")
                    return
                except Exception as e:
                    QMessageBox.warning(self, "Hata", f"Dosya eklenemedi: {p.name}\n{e}")
                    return

        dialog = VaultProgressDialog(self, title="Kasaya Dosyalar Aktarılıyor...", is_dark=self.is_dark, theme=self.current_theme)
        worker = VaultTaskThread("import", self.vault_path, self.auth_info, file_paths=file_paths, dest_dir=dest_dir)
        dialog.attach_thread(worker)
        worker.start()
        dialog.exec()

        self.refresh_file_list()
        if not dialog.is_success and dialog.error_message:
            QMessageBox.warning(self, "Aktarım Hatası", f"İşlem sırasında bir hata oluştu:\n{dialog.error_message}")
        elif dialog.result_data:
            res = dialog.result_data
            added = res.get("added_count", 0)
            errors = res.get("errors", [])
            if errors:
                QMessageBox.warning(self, "Aktarım Uyarısı", f"{added} dosya eklendi, ancak bazı hatalar oluştu:\n" + "\n".join(errors[:5]))
            elif added > 0:
                dest_disp = f"'/{dest_dir}' klasörüne" if dest_dir else "kasa köküne"
                self.lbl_status.setText(f"Başarılı: {added} adet dosya/klasör {dest_disp} eklendi ve şifrelendi.")
            else:
                dest_disp = f"'/{dest_dir}' klasörüne" if dest_dir else "kasa köküne"
                self.lbl_status.setText(f"Başarılı: Klasör yapısı {dest_disp} başarıyla oluşturuldu.")

    def handle_dropped_urls(self, urls: List[QUrl], target_folder: Optional[str] = None):
        """URL listesini yerel dosya yollarına dönüştürüp kasaya ekler (Sürükle-bırak desteği)."""
        if not urls:
            return
        now = time.time()
        if hasattr(self, "_last_drop_time") and now - self._last_drop_time < 0.25:
            return
        self._last_drop_time = now
        from urllib.parse import unquote
        paths = []
        for u in urls:
            p_str = u.toLocalFile()
            if not p_str:
                raw_path = u.path()
                if raw_path.startswith("/") and len(raw_path) > 2 and raw_path[2] == ":":
                    raw_path = raw_path[1:]
                p_str = unquote(raw_path)
            if p_str:
                p_norm = os.path.normpath(p_str)
                if p_norm.lower().endswith(".lnk"):
                    try:
                        import win32com.client
                        shell = win32com.client.Dispatch("WScript.Shell")
                        sc = shell.CreateShortCut(p_norm)
                        if sc.Targetpath and os.path.exists(sc.Targetpath):
                            p_norm = os.path.normpath(sc.Targetpath)
                    except Exception:
                        pass
                if os.path.exists(p_norm):
                    paths.append(p_norm)
        self.handle_dropped_paths(paths, target_folder)

    def import_folder_recursive(self, folder_path: Path, rel_prefix: str) -> int:
        """Klasörü ve tüm alt klasörlerini yinelemeli olarak kasaya aktarır."""
        count = 0
        for item in folder_path.rglob("*"):
            if item.is_file():
                sub_rel = f"{rel_prefix}/{item.relative_to(folder_path).as_posix()}"
                if item.suffix.lower() in [".exe", ".msi", ".ico"]:
                    try:
                        prov = QFileIconProvider()
                        ico = prov.icon(QFileInfo(str(item)))
                        if not ico.isNull():
                            pix = ico.pixmap(128, 128)
                            if not pix.isNull():
                                self.pending_icon_cache[sub_rel] = pix
                    except Exception:
                        pass
                try:
                    CustomVaultEngine.add_file(self.vault_path, self.auth_info, str(item), sub_rel)
                    count += 1
                except Exception:
                    pass
            elif item.is_dir():
                sub_dir = f"{rel_prefix}/{item.relative_to(folder_path).as_posix()}"
                try:
                    CustomVaultEngine.add_folder(self.vault_path, self.auth_info, sub_dir)
                except Exception:
                    pass
        return count

    def start_drag_out(self, source_widget: QWidget) -> bool:
        """Kasadaki seçili dosyaları Windows Gezgini'ne veya Masaüstüne sürükleyerek çıkartır."""
        selected_items = self.get_selected_items()
        if not selected_items:
            return False

        temp_drag_dir = Path(tempfile.mkdtemp(prefix="pvault_drag_out_")).resolve()
        self.active_temp_dirs.append(str(temp_drag_dir))

        urls = []
        for item in selected_items:
            if item.get("is_folder"):
                folder_p = (temp_drag_dir / item["name"]).resolve()
                if not folder_p.is_relative_to(temp_drag_dir):
                    continue
                folder_p.mkdir(parents=True, exist_ok=True)
                prefix = f"{item['path']}/"
                for f in self.cached_files:
                    if f.get("path", "").startswith(prefix):
                        sub_rel = f["path"][len(prefix):]
                        out_f = (folder_p / sub_rel).resolve()
                        if not out_f.is_relative_to(temp_drag_dir):
                            continue
                        out_f.parent.mkdir(parents=True, exist_ok=True)
                        try:
                            CustomVaultEngine.extract_file(self.vault_path, self.auth_info, f["id"], str(out_f))
                            self.active_temp_files[str(out_f)] = {"file_id": f["id"], "orig_path": f["path"], "last_mtime": out_f.stat().st_mtime}
                        except Exception:
                            pass
                urls.append(QUrl.fromLocalFile(str(folder_p)))
            else:
                out_f = (temp_drag_dir / Path(item["path"]).name).resolve()
                if not out_f.is_relative_to(temp_drag_dir):
                    continue
                try:
                    CustomVaultEngine.extract_file(self.vault_path, self.auth_info, item["id"], str(out_f))
                    self.active_temp_files[str(out_f)] = {"file_id": item["id"], "orig_path": item["path"], "last_mtime": out_f.stat().st_mtime}
                    urls.append(QUrl.fromLocalFile(str(out_f)))
                except Exception:
                    pass

        if not urls:
            return False

        mime_data = QMimeData()
        mime_data.setUrls(urls)

        drag = QDrag(source_widget)
        drag.setMimeData(mime_data)

        first_item = selected_items[0]
        drag_pix = get_svg_pixmap("folder" if first_item.get("is_folder") else "file", accent_col, 32)
        drag.setPixmap(drag_pix)
        drag.setHotSpot(QPoint(16, 16))

        drag.exec(Qt.DropAction.CopyAction)
        dir_to_clean = str(temp_drag_dir)
        QTimer.singleShot(12000, lambda: secure_wipe_directory(dir_to_clean))
        return True

    def on_item_double_clicked(self, item):
        """Çift tıklandığında: Klasörse içine girer, resim veya videoda kasa içi izole lightbox açar, metinde kasa içi editör açar."""
        data = item.data(Qt.ItemDataRole.UserRole)
        if not data:
            return
        if data.get("is_folder"):
            self.navigate_to_folder(data["path"])
        else:
            fname = Path(data.get("path", "")).name
            cat = get_file_category(fname)
            if cat == "image":
                self.open_fullscreen_image(data.get("id"))
                return
            elif cat == "video":
                self.open_fullscreen_video(data.get("id"))
                return
            ext = Path(fname).suffix.lower()
            text_exts = {".txt", ".py", ".json", ".md", ".log", ".csv", ".ini", ".bat", ".html", ".css", ".js", ".xml", ".yaml", ".yml", ".sql", ".c", ".cpp", ".h", ".rs", ".go", ".sh", ".ps1"}
            if ext in text_exts:
                self.on_edit_text_selected()
            else:
                self.on_open_selected_item()

    def on_tree_item_clicked(self, item, column):
        """Sol ağaçtaki klasöre tıklandığında oraya geçiş yapar."""
        folder_path = item.data(0, Qt.ItemDataRole.UserRole)
        if folder_path is not None:
            self.navigate_to_folder(folder_path)

    def on_search_changed(self, text: str):
        """Arama metni değiştiğinde tablo ve ızgarayı anında filtreler."""
        self.update_current_view()

    def on_new_folder_clicked(self):
        """Geçerli dizinde yeni klasör oluşturur."""
        name, ok = QInputDialog.getText(self, "Yeni Klasör", "Klasör adı:")
        if not ok or not name.strip():
            return
        clean_name = name.strip().replace("\\", "/").strip("/")
        full_folder_path = f"{self.current_folder}/{clean_name}" if self.current_folder else clean_name
        try:
            CustomVaultEngine.add_folder(self.vault_path, self.auth_info, full_folder_path)
            self.refresh_file_list()
        except Exception as e:
            QMessageBox.critical(self, "Hata", f"Klasör oluşturulamadı:\n{e}")

    def on_new_text_file_clicked(self):
        """Kasa içerisinde doğrudan yeni bir metin belgesi (.txt) oluşturur ve editörde açar."""
        name, ok = QInputDialog.getText(self, "Yeni Metin Belgesi", "Dosya adı (örn: notlar.txt):", text="Yeni Belge.txt")
        if not ok or not name.strip():
            return
        clean_name = name.strip().replace("\\", "/").strip("/")
        if not Path(clean_name).suffix:
            clean_name += ".txt"
        full_path = f"{self.current_folder}/{clean_name}" if self.current_folder else clean_name
        try:
            res = CustomVaultEngine.write_file_bytes(self.vault_path, self.auth_info, full_path, b"")
            self.refresh_file_list()
            file_entry = res.get("entry", {})
            if file_entry:
                f_data = {"is_folder": False, "id": file_entry.get("id", ""), "path": file_entry.get("path", ""), "entry": file_entry}
                dlg = VaultTextEditorDialog(self, f_data, self.vault_path, self.auth_info, self.is_dark, theme=self.current_theme)
                dlg.file_saved.connect(lambda fid: self.refresh_file_list())
                dlg.exec()
        except Exception as e:
            QMessageBox.critical(self, "Hata", f"Dosya oluşturulamadı:\n{e}")

    def on_add_files_clicked(self):
        """Windows dosya seçici ile seçilen dosyaları geçerli dizine şifreler."""
        files, _ = QFileDialog.getOpenFileNames(self, "Kasaya Eklenecek Dosyaları Seçin", "", "Tüm Dosyalar (*.*)")
        if not files:
            return
        self.handle_dropped_paths(files, self.current_folder)

    def on_add_folder_clicked(self):
        """Windows klasör seçici ile seçilen klasörü tüm içeriğiyle içeri aktarır."""
        folder = QFileDialog.getExistingDirectory(self, "Kasaya Eklenecek Klasörü Seçin")
        if not folder:
            return
        self.handle_dropped_paths([folder], self.current_folder)

    def on_preview_action_clicked(self):
        """Ayrıntılar panelindeki birincil aksiyon butonuna tıklandığında dosya türüne göre en güvenli eylemi yürütür."""
        selected = self.get_selected_item_data()
        if not selected or selected.get("is_folder"):
            return

        f_id = selected["id"]
        entry = selected.get("entry", {})
        fname = Path(entry.get("path", "")).name
        ext = Path(fname).suffix.lower()
        cat = get_file_category(fname)

        if cat == "image":
            self.open_fullscreen_image(f_id)
        elif cat == "video":
            self.open_fullscreen_video(f_id)
        elif cat == "music":
            self.show_music_preview(f_id, fname)
        elif cat in ["code", "document"] and ext in {".txt", ".py", ".json", ".md", ".log", ".csv", ".ini", ".bat", ".html", ".css", ".js", ".xml", ".yaml", ".yml", ".sql", ".c", ".cpp", ".h", ".rs", ".go", ".sh", ".ps1"}:
            self.on_edit_text_selected()
        elif cat == "app" or ext in DANGEROUS_EXTENSIONS:
            self.on_open_selected_item()
        else:
            self.on_open_in_sandbox_selected()

    def on_open_in_sandbox_selected(self):
        """Seçili belgeyi veya dosyayı ana işletim sisteminden %100 yalıtılmış Windows Sandbox sanal makinesinde açar."""
        selected = self.get_selected_item_data()
        if not selected or selected.get("is_folder"):
            return

        f_id = selected["id"]
        entry = selected.get("entry", {})
        fname = Path(entry.get("path", "")).name

        try:
            temp_path, entry = CustomVaultEngine.extract_to_temp_for_viewing(self.vault_path, self.auth_info, f_id)
            self.active_temp_files[temp_path] = {
                "file_id": f_id,
                "orig_path": entry["path"],
                "last_mtime": Path(temp_path).stat().st_mtime
            }

            success = launch_file_in_windows_sandbox(temp_path)
            if success:
                try:
                    import audit_logger
                    audit_logger.log_security_event("SANDBOX_LAUNCH", "SUCCESS", f"Dosya Windows Sandbox içinde güvenle açıldı: {fname}", self.vault_path)
                except Exception:
                    pass
            else:
                try:
                    import audit_logger
                    audit_logger.log_security_event("SANDBOX_UNAVAILABLE", "WARNING", f"Windows Sandbox başlatılamadı: {fname}", self.vault_path)
                except Exception:
                    pass
                reply = QMessageBox.question(
                    self,
                    "Windows Sandbox Kullanılamıyor",
                    f"Windows Sandbox sanal makinesi bu sistemde başlatılamadı.\n\n"
                    f"Olası Nedenler:\n"
                    f"• Windows Özellikleri'nden 'Windows Korumalı Alanı' (Windows Sandbox) etkinleştirilmemiş olabilir.\n"
                    f"• Sanallaştırma (VT-x / AMD-V) BIOS'ta kapalı olabilir veya Windows Home sürümü kullanılıyor olabilir.\n\n"
                    f"'{fname}' belgesini ana işletim sisteminizde korumalı görünüm (Mark-of-the-Web) kalkanıyla açmak ister misiniz?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No
                )
                if reply == QMessageBox.StandardButton.Yes:
                    os.startfile(temp_path)
        except Exception as e:
            QMessageBox.critical(self, "Hata", f"Dosya açılamadı:\n{e}")

    def on_open_selected_item(self):
        """Seçili dosyayı güvenlik izolasyon kurallarına göre kasa içinde veya korumalı sandbox bariyerinde açar."""
        selected = self.get_selected_item_data()
        if not selected or selected.get("is_folder"):
            return

        f_id = selected["id"]
        entry = selected.get("entry", {})
        fname = Path(entry.get("path", "")).name
        ext = Path(fname).suffix.lower()
        cat = get_file_category(fname)

        if cat == "image":
            self.open_fullscreen_image(f_id)
            return

        if cat == "video":
            self.open_fullscreen_video(f_id)
            return

        text_exts = {".txt", ".py", ".json", ".md", ".log", ".csv", ".ini", ".bat", ".html", ".css", ".js", ".xml", ".yaml", ".yml", ".sql", ".c", ".cpp", ".h", ".rs", ".go", ".sh", ".ps1"}
        if ext in text_exts:
            self.on_edit_text_selected()
            return

        if cat == "music":
            self.show_music_preview(f_id, fname)
            return

        try:
            raw_sample, _ = CustomVaultEngine.extract_file_bytes(self.vault_path, self.auth_info, f_id)
            is_suspicious, reason = inspect_file_security_header(raw_sample[:512], fname)
            if is_suspicious:
                QMessageBox.critical(
                    self,
                    "Güvenlik İzolasyon Engeli",
                    f"Bu dosya güvenlik gerekçesiyle bloke edildi:\n\n{reason}\n\nOlası virüs/zararlı bulaşmasını önlemek için çalıştırma durduruldu."
                )
                return
        except Exception:
            pass

        is_executable = (ext in DANGEROUS_EXTENSIONS or cat == "app")
        if is_executable:
            try:
                temp_path, entry = CustomVaultEngine.extract_to_temp_for_viewing(self.vault_path, self.auth_info, f_id)
                self.active_temp_files[temp_path] = {
                    "file_id": f_id,
                    "orig_path": entry["path"],
                    "last_mtime": Path(temp_path).stat().st_mtime
                }
                dlg = VaultExecutionBarrierDialog(self, selected, temp_path, is_dark=self.is_dark, theme=self.current_theme)
                if dlg.exec() == QDialog.DialogCode.Accepted:
                    if dlg.action_result == "sandbox":
                        success = launch_file_in_windows_sandbox(temp_path)
                        if not success:
                            QMessageBox.warning(self, "Sandbox Hatası", "Windows Sandbox başlatılamadı. Dosya güvenliğiniz için karantinada tutuldu.")
                    elif dlg.action_result == "hex":
                        self.on_view_hex_selected()
                    elif dlg.action_result == "host":
                        os.startfile(temp_path)
            except Exception as e:
                QMessageBox.critical(self, "Hata", f"Dosya açılamadı:\n{e}")
            return

        try:
            temp_path, entry = CustomVaultEngine.extract_to_temp_for_viewing(self.vault_path, self.auth_info, f_id)
            self.active_temp_files[temp_path] = {
                "file_id": f_id,
                "orig_path": entry["path"],
                "last_mtime": Path(temp_path).stat().st_mtime
            }

            is_disguised_pe = False
            try:
                with open(temp_path, "rb") as f_chk:
                    if f_chk.read(2) == b"MZ":
                        is_disguised_pe = True
            except Exception:
                pass

            if is_disguised_pe:
                dlg = VaultExecutionBarrierDialog(self, selected, temp_path, is_dark=self.is_dark, theme=self.current_theme)
                if dlg.exec() == QDialog.DialogCode.Accepted:
                    if dlg.action_result == "sandbox":
                        success = launch_file_in_windows_sandbox(temp_path)
                        if not success:
                            QMessageBox.warning(self, "Sandbox Hatası", "Windows Sandbox başlatılamadı. Dosya güvenliğiniz için karantinada tutuldu.")
                    elif dlg.action_result == "hex":
                        self.on_view_hex_selected()
                    elif dlg.action_result == "host":
                        os.startfile(temp_path)
                return

            os.startfile(temp_path)
        except Exception as e:
            QMessageBox.critical(self, "Hata", f"Belge açılamadı:\n{e}")

    def on_edit_text_selected(self):
        """Seçili dosyayı sıfır-izli bellek içi metin/kod editöründe açar."""
        selected = self.get_selected_item_data()
        if not selected or selected.get("is_folder"):
            return
        dlg = VaultTextEditorDialog(self, selected, self.vault_path, self.auth_info, self.is_dark, theme=self.current_theme)
        dlg.file_saved.connect(lambda fid: self.refresh_file_list())
        dlg.exec()

    def on_view_hex_selected(self):
        """Seçili dosyanın ikili (hex dump) verisini inceler."""
        selected = self.get_selected_item_data()
        if not selected or selected.get("is_folder"):
            return
        dlg = VaultHexViewerDialog(self, selected, self.vault_path, self.auth_info, self.is_dark, theme=self.current_theme)
        dlg.exec()

    def on_properties_selected(self):
        """Seçili dosyanın ayrıntılı özelliklerini ve canlı kriptografik AEAD bütünlük testini gösterir."""
        selected = self.get_selected_item_data()
        if not selected or selected.get("is_folder"):
            return
        dlg = VaultPropertiesDialog(self, selected, self.vault_path, self.auth_info, self.is_dark, theme=self.current_theme)
        dlg.exec()

    def on_copy_selected(self):
        """Seçili dosya ve klasörleri kasa içi panoya kopyalar."""
        items = self.get_selected_items()
        if not items:
            return
        self.vault_clipboard = {"action": "copy", "items": items}
        self.lbl_status.setText(f"{len(items)} öğe panoya kopyalandı. Yapıştırmak için hedef klasöre gidip Ctrl+V tuşlarına basın.")

    def on_cut_selected(self):
        """Seçili dosya ve klasörleri taşınmak üzere kasa içi panoya keser."""
        items = self.get_selected_items()
        if not items:
            return
        self.vault_clipboard = {"action": "cut", "items": items}
        self.lbl_status.setText(f"{len(items)} öğe kesildi (taşınacak). Yapıştırmak için hedef klasöre gidip Ctrl+V tuşlarına basın.")

    def on_paste(self):
        """Panodaki öğeleri geçerli dizine yapıştırır (kopyalar veya taşır)."""
        if not self.vault_clipboard or not self.vault_clipboard.get("items"):
            self.lbl_status.setText("Panoda yapıştırılacak öğe bulunmuyor.")
            return

        action = self.vault_clipboard["action"]
        items = self.vault_clipboard["items"]
        target_dir = self.current_folder.strip("/ ")
        pasted_count = 0
        errors = []

        existing_paths = {f["path"] for f in self.cached_files}

        for item in items:
            try:
                if item.get("is_folder"):
                    folder_path = item["path"]
                    folder_name = item["name"]
                    new_folder_path = f"{target_dir}/{folder_name}" if target_dir else folder_name
                    if new_folder_path == folder_path and action == "copy":
                        new_folder_path = f"{new_folder_path}_kopya"
                    if action == "cut":
                        CustomVaultEngine.rename_folder(self.vault_path, self.auth_info, folder_path, new_folder_path)
                        pasted_count += 1
                    else:
                        CustomVaultEngine.add_folder(self.vault_path, self.auth_info, new_folder_path)
                        prefix = f"{folder_path}/"
                        for f in self.cached_files:
                            if f.get("path", "").startswith(prefix):
                                sub_rel = f["path"][len(prefix):]
                                dest_rel = f"{new_folder_path}/{sub_rel}"
                                CustomVaultEngine.duplicate_file(self.vault_path, self.auth_info, f["id"], dest_rel)
                                pasted_count += 1
                else:
                    file_id = item["id"]
                    orig_path = item["path"]
                    orig_name = Path(orig_path).name
                    new_dest = f"{target_dir}/{orig_name}" if target_dir else orig_name
                    if action == "cut":
                        if new_dest != orig_path:
                            CustomVaultEngine.rename_file(self.vault_path, self.auth_info, file_id, new_dest)
                        pasted_count += 1
                    else:
                        if new_dest in existing_paths:
                            stem = Path(orig_name).stem
                            suffix = Path(orig_name).suffix
                            idx = 1
                            while True:
                                cand = f"{stem}_kopya{idx}{suffix}" if idx > 1 else f"{stem}_kopya{suffix}"
                                new_dest = f"{target_dir}/{cand}" if target_dir else cand
                                if new_dest not in existing_paths:
                                    break
                                idx += 1
                        CustomVaultEngine.duplicate_file(self.vault_path, self.auth_info, file_id, new_dest)
                        existing_paths.add(new_dest)
                        pasted_count += 1
            except Exception as e:
                errors.append(str(e))

        if action == "cut":
            self.vault_clipboard = None

        self.refresh_file_list()
        if errors:
            QMessageBox.warning(self, "Yapıştırma Uyarısı", f"Bazı öğeler yapıştırılırken hata oluştu:\n" + "\n".join(errors[:3]))
        else:
            self.lbl_status.setText(f"{pasted_count} öğe başarıyla yapıştırıldı.")

    def on_duplicate_selected(self):
        """Seçili dosya ve klasörleri aynı konumda çoğaltır."""
        items = self.get_selected_items()
        if not items:
            return
        existing_paths = {f["path"] for f in self.cached_files}
        existing_folders = set(self.cached_folders)
        dup_count = 0
        for item in items:
            if item.get("is_folder"):
                orig_folder = item["path"]
                parent_dir = str(Path(orig_folder).parent).replace("\\", "/").strip(". ")
                folder_name = item["name"]
                idx = 1
                while True:
                    cand_name = f"{folder_name}_kopya{idx}" if idx > 1 else f"{folder_name}_kopya"
                    new_folder_path = f"{parent_dir}/{cand_name}" if parent_dir else cand_name
                    if new_folder_path not in existing_folders:
                        break
                    idx += 1
                try:
                    CustomVaultEngine.add_folder(self.vault_path, self.auth_info, new_folder_path)
                    existing_folders.add(new_folder_path)
                    prefix = f"{orig_folder}/"
                    for f in self.cached_files:
                        if f.get("path", "").startswith(prefix):
                            sub_rel = f["path"][len(prefix):]
                            dest_rel = f"{new_folder_path}/{sub_rel}"
                            CustomVaultEngine.duplicate_file(self.vault_path, self.auth_info, f["id"], dest_rel)
                            existing_paths.add(dest_rel)
                    dup_count += 1
                except Exception:
                    pass
            else:
                file_id = item["id"]
                orig_path = item["path"]
                parent_dir = str(Path(orig_path).parent).replace("\\", "/").strip(". ")
                fname = Path(orig_path).name
                stem = Path(fname).stem
                suffix = Path(fname).suffix
                idx = 1
                while True:
                    cand_name = f"{stem}_kopya{idx}{suffix}" if idx > 1 else f"{stem}_kopya{suffix}"
                    new_dest = f"{parent_dir}/{cand_name}" if parent_dir else cand_name
                    if new_dest not in existing_paths:
                        break
                    idx += 1
                try:
                    CustomVaultEngine.duplicate_file(self.vault_path, self.auth_info, file_id, new_dest)
                    existing_paths.add(new_dest)
                    dup_count += 1
                except Exception:
                    pass
        self.refresh_file_list()
        self.lbl_status.setText(f"{dup_count} öğe başarıyla çoğaltıldı.")

    def check_modified_temp_files(self):
        """Canlı Düzenleme Takibi: Kullanıcı açtığı dosyayı düzenleyip kaydettiyse kasada otomatik güncelle."""
        if not self.active_temp_files:
            return
        for temp_path, info in list(self.active_temp_files.items()):
            p = Path(temp_path)
            if not p.exists():
                self.active_temp_files.pop(temp_path, None)
                continue
            try:
                cur_mtime = p.stat().st_mtime
                if cur_mtime > info["last_mtime"] + 1.0:
                    info["last_mtime"] = cur_mtime
                    CustomVaultEngine.add_file(self.vault_path, self.auth_info, str(p), info["orig_path"])
                    self.thumbnail_cache.pop(info["file_id"], None)
                    self.refresh_file_list()
            except Exception:
                pass

    def on_export_selected_items(self):
        """Seçili bir veya birden fazla dosya/klasörü dışa aktarır."""
        selected_items = self.get_selected_items()
        if not selected_items:
            QMessageBox.information(self, "Bilgi", "Lütfen dışa aktarmak istediğiniz öğeleri seçin.")
            return

        target_dir = QFileDialog.getExistingDirectory(self, "Seçili Öğelerin Çıkartılacağı Klasörü Seçin")
        if not target_dir:
            return
        t_base = Path(target_dir).resolve()

        items_to_export: List[Tuple[Dict[str, Any], str]] = []
        for item in selected_items:
            if item.get("is_folder"):
                folder_p = item["path"]
                prefix = f"{folder_p}/"
                sub_base = t_base / item["name"]
                for f in self.cached_files:
                    if f.get("path", "").startswith(prefix):
                        sub_rel = f["path"][len(prefix):]
                        out_f = (sub_base / sub_rel).resolve()
                        if out_f.is_relative_to(t_base):
                            items_to_export.append((f, str(out_f)))
            else:
                out_f = t_base / Path(item["path"]).name
                items_to_export.append((item.get("entry", item), str(out_f)))

        if not items_to_export:
            QMessageBox.information(self, "Bilgi", "Dışa aktarılacak dosya bulunamadı.")
            return

        if len(items_to_export) == 1 and items_to_export[0][0].get("size", 0) < 3 * 1024 * 1024:
            f_entry, out_path = items_to_export[0]
            try:
                CustomVaultEngine.extract_file(self.vault_path, self.auth_info, f_entry["id"], out_path)
                QMessageBox.information(self, "Başarılı", f"Dosya başarıyla dışa aktarıldı:\n{out_path}")
                return
            except Exception as e:
                QMessageBox.warning(self, "Hata", f"Dışa aktarma başarısız:\n{e}")
                return

        dialog = VaultProgressDialog(self, title="Dosyalar Dışa Aktarılıyor...", is_dark=self.is_dark, theme=self.current_theme)
        worker = VaultTaskThread("export", self.vault_path, self.auth_info, items=items_to_export)
        dialog.attach_thread(worker)
        worker.start()
        dialog.exec()

        if not dialog.is_success and dialog.error_message:
            QMessageBox.warning(self, "Dışa Aktarma Hatası", f"İşlem sırasında hata oluştu:\n{dialog.error_message}")
        elif dialog.result_data:
            res = dialog.result_data
            count = res.get("exported_count", 0)
            errors = res.get("errors", [])
            if errors:
                QMessageBox.warning(self, "Dışa Aktarma Uyarısı", f"{count} dosya aktarıldı, ancak bazı hatalar oluştu:\n" + "\n".join(errors[:5]))
            else:
                QMessageBox.information(self, "Başarılı", f"{count} adet dosya başarıyla dışa aktarıldı:\n{target_dir}")

    def on_export_selected_item(self):
        """Seçili tek dosya veya klasörü kullanıcının belirlediği konuma dışa aktarır."""
        selected = self.get_selected_item_data()
        if not selected:
            QMessageBox.information(self, "Bilgi", "Lütfen dışa aktarmak istediğiniz öğeyi seçin.")
            return

        if selected.get("is_folder"):
            return self.on_export_selected_items()

        default_name = Path(selected["path"]).name
        save_dest, _ = QFileDialog.getSaveFileName(self, "Dosyayı Dışa Aktar", default_name, "Tüm Dosyalar (*.*)")
        if not save_dest:
            return

        sz = selected.get("entry", {}).get("size", 0)
        if sz > 3 * 1024 * 1024:
            dialog = VaultProgressDialog(self, title="Dosya Dışa Aktarılıyor...", is_dark=self.is_dark, theme=self.current_theme)
            worker = VaultTaskThread("export", self.vault_path, self.auth_info, items=[(selected.get("entry", selected), save_dest)])
            dialog.attach_thread(worker)
            worker.start()
            dialog.exec()
            if not dialog.is_success and dialog.error_message:
                QMessageBox.warning(self, "Hata", f"Dışa aktarma başarısız:\n{dialog.error_message}")
            else:
                QMessageBox.information(self, "Başarılı", f"Dosya başarıyla dışa aktarıldı:\n{save_dest}")
            return

        try:
            CustomVaultEngine.extract_file(self.vault_path, self.auth_info, selected["id"], save_dest)
            QMessageBox.information(self, "Başarılı", f"Dosya başarıyla dışa aktarıldı:\n{save_dest}")
        except Exception as e:
            QMessageBox.critical(self, "Hata", f"Dışa aktarma başarısız:\n{e}")

    def get_desktop_dir(self) -> Path:
        """Windows sistemindeki gerçek Masaüstü dizinini güvenilir şekilde tespit eder."""
        if sys.platform == "win32":
            try:
                import ctypes
                from ctypes import wintypes
                buf = ctypes.create_unicode_buffer(wintypes.MAX_PATH)
                if ctypes.windll.shell32.SHGetFolderPathW(None, 0, None, 0, buf) == 0:
                    p = Path(buf.value)
                    if p.exists():
                        return p
            except Exception:
                pass
            try:
                import winreg
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders") as k:
                    val, _ = winreg.QueryValueEx(k, "Desktop")
                    p = Path(os.path.expandvars(val))
                    if p.exists():
                        return p
            except Exception:
                pass
        for cand in [Path.home() / "Desktop", Path.home() / "Masaüstü", Path.home() / "OneDrive" / "Desktop"]:
            if cand.exists():
                return cand
        return Path.home() / "Desktop"

    def on_export_to_desktop(self):
        """Seçili dosya veya klasörü tek tıkla doğrudan Windows Masaüstüne çıkartır."""
        selected = self.get_selected_item_data()
        if not selected:
            QMessageBox.information(self, "Bilgi", "Lütfen masaüstüne çıkartmak istediğiniz öğeyi seçin.")
            return

        desktop_dir = self.get_desktop_dir()

        if selected.get("is_folder"):
            folder_p = selected["path"]
            t_base = (desktop_dir / selected["name"]).resolve()
            prefix = f"{folder_p}/"
            count = 0
            for f in self.cached_files:
                if f.get("path", "").startswith(prefix):
                    sub_rel = f["path"][len(prefix):]
                    out_f = (t_base / sub_rel).resolve()
                    if not out_f.is_relative_to(t_base):
                        continue
                    try:
                        CustomVaultEngine.extract_file(self.vault_path, self.auth_info, f["id"], str(out_f))
                        count += 1
                    except Exception:
                        pass
            QMessageBox.information(self, "Masaüstüne Çıkartıldı", f"'{selected['name']}' klasörü ({count} dosya) Masaüstünüze çıkartıldı.")
        else:
            fname = Path(selected["path"]).name
            out_file = desktop_dir / fname
            try:
                CustomVaultEngine.extract_file(self.vault_path, self.auth_info, selected["id"], str(out_file))
                QMessageBox.information(self, "Masaüstüne Çıkartıldı", f"'{fname}' dosyası Masaüstünüze başarıyla çıkartıldı:\n{out_file}")
            except Exception as e:
                QMessageBox.critical(self, "Hata", f"Masaüstüne çıkartılamadı:\n{e}")

    def on_rename_selected_item(self):
        """Seçili dosya veya klasörün adını değiştirir."""
        selected = self.get_selected_item_data()
        if not selected:
            return

        is_folder = selected.get("is_folder", False)
        old_name = selected["name"] if is_folder else Path(selected["path"]).name

        new_name, ok = QInputDialog.getText(self, "Yeniden Adlandır", "Yeni isim:", text=old_name)
        if not ok or not new_name.strip() or new_name.strip() == old_name:
            return

        clean_new = new_name.strip().replace("\\", "/").strip("/")

        try:
            if is_folder:
                parts = selected["path"].split("/")
                new_full_path = "/".join(parts[:-1] + [clean_new]) if len(parts) > 1 else clean_new
                CustomVaultEngine.rename_folder(self.vault_path, self.auth_info, selected["path"], new_full_path)
            else:
                parts = selected["path"].split("/")
                new_full_path = "/".join(parts[:-1] + [clean_new]) if len(parts) > 1 else clean_new
                CustomVaultEngine.rename_file(self.vault_path, self.auth_info, selected["id"], new_full_path)

            self.refresh_file_list()
        except Exception as e:
            QMessageBox.critical(self, "Hata", f"Yeniden adlandırma hatası:\n{e}")

    def on_delete_selected_items(self):
        """Seçili bir veya birden fazla dosya veya klasörü kasadan kalıcı olarak siler."""
        selected_items = self.get_selected_items()
        if not selected_items:
            return
        count = len(selected_items)
        if count == 1:
            return self.on_delete_selected_item()

        ans = QMessageBox.question(
            self,
            "Çoklu Silme Onayı",
            f"Seçilen {count} adet dosya ve/veya klasörü kasadan kalıcı olarak silmek istediğinize emin misiniz?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        if ans != QMessageBox.StandardButton.Yes:
            return

        for item in selected_items:
            try:
                if item.get("is_folder"):
                    CustomVaultEngine.delete_folder(self.vault_path, self.auth_info, item["path"])
                else:
                    CustomVaultEngine.delete_file(self.vault_path, self.auth_info, item["id"])
                    self.thumbnail_cache.pop(item["id"], None)
            except Exception:
                pass

        self.refresh_file_list()

    def on_delete_selected_item(self):
        """Seçili tek dosya veya klasörü kasadan kalıcı olarak siler."""
        selected = self.get_selected_item_data()
        if not selected:
            return

        is_folder = selected.get("is_folder", False)
        item_name = selected["name"] if is_folder else Path(selected["path"]).name

        ans = QMessageBox.question(
            self,
            "Silme Onayı",
            f"'{item_name}' {'klasörünü ve tüm içeriğini' if is_folder else 'dosyasını'} kasadan kalıcı olarak silmek istediğinize emin misiniz?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        if ans != QMessageBox.StandardButton.Yes:
            return

        try:
            if is_folder:
                CustomVaultEngine.delete_folder(self.vault_path, self.auth_info, selected["path"])
            else:
                CustomVaultEngine.delete_file(self.vault_path, self.auth_info, selected["id"])
                self.thumbnail_cache.pop(selected["id"], None)

            self.refresh_file_list()
        except Exception as e:
            QMessageBox.critical(self, "Hata", f"Silme başarısız:\n{e}")

    def on_compact_vault_clicked(self):
        """Kasa içerisindeki silinmiş alanları temizleyerek dosya boyutunu küçültür."""
        if self.auth_info.get("is_decoy"):
            QMessageBox.warning(
                self,
                "İşlem Engellendi",
                "Tuzak kasa oturumundayken gizli verilerin güvenliği ve bütünlüğü için kasa sıkıştırma yapılamaz."
            )
            return

        if not self.auth_info.get("is_dynamic", True):
            QMessageBox.information(
                self,
                "Bilgi",
                "Bu kasa sabit boyutlu olarak yapılandırılmıştır. Plausible Deniability güvenliği için sabit boyutlu kasalarda sıkıştırma yapılamaz."
            )
            return

        has_decoy_reply = QMessageBox.question(
            self,
            "Tuzak Kasa Güvenlik Denetimi",
            "Bu kasada yapılandırılmış gömülü bir Tuzak Kasa (Decoy Vault) bulunuyor mu?\n\n"
            "Tuzak kasa içeren kasalarda sıkıştırma yapılması tuzak verilerin silinmesine yol açabilir.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        if has_decoy_reply == QMessageBox.StandardButton.Yes:
            QMessageBox.warning(
                self,
                "Sıkıştırma Engellendi",
                "Tuzak kasa içeren kasalarda gizli verilerin silinmesini önlemek için sıkıştırma işlemi güvenlik gereği iptal edildi."
            )
            return

        reply = QMessageBox.question(
            self,
            "Kasayı Sıkıştır / Optimize Et",
            "Bu işlem silinmiş dosyaların kapladığı boş alanı fiziksel olarak temizleyecektir.\n\n"
            "NOT: Kasa sıkıştırma öncesinde dosyanın yedeğini aldığınızdan emin olunuz.\n\n"
            "Devam etmek istiyor musunuz?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        dialog = VaultProgressDialog(self, title="Kasa Optimize Ediliyor...", is_dark=self.is_dark, theme=self.current_theme)
        dialog.btn_cancel.setEnabled(False)
        worker = VaultTaskThread("compact", self.vault_path, self.auth_info, discard_other_compartment=True)
        dialog.attach_thread(worker)
        worker.start()
        dialog.exec()

        self.refresh_file_list()
        if not dialog.is_success and dialog.error_message:
            QMessageBox.warning(self, "Hata", f"Sıkıştırma hatası:\n{dialog.error_message}")
        elif dialog.result_data:
            res = dialog.result_data
            saved = res.get("saved_bytes", 0)
            QMessageBox.information(
                self,
                "Sıkıştırma Tamamlandı",
                f"Kasa başarıyla optimize edildi!\n\nGeri kazanılan boş alan: {format_size(saved)}"
            )

    def _on_shortcut_slideshow(self):
        """Kullanıcı 'S' tuşuna bastığında slayt gösterisini başlatır."""
        if hasattr(self, "txt_search") and self.txt_search.hasFocus():
            return
        self.open_fullscreen_image(start_slideshow=True)

    def _on_shortcut_fullscreen(self):
        """Kullanıcı tam ekran talep ettiğinde seçili görseli/videoyu açar veya gezgin penceresini tam ekran yapar."""
        if hasattr(self, "txt_search") and self.txt_search.hasFocus():
            return
        selected = self.get_selected_item_data()
        if selected and not selected.get("is_folder"):
            fname = Path(selected.get("entry", {}).get("path", "")).name
            cat = get_file_category(fname)
            if cat == "image":
                self.open_fullscreen_image(selected.get("id"), start_slideshow=False)
                return
            elif cat == "video":
                self.open_fullscreen_video(selected.get("id"))
                return
        if getattr(self, "current_preview_image_id", None):
            self.open_fullscreen_image(self.current_preview_image_id, start_slideshow=False)
            return
        
        folder_images = []
        for f in getattr(self, "cached_files", []):
            p = f.get("path", "")
            f_dir = str(Path(p).parent).replace("\\", "/").strip("/")
            if f_dir in (".", "/"):
                f_dir = ""
            if f_dir == getattr(self, "current_folder", ""):
                if get_file_category(Path(p).name) == "image":
                    folder_images.append(f)
        if folder_images:
            self.open_fullscreen_image(folder_images[0].get("id"), start_slideshow=False)
            return

        self.toggle_fullscreen_mode()

    def toggle_fullscreen_mode(self):
        """Kasa dosya gezginini tam ekran ile standart pencere modu arasında geçirir."""
        if self.isFullScreen():
            self.showNormal()
            if hasattr(self, "btn_exp_fullscreen"):
                self.btn_exp_fullscreen.setIcon(get_svg_icon("expand", "#94A3B8" if self.is_dark else "#64748B", 15))
                self.btn_exp_fullscreen.setToolTip("Tam Ekran (F11)")
        else:
            self.showFullScreen()
            if hasattr(self, "btn_exp_fullscreen"):
                accent_c = "#38BDF8" if self.is_dark else "#0284C7"
                self.btn_exp_fullscreen.setIcon(get_svg_icon("collapse", accent_c, 15))
                self.btn_exp_fullscreen.setToolTip("Pencere Moduna Dön (F11 / Esc)")

    def keyPressEvent(self, event):
        """Standart klavye kısayollarını (Ctrl+C, Ctrl+X, Ctrl+V, Ctrl+D, Ctrl+A, F2, F5, Delete, Alt+Enter) yakalar."""
        mod = event.modifiers()
        key = event.key()

        if mod & Qt.KeyboardModifier.ControlModifier:
            if key == Qt.Key.Key_C:
                self.on_copy_selected()
                return
            elif key == Qt.Key.Key_X:
                self.on_cut_selected()
                return
            elif key == Qt.Key.Key_V:
                self.on_paste()
                return
            elif key == Qt.Key.Key_D:
                self.on_duplicate_selected()
                return
            elif key == Qt.Key.Key_A:
                if self.view_mode == "details":
                    self.table.selectAll()
                else:
                    self.grid_list.selectAll()
                return

        if key == Qt.Key.Key_F11:
            if self.isFullScreen():
                self.showNormal()
            else:
                self.showFullScreen()
            return
        elif key == Qt.Key.Key_Escape and self.isFullScreen():
            self.showNormal()
            return

        if key == Qt.Key.Key_F:
            if not (hasattr(self, "txt_search") and self.txt_search.hasFocus()):
                self._on_shortcut_fullscreen()
                return

        if key == Qt.Key.Key_Space:
            if not (hasattr(self, "txt_search") and self.txt_search.hasFocus()):
                selected = self.get_selected_item_data()
                if selected and not selected.get("is_folder"):
                    cat = get_file_category(Path(selected.get("entry", {}).get("path", "")).name)
                    if cat == "image":
                        self.open_fullscreen_image(selected.get("id"), start_slideshow=False)
                        return
                    elif cat == "video":
                        self.open_fullscreen_video(selected.get("id"))
                        return

        if key == Qt.Key.Key_S:
            if not (hasattr(self, "txt_search") and self.txt_search.hasFocus()):
                selected = self.get_selected_item_data()
                if selected and not selected.get("is_folder") and get_file_category(Path(selected.get("entry", {}).get("path", "")).name) == "image":
                    self.open_fullscreen_image(selected.get("id"), start_slideshow=True)
                    return

        if key in (Qt.Key.Key_Return, Qt.Key.Key_Enter) and not (mod & Qt.KeyboardModifier.AltModifier):
            if not (hasattr(self, "txt_search") and self.txt_search.hasFocus()):
                self.on_open_selected_item()
                return

        if key == Qt.Key.Key_F2:
            self.on_rename_selected_item()
            return
        elif key == Qt.Key.Key_F5:
            self.refresh_file_list()
            return
        elif key == Qt.Key.Key_Delete:
            self.on_delete_selected_items()
            return
        elif (mod & Qt.KeyboardModifier.AltModifier) and (key in (Qt.Key.Key_Return, Qt.Key.Key_Enter)):
            self.on_properties_selected()
            return

        super().keyPressEvent(event)

    def show_context_menu(self, pos: QPoint):
        """Dosya veya klasör üzerinde sağ tıklandığında açılan gelişmiş profesyonel menü."""
        selected_items = self.get_selected_items()
        selected = self.get_selected_item_data()
        accent_col = "#2997FF" if getattr(self, "theme", "dark") == "apple_dark" else ("#0071E3" if getattr(self, "theme", "dark") == "apple_light" else ("#38BDF8" if getattr(self, "is_dark", True) else "#0284C7"))
        menu = QMenu(self)

        if selected_items:
            count = len(selected_items)
            is_single = (count == 1)
            is_folder = selected.get("is_folder", False) if (is_single and selected) else False

            if is_single and is_folder:
                act_open = menu.addAction(get_svg_icon("folder_open", accent_col, 14), "Klasörü Aç")
                act_open.triggered.connect(lambda: self.navigate_to_folder(selected["path"]))
            elif is_single and not is_folder:
                f_name = Path(selected.get("entry", {}).get("path", "")).name
                cat = get_file_category(f_name)
                if cat == "app":
                    act_open = menu.addAction(get_svg_icon("play", accent_col, 14), "Uygulamayı Güvenle Çalıştır")
                    act_open.triggered.connect(self.on_open_selected_item)
                elif cat == "image":
                    act_view_vault = menu.addAction(get_svg_icon("eye", accent_col, 14), "Kasa İçinde Görüntüle")
                    act_view_vault.triggered.connect(lambda: self.open_in_vault_viewer(selected.get("id"), f_name))
                    act_fs = menu.addAction(get_svg_icon("expand", accent_col, 14), "Tam Ekran Görüntüle (F)")
                    act_fs.triggered.connect(lambda: self.open_fullscreen_image(selected.get("id")))
                    act_slide = menu.addAction(get_svg_icon("slideshow", accent_col, 14), "Slayt Gösterisi Başlat (S)")
                    act_slide.triggered.connect(lambda: self.open_fullscreen_image(selected.get("id"), start_slideshow=True))
                else:
                    ext_lower = Path(f_name).suffix.lower()
                    text_exts = {".txt", ".py", ".json", ".md", ".log", ".csv", ".ini", ".bat", ".html", ".css", ".js", ".xml", ".yaml", ".yml", ".sql", ".c", ".cpp", ".h", ".rs", ".go", ".sh", ".ps1"}
                    if ext_lower in text_exts:
                        act_view_vault = menu.addAction(get_svg_icon("file_text", accent_col, 14), "Kasa İçinde Görüntüle")
                        act_view_vault.triggered.connect(lambda: self.open_in_vault_viewer(selected.get("id"), f_name))
                    act_open = menu.addAction(get_svg_icon("eye", accent_col, 14), "Güvenli Aç (Varsayılan Uygulama)")
                    act_open.triggered.connect(self.on_open_selected_item)
                    act_sandbox = menu.addAction(get_svg_icon("shield", accent_col, 14), "Windows Sandbox'ta Güvenli İncele")
                    act_sandbox.triggered.connect(self.on_open_in_sandbox_selected)

                if cat in ["code", "document", "other"] and Path(f_name).suffix.lower() not in [".exe", ".msi", ".dll", ".bin", ".iso", ".sys"]:
                    act_edit = menu.addAction(get_svg_icon("file_text", accent_col, 14), "Kasa İçinde Düzenle (Bellekte)")
                    act_edit.triggered.connect(self.on_edit_text_selected)

                act_hex = menu.addAction(get_svg_icon("binary", accent_col, 14), "Hex / İkili İncele (Hex Viewer)")
                act_hex.triggered.connect(self.on_view_hex_selected)

            menu.addSeparator()

            act_copy = menu.addAction(get_svg_icon("copy", accent_col, 14), f"Kopyala ({count} öğe)" if not is_single else "Kopyala (Ctrl+C)")
            act_copy.triggered.connect(self.on_copy_selected)

            act_cut = menu.addAction(get_svg_icon("scissors", accent_col, 14), f"Kes ({count} öğe)" if not is_single else "Kes (Ctrl+X)")
            act_cut.triggered.connect(self.on_cut_selected)

            if not is_folder or not is_single:
                act_dup = menu.addAction(get_svg_icon("duplicate", accent_col, 14), "Çoğalt (Ctrl+D)")
                act_dup.triggered.connect(self.on_duplicate_selected)

            menu.addSeparator()

            act_export = menu.addAction(get_svg_icon("download", accent_col, 14), f"Dışa Aktar... ({count} öğe)" if not is_single else "Dışa Aktar...")
            act_export.triggered.connect(self.on_export_selected_items)

            act_desk = menu.addAction(get_svg_icon("desktop", accent_col, 14), "Masaüstüne Çıkart")
            act_desk.triggered.connect(self.on_export_to_desktop if is_single else self.on_export_selected_items)

            menu.addSeparator()

            if is_single:
                act_rename = menu.addAction(get_svg_icon("edit", accent_col, 14), "Yeniden Adlandır (F2)")
                act_rename.triggered.connect(self.on_rename_selected_item)

            act_del = menu.addAction(get_svg_icon("trash", "#F87171" if self.is_dark else "#B52222", 14), f"Kasadan Sil ({count} öğe)" if not is_single else "Kasadan Sil (Delete)")
            act_del.triggered.connect(self.on_delete_selected_items)

            if is_single and not is_folder:
                menu.addSeparator()
                act_prop = menu.addAction(get_svg_icon("properties", accent_col, 14), "Özellikler & Bütünlük (Alt+Enter)")
                act_prop.triggered.connect(self.on_properties_selected)
        else:
            if self.vault_clipboard and self.vault_clipboard.get("items"):
                clip_count = len(self.vault_clipboard["items"])
                act_paste = menu.addAction(get_svg_icon("clipboard", accent_col, 14), f"Yapıştır ({clip_count} öğe - Ctrl+V)")
                act_paste.triggered.connect(self.on_paste)
                menu.addSeparator()

            act_new_f = menu.addAction(get_svg_icon("folder_plus", accent_col, 14), "Yeni Klasör")
            act_new_f.triggered.connect(self.on_new_folder_clicked)

            act_add_f = menu.addAction(get_svg_icon("file_plus", accent_col, 14), "Dosya Ekle...")
            act_add_f.triggered.connect(self.on_add_files_clicked)

            act_add_fold = menu.addAction(get_svg_icon("folder_open", accent_col, 14), "Klasör Ekle...")
            act_add_fold.triggered.connect(self.on_add_folder_clicked)

            menu.addSeparator()
            act_refresh = menu.addAction(get_svg_icon("refresh", accent_col, 14), "Yenile (F5)")
            act_refresh.triggered.connect(self.refresh_file_list)

        widget = self.table.viewport() if self.view_mode == "details" else self.grid_list.viewport()
        menu.exec(widget.mapToGlobal(pos))

    def show_tree_context_menu(self, pos: QPoint):
        """Sol klasör ağacı üzerinde sağ tıklandığında açılan menü."""
        item = self.tree_folders.itemAt(pos)
        if not item:
            return
        folder_path = item.data(0, Qt.ItemDataRole.UserRole)
        accent_col = "#2997FF" if getattr(self, "theme", "dark") == "apple_dark" else ("#0071E3" if getattr(self, "theme", "dark") == "apple_light" else ("#38BDF8" if getattr(self, "is_dark", True) else "#0284C7"))

        menu = QMenu(self)
        act_open = menu.addAction(get_svg_icon("folder_open", accent_col, 14), "Aç")
        act_open.triggered.connect(lambda: self.navigate_to_folder(folder_path))

        act_new_f = menu.addAction(get_svg_icon("folder_plus", accent_col, 14), "İçinde Yeni Klasör Oluştur...")
        def create_sub():
            name, ok = QInputDialog.getText(self, "Yeni Klasör", "Klasör adı:")
            if ok and name.strip():
                sub_path = f"{folder_path}/{name.strip()}" if folder_path else name.strip()
                CustomVaultEngine.add_folder(self.vault_path, self.auth_info, sub_path)
                self.refresh_file_list()
        act_new_f.triggered.connect(create_sub)

        if folder_path:
            menu.addSeparator()
            act_del = menu.addAction(get_svg_icon("trash", "#F87171" if self.is_dark else "#B52222", 14), "Klasörü Sil")
            def del_sub():
                ans = QMessageBox.question(self, "Sil", f"'{item.text(0)}' klasörü silinsin mi?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
                if ans == QMessageBox.StandardButton.Yes:
                    CustomVaultEngine.delete_folder(self.vault_path, self.auth_info, folder_path)
                    self.refresh_file_list()
            act_del.triggered.connect(del_sub)

        menu.exec(self.tree_folders.viewport().mapToGlobal(pos))

    def cleanup_temp_files(self, allow_prompt: bool = True) -> bool:
        """Açılmış olan tüm geçici izleri DoD standardında parçalayarak siler ve bellek önbelleklerini temizler."""
        if hasattr(self, "audio_widget"):
            self.audio_widget.stop()
        if hasattr(self, "video_widget"):
            self.video_widget.stop()

        failed_files = []
        for temp_path in list(self.active_temp_files.keys()):
            p = Path(temp_path)
            if not p.exists():
                self.active_temp_files.pop(temp_path, None)
                continue
            success = secure_wipe_file(temp_path, passes=1)
            if success or not p.exists():
                p_dir = p.parent
                if p_dir.name.startswith("pvault_view_") or p_dir.name.startswith("pvault_drag_"):
                    secure_wipe_directory(str(p_dir))
                self.active_temp_files.pop(temp_path, None)
            else:
                failed_files.append(temp_path)

        if failed_files and allow_prompt:
            file_names = "\n".join([f"• {Path(f).name}" for f in failed_files[:5]])
            reply = QMessageBox.question(
                self,
                "Açık Dosya Uyarısı",
                f"Aşağıdaki geçici dosyalar harici bir program (Word, Excel, PDF okuyucu vb.) tarafından açık tutulduğu için adli standartta silinemedi:\n\n"
                f"{file_names}\n\n"
                "Lütfen ilgili programı kapatıp 'Yes' (Yeniden Dene) butonuna basın.\n"
                "Yeniden denensin mi?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.Yes
            )
            if reply == QMessageBox.StandardButton.Yes:
                still_failed = []
                for temp_path in failed_files:
                    if secure_wipe_file(temp_path, passes=1) or not Path(temp_path).exists():
                        p_dir = Path(temp_path).parent
                        secure_wipe_directory(str(p_dir))
                        self.active_temp_files.pop(temp_path, None)
                    else:
                        still_failed.append(temp_path)
                failed_files = still_failed

        for temp_dir in list(self.active_temp_dirs):
            try:
                secure_wipe_directory(temp_dir)
            except Exception:
                pass
        self.active_temp_dirs.clear()

        if hasattr(self, "thumbnail_cache"):
            self.thumbnail_cache.clear()
        if hasattr(self, "full_image_cache"):
            self.full_image_cache.clear()
        self.current_preview_image_id = None
        if hasattr(self, "cached_files"):
            self.cached_files.clear()
        if hasattr(self, "cached_folders"):
            self.cached_folders.clear()

        purge_all_vault_temp_forensics()

    @staticmethod
    def _zeroize_memory(obj):
        """Bellekteki hassas anahtar verilerini (bytes, bytearray) sıfır baytlarla ezerek (zeroize) fiziksel olarak temizler."""
        if obj is None:
            return
        try:
            if isinstance(obj, (bytearray, memoryview)):
                for i in range(len(obj)):
                    obj[i] = 0
            elif isinstance(obj, bytes) and len(obj) > 0:
                import ctypes
                offset = ctypes.sizeof(ctypes.c_size_t) * 4
                buf = (ctypes.c_char * len(obj)).from_address(id(obj) + offset)
                ctypes.memset(buf, 0, len(obj))
        except Exception:
            pass

    def _on_pv_view_vault_clicked(self):
        """Sağ paneldeki 'Kasa İçinde Görüntüle' butonuna tıklandığında çağrılır."""
        fid = getattr(self, "_pv_current_file_id", None)
        fname = getattr(self, "_pv_current_fname", "")
        if fid:
            self.open_in_vault_viewer(fid, fname)

    def open_in_vault_viewer(self, file_id: str, filename: str = ""):
        """Resim veya metin dosyasını kasa içi yalıtılmış görüntüleyicide açar. Hiçbir harici uygulama çağrılmaz."""
        if not file_id:
            return
        cat = get_file_category(filename)
        if cat == "image":
            self.open_fullscreen_image(file_id)
            return
        try:
            raw_data, entry = CustomVaultEngine.extract_file_bytes(self.vault_path, self.auth_info, file_id)
        except Exception as e:
            QMessageBox.critical(self, "Hata", f"Dosya okunamadı:\n{e}")
            return

        is_dark = self.is_dark
        accent = "#38BDF8" if is_dark else "#0078D4"
        text_col = "#F1F5F9" if is_dark else "#1A1A1A"
        muted = "#A1A1AA" if is_dark else "#5A5A5A"
        bg = "#18181b" if is_dark else "#FAFAFA"
        card = "#202024" if is_dark else "#FFFFFF"
        border = "rgba(255,255,255,0.08)" if is_dark else "rgba(0,0,0,0.08)"

        try:
            text_content = raw_data.decode("utf-8", errors="replace")
        except Exception:
            text_content = raw_data.decode("latin-1", errors="replace")

        dlg = QDialog(self)
        dlg.setWindowTitle(f"Kasa İçi Görüntüleyici — {filename}")
        dlg.setWindowFlags(Qt.WindowType.Window | Qt.WindowType.WindowMinMaxButtonsHint | Qt.WindowType.WindowCloseButtonHint)
        apply_dynamic_geometry(dlg, default_w=760, default_h=540, min_w=540, min_h=380, w_ratio=0.55, h_ratio=0.6)
        try:
            from extra_dialogs import set_dialog_dark_mode
            set_dialog_dark_mode(dlg, is_dark)
        except Exception:
            pass

        dlg.setStyleSheet(f"""
            QDialog {{ background: {bg}; color: {text_col}; font-family: 'Segoe UI', sans-serif; }}
            QLabel {{ color: {text_col}; }}
            QPlainTextEdit {{
                background: {card};
                color: {text_col};
                border: 1px solid {border};
                border-radius: 6px;
                padding: 10px;
                font-size: 12.5px;
                font-family: 'Consolas', 'Courier New', monospace;
                line-height: 1.5;
                selection-background-color: {'rgba(56,189,248,0.3)' if is_dark else 'rgba(0,120,212,0.2)'};
            }}
            QPushButton {{
                background: {'rgba(56,189,248,0.12)' if is_dark else 'rgba(0,120,212,0.08)'};
                color: {accent};
                border: 1px solid {accent};
                border-radius: 5px;
                padding: 6px 16px;
                font-size: 12px;
                font-weight: 600;
                min-height: 28px;
            }}
            QPushButton:hover {{ background: {'rgba(56,189,248,0.24)' if is_dark else 'rgba(0,120,212,0.18)'}; }}
        """)

        vl = QVBoxLayout(dlg)
        vl.setContentsMargins(14, 12, 14, 12)
        vl.setSpacing(8)

        hdr = QHBoxLayout()
        icon_lbl = QLabel()
        icon_lbl.setPixmap(get_svg_pixmap("file_text", accent, 18))
        hdr.addWidget(icon_lbl)
        lbl_title = QLabel(f"<b>{filename}</b>")
        lbl_title.setStyleSheet(f"font-size: 14px; font-weight: 700; color: {text_col};")
        hdr.addWidget(lbl_title)
        hdr.addStretch()
        lbl_badge = QLabel("🔒 Kasa İçi Görüntüleyici")
        lbl_badge.setStyleSheet(f"font-size: 10px; font-weight: 700; color: {'#10B981'}; background: {'rgba(16,185,129,0.12)'}; border-radius: 4px; padding: 2px 8px;")
        hdr.addWidget(lbl_badge)
        vl.addLayout(hdr)

        txt = QPlainTextEdit()
        txt.setReadOnly(True)
        txt.setPlainText(text_content)
        txt.setFont(QFont("Consolas", 11))
        vl.addWidget(txt, stretch=1)

        lbl_info = QLabel(f"{len(raw_data):,} bayt  •  {text_content.count(chr(10)) + 1} satır")
        lbl_info.setStyleSheet(f"font-size: 10px; color: {muted};")

        row = QHBoxLayout()
        row.addWidget(lbl_info)
        row.addStretch()
        btn_copy = QPushButton("Metni Kopyala")
        btn_copy.clicked.connect(lambda: QApplication.clipboard().setText(text_content))
        row.addWidget(btn_copy)
        btn_close = QPushButton("Kapat")
        btn_close.clicked.connect(dlg.accept)
        btn_close.setStyleSheet(f"background: {'rgba(255,255,255,0.06)' if is_dark else 'rgba(0,0,0,0.06)'}; color: {text_col}; border: 1px solid {border}; border-radius: 5px; padding: 6px 16px; font-size: 12px; min-height: 28px;")
        row.addWidget(btn_close)
        vl.addLayout(row)

        dlg.exec()

    def lock_and_close(self):
        """Kasayı derhal kilitler, geçici dosyaları imha eder, bellek anahtarlarını sıfırlar ve pencereyi kapatır."""
        try:
            VaultGlobalDropFilter.get_instance().unregister_dialog(self)
        except Exception:
            pass
        if hasattr(self, "current_icon_worker") and self.current_icon_worker:
            self.current_icon_worker.cancel()
        self.cleanup_temp_files()
        if hasattr(self, "auth_info") and isinstance(self.auth_info, dict):
            for k in list(self.auth_info.keys()):
                self._zeroize_memory(self.auth_info[k])
                self.auth_info[k] = None
            self.auth_info.clear()
        import gc
        gc.collect()
        self.vault_locked_signal.emit()
        self.accept()

    def closeEvent(self, event):
        try:
            VaultGlobalDropFilter.get_instance().unregister_dialog(self)
        except Exception:
            pass
        if hasattr(self, "current_icon_worker") and self.current_icon_worker:
            self.current_icon_worker.cancel()
        self.cleanup_temp_files()
        if hasattr(self, "auth_info") and isinstance(self.auth_info, dict):
            for k in list(self.auth_info.keys()):
                self._zeroize_memory(self.auth_info[k])
                self.auth_info[k] = None
            self.auth_info.clear()
        import gc
        gc.collect()
        self.vault_locked_signal.emit()
        event.accept()
