"""
Enclave - Tasarım Sistemi
Üç ayrı arayüz: her biri kendi yerleşimine, yazı karakterine ve açık/koyu paletine sahiptir.
Renkler yalnızca buradan gelir; widget kodunda renk yazılmaz.
"""

import sys
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Dict, Optional

@dataclass(frozen=True)
class Palette:
    window: str
    surface: str
    surface_alt: str
    rail: str
    text: str
    muted: str
    border: str
    accent: str
    on_accent: str
    accent_soft: str
    selection: str
    danger: str
    success: str
    warning: str

@dataclass(frozen=True)
class Design:
    key: str
    name: str
    summary: str
    layout: str
    heading_font: str
    meta_font: str
    radius: int
    default_view: str
    light: Palette
    dark: Palette
    style: str = "kart"
    rail: bool = True
    animated: bool = False
    body_font: str = ""
    fixed_palette: bool = False

def _design(key: str, name: str, accent_light: str, accent_dark: str, on_dark: str, soft_light: str, soft_dark: str,
            rail_light: str, rail_dark: str) -> Design:
    light = Palette(
        window="#F4F4F7", surface="#FFFFFF", surface_alt="#ECECF1", rail=rail_light,
        text="#1C1C22", muted="#5C5C68", border="#DADAE1",
        accent=accent_light, on_accent="#FFFFFF", accent_soft=soft_light, selection=soft_light,
        danger="#A32D2D", success="#1E6E46", warning="#7A4F00",
    )
    dark = Palette(
        window="#15151A", surface="#1E1E25", surface_alt="#292931", rail=rail_dark,
        text="#ECECF1", muted="#A9A9B5", border="#35353F",
        accent=accent_dark, on_accent=on_dark, accent_soft=soft_dark, selection=soft_dark,
        danger="#F2A9A3", success="#8BD0A8", warning="#E5BE6A",
    )
    return Design(key=key, name=name, summary="", layout="vault", heading_font="", meta_font="",
                  radius=10, default_view="grid", light=light, dark=dark)

DESIGNS: Dict[str, Design] = {
    "mor": _design("mor", "Mor", "#534AB7", "#AFA9EC", "#26215C", "#E4E2FA", "#34306A", "#26215C", "#1B1842"),
    "mavi": _design("mavi", "Mavi", "#185FA5", "#85B7EB", "#042C53", "#D6E7F8", "#1E3F60", "#0C2F52", "#08233E"),
    "yesil": _design("yesil", "Yeşil", "#2F6B2B", "#97C459", "#173404", "#DCEBD0", "#2C4420", "#173404", "#10260A"),
    "turkuaz": _design("turkuaz", "Turkuaz", "#0F6E56", "#5DCAA5", "#04342C", "#D2EEE4", "#16443A", "#04342C", "#032620"),
    "gul": _design("gul", "Gül", "#993556", "#ED93B1", "#4B1528", "#F7DDE6", "#4F2636", "#4B1528", "#360F1D"),
    "turuncu": _design("turuncu", "Turuncu", "#993C1D", "#F0997B", "#4A1B0C", "#F8E0D7", "#4C2A1E", "#4A1B0C", "#35130A"),
}

@dataclass(frozen=True)
class Look:
    """Arayüz stili: renklerden bağımsız yerleşim ve köşe yuvarlaklığı."""
    key: str
    name: str
    summary: str
    radius: int
    default_view: str
    rail: bool
    animated: bool = False
    light: Optional[Palette] = None
    dark: Optional[Palette] = None
    heading_font: str = ""
    body_font: str = ""

def _tones(window: str, surface: str, surface_alt: str, rail: str, text: str, muted: str, border: str, accent: str,
           on_accent: str, soft: str, night: bool) -> Palette:
    danger, success, warning = ("#F2A9A3", "#8BD0A8", "#E5BE6A") if night else ("#A32D2D", "#1E6E46", "#7A4F00")
    return Palette(window=window, surface=surface, surface_alt=surface_alt, rail=rail, text=text, muted=muted,
                   border=border, accent=accent, on_accent=on_accent, accent_soft=soft, selection=soft,
                   danger=danger, success=success, warning=warning)

_MATRIX = _tones("#070B09", "#0E1512", "#17211C", "#050806", "#D6F5E7", "#86A898", "#22332B", "#2DB58A", "#04140E", "#123428", True)
_HUD = _tones("#060B14", "#0C1420", "#14202F", "#040810", "#DCEBFF", "#8AA4C4", "#233650", "#60A5FA", "#04152B", "#16304F", True)
_STITCH_L = _tones("#F7F3E9", "#FFFDF7", "#EEE8DA", "#0F2E20", "#14231B", "#55645B", "#DDD6C5", "#0F2E20", "#F7F3E9", "#DDE7DD", False)
_STITCH_D = _tones("#0B1510", "#122019", "#1B2D24", "#081510", "#E9F1EA", "#A3B5A9", "#2A3D33", "#8FCFA8", "#0B2418", "#1F3B2D", True)
MONO = "JetBrains Mono"

STYLES: Dict[str, Look] = {
    "kart": Look("kart", "Kart", "Solda kasalar, ortada büyük dosya kartları. Varsayılan.", 10, "grid", True),
    "liste": Look("liste", "Liste", "Solda kasalar, ortada sıkı tablo. Çok dosyası olan kasalar için.", 6, "list", True),
    "canli": Look("canli", "Canlı kart", "Hareketli kartlar: açılışta sırayla belirir, üzerine gelince yükselip parlar. "
                  "Yan panelde akan ağ çizgileri.", 12, "grid", True, True),
    "siber": Look("siber", "Siber akış", "Sıkı liste ve yan panelde akan kod sütunları. Hareketli, teknik görünüm.", 8, "list", True, True),
    "matrix": Look("matrix", "Matrix", "Karanlık terminal: her yer eş aralıklı yazı, tek yeşil vurgu, akan kod.", 6, "list", True, True,
                   _MATRIX, _MATRIX, body_font=MONO),
    "hud": Look("hud", "HUD", "Savaş uçağı göstergesi: mavi çizgiler, dönen radar taraması.", 10, "grid", True, True,
                _HUD, _HUD, body_font=MONO),
    "stitch": Look("stitch", "Stitch", "Krem zemin, koyu orman yeşili ve zarif serif başlıklar.", 8, "list", True, False,
                   _STITCH_L, _STITCH_D, heading_font="Georgia"),
}
DEFAULT_STYLE = "kart"
DEFAULT_DESIGN = "mor"

def get_design(key: str, style: str = DEFAULT_STYLE) -> Design:
    base = DESIGNS.get(key, DESIGNS[DEFAULT_DESIGN])
    look = STYLES.get(style, STYLES[DEFAULT_STYLE])
    return replace(base, style=look.key, radius=look.radius, default_view=look.default_view, rail=look.rail,
                   animated=look.animated, light=look.light or base.light, dark=look.dark or base.dark,
                   heading_font=look.heading_font, body_font=look.body_font, fixed_palette=look.light is not None)

def rail_text(design: Design, dark: bool) -> str:
    """Sol panel iki modda da koyudur."""
    return "#F1F0FB"

def contrast_ratio(foreground: str, background: str) -> float:
    """WCAG 2.2 kontrast oranı."""
    def luminance(color: str) -> float:
        channels = [int(color[i:i + 2], 16) / 255 for i in (1, 3, 5)]
        linear = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
        return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]

    high, low = sorted((luminance(foreground), luminance(background)), reverse=True)
    return (high + 0.05) / (low + 0.05)

def _asset_url(name: str) -> str:
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent))
    return (base / "assets" / "ui" / name).as_posix()

def is_dark_color(color: str) -> bool:
    return contrast_ratio(color, "#FFFFFF") > contrast_ratio(color, "#000000")

def build_stylesheet(design: Design, dark: bool) -> str:
    p = design.dark if dark else design.light
    check = _asset_url(f"check_{'light' if is_dark_color(p.accent) else 'dark'}.svg")
    chevron = _asset_url(f"chevron_{'light' if is_dark_color(p.surface) else 'dark'}.svg")
    r = design.radius
    heading = f'font-family: "{design.heading_font}", "Noto Serif", "Times New Roman", serif;' if design.heading_font else ""
    meta = f'font-family: "{design.meta_font}", monospace; font-size: 12px;' if design.meta_font else "font-size: 13px;"
    tab_rail = rail_text(design, dark)
    body = f'font-family: "{design.body_font}", "Consolas", monospace;' if design.body_font else ""
    return f"""
    QWidget {{ color: {p.text}; font-size: 14px; {body} }}
    QMainWindow, QDialog, QWidget#Page, QWidget#Workspace {{ background: {p.window}; }}
    QScrollArea, QScrollArea > QWidget > QWidget {{ background: transparent; border: none; }}
    QSplitter::handle {{ background: {p.border}; }}
    QSplitter::handle:horizontal {{ width: 1px; }}
    QSplitter::handle:vertical {{ height: 1px; }}

    QFrame#Card {{ background: {p.surface}; border: 1px solid {p.border}; border-radius: {r + 4}px; }}
    QFrame#Panel {{ background: {p.surface}; border: none; }}
    QFrame#Rail {{ background: {p.rail}; border: none; }}
    QFrame#TopBar {{ background: {p.window}; border: none; border-bottom: 1px solid {p.border}; }}
    QFrame#StatusBar {{ background: {p.window}; border: none; border-top: 1px solid {p.border}; }}
    QFrame#Notice {{ background: {p.accent_soft}; border: 1px solid {p.border}; border-radius: {r}px; }}
    QFrame#NoticeWarn {{ background: {p.accent_soft}; border: 1px solid {p.accent}; border-radius: {r}px; }}
    QLabel#Notice {{ color: {p.text}; background: transparent; }}
    QProgressBar#Capacity {{ background: {p.surface_alt}; border: none; border-radius: 4px; min-height: 8px; max-height: 8px; color: transparent; }}
    QProgressBar#Capacity::chunk {{ background: {p.accent}; border-radius: 4px; }}
    QProgressBar#CapacityRail {{ background: rgba(255, 255, 255, 0.18); border: none; border-radius: 4px; min-height: 8px; max-height: 8px; color: transparent; }}
    QProgressBar#CapacityRail::chunk {{ background: {design.dark.accent}; border-radius: 4px; }}
    QFrame#Rule {{ background: {p.border}; border: none; max-height: 1px; min-height: 1px; }}

    QLabel {{ background: transparent; }}
    QLabel#Title {{ font-size: 26px; font-weight: 600; {heading} }}
    QLabel#Display {{ font-size: 34px; font-weight: 600; {heading} }}
    QLabel#Section {{ font-size: 18px; font-weight: 600; {heading} }}
    QLabel#Eyebrow {{ color: {p.muted}; font-size: 12px; font-weight: 600; }}
    QLabel#Muted {{ color: {p.muted}; }}
    QLabel#Meta {{ color: {p.muted}; {meta} }}
    QLabel#Error {{ color: {p.danger}; }}
    QLabel#Warning {{ color: {p.warning}; }}
    QLabel#Success {{ color: {p.success}; }}
    QLabel#RailText {{ color: {tab_rail}; font-size: 12px; }}
    QLabel#Empty {{ color: {p.muted}; font-size: 15px; }}

    QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox, QPlainTextEdit {{
        background: {p.surface}; border: 1px solid {p.border}; border-radius: {r}px;
        padding: 9px 11px; selection-background-color: {p.accent}; selection-color: {p.on_accent};
    }}
    QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QDoubleSpinBox:focus, QPlainTextEdit:focus {{ border: 2px solid {p.accent}; padding: 8px 10px; }}
    QLineEdit:disabled {{ color: {p.muted}; background: {p.surface_alt}; }}
    QComboBox::drop-down {{ border: none; width: 28px; }}
    QComboBox::down-arrow {{ image: url({chevron}); width: 14px; height: 14px; }}
    QFrame#SearchBox {{ background: {p.surface}; border: 1px solid {p.border}; border-radius: {r}px; }}
    QFrame#SearchBox[focused="true"] {{ border: 1px solid {p.accent}; }}
    QFrame#SearchBox QLineEdit {{ background: transparent; border: none; padding: 8px 4px; }}
    QFrame#SearchBox QLineEdit:focus {{ border: none; padding: 8px 4px; }}
    QComboBox QAbstractItemView {{
        background: {p.surface}; border: 1px solid {p.border};
        selection-background-color: {p.selection}; selection-color: {p.text}; outline: none;
    }}

    QPushButton, QToolButton {{
        background: {p.surface}; border: 1px solid {p.border}; border-radius: {r}px;
        padding: 9px 14px; font-weight: 500; min-height: 22px;
    }}
    QPushButton:hover, QToolButton:hover {{ background: {p.surface_alt}; }}
    QPushButton:pressed, QToolButton:pressed {{ background: {p.selection}; }}
    QPushButton:focus, QToolButton:focus {{ border: 2px solid {p.accent}; padding: 8px 13px; }}
    QPushButton:disabled, QToolButton:disabled {{ color: {p.muted}; background: {p.surface_alt}; }}
    QPushButton#Primary {{ background: {p.accent}; color: {p.on_accent}; border: 1px solid {p.accent}; font-weight: 600; }}
    QPushButton#Primary:hover {{ background: {p.accent}; border: 2px solid {p.text}; padding: 8px 13px; }}
    QPushButton#Primary:disabled {{ background: {p.surface_alt}; color: {p.muted}; border: 1px solid {p.border}; }}
    QToolButton#PrimaryTool {{ background: {p.accent}; color: {p.on_accent}; border: 1px solid {p.accent}; font-weight: 600; }}
    QToolButton#PrimaryTool:hover {{ border: 2px solid {p.text}; padding: 8px 13px; }}
    QPushButton#Danger {{ color: {p.danger}; border: 1px solid {p.danger}; background: transparent; }}
    QPushButton#Danger:hover {{ background: {p.surface_alt}; }}
    QPushButton#Link, QToolButton#Link {{ background: transparent; border: none; padding: 8px 9px; color: {p.text}; }}
    QPushButton#Link:hover, QToolButton#Link:hover {{ background: {p.surface_alt}; }}
    QPushButton#Crumb {{ background: transparent; border: none; padding: 5px 6px; color: {p.muted}; font-weight: 500; }}
    QPushButton#Crumb:hover {{ color: {p.text}; background: {p.surface_alt}; }}
    QPushButton#CrumbCurrent {{ background: transparent; border: none; padding: 5px 6px; color: {p.text}; font-weight: 600; }}
    QPushButton#Chip {{ border-radius: {max(r, 10)}px; padding: 6px 13px; background: transparent; }}
    QPushButton#Chip:checked {{ background: {p.accent}; color: {p.on_accent}; border: 1px solid {p.accent}; }}
    QFrame#SegmentedContainer {{ background: {p.surface_alt}; border: 1px solid {p.border}; border-radius: {r + 2}px; }}
    QPushButton#Segmented {{ border: 1px solid transparent; border-radius: {r}px; padding: 6px 14px; background: transparent; font-weight: 500; }}
    QPushButton#Segmented:checked {{ background: {p.surface}; color: {p.text}; border: 1px solid {p.border}; font-weight: 600; }}
    QPushButton#Segmented:hover:!checked {{ background: rgba(128, 128, 128, 0.12); }}
    QFrame#TotpCard {{ background: {p.surface_alt}; border: 1px solid {p.border}; border-radius: {r + 2}px; }}
    QLabel#TotpToken {{ font-family: "JetBrains Mono", "Consolas", monospace; font-size: 26px; font-weight: 700; letter-spacing: 3px; color: {p.accent}; }}
    QFrame#SidebarPane {{ background: {p.surface}; border-right: 1px solid {p.border}; }}
    QFrame#EntryCard {{ background: {p.surface}; border: 1px solid {p.border}; border-radius: {r}px; }}
    QFrame#EntryCard:hover {{ background: {p.surface_alt}; border-color: {p.muted}; }}
    QFrame#StatCard {{ background: {p.surface_alt}; border: 1px solid {p.border}; border-radius: {r}px; }}
    QFrame#ActionCard {{ background: {p.surface}; border: 1px solid {p.border}; border-radius: {r + 4}px; }}
    QFrame#ActionCard:hover {{ background: {p.surface_alt}; border: 1px solid {p.accent}; }}
    QPushButton#ActionCardButton {{
        text-align: left; background: {p.surface}; border: 1px solid {p.border};
        border-radius: {r + 3}px; padding: 12px 14px;
    }}
    QPushButton#ActionCardButton:hover {{ background: {p.surface_alt}; border: 1px solid {p.accent}; }}
    QPushButton#ActionCardButton:focus {{ border: 2px solid {p.accent}; padding: 11px 13px; }}
    QPushButton#RecentVaultCard {{
        text-align: left; background: {p.surface}; border: 1px solid {p.border};
        border-radius: {r}px; padding: 10px 14px;
    }}
    QPushButton#RecentVaultCard:hover {{ background: {p.surface_alt}; border: 1px solid {p.accent}; }}
    QPushButton#RecentVaultCard:focus {{ border: 2px solid {p.accent}; padding: 9px 13px; }}
    QFrame#SecurityBadgeCard {{ background: {p.accent_soft}; border: 1px solid {p.border}; border-radius: {r}px; }}
    QToolButton#RailButton {{
        background: transparent; border: none; border-radius: {r}px; padding: 9px 4px; color: {tab_rail}; font-size: 12px;
    }}
    QToolButton#RailButton:hover {{ background: rgba(128, 128, 128, 0.25); }}
    QToolButton#RailButton:focus {{ border: 2px solid {tab_rail}; padding: 7px 2px; }}
    QPushButton#RailItem {{
        background: transparent; border: none; color: {tab_rail}; text-align: left; padding: 8px 10px; font-weight: 400;
    }}
    QPushButton#RailItem:hover {{ background: rgba(255, 255, 255, 0.10); }}
    QPushButton#RailItem:checked {{ background: rgba(255, 255, 255, 0.18); font-weight: 600; }}
    QPushButton#RailItem:focus {{ border: 2px solid {tab_rail}; padding: 6px 8px; }}
    QLabel#RailTitle {{ color: {tab_rail}; font-size: 17px; font-weight: 600; }}
    QLabel#RailHead {{ color: {tab_rail}; font-size: 12px; font-weight: 600; }}
    QPushButton#Swatch {{ border-radius: {r}px; padding: 9px 12px; }}
    QPushButton#Swatch:checked {{ border: 2px solid {p.text}; padding: 8px 11px; font-weight: 600; }}
    QPushButton#DesignCard {{ text-align: left; padding: 10px; background: {p.surface}; }}
    QPushButton#DesignCard:checked {{ border: 2px solid {p.accent}; padding: 9px; }}
    QPushButton#RecentVault {{ text-align: left; background: transparent; }}

    QTabWidget::pane {{ background: {p.surface}; border: 1px solid {p.border}; border-radius: {r}px; top: -1px; }}
    QTabBar {{ background: transparent; }}
    QTabBar::tab {{
        background: transparent; color: {p.muted}; border: 1px solid transparent; border-bottom: none;
        border-top-left-radius: {r}px; border-top-right-radius: {r}px; padding: 9px 18px; margin-right: 4px; font-weight: 500;
    }}
    QTabBar::tab:hover {{ background: {p.surface_alt}; color: {p.text}; }}
    QTabBar::tab:selected {{ background: {p.surface}; color: {p.text}; border-color: {p.border}; font-weight: 600; }}
    QTabBar::tab:focus {{ color: {p.accent}; }}

    QCheckBox {{ spacing: 9px; padding: 6px 0; }}
    QCheckBox::indicator {{
        width: 18px; height: 18px; border: 1px solid {p.muted}; border-radius: {min(r, 5)}px; background: {p.surface};
    }}
    QCheckBox::indicator:checked {{ background: {p.accent}; border: 1px solid {p.accent}; image: url({check}); }}
    QCheckBox:focus {{ color: {p.accent}; }}

    QTreeWidget, QListWidget {{
        background: {p.surface}; border: none; outline: none; show-decoration-selected: 0;
    }}
    QTreeWidget#Folders, QListWidget#Grid {{ background: transparent; }}
    QTreeWidget::item {{ padding: 6px 4px; }}
    QTreeWidget::item:hover {{ background: {p.surface_alt}; }}
    QTreeWidget::item:selected {{ background: {p.selection}; color: {p.text}; }}
    QTreeWidget::branch:selected, QTreeWidget::branch:hover {{ background: transparent; }}
    QTreeWidget#Folders::item {{ border-radius: {min(r, 6)}px; }}
    QHeaderView {{ background: transparent; }}
    QHeaderView::section {{
        background: {p.surface}; color: {p.muted}; border: none; border-bottom: 1px solid {p.border};
        padding: 8px 6px; font-size: 13px; font-weight: 600;
    }}
    QTreeWidget#Files::item {{ padding: {"9px 4px" if design.layout == "ledger" else "6px 4px"}; {f"border-bottom: 1px solid {p.border};" if design.layout == "ledger" else ""} }}

    QProgressBar {{
        background: {p.surface_alt}; border: none; border-radius: 3px; max-height: 6px; min-height: 6px; color: transparent;
    }}
    QProgressBar::chunk {{ background: {p.accent}; border-radius: 3px; }}

    QScrollBar:vertical {{ background: transparent; width: 11px; margin: 0; }}
    QScrollBar::handle:vertical {{ background: {p.border}; border-radius: 4px; min-height: 28px; margin: 2px; }}
    QScrollBar:horizontal {{ background: transparent; height: 11px; margin: 0; }}
    QScrollBar::handle:horizontal {{ background: {p.border}; border-radius: 4px; min-width: 28px; margin: 2px; }}
    QScrollBar::add-line, QScrollBar::sub-line, QScrollBar::add-page, QScrollBar::sub-page {{ background: none; border: none; width: 0; height: 0; }}

    QMenu {{ background: {p.surface}; border: 1px solid {p.border}; padding: 5px; }}
    QMenu::item {{ padding: 8px 26px 8px 14px; border-radius: {min(r, 5)}px; }}
    QMenu::item:selected {{ background: {p.selection}; color: {p.text}; }}
    QMenu::separator {{ height: 1px; background: {p.border}; margin: 5px 6px; }}
    QToolTip {{ background: {p.surface}; color: {p.text}; border: 1px solid {p.border}; padding: 5px; }}
    """
