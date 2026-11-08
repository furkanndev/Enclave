"""Enclave - Arayüz bileşenlerinin ortak parçaları."""

import math
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional

from PyQt6.QtCore import QEvent, QMimeData, QPointF, QRectF, QThread, QTimer, Qt, pyqtSignal
from PyQt6.QtGui import QColor, QIcon, QPainter, QPen, QPixmap
from PyQt6.QtWidgets import (
    QApplication, QFrame, QHBoxLayout, QLabel, QLineEdit, QMessageBox, QProgressBar, QPushButton, QSizePolicy, QToolButton,
    QVBoxLayout, QWidget,
)

from config import load_config

from .i18n import tr
from . import designs, icons

@dataclass(frozen=True)
class Theme:
    design: designs.Design
    dark: bool

    @property
    def palette(self) -> designs.Palette:
        return self.design.dark if self.dark else self.design.light

    def icon(self, name: str, color: Optional[str] = None, size: int = 18) -> QIcon:
        return icons.icon(name, color or self.palette.text, size)

SECRET_CLIPBOARD_SECONDS = 30
_WINDOWS_MIME = 'application/x-qt-windows-mime;value="{}"'
_copied_secret = ""

def copy_secret(text: str) -> None:
    """Gizli metni panoya koyar, Windows pano geçmişi ve bulut eşitlemesi dışında tutar, süre dolunca siler."""
    global _copied_secret
    _copied_secret = text
    data = QMimeData()
    data.setText(text)
    data.setData(_WINDOWS_MIME.format("ExcludeClipboardContentFromMonitorProcessing"), b"\x01\x00\x00\x00")
    data.setData(_WINDOWS_MIME.format("CanIncludeInClipboardHistory"), b"\x00\x00\x00\x00")
    data.setData(_WINDOWS_MIME.format("CanUploadToCloudClipboard"), b"\x00\x00\x00\x00")
    QApplication.clipboard().setMimeData(data)
    QTimer.singleShot(SECRET_CLIPBOARD_SECONDS * 1000, clear_secret_clipboard)

def clear_secret_clipboard() -> None:
    """Kullanıcının sonradan kopyaladığı şeye dokunmaz; yalnızca bizim koyduğumuz gizli metni siler."""
    global _copied_secret
    if _copied_secret and QApplication.clipboard().text() == _copied_secret:
        QApplication.clipboard().clear()
    _copied_secret = ""

def resource_path(relative: str) -> Path:
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent))
    return base / relative

def app_icon() -> QIcon:
    """Uygulamanın mevcut simgesi; başka yerde üretilmez."""
    for candidate in ("assets/enclave_closed.png", "app_icon.ico"):
        path = resource_path(candidate)
        if path.exists():
            return QIcon(str(path))
    return QIcon()

def logo_label(size: int = 56) -> QLabel:
    label = QLabel()
    pixmap = app_icon().pixmap(size, size)
    label.setPixmap(pixmap)
    label.setAccessibleName(tr("Enclave simgesi"))
    return label

def format_size(size: int) -> str:
    value = float(size)
    for unit in ("bayt", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            text = f"{int(value)}" if unit == "bayt" else f"{value:.1f}".replace(".", ",")
            return f"{text} {unit}"
        value /= 1024
    return str(size)

def format_date(timestamp: Optional[int]) -> str:
    return time.strftime("%d.%m.%Y %H:%M", time.localtime(timestamp)) if timestamp else "-"

def label(text: str = "", name: str = "", wrap: bool = True) -> QLabel:
    widget = QLabel(text)
    if name:
        widget.setObjectName(name)
    widget.setWordWrap(wrap)
    return widget

def button(text: str, name: str = "", on_click: Optional[Callable] = None, icon_: Optional[QIcon] = None) -> QPushButton:
    widget = QPushButton(text)
    if name:
        widget.setObjectName(name)
    if icon_:
        widget.setIcon(icon_)
    if on_click:
        widget.clicked.connect(lambda _checked=False: on_click())
    widget.setCursor(Qt.CursorShape.PointingHandCursor)
    return widget

def tool_button(text: str, icon_: QIcon, on_click: Callable, tip: str = "", name: str = "") -> QToolButton:
    widget = QToolButton()
    widget.setText(text)
    widget.setIcon(icon_)
    widget.setIconSize(icons.icon_size(18))
    widget.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
    widget.setToolTip(tip or text)
    widget.setAccessibleName(text)
    widget.setCursor(Qt.CursorShape.PointingHandCursor)
    if name:
        widget.setObjectName(name)
    widget.clicked.connect(lambda _checked=False: on_click())
    return widget

def horizontal_rule() -> QFrame:
    rule = QFrame()
    rule.setObjectName("Rule")
    return rule

def confirm(parent: QWidget, title: str, text: str, action: str, danger: bool = True) -> bool:
    box = QMessageBox(parent)
    box.setWindowTitle(title)
    box.setText(text)
    box.setIcon(QMessageBox.Icon.Warning if danger else QMessageBox.Icon.Question)
    accept = box.addButton(action, QMessageBox.ButtonRole.DestructiveRole if danger else QMessageBox.ButtonRole.AcceptRole)
    cancel = box.addButton(tr("Vazgeç"), QMessageBox.ButtonRole.RejectRole)
    box.setDefaultButton(cancel)
    box.exec()
    return box.clickedButton() is accept

class Task(QThread):
    """Uzun işlemi arayüzü dondurmadan çalıştırır. İşlev progress(int) ve cancelled() geri çağrılarını alabilir."""

    succeeded = pyqtSignal(object)
    failed = pyqtSignal(str)
    advanced = pyqtSignal(int)

    def __init__(self, fn: Callable[..., Any], parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._fn = fn
        self._cancelled = False

    def cancel(self) -> None:
        self._cancelled = True

    def is_cancelled(self) -> bool:
        return self._cancelled

    def run(self) -> None:
        try:
            result = self._fn(self.advanced.emit, self.is_cancelled)
        except Exception as error:
            self.failed.emit(tr(str(error)))
        else:
            self.succeeded.emit(result)

class SearchBox(QFrame):
    """Simgeli arama kutusu. Klavye odağını çerçevede gösterir."""

    def __init__(self, theme: Theme, placeholder: str, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setObjectName("SearchBox")
        symbol = QLabel()
        symbol.setPixmap(icons.icon_pixmap("search", theme.palette.muted, 16))
        self.edit = QLineEdit()
        self.edit.setPlaceholderText(placeholder)
        self.edit.setAccessibleName(placeholder)
        self.edit.setClearButtonEnabled(True)
        self.edit.installEventFilter(self)
        row = QHBoxLayout(self)
        row.setContentsMargins(10, 0, 4, 0)
        row.setSpacing(4)
        row.addWidget(symbol)
        row.addWidget(self.edit, 1)
        self.setFocusProxy(self.edit)

    def eventFilter(self, watched, event) -> bool:
        if event.type() in (QEvent.Type.FocusIn, QEvent.Type.FocusOut):
            self.setProperty("focused", event.type() == QEvent.Type.FocusIn)
            self.style().unpolish(self)
            self.style().polish(self)
        return super().eventFilter(watched, event)

class PasswordField(QWidget):
    """Göster/gizle düğmeli parola alanı."""

    returnPressed = pyqtSignal()
    textChanged = pyqtSignal(str)

    def __init__(self, theme: Theme, placeholder: str = "", parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._theme = theme
        self.edit = QLineEdit()
        self.edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.edit.setPlaceholderText(placeholder)
        self.edit.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        self.edit.returnPressed.connect(self.returnPressed)
        self.edit.textChanged.connect(self.textChanged)
        self.toggle = QToolButton()
        self.toggle.setCheckable(True)
        self.toggle.setIconSize(icons.icon_size(18))
        self.toggle.setAccessibleName(tr("Parolayı göster"))
        self.toggle.setToolTip(tr("Parolayı göster"))
        self.toggle.toggled.connect(self._on_toggle)
        self._on_toggle(False)
        row = QHBoxLayout(self)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(6)
        row.addWidget(self.edit, 1)
        row.addWidget(self.toggle)
        self.setFocusProxy(self.edit)

    def _on_toggle(self, visible: bool) -> None:
        self.edit.setEchoMode(QLineEdit.EchoMode.Normal if visible else QLineEdit.EchoMode.Password)
        self.toggle.setIcon(self._theme.icon("eye-off" if visible else "eye"))

    def text(self) -> str:
        return self.edit.text()

    def setText(self, text: str) -> None:
        self.edit.setText(text)

    def clear(self) -> None:
        self.edit.clear()
        self.toggle.setChecked(False)

def with_default_suffix(path: str, suffix: str) -> str:
    """Uzantı yazılmamışsa varsayılanı ekler; kullanıcının verdiği ad ve uzantı aynen korunur."""
    if not path or Path(path).suffix:
        return path
    return path + suffix

class CapacityBar(QWidget):
    """Kasanın dolu ve boş alanı. Renkler etkin temadan gelir; rail=True koyu şerit üzerinde kullanılır."""

    def __init__(self, rail: bool = False, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.text = label(name="RailHead" if rail else "Meta")
        self.bar = QProgressBar()
        self.bar.setObjectName("CapacityRail" if rail else "Capacity")
        self.bar.setTextVisible(False)
        self.bar.setRange(0, 1000)
        self.bar.setAccessibleName(tr("Kasa doluluğu"))
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)
        layout.addWidget(self.text)
        layout.addWidget(self.bar)

    def set_values(self, used: int, total: Optional[int]) -> None:
        if not total:
            self.text.setText(tr("{} kullanıldı", format_size(used)))
            self.bar.setValue(0)
            return
        used = min(used, total)
        self.text.setText(tr("{} dolu  ·  {} boş  ·  {}", format_size(used), format_size(total - used), format_size(total)))
        self.bar.setValue(int(used * 1000 / total))

LOADERS = {
    "bars": "Dikey barlar", "ring": "Dönen halka", "dots": "Zıplayan noktalar",
    "pulse": "Nabız çizgisi", "scan": "Tarama şeridi",
}

class LoadingBars(QWidget):
    """Yükleme animasyonu. Biçim ayarlardan, renk ve köşe yuvarlaklığı etkin temadan gelir; yalnızca başlatılınca çalışır."""

    BARS = 3
    BAR_WIDTH = 12
    GAP = 8

    def __init__(self, theme: Theme, kind: str = "", parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setObjectName("LoadingBars")
        self.setFixedHeight(32)
        self.setMinimumWidth(84)
        self.setAccessibleName(tr("Yükleniyor"))
        self.kind = kind
        self._fixed = bool(kind)
        self._color = QColor(theme.palette.accent)
        self._radius = min(theme.design.radius, 5)
        self._phase = 0.0
        self._frame_width = 84
        self._timer = QTimer(self)
        self._timer.setInterval(33)
        self._timer.timeout.connect(self._tick)
        self.hide()

    def start(self) -> None:
        if not self._fixed:
            self.kind = load_config().get("loader", "bars")
        self._timer.start()
        self.show()

    def stop(self) -> None:
        self._timer.stop()
        self.hide()

    def advance(self) -> None:
        self._phase = (self._phase + 0.033) % 1.0

    def _tick(self) -> None:
        self.advance()
        self.update()

    def paint_frame(self, painter: QPainter, width: int, kind: str) -> None:
        """Bir kareyi verilen genişlikte çizer; açılır liste gibi başka yüzeyler de bunu kullanır."""
        self._frame_width = width
        painter.save()
        {"ring": self._ring, "dots": self._dots, "pulse": self._pulse, "scan": self._scan}.get(kind, self._bars)(painter)
        painter.restore()

    def paintEvent(self, _event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(Qt.PenStyle.NoPen)
        self.paint_frame(painter, self.width(), self.kind)
        painter.end()

    def _bars(self, painter: QPainter) -> None:
        total = self.BARS * self.BAR_WIDTH + (self.BARS - 1) * self.GAP
        left = (self._frame_width - total) / 2
        for index in range(self.BARS):
            wave = (math.sin(2 * math.pi * (self._phase - index * 0.2)) + 1) / 2
            height = 12 + 18 * wave
            color = QColor(self._color)
            color.setAlphaF(0.3 + 0.7 * wave)
            painter.setBrush(color)
            rect = QRectF(left + index * (self.BAR_WIDTH + self.GAP), (32 - height) / 2,
                          self.BAR_WIDTH, height)
            painter.drawRoundedRect(rect, self._radius, self._radius)

    def _ring(self, painter: QPainter) -> None:
        rect = QRectF(self._frame_width / 2 - 12, 4, 24, 24)
        track = QColor(self._color)
        track.setAlphaF(0.2)
        painter.setPen(QPen(track, 4))
        painter.drawEllipse(rect)
        painter.setPen(QPen(self._color, 4, cap=Qt.PenCapStyle.RoundCap))
        sweep = 60 + 180 * (math.sin(2 * math.pi * self._phase) + 1) / 2
        painter.drawArc(rect, int(-self._phase * 720 * 16), int(sweep * 16))

    def _dots(self, painter: QPainter) -> None:
        for index in range(5):
            wave = max(0.0, math.sin(2 * math.pi * (self._phase - index * 0.12)))
            color = QColor(self._color)
            color.setAlphaF(0.35 + 0.65 * wave)
            painter.setBrush(color)
            painter.drawEllipse(QPointF(self._frame_width / 2 + (index - 2) * 14, 23 - 14 * wave), 4.5, 4.5)

    def _pulse(self, painter: QPainter) -> None:
        width = min(self._frame_width, 120)
        left = (self._frame_width - width) / 2
        beats = ((0, 16), (0.3, 16), (0.38, 8), (0.46, 26), (0.54, 4), (0.62, 20), (0.7, 16), (1, 16))
        points = [QPointF(left + x * width, y) for x, y in beats]
        faint = QColor(self._color)
        faint.setAlphaF(0.2)
        painter.setPen(QPen(faint, 2))
        painter.drawPolyline(points)
        head = self._phase * 1.3 - 0.15
        pen = QPen(self._color, 2.5, cap=Qt.PenCapStyle.RoundCap, join=Qt.PenJoinStyle.RoundJoin)
        painter.setPen(pen)
        painter.setClipRect(QRectF(left + (head - 0.15) * width, 0, width * 0.3, 32), Qt.ClipOperation.IntersectClip)
        painter.drawPolyline(points)

    def _scan(self, painter: QPainter) -> None:
        width = min(self._frame_width, 150)
        left = (self._frame_width - width) / 2
        track = QColor(self._color)
        track.setAlphaF(0.18)
        painter.setBrush(track)
        painter.drawRoundedRect(QRectF(left, 12, width, 8), 4, 4)
        position = (math.sin(2 * math.pi * self._phase) + 1) / 2
        painter.setBrush(self._color)
        painter.drawRoundedRect(QRectF(left + position * (width - 44), 12, 44, 8), 4, 4)
