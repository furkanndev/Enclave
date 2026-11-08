"""Enclave - Görsel gösterici ve slayt gösterisi. Görseller yalnızca RAM'e çözülür."""

import random
from typing import Any, Dict, List, Optional

from PyQt6.QtCore import (
    QEasingCurve, QPointF, QPropertyAnimation, QSize, Qt, QThread, QTimer, QVariantAnimation, pyqtSignal,
)
from PyQt6.QtGui import QActionGroup, QColor, QIcon, QImage, QKeySequence, QPainter, QPixmap, QShortcut
from PyQt6.QtWidgets import (
    QAbstractItemView, QApplication, QDialog, QGridLayout, QHBoxLayout, QListView, QListWidget, QListWidgetItem, QMenu,
    QSizePolicy, QVBoxLayout, QWidget,
)

from .i18n import tr
from . import designs, icons
from .common import Task, Theme, button, format_date, format_size, label
from .session import VaultSession

ROLE = Qt.ItemDataRole.UserRole
INK = "#F1F0FB"
STRIP_LIMIT = 16 * 1024 * 1024
SPEEDS = (2, 3, 5, 10, 20)
EFFECTS = (("Solma", "fade"), ("Yakınlaşma", "zoom"), ("Efektsiz", "none"))

def _stylesheet(theme: Theme) -> str:
    """Slayt sahnesi koyu kalır; yalnızca vurgu rengi seçilen temadan gelir."""
    accent = theme.design.dark.accent
    on_accent = theme.design.dark.on_accent
    soft = QColor(accent)
    tint = f"rgba({soft.red()}, {soft.green()}, {soft.blue()}, 0.38)"
    check = designs._asset_url("check_light.svg")
    return f"""
    QDialog#Slideshow {{ background: #0B0A0F; }}
    QWidget#SlideHeader, QWidget#SlideFooter {{ background: rgba(20, 19, 28, 0.94); }}
    QWidget#ZoomPill {{ background: rgba(20, 19, 28, 0.86); border: 1px solid rgba(255, 255, 255, 0.14); border-radius: 15px; }}
    QLabel#SlideCaption {{ color: #EDEBF7; font-size: 15px; font-weight: 600; }}
    QLabel#SlideMeta {{ color: #A9A6BD; font-size: 12px; }}
    QLabel#ZoomValue {{ color: {INK}; font-size: 12px; min-width: 40px; }}
    QPushButton {{
        background: rgba(255, 255, 255, 0.10); color: {INK}; border: 1px solid rgba(255, 255, 255, 0.14);
        border-radius: 10px; padding: 8px 14px;
    }}
    QPushButton:hover {{ background: rgba(255, 255, 255, 0.20); }}
    QPushButton#SlideIcon, QPushButton#SlideNav {{
        padding: 0; min-width: 40px; max-width: 40px; min-height: 40px; max-height: 40px; border-radius: 20px;
    }}
    QPushButton#SlideNav {{
        min-width: 52px; max-width: 52px; min-height: 52px; max-height: 52px; border-radius: 26px;
        background: rgba(20, 19, 28, 0.62);
    }}
    QPushButton#SlideNav:hover {{ background: rgba(255, 255, 255, 0.24); }}
    QPushButton#SlideIcon:checked {{ background: {tint}; border: 1px solid {accent}; }}
    QPushButton#SlideIcon::menu-indicator {{ image: none; width: 0; }}
    QPushButton#ZoomIcon {{
        padding: 0; min-width: 28px; max-width: 28px; min-height: 28px; max-height: 28px; border-radius: 14px;
        background: transparent; border: none;
    }}
    QPushButton#ZoomIcon:hover {{ background: rgba(255, 255, 255, 0.16); }}
    QPushButton#Primary {{
        background: {accent}; color: {on_accent}; border: 1px solid {accent}; font-weight: 600;
        min-width: 96px; min-height: 40px; max-height: 40px; border-radius: 20px; padding: 0 20px;
    }}
    QPushButton#Primary:hover {{ background: {accent}; border: 2px solid {INK}; }}
    QMenu {{ background: #1B1A24; color: {INK}; border: 1px solid rgba(255, 255, 255, 0.14); padding: 6px; }}
    QMenu::item {{ padding: 7px 18px 7px 30px; border-radius: 6px; }}
    QMenu::item:selected {{ background: {tint}; }}
    QMenu::item:disabled {{ color: #A9A6BD; font-size: 12px; }}
    QMenu::separator {{ height: 1px; background: rgba(255, 255, 255, 0.12); margin: 5px 6px; }}
    QMenu::indicator {{ width: 14px; height: 14px; left: 8px; }}
    QMenu::indicator:checked {{ image: url({check}); }}
    QListWidget#SlideStrip {{ background: transparent; border: none; outline: none; }}
    QListWidget#SlideStrip::item {{ border: 2px solid transparent; border-radius: 8px; background: transparent; }}
    QListWidget#SlideStrip::item:selected {{ border: 2px solid {accent}; background: transparent; }}
    QListWidget#SlideStrip::item:hover {{ background: rgba(255, 255, 255, 0.08); }}
    """

class ImageCanvas(QWidget):
    """
    Görseli çizer: sığdırma, yakınlaştırma (tekerlek), sürükleyerek kaydırma, döndürme ve geçiş animasyonu.
    Tek tık clicked sinyali verir (çift tıkla karışmasın diye çift tık aralığı kadar beklenir).
    """

    zoom_changed = pyqtSignal(float)
    clicked = pyqtSignal()
    MIN_ZOOM = 0.2
    MAX_ZOOM = 10.0

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.setMinimumSize(200, 150)
        self.setAccessibleName(tr("Görsel"))
        self.effect = "fade"
        self._pixmap: Optional[QPixmap] = None
        self._rotation = 0
        self._zoom = 1.0
        self._pan = QPointF()
        self._drag: Optional[tuple] = None
        self._press: Optional[QPointF] = None
        self._moved = False
        self._progress = 1.0
        self._anim = QVariantAnimation(self)
        self._anim.setDuration(360)
        self._anim.setStartValue(0.0)
        self._anim.setEndValue(1.0)
        self._anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._anim.valueChanged.connect(self._on_progress)
        self._click_timer = QTimer(self)
        self._click_timer.setSingleShot(True)
        self._click_timer.timeout.connect(self.clicked.emit)

    def _on_progress(self, value: float) -> None:
        self._progress = float(value)
        self.update()

    def show_pixmap(self, pixmap: QPixmap, animate: bool = True) -> None:
        self._pixmap = pixmap
        self._rotation = 0
        self._zoom = 1.0
        self._pan = QPointF()
        self._anim.stop()
        if animate and self.effect != "none":
            self._progress = 0.0
            self._anim.start()
        else:
            self._progress = 1.0
        self.update()
        self.zoom_changed.emit(self.percent())

    def clear(self) -> None:
        self._anim.stop()
        self._click_timer.stop()
        self._pixmap = None
        self.update()

    def _fit(self) -> float:
        if self._pixmap is None:
            return 1.0
        width, height = self._pixmap.width(), self._pixmap.height()
        if self._rotation % 180:
            width, height = height, width
        return min(self.width() / width, self.height() / height) if width and height else 1.0

    def percent(self) -> float:
        return self._fit() * self._zoom * 100

    def is_zoomed(self) -> bool:
        return abs(self._zoom - 1.0) > 0.01

    def set_zoom(self, zoom: float) -> None:
        self._zoom = max(self.MIN_ZOOM, min(self.MAX_ZOOM, zoom))
        if self._zoom <= 1.0:
            self._pan = QPointF()
        self.update()
        self.zoom_changed.emit(self.percent())

    def zoom_by(self, factor: float) -> None:
        self.set_zoom(self._zoom * factor)

    def reset_view(self) -> None:
        self.set_zoom(1.0)

    def actual_size(self) -> None:
        self.set_zoom(1.0 / self._fit())

    def rotate(self, degrees: int) -> None:
        self._rotation = (self._rotation + degrees) % 360
        self._pan = QPointF()
        self.update()
        self.zoom_changed.emit(self.percent())

    def paintEvent(self, _event) -> None:
        if self._pixmap is None:
            return
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        grow = 0.9 + 0.1 * self._progress if self.effect == "zoom" else 1.0
        scale = self._fit() * self._zoom * grow
        painter.setOpacity(self._progress)
        painter.translate(self.width() / 2 + self._pan.x(), self.height() / 2 + self._pan.y())
        painter.rotate(self._rotation)
        painter.scale(scale, scale)
        painter.drawPixmap(QPointF(-self._pixmap.width() / 2, -self._pixmap.height() / 2), self._pixmap)

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        self.zoom_changed.emit(self.percent())

    def wheelEvent(self, event) -> None:
        self.zoom_by(1.15 ** (event.angleDelta().y() / 120))

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self._press = event.position()
            self._moved = False
            if self._zoom > 1.0:
                self._drag = (event.position(), QPointF(self._pan))

    def mouseMoveEvent(self, event) -> None:
        if self._press is not None and (event.position() - self._press).manhattanLength() > 4:
            self._moved = True
        if self._drag is not None:
            start, pan = self._drag
            self._pan = pan + (event.position() - start)
            self.update()

    def mouseReleaseEvent(self, event) -> None:
        self._drag = None
        if event.button() == Qt.MouseButton.LeftButton and self._press is not None and not self._moved:
            self._click_timer.start(QApplication.doubleClickInterval())
        self._press = None

    def mouseDoubleClickEvent(self, _event) -> None:
        self._click_timer.stop()
        self.reset_view() if self.is_zoomed() else self.actual_size()

class _StripLoader(QThread):
    """Alttaki şerit için küçük resimleri sırayla çözer; yalnızca RAM'de tutulur."""

    ready = pyqtSignal(str, QImage)

    def __init__(self, session: VaultSession, entries: List[Dict[str, Any]], parent: QWidget):
        super().__init__(parent)
        self._session = session
        self._entries = entries
        self._stopped = False

    def stop(self) -> None:
        self._stopped = True

    def run(self) -> None:
        for entry in self._entries:
            if self._stopped:
                return
            if entry.get("size", 0) > STRIP_LIMIT:
                continue
            try:
                image = QImage.fromData(self._session.read_preview(entry["id"]))
            except Exception:
                continue
            if not image.isNull() and not self._stopped:
                self.ready.emit(entry["id"], image.scaled(
                    192, 144, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation))

class SlideshowDialog(QDialog):
    """
    Koyu sahnede görsel; iki yanda dikey ortalı oklar, üstte başlık, döndürme, ayarlar ve tam ekran,
    altta önizleme şeridi ve oynatma denetimleri. Resme tek tıklayınca tüm denetimler gizlenir (tam ekrana geçmez),
    yeniden tıklayınca geri gelir. Yakınlaştırma düğmeleri yalnızca yakınlaştırılmış görselde belirir.
    Başlat'a basınca yalnızca görsel kalır; Boşluk ya da Esc durdurur.
    Kısayollar: Sol/Sağ geçiş, Boşluk başlat/durdur, F tam ekran, Home/End baş/son, +/- yakınlaştır, 0 sığdır,
    1 gerçek boyut, R/Shift+R döndür, S karıştır, L döngü.
    """

    def __init__(self, session: VaultSession, entries: List[Dict[str, Any]], start: int, thumbs: Dict[str, QPixmap],
                 theme: Theme, autoplay: bool = False, parent=None):
        super().__init__(parent)
        self.setObjectName("Slideshow")
        self.setWindowTitle(tr("Slayt gösterisi"))
        self.setStyleSheet(_stylesheet(theme))
        self.session = session
        self.entries = entries
        self.index = start
        self.theme = theme
        self.seconds = 3
        self._tasks: List[Task] = []
        self._pixmap: Optional[QPixmap] = None
        self._token = 0
        self._closing = False
        self._cleaned = False
        self._intro_played = False
        self._chrome_hidden = False
        self._animations: List[QPropertyAnimation] = []
        self._rows = {entry["id"]: row for row, entry in enumerate(entries)}

        self.canvas = ImageCanvas()
        self.canvas.zoom_changed.connect(self._on_zoom_changed)
        self.canvas.clicked.connect(self._toggle_chrome)

        self.previous_arrow = self._icon_button("chevron-left", tr("Önceki görsel"), self.previous, "SlideNav", 24)
        self.next_arrow = self._icon_button("chevron-right", tr("Sonraki görsel"), self.next, "SlideNav", 24)
        self.zoom_label = label("%100", "ZoomValue", wrap=False)
        self.zoom_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.zoom_pill = QWidget()
        self.zoom_pill.setObjectName("ZoomPill")
        pill = QHBoxLayout(self.zoom_pill)
        pill.setContentsMargins(4, 2, 4, 2)
        pill.setSpacing(0)
        pill.addWidget(self._icon_button("zoom-out", tr("Uzaklaştır (-)"), lambda: self.canvas.zoom_by(1 / 1.25), "ZoomIcon", 16))
        pill.addWidget(self.zoom_label)
        pill.addWidget(self._icon_button("zoom-in", tr("Yakınlaştır (+)"), lambda: self.canvas.zoom_by(1.25), "ZoomIcon", 16))
        self.zoom_holder = QWidget()
        holder = QHBoxLayout(self.zoom_holder)
        holder.setContentsMargins(0, 0, 4, 14)
        holder.addWidget(self.zoom_pill)
        self.zoom_holder.hide()

        stage = QGridLayout()
        stage.setContentsMargins(22, 0, 22, 0)
        stage.addWidget(self.canvas, 0, 0)
        stage.addWidget(self.previous_arrow, 0, 0, Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        stage.addWidget(self.next_arrow, 0, 0, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        stage.addWidget(self.zoom_holder, 0, 0, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignBottom)

        self.caption = label(name="SlideCaption", wrap=False)
        self.meta = label(name="SlideMeta", wrap=False)
        self.settings_button = self._icon_button("settings", tr("Slayt ayarları"), None)
        self.settings_button.setMenu(self._build_settings_menu())
        self.header = QWidget()
        self.header.setObjectName("SlideHeader")
        titles = QVBoxLayout()
        titles.setSpacing(2)
        titles.addWidget(self.caption)
        titles.addWidget(self.meta)
        head = QHBoxLayout(self.header)
        head.setContentsMargins(20, 12, 20, 12)
        head.setSpacing(8)
        head.addLayout(titles, 1)
        head.addWidget(self._icon_button("rotate-left", tr("Sola döndür (Shift+R)"), lambda: self.canvas.rotate(-90)))
        head.addWidget(self._icon_button("rotate-right", tr("Sağa döndür (R)"), lambda: self.canvas.rotate(90)))
        head.addWidget(self.settings_button)
        head.addWidget(self._icon_button("fullscreen", tr("Tam ekran (F)"), self.toggle_fullscreen))

        self.strip = QListWidget()
        self.strip.setObjectName("SlideStrip")
        self.strip.setFlow(QListView.Flow.LeftToRight)
        self.strip.setWrapping(False)
        self.strip.setIconSize(QSize(96, 72))
        self.strip.setFixedHeight(104)
        self.strip.setAccessibleName(tr("Diğer görseller"))
        self.strip.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        for entry in entries:
            item = QListWidgetItem("")
            item.setSizeHint(QSize(104, 84))
            item.setData(ROLE, entry["id"])
            item.setToolTip(entry["path"].rsplit("/", 1)[-1])
            if entry["id"] in thumbs:
                item.setIcon(QIcon(thumbs[entry["id"]]))
            self.strip.addItem(item)
        self.strip.itemClicked.connect(lambda item: self.show_index(self.strip.row(item)))

        self.shuffle = self._icon_button("shuffle", tr("Karıştır (S)"), None)
        self.loop = self._icon_button("repeat", tr("Başa dön (L)"), None)
        for toggle in (self.shuffle, self.loop):
            toggle.setCheckable(True)
        self.loop.setChecked(True)
        self.play_button = button(tr("Başlat"), "Primary", self.toggle_play)
        self.play_button.setIcon(icons.icon("play", theme.design.dark.on_accent, 18))
        self.previous_button = self._icon_button("chevron-left", tr("Önceki (←)"), self.previous)
        self.next_button = self._icon_button("chevron-right", tr("Sonraki (→)"), self.next)

        controls = QHBoxLayout()
        controls.setSpacing(10)
        controls.addStretch(1)
        for widget in (self.shuffle, self.previous_button, self.play_button, self.next_button, self.loop):
            controls.addWidget(widget)
        controls.addStretch(1)

        self.footer = QWidget()
        self.footer.setObjectName("SlideFooter")
        foot = QVBoxLayout(self.footer)
        foot.setContentsMargins(20, 10, 20, 14)
        foot.setSpacing(10)
        foot.addWidget(self.strip)
        foot.addLayout(controls)

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        root.addWidget(self.header)
        root.addLayout(stage, 1)
        root.addWidget(self.footer)
        for widget in self.findChildren(QWidget):
            if widget is not self.canvas:
                widget.setFocusPolicy(Qt.FocusPolicy.NoFocus)

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.next)
        shortcuts = (
            (Qt.Key.Key_Right, self.next), (Qt.Key.Key_Left, self.previous), (Qt.Key.Key_Space, self.toggle_play),
            (Qt.Key.Key_F, self.toggle_fullscreen), (Qt.Key.Key_F11, self.toggle_fullscreen),
            (Qt.Key.Key_Home, lambda: self.show_index(0)), (Qt.Key.Key_End, lambda: self.show_index(len(self.entries) - 1)),
            (Qt.Key.Key_Plus, lambda: self.canvas.zoom_by(1.25)), (Qt.Key.Key_Equal, lambda: self.canvas.zoom_by(1.25)),
            (Qt.Key.Key_Minus, lambda: self.canvas.zoom_by(1 / 1.25)), (Qt.Key.Key_0, self.canvas.reset_view),
            (Qt.Key.Key_1, self.canvas.actual_size), (Qt.Key.Key_R, lambda: self.canvas.rotate(90)),
            ("Shift+R", lambda: self.canvas.rotate(-90)), (Qt.Key.Key_S, self.shuffle.toggle),
            (Qt.Key.Key_L, self.loop.toggle),
        )
        for key, handler in shortcuts:
            shortcut = QShortcut(QKeySequence(key), self)
            shortcut.setContext(Qt.ShortcutContext.WindowShortcut)
            shortcut.activated.connect(handler)

        self.resize(1180, 800)
        self.show_index(start)
        pending = [e for e in entries if e["id"] not in thumbs]
        self._loader: Optional[_StripLoader] = None
        if pending:
            self._loader = _StripLoader(session, pending, self)
            self._loader.ready.connect(self._on_strip_thumb)
            self._loader.start()
        if autoplay:
            self.toggle_play()

    def _icon_button(self, name: str, tip: str, on_click, object_name: str = "SlideIcon", size: int = 20):
        widget = button("", object_name, on_click, icons.icon(name, INK, size))
        widget.setIconSize(QSize(size, size))
        widget.setToolTip(tip)
        widget.setAccessibleName(tip)
        return widget

    def _build_settings_menu(self) -> QMenu:
        """Geçiş süresi ve animasyon şekli; seçim bu pencere açık kaldıkça geçerlidir."""
        menu = QMenu(self)
        speed_group = QActionGroup(menu)
        menu.addAction(tr("Geçiş süresi")).setEnabled(False)
        for seconds in SPEEDS:
            action = menu.addAction(f"{seconds} saniye")
            action.setCheckable(True)
            action.setChecked(seconds == self.seconds)
            speed_group.addAction(action)
            action.triggered.connect(lambda _c=False, s=seconds: self._set_seconds(s))
        menu.addSeparator()
        effect_group = QActionGroup(menu)
        menu.addAction(tr("Animasyon")).setEnabled(False)
        for title, key in EFFECTS:
            action = menu.addAction(title)
            action.setCheckable(True)
            action.setChecked(key == "fade")
            effect_group.addAction(action)
            action.triggered.connect(lambda _c=False, k=key: setattr(self.canvas, "effect", k))
        return menu

    def _set_seconds(self, seconds: int) -> None:
        self.seconds = seconds
        if self.timer.isActive():
            self.timer.start(seconds * 1000)

    def show_index(self, index: int) -> None:
        self.index = index % len(self.entries)
        entry = self.entries[self.index]
        name = entry["path"].rsplit("/", 1)[-1]
        self.strip.setCurrentRow(self.index)
        self.strip.scrollToItem(self.strip.item(self.index), QAbstractItemView.ScrollHint.PositionAtCenter)
        self.caption.setText(f"{self.index + 1} / {len(self.entries)}   ·   {name}")
        self.meta.setText(f"{format_size(entry.get('size', 0))}   ·   {format_date(entry.get('mtime'))}")
        self._token += 1
        token = self._token
        session, file_id = self.session, entry["id"]
        task = Task(lambda _p, _c: QImage.fromData(session.read_preview(file_id)), self)
        task.succeeded.connect(lambda image: self._on_image(token, image))
        task.failed.connect(self.meta.setText)
        task.finished.connect(lambda: self._tasks.remove(task))
        self._tasks.append(task)
        task.start()

    def _on_image(self, token: int, image: QImage) -> None:
        if token != self._token or image.isNull():
            return
        self._pixmap = QPixmap.fromImage(image)
        entry = self.entries[self.index]
        self.meta.setText(
            f"{image.width()} × {image.height()}   ·   {format_size(entry.get('size', 0))}   ·   "
            f"{format_date(entry.get('mtime'))}"
        )
        item = self.strip.item(self.index)
        if item.icon().isNull():
            item.setIcon(QIcon(self._pixmap.scaled(192, 144, Qt.AspectRatioMode.KeepAspectRatio)))
        self.canvas.show_pixmap(self._pixmap)

    def _on_strip_thumb(self, file_id: str, image: QImage) -> None:
        row = self._rows.get(file_id)
        item = self.strip.item(row) if row is not None else None
        if item is not None and item.icon().isNull():
            item.setIcon(QIcon(QPixmap.fromImage(image)))

    def _on_zoom_changed(self, percent: float) -> None:
        self.zoom_label.setText(f"%{int(round(percent))}")
        self._update_chrome()

    def next(self) -> None:
        self._step(1)

    def previous(self) -> None:
        self._step(-1)

    def _step(self, direction: int) -> None:
        count = len(self.entries)
        if self.shuffle.isChecked() and direction > 0 and count > 1:
            self.show_index(random.choice([i for i in range(count) if i != self.index]))
            return
        target = self.index + direction
        if not self.loop.isChecked() and not 0 <= target < count:
            if self.timer.isActive():
                self._stop()
            return
        self.show_index(target)

    def toggle_play(self) -> None:
        if self.timer.isActive():
            self._stop()
        else:
            self.timer.start(self.seconds * 1000)
            self._set_playing(True)

    def _stop(self) -> None:
        self.timer.stop()
        self._chrome_hidden = False
        self._set_playing(False)

    def _set_playing(self, playing: bool) -> None:
        self.setCursor(Qt.CursorShape.BlankCursor if playing else Qt.CursorShape.ArrowCursor)
        self.play_button.setText(tr("Durdur") if playing else tr("Başlat"))
        self.play_button.setIcon(icons.icon("pause" if playing else "play", self.theme.design.dark.on_accent, 18))
        self._update_chrome()

    def _toggle_chrome(self) -> None:
        """Resme tek tık: tüm denetimleri gizler ya da geri getirir. Tam ekrana geçmez."""
        if self.timer.isActive():
            return
        self._chrome_hidden = not self._chrome_hidden
        self._update_chrome()

    def _update_chrome(self) -> None:
        """Oynarken ya da gizliyken yalnızca görsel kalır. Yakınlaştırma düğmeleri yalnızca yakınlaştırılmışken görünür."""
        show = not (self.timer.isActive() or self._chrome_hidden)
        for widget in (self.header, self.footer, self.previous_arrow, self.next_arrow):
            widget.setVisible(show)
        self.zoom_holder.setVisible(show and self.canvas.is_zoomed())

    def toggle_fullscreen(self) -> None:
        self.showNormal() if self.isFullScreen() else self.showFullScreen()

    def _fade_window(self, start: float, end: float, duration: int, finished=None) -> None:
        animation = QPropertyAnimation(self, b"windowOpacity", self)
        animation.setDuration(duration)
        animation.setStartValue(start)
        animation.setEndValue(end)
        animation.setEasingCurve(QEasingCurve.Type.OutCubic)
        if finished:
            animation.finished.connect(finished)
        self._animations.append(animation)
        animation.start()

    def showEvent(self, event) -> None:
        super().showEvent(event)
        if not self._intro_played:
            self._intro_played = True
            self.setWindowOpacity(0.0)
            self._fade_window(0.0, 1.0, 320)

    def reject(self) -> None:
        """Esc: oynarken yalnızca durdurur, tam ekrandaysa küçültür, aksi halde solarak kapanır."""
        if self.timer.isActive():
            self._stop()
        elif self.isFullScreen():
            self.showNormal()
        elif self._closing or not self.isVisible():
            super().reject()
        else:
            self._closing = True
            self._fade_window(self.windowOpacity(), 0.0, 180, lambda: QDialog.reject(self))

    def _cleanup(self) -> None:
        if self._cleaned:
            return
        self._cleaned = True
        self.timer.stop()
        if self._loader is not None:
            self._loader.stop()
            self._loader.wait()
        for task in list(self._tasks):
            task.wait()
        self._pixmap = None
        self.canvas.clear()

    def done(self, result: int) -> None:
        self._cleanup()
        super().done(result)

    def closeEvent(self, event) -> None:
        super().closeEvent(event)
        if event.isAccepted():
            self._cleanup()
