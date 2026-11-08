"""
Enclave - Dosya çalışma alanı.
Tüm davranış tek yerdedir; üç tasarım yalnızca parçaları farklı dizer.
Önizleme ve küçük resimler yalnızca RAM'de tutulur, diske yazılmaz.
"""

import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from PyQt6.QtCore import QRect, QRectF, QSize, Qt, QThread, QTimer, pyqtSignal
from PyQt6.QtGui import QColor, QFontMetrics, QIcon, QImage, QKeySequence, QPainter, QPainterPath, QPen, QPixmap, QShortcut
from PyQt6.QtWidgets import (
    QAbstractItemView, QButtonGroup, QFileDialog, QFrame, QGridLayout, QHBoxLayout, QHeaderView, QInputDialog, QLabel, QLineEdit,
    QListView, QListWidget, QListWidgetItem, QMenu, QMessageBox, QPlainTextEdit, QProgressBar, QPushButton,
    QScrollArea, QSizePolicy, QSplitter, QStackedWidget, QStyle, QStyledItemDelegate, QStyleOptionViewItem,
    QToolButton, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget,
)

from config import load_config
from enclave_core import CustomVaultError

from .i18n import tr
from . import designs, icons
from .dialogs import TwoFactorDialog
from .editor import TextEditorDialog, can_edit
from .motion import BackdropFrame
from .slideshow import SlideshowDialog
from .common import (
    CapacityBar, LoadingBars, SearchBox, Task, Theme, button, confirm, format_date, format_size, horizontal_rule, label, tool_button,
)
from .session import (
    IMAGE_EXTS, PREVIEW_LIMIT, TEXT_EXTS, VaultSession, cloud_provider, file_category,
    open_with_system,
)

ROLE = Qt.ItemDataRole.UserRole
THUMB_ROLE = Qt.ItemDataRole.UserRole + 2
BADGE_ROLE = Qt.ItemDataRole.UserRole + 3
META_ROLE = Qt.ItemDataRole.UserRole + 4
TAG_ROLE = Qt.ItemDataRole.UserRole + 5
BADGES = {
    "folder": ("#EEEDFE", "#3C3489", "folder"), "image": ("#FAECE7", "#712B13", "image"),
    "video": ("#FBEAF0", "#72243E", "video"), "audio": ("#EEEDFE", "#3C3489", "audio"),
    "document": ("#E1F5EE", "#085041", "document"), "text": ("#E6F1FB", "#0C447C", "text"),
    "archive": ("#FAEEDA", "#633806", "archive"), "file": ("#F1EFE8", "#444441", "file"),
}
THUMB_LIMIT = 40 * 1024 * 1024
FILTERS = (("Tümü", None), ("Görsel", "image"), ("Video", "video"), ("Ses", "audio"), ("Belge", "document"))
CATEGORY_LABELS = {
    "image": "Görsel", "video": "Video", "audio": "Ses", "document": "Belge",
    "archive": "Arşiv", "text": "Metin", "file": "Dosya",
}

class TileDelegate(QStyledItemDelegate):
    """Izgara kutusu: görsel kutuyu doldurur, ad altta tek satır görünür, seçim çerçeveyle belli olur."""

    INTRO_SECONDS = 0.38
    INTRO_STAGGER = 0.035

    def __init__(self, theme: Theme, tile: QSize, parent: QWidget):
        super().__init__(parent)
        self.theme = theme
        self.tile = tile
        self.animated = theme.design.animated
        self._levels: Dict[int, float] = {}
        self._intro_start = time.monotonic()
        self._last_paint = self._intro_start
        self._refresh_queued = False

    def reset_intro(self) -> None:
        """Kartlar yeniden doldurulunca animasyonlu stillerde sırayla belirir."""
        self._intro_start = time.monotonic()
        self._levels.clear()
        self._queue_refresh()

    def _queue_refresh(self) -> None:
        view = self.parent()
        if self.animated and not self._refresh_queued and isinstance(view, QAbstractItemView):
            self._refresh_queued = True
            QTimer.singleShot(16, self._refresh)

    def _refresh(self) -> None:
        self._refresh_queued = False
        view = self.parent()
        if isinstance(view, QAbstractItemView):
            view.viewport().update()

    def sizeHint(self, _option: QStyleOptionViewItem, _index) -> QSize:
        return self.tile

    def paint(self, painter: QPainter, option: QStyleOptionViewItem, index) -> None:
        p = self.theme.palette
        radius = float(self.theme.design.radius)
        card_radius = radius + 2.0
        selected = bool(option.state & QStyle.StateFlag.State_Selected)
        hovered = bool(option.state & QStyle.StateFlag.State_MouseOver)
        cell = option.rect.adjusted(5, 5, -5, -5)

        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
        level = 0.0
        if self.animated:
            now = time.monotonic()
            step = min(0.1, now - self._last_paint) / 0.16
            row = index.row()
            target = 1.0 if hovered else 0.0
            level = self._levels.get(row, 0.0)
            level = min(target, level + step) if level < target else max(target, level - step)
            self._levels[row] = level
            self._last_paint = now
            reveal = (now - self._intro_start - min(row, 24) * self.INTRO_STAGGER) / self.INTRO_SECONDS
            reveal = max(0.0, min(1.0, reveal))
            eased = 1 - (1 - reveal) ** 3
            painter.setOpacity(eased)
            painter.translate(0, (1 - eased) * 18 - level * 4)
            if reveal < 1.0 or level != target:
                self._queue_refresh()

        card_rect = QRectF(cell)
        card_path = QPainterPath()
        card_path.addRoundedRect(card_rect, card_radius, card_radius)

        # Card Base Surface
        if selected:
            card_bg = QColor(p.surface)
            painter.fillPath(card_path, card_bg)
            sel_tint = QColor(p.accent)
            sel_tint.setAlpha(28)
            painter.fillPath(card_path, sel_tint)
        elif hovered:
            painter.fillPath(card_path, QColor(p.surface_alt))
        else:
            painter.fillPath(card_path, QColor(p.surface))

        # Preview Window (letterboxed with inner surface)
        preview_h = max(50.0, card_rect.height() - 56.0)
        preview_rect = QRectF(card_rect.x() + 6, card_rect.y() + 6, card_rect.width() - 12, preview_h)
        preview_path = QPainterPath()
        preview_path.addRoundedRect(preview_rect, radius, radius)
        painter.fillPath(preview_path, QColor(p.surface_alt))

        thumb = index.data(THUMB_ROLE)
        if isinstance(thumb, QPixmap) and not thumb.isNull():
            painter.save()
            painter.setClipPath(preview_path)
            scale = max(preview_rect.width() / thumb.width(), preview_rect.height() / thumb.height())
            width, height = thumb.width() * scale, thumb.height() * scale
            painter.drawPixmap(
                QRectF(preview_rect.center().x() - width / 2, preview_rect.center().y() - height / 2, width, height),
                thumb, QRectF(thumb.rect())
            )
            painter.restore()
        else:
            tint, ink, symbol = BADGES.get(index.data(BADGE_ROLE) or "file", BADGES["file"])
            size = int(min(preview_rect.width(), preview_rect.height()) * 0.52)
            badge = QRectF(preview_rect.center().x() - size / 2, preview_rect.center().y() - size / 2, size, size)
            shape = QPainterPath()
            shape.addRoundedRect(badge, 12, 12)
            painter.fillPath(shape, QColor(tint))
            icons.icon(symbol, ink, 28).paint(painter, badge.adjusted(size * .22, size * .22, -size * .22, -size * .22).toRect())

        # Type Tag Chip (top-right of preview)
        tag = index.data(TAG_ROLE)
        if tag:
            tag_str = str(tag)[:5].upper()
            tag_font = option.font
            tag_font.setPixelSize(10)
            tag_font.setBold(True)
            tag_metrics = QFontMetrics(tag_font)
            tag_w = tag_metrics.horizontalAdvance(tag_str) + 10
            tag_rect = QRectF(preview_rect.right() - tag_w - 4, preview_rect.top() + 4, tag_w, 16)
            tag_path = QPainterPath()
            tag_path.addRoundedRect(tag_rect, 4, 4)
            tag_bg = QColor(p.surface)
            tag_bg.setAlpha(225)
            painter.fillPath(tag_path, tag_bg)
            painter.setPen(QPen(QColor(p.border), 1))
            painter.drawPath(tag_path)
            painter.setFont(tag_font)
            painter.setPen(QColor(p.muted))
            painter.drawText(tag_rect, Qt.AlignmentFlag.AlignCenter, tag_str)

        # Subtle Card Divider
        div_y = preview_rect.bottom() + 4
        painter.setPen(QPen(QColor(p.border), 1))
        painter.drawLine(int(card_rect.x() + 8), int(div_y), int(card_rect.right() - 8), int(div_y))

        # Animated Glow
        if level > 0.01:
            for spread, alpha in ((7.0, 0.10), (4.5, 0.17), (2.0, 0.30)):
                glow = QColor(p.accent)
                glow.setAlphaF(alpha * level)
                painter.setPen(QPen(glow, spread))
                painter.setBrush(Qt.BrushStyle.NoBrush)
                painter.drawRoundedRect(card_rect.adjusted(-spread / 2 + 1, -spread / 2 + 1, spread / 2 - 1, spread / 2 - 1),
                                        card_radius + spread / 2, card_radius + spread / 2)

        # Card Border
        if selected:
            painter.setPen(QPen(QColor(p.accent), 2.0))
        elif hovered:
            painter.setPen(QPen(QColor(p.accent if self.animated else p.border), 1.5))
        else:
            painter.setPen(QPen(QColor(p.border), 1.0))
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawPath(card_path)

        # Card Text: Title
        name_rect = QRect(int(card_rect.x() + 8), int(div_y + 4), int(card_rect.width() - 16), 18)
        title_font = option.font
        title_font.setPixelSize(12)
        title_font.setBold(True)
        painter.setFont(title_font)
        painter.setPen(QColor(p.text))
        text = option.fontMetrics.elidedText(index.data(Qt.ItemDataRole.DisplayRole) or "", Qt.TextElideMode.ElideMiddle, name_rect.width())
        painter.drawText(name_rect, Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignVCenter, text)

        # Card Text: Metadata / Size
        meta_rect = QRect(int(card_rect.x() + 8), int(div_y + 24), int(card_rect.width() - 16), 16)
        meta_font = option.font
        meta_font.setPixelSize(11)
        meta_font.setBold(False)
        painter.setFont(meta_font)
        painter.setPen(QColor(p.muted))
        meta_val = str(index.data(META_ROLE) or "")
        painter.drawText(meta_rect, Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignVCenter, meta_val)

        painter.restore()

class FileRow(QTreeWidgetItem):
    """Klasörleri üstte tutan ve boyutu sayısal sıralayan satır."""

    def __lt__(self, other: QTreeWidgetItem) -> bool:
        tree = self.treeWidget()
        column = tree.sortColumn() if tree else 0
        ascending = tree is None or tree.header().sortIndicatorOrder() == Qt.SortOrder.AscendingOrder
        mine, theirs = self.data(0, ROLE), other.data(0, ROLE)
        if mine[0] != theirs[0]:
            return (mine[0] == "folder") == ascending
        key = Qt.ItemDataRole.UserRole + 1
        if column in (2, 3):
            return (self.data(column, key) or 0) < (other.data(column, key) or 0)
        return self.text(column).casefold() < other.text(column).casefold()

class ThumbnailWorker(QThread):
    """Küçük resimleri arka planda RAM'e çözer."""

    ready = pyqtSignal(str, QImage)

    def __init__(self, session: VaultSession, entries: List[Dict[str, Any]], size: int, parent: QWidget):
        super().__init__(parent)
        self._session = session
        self._entries = entries
        self._size = size
        self._stop = False

    def stop(self) -> None:
        self._stop = True

    def run(self) -> None:
        for entry in self._entries:
            if self._stop or not self._session.is_open:
                return
            try:
                image = QImage.fromData(self._session.read_preview(entry["id"]))
            except (CustomVaultError, OSError, KeyError, TypeError):
                continue
            if not image.isNull():
                self.ready.emit(entry["id"], image.scaled(
                    self._size, self._size, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation
                ))

class DetailsPane(QFrame):
    """Seçili öğenin önizlemesi ve eylemleri."""

    open_clicked = pyqtSignal()
    export_clicked = pyqtSignal()
    rename_clicked = pyqtSignal()
    delete_clicked = pyqtSignal()

    def __init__(self, session: VaultSession, theme: Theme, horizontal: bool, parent: QWidget):
        super().__init__(parent)
        self.setObjectName("Panel")
        self.session = session
        self.theme = theme
        self._tasks: List[Task] = []
        self._token = 0
        self._pixmap: Optional[QPixmap] = None

        self.preview_image = QLabel(alignment=Qt.AlignmentFlag.AlignCenter)
        self.preview_image.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Ignored)
        self.preview_image.setMinimumHeight(120)
        self.preview_text = QPlainTextEdit(readOnly=True)
        self.preview_text.setAccessibleName(tr("Metin önizleme"))
        self.placeholder = QLabel(alignment=Qt.AlignmentFlag.AlignCenter)
        self.preview = QStackedWidget()
        for widget in (self.placeholder, self.preview_image, self.preview_text):
            self.preview.addWidget(widget)

        self.title = label(name="Section")
        self.title.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.meta = label(name="Meta")
        self.meta.setTextFormat(Qt.TextFormat.PlainText)
        p = theme.palette
        self.open_button = button(tr("Aç"), "Primary", self.open_clicked.emit, theme.icon("open", p.on_accent))
        self.export_button = button(tr("Dışa aktar"), on_click=self.export_clicked.emit, icon_=theme.icon("export"))
        self.rename_button = button(tr("Yeniden adlandır"), on_click=self.rename_clicked.emit, icon_=theme.icon("edit"))
        self.delete_button = button(tr("Sil"), "Danger", self.delete_clicked.emit, theme.icon("trash", p.danger))
        self.open_button.setToolTip(tr("Şifresiz geçici kopya oluşturur; kasa kilitlenince silinir."))

        if horizontal:
            self._layout_horizontal()
        else:
            self._layout_vertical()
        self.show_nothing()

    def _layout_vertical(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)

        self.preview_card = QFrame()
        self.preview_card.setObjectName("Card")
        pc_l = QVBoxLayout(self.preview_card)
        pc_l.setContentsMargins(8, 8, 8, 8)
        pc_l.addWidget(self.preview)
        layout.addWidget(self.preview_card, 3)

        self.info_card = QFrame()
        self.info_card.setObjectName("Card")
        ic_l = QVBoxLayout(self.info_card)
        ic_l.setContentsMargins(12, 10, 12, 10)
        ic_l.setSpacing(4)
        ic_l.addWidget(self.title)
        ic_l.addWidget(self.meta)
        layout.addWidget(self.info_card)

        self.overview_card = QFrame()
        self.overview_card.setObjectName("Card")
        oc_l = QVBoxLayout(self.overview_card)
        oc_l.setContentsMargins(12, 10, 12, 10)
        oc_l.setSpacing(6)
        oc_l.addWidget(label(tr("Kasa Genel Bakış"), "Eyebrow"))

        stat_grid = QGridLayout()
        stat_grid.setSpacing(6)

        def make_stat_box(title_s: str, val_attr: str) -> QFrame:
            box = QFrame()
            box.setObjectName("StatCard")
            b_l = QVBoxLayout(box)
            b_l.setContentsMargins(8, 6, 8, 6)
            b_l.setSpacing(2)
            b_l.addWidget(label(title_s, "Meta"))
            val_lbl = label("—", wrap=False)
            val_lbl.setStyleSheet("font-weight: 600; font-size: 13px;")
            b_l.addWidget(val_lbl)
            setattr(self, val_attr, val_lbl)
            return box

        stat_grid.addWidget(make_stat_box(tr("Dosyalar"), "stat_files_lbl"), 0, 0)
        stat_grid.addWidget(make_stat_box(tr("Kullanılan"), "stat_used_lbl"), 0, 1)
        stat_grid.addWidget(make_stat_box(tr("Sınır"), "stat_quota_lbl"), 1, 0)
        stat_grid.addWidget(make_stat_box(tr("Güvenlik"), "stat_sec_lbl"), 1, 1)
        self.stat_sec_lbl.setText("AES-256")
        self.stat_sec_lbl.setStyleSheet(f"color: {self.theme.palette.accent}; font-weight: 700; font-size: 12px;")
        oc_l.addLayout(stat_grid)
        layout.addWidget(self.overview_card)

        layout.addStretch(1)
        actions = QHBoxLayout()
        actions.setSpacing(6)
        layout.addWidget(self.open_button)
        for widget in (self.export_button, self.rename_button, self.delete_button):
            actions.addWidget(widget)
        layout.addLayout(actions)
        self.export_button.setText("")
        self.rename_button.setText("")
        self.delete_button.setText("")
        self.export_button.setToolTip(tr("Dışa aktar"))
        self.rename_button.setToolTip(tr("Yeniden adlandır"))
        self.delete_button.setToolTip(tr("Sil"))
        self.export_button.setAccessibleName(tr("Dışa aktar"))
        self.rename_button.setAccessibleName(tr("Yeniden adlandır"))
        self.delete_button.setAccessibleName(tr("Sil"))

    def _layout_horizontal(self) -> None:
        layout = QHBoxLayout(self)
        layout.setContentsMargins(20, 14, 20, 14)
        layout.setSpacing(20)
        layout.addWidget(self.preview, 2)
        info = QVBoxLayout()
        info.setSpacing(6)
        info.addWidget(self.title)
        info.addWidget(self.meta)
        info.addStretch(1)
        actions = QHBoxLayout()
        actions.setSpacing(8)
        for widget in (self.open_button, self.export_button, self.rename_button, self.delete_button):
            actions.addWidget(widget)
        actions.addStretch(1)
        info.addLayout(actions)
        layout.addLayout(info, 5)

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        self._fit_image()

    def _fit_image(self) -> None:
        if self._pixmap is None:
            return
        size = self.preview_image.size()
        self.preview_image.setPixmap(self._pixmap.scaled(
            size * self.devicePixelRatioF(), Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation
        ))

    def _set_placeholder(self, name: str, size: int = 56) -> None:
        self.placeholder.setPixmap(icons.icon_pixmap(name, self.theme.palette.muted, size, 1.2))
        self.preview.setCurrentWidget(self.placeholder)

    def _set_actions(self, *visible: QPushButton) -> None:
        for widget in (self.open_button, self.export_button, self.rename_button, self.delete_button):
            widget.setVisible(widget in visible)

    def clear_preview(self) -> None:
        self._token += 1
        self._pixmap = None
        self.preview_image.clear()
        self.preview_text.clear()

    def show_nothing(self) -> None:
        self.clear_preview()
        self._set_placeholder("shield")
        stats = self.session.stats()
        self.title.setText(self.session.name)
        quota = f" / {format_size(stats['quota'])}" if stats["quota"] else ""
        self.meta.setText(tr("{} dosya\n{}", stats['count'], f"{format_size(stats['used'])}{quota}"))
        if hasattr(self, "stat_files_lbl"):
            self.stat_files_lbl.setText(str(stats['count']))
        if hasattr(self, "stat_used_lbl"):
            self.stat_used_lbl.setText(format_size(stats['used']))
        if hasattr(self, "stat_quota_lbl"):
            self.stat_quota_lbl.setText(format_size(stats['quota']) if stats['quota'] else tr("Dinamik"))
        if hasattr(self, "overview_card"):
            self.overview_card.show()
        self._set_actions()

    def show_many(self, count: int, size: int) -> None:
        self.clear_preview()
        if hasattr(self, "overview_card"):
            self.overview_card.hide()
        self._set_placeholder("file")
        self.title.setText(tr("{} öğe seçili", count))
        self.meta.setText(format_size(size))
        self._set_actions(self.export_button, self.delete_button)

    def show_folder(self, folder: str, count: int, size: int) -> None:
        self.clear_preview()
        if hasattr(self, "overview_card"):
            self.overview_card.hide()
        self._set_placeholder("folder")
        self.title.setText(folder.rsplit("/", 1)[-1])
        self.meta.setText(tr("Klasör\n{} dosya, {}", count, format_size(size)))
        self._set_actions(self.export_button, self.rename_button, self.delete_button)

    def show_file(self, entry: Dict[str, Any]) -> None:
        self.clear_preview()
        if hasattr(self, "overview_card"):
            self.overview_card.hide()
        name = entry["path"].rsplit("/", 1)[-1]
        category = file_category(name)
        self.title.setText(name)
        self.meta.setText(
            tr("{}, {}\nDeğiştirilme: {}", CATEGORY_LABELS[category], format_size(entry.get('size', 0)), format_date(entry.get('mtime')))
        )
        suffix = Path(name).suffix.lower()
        is_image = suffix in IMAGE_EXTS and entry.get("size", 0) <= PREVIEW_LIMIT
        if is_image:
            self.open_button.setText(tr("Görüntüle"))
            self.open_button.setToolTip(tr("Uygulama içinde açar; diske hiçbir şey yazılmaz."))
        elif can_edit(entry):
            self.open_button.setText(tr("Düzenle"))
            self.open_button.setToolTip(tr("Uygulama içinde düzenler; kayıt doğrudan kasaya şifrelenir."))
        else:
            self.open_button.setText(tr("Aç"))
            self.open_button.setToolTip(tr("Şifresiz geçici kopya oluşturur; kasa kilitlenince silinir."))
        self._set_actions(self.open_button, self.export_button, self.rename_button, self.delete_button)
        self._set_placeholder(category)

        previewable = suffix in IMAGE_EXTS or suffix in TEXT_EXTS
        if not previewable or entry.get("size", 0) > PREVIEW_LIMIT:
            return

        self._token += 1
        token = self._token
        file_id = entry["id"]
        session = self.session

        def work(_progress: Callable, _cancelled: Callable) -> Tuple[Optional[QImage], Optional[str]]:
            data = session.read_preview(file_id)
            if suffix in IMAGE_EXTS:
                return QImage.fromData(data), None
            return None, data[:512 * 1024].decode("utf-8", errors="replace")

        task = Task(work, self)
        task.succeeded.connect(lambda result: self._on_preview(token, result))
        task.finished.connect(lambda: self._tasks.remove(task))
        self._tasks.append(task)
        task.start()

    def shutdown(self) -> None:
        """Pencere silinmeden önce önizleme iş parçacıklarının bitmesini bekler."""
        self._token += 1
        for task in list(self._tasks):
            task.wait()

    def _on_preview(self, token: int, result: Tuple[Optional[QImage], Optional[str]]) -> None:
        if token != self._token:
            return
        image, text = result
        if text is not None:
            self.preview_text.setPlainText(text)
            self.preview.setCurrentWidget(self.preview_text)
        elif image is not None and not image.isNull():
            self._pixmap = QPixmap.fromImage(image)
            self.preview.setCurrentWidget(self.preview_image)
            self._fit_image()

class Workspace(QWidget):
    lock_requested = pyqtSignal()
    settings_requested = pyqtSignal()
    view_mode_changed = pyqtSignal(str)
    switch_vault = pyqtSignal(str)

    DETAILS_MIN_WIDTH = {"vault": 940}
    RAIL_MIN_WIDTH = 720
    TOOLBAR_TEXT_MIN_WIDTH = {"vault": 1500}

    def __init__(self, session: VaultSession, theme: Theme, view_mode: str = "", folder: str = "", parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setObjectName("Workspace")
        self.setAcceptDrops(True)
        self.session = session
        self.theme = theme
        self.folder = folder if folder in session.all_folders() else ""
        self.view_mode = view_mode or theme.design.default_view
        self.category: Optional[str] = None
        self._thumbs: Dict[str, QPixmap] = {}
        self._thumb_worker: Optional[ThumbnailWorker] = None
        self._task: Optional[Task] = None
        self._notice_action: Optional[Callable] = None
        self._transfer_total = 0
        self._transfer_done = 0

        self._build_parts()
        self._arrange_vault()
        self._build_shortcuts()
        self.reload()

    def _build_parts(self) -> None:
        t, p = self.theme, self.theme.palette
        self.active_mode = "files"

        self.mode_container = QFrame()
        self.mode_container.setObjectName("SegmentedContainer")
        mc_l = QHBoxLayout(self.mode_container)
        mc_l.setContentsMargins(2, 2, 2, 2)
        mc_l.setSpacing(2)

        self.mode_group = QButtonGroup(self)
        self.mode_files_btn = QPushButton(tr("Dosyalar"))
        self.mode_files_btn.setObjectName("Segmented")
        self.mode_files_btn.setIcon(t.icon("folder", size=16))
        self.mode_files_btn.setCheckable(True)
        self.mode_files_btn.setChecked(True)
        self.mode_files_btn.clicked.connect(lambda: self.set_mode("files"))
        self.mode_group.addButton(self.mode_files_btn)
        mc_l.addWidget(self.mode_files_btn)

        self.mode_pwds_btn = QPushButton(tr("Şifreler"))
        self.mode_pwds_btn.setObjectName("Segmented")
        self.mode_pwds_btn.setIcon(t.icon("key", size=16))
        self.mode_pwds_btn.setCheckable(True)
        self.mode_pwds_btn.clicked.connect(lambda: self.set_mode("passwords"))
        self.mode_group.addButton(self.mode_pwds_btn)
        mc_l.addWidget(self.mode_pwds_btn)

        from .pwd_view import PasswordView
        self.pwd_view = PasswordView(self.session, self.theme, self)
        self.pwd_view.entry_count_changed.connect(self._on_pwd_count_changed)

        self.pwd_status = label(name="Meta")
        self.pwd_status.hide()

        self.search_box = SearchBox(t, tr("Kasada ara"))
        self.search_box.setMinimumWidth(160)
        self.search = self.search_box.edit
        self.search.textChanged.connect(lambda _text: self.show_current())

        self.crumbs = QWidget()
        self.crumb_layout = QHBoxLayout(self.crumbs)
        self.crumb_layout.setContentsMargins(0, 0, 0, 0)
        self.crumb_layout.setSpacing(2)

        self.folder_tree = QTreeWidget()
        self.folder_tree.setObjectName("Folders")
        self.folder_tree.setHeaderHidden(True)
        self.folder_tree.setIconSize(icons.icon_size(18))
        self.folder_tree.setAccessibleName(tr("Klasörler"))
        self.folder_tree.itemClicked.connect(lambda item, _col: self.navigate(item.data(0, ROLE)))
        self.folder_tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.folder_tree.customContextMenuRequested.connect(self._folder_tree_menu)

        self.table = QTreeWidget()
        self.table.setObjectName("Files")
        self.table.setColumnCount(4)
        self.table.setHeaderLabels([tr("Ad"), tr("Tür"), tr("Boyut"), tr("Değiştirilme")])
        self.table.setRootIsDecorated(False)
        self.table.setUniformRowHeights(True)
        self.table.setSortingEnabled(True)
        self.table.sortByColumn(0, Qt.SortOrder.AscendingOrder)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.table.setIconSize(icons.icon_size(18))
        self.table.setAccessibleName(tr("Dosyalar"))
        header = self.table.header()
        header.setStretchLastSection(False)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for column in (1, 2, 3):
            header.setSectionResizeMode(column, QHeaderView.ResizeMode.ResizeToContents)
        self.table.itemSelectionChanged.connect(self._on_selection)
        self.table.itemActivated.connect(lambda item, _col: self._activate(item.data(0, ROLE)))
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(lambda pos: self._show_menu(self.table.viewport().mapToGlobal(pos)))

        self.grid = QListWidget()
        self.grid.setObjectName("Grid")
        self.grid.setViewMode(QListView.ViewMode.IconMode)
        self.grid.setResizeMode(QListView.ResizeMode.Adjust)
        self.grid.setMovement(QListView.Movement.Static)
        self.grid.setWordWrap(True)
        self.grid.setSpacing(0)
        self.grid.setMouseTracking(True)
        self.grid.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.grid.setAccessibleName(tr("Dosyalar"))
        tile = QSize(196, 172)
        self.tile_delegate = TileDelegate(self.theme, tile, self.grid)
        self.grid.setItemDelegate(self.tile_delegate)
        self.grid.setGridSize(tile)
        self.grid.itemSelectionChanged.connect(self._on_selection)
        self.grid.itemActivated.connect(lambda item: self._activate(item.data(ROLE)))
        self.grid.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.grid.customContextMenuRequested.connect(lambda pos: self._show_menu(self.grid.viewport().mapToGlobal(pos)))

        self.empty = QWidget()
        empty_layout = QVBoxLayout(self.empty)
        empty_layout.setContentsMargins(24, 24, 24, 24)
        empty_layout.setSpacing(16)
        empty_layout.addStretch(1)
        empty_icon = QLabel(alignment=Qt.AlignmentFlag.AlignCenter)
        empty_icon.setPixmap(icons.icon_pixmap("folder-plus", p.muted, 44, 1.2))
        empty_layout.addWidget(empty_icon)
        self.empty_text = label("", "Empty")
        self.empty_text.setAlignment(Qt.AlignmentFlag.AlignCenter)
        empty_layout.addWidget(self.empty_text)

        self.empty_cards = QWidget()
        cards_layout = QHBoxLayout(self.empty_cards)
        cards_layout.setContentsMargins(0, 10, 0, 10)
        cards_layout.setSpacing(14)
        cards_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        def make_action_card(title_txt: str, sub_txt: str, icon_name: str, callback: Callable) -> QPushButton:
            card_btn = QPushButton()
            card_btn.setObjectName("ActionCardButton")
            card_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            card_btn.setMinimumWidth(210)
            card_btn.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Minimum)
            c_inner = QVBoxLayout(card_btn)
            c_inner.setContentsMargins(14, 12, 14, 12)
            c_inner.setSpacing(6)

            ic_box = QFrame()
            ic_box.setFixedSize(34, 34)
            ic_box.setStyleSheet(f"background: {p.surface_alt}; border: 1px solid {p.border}; border-radius: 8px;")
            ic_box_l = QVBoxLayout(ic_box)
            ic_box_l.setContentsMargins(0, 0, 0, 0)
            ic_box_l.setAlignment(Qt.AlignmentFlag.AlignCenter)
            ic_lbl = QLabel()
            ic_lbl.setPixmap(t.icon(icon_name, p.accent, size=18).pixmap(18, 18))
            ic_lbl.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
            ic_box_l.addWidget(ic_lbl)
            c_inner.addWidget(ic_box)

            tl = label(title_txt, "Section", wrap=False)
            tl.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
            c_inner.addWidget(tl)

            desc = label(sub_txt, "Meta", wrap=True)
            desc.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
            c_inner.addWidget(desc)

            card_btn.clicked.connect(callback)
            return card_btn

        self.btn_card_add = make_action_card(
            tr("Dosya Ekle"),
            tr("Belgelerinizi şifreleyerek kasaya aktarın."),
            "plus",
            self.add_files
        )
        self.btn_card_folder = make_action_card(
            tr("Yeni Klasör"),
            tr("İçeriği düzenlemek için klasör oluşturun."),
            "folder-plus",
            self.new_folder
        )
        self.btn_card_pwd = make_action_card(
            tr("Şifre Kasası"),
            tr("Hesap, parola ve 2FA kodlarınızı yönetin."),
            "key",
            lambda: self.set_mode("passwords")
        )

        cards_layout.addWidget(self.btn_card_add)
        cards_layout.addWidget(self.btn_card_folder)
        cards_layout.addWidget(self.btn_card_pwd)

        empty_layout.addWidget(self.empty_cards)
        empty_layout.addStretch(1)

        self.views = QStackedWidget()
        for widget in (self.table, self.grid, self.empty):
            self.views.addWidget(widget)

        self.details = DetailsPane(self.session, t, t.design.layout == "ledger", self)
        self.details.open_clicked.connect(self.open_selected)
        self.details.export_clicked.connect(self.export_selected)
        self.details.rename_clicked.connect(self.rename_selected)
        self.details.delete_clicked.connect(self.delete_selected)

        self.notice = QFrame()
        self.notice.setObjectName("NoticeWarn")
        notice_row = QHBoxLayout(self.notice)
        notice_row.setContentsMargins(12, 8, 8, 8)
        notice_row.setSpacing(10)
        self.notice_text = label(name="Notice")
        self.notice_button = button("", on_click=self._run_notice_action)
        close = tool_button("", t.icon("close", size=16), self.notice.hide, "Kapat", "Link")
        notice_row.addWidget(self.notice_text, 1)
        notice_row.addWidget(self.notice_button)
        notice_row.addWidget(close)
        self.notice.hide()

        self.transfer = QFrame()
        self.transfer.setObjectName("Panel")
        transfer_row = QHBoxLayout(self.transfer)
        transfer_row.setContentsMargins(14, 8, 10, 8)
        transfer_row.setSpacing(12)
        self.transfer_text = label(wrap=False)
        self.transfer_spin = LoadingBars(t)
        self.transfer_bar = QProgressBar()
        self.transfer_bar.setTextVisible(False)
        self.transfer_bar.setRange(0, 1000)
        self.transfer_cancel = button(tr("İptal"), on_click=self._cancel_transfer)
        transfer_row.addWidget(self.transfer_spin)
        transfer_row.addWidget(self.transfer_text)
        transfer_row.addWidget(self.transfer_bar, 1)
        transfer_row.addWidget(self.transfer_cancel)
        self.transfer.hide()

        self.status_rail = label(name="Meta")
        self.status = self.status_rail

        self.add_button = tool_button(tr("Dosya ekle"), t.icon("plus"), self.add_files, "Dosya ekle")
        self.add_folder_button = tool_button(tr("Klasör ekle"), t.icon("archive"), self.add_folder, "Bir klasörü içindekilerle ekle")
        self.new_folder_button = tool_button(tr("Yeni klasör"), t.icon("folder-plus"), self.new_folder)
        self.view_button = tool_button("", t.icon("grid"), self.toggle_view, "Liste ve küçük resim arasında geç")
        self.settings_button = tool_button(tr("Ayarlar"), t.icon("settings"), self.settings_requested.emit)
        self.lock_button = tool_button(tr("Kilitle"), t.icon("lock"), self.lock_requested.emit, "Kasayı kilitle (Ctrl+L)")
        self.collapsible = [self.add_folder_button, self.new_folder_button, self.settings_button]
        if t.design.layout != "gallery":
            self.add_button.setObjectName("PrimaryTool")
            self.add_button.setIcon(t.icon("plus", p.on_accent))
            for widget in (self.add_folder_button, self.new_folder_button, self.view_button, self.settings_button,
                           self.lock_button):
                widget.setObjectName("Link")

    def _main_column(self) -> QVBoxLayout:
        column = QVBoxLayout()
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(0)
        column.addWidget(self.notice)
        column.addWidget(self.views, 1)
        column.addWidget(self.transfer)
        return column

    def _arrange_vault(self) -> None:
        t = self.theme
        ink = designs.rail_text(t.design, t.dark)
        rail_on = t.design.rail
        self.side_panel = None
        self.capacity = CapacityBar()
        group = QButtonGroup(self)
        category_buttons = []
        for title, category in FILTERS:
            if rail_on:
                item = button(tr(title), "RailItem", lambda c=category: self.set_category(c), t.icon(category or "shield", ink))
            else:
                item = button(tr(title), "Chip", lambda c=category: self.set_category(c))
            item.setCheckable(True)
            item.setChecked(category is None)
            group.addButton(item)
            category_buttons.append(item)

        top = QFrame()
        top.setObjectName("TopBar")
        top_layout = QVBoxLayout(top)
        top_layout.setContentsMargins(16, 12, 16, 10)
        top_layout.setSpacing(8)
        first = QHBoxLayout()
        first.setSpacing(8)
        first.addWidget(self.mode_container)
        first.addWidget(self.search_box, 1)
        for widget in (self.add_button, self.add_folder_button, self.new_folder_button,
                       self.view_button, self.settings_button, self.lock_button):
            first.addWidget(widget)
        top_layout.addLayout(first)

        self.second_bar = QWidget()
        second = QHBoxLayout(self.second_bar)
        second.setContentsMargins(0, 0, 0, 0)
        second.setSpacing(12)
        second.addWidget(self.crumbs, 1)
        if not rail_on:
            for item in category_buttons:
                second.addWidget(item)
        top_layout.addWidget(self.second_bar)

        middle = QWidget()
        middle_layout = QVBoxLayout(middle)
        middle_layout.setContentsMargins(0, 0, 0, 0)
        middle_layout.setSpacing(0)
        middle_layout.addWidget(top)

        self.content_stack = QStackedWidget()

        files_widget = QWidget()
        files_l = QVBoxLayout(files_widget)
        files_l.setContentsMargins(0, 0, 0, 0)
        files_l.setSpacing(0)
        grid_column = self._main_column()
        grid_column.setContentsMargins(10, 8, 10, 0)
        files_l.addLayout(grid_column, 1)

        self.files_splitter = QSplitter(Qt.Orientation.Horizontal)
        self.files_splitter.setChildrenCollapsible(False)
        self.files_splitter.addWidget(files_widget)
        self.files_splitter.addWidget(self.details)
        self.files_splitter.setStretchFactor(0, 1)
        self.files_splitter.setStretchFactor(1, 0)
        self.files_splitter.setSizes([800, 280])

        self.content_stack.addWidget(self.files_splitter)
        self.content_stack.addWidget(self.pwd_view)

        middle_layout.addWidget(self.content_stack, 1)

        body = QHBoxLayout()
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(0)
        if rail_on:
            self.side_panel = self._build_rail(category_buttons, ink)
            body.addWidget(self.side_panel)
        body.addWidget(middle, 1)
        footer = QFrame()
        footer.setObjectName("StatusBar")
        footer_layout = QVBoxLayout(footer)
        footer_layout.setContentsMargins(16, 8, 16, 10)
        footer_layout.setSpacing(6)
        footer_layout.addWidget(self.status_rail)
        footer_layout.addWidget(self.pwd_status)
        footer_layout.addWidget(self.capacity)
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        root.addLayout(body, 1)
        root.addWidget(footer)

    def _build_rail(self, category_buttons: list, ink: str) -> QFrame:
        t = self.theme
        rail = BackdropFrame(t)
        column = QVBoxLayout(rail)
        column.setContentsMargins(12, 16, 12, 12)
        column.setSpacing(3)
        column.addWidget(label("Enclave", "RailTitle", wrap=False))
        column.addSpacing(12)
        column.addWidget(label(tr("Kasalarım"), "RailHead", wrap=False))
        current = button(self.session.name, "RailItem", icon_=t.icon("lock", ink))
        current.setCheckable(True)
        current.setChecked(True)
        column.addWidget(current)
        for path in load_config().get("remembered_vaults", []):
            if path != self.session.path and Path(path).exists():
                item = button(Path(path).stem, "RailItem", lambda p=path: self.switch_vault.emit(p), t.icon("lock", ink))
                item.setToolTip(path)
                column.addWidget(item)
        column.addSpacing(12)
        self.rail_categories_box = QWidget()
        rc_l = QVBoxLayout(self.rail_categories_box)
        rc_l.setContentsMargins(0, 0, 0, 0)
        rc_l.setSpacing(3)
        rc_l.addWidget(label(tr("Kategoriler"), "RailHead", wrap=False))
        for item in category_buttons:
            rc_l.addWidget(item)
        column.addWidget(self.rail_categories_box)
        column.addStretch(1)
        return rail

    def set_mode(self, mode: str) -> None:
        self.active_mode = mode
        is_files = (mode == "files")
        self.mode_files_btn.setChecked(is_files)
        self.mode_pwds_btn.setChecked(not is_files)
        self.search_box.setVisible(is_files)
        for btn in (self.add_button, self.add_folder_button, self.new_folder_button, self.view_button):
            btn.setVisible(is_files)
        self.second_bar.setVisible(is_files)
        if hasattr(self, "rail_categories_box") and self.rail_categories_box:
            self.rail_categories_box.setVisible(is_files)
        self.content_stack.setCurrentIndex(0 if is_files else 1)
        self.status_rail.setVisible(is_files)
        self.pwd_status.setVisible(not is_files)
        if is_files:
            layout = self.theme.design.layout
            self.details.setVisible(self.width() >= self.DETAILS_MIN_WIDTH[layout])
            self.show_current()
        else:
            self.details.setVisible(False)
            self._update_pwd_status()
            self.pwd_view.refresh()

    def _on_pwd_count_changed(self, count: int) -> None:
        self.pwd_status.setText(tr("{} şifre kaydı güvenle saklanıyor").format(count))

    def _update_pwd_status(self) -> None:
        count = len(self.pwd_view.store.all(include_deleted=False))
        self.pwd_status.setText(tr("{} şifre kaydı güvenle saklanıyor").format(count))

    @staticmethod
    def _rail_button(widget: QToolButton) -> None:
        widget.setObjectName("RailButton")
        widget.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextUnderIcon)
        widget.setIconSize(icons.icon_size(20))
        widget.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)

    def _build_shortcuts(self) -> None:
        bindings = (
            (QKeySequence.StandardKey.Delete, lambda: self.delete_selected() if self.active_mode == "files" else None),
            (Qt.Key.Key_F2, lambda: self.rename_selected() if self.active_mode == "files" else None),
            (QKeySequence.StandardKey.Find, self._on_find_focus),
            (Qt.Key.Key_Backspace, lambda: self.go_up() if self.active_mode == "files" else None),
        )
        for key, handler in bindings:
            shortcut = QShortcut(QKeySequence(key), self)
            shortcut.setContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)
            shortcut.activated.connect(handler)

    def _on_find_focus(self) -> None:
        if self.active_mode == "files":
            self.search.setFocus()
        else:
            self.pwd_view.search_box.edit.setFocus()

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        width = self.width()
        layout = self.theme.design.layout
        self.details.setVisible(self.active_mode == "files" and width >= self.DETAILS_MIN_WIDTH[layout])
        if self.side_panel is not None:
            min_w = 980 if self.active_mode == "passwords" else self.RAIL_MIN_WIDTH
            self.side_panel.setVisible(width >= min_w)
        style = (Qt.ToolButtonStyle.ToolButtonIconOnly if width < self.TOOLBAR_TEXT_MIN_WIDTH[layout]
                 else Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        for widget in self.collapsible:
            widget.setToolButtonStyle(style)

    def reload(self) -> None:
        self._rebuild_tree()
        self.show_current()

    def _rebuild_tree(self) -> None:
        self.folder_tree.clear()
        muted = self.theme.icon("folder", self.theme.palette.muted)
        root = QTreeWidgetItem([tr("Tüm dosyalar")])
        root.setIcon(0, self.theme.icon("shield", self.theme.palette.muted))
        root.setData(0, ROLE, "")
        self.folder_tree.addTopLevelItem(root)
        nodes = {"": root}
        for folder in self.session.all_folders():
            parent, _, name = folder.rpartition("/")
            item = QTreeWidgetItem([name])
            item.setIcon(0, muted)
            item.setData(0, ROLE, folder)
            nodes.get(parent, root).addChild(item)
            nodes[folder] = item
        self.folder_tree.expandAll()
        self.folder_tree.setCurrentItem(nodes.get(self.folder, root))

    def set_category(self, category: Optional[str]) -> None:
        self.category = category
        self.show_current()

    def navigate(self, folder: str) -> None:
        self.folder = folder
        self.search.clear()
        self.show_current()

    def go_up(self) -> None:
        if self.folder:
            self.navigate(self.folder.rpartition("/")[0])

    def _rebuild_crumbs(self) -> None:
        while self.crumb_layout.count():
            item = self.crumb_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        parts = self.folder.split("/") if self.folder else []
        trail = [(tr("Kasa"), "")] + [(part, "/".join(parts[:i + 1])) for i, part in enumerate(parts)]
        for index, (title, target) in enumerate(trail):
            if index:
                self.crumb_layout.addWidget(label("/", "Meta", wrap=False))
            is_last = index == len(trail) - 1
            self.crumb_layout.addWidget(
                button(title, "CrumbCurrent" if is_last else "Crumb", lambda f=target: self.navigate(f))
            )
        self.crumb_layout.addStretch(1)

    def _current_items(self) -> Tuple[List[str], List[Dict[str, Any]]]:
        text = self.search.text().strip()
        if text or self.category:
            return [], self.session.search(text, self.category)
        return self.session.list_folder(self.folder)

    def show_current(self) -> None:
        self._stop_thumbnails()
        folders, files = self._current_items()
        searching = bool(self.search.text().strip() or self.category)
        self._rebuild_crumbs()
        self._fill_table(folders, files, searching)
        self._fill_grid(folders, files)
        if folders or files:
            self.views.setCurrentWidget(self.table if self.view_mode == "list" else self.grid)
            self.grid.setProperty("active", self.view_mode == "grid")
        else:
            if searching:
                self.empty_text.setText(tr("Sonuç yok."))
                self.empty_cards.hide()
            else:
                self.empty_text.setText(tr("Bu klasör boş.\nDosyaları buraya sürükleyin veya aşağıdaki hızlı kartları kullanın."))
                self.empty_cards.show()
            self.views.setCurrentWidget(self.empty)
        self.view_button.setIcon(self.theme.icon(
            "list" if self.view_mode == "grid" else "grid",
            "#E6EAE2" if self.theme.design.layout == "gallery" else None,
            20 if self.theme.design.layout == "gallery" else 18,
        ))
        self._update_status()
        self._on_selection()
        if self.view_mode == "grid":
            self._start_thumbnails(files)

    def showEvent(self, event) -> None:
        super().showEvent(event)
        self.views.currentWidget().setFocus()

    def _update_status(self) -> None:
        stats = self.session.stats()
        self.status.setText(tr("{} dosya", stats['count']))
        self.capacity.set_values(stats["used"], stats["quota"])
        provider = cloud_provider(self.session.path)
        self.status.setToolTip(tr("Kasa {} klasöründe; aynı anda iki cihazda açmayın.", provider) if provider else "")

    def _file_icon(self, name: str) -> QIcon:
        return self.theme.icon(file_category(name), self.theme.palette.muted)

    def _fill_table(self, folders: List[str], files: List[Dict[str, Any]], full_path: bool) -> None:
        self.table.setUpdatesEnabled(False)
        self.table.setSortingEnabled(False)
        self.table.clear()
        key = Qt.ItemDataRole.UserRole + 1
        folder_icon = self.theme.icon("folder", self.theme.palette.accent)
        for folder in folders:
            row = FileRow([folder.rsplit("/", 1)[-1], tr("Klasör"), "", ""])
            row.setIcon(0, folder_icon)
            row.setData(0, ROLE, ("folder", folder))
            self.table.addTopLevelItem(row)
        for entry in files:
            name = entry["path"] if full_path else entry["path"].rsplit("/", 1)[-1]
            row = FileRow([name, tr(CATEGORY_LABELS[file_category(name)]), format_size(entry.get("size", 0)), format_date(entry.get("mtime"))])
            row.setIcon(0, self._file_icon(name))
            row.setData(0, ROLE, ("file", entry["id"]))
            row.setData(2, key, entry.get("size", 0))
            row.setData(3, key, entry.get("mtime", 0))
            row.setTextAlignment(2, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            self.table.addTopLevelItem(row)
        self.table.setSortingEnabled(True)
        self.table.setUpdatesEnabled(True)

    def _fill_grid(self, folders: List[str], files: List[Dict[str, Any]]) -> None:
        self.grid.clear()
        for folder in folders:
            item = QListWidgetItem(self.theme.icon("folder", self.theme.palette.accent, 64), folder.rsplit("/", 1)[-1])
            item.setData(ROLE, ("folder", folder))
            item.setData(BADGE_ROLE, "folder")
            item.setData(META_ROLE, tr("Klasör"))
            item.setData(TAG_ROLE, "DIR")
            self.grid.addItem(item)
        for entry in files:
            name = entry["path"].rsplit("/", 1)[-1]
            item = QListWidgetItem(self.theme.icon(file_category(name), self.theme.palette.muted, 64), name)
            item.setData(ROLE, ("file", entry["id"]))
            item.setData(THUMB_ROLE, self._thumbs.get(entry["id"]))
            item.setData(BADGE_ROLE, file_category(name))
            item.setData(META_ROLE, format_size(entry.get("size", 0)))
            ext = Path(name).suffix.lstrip(".").upper()
            item.setData(TAG_ROLE, ext[:5] if ext else "FILE")
            item.setToolTip(name)
            self.grid.addItem(item)
        self._grid_index = {self.grid.item(i).data(ROLE)[1]: self.grid.item(i) for i in range(self.grid.count())}
        self.tile_delegate.reset_intro()

    def _start_thumbnails(self, files: List[Dict[str, Any]]) -> None:
        wanted = [
            e for e in files
            if e["id"] not in self._thumbs and Path(e["path"]).suffix.lower() in IMAGE_EXTS and e.get("size", 0) <= THUMB_LIMIT
        ]
        if not wanted:
            return
        self._thumb_worker = ThumbnailWorker(self.session, wanted, 320, self)
        self._thumb_worker.ready.connect(self._on_thumbnail)
        self._thumb_worker.start()

    def _stop_thumbnails(self) -> None:
        if self._thumb_worker:
            self._thumb_worker.stop()
            self._thumb_worker.wait()
            self._thumb_worker = None

    def _on_thumbnail(self, file_id: str, image: QImage) -> None:
        pixmap = QPixmap.fromImage(image)
        self._thumbs[file_id] = pixmap
        item = self._grid_index.get(file_id)
        if item:
            try:
                item.setData(THUMB_ROLE, pixmap)
            except RuntimeError:
                self._grid_index.pop(file_id, None)

    def toggle_view(self) -> None:
        self.view_mode = "grid" if self.view_mode == "list" else "list"
        self.view_mode_changed.emit(self.view_mode)
        self.show_current()

    def _selection(self) -> Tuple[List[str], List[str]]:
        if self.views.currentWidget() is self.table:
            data = [item.data(0, ROLE) for item in self.table.selectedItems()]
        elif self.views.currentWidget() is self.grid:
            data = [item.data(ROLE) for item in self.grid.selectedItems()]
        else:
            data = []
        return [d[1] for d in data if d[0] == "file"], [d[1] for d in data if d[0] == "folder"]

    def _entry(self, file_id: str) -> Optional[Dict[str, Any]]:
        return next((f for f in self.session.files if f["id"] == file_id), None)

    def _on_selection(self) -> None:
        file_ids, folders = self._selection()
        total = len(file_ids) + len(folders)
        if total == 0:
            self.details.show_nothing()
        elif total == 1 and file_ids:
            entry = self._entry(file_ids[0])
            if entry:
                self.details.show_file(entry)
        elif total == 1:
            prefix = folders[0] + "/"
            inside = [f for f in self.session.files if f["path"].startswith(prefix)]
            self.details.show_folder(folders[0], len(inside), sum(f.get("size", 0) for f in inside))
        else:
            size = sum(f.get("size", 0) for f in self.session.files if f["id"] in file_ids)
            self.details.show_many(total, size)

    def _activate(self, data: Tuple[str, str]) -> None:
        if data[0] == "folder":
            self.navigate(data[1])
            return
        entry = self._entry(data[1])
        if entry is None:
            return
        if Path(entry["path"]).suffix.lower() in IMAGE_EXTS and entry.get("size", 0) <= PREVIEW_LIMIT:
            self.open_viewer(data[1])
        elif can_edit(entry):
            self.edit_text(entry)
        else:
            self._open_external(data[1])

    def edit_text(self, entry: Dict[str, Any]) -> None:
        try:
            dialog = TextEditorDialog(self.session, entry, self.theme, self)
        except ValueError:
            self.show_notice(tr("Bu dosya UTF-8 metin değil, uygulama içinde düzenlenemiyor."),
                             tr("Harici uygulamada aç"), lambda: self._open_external(entry["id"]))
            return
        except (CustomVaultError, OSError) as error:
            self._error(str(error))
            return
        dialog.exec()
        if dialog.saved_once:
            self.reload()

    def _visible_images(self) -> List[Dict[str, Any]]:
        files = self._current_items()[1]
        return [f for f in files if Path(f["path"]).suffix.lower() in IMAGE_EXTS and f.get("size", 0) <= PREVIEW_LIMIT]

    def open_viewer(self, file_id: Optional[str] = None, autoplay: bool = False) -> None:
        images = self._visible_images() or self.session.images()
        if not images:
            self.show_notice(tr("Bu görünümde gösterilecek görsel yok."))
            return
        start = next((i for i, e in enumerate(images) if e["id"] == file_id), 0)
        SlideshowDialog(self.session, images, start, self._thumbs, self.theme, autoplay, self).exec()

    def start_slideshow(self) -> None:
        selected = self._selection()[0]
        self.open_viewer(selected[0] if selected else None, autoplay=True)

    def _show_menu(self, position) -> None:
        file_ids, folders = self._selection()
        menu = QMenu(self)
        if file_ids or folders:
            if len(file_ids) == 1 and not folders:
                entry = self._entry(file_ids[0]) or {"path": ""}
                is_image = Path(entry["path"]).suffix.lower() in IMAGE_EXTS
                title = tr("Görüntüle") if is_image else tr("Düzenle") if can_edit(entry) else tr("Aç")
                menu.addAction(self.theme.icon("open"), title, self.open_selected)
                menu.addAction(self.theme.icon("open"), tr("Harici uygulamada aç (şifresiz kopya)"), self.open_external)
            if any(Path(f["path"]).suffix.lower() in IMAGE_EXTS for f in self.session.files if f["id"] in file_ids):
                menu.addAction(self.theme.icon("image"), tr("Slayt gösterisi"), self.start_slideshow)
            menu.addAction(self.theme.icon("export"), tr("Dışa aktar"), self.export_selected)
            if len(file_ids) + len(folders) == 1:
                menu.addAction(self.theme.icon("edit"), tr("Yeniden adlandır"), self.rename_selected)
            menu.addSeparator()
            menu.addAction(self.theme.icon("trash", self.theme.palette.danger), tr("Sil"), self.delete_selected)
        else:
            menu.addAction(self.theme.icon("image"), tr("Slayt gösterisi"), self.start_slideshow)
            menu.addAction(self.theme.icon("plus"), tr("Dosya ekle"), self.add_files)
            menu.addAction(self.theme.icon("folder-plus"), tr("Yeni klasör"), self.new_folder)
        menu.exec(position)

    def _folder_tree_menu(self, position) -> None:
        item = self.folder_tree.itemAt(position)
        folder = item.data(0, ROLE) if item else ""
        if not folder:
            return
        menu = QMenu(self)
        menu.addAction(self.theme.icon("edit"), tr("Yeniden adlandır"), lambda: self._rename_folder(folder))
        menu.addAction(self.theme.icon("export"), tr("Dışa aktar"), lambda: self._export([], [folder]))
        menu.addSeparator()
        menu.addAction(self.theme.icon("trash", self.theme.palette.danger), tr("Sil"), lambda: self._delete([], [folder]))
        menu.exec(self.folder_tree.viewport().mapToGlobal(position))

    def show_notice(self, text: str, action: str = "", on_action: Optional[Callable] = None) -> None:
        self.notice_text.setText(text)
        self._notice_action = on_action
        self.notice_button.setText(action)
        self.notice_button.setVisible(bool(action))
        self.notice.show()

    def offer_two_factor(self) -> None:
        """2FA'sız kasayı açan kullanıcıya etkinleştirme önerir; önceden oluşturulmuş kasalar da kapsanır."""
        if not self.session.two_factor_enabled:
            self.show_notice(tr("Bu kasada iki adımlı doğrulama kapalı. Parolanın yanında kod da istensin mi?"),
                             tr("Etkinleştir"), self._enable_two_factor)

    def _enable_two_factor(self) -> None:
        if self._refuse_during_transfer():
            return
        if TwoFactorDialog(self.session, self.theme, self).exec():
            self.show_notice(tr("İki adımlı doğrulama açıldı. Kasa bir sonraki açılışta kod isteyecek."))

    def _run_notice_action(self) -> None:
        action, self._notice_action = self._notice_action, None
        self.notice.hide()
        if action:
            action()

    def _error(self, text: str) -> None:
        QMessageBox.warning(self, tr("İşlem tamamlanamadı"), text)

    def _guarded(self, fn: Callable, *args: Any) -> bool:
        try:
            fn(*args)
            return True
        except (CustomVaultError, OSError) as error:
            self._error(str(error))
            return False

    @property
    def is_busy(self) -> bool:
        return self._task is not None

    def _start_transfer(self, title: str, total: int, work: Callable, done: Callable) -> None:
        self._transfer_total = max(1, total)
        self._transfer_done = 0
        self.transfer_text.setText(title)
        self.transfer_bar.setValue(0)
        self.transfer_cancel.setEnabled(True)
        self.transfer.show()
        self.transfer_spin.start()
        task = Task(work, self)
        task.advanced.connect(self._on_transfer_progress)
        task.succeeded.connect(lambda result: self._finish_transfer(result, done, None))
        task.failed.connect(lambda message: self._finish_transfer(None, done, message))
        self._task = task
        task.start()

    def _on_transfer_progress(self, count: int) -> None:
        self._transfer_done += count
        self.transfer_bar.setValue(int(self._transfer_done * 1000 / self._transfer_total))

    def _finish_transfer(self, result: Any, done: Callable, error: Optional[str]) -> None:
        cancelled = self._task.is_cancelled() if self._task else False
        self._task = None
        self.transfer.hide()
        self.transfer_spin.stop()
        self._guarded(self.session.refresh)
        self.reload()
        if error and "iptal" not in error.lower():
            self._error(error)
        elif not error:
            done(result, cancelled)

    def _cancel_transfer(self) -> None:
        if self._task:
            self._task.cancel()
            self.transfer_cancel.setEnabled(False)

    def stop_transfer(self) -> None:
        """Otomatik kilitten önce aktarımı keser ve bitmesini bekler; bekleme en fazla bir parça sürer."""
        if self._task:
            self._task.cancel()
            self._task.wait()

    def _refuse_during_transfer(self) -> bool:
        if self.is_busy:
            self.show_notice(tr("Devam eden aktarım bitmeden kasa değiştirilemez."))
        return self.is_busy

    def add_paths(self, paths: List[str]) -> None:
        if self.is_busy:
            self.show_notice(tr("Devam eden aktarım bitmeden yeni dosya eklenemez."))
            return
        plan = self.session.plan_import(paths, self.folder)
        if not plan:
            return
        total = sum(Path(source).stat().st_size for source, _ in plan)
        stats = self.session.stats()
        if stats["quota"] and stats["used"] + total > stats["quota"]:
            self._error(tr("Kasada yer yok. Gereken {}, kalan {}.", format_size(total), format_size(stats['quota'] - stats['used'])))
            return
        session = self.session

        def work(progress: Callable, cancelled: Callable) -> int:
            return session.import_files(plan, progress, cancelled)

        def done(count: int, _cancelled: bool) -> None:
            self.show_notice(tr("{} dosya şifrelenerek kasaya eklendi.", count))

        self._start_transfer(tr("{} dosya şifreleniyor", len(plan)), total, work, done)

    def add_files(self) -> None:
        paths, _ = QFileDialog.getOpenFileNames(self, tr("Kasaya eklenecek dosyalar"))
        if paths:
            self.add_paths(paths)

    def add_folder(self) -> None:
        path = QFileDialog.getExistingDirectory(self, tr("Kasaya eklenecek klasör"))
        if path:
            self.add_paths([path])

    def dragEnterEvent(self, event) -> None:
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event) -> None:
        paths = [url.toLocalFile() for url in event.mimeData().urls() if url.isLocalFile()]
        if paths:
            event.acceptProposedAction()
            self.add_paths(paths)

    def export_selected(self) -> None:
        file_ids, folders = self._selection()
        if file_ids or folders:
            self._export(file_ids, folders)

    def _export(self, file_ids: List[str], folders: List[str]) -> None:
        if self.is_busy:
            return
        destination = QFileDialog.getExistingDirectory(self, tr("Dışa aktarılacak konum"))
        if not destination:
            return
        plan = self.session.plan_export(file_ids, folders, destination)
        by_id = {f["id"]: f.get("size", 0) for f in self.session.files}
        session = self.session

        def work(progress: Callable, cancelled: Callable) -> int:
            return session.export_files(plan, progress, cancelled)

        def done(count: int, _cancelled: bool) -> None:
            self.show_notice(tr("{} dosya şifresiz olarak dışa aktarıldı: {}", count, destination))

        self._start_transfer(tr("{} dosya çözülüyor", len(plan)), sum(by_id[i] for i, _ in plan), work, done)

    def open_selected(self) -> None:
        file_ids, folders = self._selection()
        if len(file_ids) == 1 and not folders:
            self._activate(("file", file_ids[0]))

    def open_external(self) -> None:
        file_ids, folders = self._selection()
        if len(file_ids) == 1 and not folders:
            self._open_external(file_ids[0])

    def _open_external(self, file_id: str) -> None:
        try:
            temp_path = self.session.open_temp_copy(file_id)
            open_with_system(temp_path)
        except (CustomVaultError, OSError) as error:
            self._error(str(error))
            return
        self.show_notice(tr("Dosya şifresiz geçici kopya olarak açıldı. Kasa kilitlenince kopya silinir."))

    def new_folder(self) -> None:
        if self._refuse_during_transfer():
            return
        name, ok = QInputDialog.getText(self, tr("Yeni klasör"), tr("Klasör adı:"))
        if ok and name.strip() and self._guarded(self.session.create_folder, self.folder, name.strip()):
            self.reload()

    def rename_selected(self) -> None:
        file_ids, folders = self._selection()
        if len(file_ids) + len(folders) != 1 or self._refuse_during_transfer():
            return
        if folders:
            self._rename_folder(folders[0])
            return
        entry = self._entry(file_ids[0])
        current = entry["path"].rsplit("/", 1)[-1]
        name, ok = QInputDialog.getText(self, tr("Yeniden adlandır"), tr("Yeni ad:"), text=current)
        if ok and name.strip() and name != current and self._guarded(self.session.rename_file, file_ids[0], name.strip()):
            self.reload()

    def _rename_folder(self, folder: str) -> None:
        if self._refuse_during_transfer():
            return
        current = folder.rsplit("/", 1)[-1]
        name, ok = QInputDialog.getText(self, tr("Yeniden adlandır"), tr("Yeni ad:"), text=current)
        if ok and name.strip() and name != current and self._guarded(self.session.rename_folder, folder, name.strip()):
            if self.folder == folder or self.folder.startswith(folder + "/"):
                self.folder = ""
            self.reload()

    def delete_selected(self) -> None:
        file_ids, folders = self._selection()
        if file_ids or folders:
            self._delete(file_ids, folders)

    def _delete(self, file_ids: List[str], folders: List[str]) -> None:
        if self._refuse_during_transfer():
            return
        count = len(file_ids) + len(folders)
        if not confirm(self, tr("Kasadan sil"),
                       tr("{} öğe kasadan kalıcı olarak silinecek. Bu işlem geri alınamaz.", count), tr("Sil")):
            return
        if self._guarded(self.session.delete, file_ids, folders):
            if self.folder in folders or any(self.folder.startswith(f + "/") for f in folders):
                self.folder = ""
            self.reload()

    def dispose(self) -> None:
        """Kasa kilitlenirken RAM'deki önizlemeleri bırakır."""
        self._stop_thumbnails()
        if self._task:
            self._task.cancel()
            self._task.wait()
        self.details.shutdown()
        self._thumbs.clear()
        self.details.clear_preview()
        self.table.clear()
        self.grid.clear()
        if hasattr(self, "pwd_view") and hasattr(self.pwd_view, "inspector"):
            self.pwd_view.inspector._totp_timer.stop()
            self.pwd_view.store.entries.clear()
