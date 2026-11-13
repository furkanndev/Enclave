"""Enclave - Entegre Şifre Yöneticisi Ana Arayüzü (Password View).

3 sütunlu modern masaüstü görünümü:
1. Sol Sütun: Kategoriler, Filtreler, Etiketler, Güvenlik Denetimi kartı ve Araçlar
2. Orta Sütun: Arama, Sıralama, Yeni Kayıt butonu ve Kart Listesi
3. Sağ Sütun: Detaylı Bilgi Paneli (Live TOTP geri sayımı, Gizli parola gösterimi, Kopyalama)
"""

import time
from typing import Any, Callable, Dict, List, Optional

from PyQt6.QtCore import QSize, Qt, QTimer, QUrl, pyqtSignal
from PyQt6.QtGui import QDesktopServices, QIcon
from PyQt6.QtWidgets import (
    QApplication, QButtonGroup, QComboBox, QFrame, QHBoxLayout,
    QLabel, QListWidget, QListWidgetItem, QMenu, QProgressBar,
    QPushButton, QScrollArea, QSizePolicy, QSplitter, QStackedWidget,
    QToolButton, QVBoxLayout, QWidget
)

from . import icons
from .common import (
    ElidedLabel, SearchBox, Theme, button, confirm, copy_secret, format_date,
    horizontal_rule, label, tool_button
)
from .i18n import tr
from .pwd_dialogs import (
    EntryEditorDialog, HealthAuditDialog, ImportExportDialog,
    PasswordGeneratorDialog
)
from .pwd_engine import (
    ENTRY_TYPES, TYPE_ICONS, TYPE_LABELS, PasswordEntry, PasswordStore,
    evaluate_password, get_live_totp
)

class EntryListItemWidget(QFrame):
    """Orta sütundaki liste öğesi için kart bileşeni."""

    def __init__(self, entry: PasswordEntry, theme: Theme, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setObjectName("EntryCard")
        self.entry = entry
        self.theme = theme

        p = theme.palette
        layout = QHBoxLayout(self)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(10)

        icon_name = TYPE_ICONS.get(entry.type, "key")
        icon_box = QFrame()
        icon_box.setFixedSize(36, 36)
        icon_box.setStyleSheet(f"background: {p.surface_alt}; border-radius: 8px; border: 1px solid {p.border};")
        ib_l = QVBoxLayout(icon_box)
        ib_l.setContentsMargins(0, 0, 0, 0)
        ib_l.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_lbl = QLabel()
        icon_lbl.setPixmap(theme.icon(icon_name, p.accent, size=20).pixmap(20, 20))
        ib_l.addWidget(icon_lbl)
        layout.addWidget(icon_box)

        center = QVBoxLayout()
        center.setContentsMargins(0, 0, 0, 0)
        center.setSpacing(2)

        top_row = QHBoxLayout()
        top_row.setSpacing(6)
        title_lbl = ElidedLabel(entry.title or tr("(Başlıksız)"))
        title_lbl.setStyleSheet("font-weight: 600; font-size: 14px;")
        top_row.addWidget(title_lbl, 1)

        if entry.favorite:
            star_lbl = QLabel()
            star_lbl.setPixmap(theme.icon("star", "#F4B400", size=14).pixmap(14, 14))
            top_row.addWidget(star_lbl)

        if entry.totp_secret:
            totp_badge = QLabel("2FA")
            totp_badge.setStyleSheet(
                f"background: {p.accent_soft}; color: {p.accent}; "
                f"font-size: 10px; font-weight: 700; padding: 1px 4px; border-radius: 4px;"
            )
            top_row.addWidget(totp_badge)

        center.addLayout(top_row)

        subtitle_text = entry.username
        if not subtitle_text and entry.type == "card":
            subtitle_text = entry.url or tr("Kredi Kartı")
        elif not subtitle_text and entry.type == "note":
            subtitle_text = (entry.notes.splitlines()[0] if entry.notes else "")[:30]
        elif not subtitle_text:
            subtitle_text = tr(TYPE_LABELS.get(entry.type, ""))

        sub_lbl = ElidedLabel(subtitle_text or "—", "Meta")
        center.addWidget(sub_lbl)
        layout.addLayout(center, 1)

        if entry.username:
            user_btn = tool_button(
                "", theme.icon("user", p.muted, size=16),
                lambda: self._copy_text(entry.username, tr("Kullanıcı adı kopyalandı")),
                tr("Kullanıcı Adını Kopyala")
            )
            user_btn.setFixedSize(30, 30)
            user_btn.setStyleSheet("padding: 0px;")
            layout.addWidget(user_btn)

        if entry.password:
            pwd_btn = tool_button(
                "", theme.icon("key", p.muted, size=16),
                lambda: self._copy_pwd(entry.password),
                tr("Parolayı Kopyala (30s)")
            )
            pwd_btn.setFixedSize(30, 30)
            pwd_btn.setStyleSheet("padding: 0px;")
            layout.addWidget(pwd_btn)

    def _copy_text(self, text: str, msg: str) -> None:
        QApplication.clipboard().setText(text)

    def _copy_pwd(self, text: str) -> None:
        copy_secret(text)

class PasswordInspector(QWidget):
    """Sağ sütundaki detay ve inceleme paneli."""

    entry_edited = pyqtSignal(object)
    entry_deleted = pyqtSignal(object)
    entry_restored = pyqtSignal(object)
    entry_purged = pyqtSignal(object)
    favorite_toggled = pyqtSignal(object)

    def __init__(self, theme: Theme, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.theme = theme
        self.entry: Optional[PasswordEntry] = None
        self._pwd_revealed = False

        self._totp_timer = QTimer(self)
        self._totp_timer.setInterval(1000)
        self._totp_timer.timeout.connect(self._update_totp_tick)

        self._build_ui()

    def _build_ui(self) -> None:
        p = self.theme.palette
        root = QVBoxLayout(self)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(12)

        self.stack = QStackedWidget()

        empty_w = QWidget()
        emp_l = QVBoxLayout(empty_w)
        emp_l.setAlignment(Qt.AlignmentFlag.AlignCenter)
        emp_icon = QLabel()
        emp_icon.setPixmap(self.theme.icon("key", p.muted, size=48).pixmap(48, 48))
        emp_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        emp_l.addWidget(emp_icon)
        emp_title = label(tr("Kayıt Seçilmedi"), "Section")
        emp_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        emp_l.addWidget(emp_title)
        emp_sub = label(tr("Ayrıntıları görüntülemek için sol listeden bir kayıt seçin veya yeni bir kayıt ekleyin."), "Meta")
        emp_sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        emp_l.addWidget(emp_sub)
        self.stack.addWidget(empty_w)

        detail_w = QWidget()
        det_l = QVBoxLayout(detail_w)
        det_l.setContentsMargins(0, 0, 0, 0)
        det_l.setSpacing(12)

        top_box = QHBoxLayout()
        top_box.setSpacing(12)

        self.head_icon = QLabel()
        self.head_icon.setFixedSize(40, 40)
        self.head_icon.setStyleSheet(f"background: {p.surface_alt}; border-radius: 8px; border: 1px solid {p.border};")
        self.head_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        top_box.addWidget(self.head_icon)

        head_text_col = QVBoxLayout()
        head_text_col.setSpacing(2)
        self.head_title = ElidedLabel("", "Title")
        self.head_type = ElidedLabel("", "Eyebrow")
        head_text_col.addWidget(self.head_title)
        head_text_col.addWidget(self.head_type)
        top_box.addLayout(head_text_col, 1)

        det_l.addLayout(top_box)

        self.fav_btn = tool_button("", self.theme.icon("star"), self._on_fav_click, tr("Favorilere Ekle / Çıkar"))
        self.edit_btn = tool_button(tr("Düzenle"), self.theme.icon("edit"), self._on_edit_click, tr("Kaydı Düzenle"))
        self.del_btn = tool_button(tr("Sil"), self.theme.icon("trash"), self._on_delete_click, tr("Kayıt İşlemleri"))
        self.purge_btn = tool_button(tr("Kalıcı Sil"), self.theme.icon("close"), self._on_purge_click, tr("Kalıcı Olarak Sil"))
        self.purge_btn.setObjectName("Danger")
        self.purge_btn.hide()

        action_row = QHBoxLayout()
        action_row.setSpacing(8)
        for _b in (self.fav_btn, self.edit_btn, self.del_btn, self.purge_btn):
            _b.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
            action_row.addWidget(_b)
        action_row.addStretch(1)
        det_l.addLayout(action_row)

        det_l.addWidget(horizontal_rule())

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        content = QWidget()
        self.fields_layout = QVBoxLayout(content)
        self.fields_layout.setContentsMargins(4, 4, 4, 4)
        self.fields_layout.setSpacing(10)
        scroll.setWidget(content)
        det_l.addWidget(scroll, 1)

        self.stack.addWidget(detail_w)
        root.addWidget(self.stack)

    def set_entry(self, entry: Optional[PasswordEntry]) -> None:
        self.entry = entry
        self._pwd_revealed = False
        self._totp_timer.stop()

        if not entry:
            self.stack.setCurrentIndex(0)
            return

        self.stack.setCurrentIndex(1)
        p = self.theme.palette

        self.head_title.setText(entry.title or tr("(Başlıksız)"))
        self.head_type.setText(tr(TYPE_LABELS.get(entry.type, entry.type)).upper())
        icon_name = TYPE_ICONS.get(entry.type, "key")
        self.head_icon.setPixmap(self.theme.icon(icon_name, p.accent, size=24).pixmap(24, 24))

        star_color = "#F4B400" if entry.favorite else p.muted
        self.fav_btn.setIcon(self.theme.icon("star", star_color))

        if entry.deleted:
            self.del_btn.setText(tr("Geri Yükle"))
            self.del_btn.setIcon(self.theme.icon("refresh"))
            self.purge_btn.show()
            self.edit_btn.setEnabled(False)
        else:
            self.del_btn.setText(tr("Sil"))
            self.del_btn.setIcon(self.theme.icon("trash"))
            self.purge_btn.hide()
            self.edit_btn.setEnabled(True)

        self._clear_fields()
        self._populate_fields(entry)

        if entry.totp_secret:
            self._update_totp_tick()
            self._totp_timer.start()

    def _clear_fields(self) -> None:
        def purge(layout) -> None:
            while layout.count():
                item = layout.takeAt(0)
                widget = item.widget()
                if widget is not None:
                    widget.hide()
                    widget.setParent(None)
                    widget.deleteLater()
                elif item.layout() is not None:
                    purge(item.layout())
        purge(self.fields_layout)
        for attr in ("pwd_label", "eye_btn", "totp_lbl", "totp_bar", "totp_sec_lbl", "totp_copy_btn"):
            if hasattr(self, attr):
                delattr(self, attr)

    def _populate_fields(self, entry: PasswordEntry) -> None:
        p = self.theme.palette

        if entry.url:
            self.fields_layout.addWidget(self._field_row(
                tr("Web Sitesi"), entry.url,
                copy_val=entry.url,
                action_text=tr("Aç"),
                action_icon="open",
                action_cb=lambda: QDesktopServices.openUrl(QUrl(entry.url if "://" in entry.url else f"https://{entry.url}"))
            ))

        if entry.username:
            self.fields_layout.addWidget(self._field_row(
                tr("Kullanıcı Adı"), entry.username, copy_val=entry.username
            ))

        if entry.password:
            self.fields_layout.addWidget(self._password_card(entry.password))

        if entry.totp_secret:
            self.fields_layout.addWidget(self._totp_card(entry.totp_secret))

        if entry.custom_fields:
            self.fields_layout.addWidget(label(tr("Özel Alanlar"), "Eyebrow"))
            for cf in entry.custom_fields:
                name = cf.get("name", "")
                val = cf.get("value", "")
                is_sec = cf.get("secret", False)
                self.fields_layout.addWidget(self._field_row(
                    name, "••••••••" if is_sec else val,
                    copy_val=val,
                    is_secret=is_sec
                ))

        if entry.notes:
            self.fields_layout.addWidget(label(tr("Güvenli Notlar"), "Eyebrow"))
            note_box = QFrame()
            note_box.setObjectName("Card")
            nb_l = QVBoxLayout(note_box)
            nb_l.setContentsMargins(12, 10, 12, 10)
            note_lbl = label(entry.notes, wrap=True)
            note_lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            nb_l.addWidget(note_lbl)
            self.fields_layout.addWidget(note_box)

        if entry.tags:
            tag_box = QHBoxLayout()
            tag_box.setSpacing(6)
            tag_box.addWidget(label(tr("Etiketler:"), "Eyebrow"))
            for t in entry.tags:
                tag_lbl = QLabel(t)
                tag_lbl.setStyleSheet(f"background: {p.surface_alt}; border: 1px solid {p.border}; border-radius: 4px; padding: 2px 6px; font-size: 11px;")
                tag_box.addWidget(tag_lbl)
            tag_box.addStretch(1)
            self.fields_layout.addLayout(tag_box)

        self.fields_layout.addSpacing(2)
        self.fields_layout.addWidget(horizontal_rule())
        meta_row = QHBoxLayout()
        created_str = format_date(entry.created_at)
        updated_str = format_date(entry.updated_at)
        meta_lbl = label(tr("Oluşturulma: {}  •  Güncelleme: {}").format(created_str, updated_str), "Meta")
        meta_row.addWidget(meta_lbl)
        self.fields_layout.addLayout(meta_row)

        self.fields_layout.addStretch(1)

    def _field_row(
        self,
        title: str,
        display_val: str,
        copy_val: str = "",
        action_text: str = "",
        action_icon: str = "",
        action_cb: Optional[Callable] = None,
        is_secret: bool = False
    ) -> QWidget:
        card = QFrame()
        card.setObjectName("Card")
        c_l = QHBoxLayout(card)
        c_l.setContentsMargins(12, 10, 12, 10)
        c_l.setSpacing(10)

        v = QVBoxLayout()
        v.setSpacing(2)
        v.addWidget(label(title, "Eyebrow"))
        val_lbl = label(display_val, wrap=True)
        val_lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        val_lbl.setStyleSheet("font-size: 14px; font-weight: 500;")
        v.addWidget(val_lbl)
        c_l.addLayout(v, 1)

        if action_text and action_cb:
            btn = tool_button(action_text, self.theme.icon(action_icon or "open"), action_cb, action_text)
            c_l.addWidget(btn)

        if copy_val:
            cp_cb = (lambda: copy_secret(copy_val)) if is_secret else (lambda: QApplication.clipboard().setText(copy_val))
            c_l.addWidget(tool_button(
                "", self.theme.icon("copy"), cp_cb, tr("Panoya Kopyala")
            ))

        return card

    def _password_card(self, password: str) -> QWidget:
        p = self.theme.palette
        card = QFrame()
        card.setObjectName("Card")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        top = QHBoxLayout()
        top.setSpacing(8)
        top.addWidget(label(tr("Parola"), "Eyebrow"))
        top.addStretch(1)
        layout.addLayout(top)

        mid = QHBoxLayout()
        mid.setSpacing(10)

        self.pwd_label = label("••••••••••••••••", wrap=False)
        self.pwd_label.setStyleSheet("font-family: monospace; font-size: 16px; font-weight: 600;")
        self.pwd_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        mid.addWidget(self.pwd_label, 1)

        self.eye_btn = tool_button(
            "", self.theme.icon("eye"), self._toggle_pwd_visibility, tr("Parolayı Göster / Gizle")
        )
        mid.addWidget(self.eye_btn)

        copy_btn = tool_button(
            tr("Kopyala"), self.theme.icon("key"), lambda: copy_secret(password), tr("Parolayı Kopyala (30s)")
        )
        mid.addWidget(copy_btn)
        layout.addLayout(mid)

        score, text = evaluate_password(password)
        colors = ["#D93025", "#EA8600", "#F9AB00", "#1E8E3E", "#137333"]
        score_color = colors[score]

        bar = QProgressBar()
        bar.setRange(0, 4)
        bar.setValue(score)
        bar.setTextVisible(False)
        bar.setFixedHeight(5)
        bar.setStyleSheet(f"""
            QProgressBar {{ background: {p.surface_alt}; border-radius: 2px; border: none; }}
            QProgressBar::chunk {{ background: {score_color}; border-radius: 2px; }}
        """)
        layout.addWidget(bar)

        score_lbl = label(tr("Güvenlik: {} ({}/4)").format(text, score), "Meta")
        score_lbl.setStyleSheet(f"color: {score_color}; font-size: 12px; font-weight: 600;")
        layout.addWidget(score_lbl)

        return card

    def _toggle_pwd_visibility(self) -> None:
        if not self.entry:
            return
        self._pwd_revealed = not self._pwd_revealed
        if self._pwd_revealed:
            self.pwd_label.setText(self.entry.password)
            self.eye_btn.setIcon(self.theme.icon("eye-off"))
        else:
            self.pwd_label.setText("••••••••••••••••")
            self.eye_btn.setIcon(self.theme.icon("eye"))

    def _totp_card(self, secret: str) -> QWidget:
        p = self.theme.palette
        card = QFrame()
        card.setObjectName("TotpCard")
        c_l = QVBoxLayout(card)
        c_l.setContentsMargins(14, 12, 14, 12)
        c_l.setSpacing(8)

        head = QHBoxLayout()
        head.addWidget(label(tr("İki Adımlı Doğrulama Kodu (TOTP)"), "Eyebrow", wrap=False))
        head.addStretch(1)
        c_l.addLayout(head)

        token_row = QHBoxLayout()
        token_row.setSpacing(12)

        self.totp_lbl = QLabel("--- ---")
        self.totp_lbl.setObjectName("TotpToken")
        token_row.addWidget(self.totp_lbl, 1)

        self.totp_copy_btn = tool_button(
            tr("Kopyala"), self.theme.icon("clock"), self._copy_live_totp, tr("2FA Kodunu Kopyala")
        )
        token_row.addWidget(self.totp_copy_btn)
        c_l.addLayout(token_row)

        foot = QHBoxLayout()
        foot.setSpacing(8)
        self.totp_bar = QProgressBar()
        self.totp_bar.setRange(0, 100)
        self.totp_bar.setTextVisible(False)
        self.totp_bar.setFixedHeight(5)
        foot.addWidget(self.totp_bar, 1)

        self.totp_sec_lbl = label("30s", "Meta")
        foot.addWidget(self.totp_sec_lbl)
        c_l.addLayout(foot)

        return card

    def _update_totp_tick(self) -> None:
        if not self.entry or not self.entry.totp_secret:
            return
        token, remaining, progress = get_live_totp(self.entry.totp_secret)
        if token and len(token) == 6:
            formatted = f"{token[:3]} {token[3:]}"
        else:
            formatted = token or tr("Geçersiz Kod")

        if hasattr(self, "totp_lbl"):
            self.totp_lbl.setText(formatted)
        if hasattr(self, "totp_bar"):
            self.totp_bar.setValue(int(progress * 100))
        if hasattr(self, "totp_sec_lbl"):
            self.totp_sec_lbl.setText(f"{remaining}s")

    def _copy_live_totp(self) -> None:
        if not self.entry or not self.entry.totp_secret:
            return
        token, _, _ = get_live_totp(self.entry.totp_secret)
        if token:
            copy_secret(token)

    def _on_fav_click(self) -> None:
        if self.entry:
            self.favorite_toggled.emit(self.entry)

    def _on_edit_click(self) -> None:
        if self.entry:
            self.entry_edited.emit(self.entry)

    def _on_delete_click(self) -> None:
        if not self.entry:
            return
        if self.entry.deleted:
            self.entry_restored.emit(self.entry)
        else:
            self.entry_deleted.emit(self.entry)

    def _on_purge_click(self) -> None:
        if self.entry:
            self.entry_purged.emit(self.entry)

class PasswordView(QWidget):
    """Enclave tam ekran 3 sütunlu Şifre Yöneticisi arayüzü."""

    entry_count_changed = pyqtSignal(int)

    def __init__(self, session: Any, theme: Theme, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.session = session
        self.theme = theme
        self.store = PasswordStore(session)

        self.current_category: Optional[str] = None
        self.current_filter: Optional[str] = None
        self.current_tag: Optional[str] = None
        self.search_query: str = ""
        self.sort_by: str = "title_asc"
        self.selected_entry_id: Optional[str] = None

        self._build_ui()
        self.refresh()

    def _build_ui(self) -> None:
        p = self.theme.palette
        root = QHBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        self.splitter = QSplitter(Qt.Orientation.Horizontal)
        self.splitter.setChildrenCollapsible(False)

        self.sidebar = self._build_sidebar()
        self.splitter.addWidget(self.sidebar)

        self.list_pane = self._build_list_pane()
        self.splitter.addWidget(self.list_pane)

        self.inspector = PasswordInspector(self.theme, self)
        self.inspector.entry_edited.connect(self._open_edit_dialog)
        self.inspector.entry_deleted.connect(self._on_delete_entry)
        self.inspector.entry_restored.connect(self._on_restore_entry)
        self.inspector.entry_purged.connect(self._on_purge_entry)
        self.inspector.favorite_toggled.connect(self._on_toggle_favorite)
        self.splitter.addWidget(self.inspector)

        self.splitter.setStretchFactor(0, 0)
        self.splitter.setStretchFactor(1, 1)
        self.splitter.setStretchFactor(2, 2)
        self.splitter.setSizes([220, 340, 480])

        root.addWidget(self.splitter)

    def _build_sidebar(self) -> QWidget:
        p = self.theme.palette
        side = QFrame()
        side.setObjectName("SidebarPane")
        side.setMinimumWidth(180)
        side_l = QVBoxLayout(side)
        side_l.setContentsMargins(12, 14, 12, 14)
        side_l.setSpacing(6)

        side_l.addWidget(label(tr("Kategoriler"), "RailHead", wrap=False))

        self.cat_group = QButtonGroup(self)
        self.cat_buttons: Dict[Optional[str], QPushButton] = {}

        all_btn = self._make_sidebar_btn(tr("Tüm Kayıtlar"), "shield", lambda: self._select_category(None))
        self.cat_buttons[None] = all_btn
        side_l.addWidget(all_btn)

        for c_key in ENTRY_TYPES:
            lbl = TYPE_LABELS[c_key]
            ic = TYPE_ICONS.get(c_key, "key")
            btn = self._make_sidebar_btn(tr(lbl), ic, lambda k=c_key: self._select_category(k))
            self.cat_buttons[c_key] = btn
            side_l.addWidget(btn)

        side_l.addSpacing(10)
        side_l.addWidget(label(tr("Filtreler"), "RailHead", wrap=False))

        self.flt_buttons: Dict[str, QPushButton] = {}

        fav_btn = self._make_sidebar_btn(tr("Favoriler"), "star", lambda: self._select_filter("favorites"))
        self.flt_buttons["favorites"] = fav_btn
        side_l.addWidget(fav_btn)

        totp_btn = self._make_sidebar_btn(tr("2FA / TOTP"), "clock", lambda: self._select_filter("totp"))
        self.flt_buttons["totp"] = totp_btn
        side_l.addWidget(totp_btn)

        trash_btn = self._make_sidebar_btn(tr("Çöp Kutusu"), "trash", lambda: self._select_filter("trash"))
        self.flt_buttons["trash"] = trash_btn
        side_l.addWidget(trash_btn)

        side_l.addStretch(1)

        self.audit_card = QFrame()
        self.audit_card.setObjectName("Card")
        ac_l = QVBoxLayout(self.audit_card)
        ac_l.setContentsMargins(10, 8, 10, 8)
        ac_l.setSpacing(4)
        ac_l.addWidget(label(tr("Güvenlik Denetimi"), "Eyebrow"))
        self.audit_summary_lbl = label(tr("Denetleniyor..."), "Meta")
        ac_l.addWidget(self.audit_summary_lbl)
        audit_btn = button(tr("Raporu Aç"), on_click=self._open_audit_dialog)
        ac_l.addWidget(audit_btn)
        side_l.addWidget(self.audit_card)

        side_l.addSpacing(4)
        gen_btn = tool_button(tr("Parola Üret"), self.theme.icon("key"), self._open_generator_dialog, tr("Parola Üreteci"))
        imp_btn = tool_button(tr("İçe / Dışa Aktar"), self.theme.icon("export"), self._open_import_export_dialog, tr("Yedekleme ve Aktarım"))
        side_l.addWidget(gen_btn)
        side_l.addWidget(imp_btn)

        all_btn.setChecked(True)
        return side

    def _make_sidebar_btn(self, text: str, icon_name: str, on_click: Callable) -> QPushButton:
        p = self.theme.palette
        btn = button(text, "RailItem", on_click=on_click, icon_=self.theme.icon(icon_name, p.muted, size=16))
        btn.setCheckable(True)
        self.cat_group.addButton(btn)
        return btn

    def _build_list_pane(self) -> QWidget:
        p = self.theme.palette
        pane = QFrame()
        pane.setObjectName("Panel")
        pane.setMinimumWidth(260)
        layout = QVBoxLayout(pane)
        layout.setContentsMargins(12, 14, 12, 10)
        layout.setSpacing(10)

        self.search_box = SearchBox(self.theme, tr("Şifrelerde ara..."))
        self.search_box.edit.textChanged.connect(self._on_search_changed)
        layout.addWidget(self.search_box)

        action_bar = QHBoxLayout()
        action_bar.setSpacing(8)

        self.new_btn = button(tr("+ Yeni Kayıt"), "Primary", self._open_create_dialog)
        action_bar.addWidget(self.new_btn)

        action_bar.addStretch(1)

        self.sort_combo = QComboBox()
        self.sort_combo.addItem(tr("Başlık (A-Z)"), "title_asc")
        self.sort_combo.addItem(tr("Başlık (Z-A)"), "title_desc")
        self.sort_combo.addItem(tr("Son Güncellenen"), "updated")
        self.sort_combo.addItem(tr("Oluşturulma"), "created")
        self.sort_combo.currentIndexChanged.connect(self._on_sort_changed)
        action_bar.addWidget(self.sort_combo)

        layout.addLayout(action_bar)

        self.list_stack = QStackedWidget()

        self.list_widget = QListWidget()
        self.list_widget.setSelectionMode(QListWidget.SelectionMode.SingleSelection)
        self.list_widget.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.list_widget.setVerticalScrollMode(QListWidget.ScrollMode.ScrollPerPixel)
        self.list_widget.setSpacing(2)
        self.list_widget.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.list_widget.customContextMenuRequested.connect(self._show_list_context_menu)
        self.list_widget.currentItemChanged.connect(self._on_item_selected)
        self.list_stack.addWidget(self.list_widget)

        self.empty_label = label(tr("Kayıt bulunamadı."), "Empty")
        self.empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.list_stack.addWidget(self.empty_label)

        layout.addWidget(self.list_stack, 1)

        self.count_lbl = label("", "Meta")
        layout.addWidget(self.count_lbl)

        return pane

    def _select_category(self, cat: Optional[str]) -> None:
        self.current_category = cat
        self.current_filter = None
        self.refresh()

    def _select_filter(self, flt: str) -> None:
        self.current_category = None
        self.current_filter = flt
        self.refresh()

    def _on_search_changed(self, text: str) -> None:
        self.search_query = text.strip()
        self.refresh()

    def _on_sort_changed(self) -> None:
        self.sort_by = self.sort_combo.currentData() or "title_asc"
        self.refresh()

    def refresh(self) -> None:
        """Kayıtları filtreler, sıralar ve listeyi yeniden doldurur."""
        include_deleted = (self.current_filter == "trash")
        entries = self.store.all(include_deleted=include_deleted)

        if self.current_category:
            entries = [e for e in entries if e.type == self.current_category]
        elif self.current_filter == "favorites":
            entries = [e for e in entries if e.favorite and not e.deleted]
        elif self.current_filter == "totp":
            entries = [e for e in entries if bool(e.totp_secret) and not e.deleted]
        elif self.current_filter == "trash":
            entries = [e for e in entries if e.deleted]
        else:
            entries = [e for e in entries if not e.deleted]

        if self.search_query:
            q = self.search_query.casefold()
            entries = [
                e for e in entries
                if q in e.title.casefold()
                or q in e.username.casefold()
                or q in e.url.casefold()
                or q in e.notes.casefold()
                or any(q in t.casefold() for t in e.tags)
            ]

        if self.sort_by == "title_asc":
            entries.sort(key=lambda e: (e.title or "").casefold())
        elif self.sort_by == "title_desc":
            entries.sort(key=lambda e: (e.title or "").casefold(), reverse=True)
        elif self.sort_by == "updated":
            entries.sort(key=lambda e: e.updated_at, reverse=True)
        elif self.sort_by == "created":
            entries.sort(key=lambda e: e.created_at, reverse=True)

        self.list_widget.clear()
        found_selected = False

        for entry in entries:
            item = QListWidgetItem()
            card = EntryListItemWidget(entry, self.theme)
            item.setSizeHint(QSize(0, card.sizeHint().height()))
            item.setData(Qt.ItemDataRole.UserRole, entry.id)
            self.list_widget.addItem(item)
            self.list_widget.setItemWidget(item, card)

            if entry.id == self.selected_entry_id:
                self.list_widget.setCurrentItem(item)
                found_selected = True

        if not found_selected and entries:
            self.list_widget.setCurrentRow(0)
            self.selected_entry_id = entries[0].id
            self.inspector.set_entry(entries[0])
        elif not entries:
            self.selected_entry_id = None
            self.inspector.set_entry(None)

        self.list_stack.setCurrentIndex(0 if entries else 1)
        self.count_lbl.setText(tr("{} kayıt listeleniyor").format(len(entries)))
        self.entry_count_changed.emit(len(self.store.all(include_deleted=False)))

        self._update_audit_summary()

    def _update_audit_summary(self) -> None:
        audit = self.store.audit()
        weak_count = len(audit["weak"])
        reused_count = len(audit["reused"])
        if weak_count > 0 or reused_count > 0:
            msg = tr("{} zayıf, {} tekrar eden").format(weak_count, reused_count)
            self.audit_summary_lbl.setText(msg)
            self.audit_summary_lbl.setStyleSheet("color: #D93025; font-size: 12px; font-weight: 600;")
        else:
            self.audit_summary_lbl.setText(tr("Tüm parolalar güvenli."))
            self.audit_summary_lbl.setStyleSheet("color: #1E8E3E; font-size: 12px; font-weight: 600;")

    def _on_item_selected(self, current: Optional[QListWidgetItem], _prev: Optional[QListWidgetItem]) -> None:
        if not current:
            self.inspector.set_entry(None)
            self.selected_entry_id = None
            return
        entry_id = current.data(Qt.ItemDataRole.UserRole)
        self.selected_entry_id = entry_id
        entry = self.store.get(entry_id)
        self.inspector.set_entry(entry)

    def _show_list_context_menu(self, pos) -> None:
        item = self.list_widget.itemAt(pos)
        if not item:
            return
        entry_id = item.data(Qt.ItemDataRole.UserRole)
        entry = self.store.get(entry_id)
        if not entry:
            return

        menu = QMenu(self)
        if not entry.deleted:
            edit_act = menu.addAction(tr("Düzenle"))
            edit_act.triggered.connect(lambda: self._open_edit_dialog(entry))

            if entry.password:
                pwd_act = menu.addAction(tr("Parolayı Kopyala"))
                pwd_act.triggered.connect(lambda: copy_secret(entry.password))

            if entry.username:
                user_act = menu.addAction(tr("Kullanıcı Adını Kopyala"))
                user_act.triggered.connect(lambda: QApplication.clipboard().setText(entry.username))

            if entry.totp_secret:
                totp_act = menu.addAction(tr("2FA Kodunu Kopyala"))
                totp_act.triggered.connect(lambda: self._copy_totp_action(entry))

            fav_act = menu.addAction(tr("Favorilerden Kaldır") if entry.favorite else tr("Favorilere Ekle"))
            fav_act.triggered.connect(lambda: self._on_toggle_favorite(entry))

            menu.addSeparator()
            del_act = menu.addAction(tr("Çöp Kutusuna Taşı"))
            del_act.triggered.connect(lambda: self._on_delete_entry(entry))
        else:
            restore_act = menu.addAction(tr("Geri Yükle"))
            restore_act.triggered.connect(lambda: self._on_restore_entry(entry))

            menu.addSeparator()
            purge_act = menu.addAction(tr("Kalıcı Olarak Sil"))
            purge_act.triggered.connect(lambda: self._on_purge_entry(entry))

        menu.exec(self.list_widget.viewport().mapToGlobal(pos))

    def _copy_totp_action(self, entry: PasswordEntry) -> None:
        token, _, _ = get_live_totp(entry.totp_secret)
        if token:
            copy_secret(token)

    def _open_create_dialog(self) -> None:
        dlg = EntryEditorDialog(
            theme=self.theme,
            store=self.store,
            entry=None,
            default_type=self.current_category or "login",
            parent=self.window()
        )
        if dlg.exec():
            self.refresh()
            if dlg.entry:
                self.selected_entry_id = dlg.entry.id
                self.refresh()

    def _open_edit_dialog(self, entry: PasswordEntry) -> None:
        dlg = EntryEditorDialog(
            theme=self.theme,
            store=self.store,
            entry=entry,
            parent=self.window()
        )
        if dlg.exec():
            self.refresh()

    def _on_toggle_favorite(self, entry: PasswordEntry) -> None:
        self.store.toggle_favorite(entry.id)
        self.refresh()

    def _on_delete_entry(self, entry: PasswordEntry) -> None:
        self.store.delete(entry.id, soft=True)
        self.refresh()

    def _on_restore_entry(self, entry: PasswordEntry) -> None:
        self.store.restore(entry.id)
        self.refresh()

    def _on_purge_entry(self, entry: PasswordEntry) -> None:
        if confirm(
            self.window(),
            tr("Kalıcı Silme Onayı"),
            tr("'{}' kaydı kalıcı olarak silinecektir. Bu işlem geri alınamaz!").format(entry.title),
            tr("Kalıcı Olarak Sil"),
            danger=True
        ):
            self.store.delete(entry.id, soft=False)
            self.refresh()

    def _open_generator_dialog(self) -> None:
        dlg = PasswordGeneratorDialog(self.theme, self.window())
        dlg.exec()

    def _open_import_export_dialog(self) -> None:
        dlg = ImportExportDialog(self.theme, self.store, self.window())
        if dlg.exec():
            self.refresh()

    def _open_audit_dialog(self) -> None:
        dlg = HealthAuditDialog(self.theme, self.store, self._open_edit_dialog, self.window())
        dlg.exec()
        self.refresh()

