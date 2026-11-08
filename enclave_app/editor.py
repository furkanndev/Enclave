"""Enclave - Uygulama içi metin düzenleyici. Dosya yalnızca RAM'de açılır; kayıt doğrudan kasaya şifrelenir."""

from pathlib import Path
from typing import Any, Dict

from PyQt6.QtGui import QFontDatabase, QKeySequence, QShortcut, QTextOption
from PyQt6.QtWidgets import QDialog, QHBoxLayout, QMessageBox, QPlainTextEdit, QVBoxLayout, QWidget

from enclave_core import CustomVaultError

from .i18n import tr
from .common import Theme, button, label
from .session import TEXT_EXTS, VaultSession

EDIT_LIMIT = 4 * 1024 * 1024

def can_edit(entry: Dict[str, Any]) -> bool:
    return Path(entry["path"]).suffix.lower() in TEXT_EXTS and entry.get("size", 0) <= EDIT_LIMIT

class TextEditorDialog(QDialog):
    """Ctrl+S kaydeder. Satır sonu (CRLF/LF) dosyadaki gibi korunur. UTF-8 olmayan dosya açılmaz (ValueError)."""

    def __init__(self, session: VaultSession, entry: Dict[str, Any], theme: Theme, parent=None):
        super().__init__(parent)
        self.session = session
        self.file_id = entry["id"]
        self.name = entry["path"].rsplit("/", 1)[-1]
        self.saved_once = False
        data = session.read_preview(self.file_id)
        try:
            text = data.decode("utf-8-sig")
        except UnicodeDecodeError as error:
            raise ValueError(tr("Dosya UTF-8 metin değil.")) from error
        self._bom = data.startswith(b"\xef\xbb\xbf")
        self._newline = "\r\n" if "\r\n" in text else "\n"

        self.setWindowTitle(tr("{} - Düzenle", self.name))
        self.title = label(self.name, "Section", wrap=False)
        self.state = label(name="Muted", wrap=False)
        self.editor = QPlainTextEdit()
        self.editor.setAccessibleName(tr("Metin düzenleyici"))
        self.editor.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
        self.editor.setPlainText(text)
        self.editor.document().setModified(False)
        self.editor.document().modificationChanged.connect(lambda _m: self._refresh())
        self.editor.cursorPositionChanged.connect(self._refresh)

        self.save_button = button(tr("Kaydet"), "Primary", self.save)
        self.wrap_button = button(tr("Satır kaydır"), "Chip")
        self.wrap_button.setCheckable(True)
        self.wrap_button.setChecked(True)
        self.wrap_button.toggled.connect(self._toggle_wrap)

        head = QHBoxLayout()
        head.setSpacing(8)
        head.addWidget(self.title, 1)
        head.addWidget(self.wrap_button)
        head.addWidget(self.save_button)
        head.addWidget(button(tr("Kapat"), on_click=self.close))
        root = QVBoxLayout(self)
        root.setContentsMargins(16, 14, 16, 12)
        root.setSpacing(10)
        root.addLayout(head)
        root.addWidget(self.editor, 1)
        root.addWidget(self.state)
        QShortcut(QKeySequence.StandardKey.Save, self, activated=self.save)
        self.resize(900, 640)
        self._refresh()

    def _toggle_wrap(self, wrapped: bool = True) -> None:
        self.editor.setWordWrapMode(QTextOption.WrapMode.WordWrap if wrapped else QTextOption.WrapMode.NoWrap)

    def _refresh(self) -> None:
        cursor = self.editor.textCursor()
        modified = self.editor.document().isModified()
        self.setWindowTitle(tr("{}{} - Düzenle", self.name, ' *' if modified else ''))
        self.state.setText(
            tr("Satır {}, sütun {}   ·   {}   ·   kasada şifreli", cursor.blockNumber() + 1, cursor.positionInBlock() + 1, 'Kaydedilmemiş değişiklik var' if modified else 'Kayıtlı')
        )

    def save(self) -> bool:
        text = self.editor.toPlainText().replace("\n", self._newline)
        data = (b"\xef\xbb\xbf" if self._bom else b"") + text.encode("utf-8")
        try:
            self.session.write_bytes(self.file_id, data)
        except (CustomVaultError, OSError) as error:
            QMessageBox.warning(self, tr("Kaydedilemedi"), str(error))
            return False
        self.editor.document().setModified(False)
        self.saved_once = True
        return True

    def close_for_lock(self) -> None:
        """Kasa kilitlenirken sormadan kapanır; değişiklikler kasaya şifreli kaydedilir, düz metin kalmaz."""
        if self.editor.document().isModified():
            self.save()
        self.editor.document().setModified(False)
        self.close()

    def closeEvent(self, event) -> None:
        if self.editor.document().isModified():
            box = QMessageBox(self)
            box.setWindowTitle(tr("Kaydedilmemiş değişiklik"))
            box.setText(tr("{} dosyasındaki değişiklikler kaydedilsin mi?", self.name))
            save = box.addButton(tr("Kaydet"), QMessageBox.ButtonRole.AcceptRole)
            discard = box.addButton(tr("Kaydetme"), QMessageBox.ButtonRole.DestructiveRole)
            cancel = box.addButton(tr("Vazgeç"), QMessageBox.ButtonRole.RejectRole)
            box.setDefaultButton(save)
            box.exec()
            clicked = box.clickedButton()
            if clicked is cancel or (clicked is save and not self.save()):
                event.ignore()
                return
            if clicked is discard:
                self.editor.document().setModified(False)
        self.editor.clear()
        super().closeEvent(event)
