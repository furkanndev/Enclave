"""Enclave - Ana pencere. Kilit ekranı ile çalışma alanı arasında geçişi ve otomatik kilitlemeyi yönetir."""

import sys
from pathlib import Path
from typing import List, Optional, Tuple

from PyQt6.QtCore import QEvent, QObject, QTimer, Qt
from PyQt6.QtGui import QFontDatabase, QGuiApplication, QKeySequence, QShortcut
from PyQt6.QtWidgets import QApplication, QDialog, QMainWindow, QMessageBox, QStackedWidget

from config import load_config, save_config
from enclave_core import CustomVaultError

from . import designs
from .elevated_drop import enable_elevated_drop
from .i18n import set_language, tr
from .common import Theme, clear_secret_clipboard, confirm, resource_path
from .dialogs import CreateVaultDialog, SettingsDialog
from .session import VaultSession
from .unlock_page import UnlockPage
from .workspace import Workspace
from .vhd_page import VhdPage
from .vhd_service import VhdSession

ACTIVITY_EVENTS = {
    QEvent.Type.KeyPress, QEvent.Type.MouseButtonPress, QEvent.Type.MouseMove, QEvent.Type.Wheel, QEvent.Type.DragEnter,
}

def load_bundled_fonts() -> None:
    for name in ("JetBrainsMono-Regular.ttf", "JetBrainsMono-Bold.ttf"):
        path = resource_path(f"assets/fonts/{name}")
        if path.exists():
            QFontDatabase.addApplicationFont(str(path))

def is_system_dark() -> bool:
    hints = QGuiApplication.styleHints()
    return hints is not None and hints.colorScheme() == Qt.ColorScheme.Dark

class VaultWindow(QMainWindow):
    def __init__(self, initial_path: str = ""):
        super().__init__()
        self.setWindowTitle("Enclave")
        self.setMinimumSize(560, 520)
        self.resize(1160, 740)
        self.config = load_config()
        set_language(self.config.get("language", "tr"))
        self.session: Optional[VaultSession] = None
        self._unsaved_copies = 0
        self.workspace: Optional[Workspace] = None
        self.vhd_session: Optional[VhdSession] = None
        self.vhd_page: Optional[VhdPage] = None
        self.theme = self._resolve_theme(self.config.get("design", designs.DEFAULT_DESIGN), self.config.get("appearance", "system"))

        self.stack = QStackedWidget()
        self.setCentralWidget(self.stack)
        self._apply_stylesheet()
        self.unlock_page = self._make_unlock_page(initial_path)
        self.stack.addWidget(self.unlock_page)

        self.idle_timer = QTimer(self)
        self.idle_timer.setSingleShot(True)
        self.idle_timer.timeout.connect(self._on_idle)
        QApplication.instance().installEventFilter(self)
        self.vhd_idle_timer = QTimer(self)
        self.vhd_idle_timer.setInterval(30000)
        self.vhd_idle_timer.timeout.connect(self._check_vhd_idle)

        self.session_guard = QTimer(self)
        self.session_guard.setInterval(1500)
        self.session_guard.timeout.connect(self._check_os_lock)
        self.session_guard.start()
        lock = QShortcut(QKeySequence("Ctrl+L"), self)
        lock.activated.connect(lambda: self.lock())

        hints = QGuiApplication.styleHints()
        if hints is not None:
            hints.colorSchemeChanged.connect(lambda _scheme: self._on_system_scheme())

    @staticmethod
    def _resolve_theme(design_key: str, appearance: str, style: Optional[str] = None) -> Theme:
        dark = is_system_dark() if appearance == "system" else appearance == "dark"
        style = style or load_config().get("style", designs.DEFAULT_STYLE)
        return Theme(designs.get_design(design_key, style), dark)

    def _apply_stylesheet(self) -> None:
        self.setStyleSheet(designs.build_stylesheet(self.theme.design, self.theme.dark))

    def _make_unlock_page(self, initial_path: str = "") -> UnlockPage:
        page = UnlockPage(self.theme, initial_path)
        page.unlocked.connect(self._on_unlocked)
        page.create_requested.connect(self._create_vault)
        page.settings_requested.connect(self.open_settings)
        return page

    def set_design(self, key: str, appearance: str, style: str = "") -> None:
        self.config = load_config()
        style = style or self.config.get("style", designs.DEFAULT_STYLE)
        changed = key != self.config.get("design") or style != self.config.get("style")
        self.config.update(design=key, appearance=appearance, style=style)
        if changed:
            self.config.pop("view_mode", None)
        save_config(self.config)
        self.theme = self._resolve_theme(key, appearance, style)
        self._apply_stylesheet()
        self._rebuild_pages(reset_view=changed)

    def _on_system_scheme(self) -> None:
        if load_config().get("appearance", "system") == "system":
            self.theme = self._resolve_theme(self.theme.design.key, "system")
            self._apply_stylesheet()
            self._rebuild_pages()

    def _rebuild_pages(self, reset_view: bool = False) -> None:
        path = self.unlock_page.path_edit.text()
        old = self.unlock_page
        self.unlock_page = self._make_unlock_page(path)
        self.stack.insertWidget(0, self.unlock_page)
        self.stack.removeWidget(old)
        old.deleteLater()
        if self.vhd_page:
            old_page = self.vhd_page
            self.stack.removeWidget(old_page)
            old_page.dispose()
            old_page.deleteLater()
            self._show_vhd_page()
        if self.session and self.workspace:
            folder = self.workspace.folder
            view = "" if reset_view else self.workspace.view_mode
            self._close_workspace()
            self._show_workspace(view, folder)

    def _show_workspace(self, view_mode: str = "", folder: str = "") -> None:
        self.workspace = Workspace(self.session, self.theme, view_mode, folder)
        self.workspace.lock_requested.connect(lambda: self.lock())
        self.workspace.switch_vault.connect(self._switch_vault)
        self.workspace.settings_requested.connect(self.open_settings)
        self.workspace.view_mode_changed.connect(self._remember_view)
        self.stack.addWidget(self.workspace)
        self.stack.setCurrentWidget(self.workspace)
        enable_elevated_drop(self, self._on_native_drop)
        self.setWindowTitle(tr("{} - Enclave", self.session.name))
        self._restart_idle()

    def _switch_vault(self, path: str) -> None:
        self.lock()
        if not self.session:
            self.unlock_page.set_vault(path)

    def _close_workspace(self) -> None:
        if self.workspace:
            self.workspace.dispose()
            self.stack.removeWidget(self.workspace)
            self.workspace.deleteLater()
            self.workspace = None

    def _remember_view(self, mode: str) -> None:
        self.config = load_config()
        self.config["view_mode"] = mode
        save_config(self.config)

    def _check_os_lock(self) -> None:
        """Windows kilitliyse açık kasayı ve sanal diski kapatır. Diğer sistemlerde bir şey yapmaz."""
        if sys.platform != "win32" or not (self.session or self.vhd_session or self.unlock_page.awaiting_code):
            return
        from engine import VHDEngine
        if VHDEngine.is_workstation_locked():
            self.lock_everything()

    def lock_everything(self) -> None:
        """Açık pencereleri kapatır, sonra kasayı ve sanal diski ayırır."""
        for widget in QApplication.topLevelWidgets():
            if widget is not self and isinstance(widget, QDialog) and widget.isVisible():
                getattr(widget, "close_for_lock", widget.close)()
        if self.vhd_session:
            self._close_vhd()
        if self.session:
            self.lock(automatic=True)
        if self.unlock_page.awaiting_code:
            self.unlock_page.cancel_code()

    def _show_vhd_page(self) -> None:
        self.vhd_page = VhdPage(self.vhd_session, self.theme, self._close_vhd, self.open_settings)
        self.stack.addWidget(self.vhd_page)
        self.stack.setCurrentWidget(self.vhd_page)
        self.setWindowTitle(tr("{} - Enclave", self.vhd_session.name))
        self.vhd_idle_timer.start()

    def _check_vhd_idle(self) -> None:
        minutes = load_config().get("idle_lock_minutes", 5)
        if minutes and self.vhd_session and self.vhd_session.idle_seconds() >= minutes * 60:
            self._close_vhd()

    def _close_vhd(self) -> bool:
        """Sanal diski ayırır. Ayrılamazsa kullanıcıya bildirir ve ekranı açık tutar."""
        if not self.vhd_session:
            return True
        try:
            self.vhd_session.close()
        except Exception as error:
            QMessageBox.warning(self, tr("Disk ayrılamadı"), tr("{}\n\nDiskteki açık dosyaları kapatıp yeniden deneyin.", error))
            return False
        self.vhd_idle_timer.stop()
        self.vhd_page.dispose()
        self.stack.removeWidget(self.vhd_page)
        self.vhd_page.deleteLater()
        self.vhd_page = None
        self.vhd_session = None
        self.setWindowTitle("Enclave")
        self.unlock_page.reset()
        self.stack.setCurrentWidget(self.unlock_page)
        return True

    def _on_unlocked(self, session) -> None:
        if isinstance(session, VhdSession):
            self.vhd_session = session
            self._show_vhd_page()
            return
        self.session = session
        self._show_workspace(load_config().get("view_mode", ""))
        self.workspace.offer_two_factor()

    def _save_copies(self, modified: List[Tuple[str, str]]) -> int:
        """Kopyaları kasaya alır, kaydedilemeyen dosya sayısını döndürür. Bir dosyanın hatası diğerlerini durdurmaz."""
        failed = 0
        for temp_path, rel_path in modified:
            try:
                self.session.save_temp_back(temp_path, rel_path)
            except (CustomVaultError, OSError):
                failed += 1
        return failed

    def _save_modified_copies(self, can_cancel: bool, ask: bool = True) -> bool:
        """
        Harici uygulamada değişmiş kopyaları kilitlemeden önce kasaya alır.
        Otomatik kilitte kullanıcı başında olmadığından sormaz ve kaydedilemeyen kopya kilidi engellemez:
        kasanın açık kalması, bir düzenlemenin kaybolmasından daha ağır bir sonuçtur.
        """
        if not self.session:
            return True
        modified = self.session.modified_temp_files()
        if not modified:
            return True
        if not ask:
            self._unsaved_copies = self._save_copies(modified)
            return True
        names = "\n".join(Path(rel).name for _, rel in modified[:8])
        box = QMessageBox(self)
        box.setWindowTitle(tr("Değişiklikler kasaya alınmadı"))
        box.setText(tr("Açtığınız dosyalar değişmiş:\n\n{}\n\nKasaya kaydedilsin mi? Kaydedilmezse değişiklikler silinir.", names))
        save = box.addButton(tr("Kasaya kaydet"), QMessageBox.ButtonRole.AcceptRole)
        box.addButton(tr("Değişiklikleri at"), QMessageBox.ButtonRole.DestructiveRole)
        cancel = box.addButton(tr("Vazgeç"), QMessageBox.ButtonRole.RejectRole) if can_cancel else None
        box.exec()
        if box.clickedButton() is cancel:
            return False
        if box.clickedButton() is save:
            failed = self._save_copies(modified)
            if failed:
                QMessageBox.warning(self, tr("Değişiklikler kaydedilemedi"),
                                    tr("{} dosyadaki değişiklik kasaya alınamadı. Kasa açık kaldı.", failed))
                return not can_cancel
        return True

    def _on_idle(self) -> None:
        busy = self.session and (self.session.maintenance or (self.workspace and self.workspace.is_busy))
        if busy:
            self._restart_idle()
        else:
            self.lock(automatic=True)

    def lock(self, automatic: bool = False) -> None:
        if not self.session:
            return
        self._unsaved_copies = 0
        if automatic:
            while (modal := QApplication.activeModalWidget()) is not None:
                getattr(modal, "close_for_lock", modal.close)()
            if self.workspace:
                self.workspace.stop_transfer()
        if not self._save_modified_copies(can_cancel=True, ask=not automatic):
            return
        self.idle_timer.stop()
        try:
            self._close_workspace()
        finally:
            self.session.close()
            self.session = None
            clear_secret_clipboard()
        self.setWindowTitle("Enclave")
        self.unlock_page.reset()
        self.stack.setCurrentWidget(self.unlock_page)
        if self._unsaved_copies:
            self.unlock_page.show_notice(tr("{} dosyadaki değişiklik kasaya alınamadı. Kasa yine de kilitlendi.", self._unsaved_copies))

    def _restart_idle(self) -> None:
        minutes = load_config().get("idle_lock_minutes", 5)
        if self.session and minutes:
            self.idle_timer.start(minutes * 60 * 1000)
        else:
            self.idle_timer.stop()

    def eventFilter(self, watched: QObject, event: QEvent) -> bool:
        if event.type() in ACTIVITY_EVENTS and self.stack.currentWidget() is self.unlock_page:
            self.unlock_page.mascot.nudge()
        if self.session and self.idle_timer.isActive() and event.type() in ACTIVITY_EVENTS:
            self.idle_timer.start()
        return super().eventFilter(watched, event)

    def _on_native_drop(self, paths: List[str]) -> None:
        if self.workspace and self.stack.currentWidget() is self.workspace:
            self.workspace.add_paths(paths)
        elif self.stack.currentWidget() is self.unlock_page and paths and Path(paths[0]).is_file():
            self.unlock_page.set_vault(paths[0])

    def showEvent(self, event) -> None:
        super().showEvent(event)
        enable_elevated_drop(self, self._on_native_drop)

    def changeEvent(self, event: QEvent) -> None:
        super().changeEvent(event)
        if (event.type() == QEvent.Type.WindowStateChange and self.isMinimized()
                and self.session and load_config().get("lock_on_minimize", False)):
            self.lock(automatic=True)

    def closeEvent(self, event) -> None:
        if not self._close_vhd():
            event.ignore()
            return
        if self.workspace and self.workspace.is_busy:
            if not confirm(self, tr("Aktarım sürüyor"), tr("Aktarım iptal edilecek. Biten dosyalar korunur."), tr("Kapat")):
                event.ignore()
                return
        if not self._save_modified_copies(can_cancel=True):
            event.ignore()
            return
        if self.session:
            self._close_workspace()
            self.session.close()
            self.session = None
        clear_secret_clipboard()
        event.accept()
        QApplication.quit()

    def _create_vault(self) -> None:
        dialog = CreateVaultDialog(self.theme, self)
        if dialog.exec() and dialog.created_path:
            self.unlock_page.set_vault(dialog.created_path)

    def open_settings(self) -> None:
        dialog = SettingsDialog(self.theme, self.session, self)
        dialog.design_changed.connect(self.set_design)
        dialog.mascot_changed.connect(lambda kind: self.unlock_page.mascot.set_kind(kind))
        dialog.exec()
        if dialog.chosen_language:
            config = load_config()
            config["language"] = dialog.chosen_language
            save_config(config)
            set_language(dialog.chosen_language)
            self._rebuild_pages()
            self.open_settings()
            return
        if self.session:
            self._restart_idle()
            if self.workspace:
                self.workspace.reload()
