"""Enclave - Kasa açma ekranı. Her tasarım aynı formu kendi düzeninde sunar."""

import time
from pathlib import Path
from typing import Callable, List, Optional

from PyQt6.QtCore import QTimer, Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QInputDialog, QFileDialog, QFrame, QGridLayout, QHBoxLayout, QLineEdit, QMenu,
    QStackedWidget, QVBoxLayout, QWidget,
)

from config import load_config, save_config
from enclave_core import CustomVaultError, InvalidPasswordError, read_key_file

from .i18n import tr
from .common import LoadingBars, PasswordField, Task, Theme, button, confirm, horizontal_rule, label
from .extras import ShaDialog, WrapCarrierDialog, StripCarrierDialog
from .mascot import DEFAULT_MASCOT, CyberMascot
from .motion import BackdropFrame, fade_in
from .session import VaultSession, cloud_provider
from . import vhd_service
from .dialogs import ChangePasswordDialog, RecoveryKeyDialog

IDLE_CHOICES = (("Kapalı", 0), ("1 dakika", 1), ("5 dakika", 5), ("15 dakika", 15), ("30 dakika", 30))

class UnlockPage(QWidget):
    unlocked = pyqtSignal(object)
    create_requested = pyqtSignal()
    settings_requested = pyqtSignal()

    MAX_DELAY = 16

    def __init__(self, theme: Theme, initial_path: str = "", parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setObjectName("Page")
        self.theme = theme
        self._task: Optional[Task] = None
        self._session: Optional[VaultSession] = None
        self._failures = 0
        self._retry_at = 0.0
        self._code_failures = 0
        self._code_retry_at = 0.0
        self._recovering = False
        self._key_digest: Optional[bytes] = None
        self._build_form()
        self._arrange()
        self._load_remembered()
        if initial_path:
            self.set_vault(initial_path)

    def _build_form(self) -> None:
        self.path_edit = QLineEdit()
        self.path_edit.setPlaceholderText(tr("Kasa dosyası (.pvault, .vhd, medya)"))
        self.path_edit.setAccessibleName(tr("Kasa dosyası yolu"))
        self.path_edit.textChanged.connect(self._on_path_changed)
        self.browse_button = button(tr("Gözat"), on_click=self._browse)

        self.password = PasswordField(self.theme, tr("Parola"))
        self.password.edit.setAccessibleName(tr("Kasa parolası"))
        self.password.returnPressed.connect(self._submit_password)
        self.password.textChanged.connect(self._on_password_typed)

        self.key_file_button = button(tr("Anahtar dosyası seç"), "Link", self._toggle_key_file)
        self.key_file_button.setToolTip(tr("Kasada anahtar dosyası kullanıyorsanız seçin. Yol hiçbir yere kaydedilmez."))

        self.remember = QCheckBox(tr("Bu kasayı bu cihazda hatırla"))
        self.remember.setToolTip(tr("Kasa yolu şifresiz ayar dosyasına yazılır. Gizliliği önemliyse işaretlemeyin."))

        self.error = label(name="Error")
        self.error.hide()
        self.cloud_note = label(name="Notice")
        self.cloud_note.hide()
        self.busy = LoadingBars(self.theme)
        self.open_button = button(tr("Kilidi aç"), "Primary", self._submit_password)
        self.new_button = button(tr("Yeni kasa"), on_click=self.create_requested.emit)
        self.settings_button = button(tr("Ayarlar"), "Link", self.settings_requested.emit, self.theme.icon("settings"))
        self.recover_button = button(tr("Parolamı unuttum"), "Link", self._recover)
        self.mascot = CyberMascot(self.theme, kind=load_config().get("mascot", DEFAULT_MASCOT))
        self.extras_button = button(tr("Ekstralar"), "Link", icon_=self.theme.icon("shield"))
        self.extras_button.setToolTip(tr("Kasa açmadan kullanılan araçlar"))
        extras = QMenu(self.extras_button)
        extras.addAction(self.theme.icon("shield"), tr("SHA-256 hesapla..."), lambda: self._open_sha(False))
        extras.addAction(self.theme.icon("shield"), tr("SHA-256 karşılaştır..."), lambda: self._open_sha(True))
        extras.addSeparator()
        extras.addAction(self.theme.icon("eye"), tr("Kasaya medya kılıfı giydir (Kamuflaj)..."), self._open_wrap_carrier)
        extras.addAction(self.theme.icon("eye-off"), tr("Kasadan medya kılıfını çıkar (Saf .pvault)..."), self._open_strip_carrier)
        self.extras_button.setMenu(extras)

        self.code_edit = QLineEdit()
        self.code_edit.setPlaceholderText("000000")
        self.code_edit.setAccessibleName(tr("Doğrulama kodu"))
        self.code_edit.returnPressed.connect(self._submit_code)
        self.code_button = button(tr("Doğrula"), "Primary", self._submit_code)
        self.code_back = button(tr("Geri"), on_click=self._cancel_code)
        self.code_error = label(name="Error")
        self.code_error.hide()

        self._recent_open = False
        self._recent_title = ""
        config = load_config()
        self.idle = QComboBox()
        self.idle.setAccessibleName(tr("Hareketsizlikte kilitle"))
        for title, minutes in IDLE_CHOICES:
            self.idle.addItem(tr(title), minutes)
        self.idle.setCurrentIndex(max(0, self.idle.findData(config.get("idle_lock_minutes", 5))))
        self.idle.currentIndexChanged.connect(self._save_security)
        self.lock_minimize = QCheckBox(tr("Pencere küçültülünce kilitle"))
        self.lock_minimize.setChecked(bool(config.get("lock_on_minimize", False)))
        self.lock_minimize.toggled.connect(self._save_security)

        self.recent_box = QWidget()
        self.recent_layout = QVBoxLayout(self.recent_box)
        self.recent_layout.setContentsMargins(0, 0, 0, 0)
        self.recent_layout.setSpacing(4)
        self.recent_toggle = button("", "Link", lambda: self._set_recent_open(not self._recent_open))
        self.recent_toggle.setAccessibleName(tr("Hatırlanan kasaları aç veya kapat"))
        self.recent_list = QWidget()
        self.recent_list_layout = QVBoxLayout(self.recent_list)
        self.recent_list_layout.setContentsMargins(0, 0, 0, 0)
        self.recent_list_layout.setSpacing(2)
        self.recent_list.hide()
        self.recent_layout.addWidget(self.recent_toggle)
        self.recent_layout.addWidget(self.recent_list)

        self.form_stack = QStackedWidget()
        self.form_stack.addWidget(self._password_step())
        self.form_stack.addWidget(self._code_step())

    def _password_step(self) -> QWidget:
        step = QWidget()
        layout = QVBoxLayout(step)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        layout.addWidget(self.recent_box)
        layout.addWidget(label(tr("Kasa"), "Eyebrow"))
        row = QHBoxLayout()
        row.setSpacing(8)
        row.addWidget(self.path_edit, 1)
        row.addWidget(self.browse_button)
        layout.addLayout(row)
        layout.addWidget(self.cloud_note)
        layout.addSpacing(4)
        layout.addWidget(label(tr("Parola"), "Eyebrow"))
        layout.addWidget(self.password)
        layout.addWidget(self.key_file_button, 0, Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(self.remember)
        layout.addWidget(self.error)
        layout.addWidget(self.busy)
        layout.addSpacing(4)
        actions = QHBoxLayout()
        actions.setSpacing(8)
        actions.addWidget(self.open_button, 1)
        actions.addWidget(self.new_button)
        layout.addLayout(actions)
        layout.addWidget(self.recover_button, 0, Qt.AlignmentFlag.AlignLeft)
        layout.addSpacing(4)
        layout.addWidget(horizontal_rule())
        layout.addWidget(label(tr("Güvenlik"), "Eyebrow"))
        idle_row = QHBoxLayout()
        idle_row.setSpacing(10)
        idle_row.addWidget(label(tr("Hareketsizlikte kilitle"), "Muted", wrap=False))
        idle_row.addWidget(self.idle)
        idle_row.addStretch(1)
        layout.addLayout(idle_row)
        layout.addWidget(self.lock_minimize)
        layout.addWidget(label(tr("Windows kilitlendiğinde açık kasa her zaman kilitlenir."), "Muted"))
        return step

    def _code_step(self) -> QWidget:
        step = QWidget()
        layout = QVBoxLayout(step)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        layout.addWidget(label(tr("Doğrulama kodu"), "Section"))
        layout.addWidget(label(tr("Doğrulayıcı uygulamadaki 6 haneli kodu veya bir kurtarma kodunu girin."), "Muted"))
        layout.addWidget(self.code_edit)
        layout.addWidget(self.code_error)
        actions = QHBoxLayout()
        actions.setSpacing(8)
        actions.addWidget(self.code_button, 1)
        actions.addWidget(self.code_back)
        layout.addLayout(actions)
        layout.addStretch(1)
        return step

    def _arrange(self) -> None:
        self._arrange_split()

    def _arrange_centered(self) -> None:
        card = QFrame()
        card.setObjectName("Card")
        inner = QVBoxLayout(card)
        inner.setContentsMargins(28, 26, 28, 24)
        inner.setSpacing(14)
        head = QHBoxLayout()
        head.setSpacing(14)
        self.mascot.setFixedSize(84, 84)
        head.addWidget(self.mascot)
        titles = QVBoxLayout()
        titles.setSpacing(2)
        titles.addWidget(label("Enclave", "Title"))
        titles.addWidget(label(tr("Kasanız kilitli"), "Muted"))
        head.addLayout(titles, 1)
        inner.addLayout(head)
        inner.addWidget(self.form_stack)
        foot = QHBoxLayout()
        foot.addStretch(1)
        foot.addWidget(self.settings_button)
        inner.addLayout(foot)

        grid = QGridLayout(self)
        grid.setContentsMargins(20, 20, 20, 20)
        grid.addWidget(card, 1, 1)
        grid.setRowStretch(0, 1)
        grid.setRowStretch(2, 1)
        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 3)
        grid.setColumnStretch(2, 1)

    def _arrange_split(self) -> None:
        cover = BackdropFrame(self.theme)
        left = QVBoxLayout(cover)
        left.setContentsMargins(40, 32, 40, 28)
        left.setSpacing(10)
        left.addWidget(self.mascot, 3)
        left.addWidget(label("Enclave", "RailTitle"))
        left.addWidget(label(tr("Dosyalarınız şifreli olarak tek bir kasa dosyasında durur. Parola olmadan içeriği, "
                             "dosya adları dahil, okunamaz."), "RailHead"))
        left.addStretch(1)

        self.form_card = QFrame()
        self.form_card.setObjectName("Card")
        card_layout = QVBoxLayout(self.form_card)
        card_layout.setContentsMargins(26, 24, 26, 22)
        card_layout.addWidget(self.form_stack)
        right = QVBoxLayout()
        right.setContentsMargins(36, 16, 20, 28)
        top = QHBoxLayout()
        top.setSpacing(4)
        top.addStretch(1)
        top.addWidget(self.extras_button)
        top.addWidget(self.settings_button)
        right.addLayout(top)
        right.addStretch(1)
        form_row = QHBoxLayout()
        form_row.setContentsMargins(0, 0, 16, 0)
        form_row.addWidget(self.form_card)
        right.addLayout(form_row)
        right.addStretch(1)

        row = QHBoxLayout(self)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(0)
        row.addWidget(cover, 5)
        row.addLayout(right, 6)

    def _arrange_poster(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(56, 44, 56, 40)
        outer.setSpacing(16)
        top = QHBoxLayout()
        top.setSpacing(12)
        self.mascot.setFixedSize(64, 64)
        top.addWidget(self.mascot)
        top.addWidget(label("Enclave", "Section", wrap=False))
        top.addStretch(1)
        top.addWidget(self.settings_button)
        outer.addLayout(top)
        outer.addStretch(2)
        outer.addWidget(label(tr("Kilitli"), "Display"))
        limited = QHBoxLayout()
        limited.addWidget(self.form_stack, 5)
        limited.addStretch(3)
        outer.addLayout(limited)
        outer.addStretch(1)

    def _load_remembered(self) -> None:
        while self.recent_list_layout.count():
            item = self.recent_list_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        existing: List[str] = [p for p in load_config().get("remembered_vaults", []) if Path(p).exists()]
        if not existing:
            self.recent_box.hide()
            return
        self.recent_box.show()
        self._recent_title = tr("Hatırlanan kasalar ({})", len(existing))
        for path in existing:
            item = button(Path(path).stem, "RecentVault", lambda p=path: self.set_vault(p),
                          self.theme.icon("lock", self.theme.palette.muted))
            item.setToolTip(path)
            self.recent_list_layout.addWidget(item)
        self._set_recent_open(False)
        if not self.path_edit.text():
            self.set_vault(existing[0])

    def _save_security(self, *_args: object) -> None:
        config = load_config()
        config["idle_lock_minutes"] = self.idle.currentData()
        config["lock_on_minimize"] = self.lock_minimize.isChecked()
        save_config(config)

    def _set_recent_open(self, opened: bool) -> None:
        self._recent_open = opened
        self.recent_list.setVisible(opened)
        self.recent_toggle.setText(("▾  " if opened else "▸  ") + self._recent_title)

    def set_vault(self, path: str) -> None:
        self._set_recent_open(False)
        self.path_edit.setText(path)
        self.path_edit.setCursorPosition(0)
        self.path_edit.setToolTip(path)
        self.remember.setChecked(path in load_config().get("remembered_vaults", []))
        self.password.setFocus()

    def _browse(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, tr("Kasa dosyasını seçin"), "",
            tr("Kasa dosyaları (*.pvault *.vhd *.vhdx *.mp4 *.mkv *.mov *.avi *.webm *.mp3 *.flac *.wav *.png *.jpg *.jpeg *.webp *.iso *.zip);;Tüm dosyalar (*)")
        )
        if path:
            self.set_vault(path)

    def _on_path_changed(self, path: str) -> None:
        provider = cloud_provider(path) if path else None
        self.cloud_note.setVisible(bool(provider))
        if provider:
            self.cloud_note.setText(tr("Kasa {} klasöründe. Eşitleme bitmeden başka cihazda açarsanız değişiklikler kaybolabilir.", provider))

    def _show_error(self, text: str) -> None:
        self.error.setText(text)
        self.error.setVisible(bool(text))
        if text:
            self.mascot.alert()

    def _on_password_typed(self, text: str) -> None:
        if text:
            self.mascot.pick_lock()
        else:
            self.mascot.stop_picking()

    def _toggle_key_file(self) -> None:
        """Seçili değilse dosya sorar, seçiliyse bırakır. Yalnızca özet bellekte tutulur."""
        if self._key_digest:
            self._forget_key_file()
            return
        path, _ = QFileDialog.getOpenFileName(self, tr("Anahtar dosyasını seçin"), "", tr("Tüm dosyalar (*)"))
        if not path:
            return
        try:
            self._key_digest = read_key_file(path)
        except CustomVaultError as error:
            self._show_error(tr(str(error)))
            return
        self.key_file_button.setText(tr("Anahtar dosyası seçildi: {} (kaldır)", Path(path).name))

    def _forget_key_file(self) -> None:
        self._key_digest = None
        self.key_file_button.setText(tr("Anahtar dosyası seç"))

    def _open_sha(self, compare: bool) -> None:
        ShaDialog(self.theme, compare, self).exec()

    def _open_wrap_carrier(self) -> None:
        current_path = self.path_edit.text().strip()
        initial_path = current_path if current_path.endswith(".pvault") and Path(current_path).is_file() else ""
        WrapCarrierDialog(self.theme, initial_vault_path=initial_path, parent=self).exec()

    def _open_strip_carrier(self) -> None:
        current_path = self.path_edit.text().strip()
        initial_path = current_path if not current_path.endswith(".pvault") and Path(current_path).is_file() else ""
        StripCarrierDialog(self.theme, initial_stego_path=initial_path, parent=self).exec()

    def _set_busy(self, busy: bool) -> None:
        if busy:
            self.busy.start()
        else:
            self.busy.stop()
        for widget in (self.open_button, self.new_button, self.path_edit, self.browse_button, self.password,
                       self.key_file_button, self.settings_button):
            widget.setEnabled(not busy)

    def _recover(self) -> None:
        if self._task:
            return
        path = self.path_edit.text().strip()
        if not path or not Path(path).is_file():
            self._show_error(tr("Önce kasa dosyasını seçin."))
            return
        if vhd_service.is_virtual_disk(path):
            self._recover_virtual_disk(path)
            return
        key, ok = QInputDialog.getText(self, tr("Kurtarma anahtarı"), tr("Kurtarma anahtarını girin:"))
        if not ok or not key.strip():
            return
        session = VaultSession(path)
        try:
            needs_code = session.unlock_with_recovery_key(key)
        except CustomVaultError as error:
            self._show_error(tr(str(error)))
            return
        self._session = session
        if needs_code:
            self._recovering = True
            self._show_code_step()
            return
        self._finish_recovery()

    def _finish_recovery(self) -> None:
        """Kurtarma yalnızca yeni parola belirlenince tamamlanır; vazgeçilirse kasa kapanır."""
        session = self._session
        if ChangePasswordDialog(session, self.theme, self).exec():
            RecoveryKeyDialog(session.recovery_key(), session.path, self.theme, self).exec()
            self._finish()
        else:
            self._cancel_code()

    def _recover_virtual_disk(self, path: str) -> None:
        if vhd_service.needs_elevation():
            if confirm(self, tr("Yönetici izni"), tr("Sanal disk bağlamak için uygulama yönetici olarak yeniden açılacak."),
                       tr("Yeniden aç"), danger=False) and vhd_service.elevate([path]):
                QApplication.quit()
            return
        key, ok = QInputDialog.getText(self, tr("Kurtarma anahtarı"), tr("48 haneli BitLocker kurtarma anahtarını girin:"))
        if not ok or not key.strip():
            return
        self._show_error("")
        self._set_busy(True)
        session = vhd_service.VhdSession(path)

        def work(_progress: Callable, _cancelled: Callable) -> None:
            session.unlock_with_recovery_key(key)

        self._task = Task(work, self)
        self._task.succeeded.connect(lambda _result: self._on_disk_recovered(session))
        self._task.failed.connect(self._on_recovery_failed)
        self._task.start()

    def _on_disk_recovered(self, session: vhd_service.VhdSession) -> None:
        self._task = None
        self._set_busy(False)
        self._failures = 0
        ChangePasswordDialog(session, self.theme, self).exec()
        self._session = session
        self._finish()

    def _on_recovery_failed(self, message: str) -> None:
        self._task = None
        self._set_busy(False)
        self._show_error(message)

    def _submit_password(self) -> None:
        if self._task:
            return
        path = self.path_edit.text().strip()
        password = self.password.text()
        if not path or not Path(path).is_file():
            self._show_error(tr("Kasa dosyası bulunamadı."))
            return
        virtual_disk = vhd_service.is_virtual_disk(path)
        if not password and not virtual_disk:
            self._show_error(tr("Parolayı girin."))
            self.password.setFocus()
            return
        if virtual_disk and vhd_service.needs_elevation():
            if confirm(self, tr("Yönetici izni"), tr("Sanal disk bağlamak için uygulama yönetici olarak yeniden açılacak."),
                       tr("Yeniden aç"), danger=False) and vhd_service.elevate([path]):
                QApplication.quit()
            return
        wait = self._retry_at - time.monotonic()
        if wait > 0:
            self._show_error(tr("Çok fazla hatalı deneme. {} saniye bekleyin.", int(wait) + 1))
            return

        self._show_error("")
        self._set_busy(True)
        session = vhd_service.VhdSession(path) if virtual_disk else VaultSession(path)
        key_digest = self._key_digest

        def work(_progress: Callable, _cancelled: Callable) -> bool:
            return session.unlock(password) if virtual_disk else session.unlock(password, key_digest)

        self._task = Task(work, self)
        self._task.succeeded.connect(lambda needs_code: self._on_password_ok(session, needs_code))
        self._task.failed.connect(self._on_password_failed)
        self._task.start()

    def _on_password_ok(self, session: VaultSession, needs_code: bool) -> None:
        self._task = None
        self._set_busy(False)
        self._failures = 0
        self._session = session
        if needs_code:
            self._show_code_step()
            return
        self._finish()

    def _show_code_step(self) -> None:
        self.code_edit.clear()
        self.code_error.hide()
        self.form_stack.setCurrentIndex(1)
        self.code_edit.setFocus()

    def _on_password_failed(self, message: str) -> None:
        self._task = None
        self._set_busy(False)
        self.password.clear()
        self.password.setFocus()
        wrong_password = "parola" in message.lower() or "password" in message.lower()
        if wrong_password:
            self._failures += 1
            delay = min(self.MAX_DELAY, 2 ** (self._failures - 1)) if self._failures > 2 else 0
            self._retry_at = time.monotonic() + delay
            self._show_error(tr("Parola veya anahtar dosyası yanlış.") + (tr(" {} saniye sonra tekrar deneyin.", delay) if delay else ""))
        else:
            self._show_error(message)

    def _submit_code(self) -> None:
        code = self.code_edit.text().strip()
        if not code or not self._session or time.monotonic() < self._code_retry_at:
            return
        try:
            ok, _message = self._session.verify_second_factor(code)
        except (CustomVaultError, OSError, ValueError) as error:
            ok, _message = False, str(error)
        if ok:
            self._code_failures = 0
            if self._recovering:
                self._recovering = False
                self._finish_recovery()
            else:
                self._finish()
            return
        self.code_error.setText(tr("Kod geçersiz veya az önce kullanıldı. Yeni kodu bekleyin; saatin doğru olduğundan emin olun."))
        self.code_error.show()
        self.mascot.alert()
        self.code_edit.clear()
        self._code_failures += 1
        delay = min(self.MAX_DELAY, 2 ** self._code_failures)
        self._code_retry_at = time.monotonic() + delay
        self.code_button.setEnabled(False)
        QTimer.singleShot(delay * 1000, lambda: self.code_button.setEnabled(True))

    @property
    def awaiting_code(self) -> bool:
        """Parola doğrulandı, kod bekleniyor: anahtarlar bu aşamada da bellektedir."""
        return self._session is not None

    def cancel_code(self) -> None:
        self._cancel_code()

    def show_notice(self, text: str) -> None:
        self._show_error(text)

    def _cancel_code(self) -> None:
        self._recovering = False
        if self._session:
            self._session.close()
            self._session = None
        self.form_stack.setCurrentIndex(0)
        self.password.clear()
        self.password.setFocus()

    def _finish(self) -> None:
        session, self._session = self._session, None
        self._update_remembered(session.path)
        self.password.clear()
        self._forget_key_file()
        self.form_stack.setCurrentIndex(0)
        self.mascot.celebrate()
        self.unlocked.emit(session)

    def _update_remembered(self, path: str) -> None:
        config = load_config()
        remembered = [p for p in config.get("remembered_vaults", []) if p != path]
        if self.remember.isChecked():
            remembered.insert(0, path)
        if remembered != config.get("remembered_vaults", []):
            config["remembered_vaults"] = remembered
            save_config(config)

    def showEvent(self, event) -> None:
        super().showEvent(event)
        (self.password if self.path_edit.text() else self.path_edit).setFocus()
        if self.theme.design.animated and hasattr(self, "form_card"):
            fade_in(self.form_card)

    def reset(self) -> None:
        """Kilitlendikten sonra formu temizler."""
        self._show_error("")
        self.password.clear()
        self._forget_key_file()
        self.form_stack.setCurrentIndex(0)
        self._load_remembered()
        self.password.setFocus()
