"""Enclave - Bağlı sanal disk ekranı. VHD ve BitLocker işlemleri yeni arayüzde burada yapılır."""

from typing import Any, Callable, List, Optional

from PyQt6.QtCore import QTimer, Qt
from PyQt6.QtWidgets import QFrame, QHBoxLayout, QVBoxLayout, QWidget

from .i18n import tr
from .common import CapacityBar, LoadingBars, Task, Theme, button, label
from .dialogs import ChangePasswordDialog, RecoveryKeyDialog
from .vhd_service import VhdSession

class VhdPage(QWidget):

    def __init__(self, session: VhdSession, theme: Theme, on_lock: Callable, on_settings: Callable,
                 parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setObjectName("Page")
        self.session = session
        self.theme = theme
        self._tasks: List[Task] = []

        card = QFrame()
        card.setObjectName("Card")
        body = QVBoxLayout(card)
        body.setContentsMargins(28, 24, 28, 24)
        body.setSpacing(14)
        body.addWidget(label(tr("SANAL DİSK"), "Eyebrow"))
        body.addWidget(label(session.name, "Title"))
        self.drive = label(name="Muted")
        body.addWidget(self.drive)
        self.usage = CapacityBar()
        body.addWidget(self.usage)

        main = QHBoxLayout()
        main.setSpacing(8)
        main.addWidget(button(tr("Dosya Gezgini'nde aç"), "Primary", session.open_in_explorer, theme.icon("open", theme.palette.on_accent)), 1)
        main.addWidget(button(tr("Kilitle ve ayır"), on_click=on_lock, icon_=theme.icon("lock")))
        body.addLayout(main)

        body.addWidget(label(tr("BitLocker ve bakım"), "Section"))
        tools = QHBoxLayout()
        tools.setSpacing(8)
        tools.addWidget(button(tr("Kurtarma anahtarı"), on_click=self._show_recovery_key))
        tools.addWidget(button(tr("Parolayı değiştir"), on_click=self._change_password))
        tools.addWidget(button(tr("Disk sağlığı"), on_click=self._check_health))
        tools.addWidget(button(tr("Ayarlar"), on_click=on_settings))
        tools.addStretch(1)
        body.addLayout(tools)
        self.busy = LoadingBars(theme)
        body.addWidget(self.busy)
        self.note = label(name="Muted")
        body.addWidget(self.note)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(24, 24, 24, 24)
        outer.addStretch(1)
        row = QHBoxLayout()
        row.addStretch(1)
        row.addWidget(card, 4)
        row.addStretch(1)
        outer.addLayout(row)
        outer.addStretch(2)
        self.refresh()
        self.usage_timer = QTimer(self)
        self.usage_timer.setInterval(1500)
        self.usage_timer.timeout.connect(self.refresh)
        self.usage_timer.start()

    def refresh(self) -> None:
        if not self.session.drive_letter:
            return
        status = self.session.status()
        total, free = status.get("total_bytes", 0), status.get("free_bytes", 0)
        self.drive.setText(tr("Sürücü {}", self.session.drive_letter))
        self.usage.set_values(total - free, total or None)

    def _run(self, work: Callable[[], Any], done: Callable[[Any], None]) -> None:
        self.note.setText(tr("İşlem sürüyor..."))
        task = Task(lambda _progress, _cancelled: work(), self)
        task.succeeded.connect(done)
        task.failed.connect(self.note.setText)
        task.finished.connect(lambda: self._task_ended(task))
        self._tasks.append(task)
        self.busy.start()
        task.start()

    def _task_ended(self, task: Task) -> None:
        self._tasks.remove(task)
        if not self._tasks:
            self.busy.stop()

    def _show_recovery_key(self) -> None:
        def done(result: dict) -> None:
            key = result.get("recovery_key") or result.get("key")
            if key:
                self.note.setText("")
                RecoveryKeyDialog(key, self.session.path, self.theme, self).exec()
            else:
                self.note.setText(result.get("error", "Kurtarma anahtarı bulunamadı."))
        self._run(self.session.recovery_key, done)

    def _change_password(self) -> None:
        if ChangePasswordDialog(self.session, self.theme, self).exec():
            self.note.setText(tr("BitLocker parolası değiştirildi."))

    def _check_health(self) -> None:
        self._run(self.session.check_health, lambda r: self.note.setText(r.get("message") or r.get("error", "")))

    def dispose(self) -> None:
        self.usage_timer.stop()
        for task in list(self._tasks):
            task.wait()
