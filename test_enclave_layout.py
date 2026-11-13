"""
Enclave - Pencere yerleşim (taşma / kırpılma / hizasızlık) testleri.
Her pencere Türkçe ve İngilizce, farklı boyutlarda açılır; sığmayan etiket ve butonlar,
ana pencereden taşan öğeler ve yatay kaydırma gerektiren içerik raporlanır.
Çalıştırma: python -m unittest test_enclave_layout -v
"""

import atexit
import os
import shutil
import sys
import tempfile
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
_CONFIG_HOME = tempfile.mkdtemp(prefix="vault_cfg_")
atexit.register(shutil.rmtree, _CONFIG_HOME, ignore_errors=True)
os.environ["APPDATA"] = _CONFIG_HOME
os.environ["XDG_CONFIG_HOME"] = _CONFIG_HOME

from PyQt6.QtWidgets import (
    QAbstractScrollArea, QApplication, QCheckBox, QLabel, QPushButton, QScrollArea, QToolButton, QWidget,
)

import enclave_app.i18n as i18n
from enclave_core import CustomVaultEngine as E
from enclave_app import designs
from enclave_app.common import ElidedLabel, Theme
from enclave_app.dialogs import (
    ChangePasswordDialog, CreateVaultDialog, RecoveryKeyDialog, SettingsDialog, TwoFactorDialog,
)
from enclave_app.extras import ShaDialog, StripCarrierDialog, WrapCarrierDialog
from enclave_app.pwd_dialogs import (
    EntryEditorDialog, HealthAuditDialog, ImportExportDialog, PasswordGeneratorDialog,
)
from enclave_app.pwd_engine import PasswordEntry, PasswordStore
from enclave_app.session import VaultSession
from enclave_app.window import VaultWindow, load_bundled_fonts
from enclave_app.workspace import Workspace

app = QApplication.instance() or QApplication([])
load_bundled_fonts()

TOLERANCE = 2


def _scroll_ancestor(widget: QWidget):
    parent = widget.parentWidget()
    while parent is not None:
        if isinstance(parent, QAbstractScrollArea):
            return parent
        parent = parent.parentWidget()
    return None


def _text(widget: QWidget) -> str:
    for cls in (QLabel, QPushButton, QToolButton, QCheckBox):
        if isinstance(widget, cls):
            return cls.text(widget)
    return ""


def find_problems(root: QWidget) -> list:
    """Kök pencere içindeki yerleşim sorunlarını metin olarak döndürür."""
    problems = []
    app.processEvents()
    for widget in root.findChildren(QWidget):
        if not widget.isVisibleTo(root) or widget.width() <= 0:
            continue
        name = f"{type(widget).__name__}({widget.objectName() or _text(widget)[:28]})"

        # Etiket: tek satırlık ve kısaltılmayan metin kutudan taşıyor mu?
        if isinstance(widget, QLabel) and not isinstance(widget, ElidedLabel):
            text = QLabel.text(widget)
            if text and not widget.wordWrap() and widget.pixmap().isNull() and "<" not in text:
                need = widget.fontMetrics().horizontalAdvance(text)
                if need > widget.width() - widget.contentsMargins().left() - widget.contentsMargins().right() + 6 \
                        and widget.sizeHint().width() > widget.width() + TOLERANCE:
                    problems.append(f"etiket kırpılıyor: {name} gerek={need} var={widget.width()} '{text[:40]}'")
            if widget.wordWrap() and text and widget.height() < widget.fontMetrics().height():
                problems.append(f"sarmalı etiket ezilmiş: {name} yükseklik={widget.height()}")

        # Buton: metin + ikon sığıyor mu?
        elif isinstance(widget, (QPushButton, QToolButton)) and _text(widget):
            hint = widget.sizeHint().width()
            if hint > widget.width() + TOLERANCE and widget.minimumSizeHint().width() > widget.width() + TOLERANCE:
                problems.append(f"buton metni kırpılıyor: {name} gerek={hint} var={widget.width()}")
        elif isinstance(widget, QCheckBox) and _text(widget):
            if widget.sizeHint().width() > widget.width() + TOLERANCE:
                problems.append(f"onay kutusu metni kırpılıyor: {name} gerek={widget.sizeHint().width()} var={widget.width()}")

        # Kaydırma alanı dışında kalan öğe ana pencerenin dışına taşıyor mu?
        scroller = _scroll_ancestor(widget)
        if scroller is None:
            top_left = widget.mapTo(root, widget.rect().topLeft())
            if top_left.x() + widget.width() > root.width() + TOLERANCE or top_left.x() < -TOLERANCE:
                problems.append(f"pencereden taşıyor: {name} x={top_left.x()} w={widget.width()} pencere={root.width()}")

    # Yatay kaydırma çubuğu belirmesi, içerik genişliğinin sığmadığını gösterir
    for area in root.findChildren(QAbstractScrollArea):
        if area.isVisibleTo(root) and area.horizontalScrollBar().isVisibleTo(root) \
                and area.horizontalScrollBar().maximum() > 0 and not isinstance(area, QScrollArea):
            problems.append(f"yatay kaydırma çıkıyor: {type(area).__name__}({area.objectName()})")
        if isinstance(area, QScrollArea) and area.isVisibleTo(root) and area.widget() is not None \
                and area.horizontalScrollBar().maximum() > 0:
            problems.append(f"yatay kaydırma çıkıyor: QScrollArea({area.objectName()}) taşma={area.horizontalScrollBar().maximum()}")
    return problems


class LayoutTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="pvault_layout_")
        cls.vault_path = os.path.join(cls.tmp, "layout.pvault")
        E.create_vault(cls.vault_path, "LayoutPassword123!")
        cls.session = VaultSession(cls.vault_path)
        cls.session.unlock("LayoutPassword123!")
        cls.store = PasswordStore(cls.session)
        cls.store.add(PasswordEntry(
            title="Çok uzun başlıklı bir kayıt adı: Üretim Bulut Konsolu Yönetici Hesabı",
            type="login", username="uzun.kullanici.adi.ornegi@cok-uzun-bir-alan-adi.example.com",
            password="s3Cur3#P@ssw0rd!2026-XyZ", url="https://example.com/a/very/long/path/to/console/login",
            totp_secret="JBSWY3DPEHPK3PXP", favorite=True, tags=["Bulut", "Üretim", "Altyapı"],
            notes="Uzun not satırı " * 12,
        ))
        cls.store.add(PasswordEntry(title="Kısa", type="note", notes="x"))
        cls.theme = Theme(designs.get_design("purple", "card"), dark=True)
        app.setStyleSheet(designs.build_stylesheet(cls.theme.design, cls.theme.dark))

    @classmethod
    def tearDownClass(cls):
        cls.session.close()
        shutil.rmtree(cls.tmp, ignore_errors=True)
        i18n.set_language("tr")

    def _check(self, factory, label, sizes=None):
        failures = []
        for lang in ("tr", "en"):
            i18n.set_language(lang)
            widget = factory()
            try:
                for size in (sizes or [None]):
                    if size:
                        widget.resize(*size)
                    widget.show()
                    app.processEvents()
                    for problem in find_problems(widget):
                        failures.append(f"[{lang} {size or widget.size().width()}] {problem}")
            finally:
                widget.close()
                widget.deleteLater()
        self.assertEqual(failures, [], f"{label} yerleşim sorunları:\n" + "\n".join(failures))

    # ---- Diyaloglar -------------------------------------------------------------------------------------------
    def test_settings_dialog(self):
        self._check(lambda: SettingsDialog(self.theme, self.session), "Ayarlar")

    def test_create_vault_dialog(self):
        self._check(lambda: CreateVaultDialog(self.theme), "Kasa oluştur")

    def test_change_password_dialog(self):
        self._check(lambda: ChangePasswordDialog(self.session, self.theme), "Parola değiştir")

    def test_two_factor_dialog(self):
        self._check(lambda: TwoFactorDialog(self.session, self.theme), "İki adımlı doğrulama")

    def test_recovery_key_dialog(self):
        self._check(lambda: RecoveryKeyDialog("ABCD-EFGH-IJKL-MNOP-QRST-UVWX", self.vault_path, self.theme), "Kurtarma anahtarı")

    def test_sha_dialog(self):
        self._check(lambda: ShaDialog(self.theme, False), "SHA")
        self._check(lambda: ShaDialog(self.theme, True), "SHA karşılaştır")

    def test_carrier_dialogs(self):
        self._check(lambda: WrapCarrierDialog(self.theme), "Kılıf giydir")
        self._check(lambda: StripCarrierDialog(self.theme), "Kılıf çıkar")

    def test_password_dialogs(self):
        self._check(lambda: PasswordGeneratorDialog(self.theme), "Parola üreteci")
        self._check(lambda: HealthAuditDialog(self.theme, self.store), "Güvenlik raporu")
        self._check(lambda: ImportExportDialog(self.theme, self.store), "İçe/Dışa aktar")
        self._check(lambda: EntryEditorDialog(self.theme, self.store), "Kayıt düzenleyici")
        self._check(lambda: EntryEditorDialog(self.theme, self.store, entry=self.store.all()[0]), "Kayıt düzenleyici (dolu)")

    # ---- Ana pencereler ---------------------------------------------------------------------------------------
    def test_unlock_window(self):
        self._check(lambda: VaultWindow(""), "Kilit ekranı", sizes=[(560, 520), (800, 600), (1160, 740)])

    def test_workspace_files(self):
        self._check(lambda: Workspace(self.session, self.theme), "Çalışma alanı", sizes=[(700, 520), (900, 600), (1160, 740)])

    def test_workspace_passwords(self):
        def factory():
            ws = Workspace(self.session, self.theme)
            ws.set_mode("passwords")
            ws.pwd_view.refresh()
            return ws
        self._check(factory, "Şifre yöneticisi", sizes=[(900, 600), (1160, 740)])


if __name__ == "__main__":
    unittest.main()
