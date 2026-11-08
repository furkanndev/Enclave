"""Enclave - Kasa oluşturma, ayarlar, parola ve iki faktörlü doğrulama pencereleri."""

import hashlib
import sys
from pathlib import Path
from typing import Any, Callable, List, Optional, Tuple

from PyQt6.QtCore import QEventLoop, QRectF, QSize, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QColor, QIcon, QPainter, QPixmap
from PyQt6.QtWidgets import (
    QApplication, QButtonGroup, QCheckBox, QComboBox, QDialog, QFileDialog, QFormLayout, QFrame, QGridLayout, QHBoxLayout,
    QLabel, QLineEdit, QMessageBox, QProgressBar, QPushButton, QScrollArea, QSizePolicy, QSpinBox, QStyledItemDelegate, QDoubleSpinBox, QTabWidget, QVBoxLayout, QWidget,
)

from config import load_config, save_config
from enclave_core import CustomVaultEngine, CustomVaultError, create_key_file, safe_vault_name
import totp_engine

from .i18n import tr
from . import designs, icons
from .common import LOADERS, LoadingBars, PasswordField, Task, Theme, button, confirm, copy_secret, format_size, horizontal_rule, label, with_default_suffix
from .mascot import DEFAULT_MASCOT, MASCOTS, CyberMascot
from .session import VaultSession, cloud_provider, password_strength

RECOVERY_FILE_TEXT = ("ENCLAVE - KURTARMA ANAHTARI\n\nKasa: {}\nKasa SHA-256 (kayıt anında): {}\n\n{}\n\n"
                      "Parolanızı unutursanız kasayı bu anahtarla açabilirsiniz; 2FA açıksa kod da gerekir.\n"
                      "Parola değişince bu anahtar geçersiz olur. SHA-256 kasa her değiştiğinde değişir.\n"
                      "Bu dosya şifresizdir. Kasanın yanında veya kolay erişilen yerlerde bırakmayın.\n")
TWO_FACTOR_FILE_TEXT = ("ENCLAVE - İKİ ADIMLI DOĞRULAMA ANAHTARI\n\nKasa: {}\nKasa SHA-256 (kayıt anında): {}\n\n"
                        "Doğrulayıcı anahtarı:\n{}\n\nKurtarma kodları (her biri tek kullanımlık):\n{}\n\n"
                        "SHA-256 kasa her değiştiğinde, 2FA ile her açılışta da değişir.\n"
                        "Bu dosya şifresizdir. Kasanın yanında veya kolay erişilen yerlerde bırakmayın.\n")

SECOND_PARTITION_NOTE = ("Dosyada ikinci parolayla açılan bir bölme varsa parolasını girin; iki bölmenin 2FA ayarı aynı olur. "
                         "Bölmeler ayrı anahtarla şifreli olduğundan parola olmadan diğerine dokunulamaz. "
                         "Boş bırakırsanız yalnızca açık bölme değişir.")

class StrengthMeter(QWidget):
    """Parola gücünü çubuk ve metinle gösterir; renge bağımlı değildir."""

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.bar = QProgressBar()
        self.bar.setRange(0, 4)
        self.bar.setTextVisible(False)
        self.text = label(name="Meta")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)
        layout.addWidget(self.bar)
        layout.addWidget(self.text)

    def update_for(self, password: str) -> int:
        score, description = password_strength(password)
        self.bar.setValue(score)
        self.text.setText(description)
        return score

class DialogBase(QDialog):
    def __init__(self, title: str, theme: Theme, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.theme = theme
        self.setSizeGripEnabled(True)

        self.content = QWidget()
        self.body = QVBoxLayout(self.content)
        self.body.setContentsMargins(24, 22, 24, 12)
        self.body.setSpacing(14)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setWidget(self.content)

        self.footer = QHBoxLayout()
        self.footer.setContentsMargins(24, 12, 24, 18)
        self.footer.setSpacing(8)
        self.footer.addStretch(1)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        outer.addWidget(scroll, 1)
        self.status = QVBoxLayout()
        self.status.setContentsMargins(24, 6, 24, 0)
        self.status.setSpacing(4)
        outer.addLayout(self.status)
        outer.addLayout(self.footer)

    def fit_to_screen(self, width: int, height: int) -> None:
        screen = self.screen().availableGeometry() if self.screen() else None
        if screen:
            width, height = min(width, screen.width() - 40), min(height, screen.height() - 60)
        self.resize(width, height)

class LoaderItemDelegate(QStyledItemDelegate):
    """Yükleme animasyonu listesinde her seçeneğin yanında kendi animasyonunu oynatır."""

    SAMPLE_WIDTH = 130

    def __init__(self, theme: Theme, view: QWidget):
        super().__init__(view)
        self.view = view
        self.sample = LoadingBars(theme, "bars")
        self.timer = QTimer(self)
        self.timer.setInterval(33)
        self.timer.timeout.connect(self._tick)
        self.timer.start()

    def _tick(self) -> None:
        if self.view.isVisible():
            self.sample.advance()
            self.view.viewport().update()

    def sizeHint(self, option, index) -> QSize:
        return QSize(super().sizeHint(option, index).width() + self.SAMPLE_WIDTH + 24, 44)

    def paint(self, painter: QPainter, option, index) -> None:
        super().paint(painter, option, index)
        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.translate(option.rect.right() - self.SAMPLE_WIDTH - 10, option.rect.top() + (option.rect.height() - 32) / 2)
        painter.setPen(Qt.PenStyle.NoPen)
        self.sample.paint_frame(painter, self.SAMPLE_WIDTH, index.data(Qt.ItemDataRole.UserRole))
        painter.restore()

class CreateVaultDialog(DialogBase):
    """Yeni kasa. Sonuç: created_path."""

    def __init__(self, theme: Theme, parent: Optional[QWidget] = None):
        super().__init__(tr("Yeni kasa"), theme, parent)
        self.created_path = ""
        self._task: Optional[Task] = None

        self.body.addWidget(label(tr("Yeni kasa oluştur"), "Title"))
        self.body.addWidget(label(tr("Kasa, istediğiniz yere taşıyabileceğiniz tek bir şifreli dosyadır. "
                                  "Windows, macOS ve Linux'ta aynı şekilde açılır."), "Muted"))

        self.architecture = "pvault"
        self.recovery_key = ""
        self.format_box = QComboBox()
        self.allocation_box = QComboBox()
        self.carrier_edit = QLineEdit()
        self.carrier_edit.setAccessibleName(tr("Kılıf medya dosyası konumu"))
        self.carrier_edit.setPlaceholderText(tr("Kılıf olarak kullanılacak medya dosyası"))
        self.carrier_edit.textChanged.connect(self._on_carrier_edited)
        self._add_architecture_choice()

        self.path_edit = QLineEdit()
        self.path_edit.setAccessibleName(tr("Kasa dosyası konumu"))
        self.path_edit.setPlaceholderText(tr("Kasanın kaydedileceği yer"))
        pick = button(tr("Konum seç"), on_click=self._pick_path)
        row = QHBoxLayout()
        row.setSpacing(8)
        row.addWidget(self.path_edit, 1)
        row.addWidget(pick)
        self.body.addWidget(label(tr("Dosya"), "Eyebrow"))
        self.body.addLayout(row)

        self.body.addWidget(label(tr("Parola"), "Eyebrow"))
        self.password = PasswordField(theme, tr("En az 8 karakter, tercihen birkaç kelime"))
        self.password.textChanged.connect(self._validate)
        self.body.addWidget(self.password)
        self.meter = StrengthMeter()
        self.body.addWidget(self.meter)
        self.password_again = PasswordField(theme, tr("Parolayı tekrar girin"))
        self.password_again.textChanged.connect(self._validate)
        self.body.addWidget(self.password_again)

        self.body.addWidget(label(tr("Boyut sınırı"), "Eyebrow"))
        self.size_box = QSpinBox()
        self.size_box.setRange(1, 1024 * 16)
        self.size_box.setValue(10)
        self.size_box.setSuffix(" GB")
        self.size_box.setAccessibleName(tr("Kasa boyut sınırı"))
        self.size_box.setButtonSymbols(QSpinBox.ButtonSymbols.NoButtons)
        size_row = QHBoxLayout()
        size_row.addWidget(self.size_box)
        size_row.addWidget(label(tr("Dosya kullandıkça büyür; diskte hemen bu kadar yer tutmaz."), "Muted"), 1)
        self.body.addLayout(size_row)

        self.decoy_toggle = QCheckBox(tr("İkinci parolayla açılan ayrı bir bölme ekle"))
        self.decoy_toggle.setToolTip(tr("Baskı altında verebileceğiniz ikinci bir parola. O parolayla yalnızca o bölmenin dosyaları görünür."))
        self.decoy_toggle.toggled.connect(lambda on: (self.decoy.setVisible(on), self.decoy_options.setVisible(on), self.decoy_note.setVisible(on), self._validate()))
        self.body.addWidget(self.decoy_toggle)
        self.decoy = PasswordField(theme, tr("İkinci bölme parolası"))
        self.decoy.textChanged.connect(self._validate)
        self.decoy.hide()
        self.body.addWidget(self.decoy)
        self.decoy_size = QDoubleSpinBox()
        self.decoy_size.setRange(0.25, 1024 * 16)
        self.decoy_size.setDecimals(2)
        self.decoy_size.setSingleStep(0.5)
        self.decoy_size.setSuffix(" GB")
        self.decoy_size.setAccessibleName(tr("İkinci bölme boyutu"))
        self.decoy_size.setButtonSymbols(QDoubleSpinBox.ButtonSymbols.NoButtons)
        self.decoy_size_touched = False
        self.decoy_hint = label(name="Muted")
        self.decoy_options = QWidget()
        decoy_row = QHBoxLayout(self.decoy_options)
        decoy_row.setContentsMargins(0, 0, 0, 0)
        decoy_row.addWidget(label(tr("İkinci bölme boyutu"), "Eyebrow", wrap=False))
        decoy_row.addWidget(self.decoy_size)
        decoy_row.addWidget(self.decoy_hint, 1)
        self.decoy_options.hide()
        self.body.addWidget(self.decoy_options)
        self._suggest_decoy_size()
        self.decoy_size.valueChanged.connect(self._on_decoy_size_edited)
        self.size_box.valueChanged.connect(self._on_size_changed)
        self.decoy_note = label(tr("İkinci bölmeye inandırıcı birkaç dosya koyun. Dosya boyutu, içindekilerden çok büyükse "
                                "başka veri olduğundan şüphelenilebilir. Kasayı sıkıştırmak diğer bölmeyi siler."), "Muted")
        self.decoy_note.hide()
        self.body.addWidget(self.decoy_note)

        self.two_factor_toggle = QCheckBox(tr("İki adımlı doğrulamayı (2FA) şimdi kur"))
        self.body.addWidget(self.two_factor_toggle)
        self.body.addWidget(horizontal_rule())
        self.ack = QCheckBox(tr("Parolamı unutursam dosyalarımın kurtarılamayacağını biliyorum."))
        self.ack.toggled.connect(self._validate)
        self.body.addWidget(self.ack)
        self.body.addStretch(1)
        self.error = label(name="Error")
        self.error.hide()
        self.failure = label(name="Error")
        self.failure.hide()
        self.busy = LoadingBars(theme)
        self.busy_note = label(name="Muted")
        self.busy_note.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        self.busy_note.hide()
        self.status.addWidget(self.error)
        self.status.addWidget(self.failure)
        self.status.addWidget(self.busy)
        self.status.addWidget(self.busy_note)

        self.footer.addWidget(button(tr("Vazgeç"), on_click=self.reject))
        self.create_button = button(tr("Kasayı oluştur"), "Primary", self._create)
        self.footer.addWidget(self.create_button)
        self._validate()
        self.fit_to_screen(640, 720)

    def _add_architecture_choice(self) -> None:
        self.body.addWidget(label(tr("Kasa türü"), "Eyebrow"))
        row = QHBoxLayout()
        row.setSpacing(10)
        group = QButtonGroup(self)
        choices = [
            ("pvault", tr("Bağımsız kasa"), tr("Tek .pvault dosyası. Windows, macOS ve Linux'ta açılır. Yönetici izni gerekmez.")),
        ]
        if sys.platform == "win32":
            choices.append(
                ("vhd", tr("Sanal disk (VHD)"), tr("BitLocker ile şifreli sürücü. Dosya Gezgini'nde disk olarak görünür. Yalnızca Windows, yönetici izni ister."))
            )
        for key, title, summary in choices:
            card = QPushButton()
            card.setObjectName("DesignCard")
            card.setCheckable(True)
            card.setChecked(key == "pvault")
            card.setAccessibleName(title)
            card.setMinimumHeight(118)
            card.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)
            inner = QVBoxLayout(card)
            inner.setContentsMargins(10, 8, 10, 8)
            for widget in (label(title, "Section", wrap=False), label(summary, "Muted")):
                widget.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
                inner.addWidget(widget)
            card.clicked.connect(lambda _c=False, k=key: self._set_architecture(k))
            group.addButton(card)
            row.addWidget(card, 1)
        self.body.addLayout(row)

        self.carrier_toggle = QCheckBox(tr("Bu kasayı bir medya dosyası içine gizle (Kamuflaj / Kılıf)"))
        self.carrier_toggle.setToolTip(tr("Kasa verilerini video, ses veya resim dosyasının içine gizler. Dosya dışarıdan normal medya gibi oynatılır."))
        self.carrier_toggle.toggled.connect(self._on_carrier_toggled)
        self.body.addWidget(self.carrier_toggle)

        self.carrier_options = QWidget()
        carrier_layout = QVBoxLayout(self.carrier_options)
        carrier_layout.setContentsMargins(0, 0, 0, 0)
        carrier_layout.setSpacing(6)
        carrier_layout.addWidget(label(tr("Kılıf medya dosyası (Video, ses, resim veya kalıp)"), "Eyebrow"))
        c_row = QHBoxLayout()
        c_row.setSpacing(8)
        c_row.addWidget(self.carrier_edit, 1)
        c_row.addWidget(button(tr("Gözat"), on_click=self._pick_carrier))
        carrier_layout.addLayout(c_row)
        self.carrier_note = label(tr("Seçilen medya dosyası kopyalanır ve içine şifreli kasa gizlenir. Dosya VLC veya Fotoğraflar'da normal açılır."), "Muted")
        carrier_layout.addWidget(self.carrier_note)
        self.carrier_options.hide()
        self.body.addWidget(self.carrier_options)

        self.vhd_options = QWidget()
        options = QFormLayout(self.vhd_options)
        options.setContentsMargins(0, 0, 0, 0)
        options.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
        self.format_box.addItems([tr("VHDX (önerilen)"), tr("VHD (eski sistemlerle uyumlu)")])
        self.allocation_box.addItems([tr("Dinamik: kullandıkça büyür"), tr("Sabit: tüm alanı hemen ayırır")])
        options.addRow(tr("Disk biçimi"), self.format_box)
        options.addRow(tr("Yer ayırma"), self.allocation_box)
        self.vhd_options.hide()
        self.body.addWidget(self.vhd_options)

    def _on_carrier_toggled(self, checked: bool) -> None:
        self.carrier_options.setVisible(checked)
        if checked:
            if self.carrier_edit.text():
                c_p = Path(self.carrier_edit.text())
                self.path_edit.setText(str(c_p.parent / f"{c_p.stem}_kasa{c_p.suffix}"))
            elif self.path_edit.text() and self.path_edit.text().endswith(".pvault"):
                p = Path(self.path_edit.text())
                self.path_edit.setText(str(p.with_suffix(".mp4")))
        else:
            if self.path_edit.text():
                p = Path(self.path_edit.text())
                if p.suffix != ".pvault":
                    stem = p.stem[:-5] if p.stem.endswith("_kasa") else p.stem
                    self.path_edit.setText(str(p.parent / f"{stem}.pvault"))
        self._validate()

    def _on_carrier_edited(self) -> None:
        carrier = self.carrier_edit.text().strip()
        if carrier and hasattr(self, "carrier_toggle") and self.carrier_toggle.isChecked():
            c_p = Path(carrier)
            p_text = self.path_edit.text().strip()
            if not p_text or p_text.endswith(".pvault") or p_text.endswith(c_p.suffix):
                self.path_edit.setText(str(c_p.parent / f"{c_p.stem}_kasa{c_p.suffix}"))
        self._validate()

    def _pick_carrier(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, tr("Kılıf medya dosyasını seçin"), "",
            tr("Medya ve kalıp dosyaları (*.mp4 *.mkv *.mov *.avi *.webm *.mp3 *.flac *.wav *.png *.jpg *.jpeg *.webp *.iso *.zip);;Tüm dosyalar (*)")
        )
        if path:
            self.carrier_edit.setText(path)
            c_p = Path(path)
            default_target = c_p.parent / f"{c_p.stem}_kasa{c_p.suffix}"
            self.path_edit.setText(str(default_target))
            self._validate()

    def _set_architecture(self, key: str) -> None:
        self.architecture = key
        is_pvault = key == "pvault"
        self.vhd_options.setVisible(key == "vhd")
        if hasattr(self, "carrier_toggle"):
            self.carrier_toggle.setVisible(is_pvault)
            self.carrier_options.setVisible(is_pvault and self.carrier_toggle.isChecked())
        self.two_factor_toggle.setVisible(is_pvault)
        self.path_edit.clear()
        self._validate()

    def _extension(self) -> str:
        if self.architecture == "pvault":
            if hasattr(self, "carrier_toggle") and self.carrier_toggle.isChecked():
                carrier_path = self.carrier_edit.text().strip()
                return Path(carrier_path).suffix if carrier_path else ".mp4"
            return ".pvault"
        return ".vhdx" if self.format_box.currentIndex() == 0 else ".vhd"

    def _pick_path(self) -> None:
        if self.architecture == "pvault" and hasattr(self, "carrier_toggle") and self.carrier_toggle.isChecked() and self.carrier_edit.text():
            c_p = Path(self.carrier_edit.text())
            default_name = f"{c_p.stem}_kasa{c_p.suffix}"
        else:
            default_name = f"kasa{self._extension()}"
        path, _ = QFileDialog.getSaveFileName(self, tr("Kasa dosyası"), default_name, tr("Tüm dosyalar (*)"))
        if path:
            self.path_edit.setText(with_default_suffix(path, self._extension()))

    def _suggest_decoy_size(self) -> None:
        self.decoy_size.blockSignals(True)
        self.decoy_size.setValue(max(0.25, round(self.size_box.value()) / 4))
        self.decoy_size.blockSignals(False)

    def _on_decoy_size_edited(self, _value: float) -> None:
        self.decoy_size_touched = True
        self._validate()

    def _on_size_changed(self, _value: int) -> None:
        if not self.decoy_size_touched:
            self._suggest_decoy_size()
        self._validate()

    def _decoy_mb(self) -> int:
        return int(self.decoy_size.value() * 1024)

    def _validate(self) -> None:
        password = self.password.text()
        self.meter.update_for(password)
        main_left = self.size_box.value() - self.decoy_size.value()
        self.decoy_hint.setText(
            tr("Ana bölmeye {} GB kalır.", f"{max(0.0, main_left):g}") if self.architecture == "vhd"
            else tr("Ana bölmenin sınırından ayrıdır.")
        )
        problem = ""
        if self.architecture == "pvault" and hasattr(self, "carrier_toggle") and self.carrier_toggle.isChecked():
            c_text = self.carrier_edit.text().strip()
            if not c_text:
                problem = tr("Kılıf olarak kullanılacak bir medya dosyası seçin.")
            elif not Path(c_text).is_file():
                problem = tr("Seçilen kılıf medya dosyası bulunamadı.")
        elif password and len(password) < 8:
            problem = tr("Parola en az 8 karakter olmalı.")
        elif self.password_again.text() and password != self.password_again.text():
            problem = tr("Parolalar eşleşmiyor.")
        elif self.decoy_toggle.isChecked() and self.decoy.text() and self.decoy.text() == password:
            problem = tr("İkinci bölme parolası ana paroladan farklı olmalı.")
        elif self.decoy_toggle.isChecked() and self.architecture == "vhd" and main_left < 0.25:
            problem = tr("İkinci bölme diskten en az 0,25 GB küçük olmalı.")
        elif self.decoy_toggle.isChecked() and 0 < len(self.decoy.text()) < 8:
            problem = tr("İkinci bölme parolası en az 8 karakter olmalı.")
        elif password and password == self.password_again.text() and not self.ack.isChecked():
            problem = tr("Devam etmek için kurtarılamama uyarısını onaylayın.")
        self.error.setText(problem)
        self.error.setVisible(bool(problem))
        decoy_ok = not self.decoy_toggle.isChecked() or len(self.decoy.text()) >= 8
        ready = (
            not problem and len(password) >= 8 and password == self.password_again.text()
            and decoy_ok and self.ack.isChecked() and not self._task
        )
        self.create_button.setEnabled(ready)

    def _create(self) -> None:
        path = with_default_suffix(self.path_edit.text().strip(), self._extension())
        self.path_edit.setText(path)
        if not path:
            self._pick_path()
            path = self.path_edit.text().strip()
            if not path:
                return
        password = self.password.text()
        decoy = self.decoy.text() if self.decoy_toggle.isChecked() else None
        decoy_mb = self._decoy_mb()
        size_gb = self.size_box.value()
        architecture = self.architecture
        is_dynamic = self.allocation_box.currentIndex() == 0

        def work(_progress: Callable, _cancelled: Callable) -> dict:
            if architecture == "vhd":
                from . import vhd_service
                create = vhd_service.create_virtual_disk_elevated if vhd_service.needs_elevation() else vhd_service.create_virtual_disk
                return create(path, password, size_gb, is_dynamic, decoy, decoy_mb)

            if hasattr(self, "carrier_toggle") and self.carrier_toggle.isChecked():
                from stego_enclave import create_stego_vault
                carrier_src = self.carrier_edit.text().strip()
                result = create_stego_vault(
                    carrier_source_path=carrier_src,
                    target_vault_path=path,
                    password=password,
                    max_size_gb=size_gb,
                    is_dynamic=True,
                    decoy_password=decoy,
                    decoy_size_gb=max(1, decoy_mb // 1024)
                )
            else:
                result = CustomVaultEngine.create_vault(
                    path, password, label=Path(path).stem, decoy_password=decoy, max_size_gb=size_gb,
                    decoy_size_gb=max(1, decoy_mb // 1024), decoy_size_mb=decoy_mb
                )
            session = VaultSession(result["path"])
            session.unlock(password)
            result["session"] = session
            result["recovery_key"] = session.recovery_key()
            return result

        self.failure.hide()
        self.busy.start()
        self.busy_note.setText(tr("Sanal disk oluşturuluyor. Windows yönetici onayı isteyebilir; bu işlem bir dakika sürebilir.")
                               if architecture == "vhd" else tr("Kasa oluşturuluyor..."))
        self.busy_note.show()
        self.content.setEnabled(False)
        self.create_button.setEnabled(False)
        self._task = Task(work, self)
        self._task.succeeded.connect(self._on_created)
        self._task.failed.connect(self._on_failed)
        self._task.start()

    def _on_created(self, result: dict) -> None:
        self.created_path = result["path"]
        if result.get("recovery_key"):
            RecoveryKeyDialog(result["recovery_key"], self.created_path, self.theme, self).exec()
        session = result.get("session")
        if session:
            if self.two_factor_toggle.isChecked():
                decoy = self.decoy.text() if self.decoy_toggle.isChecked() else ""
                TwoFactorDialog(session, self.theme, self, other_password=decoy).exec()
            session.close()
        self.accept()

    def _on_failed(self, message: str) -> None:
        self._task = None
        self.busy.stop()
        self.busy_note.hide()
        self.content.setEnabled(True)
        self.failure.setText(message)
        self.failure.show()
        self._validate()

def run_blocking(widget: QWidget, session: Any, fn: Callable[[], Any], note: Optional[QLabel] = None, text: str = "") -> Optional[str]:
    """
    Uzun işlemi pencereyi dondurmadan çalıştırır ve bitmesini bekler. Hata iletisini döndürür, başarıda None.
    İşlem sürerken otomatik kilit bekler.
    """
    task = Task(lambda _progress, _cancelled: fn(), widget)
    problems: List[str] = []
    task.failed.connect(problems.append)
    loop = QEventLoop()
    task.finished.connect(loop.quit)
    if note is not None and text:
        note.setText(text)
        note.show()
    widget.setEnabled(False)
    if session is not None:
        session.maintenance = True
    task.start()
    loop.exec()
    if session is not None:
        session.maintenance = False
    widget.setEnabled(True)
    return problems[0] if problems else None

def vault_sha256(vault_path: str) -> str:
    digest = hashlib.sha256()
    with open(vault_path, "rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def save_vault_secret(widget: QWidget, title: str, vault_path: str, suffix: str, build: Callable[[str, str], str]) -> None:
    """Gizli metni kasa adıyla kaydeder. build(kasa adı, kasa SHA-256) dosya içeriğini üretir."""
    name = Path(vault_path).stem
    path, _ = QFileDialog.getSaveFileName(widget, title, f"{safe_vault_name(name)}_{suffix}.txt", tr("Metin (*.txt)"))
    if not path:
        return
    hashes: List[str] = []
    run_blocking(widget, None, lambda: hashes.append(vault_sha256(vault_path)))
    Path(path).write_text(build(name, hashes[0] if hashes else tr("(Hesaplanamadı)")), encoding="utf-8")

class ConfirmIdentityDialog(DialogBase):
    """Açık bırakılmış pencereden hassas işlem yapılamaması için parolayı ve varsa kodu yeniden ister."""

    def __init__(self, session: VaultSession, theme: Theme, parent: Optional[QWidget] = None):
        super().__init__(tr("Kimliğinizi doğrulayın"), theme, parent)
        self.session = session
        self.confirmed_password = ""
        self._failures = 0
        self.body.addWidget(label(tr("Kimliğinizi doğrulayın"), "Title"))
        self.body.addWidget(label(tr("Bu işlem kasaya kalıcı erişim verebilir. Kasa açık olsa bile yeniden doğrulama gerekir."), "Muted"))
        self.password = PasswordField(theme, tr("Parola"))
        self.password.returnPressed.connect(self._save)
        self.body.addWidget(self.password)
        self.code = QLineEdit()
        self.code.setPlaceholderText("000000")
        self.code.setAccessibleName(tr("Doğrulama kodu"))
        self.code.setVisible(session.two_factor_enabled)
        self.code.returnPressed.connect(self._save)
        self.body.addWidget(self.code)
        self.error = label(name="Error")
        self.error.hide()
        self.body.addWidget(self.error)
        self.body.addStretch(1)
        self.footer.addWidget(button(tr("Vazgeç"), on_click=self.reject))
        self.save_button = button(tr("Doğrula"), "Primary", self._save)
        self.footer.addWidget(self.save_button)
        self.fit_to_screen(460, 300)

    def _save(self) -> None:
        if not self.save_button.isEnabled():
            return
        session, password, code = self.session, self.password.text(), self.code.text().strip()
        problem = run_blocking(self, session, lambda: session.confirm_identity(password, code))
        if problem is None:
            self.confirmed_password = password
            self.accept()
            return
        self.error.setText(problem)
        self.error.show()
        self.password.clear()
        self.code.clear()
        self._failures += 1
        self.save_button.setEnabled(False)
        QTimer.singleShot(min(16, 2 ** self._failures) * 1000, lambda: self.save_button.setEnabled(True))

class KeyFileDialog(DialogBase):
    """Anahtar dosyasını açar veya kapatır. Parola ConfirmIdentityDialog ile doğrulanmış olarak gelir."""

    def __init__(self, session: VaultSession, password: str, theme: Theme, parent: Optional[QWidget] = None):
        super().__init__(tr("Anahtar dosyası"), theme, parent)
        self.session = session
        self.confirmed_password = password
        self.enabling = not session.has_key_file
        self.body.addWidget(label(tr("Anahtar dosyası"), "Title"))
        self.body.addWidget(label(tr(
            "Kasa bundan sonra parola ve bu dosya birlikte olmadan açılmaz. Parola ve kasa dosyası ele geçirilse bile içerik "
            "okunamaz. Dosyayı kasanın yanında tutmayın; USB bellek gibi ayrı bir yerde saklayın. Dosya kaybolursa kasa yalnızca "
            "kurtarma anahtarıyla açılır. Eski kurtarma anahtarı geçersiz olur."
            if self.enabling else "Kasa yeniden yalnızca parolayla açılır. Dosyalar yeni bir anahtarla yeniden şifrelenir."
        ), "Muted"))
        self.error = label(name="Error")
        self.error.hide()
        self.body.addWidget(self.error)
        self.body.addStretch(1)
        self.footer.addWidget(button(tr("Vazgeç"), on_click=self.reject))
        self.footer.addWidget(button(tr("Dosyayı oluştur") if self.enabling else tr("Anahtar dosyasını kaldır"),
                                     "Primary" if self.enabling else "Danger", self._save))
        self.fit_to_screen(520, 340)

    def _save(self) -> None:
        session, password = self.session, self.confirmed_password
        target, digest = "", None
        if self.enabling:
            target, _ = QFileDialog.getSaveFileName(self, tr("Anahtar dosyası"), "kasa.key", tr("Tüm dosyalar (*)"))
            if not target:
                return
            if cloud_provider(target) or Path(target).resolve().parent == Path(session.path).parent:
                self.error.setText(tr("Anahtar dosyasını kasanın yanına veya bulut klasörüne koymayın; başka bir yer seçin."))
                self.error.show()
                return
            try:
                digest = create_key_file(target)
            except CustomVaultError as error:
                self.error.setText(tr(str(error)))
                self.error.show()
                return

        problem = run_blocking(self, session, lambda: session.set_key_file(password, digest), self.error,
                               tr("Dosyalar yeniden şifreleniyor. Bu pencereyi kapatmayın."))
        if problem is None:
            self.accept()
            return
        if target:
            Path(target).unlink(missing_ok=True)
        self.error.setText(problem)
        self.error.show()

class RecoveryKeyDialog(DialogBase):
    """Kasa kurtarma anahtarı. Yalnızca kullanıcının seçtiği yere kaydedilir ve parola değişince geçersiz olur."""

    def __init__(self, key: str, vault_path: str, theme: Theme, parent: Optional[QWidget] = None):
        super().__init__(tr("Kurtarma anahtarı"), theme, parent)
        self.key = key
        self.vault_path = vault_path
        self.body.addWidget(label(tr("Kurtarma anahtarı"), "Title"))
        self.body.addWidget(label(tr("Parolayı unutursanız bu anahtar kasayı açar; 2FA açıksa kod da gerekir. Parola değişince geçersiz olur. Kaydedilen dosya şifresizdir: kasanın dışında, güvenli bir yerde saklayın."), "Muted"))
        text = label(key, "Section")
        text.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.body.addWidget(text)
        self.body.addStretch(1)
        self.footer.addWidget(button(tr("Panoya kopyala"), on_click=lambda: copy_secret(key)))
        self.footer.addWidget(button(tr("Dosyaya kaydet"), on_click=self._save))
        self.footer.addWidget(button(tr("Sakladım"), "Primary", self.accept))
        self.fit_to_screen(620, 320)

    def _save(self) -> None:
        save_vault_secret(self, tr("Kurtarma anahtarı"), self.vault_path, "kurtarma",
                          lambda name, digest: tr(RECOVERY_FILE_TEXT, name, digest, self.key))

class ChangePasswordDialog(DialogBase):
    def __init__(self, session: VaultSession, theme: Theme, parent: Optional[QWidget] = None):
        super().__init__(tr("Parolayı değiştir"), theme, parent)
        self.session = session
        self.body.addWidget(label(tr("Parolayı değiştir"), "Title"))
        self.rekeys = isinstance(session, VaultSession)
        self.body.addWidget(label(tr(
            "Yalnızca şu an açık olan bölmenin parolası değişir. Dosyalar yeni bir anahtarla yeniden şifrelenir; eski parola ve eski yedekler bu dosyaları açamaz. Kasa boyutuna göre sürebilir."
            if self.rekeys else "Yalnızca şu an açık olan bölmenin parolası değişir. Dosyalar yeniden şifrelenmez."
        ), "Muted"))
        self.password = PasswordField(theme, tr("Yeni parola"))
        self.password.textChanged.connect(self._validate)
        self.again = PasswordField(theme, tr("Yeni parolayı tekrar girin"))
        self.again.textChanged.connect(self._validate)
        self.meter = StrengthMeter()
        self.body.addWidget(self.password)
        self.body.addWidget(self.meter)
        self.body.addWidget(self.again)
        self.error = label(name="Error")
        self.error.hide()
        self.body.addWidget(self.error)
        self.body.addStretch(1)
        self.footer.addWidget(button(tr("Vazgeç"), on_click=self.reject))
        self.save_button = button(tr("Değiştir"), "Primary", self._save)
        self.footer.addWidget(self.save_button)
        self._validate()
        self.fit_to_screen(480, 380)

    def _validate(self) -> None:
        self.meter.update_for(self.password.text())
        self.save_button.setEnabled(len(self.password.text()) >= 8 and self.password.text() == self.again.text())

    def _save(self) -> None:
        session, password = self.session, self.password.text()
        note = tr("Dosyalar yeniden şifreleniyor. Bu pencereyi kapatmayın.") if self.rekeys else ""
        problem = run_blocking(self, session, lambda: session.change_password(password), self.error, note)
        if problem is not None:
            self.error.setText(problem)
            self.error.show()
            return
        self.accept()

class TwoFactorDialog(DialogBase):
    """Doğrulayıcı uygulama kurulumu. Kod doğrulanmadan kasaya yazılmaz."""

    def __init__(self, session: VaultSession, theme: Theme, parent: Optional[QWidget] = None, other_password: str = ""):
        super().__init__(tr("İki adımlı doğrulama"), theme, parent)
        self.session = session
        self.known_other_password = other_password
        self.secret = totp_engine.generate_totp_secret()
        self.backup_codes = totp_engine.generate_backup_codes()

        self.body.addWidget(label(tr("İki adımlı doğrulama"), "Title"))
        self.body.addWidget(label(
            tr("Bu uygulamada parolanın yanında kod da istenir. Kod, başkasının bilgisayarınızda kasayı açmasını zorlaştırır; "
            "şifrelemeyi güçlendirmez. Bu yüzden güçlü parola yine de şarttır."), "Muted"))

        uri = totp_engine.get_otpauth_uri(self.secret, session.name)
        qr = totp_engine.generate_qr_pixmap(uri, 200)
        if qr is not None:
            image = label(wrap=False)
            image.setPixmap(qr)
            image.setAccessibleName(tr("Doğrulayıcı uygulama için QR kod"))
            self.body.addWidget(image, 0, Qt.AlignmentFlag.AlignHCenter)
        self.body.addWidget(label(tr("Anahtar"), "Eyebrow"))
        key = label(totp_engine.format_secret_for_display(self.secret), "Meta")
        key.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.body.addWidget(key)

        self.body.addWidget(label(tr("Kurtarma kodları"), "Eyebrow"))
        self.body.addWidget(label(tr("Telefonunuzu kaybederseniz bu kodlar tek seferlik kullanılır. Kasanın dışında, güvenli bir yere yazın."), "Muted"))
        codes = QGridLayout()
        codes.setSpacing(6)
        for index, code in enumerate(self.backup_codes):
            item = label(code, "Meta", wrap=False)
            item.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            codes.addWidget(item, index // 2, index % 2)
        self.body.addLayout(codes)

        self.body.addWidget(label(tr("Uygulamadaki 6 haneli kod"), "Eyebrow"))
        self.code = QLineEdit()
        self.code.setAccessibleName(tr("Doğrulama kodu"))
        self.code.returnPressed.connect(self._save)
        self.body.addWidget(self.code)
        self.other_password = PasswordField(theme, tr("İkinci bölme parolası"))
        if not other_password:
            self.body.addWidget(label(tr("İkinci bölme"), "Eyebrow"))
            self.body.addWidget(label(tr(SECOND_PARTITION_NOTE), "Muted"))
            self.body.addWidget(self.other_password)
        else:
            self.other_password.hide()
        self.error = label(name="Error")
        self.error.hide()
        self.body.addWidget(self.error)
        self.footer.addWidget(button(tr("Vazgeç"), on_click=self.reject))
        self.footer.addWidget(button(tr("Dosyaya kaydet"), on_click=self._save_to_file))
        self.footer.addWidget(button(tr("Etkinleştir"), "Primary", self._save))
        self.fit_to_screen(520, 720)

    def _save_to_file(self) -> None:
        secret = totp_engine.format_secret_for_display(self.secret)
        codes = "\n".join(self.backup_codes)
        save_vault_secret(self, tr("İki adımlı doğrulama"), self.session.path, "2fa",
                          lambda name, digest: tr(TWO_FACTOR_FILE_TEXT, name, digest, secret, codes))

    def _save(self) -> None:
        if not totp_engine.verify_totp_token(self.secret, self.code.text()):
            self.error.setText(tr("Kod eşleşmedi. Telefonun saati doğru mu?"))
            self.error.show()
            return
        try:
            self.session.enable_two_factor(self.secret, self.backup_codes,
                                           self.known_other_password or self.other_password.text())
        except (CustomVaultError, OSError) as error:
            self.error.setText(tr(str(error)))
            self.error.show()
            return
        self.accept()

class DisableTwoFactorDialog(DialogBase):
    """2FA'yı kapatmak için geçerli kod ister; yanlış denemelerde bekleme süresi uzar."""

    def __init__(self, session: VaultSession, theme: Theme, parent: Optional[QWidget] = None):
        super().__init__(tr("İki adımlı doğrulamayı kapat"), theme, parent)
        self.session = session
        self._failures = 0
        self.body.addWidget(label(tr("İki adımlı doğrulamayı kapat"), "Title"))
        self.body.addWidget(label(tr("Devam etmek için doğrulayıcı uygulamadaki kodu veya bir kurtarma kodunu girin. "
                                  "Kasa açık olsa bile kod olmadan kapatılamaz."), "Muted"))
        self.code = QLineEdit()
        self.code.setPlaceholderText("000000")
        self.code.setAccessibleName(tr("Doğrulama kodu"))
        self.code.returnPressed.connect(self._save)
        self.body.addWidget(self.code)
        self.body.addWidget(label(tr("İkinci bölme"), "Eyebrow"))
        self.body.addWidget(label(tr(SECOND_PARTITION_NOTE), "Muted"))
        self.other_password = PasswordField(theme, tr("İkinci bölme parolası"))
        self.body.addWidget(self.other_password)
        self.error = label(name="Error")
        self.error.hide()
        self.body.addWidget(self.error)
        self.body.addStretch(1)
        self.footer.addWidget(button(tr("Vazgeç"), on_click=self.reject))
        self.save_button = button(tr("Kapat"), "Danger", self._save)
        self.footer.addWidget(self.save_button)
        self.fit_to_screen(520, 440)

    def _save(self) -> None:
        if not self.save_button.isEnabled():
            return
        try:
            self.session.disable_two_factor(self.code.text().strip(), self.other_password.text())
        except (CustomVaultError, OSError) as error:
            self.error.setText(tr(str(error)))
            self.error.show()
            self.code.clear()
            self._failures += 1
            self.save_button.setEnabled(False)
            QTimer.singleShot(min(16, 2 ** self._failures) * 1000, lambda: self.save_button.setEnabled(True))
            return
        self.accept()

class SettingsDialog(DialogBase):
    design_changed = pyqtSignal(str, str, str)
    mascot_changed = pyqtSignal(str)

    def __init__(self, theme: Theme, session: Optional[VaultSession], parent: Optional[QWidget] = None):
        super().__init__(tr("Ayarlar"), theme, parent)
        self.session = session
        self.config = load_config()
        self.chosen_language = ""
        self.tabs = QTabWidget()
        self.tabs.addTab(self._appearance_tab(), theme.icon("image"), tr("Görünüm"))
        self.tabs.addTab(self._security_tab(), theme.icon("lock"), tr("Güvenlik"))
        self.tabs.addTab(self._language_tab(), theme.icon("text"), tr("Dil"))
        if isinstance(session, VaultSession) and session.is_open:
            self.tabs.addTab(self._vault_tab(), theme.icon("drive"), tr("Bu kasa"))
        self.body.addWidget(self.tabs, 1)
        self.footer.addWidget(button(tr("Kapat"), "Primary", self.accept))
        self.fit_to_screen(800, 760)

    @staticmethod
    def _page() -> Tuple[QWidget, QVBoxLayout]:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(12)
        return page, layout

    def _appearance_tab(self) -> QWidget:
        page, layout = self._page()
        theme = self.theme
        layout.addWidget(label(tr("Tema rengi"), "Section"))
        swatches = QGridLayout()
        swatches.setSpacing(8)
        self.group = QButtonGroup(self)
        for position, design in enumerate(designs.DESIGNS.values()):
            accent = (design.dark if theme.dark else design.light).accent
            swatch = button(tr(design.name), "Swatch", lambda key=design.key: self._emit_design(key),
                            icons.icon("shield", accent, 18))
            swatch.setCheckable(True)
            swatch.setChecked(design.key == theme.design.key)
            self.group.addButton(swatch)
            swatches.addWidget(swatch, position // 3, position % 3)
        layout.addLayout(swatches)
        self.selected_design = theme.design.key
        self.palette_note = label(tr("Bu arayüz kendi renkleriyle gelir; tema rengi yalnızca renkli stillerde uygulanır."), "Muted")
        layout.addWidget(self.palette_note)

        layout.addSpacing(4)
        layout.addWidget(label(tr("Arayüz stili"), "Section"))
        styles = QGridLayout()
        styles.setSpacing(8)
        self.style_group = QButtonGroup(self)
        self.selected_style = theme.design.style
        for position, look in enumerate(designs.STYLES.values()):
            card = button(tr(look.name), "Swatch", lambda key=look.key: self._emit_design(style=key),
                          self._style_icon(look.key))
            card.setIconSize(QSize(36, 16))
            card.setCheckable(True)
            card.setChecked(look.key == theme.design.style)
            card.setToolTip(tr(look.summary))
            card.setAccessibleName(tr(look.name))
            self.style_group.addButton(card)
            styles.addWidget(card, position // 3, position % 3)
        layout.addLayout(styles)
        self.style_note = label(tr(designs.STYLES[self.selected_style].summary), "Muted")
        layout.addWidget(self.style_note)
        self._sync_palette_lock()

        layout.addSpacing(4)
        form = QFormLayout()
        form.setSpacing(10)
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
        self.appearance = QComboBox()
        self.appearance.setAccessibleName(tr("Renk düzeni"))
        for title, key in ((tr("Sistemle aynı"), "system"), (tr("Açık"), "light"), (tr("Koyu"), "dark")):
            self.appearance.addItem(title, key)
        self.appearance.setCurrentIndex(max(0, self.appearance.findData(self.config.get("appearance", "system"))))
        self.appearance.currentIndexChanged.connect(lambda _i: self._emit_design(self.selected_design))
        form.addRow(tr("Renk düzeni"), self.appearance)
        self.loader = QComboBox()
        self.loader.setAccessibleName(tr("Yükleme animasyonu"))
        for key, title in LOADERS.items():
            self.loader.addItem(tr(title), key)
        self.loader.setItemDelegate(LoaderItemDelegate(theme, self.loader.view()))
        self.loader.setCurrentIndex(max(0, self.loader.findData(self.config.get("loader", "bars"))))
        self.loader.currentIndexChanged.connect(self._choose_loader)
        form.addRow(tr("Yükleme animasyonu"), self.loader)
        layout.addLayout(form)
        layout.addSpacing(4)
        self._add_mascot_section(layout)
        layout.addStretch(1)
        return page

    def _language_tab(self) -> QWidget:
        page, layout = self._page()
        layout.addWidget(label(tr("Uygulama dili"), "Section"))
        self.language = QComboBox()
        self.language.setAccessibleName(tr("Dil"))
        self.language.addItem("Türkçe", "tr")
        self.language.addItem("English", "en")
        self.language.setCurrentIndex(max(0, self.language.findData(self.config.get("language", "tr"))))
        self.language.currentIndexChanged.connect(self._choose_language)
        layout.addWidget(self.language)
        layout.addWidget(label(tr("Seçim hemen uygulanır."), "Muted"))
        layout.addStretch(1)
        return page

    def _choose_loader(self, _index: int) -> None:
        config = load_config()
        config["loader"] = self.loader.currentData()
        save_config(config)

    def _choose_language(self, _index: int) -> None:
        self.chosen_language = self.language.currentData()
        self.accept()

    def _style_icon(self, style: str) -> QIcon:
        """Stilin zemin, yan panel ve vurgu rengini gösteren küçük örnek."""
        palette = designs.get_design(self.theme.design.key, style)
        palette = palette.dark if self.theme.dark else palette.light
        ratio = 2
        pixmap = QPixmap(36 * ratio, 16 * ratio)
        pixmap.fill(Qt.GlobalColor.transparent)
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.scale(ratio, ratio)
        painter.setPen(QColor(palette.border))
        for index, color in enumerate((palette.rail, palette.window, palette.accent)):
            painter.setBrush(QColor(color))
            painter.drawRoundedRect(QRectF(0.5 + index * 12, 0.5, 11, 15), 3, 3)
        painter.end()
        pixmap.setDevicePixelRatio(ratio)
        return QIcon(pixmap)

    def _sync_palette_lock(self) -> None:
        fixed = designs.STYLES[self.selected_style].light is not None
        self.palette_note.setVisible(fixed)
        for swatch in self.group.buttons():
            swatch.setEnabled(not fixed)

    def _add_mascot_section(self, layout: QVBoxLayout) -> None:
        layout.addWidget(label(tr("Maskot"), "Section"))
        layout.addWidget(label(tr("Parola yazarken kasaya eğilir, yazmayı bırakınca o da bırakır. Maskotlar tema rengini giyer."), "Muted"))
        grid = QGridLayout()
        grid.setSpacing(10)
        self.mascot_group = QButtonGroup(self)
        self.mascot_previews: List[CyberMascot] = []
        current = self.config.get("mascot", DEFAULT_MASCOT)
        for position, info in enumerate(MASCOTS.values()):
            card = QFrame()
            card.setObjectName("Card")
            inner = QVBoxLayout(card)
            inner.setContentsMargins(8, 6, 8, 8)
            inner.setSpacing(4)
            preview = CyberMascot(self.theme, 200, on_dark=self.theme.dark, kind=info.key, demo=True)
            preview.setMinimumSize(130, 92)
            preview.setFixedHeight(96)
            self.mascot_previews.append(preview)
            inner.addWidget(preview, 1)
            choose = button(tr(info.name), "Swatch", lambda key=info.key: self._choose_mascot(key))
            choose.setCheckable(True)
            choose.setChecked(info.key == current)
            choose.setToolTip(tr(info.summary))
            self.mascot_group.addButton(choose)
            inner.addWidget(choose)
            grid.addWidget(card, position // 3, position % 3)
        layout.addLayout(grid)

    def _security_tab(self) -> QWidget:
        page, layout = self._page()
        layout.addWidget(label(tr("Otomatik kilit"), "Section"))
        form = QFormLayout()
        form.setSpacing(10)
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
        self.idle = QComboBox()
        self.idle.setAccessibleName(tr("Hareketsizlikte kilitle"))
        for title, minutes in ((tr("Kapalı"), 0), (tr("1 dakika"), 1), (tr("5 dakika"), 5), (tr("15 dakika"), 15), (tr("30 dakika"), 30)):
            self.idle.addItem(title, minutes)
        self.idle.setCurrentIndex(max(0, self.idle.findData(self.config.get("idle_lock_minutes", 5))))
        self.idle.currentIndexChanged.connect(self._save_security)
        form.addRow(tr("Hareketsizlikte kilitle"), self.idle)
        layout.addLayout(form)
        self.lock_minimize = QCheckBox(tr("Pencere küçültülünce kilitle"))
        self.lock_minimize.setChecked(self.config.get("lock_on_minimize", False))
        self.lock_minimize.toggled.connect(self._save_security)
        layout.addWidget(self.lock_minimize)
        layout.addWidget(label(tr("Windows kilitlendiğinde açık kasa her zaman kilitlenir."), "Muted"))
        layout.addStretch(1)
        return page

    def _vault_tab(self) -> QWidget:
        page, layout = self._page()
        layout.addWidget(label(self.session.name, "Section"))
        self.two_factor_note = label(name="Muted")
        layout.addWidget(self.two_factor_note)
        self.two_factor_button = button("", on_click=self._toggle_two_factor)
        self._refresh_two_factor()
        layout.addWidget(self.two_factor_button, 0, Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(horizontal_rule())
        row = QHBoxLayout()
        row.setSpacing(8)
        row.addWidget(button(tr("Parolayı değiştir"), on_click=self._change_password))
        self.compact_button = button(tr("Kasayı sıkıştır"), on_click=self._compact)
        row.addWidget(self.compact_button)
        row.addWidget(button(tr("Kurtarma anahtarı"), on_click=self._show_recovery_key))
        self.key_file_button = button("", on_click=self._toggle_key_file)
        self._refresh_key_file()
        row.addWidget(self.key_file_button)
        row.addStretch(1)
        layout.addLayout(row)
        morph_row = QHBoxLayout()
        morph_row.setSpacing(8)
        if self.session.is_stego:
            morph_btn = button(
                tr("Kasadan medya kılıfını çıkar (Saf .pvault)..."),
                on_click=self._strip_carrier,
                icon_=self.theme.icon("eye-off")
            )
            morph_row.addWidget(morph_btn)
        else:
            morph_btn = button(
                tr("Bu kasaya medya kılıfı giydir (Kamuflaj)..."),
                on_click=self._wrap_carrier,
                icon_=self.theme.icon("eye")
            )
            morph_row.addWidget(morph_btn)
        morph_row.addStretch(1)
        layout.addLayout(morph_row)
        self.vault_note = label(name="Muted")
        stats = self.session.stats()
        self.vault_note.setText(tr("Diskte {} yer kaplıyor, {} kullanımda.", format_size(stats['size_on_disk']), format_size(stats['used'])))
        layout.addWidget(self.vault_note)
        layout.addStretch(1)
        return page

    def _choose_mascot(self, key: str) -> None:
        config = load_config()
        config["mascot"] = key
        save_config(config)
        self.mascot_changed.emit(key)

    def _refresh_two_factor(self) -> None:
        enabled = self.session.two_factor_enabled
        self.two_factor_button.setText(tr("İki adımlı doğrulamayı kapat") if enabled else tr("İki adımlı doğrulamayı aç"))
        self.two_factor_note.setText(
            tr("İki adımlı doğrulama açık: kasa açılırken kod istenir.") if enabled
            else tr("İki adımlı doğrulama kapalı. Önceden oluşturulmuş kasalarda da açabilirsiniz; dosyalar etkilenmez.")
        )

    def _emit_design(self, key: str = "", style: str = "") -> None:
        self.selected_design = key or self.selected_design
        self.selected_style = style or self.selected_style
        self.style_note.setText(tr(designs.STYLES[self.selected_style].summary))
        self._sync_palette_lock()
        appearance = self.appearance.currentData()
        self.design_changed.emit(self.selected_design, appearance, self.selected_style)
        dark = self.theme.dark if appearance == "system" else appearance == "dark"
        preview = Theme(designs.get_design(self.selected_design, self.selected_style), dark)
        for mascot in self.mascot_previews:
            mascot.set_theme(preview)

    def _save_security(self, *_args: object) -> None:
        config = load_config()
        config["idle_lock_minutes"] = self.idle.currentData()
        config["lock_on_minimize"] = self.lock_minimize.isChecked()
        save_config(config)

    def _confirm_identity(self) -> Optional[str]:
        """Doğrulanan parolayı döndürür; vazgeçilirse None."""
        dialog = ConfirmIdentityDialog(self.session, self.theme, self)
        return dialog.confirmed_password if dialog.exec() else None

    def _present_recovery_key(self) -> None:
        RecoveryKeyDialog(self.session.recovery_key(), self.session.path, self.theme, self).exec()

    def _show_recovery_key(self) -> None:
        if self._confirm_identity() is not None:
            self._present_recovery_key()

    def _change_password(self) -> None:
        if self._confirm_identity() is None:
            return
        if ChangePasswordDialog(self.session, self.theme, self).exec():
            self.vault_note.setText(tr("Parola değiştirildi, eski kurtarma anahtarı artık geçersiz."))
            self._present_recovery_key()

    def _refresh_key_file(self) -> None:
        self.key_file_button.setText(tr("Anahtar dosyasını kaldır") if self.session.has_key_file else tr("Anahtar dosyası ekle"))

    def _toggle_key_file(self) -> None:
        password = self._confirm_identity()
        if password is None:
            return
        if KeyFileDialog(self.session, password, self.theme, self).exec():
            self.vault_note.setText(tr("Anahtar dosyası güncellendi, eski kurtarma anahtarı artık geçersiz."))
            self._refresh_key_file()
            self._present_recovery_key()

    def _toggle_two_factor(self) -> None:
        if self.session.two_factor_enabled:
            DisableTwoFactorDialog(self.session, self.theme, self).exec()
        else:
            TwoFactorDialog(self.session, self.theme, self).exec()
        self._refresh_two_factor()

    def _compact(self) -> None:
        if not confirm(
            self, tr("Kasayı sıkıştır"),
            tr("Boşalan alan geri kazanılır ve kasa dosyası yeniden yazılır.\n\n"
            "Bu dosyada başka bir parolayla açılan ikinci bölme varsa KALICI OLARAK SİLİNİR. "
            "İkinci bölmeniz varsa bu işlemi yapmayın."),
            tr("Sıkıştır")
        ):
            return
        session = self.session
        task = Task(lambda _progress, _cancelled: session.compact(), self)
        outcome: List[str] = []
        task.succeeded.connect(lambda result: outcome.append(tr("{} geri kazanıldı.", format_size(result['saved_bytes']))))
        task.failed.connect(lambda message: outcome.append(tr("Sıkıştırılamadı: {}", message)))
        loop = QEventLoop()
        task.finished.connect(loop.quit)
        session.maintenance = True
        self.setEnabled(False)
        self.vault_note.setText(tr("Kasa yeniden yazılıyor. Bu pencereyi kapatmayın."))
        task.start()
        loop.exec()
        self.setEnabled(True)
        session.maintenance = False
        self.vault_note.setText(outcome[0] if outcome else "")

    def _wrap_carrier(self) -> None:
        password = self._confirm_identity()
        if password is None:
            return
        from .extras import WrapCarrierDialog
        WrapCarrierDialog(
            self.theme,
            initial_vault_path=self.session.path,
            initial_password=password,
            parent=self
        ).exec()

    def _strip_carrier(self) -> None:
        password = self._confirm_identity()
        if password is None:
            return
        from .extras import StripCarrierDialog
        StripCarrierDialog(
            self.theme,
            initial_stego_path=self.session.path,
            initial_password=password,
            parent=self
        ).exec()
