"""Enclave - Ekstralar: kasa açılmadan veya ayarlar içinden kullanılan araçlar
(SHA-256 hesaplama/karşılaştırma, kasaya medya kılıfı giydirme ve kılıf çıkarma)."""

import hashlib
import re
from pathlib import Path
from typing import Optional

from PyQt6.QtWidgets import (
    QApplication, QCheckBox, QFileDialog, QFrame, QHBoxLayout,
    QLineEdit, QProgressBar, QVBoxLayout, QWidget
)

from .i18n import tr
from .common import LoadingBars, PasswordField, Task, Theme, button, confirm, format_size, label
from .dialogs import DialogBase
from enclave_core import read_key_file
from stego_enclave import wrap_vault_into_carrier, strip_carrier_from_vault

HASH_PATTERN = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])")
CHUNK = 4 * 1024 * 1024

def extract_hash(text: str) -> str:
    """Yapıştırılan metinde 64 haneli özeti bulur; kurtarma dosyasındaki tüm satır da yapıştırılabilir."""
    found = HASH_PATTERN.search(text or "")
    return found.group(0).lower() if found else ""

def sha256_of(path: str, progress=None, cancelled=None) -> str:
    total = Path(path).stat().st_size or 1
    digest, done = hashlib.sha256(), 0
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK), b""):
            if cancelled and cancelled():
                raise RuntimeError(tr("Hesaplama iptal edildi."))
            digest.update(chunk)
            done += len(chunk)
            if progress:
                progress(int(done * 1000 / total))
    return digest.hexdigest()

class ShaDialog(DialogBase):
    """SHA-256 aracı. compare=False yalnızca hesaplar; compare=True beklenen özetle karşılaştırır."""

    def __init__(self, theme: Theme, compare: bool, parent: Optional[QWidget] = None):
        super().__init__(tr("SHA-256 karşılaştır") if compare else tr("SHA-256 hesapla"), theme, parent)
        self.compare = compare
        self._task: Optional[Task] = None
        self._computed = ""

        self.body.addWidget(label(tr("SHA-256 karşılaştır") if compare else tr("SHA-256 hesapla"), "Title"))
        self.body.addWidget(label(
            tr("Dosyanın SHA-256 özetini ve eşleşip eşleşmediğini gösterir. Kasa dosyasını kurtarma anahtarı TXT'sindeki "
            "özetle denetleyerek kasanın değişmediğini doğrulayabilirsiniz.") if compare else
            tr("Seçtiğiniz dosyanın SHA-256 özetini hesaplar. Dosya diskten okunur; kasa ya da parola gerekmez."), "Muted"))

        box = QFrame()
        box.setObjectName("Card")
        inner = QVBoxLayout(box)
        inner.setContentsMargins(18, 16, 18, 16)
        inner.setSpacing(8)
        inner.addWidget(label(tr("Dosya"), "Eyebrow"))
        row = QHBoxLayout()
        row.setSpacing(8)
        self.path_edit = QLineEdit()
        self.path_edit.setPlaceholderText(tr("Doğrulanacak dosya"))
        self.path_edit.setAccessibleName(tr("Dosya yolu"))
        self.path_edit.textChanged.connect(self._reset)
        row.addWidget(self.path_edit, 1)
        row.addWidget(button(tr("Gözat"), on_click=self._browse))
        inner.addLayout(row)
        self.size_note = label(name="Meta")
        inner.addWidget(self.size_note)
        self.expected = QLineEdit()
        if compare:
            inner.addSpacing(4)
            inner.addWidget(label(tr("Beklenen SHA-256"), "Eyebrow"))
            self.expected.setPlaceholderText(tr("64 haneli özeti ya da kurtarma dosyasındaki satırı yapıştırın"))
            self.expected.setAccessibleName(tr("Beklenen SHA-256"))
            self.expected.textChanged.connect(self._show_result)
            inner.addWidget(self.expected)
        inner.addSpacing(4)
        inner.addWidget(label(tr("Hesaplanan SHA-256"), "Eyebrow"))
        self.result = QLineEdit()
        self.result.setReadOnly(True)
        self.result.setPlaceholderText(tr("Henüz hesaplanmadı"))
        self.result.setAccessibleName(tr("Hesaplanan SHA-256"))
        inner.addWidget(self.result)
        self.progress = QProgressBar()
        self.progress.setRange(0, 1000)
        self.progress.setTextVisible(False)
        self.progress.hide()
        inner.addWidget(self.progress)
        self.busy = LoadingBars(theme)
        inner.addWidget(self.busy)
        self.verdict = label(name="Section")
        self.verdict.hide()
        inner.addWidget(self.verdict)
        self.error = label(name="Error")
        self.error.hide()
        inner.addWidget(self.error)
        self.body.addWidget(box)
        self.body.addStretch(1)

        self.copy_button = button(tr("Özeti kopyala"), on_click=self._copy)
        self.copy_button.setEnabled(False)
        self.run_button = button(tr("Karşılaştır") if compare else tr("Hesapla"), "Primary", self._start)
        self.run_button.setEnabled(False)
        self.footer.addWidget(button(tr("Kapat"), on_click=self.reject))
        self.footer.addWidget(self.copy_button)
        self.footer.addWidget(self.run_button)
        self.run_button.setDefault(True)
        self.fit_to_screen(640, 560 if compare else 470)

    def _browse(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, tr("Dosya seçin"), "", tr("Tüm dosyalar (*)"))
        if path:
            self.path_edit.setText(path)

    def _reset(self) -> None:
        path = self.path_edit.text().strip()
        valid = bool(path) and Path(path).is_file()
        self.run_button.setEnabled(valid and self._task is None)
        self.size_note.setText(format_size(Path(path).stat().st_size) if valid else "")
        self._computed = ""
        self.result.clear()
        self.copy_button.setEnabled(False)
        self.verdict.hide()
        self.error.hide()

    def _start(self) -> None:
        path = self.path_edit.text().strip()
        self.run_button.setEnabled(False)
        self.error.hide()
        self.progress.setValue(0)
        self.progress.show()
        self.busy.start()
        self._task = Task(lambda progress, cancelled: sha256_of(path, progress, cancelled), self)
        self._task.advanced.connect(self.progress.setValue)
        self._task.succeeded.connect(self._on_done)
        self._task.failed.connect(self._on_failed)
        self._task.start()

    def _on_done(self, digest: str) -> None:
        self._task = None
        self.progress.hide()
        self.busy.stop()
        self._computed = digest
        self.result.setText(digest)
        self.result.setCursorPosition(0)
        self.copy_button.setEnabled(True)
        self._reset_run_state()
        self._show_result()

    def _on_failed(self, message: str) -> None:
        self._task = None
        self.progress.hide()
        self.busy.stop()
        self.error.setText(message)
        self.error.show()
        self._reset_run_state()

    def _reset_run_state(self) -> None:
        path = self.path_edit.text().strip()
        self.run_button.setEnabled(bool(path) and Path(path).is_file())

    def _show_result(self) -> None:
        if not self.compare or not self._computed:
            return
        typed = self.expected.text().strip()
        if not typed:
            self.verdict.hide()
            return
        wanted = extract_hash(typed)
        self.verdict.show()
        if not wanted:
            self.verdict.setObjectName("Warning")
            self.verdict.setText(tr("Girilen metinde 64 haneli geçerli bir SHA-256 özeti yok."))
        elif wanted == self._computed:
            self.verdict.setObjectName("Success")
            self.verdict.setText(tr("Eşleşti: dosya değişmemiş."))
        else:
            self.verdict.setObjectName("Error")
            self.verdict.setText(tr("Eşleşmedi: dosya değişmiş, bozulmuş ya da başka bir dosya."))
        self.verdict.style().unpolish(self.verdict)
        self.verdict.style().polish(self.verdict)

    def _copy(self) -> None:
        if self._computed:
            QApplication.clipboard().setText(self._computed)

    def done(self, result: int) -> None:
        if self._task:
            self._task.cancel()
            self._task.wait(2000)
        super().done(result)

class WrapCarrierDialog(DialogBase):
    """Mevcut bir .pvault kasasına medya kılıfı giydirerek kamuflaj kasaya dönüştürür."""

    def __init__(
        self,
        theme: Theme,
        initial_vault_path: str = "",
        initial_password: str = "",
        parent: Optional[QWidget] = None
    ):
        super().__init__(tr("Kasaya medya kılıfı giydir (Kamuflaj)"), theme, parent)
        self._task: Optional[Task] = None
        self._key_digest: Optional[bytes] = None

        self.body.addWidget(label(tr("Kasaya medya kılıfı giydir (Kamuflaj)"), "Title"))
        self.body.addWidget(label(
            tr("Mevcut bir bağımsız kasayı (.pvault) seçtiğiniz bir medya dosyasının (video, ses, resim vb.) içine kılıf olarak aktarır. "
               "Yeni dosya standart bir medya oynatıcıda oynatılabilir; Enclave ile açıldığında ise kasa verilerinize erişilir."),
            "Muted"
        ))

        box = QFrame()
        box.setObjectName("Card")
        inner = QVBoxLayout(box)
        inner.setContentsMargins(18, 16, 18, 16)
        inner.setSpacing(10)

        inner.addWidget(label(tr("Kaynak kasa dosyası (.pvault)"), "Eyebrow"))
        row1 = QHBoxLayout()
        row1.setSpacing(8)
        self.vault_edit = QLineEdit(initial_vault_path)
        self.vault_edit.setPlaceholderText(tr("Kılıf giydirilecek .pvault dosyası"))
        self.vault_edit.textChanged.connect(self._on_input_changed)
        row1.addWidget(self.vault_edit, 1)
        row1.addWidget(button(tr("Gözat"), on_click=self._browse_vault))
        inner.addLayout(row1)

        inner.addWidget(label(tr("Kılıf olarak kullanılacak medya dosyası"), "Eyebrow"))
        row2 = QHBoxLayout()
        row2.setSpacing(8)
        self.carrier_edit = QLineEdit()
        self.carrier_edit.setPlaceholderText(tr("Video, ses, resim veya kalıp dosyası"))
        self.carrier_edit.textChanged.connect(self._on_carrier_changed)
        row2.addWidget(self.carrier_edit, 1)
        row2.addWidget(button(tr("Gözat"), on_click=self._browse_carrier))
        inner.addLayout(row2)

        inner.addWidget(label(tr("Oluşturulacak yeni kamuflaj kasa dosyası"), "Eyebrow"))
        row3 = QHBoxLayout()
        row3.setSpacing(8)
        self.target_edit = QLineEdit()
        self.target_edit.setPlaceholderText(tr("Yeni kamuflaj kasanın kaydedileceği yer"))
        self.target_edit.textChanged.connect(self._on_input_changed)
        row3.addWidget(self.target_edit, 1)
        row3.addWidget(button(tr("Gözat"), on_click=self._browse_target))
        inner.addLayout(row3)

        inner.addWidget(label(tr("Kasa parolası"), "Eyebrow"))
        self.password_field = PasswordField(theme, tr("Kasanın mevcut parolası"))
        if initial_password:
            self.password_field.setText(initial_password)
        self.password_field.textChanged.connect(self._on_input_changed)
        inner.addWidget(self.password_field)

        self.decoy_check = QCheckBox(tr("İkinci (tuzak) bölmeyi de kılıfa aktar"))
        self.decoy_check.toggled.connect(self._on_decoy_toggled)
        inner.addWidget(self.decoy_check)

        self.decoy_box = QWidget()
        decoy_layout = QVBoxLayout(self.decoy_box)
        decoy_layout.setContentsMargins(0, 0, 0, 0)
        decoy_layout.setSpacing(4)
        decoy_layout.addWidget(label(tr("Tuzak bölme parolası"), "Eyebrow"))
        self.decoy_field = PasswordField(theme, tr("Tuzak bölme parolası"))
        self.decoy_field.textChanged.connect(self._on_input_changed)
        decoy_layout.addWidget(self.decoy_field)
        self.decoy_box.hide()
        inner.addWidget(self.decoy_box)

        row_key = QHBoxLayout()
        self.key_button = button(tr("Anahtar dosyası seç (opsiyonel)"), "Link", self._pick_key_file)
        row_key.addWidget(self.key_button)
        row_key.addStretch(1)
        inner.addLayout(row_key)

        self.progress = QProgressBar()
        self.progress.setRange(0, 1000)
        self.progress.setTextVisible(False)
        self.progress.hide()
        inner.addWidget(self.progress)
        self.busy = LoadingBars(theme)
        inner.addWidget(self.busy)
        self.status = label(name="Success")
        self.status.hide()
        inner.addWidget(self.status)
        self.error = label(name="Error")
        self.error.hide()
        inner.addWidget(self.error)

        self.body.addWidget(box)
        self.body.addStretch(1)

        self.close_button = button(tr("Vazgeç"), on_click=self.reject)
        self.run_button = button(tr("Kılıf giydir"), "Primary", self._start)
        self.run_button.setEnabled(False)
        self.footer.addWidget(self.close_button)
        self.footer.addWidget(self.run_button)
        self.run_button.setDefault(True)

        self._on_input_changed()
        self.fit_to_screen(680, 680)

    def _browse_vault(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, tr("Kaynak .pvault kasasını seçin"), "", tr("Kasa dosyaları (*.pvault);;Tüm dosyalar (*)")
        )
        if path:
            self.vault_edit.setText(path)

    def _browse_carrier(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, tr("Kılıf medya dosyasını seçin"), "",
            tr("Medya ve kalıp dosyaları (*.mp4 *.mkv *.mov *.avi *.webm *.mp3 *.flac *.wav *.png *.jpg *.jpeg *.webp *.iso *.zip);;Tüm dosyalar (*)")
        )
        if path:
            self.carrier_edit.setText(path)

    def _on_carrier_changed(self) -> None:
        carrier = self.carrier_edit.text().strip()
        if carrier and not self.target_edit.text().strip():
            cp = Path(carrier)
            default_target = cp.parent / f"{cp.stem}_kasa{cp.suffix}"
            self.target_edit.setText(str(default_target))
        self._on_input_changed()

    def _browse_target(self) -> None:
        carrier = self.carrier_edit.text().strip()
        ext = Path(carrier).suffix if carrier else ".mp4"
        default_name = f"kasa{ext}"
        if carrier:
            cp = Path(carrier)
            default_name = f"{cp.stem}_kasa{cp.suffix}"
        path, _ = QFileDialog.getSaveFileName(
            self, tr("Yeni kamuflaj kasa dosyası"), default_name, tr("Tüm dosyalar (*)")
        )
        if path:
            self.target_edit.setText(path)

    def _on_decoy_toggled(self, checked: bool) -> None:
        self.decoy_box.setVisible(checked)
        self._on_input_changed()

    def _pick_key_file(self) -> None:
        if self._key_digest is not None:
            self._key_digest = None
            self.key_button.setText(tr("Anahtar dosyası seç (opsiyonel)"))
            return
        path, _ = QFileDialog.getOpenFileName(
            self, tr("Anahtar dosyasını seçin"), "", tr("Tüm dosyalar (*)")
        )
        if not path:
            return
        try:
            self._key_digest = read_key_file(path)
            self.key_button.setText(tr("Anahtar dosyası seçildi: {} (kaldır)").format(Path(path).name))
        except Exception as err:
            self.error.setText(tr("Anahtar dosyası okunamadı: {}").format(err))
            self.error.show()

    def _on_input_changed(self) -> None:
        if self._task is not None:
            return
        v = self.vault_edit.text().strip()
        c = self.carrier_edit.text().strip()
        t = self.target_edit.text().strip()
        p = self.password_field.text()
        decoy_valid = True
        if self.decoy_check.isChecked():
            dp = self.decoy_field.text()
            decoy_valid = bool(dp) and len(dp) >= 8 and dp != p
        valid = bool(v and c and t and p and len(p) >= 8 and decoy_valid)
        self.run_button.setEnabled(valid)

    def _start(self) -> None:
        vault_path = self.vault_edit.text().strip()
        carrier_path = self.carrier_edit.text().strip()
        target_path = self.target_edit.text().strip()
        password = self.password_field.text()
        decoy_pw = self.decoy_field.text() if self.decoy_check.isChecked() else None

        self.error.hide()
        self.status.hide()

        if not Path(vault_path).is_file():
            self.error.setText(tr("Kaynak kasa dosyası bulunamadı."))
            self.error.show()
            return

        if not Path(carrier_path).is_file():
            self.error.setText(tr("Kılıf medya dosyası bulunamadı."))
            self.error.show()
            return

        if Path(target_path).resolve() == Path(vault_path).resolve():
            self.error.setText(tr("Hedef dosya kaynak kasa ile aynı olamaz."))
            self.error.show()
            return

        if Path(target_path).resolve() == Path(carrier_path).resolve():
            self.error.setText(tr("Hedef dosya kılıf medya ile aynı olamaz."))
            self.error.show()
            return

        if Path(target_path).exists():
            if not confirm(
                self, tr("Dosyanın üzerine yazılsın mı?"),
                tr("Hedef dosya zaten mevcut: {}\nÜzerine yazılsın mı?").format(target_path),
                tr("Üzerine yaz")
            ):
                return

        self.run_button.setEnabled(False)
        self.close_button.setEnabled(False)
        self.progress.setValue(0)
        self.progress.show()
        self.busy.start()

        def run(progress, cancelled):
            def on_progress(done, total):
                if cancelled and cancelled():
                    raise RuntimeError(tr("İşlem iptal edildi."))
                if total > 0:
                    progress(int(done * 1000 / total))

            return wrap_vault_into_carrier(
                source_vault_path=vault_path,
                carrier_source_path=carrier_path,
                target_vault_path=target_path,
                password=password,
                decoy_password=decoy_pw or None,
                key_digest=self._key_digest,
                on_progress=on_progress
            )

        self._task = Task(run, self)
        self._task.advanced.connect(self.progress.setValue)
        self._task.succeeded.connect(self._on_success)
        self._task.failed.connect(self._on_failed)
        self._task.start()

    def _on_success(self, result: dict) -> None:
        self._task = None
        self.progress.hide()
        self.busy.stop()
        self.close_button.setEnabled(True)
        self.close_button.setText(tr("Kapat"))
        self.run_button.setEnabled(False)
        count = result.get("files_transferred", 0)
        has_decoy = result.get("has_decoy", False)
        decoy_msg = tr(" (Tuzak bölme dahil)") if has_decoy else ""
        self.status.setText(
            tr("Kılıf başarıyla giydirildi! {} dosya aktarıldı{}.\nDosya: {}\nBu dosya hem standart medya oynatıcılarda oynatılır hem de Enclave ile açılabilir.")
            .format(count, decoy_msg, result.get("path", ""))
        )
        self.status.show()

    def _on_failed(self, message: str) -> None:
        self._task = None
        self.progress.hide()
        self.busy.stop()
        self.close_button.setEnabled(True)
        self.run_button.setEnabled(True)
        self.error.setText(tr("Kılıf giydirilemedi: {}").format(message))
        self.error.show()

    def done(self, result: int) -> None:
        if self._task:
            self._task.cancel()
            self._task.wait(2000)
        super().done(result)

class StripCarrierDialog(DialogBase):
    """Kamuflaj kasadan medya kılıfını sıyırıp saf bağımsız .pvault kasasına dönüştürür."""

    def __init__(
        self,
        theme: Theme,
        initial_stego_path: str = "",
        initial_password: str = "",
        parent: Optional[QWidget] = None
    ):
        super().__init__(tr("Kasadan medya kılıfını çıkar (Saf .pvault)"), theme, parent)
        self._task: Optional[Task] = None
        self._key_digest: Optional[bytes] = None

        self.body.addWidget(label(tr("Kasadan medya kılıfını çıkar (Saf .pvault)"), "Title"))
        self.body.addWidget(label(
            tr("Medya kılıfı giydirilmiş bir kamuflaj kasayı medya dosyasından ayırarak saf, bağımsız bir .pvault kasasına dönüştürür. "
               "Yeni dosya standart bir Enclave kasası olarak kullanılabilir."),
            "Muted"
        ))

        box = QFrame()
        box.setObjectName("Card")
        inner = QVBoxLayout(box)
        inner.setContentsMargins(18, 16, 18, 16)
        inner.setSpacing(10)

        inner.addWidget(label(tr("Kaynak kamuflaj kasa dosyası"), "Eyebrow"))
        row1 = QHBoxLayout()
        row1.setSpacing(8)
        self.stego_edit = QLineEdit(initial_stego_path)
        self.stego_edit.setPlaceholderText(tr("Kılıfı çıkarılacak kamuflaj dosya"))
        self.stego_edit.textChanged.connect(self._on_stego_changed)
        row1.addWidget(self.stego_edit, 1)
        row1.addWidget(button(tr("Gözat"), on_click=self._browse_stego))
        inner.addLayout(row1)

        inner.addWidget(label(tr("Oluşturulacak saf kasa dosyası (.pvault)"), "Eyebrow"))
        row2 = QHBoxLayout()
        row2.setSpacing(8)
        self.target_edit = QLineEdit()
        self.target_edit.setPlaceholderText(tr("Yeni .pvault dosyasının kaydedileceği yer"))
        self.target_edit.textChanged.connect(self._on_input_changed)
        row2.addWidget(self.target_edit, 1)
        row2.addWidget(button(tr("Gözat"), on_click=self._browse_target))
        inner.addLayout(row2)

        inner.addWidget(label(tr("Kasa parolası"), "Eyebrow"))
        self.password_field = PasswordField(theme, tr("Kasanın mevcut parolası"))
        if initial_password:
            self.password_field.setText(initial_password)
        self.password_field.textChanged.connect(self._on_input_changed)
        inner.addWidget(self.password_field)

        self.decoy_check = QCheckBox(tr("İkinci (tuzak) bölmeyi de aktar"))
        self.decoy_check.toggled.connect(self._on_decoy_toggled)
        inner.addWidget(self.decoy_check)

        self.decoy_box = QWidget()
        decoy_layout = QVBoxLayout(self.decoy_box)
        decoy_layout.setContentsMargins(0, 0, 0, 0)
        decoy_layout.setSpacing(4)
        decoy_layout.addWidget(label(tr("Tuzak bölme parolası"), "Eyebrow"))
        self.decoy_field = PasswordField(theme, tr("Tuzak bölme parolası"))
        self.decoy_field.textChanged.connect(self._on_input_changed)
        decoy_layout.addWidget(self.decoy_field)
        self.decoy_box.hide()
        inner.addWidget(self.decoy_box)

        row_key = QHBoxLayout()
        self.key_button = button(tr("Anahtar dosyası seç (opsiyonel)"), "Link", self._pick_key_file)
        row_key.addWidget(self.key_button)
        row_key.addStretch(1)
        inner.addLayout(row_key)

        self.progress = QProgressBar()
        self.progress.setRange(0, 1000)
        self.progress.setTextVisible(False)
        self.progress.hide()
        inner.addWidget(self.progress)
        self.busy = LoadingBars(theme)
        inner.addWidget(self.busy)
        self.status = label(name="Success")
        self.status.hide()
        inner.addWidget(self.status)
        self.error = label(name="Error")
        self.error.hide()
        inner.addWidget(self.error)

        self.body.addWidget(box)
        self.body.addStretch(1)

        self.close_button = button(tr("Vazgeç"), on_click=self.reject)
        self.run_button = button(tr("Kılıfı çıkar"), "Primary", self._start)
        self.run_button.setEnabled(False)
        self.footer.addWidget(self.close_button)
        self.footer.addWidget(self.run_button)
        self.run_button.setDefault(True)

        if initial_stego_path:
            self._on_stego_changed()
        else:
            self._on_input_changed()
        self.fit_to_screen(680, 640)

    def _browse_stego(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, tr("Kaynak kamuflaj kasasını seçin"), "",
            tr("Kamuflaj dosyaları (*.mp4 *.mkv *.mov *.avi *.webm *.mp3 *.flac *.wav *.png *.jpg *.jpeg *.webp *.iso *.zip);;Tüm dosyalar (*)")
        )
        if path:
            self.stego_edit.setText(path)

    def _on_stego_changed(self) -> None:
        stego = self.stego_edit.text().strip()
        if stego and not self.target_edit.text().strip():
            sp = Path(stego)
            stem = sp.stem
            if stem.endswith("_kasa"):
                stem = stem[:-5]
            default_target = sp.parent / f"{stem}.pvault"
            self.target_edit.setText(str(default_target))
        self._on_input_changed()

    def _browse_target(self) -> None:
        stego = self.stego_edit.text().strip()
        stem = Path(stego).stem if stego else "kasa"
        if stem.endswith("_kasa"):
            stem = stem[:-5]
        path, _ = QFileDialog.getSaveFileName(
            self, tr("Yeni .pvault kasa dosyası"), f"{stem}.pvault", tr("Kasa dosyaları (*.pvault)")
        )
        if path:
            self.target_edit.setText(path)

    def _on_decoy_toggled(self, checked: bool) -> None:
        self.decoy_box.setVisible(checked)
        self._on_input_changed()

    def _pick_key_file(self) -> None:
        if self._key_digest is not None:
            self._key_digest = None
            self.key_button.setText(tr("Anahtar dosyası seç (opsiyonel)"))
            return
        path, _ = QFileDialog.getOpenFileName(
            self, tr("Anahtar dosyasını seçin"), "", tr("Tüm dosyalar (*)")
        )
        if not path:
            return
        try:
            self._key_digest = read_key_file(path)
            self.key_button.setText(tr("Anahtar dosyası seçildi: {} (kaldır)").format(Path(path).name))
        except Exception as err:
            self.error.setText(tr("Anahtar dosyası okunamadı: {}").format(err))
            self.error.show()

    def _on_input_changed(self) -> None:
        if self._task is not None:
            return
        s = self.stego_edit.text().strip()
        t = self.target_edit.text().strip()
        p = self.password_field.text()
        decoy_valid = True
        if self.decoy_check.isChecked():
            dp = self.decoy_field.text()
            decoy_valid = bool(dp) and len(dp) >= 8 and dp != p
        valid = bool(s and t and p and len(p) >= 8 and decoy_valid)
        self.run_button.setEnabled(valid)

    def _start(self) -> None:
        stego_path = self.stego_edit.text().strip()
        target_path = self.target_edit.text().strip()
        password = self.password_field.text()
        decoy_pw = self.decoy_field.text() if self.decoy_check.isChecked() else None

        self.error.hide()
        self.status.hide()

        if not Path(stego_path).is_file():
            self.error.setText(tr("Kaynak kamuflaj dosyası bulunamadı."))
            self.error.show()
            return

        if Path(target_path).resolve() == Path(stego_path).resolve():
            self.error.setText(tr("Hedef dosya kaynak dosya ile aynı olamaz."))
            self.error.show()
            return

        if Path(target_path).exists():
            if not confirm(
                self, tr("Dosyanın üzerine yazılsın mı?"),
                tr("Hedef dosya zaten mevcut: {}\nÜzerine yazılsın mı?").format(target_path),
                tr("Üzerine yaz")
            ):
                return

        self.run_button.setEnabled(False)
        self.close_button.setEnabled(False)
        self.progress.setValue(0)
        self.progress.show()
        self.busy.start()

        def run(progress, cancelled):
            def on_progress(done, total):
                if cancelled and cancelled():
                    raise RuntimeError(tr("İşlem iptal edildi."))
                if total > 0:
                    progress(int(done * 1000 / total))

            return strip_carrier_from_vault(
                stego_vault_path=stego_path,
                target_vault_path=target_path,
                password=password,
                decoy_password=decoy_pw or None,
                key_digest=self._key_digest,
                on_progress=on_progress
            )

        self._task = Task(run, self)
        self._task.advanced.connect(self.progress.setValue)
        self._task.succeeded.connect(self._on_success)
        self._task.failed.connect(self._on_failed)
        self._task.start()

    def _on_success(self, result: dict) -> None:
        self._task = None
        self.progress.hide()
        self.busy.stop()
        self.close_button.setEnabled(True)
        self.close_button.setText(tr("Kapat"))
        self.run_button.setEnabled(False)
        count = result.get("files_transferred", 0)
        has_decoy = result.get("has_decoy", False)
        decoy_msg = tr(" (Tuzak bölme dahil)") if has_decoy else ""
        self.status.setText(
            tr("Medya kılıfı başarıyla çıkarıldı! {} dosya aktarıldı{}.\nDosya: {}\nKasa artık saf bağımsız .pvault olarak kullanılabilir.")
            .format(count, decoy_msg, result.get("path", ""))
        )
        self.status.show()

    def _on_failed(self, message: str) -> None:
        self._task = None
        self.progress.hide()
        self.busy.stop()
        self.close_button.setEnabled(True)
        self.run_button.setEnabled(True)
        self.error.setText(tr("Kılıf çıkarılamadı: {}").format(message))
        self.error.show()

    def done(self, result: int) -> None:
        if self._task:
            self._task.cancel()
            self._task.wait(2000)
        super().done(result)
