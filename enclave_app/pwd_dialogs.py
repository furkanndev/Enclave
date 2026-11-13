"""Enclave - Parola Yöneticisi Diyalog Pencereleri.

Kayıt düzenleme modalı, parola üreteci, içe/dışa aktarma sihirbazı ve güvenlik denetim raporu.
"""

from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QCheckBox, QComboBox, QFileDialog, QFormLayout, QFrame,
    QHBoxLayout, QLabel, QLineEdit, QMessageBox, QPushButton,
    QRadioButton, QScrollArea, QSlider, QSpinBox, QTabWidget,
    QTextEdit, QVBoxLayout, QWidget
)

from .common import (
    PasswordField, Theme, button, confirm, copy_secret, format_size,
    horizontal_rule, label, tool_button
)
from .dialogs import DialogBase
from .i18n import tr
from .pwd_engine import (
    ENTRY_TYPES, TYPE_ICONS, TYPE_LABELS, PasswordEntry, PasswordStore,
    evaluate_password, generate_password, get_live_totp
)
from .pwd_importer import (
    detect_and_import_csv, detect_and_import_json, export_encrypted_backup,
    export_to_csv, import_encrypted_backup
)

class EntryEditorDialog(DialogBase):
    """Yeni kayıt oluşturan veya mevcut kaydı düzenleyen çok yönlü diyalog."""

    def __init__(
        self,
        theme: Theme,
        store: PasswordStore,
        entry: Optional[PasswordEntry] = None,
        default_type: str = "login",
        parent: Optional[QWidget] = None
    ):
        self.is_new = entry is None
        title_text = tr("Yeni Kayıt Ekle") if self.is_new else tr("Kaydı Düzenle")
        super().__init__(title_text, theme, parent)

        self.store = store
        self.entry = entry or PasswordEntry(type=default_type)
        self.save_button = None
        self._custom_rows: List[Tuple[QLineEdit, QLineEdit, QCheckBox]] = []

        self.body.addWidget(label(title_text, "Title"))

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        content = QWidget()
        self.layout = QVBoxLayout(content)
        self.layout.setContentsMargins(12, 12, 12, 12)
        self.layout.setSpacing(10)

        head_row = QHBoxLayout()
        head_row.setSpacing(8)
        self.type_combo = QComboBox()
        for t_key in ENTRY_TYPES:
            self.type_combo.addItem(tr(TYPE_LABELS[t_key]), t_key)
        self.type_combo.setCurrentIndex(ENTRY_TYPES.index(self.entry.type) if self.entry.type in ENTRY_TYPES else 0)
        self.type_combo.currentIndexChanged.connect(self._on_type_changed)
        head_row.addWidget(label(tr("Tür"), "Eyebrow", wrap=False))
        head_row.addWidget(self.type_combo)

        self.fav_check = QCheckBox(tr("Favorilere ekle"))
        self.fav_check.setChecked(self.entry.favorite)
        head_row.addStretch(1)
        head_row.addWidget(self.fav_check)
        self.layout.addLayout(head_row)

        self.title_edit = QLineEdit(self.entry.title)
        self.title_edit.setPlaceholderText(tr("Kayıt Başlığı (örn. Google Hesabım, Finans Kartı)"))
        self.title_edit.textChanged.connect(self._validate)
        self.layout.addWidget(label(tr("Başlık"), "Eyebrow"))
        self.layout.addWidget(self.title_edit)

        self.form_box = QFrame()
        self.form_box.setObjectName("Card")
        self.form_layout = QFormLayout(self.form_box)
        self.form_layout.setContentsMargins(16, 14, 16, 14)
        self.form_layout.setSpacing(10)
        self.form_layout.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
        self.layout.addWidget(self.form_box)

        self.user_edit = QLineEdit(self.entry.username)
        self.pass_field = PasswordField(theme, tr("Parola"))
        self.pwd_edit = self.pass_field.edit
        if self.entry.password:
            self.pass_field.setText(self.entry.password)
        self.pass_field.textChanged.connect(self._on_password_changed)

        pass_row = QHBoxLayout()
        pass_row.setSpacing(6)
        pass_row.addWidget(self.pass_field, 1)
        gen_btn = button(tr("Üret"), on_click=self._open_generator, icon_=theme.icon("refresh"))
        gen_btn.setToolTip(tr("Güçlü rastgele parola üret"))
        pass_row.addWidget(gen_btn)

        self.strength_label = label(name="Meta")
        self._on_password_changed(self.entry.password)

        self.url_edit = QLineEdit(self.entry.url)
        self.url_edit.setPlaceholderText("https://...")

        self.totp_edit = QLineEdit(self.entry.totp_secret)
        self.totp_edit.setPlaceholderText(tr("Gizli Anahtar (Base32, örn. JBSWY3DPEHPK3PXP)"))
        self.totp_test_label = label(name="Meta")
        self.totp_edit.textChanged.connect(self._test_totp)
        self._test_totp()

        self.card_number = QLineEdit()
        self.card_holder = QLineEdit()
        self.card_expiry = QLineEdit()
        self.card_cvv = QLineEdit()
        self.card_pin = QLineEdit()

        self.key_data = QTextEdit()
        self.key_data.setMaximumHeight(90)

        self._populate_type_fields()

        self.layout.addWidget(label(tr("Etiketler (Virgülle ayırın)"), "Eyebrow"))
        self.tags_edit = QLineEdit(", ".join(self.entry.tags))
        self.tags_edit.setPlaceholderText(tr("örn. İş, Kişisel, Kripto"))
        self.layout.addWidget(self.tags_edit)

        self.layout.addWidget(label(tr("Güvenli Notlar"), "Eyebrow"))
        self.notes_edit = QTextEdit()
        self.notes_edit.setPlaceholderText(tr("Yalnızca sizin görebileceğiniz gizli notlar..."))
        self.notes_edit.setPlainText(self.entry.notes)
        self.notes_edit.setMaximumHeight(100)
        self.layout.addWidget(self.notes_edit)

        self.custom_box = QFrame()
        self.custom_box.setObjectName("Card")
        self.custom_layout = QVBoxLayout(self.custom_box)
        self.custom_layout.setContentsMargins(14, 12, 14, 12)
        self.custom_layout.setSpacing(6)
        custom_header = QHBoxLayout()
        custom_header.addWidget(label(tr("Özel Alanlar"), "Eyebrow"))
        custom_header.addStretch(1)
        add_field_btn = button(tr("+ Alan Ekle"), "Link", self._add_custom_field, theme.icon("plus"))
        custom_header.addWidget(add_field_btn)
        self.custom_layout.addLayout(custom_header)
        self.layout.addWidget(self.custom_box)

        for cf in self.entry.custom_fields:
            self._add_custom_field(cf.get("name", ""), cf.get("value", ""), bool(cf.get("secret", False)))

        scroll.setWidget(content)
        self.body.addWidget(scroll, 1)

        self.error = label(name="Error")
        self.error.hide()
        self.body.addWidget(self.error)

        self.footer.addWidget(button(tr("Vazgeç"), on_click=self.reject))
        self.save_button = button(tr("Kaydet"), "Primary", self._save)
        self.footer.addWidget(self.save_button)

        self._validate()
        self.fit_to_screen(680, 720)

    def _on_type_changed(self) -> None:
        self._populate_type_fields()
        self._validate()

    def _populate_type_fields(self) -> None:
        """Seçilen türe göre form satırlarını dinamik temizleyip yeniden dizer."""
        while self.form_layout.rowCount() > 0:
            self.form_layout.removeRow(0)

        t = self.type_combo.currentData()
        if t == "login":
            self.form_layout.addRow(tr("Kullanıcı Adı / E-posta"), self.user_edit)
            pass_v = QVBoxLayout()
            pass_row = QHBoxLayout()
            pass_row.addWidget(self.pass_field, 1)
            gen = button(tr("Üret"), on_click=self._open_generator, icon_=self.theme.icon("refresh"))
            pass_row.addWidget(gen)
            pass_v.addLayout(pass_row)
            pass_v.addWidget(self.strength_label)
            self.form_layout.addRow(tr("Parola"), pass_v)
            self.form_layout.addRow(tr("Web Sitesi (URL)"), self.url_edit)
            totp_v = QVBoxLayout()
            totp_v.addWidget(self.totp_edit)
            totp_v.addWidget(self.totp_test_label)
            self.form_layout.addRow(tr("2FA / TOTP Anahtarı"), totp_v)

        elif t == "card":
            self.form_layout.addRow(tr("Kart Sahibi"), self.user_edit)
            self.card_number.setPlaceholderText("4543 .... .... ....")
            self.form_layout.addRow(tr("Kart Numarası"), self.card_number)
            exp_row = QHBoxLayout()
            self.card_expiry.setPlaceholderText("MM/YY")
            self.card_cvv.setPlaceholderText("CVC/CVV")
            self.card_pin.setPlaceholderText("PIN")
            exp_row.addWidget(self.card_expiry)
            exp_row.addWidget(self.card_cvv)
            exp_row.addWidget(self.card_pin)
            self.form_layout.addRow(tr("Son Kullanma / CVV / PIN"), exp_row)

        elif t == "key":
            self.form_layout.addRow(tr("Anahtar Adı / Kimliği"), self.user_edit)
            self.form_layout.addRow(tr("Gizli Anahtar / Token"), self.key_data)

        elif t == "server":
            self.form_layout.addRow(tr("Sunucu Adresi / IP"), self.url_edit)
            self.form_layout.addRow(tr("Kullanıcı Adı"), self.user_edit)
            self.form_layout.addRow(tr("Parola"), self.pass_field)

        elif t == "identity":
            self.form_layout.addRow(tr("Tam Ad"), self.user_edit)
            self.form_layout.addRow(tr("Kimlik / Pasaport No"), self.url_edit)

        elif t == "note":
            pass

    def _on_password_changed(self, text: str) -> None:
        score, lbl = evaluate_password(text)
        colors = ["#C5221F", "#D93025", "#F29900", "#188038", "#137333"]
        self.strength_label.setText(tr("Güç: {} ({}/4)").format(lbl, score))
        self.strength_label.setStyleSheet(f"color: {colors[score]}; font-size: 12px; font-weight: bold;")
        self._validate()

    def _test_totp(self) -> None:
        sec = self.totp_edit.text().strip()
        if not sec:
            self.totp_test_label.setText("")
            return
        token, rem, _ = get_live_totp(sec)
        if token:
            self.totp_test_label.setText(tr("Geçerli! Canlı Kod: {} ({} sn)").format(token, rem))
            self.totp_test_label.setStyleSheet("color: #188038; font-size: 12px;")
        else:
            self.totp_test_label.setText(tr("Geçersiz Base32 TOTP anahtarı"))
            self.totp_test_label.setStyleSheet("color: #C5221F; font-size: 12px;")

    def _open_generator(self) -> None:
        dlg = PasswordGeneratorDialog(self.theme, self)
        if dlg.exec() and dlg.generated:
            self.pass_field.setText(dlg.generated)

    def _add_custom_field(self, name: str = "", val: str = "", secret: bool = False) -> None:
        row = QHBoxLayout()
        row.setSpacing(6)
        n_edit = QLineEdit(name)
        n_edit.setPlaceholderText(tr("Alan Adı"))
        v_edit = QLineEdit(val)
        v_edit.setPlaceholderText(tr("Değer"))
        sec_chk = QCheckBox(tr("Gizle"))
        sec_chk.setChecked(secret)
        if secret:
            v_edit.setEchoMode(QLineEdit.EchoMode.Password)
        sec_chk.toggled.connect(lambda on: v_edit.setEchoMode(QLineEdit.EchoMode.Password if on else QLineEdit.EchoMode.Normal))

        del_btn = tool_button("", self.theme.icon("close", size=14), on_click=lambda: self._remove_custom_field(row), name="Link")

        row.addWidget(n_edit, 2)
        row.addWidget(v_edit, 3)
        row.addWidget(sec_chk)
        row.addWidget(del_btn)

        self.custom_layout.addLayout(row)
        self._custom_rows.append((n_edit, v_edit, sec_chk))

    def _remove_custom_field(self, row_layout: QHBoxLayout) -> None:
        for i in range(row_layout.count()):
            w = row_layout.itemAt(i).widget()
            if w:
                w.deleteLater()
        self.custom_layout.removeItem(row_layout)
        self._custom_rows = [r for r in self._custom_rows if r[0].isVisible()]

    def _validate(self) -> None:
        title = self.title_edit.text().strip() if hasattr(self, "title_edit") else ""
        if hasattr(self, "save_button") and self.save_button:
            self.save_button.setEnabled(bool(title))

    def _on_save(self) -> bool:
        title = self.title_edit.text().strip() if hasattr(self, "title_edit") else ""
        if not title:
            return False
        self._save()
        return True

    def _save(self) -> None:
        t = self.type_combo.currentData()
        title = self.title_edit.text().strip()
        if not title:
            return

        self.entry.type = t
        self.entry.title = title
        self.entry.favorite = self.fav_check.isChecked()
        self.entry.notes = self.notes_edit.toPlainText().strip()
        tags_raw = self.tags_edit.text().split(",")
        self.entry.tags = [tag.strip() for tag in tags_raw if tag.strip()]

        if t == "login":
            self.entry.username = self.user_edit.text().strip()
            self.entry.password = self.pass_field.text()
            self.entry.url = self.url_edit.text().strip()
            self.entry.totp_secret = self.totp_edit.text().strip().replace(" ", "").upper()
        elif t == "card":
            self.entry.username = self.user_edit.text().strip()
            self.entry.password = self.card_cvv.text().strip()
            self.entry.url = self.card_number.text().strip()
            self.entry.custom_fields = [
                {"name": "Son Kullanma", "value": self.card_expiry.text().strip(), "secret": False},
                {"name": "PIN", "value": self.card_pin.text().strip(), "secret": True}
            ]
        elif t == "key":
            self.entry.username = self.user_edit.text().strip()
            self.entry.password = self.key_data.toPlainText().strip()
        elif t == "server":
            self.entry.url = self.url_edit.text().strip()
            self.entry.username = self.user_edit.text().strip()
            self.entry.password = self.pass_field.text()
        elif t == "identity":
            self.entry.username = self.user_edit.text().strip()
            self.entry.url = self.url_edit.text().strip()

        c_fields = list(self.entry.custom_fields) if t == "card" else []
        for n_e, v_e, s_c in self._custom_rows:
            if n_e.text().strip():
                c_fields.append({
                    "name": n_e.text().strip(),
                    "value": v_e.text(),
                    "secret": s_c.isChecked()
                })
        self.entry.custom_fields = c_fields

        if self.is_new:
            self.store.add(self.entry)
        else:
            self.store.update(self.entry)

        self.accept()

class PasswordGeneratorDialog(DialogBase):
    """Kapsamlı kriptografik parola ve parola öbeği üreteci."""

    def __init__(self, theme: Theme, parent: Optional[QWidget] = None):
        super().__init__(tr("Parola Üreteci"), theme, parent)
        self.generated = ""

        self.body.addWidget(label(tr("Güvenli Parola Üreteci"), "Title"))
        self.body.addWidget(label(tr("Kriptografik rastgelelik ile tahmin edilmesi imkansız parolalar oluşturur."), "Muted"))

        res_box = QFrame()
        res_box.setObjectName("Card")
        res_layout = QHBoxLayout(res_box)
        res_layout.setContentsMargins(14, 12, 14, 12)
        res_layout.setSpacing(8)

        self.result_edit = QLineEdit()
        self.result_edit.setReadOnly(True)
        self.result_edit.setStyleSheet("font-family: monospace; font-size: 15px; font-weight: bold;")
        res_layout.addWidget(self.result_edit, 1)

        copy_btn = button(tr("Kopyala"), on_click=self._copy, icon_=theme.icon("copy"))
        res_layout.addWidget(copy_btn)
        regen_btn = button(tr("Yenile"), on_click=self._generate, icon_=theme.icon("refresh"))
        res_layout.addWidget(regen_btn)
        self.body.addWidget(res_box)

        self.strength_lbl = label(name="Meta")
        self.body.addWidget(self.strength_lbl)

        box = QFrame()
        box.setObjectName("Card")
        layout = QVBoxLayout(box)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(10)

        len_row = QHBoxLayout()
        len_row.addWidget(label(tr("Uzunluk:"), "Eyebrow"))
        self.len_slider = QSlider(Qt.Orientation.Horizontal)
        self.len_slider.setRange(8, 64)
        self.len_slider.setValue(18)
        self.len_spin = QSpinBox()
        self.len_spin.setRange(8, 64)
        self.len_spin.setValue(18)
        self.len_slider.valueChanged.connect(self.len_spin.setValue)
        self.len_spin.valueChanged.connect(self.len_slider.setValue)
        self.len_slider.valueChanged.connect(lambda _v: self._generate())
        len_row.addWidget(self.len_slider, 1)
        len_row.addWidget(self.len_spin)
        layout.addLayout(len_row)

        self.upper_chk = QCheckBox(tr("Büyük Harfler (A-Z)"))
        self.upper_chk.setChecked(True)
        self.upper_chk.toggled.connect(lambda _v: self._generate())
        layout.addWidget(self.upper_chk)

        self.lower_chk = QCheckBox(tr("Küçük Harfler (a-z)"))
        self.lower_chk.setChecked(True)
        self.lower_chk.toggled.connect(lambda _v: self._generate())
        layout.addWidget(self.lower_chk)

        self.num_chk = QCheckBox(tr("Rakamlar (0-9)"))
        self.num_chk.setChecked(True)
        self.num_chk.toggled.connect(lambda _v: self._generate())
        layout.addWidget(self.num_chk)

        self.sym_chk = QCheckBox(tr("Özel Semboller (!@#$%^&*)"))
        self.sym_chk.setChecked(True)
        self.sym_chk.toggled.connect(lambda _v: self._generate())
        layout.addWidget(self.sym_chk)

        self.ambig_chk = QCheckBox(tr("Benzer karakterleri hariç tut (l, 1, I, 0, O)"))
        self.ambig_chk.setChecked(True)
        self.ambig_chk.toggled.connect(lambda _v: self._generate())
        layout.addWidget(self.ambig_chk)

        layout.addWidget(horizontal_rule())

        self.passphrase_chk = QCheckBox(tr("Parola Öbeği Modu"))
        self.passphrase_chk.toggled.connect(self._on_passphrase_toggled)
        layout.addWidget(self.passphrase_chk)
        layout.addWidget(label(tr("Kelimelerden oluşan akılda kalıcı parola"), "Muted"))

        self.body.addWidget(box)
        self.body.addStretch(1)

        self.footer.addWidget(button(tr("Kapat"), on_click=self.reject))
        use_btn = button(tr("Bu Parolayı Kullan"), "Primary", self._use)
        self.footer.addWidget(use_btn)

        self._generate()
        self.fit_to_screen(540, 520)

    def _on_passphrase_toggled(self, on: bool) -> None:
        self.len_slider.setEnabled(not on)
        self.len_spin.setEnabled(not on)
        self.ambig_chk.setEnabled(not on)
        self._generate()

    def _generate(self) -> None:
        is_phrase = self.passphrase_chk.isChecked()
        self.generated = generate_password(
            length=self.len_slider.value(),
            uppercase=self.upper_chk.isChecked(),
            lowercase=self.lower_chk.isChecked(),
            numbers=self.num_chk.isChecked(),
            symbols=self.sym_chk.isChecked(),
            avoid_ambiguous=self.ambig_chk.isChecked(),
            passphrase_mode=is_phrase,
            word_count=4
        )
        self.result_edit.setText(self.generated)
        score, lbl = evaluate_password(self.generated)
        self.strength_lbl.setText(tr("Parola Güvenliği: {} ({}/4)").format(lbl, score))

    def _copy(self) -> None:
        if self.generated:
            copy_secret(self.generated)

    def _use(self) -> None:
        self.accept()

class ImportExportDialog(DialogBase):
    """Tarayıcılardan ve Bitwarden'dan içe aktarma ve şifreli dışa aktarma."""

    def __init__(self, theme: Theme, store: PasswordStore, parent: Optional[QWidget] = None):
        super().__init__(tr("Parolaları İçe / Dışa Aktar"), theme, parent)
        self.store = store
        self.imported_count = 0

        tabs = QTabWidget()
        tabs.addTab(self._build_import_tab(), theme.icon("export"), tr("İçe Aktar (Import)"))
        tabs.addTab(self._build_export_tab(), theme.icon("open"), tr("Dışa Aktar (Export)"))
        self.body.addWidget(tabs, 1)

        self.footer.addWidget(button(tr("Kapat"), "Primary", self.accept))
        self.fit_to_screen(620, 500)

    def _build_import_tab(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)
        l.setContentsMargins(14, 14, 14, 14)
        l.setSpacing(10)

        l.addWidget(label(tr("Başka bir programdan şifre aktarın"), "Section"))
        l.addWidget(label(
            tr("Google Chrome, Mozilla Firefox, Bitwarden, 1Password veya KeePass'ten dışa aktardığınız "
               "CSV veya JSON dosyasını seçin."),
            "Muted"
        ))

        box = QFrame()
        box.setObjectName("Card")
        b_l = QVBoxLayout(box)
        b_l.setSpacing(8)

        row = QHBoxLayout()
        self.import_path = QLineEdit()
        self.import_path.setPlaceholderText(tr("Aktarılacak CSV veya JSON dosyası"))
        browse = button(tr("Gözat"), on_click=self._browse_import)
        row.addWidget(self.import_path, 1)
        row.addWidget(browse)
        b_l.addLayout(row)

        self.import_status = label(name="Success")
        self.import_status.hide()
        b_l.addWidget(self.import_status)

        self.import_btn = button(tr("Şifreleri İçe Aktar"), "Primary", self._run_import)
        self.import_btn.setEnabled(False)
        b_l.addWidget(self.import_btn)

        l.addWidget(box)
        l.addStretch(1)
        return w

    def _browse_import(self) -> None:
        p, _ = QFileDialog.getOpenFileName(
            self, tr("Şifre Dosyasını Seçin"), "",
            tr("Desteklenen Dosyalar (*.csv *.json *.pvault-pwd);;Tüm Dosyalar (*)")
        )
        if p:
            self.import_path.setText(p)
            self.import_btn.setEnabled(True)

    def _run_import(self) -> None:
        p = Path(self.import_path.text().strip())
        if not p.is_file():
            return
        content = p.read_text(encoding="utf-8", errors="replace")
        new_items: List[PasswordEntry] = []

        if p.suffix.lower() == ".json":
            new_items = detect_and_import_json(content)
        elif p.suffix.lower() in (".csv", ".txt"):
            new_items = detect_and_import_csv(content)

        count = 0
        for item in new_items:
            self.store.add(item)
            count += 1

        self.imported_count += count
        self.import_status.setText(tr("Başarıyla {} kayıt kasaya aktarıldı!").format(count))
        self.import_status.show()

    def _build_export_tab(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)
        l.setContentsMargins(14, 14, 14, 14)
        l.setSpacing(10)

        l.addWidget(label(tr("Kasayı Dışa Aktar"), "Section"))
        l.addWidget(label(
            tr("Şifrelerinizi başka bir cihaza taşımak veya yedeklemek için dışa aktarabilirsiniz."),
            "Muted"
        ))

        box = QFrame()
        box.setObjectName("Card")
        b_l = QVBoxLayout(box)
        b_l.setSpacing(10)

        self.exp_encrypted = QRadioButton(tr("Şifreli Yedek (.pvault-pwd)"))
        self.exp_encrypted.setChecked(True)
        self.exp_csv = QRadioButton(tr("Düz Metin CSV (.csv)"))
        b_l.addWidget(self.exp_encrypted)
        b_l.addWidget(label(tr("Güvenli, parola korumalı"), "Muted"))
        b_l.addWidget(self.exp_csv)
        b_l.addWidget(label(tr("Dikkat: Parolalar açık metin olarak yazılır!"), "Muted"))

        b_l.addWidget(label(tr("Yedek Parolası (Şifreli yedek için)"), "Eyebrow"))
        self.backup_pass = PasswordField(self.theme, tr("Yedek parolasını belirleyin"))
        b_l.addWidget(self.backup_pass)

        exp_action_btn = button(tr("Dışa Aktar..."), "Primary", self._run_export)
        b_l.addWidget(exp_action_btn)

        l.addWidget(box)
        l.addStretch(1)
        return w

    def _run_export(self) -> None:
        items = self.store.list_items()
        if not items:
            QMessageBox.information(self, tr("Bilgi"), tr("Kasada dışa aktarılacak aktif şifre kaydı yok."))
            return

        if self.exp_csv.isChecked():
            if not confirm(
                self, tr("Güvenlik Uyarısı"),
                tr("Parolalarınız şifresiz, açık CSV dosyası olarak kaydedilecek. Bu dosya ele geçirilirse "
                   "tüm hesaplarınız tehlikeye girer.\n\nDevam etmek istiyor musunuz?"),
                tr("Şifresiz Kaydet"),
                danger=True
            ):
                return
            path, _ = QFileDialog.getSaveFileName(self, tr("CSV Olarak Kaydet"), "passwords.csv", tr("CSV (*.csv)"))
            if path:
                csv_data = export_to_csv(items)
                Path(path).write_text(csv_data, encoding="utf-8")
                QMessageBox.information(self, tr("Tamamlandı"), tr("{} kayıt CSV dosyasına aktarıldı.").format(len(items)))
        else:
            pw = self.backup_pass.text()
            if not pw or len(pw) < 8:
                QMessageBox.warning(self, tr("Hata"), tr("Yedek parolası en az 8 karakter olmalıdır."))
                return
            path, _ = QFileDialog.getSaveFileName(self, tr("Şifreli Yedek Olarak Kaydet"), "vault_backup.pvault-pwd", tr("Vault Backup (*.pvault-pwd)"))
            if path:
                enc_data = export_encrypted_backup(items, pw)
                Path(path).write_bytes(enc_data)
                QMessageBox.information(self, tr("Tamamlandı"), tr("{} kayıt güvenli şifreli yedek olarak kaydedildi.").format(len(items)))

class HealthAuditDialog(DialogBase):
    """Zayıf ve tekrar eden parolaları listeler."""

    def __init__(self, theme: Theme, store: PasswordStore, on_edit: Optional[Callable[[PasswordEntry], None]] = None, parent: Optional[QWidget] = None):
        super().__init__(tr("Güvenlik Sağlık Raporu"), theme, parent)
        self.store = store
        self.on_edit = on_edit
        audit = store.audit()

        self.body.addWidget(label(tr("Güvenlik Sağlık Raporu"), "Title"))
        self.body.addWidget(label(
            tr("Zayıf ve tekrar eden parolalar hesaplarınız için en büyük siber güvenlik açığıdır. "
               "Aşağıdaki kayıtları güncelleyerek kasanızı güçlendirin."),
            "Muted"
        ))

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setSpacing(12)

        layout.addWidget(label(tr("Zayıf Parolalar ({})").format(len(audit["weak"])), "Section"))
        if audit["weak"]:
            for e in audit["weak"]:
                layout.addWidget(self._entry_card(e, tr("Zayıf parola (< 12 karakter veya basit)"), "#C5221F"))
        else:
            layout.addWidget(label(tr("Tebrikler! Kasada zayıf parola bulunmuyor."), "Success"))

        layout.addWidget(horizontal_rule())

        layout.addWidget(label(tr("Tekrar Eden Parolalar ({})").format(len(audit["reused"])), "Section"))
        if audit["reused"]:
            for e in audit["reused"]:
                layout.addWidget(self._entry_card(e, tr("Aynı parola başka bir hesapta da kullanılıyor!"), "#D93025"))
        else:
            layout.addWidget(label(tr("Mükemmel! Hiçbir parolanız başka bir hesapla ortak değil."), "Success"))

        scroll.setWidget(content)
        self.body.addWidget(scroll, 1)

        self.footer.addWidget(button(tr("Kapat"), "Primary", self.accept))
        self.fit_to_screen(640, 600)

    def _entry_card(self, entry: PasswordEntry, warn_text: str, color: str) -> QWidget:
        card = QFrame()
        card.setObjectName("Card")
        c_l = QHBoxLayout(card)
        c_l.setContentsMargins(12, 10, 12, 10)
        c_l.setSpacing(8)

        v = QVBoxLayout()
        v.addWidget(label(entry.title, "Section"))
        v.addWidget(label(f"{entry.username} • {warn_text}", "Meta"))
        c_l.addLayout(v, 1)

        edit_btn = button(tr("Düzelt"), on_click=lambda e=entry: self._jump_edit(e))
        c_l.addWidget(edit_btn)
        return card

    def _jump_edit(self, entry: PasswordEntry) -> None:
        self.accept()
        self.on_edit(entry)

