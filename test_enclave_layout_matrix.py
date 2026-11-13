"""
Enclave - Yerleşim matris testleri: tüm tasarım stilleri, renkler, açık/koyu mod, diller ve pencere boyutları.
Çalıştırma: python -m unittest test_enclave_layout_matrix -v
"""

import os
import shutil
import tempfile
import unittest

from test_enclave_layout import app, find_problems  # noqa: E402  (ortam ayarlarını da yapar)

import enclave_app.i18n as i18n
from enclave_core import CustomVaultEngine as E
from enclave_app import designs
from enclave_app.common import Theme
from enclave_app.dialogs import CreateVaultDialog, SettingsDialog
from enclave_app.extras import ShaDialog, StripCarrierDialog, WrapCarrierDialog
from enclave_app.pwd_dialogs import (
    EntryEditorDialog, HealthAuditDialog, ImportExportDialog, PasswordGeneratorDialog,
)
from enclave_app.pwd_engine import PasswordEntry, PasswordStore
from enclave_app.session import VaultSession
from enclave_app.window import VaultWindow
from enclave_app.workspace import Workspace

# Tam matris (tüm stiller x 4 renk/mod) çok yavaş: ENCLAVE_FULL_MATRIX=1 ile açılır. Varsayılan hızlı kümedir.
FULL = os.environ.get("ENCLAVE_FULL_MATRIX") == "1"
COMBOS = (("mor", True), ("mor", False), ("turuncu", True), ("turkuaz", False)) if FULL else (("mor", True),)
STYLE_KEYS = tuple(designs.STYLES) if FULL else ("kart",)


class MatrixLayoutTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="pvault_layout2_")
        path = os.path.join(cls.tmp, "matrix.pvault")
        E.create_vault(path, "LayoutPassword123!")
        plan = []
        names = [
            "Çok_uzun_bir_dosya_adı_Müşteri_Sözleşmeleri_2026_Final_Sürüm_v12_İmzalı.docx",
            "report.pdf", "photo.png", "song.mp3", "clip.mp4", "dump.sql", "k.txt",
        ]
        for name in names:
            src = os.path.join(cls.tmp, name)
            with open(src, "wb") as handle:
                handle.write(b"x" * 3000)
            plan.append((src, name))
        cls.session = VaultSession(path)
        cls.session.unlock("LayoutPassword123!")
        cls.session.import_files(plan)
        cls.session.create_folder("", "Belgeler ve Sözleşmeler Arşivi")
        cls.store = PasswordStore(cls.session)
        for index in range(8):
            cls.store.add(PasswordEntry(
                title=f"Kayıt {index} " + "uzun başlık " * 4, type=("login", "card", "note", "key")[index % 4],
                username="kullanici@ornek-alan-adi.example.com", password="Aa1!aA1!aA1!aA1!x",
                url="https://example.com/yol", totp_secret="JBSWY3DPEHPK3PXP" if index % 2 else "",
                favorite=index % 3 == 0, tags=["a", "b"], notes="not " * 30,
            ))

    @classmethod
    def tearDownClass(cls):
        cls.session.close()
        shutil.rmtree(cls.tmp, ignore_errors=True)
        i18n.set_language("tr")
        app.setStyleSheet("")

    @staticmethod
    def _themed(design, style, dark):
        theme = Theme(designs.get_design(design, style), dark)
        app.setStyleSheet(designs.build_stylesheet(theme.design, theme.dark))
        return theme

    def _run(self, make, sizes, langs=("tr", "en")):
        failures = []
        for style in STYLE_KEYS:
            for design, dark in COMBOS:
                theme = self._themed(design, style, dark)
                for lang in langs:
                    i18n.set_language(lang)
                    widget = make(theme)
                    try:
                        for size in sizes:
                            widget.resize(*size)
                            widget.show()
                            app.processEvents()
                            for problem in find_problems(widget):
                                failures.append(f"[{style}/{design}/{'koyu' if dark else 'açık'}/{lang}/{size}] {problem}")
                    finally:
                        widget.close()
                        widget.deleteLater()
        unique = sorted({f.split("] ", 1)[1] for f in failures})
        self.assertEqual(
            failures, [],
            f"{len(failures)} sorun, {len(unique)} farklı:\n" + "\n".join(unique[:40]) + "\n\nİlk örnekler:\n" + "\n".join(failures[:15]),
        )

    def test_workspace_files_all_styles(self):
        self._run(lambda theme: Workspace(self.session, theme), [(760, 540), (1160, 740)])

    def test_workspace_selected_file(self):
        def make(theme):
            ws = Workspace(self.session, theme)
            ws.details.show_file(self.session.files[0])
            return ws
        self._run(make, [(900, 600), (1160, 740)])

    def test_workspace_many_selected(self):
        def make(theme):
            ws = Workspace(self.session, theme)
            ws.details.show_many(5, 123456)
            return ws
        self._run(make, [(900, 600)])

    def test_workspace_folder_selected(self):
        def make(theme):
            ws = Workspace(self.session, theme)
            ws.details.show_folder("Belgeler ve Sözleşmeler Arşivi", 3, 4096)
            return ws
        self._run(make, [(900, 600)])

    def test_workspace_passwords_all_styles(self):
        def make(theme):
            ws = Workspace(self.session, theme)
            ws.set_mode("passwords")
            ws.pwd_view.refresh()
            return ws
        self._run(make, [(900, 600), (1160, 740)])

    def test_password_filters_and_trash(self):
        theme = self._themed("mor", "kart", True)
        failures = []
        for lang in ("tr", "en"):
            i18n.set_language(lang)
            ws = Workspace(self.session, theme)
            ws.set_mode("passwords")
            view = ws.pwd_view
            self.store.delete(self.store.all()[0].id)
            view.refresh()
            actions = (
                lambda: view._select_filter("trash"), lambda: view._select_filter("totp"),
                lambda: view._select_filter("favorites"), lambda: view._select_category("card"),
                lambda: view._select_category("note"), lambda: view._select_category(None),
            )
            for action in actions:
                action()
                for size in ((900, 600), (1160, 740)):
                    ws.resize(*size)
                    ws.show()
                    app.processEvents()
                    failures += [f"[{lang}/{size}] {p}" for p in find_problems(ws)]
            ws.close()
        self.assertEqual(failures, [], "\n".join(failures[:30]))

    def test_unlock_all_styles(self):
        self._run(lambda theme: VaultWindow(""), [(560, 520), (800, 600), (1160, 740), (1600, 900)])

    def test_unlock_code_step_and_error(self):
        self._themed("mor", "kart", True)
        failures = []
        for lang in ("tr", "en"):
            i18n.set_language(lang)
            win = VaultWindow("")
            for size in ((560, 520), (800, 600), (1160, 740)):
                win.resize(*size)
                win.show()
                page = win.unlock_page
                page._show_error("Parola yanlış. " * 6)
                app.processEvents()
                failures += [f"[{lang}/{size}/hata] {p}" for p in find_problems(win)]
                page._show_code_step()
                app.processEvents()
                failures += [f"[{lang}/{size}/kod] {p}" for p in find_problems(win)]
                page.form_stack.setCurrentIndex(0)
            win.close()
        self.assertEqual(failures, [], "\n".join(failures[:30]))

    def test_dialogs_resized_small(self):
        theme = self._themed("mor", "kart", True)
        factories = [
            lambda: SettingsDialog(theme, self.session), lambda: CreateVaultDialog(theme),
            lambda: PasswordGeneratorDialog(theme), lambda: HealthAuditDialog(theme, self.store),
            lambda: ImportExportDialog(theme, self.store), lambda: EntryEditorDialog(theme, self.store),
            lambda: WrapCarrierDialog(theme), lambda: StripCarrierDialog(theme), lambda: ShaDialog(theme, True),
        ]
        failures = []
        for lang in ("tr", "en"):
            i18n.set_language(lang)
            for factory in factories:
                dialog = factory()
                for size in ((520, 400), (640, 480), (900, 700)):
                    dialog.resize(*size)
                    dialog.show()
                    app.processEvents()
                    failures += [f"[{lang}/{type(dialog).__name__}/{size}] {p}" for p in find_problems(dialog)]
                dialog.close()
        self.assertEqual(failures, [], "\n".join(failures[:40]))


if __name__ == "__main__":
    unittest.main()
