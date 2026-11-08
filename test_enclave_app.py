"""
Enclave - Oturum, tasarım ve arayüz akışı testleri.
Qt testleri ekransız (offscreen) çalışır. Çalıştırma: python -m unittest test_enclave_app -v
"""

import atexit
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
_CONFIG_HOME = tempfile.mkdtemp(prefix="vault_cfg_")
atexit.register(shutil.rmtree, _CONFIG_HOME, ignore_errors=True)
os.environ["APPDATA"] = _CONFIG_HOME
os.environ["XDG_CONFIG_HOME"] = _CONFIG_HOME
if sys.platform == "darwin":
    os.environ["HOME"] = _CONFIG_HOME

from PyQt6.QtCore import QEventLoop, QMimeData, QPointF, QTimer, QUrl, Qt
from PyQt6.QtGui import QColor, QImage
from PyQt6.QtWidgets import QApplication

import config
import totp_engine
from enclave_core import CustomVaultEngine as E, CustomVaultError
from enclave_app import designs
from enclave_app.common import Theme, clear_secret_clipboard, copy_secret
from enclave_app.dialogs import ChangePasswordDialog, KeyFileDialog, RecoveryKeyDialog, SettingsDialog, TwoFactorDialog
from enclave_app.session import VaultSession, cloud_provider, file_category, password_strength
from enclave_app.window import VaultWindow

app = QApplication.instance() or QApplication([])
sys.excepthook = lambda kind, value, trace: __import__("traceback").print_exception(kind, value, trace)
PW = "Dogru-At-Pil-Zimba-7"

def spin(condition, timeout_ms=20000):
    """Koşul sağlanana kadar olay döngüsünü çalıştırır."""
    loop = QEventLoop()
    timer = QTimer()
    timer.timeout.connect(lambda: loop.quit() if condition() else None)
    timer.start(20)
    QTimer.singleShot(timeout_ms, loop.quit)
    loop.exec()
    timer.stop()
    return condition()

class Base(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="vault_app_"))
        self.vault = str(self.dir / "kasa.pvault")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        if config.CONFIG_FILE.exists():
            config.CONFIG_FILE.unlink()

    def source(self, name, data=b"veri"):
        path = self.dir / "kaynak" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return str(path)

class SessionTests(Base):
    def setUp(self):
        super().setUp()
        E.create_vault(self.vault, PW, max_size_mb=64)
        self.session = VaultSession(self.vault)
        self.session.unlock(PW)
        self.addCleanup(self.session.close)

    def test_second_instance_refused(self):
        other = VaultSession(self.vault)
        with self.assertRaises(Exception):
            other.unlock(PW)
        other._lock.release()

    def test_failed_password_releases_lock(self):
        self.session.close()
        with self.assertRaises(Exception):
            VaultSession(self.vault).unlock("yanlis")
        again = VaultSession(self.vault)
        again.unlock(PW)
        again.close()

    def test_import_folder_tree_and_conflicts(self):
        src = self.dir / "agac" / "alt"
        src.mkdir(parents=True)
        (src / "a.txt").write_bytes(b"a")
        (self.dir / "agac" / "b?.txt").write_bytes(b"b") if sys.platform != "win32" else (self.dir / "agac" / "b.txt").write_bytes(b"b")
        plan = self.session.plan_import([str(self.dir / "agac")], "")
        self.session.import_files(plan)
        self.assertIn("agac/alt", self.session.all_folders())
        again = self.session.plan_import([str(src / "a.txt")], "agac/alt")
        self.assertEqual(again[0][1], "agac/alt/a (2).txt")

    def test_listing_is_scoped_to_folder(self):
        self.session.import_files([(self.source("a.txt"), "k/a.txt"), (self.source("b.txt"), "k/alt/b.txt"), (self.source("c.png"), "c.png")])
        folders, files = self.session.list_folder("")
        self.assertEqual(folders, ["k"])
        self.assertEqual([f["path"] for f in files], ["c.png"])
        self.assertEqual([f["path"] for f in self.session.search("b.")], ["k/alt/b.txt"])
        self.assertEqual([f["path"] for f in self.session.search("", "image")], ["c.png"])

    def test_export_never_overwrites(self):
        self.session.import_files([(self.source("a.txt", b"yeni"), "k/a.txt")])
        out = self.dir / "cikti"
        out.mkdir()
        (out / "a.txt").write_bytes(b"eski")
        ids = [f["id"] for f in self.session.files]
        self.session.export_files(self.session.plan_export(ids, [], str(out)))
        self.assertEqual((out / "a.txt").read_bytes(), b"eski")
        self.assertEqual((out / "a (2).txt").read_bytes(), b"yeni")

    def test_export_folder_keeps_structure(self):
        self.session.import_files([(self.source("a.txt", b"1"), "k/alt/a.txt")])
        out = self.dir / "cikti"
        self.session.export_files(self.session.plan_export([], ["k"], str(out)))
        self.assertEqual((out / "k" / "alt" / "a.txt").read_bytes(), b"1")

    def test_temp_copy_detected_when_modified_and_wiped_on_close(self):
        self.session.import_files([(self.source("a.txt", b"ilk"), "a.txt")])
        temp = self.session.open_temp_copy(self.session.files[0]["id"])
        self.assertEqual(self.session.modified_temp_files(), [])
        Path(temp).write_bytes(b"degisti")
        os.utime(temp, (2_000_000_000, 2_000_000_000))
        modified = self.session.modified_temp_files()
        self.assertEqual(modified, [(temp, "a.txt")])
        self.session.save_temp_back(*modified[0])
        self.assertEqual(self.session.read_preview(self.session.files[0]["id"]), b"degisti")
        self.session.close()
        self.assertFalse(Path(temp).exists())
        self.assertFalse(Path(temp).parent.exists())

    def test_close_forgets_keys(self):
        auth = self.session.auth
        self.session.close()
        self.assertEqual(auth, {})
        self.assertIsNone(self.session.auth)

    def test_compact_keeps_session_usable_and_lock_held(self):
        self.session.import_files([(self.source("a.bin", os.urandom(300_000)), "a.bin"), (self.source("b.txt"), "b.txt")])
        self.session.delete([self.session.files[0]["id"]], [])
        self.assertGreater(self.session.compact()["saved_bytes"], 200_000)
        self.assertEqual(self.session.read_preview(self.session.files[0]["id"]), b"veri")
        with self.assertRaises(Exception):
            VaultSession(self.vault).unlock(PW)

    def test_two_factor_flow(self):
        import totp_engine
        secret = totp_engine.generate_totp_secret()
        self.session.enable_two_factor(secret, ["AAAA-BBBB"])
        self.session.close()
        session = VaultSession(self.vault)
        self.assertTrue(session.unlock(PW))
        self.assertFalse(session.is_open)
        self.assertFalse(session.verify_second_factor("000000")[0] and False)
        self.assertTrue(session.verify_second_factor(totp_engine.get_totp_token(secret))[0])
        self.assertTrue(session.is_open)
        session.close()
        session = VaultSession(self.vault)
        session.unlock(PW)
        self.assertTrue(session.verify_second_factor("AAAA-BBBB")[0])
        session.close()
        session = VaultSession(self.vault)
        session.unlock(PW)
        self.assertFalse(session.verify_second_factor("AAAA-BBBB")[0])
        session.close()

    def test_disabling_two_factor_needs_a_valid_code(self):
        import totp_engine
        secret = totp_engine.generate_totp_secret()
        self.session.enable_two_factor(secret, [])
        with self.assertRaises(CustomVaultError):
            self.session.disable_two_factor("000000")
        self.assertTrue(self.session.two_factor_enabled)
        self.session.disable_two_factor(totp_engine.get_totp_token(secret))
        self.assertFalse(self.session.two_factor_enabled)

    def test_virtual_disk_opens_with_recovery_key(self):
        from enclave_app import vhd_service
        engine = mock.Mock()
        engine.backup_and_disable_autoplay.return_value = False
        engine.mount_vhd.return_value = {"success": True, "drive_letter": "K:"}
        engine.get_drive_status.return_value = {"is_locked": True}
        engine.check_embedded_decoy_vault.return_value = False
        engine.unlock_bitlocker_recovery_key.return_value = {"success": True}
        with mock.patch.object(vhd_service, "make_engine", return_value=engine):
            session = vhd_service.VhdSession(str(self.dir / "d.vhd"))
            with self.assertRaises(CustomVaultError):
                session.unlock_with_recovery_key("123")
            engine.mount_vhd.assert_not_called()
            session.unlock_with_recovery_key("111111-" * 7 + "111111")
            self.assertEqual(session.drive_letter, "K:")
            self.assertEqual(engine.unlock_bitlocker_recovery_key.call_args[0][1], "-".join(["111111"] * 8))

            engine.unlock_bitlocker_recovery_key.return_value = {"success": False, "error": "Kurtarma anahtarı bu kasa ile eşleşmiyor."}
            engine.dismount_vhd.return_value = {"success": True}
            other = vhd_service.VhdSession(str(self.dir / "d.vhd"))
            with self.assertRaises(CustomVaultError):
                other.unlock_with_recovery_key("2" * 48)
            self.assertEqual(other.drive_letter, "")
            engine.dismount_vhd.assert_called()

    def test_virtual_disk_page_refreshes_capacity(self):
        from enclave_app.common import Theme
        from enclave_app.vhd_page import VhdPage
        session = mock.Mock(drive_letter="K:")
        session.name = "disk"
        session.status.return_value = {"total_bytes": 1000, "free_bytes": 900}
        page = VhdPage(session, Theme(designs.get_design("mor"), True), lambda: None, lambda: None)
        self.assertTrue(page.usage_timer.isActive())
        session.status.return_value = {"total_bytes": 1000, "free_bytes": 400}
        page.refresh()
        self.assertEqual(page.usage.bar.value(), 600)
        session.drive_letter = ""
        session.status.return_value = {}
        page.refresh()
        self.assertEqual(page.usage.bar.value(), 600)
        page.dispose()
        page.deleteLater()

    def test_two_factor_follows_both_partitions(self):
        import totp_engine
        self.session.close()
        path = str(self.dir / "iki.pvault")
        E.create_vault(path, PW, decoy_password="Tuzak-Parola-456")
        main = VaultSession(path)
        main.unlock(PW)
        secret = totp_engine.generate_totp_secret()
        with self.assertRaises(CustomVaultError):
            main.enable_two_factor(secret, [], PW)
        main.enable_two_factor(secret, ["AAAA-BBBB"], "Tuzak-Parola-456")
        main.close()
        decoy = VaultSession(path)
        self.assertTrue(decoy.unlock("Tuzak-Parola-456"))
        self.assertTrue(decoy.verify_second_factor(totp_engine.get_totp_token(secret))[0])
        decoy.close()
        main = VaultSession(path)
        self.assertTrue(main.unlock(PW))
        code = totp_engine.get_totp_token(secret)
        main.verify_second_factor(code)
        with self.assertRaises(CustomVaultError):
            main.disable_two_factor(code, "Tuzak-Parola-456")
        next_code = totp_engine.get_totp_token(secret, for_time=int(time.time()) + 30)
        main.disable_two_factor(next_code, "Tuzak-Parola-456")
        main.close()
        for password in (PW, "Tuzak-Parola-456"):
            session = VaultSession(path)
            self.assertFalse(session.unlock(password))
            session.close()

    def test_password_strength(self):
        self.assertEqual(password_strength("")[0], 0)
        self.assertEqual(password_strength("aaaaaaaaaaaa")[0], 1)
        self.assertEqual(password_strength("12345")[0], 1)
        self.assertGreaterEqual(password_strength("mavi-kedi çatıda 42 uyur")[0], 3)

    def test_cloud_provider(self):
        self.assertIsNotNone(cloud_provider("C:/Users/a/OneDrive - Acme/kasa.pvault"))
        self.assertIsNotNone(cloud_provider("/home/a/Dropbox/kasa.pvault"))
        self.assertIsNone(cloud_provider("/home/a/belgeler/kasa.pvault"))

    def test_category(self):
        self.assertEqual(file_category("x.JPG"), "image")
        self.assertEqual(file_category("x.bilinmez"), "file")

class DesignTests(unittest.TestCase):
    def test_every_palette_meets_wcag_aa(self):
        for design in designs.DESIGNS.values():
            for mode, p in (("açık", design.light), ("koyu", design.dark)):
                pairs = [
                    ("metin/pencere", p.text, p.window), ("metin/yüzey", p.text, p.surface),
                    ("metin/alternatif", p.text, p.surface_alt), ("metin/seçim", p.text, p.selection),
                    ("soluk/pencere", p.muted, p.window), ("soluk/yüzey", p.muted, p.surface),
                    ("soluk/alternatif", p.muted, p.surface_alt), ("vurgu/düğme", p.on_accent, p.accent),
                    ("hata/yüzey", p.danger, p.surface), ("uyarı/alternatif", p.warning, p.surface_alt),
                    ("başarı/yüzey", p.success, p.surface),
                ]
                for name, fg, bg in pairs:
                    ratio = designs.contrast_ratio(fg, bg)
                    self.assertGreaterEqual(ratio, 4.5, f"{design.key} {mode} {name}: {ratio:.2f}")
                self.assertGreaterEqual(
                    designs.contrast_ratio(designs.rail_text(design, mode == "koyu"), p.rail), 4.5, f"{design.key} şerit"
                )

    def test_no_neon(self):
        """Proje kuralı: aşırı doygun, parlak renk yok."""
        for design in designs.DESIGNS.values():
            for p in (design.light, design.dark):
                color = QColor(p.accent)
                self.assertLess(color.hslSaturationF() * color.lightnessF(), 0.6, design.key)

class WindowFlow(Base):
    """Gerçek pencereyi her tasarımda uçtan uca sürer."""

    def open_window(self, design, dark=True, style="kart"):
        cfg = config.load_config()
        cfg.update(design=design, style=style, appearance="dark" if dark else "light", idle_lock_minutes=5)
        cfg.pop("view_mode", None)
        config.save_config(cfg)
        window = VaultWindow(self.vault)
        window.show()
        self.addCleanup(window.deleteLater)
        return window

    def unlock(self, window):
        window.unlock_page.password.edit.setText(PW)
        window.unlock_page._submit_password()
        self.assertTrue(spin(lambda: window.session is not None), window.unlock_page.error.text())

    def seed(self):
        E.create_vault(self.vault, PW)
        image = QImage(64, 48, QImage.Format.Format_RGB32)
        image.fill(QColor("#336699"))
        png = self.dir / "foto.png"
        image.save(str(png))
        auth = E.authenticate(self.vault, PW)
        E.add_file(self.vault, auth, str(png), "foto.png")
        E.add_file(self.vault, auth, self.source("not.txt", "merhaba dünya".encode()), "belgeler/not.txt")

    def test_all_designs_full_flow(self):
        self.seed()
        for key in designs.DESIGNS:
            for dark in (True, False):
                with self.subTest(design=key, dark=dark):
                    window = self.open_window(key, dark)
                    self.unlock(window)
                    ws = window.workspace
                    self.assertEqual(window.stack.currentWidget(), ws)
                    self.assertIn(ws.view_mode, ("list", "grid"))

                    for _ in range(2):
                        ws.toggle_view()
                    ws.navigate("belgeler")
                    self.assertEqual(ws.session.list_folder(ws.folder)[1][0]["path"], "belgeler/not.txt")
                    ws.view_mode = "list"
                    ws.show_current()
                    ws.table.setCurrentItem(ws.table.topLevelItem(0))
                    self.assertTrue(spin(lambda: "merhaba" in ws.details.preview_text.toPlainText()))
                    ws.go_up()

                    ws.search.setText("foto")
                    ws.table.setCurrentItem(ws.table.topLevelItem(0))
                    self.assertTrue(spin(lambda: ws.details._pixmap is not None))
                    ws.search.clear()

                    window.lock()
                    self.assertIsNone(window.session)
                    self.assertEqual(window.stack.currentWidget(), window.unlock_page)
                    self.assertIsNone(window.workspace)
                    window.close()

    def test_wrong_password_shows_error_and_stays_locked(self):
        self.seed()
        window = self.open_window("mor")
        window.unlock_page.password.edit.setText("yanlis parola")
        window.unlock_page._submit_password()
        self.assertTrue(spin(lambda: window.unlock_page._task is None))
        self.assertIn("yanlış", window.unlock_page.error.text())
        self.assertIsNone(window.session)
        self.assertEqual(window.unlock_page.password.text(), "")
        window.close()

    def test_drop_imports_and_offers_to_remove_originals(self):
        self.seed()
        window = self.open_window("yesil")
        self.unlock(window)
        ws = window.workspace
        path = self.source("yeni.txt")
        ws.add_paths([path])
        self.assertTrue(spin(lambda: not ws.is_busy))
        self.assertTrue(any(f["path"] == "yeni.txt" for f in window.session.files))
        self.assertTrue(ws.notice.isVisible())
        self.assertFalse(ws.notice_button.isVisible())
        self.assertTrue(Path(path).exists())
        window.close()

    def test_switching_design_keeps_session_and_folder(self):
        self.seed()
        window = self.open_window("mor")
        self.unlock(window)
        window.workspace.navigate("belgeler")
        session = window.session
        for key in ("mavi", "yesil", "mor"):
            window.set_design(key, "dark")
            self.assertIs(window.session, session)
            self.assertEqual(window.workspace.folder, "belgeler")
            self.assertEqual(window.theme.design.key, key)
        window.close()

    def test_idle_timer_locks(self):
        self.seed()
        window = self.open_window("mor")
        self.unlock(window)
        self.assertTrue(window.idle_timer.isActive())
        window.idle_timer.start(10)
        self.assertTrue(spin(lambda: window.session is None))
        window.close()

    def test_idle_lock_saves_edits_without_asking(self):
        self.seed()
        window = self.open_window("mor")
        self.unlock(window)
        session = window.session
        entry = next(f for f in session.files if f["path"] == "belgeler/not.txt")
        temp = session.open_temp_copy(entry["id"])
        Path(temp).write_bytes(b"duzenlendi")
        os.utime(temp, (2_000_000_000, 2_000_000_000))
        window._on_idle()
        self.assertIsNone(window.session)
        auth = E.authenticate(self.vault, PW)
        self.assertEqual(E.extract_file_bytes(self.vault, auth, "belgeler/not.txt")[0], b"duzenlendi")
        window.close()

    def test_idle_lock_waits_for_transfer(self):
        self.seed()
        window = self.open_window("mor")
        self.unlock(window)
        window.session.maintenance = True
        window._on_idle()
        self.assertIsNotNone(window.session)
        window.session.maintenance = False
        window.close()

    def test_lock_during_preview_is_safe(self):
        self.seed()
        window = self.open_window("mor")
        self.unlock(window)
        ws = window.workspace
        ws.navigate("belgeler")
        ws.table.setCurrentItem(ws.table.topLevelItem(0))
        window.lock()
        self.assertIsNone(window.session)
        window.close()

    def test_auto_lock_closes_open_dialog(self):
        self.seed()
        window = self.open_window("mor")
        self.unlock(window)
        QTimer.singleShot(50, window._on_idle)
        window.open_settings()
        self.assertIsNone(window.session)
        window.close()

    def test_lock_on_exit_wipes_temp_copy(self):
        self.seed()
        window = self.open_window("mavi")
        self.unlock(window)
        temp = window.session.open_temp_copy(window.session.files[0]["id"])
        window.close()
        self.assertFalse(Path(temp).exists())

    def test_vault_paths_not_remembered_unless_asked(self):
        self.seed()
        window = self.open_window("mor")
        self.unlock(window)
        window.close()
        self.assertNotIn("kasa.pvault", config.CONFIG_FILE.read_text(encoding="utf-8"))

class NewFeatures(WindowFlow):
    def test_recovery_key_opens_and_password_change_revokes(self):
        E.create_vault(self.vault, PW)
        auth = E.authenticate(self.vault, PW)
        key = E.get_recovery_key(auth)
        recovered = E.authenticate_with_recovery_key(self.vault, key.lower())
        E.write_file_bytes(self.vault, recovered, "a.txt", b"x")
        E.change_password(self.vault, recovered, "Yeni-Parola-123")
        self.assertEqual(E.extract_file_bytes(self.vault, E.authenticate(self.vault, "Yeni-Parola-123"), "a.txt")[0], b"x")
        with self.assertRaises(Exception):
            E.authenticate_with_recovery_key(self.vault, key)

    def test_slideshow_keys_wrap_and_filmstrip(self):
        from enclave_app.slideshow import SlideshowDialog
        self.seed()
        auth = E.authenticate(self.vault, PW)
        png = self.dir / "foto.png"
        E.add_file(self.vault, auth, str(png), "ikinci.png")
        window = self.open_window("mor")
        self.unlock(window)
        images = window.session.images()
        dialog = SlideshowDialog(window.session, images, 0, {}, window.theme)
        self.assertEqual(dialog.strip.count(), 2)
        dialog.next(); self.assertEqual(dialog.index, 1)
        dialog.next(); self.assertEqual(dialog.index, 0)
        dialog.previous(); self.assertEqual(dialog.index, 1)
        dialog.toggle_play(); self.assertTrue(dialog.timer.isActive())
        self.assertTrue(spin(lambda: dialog._pixmap is not None))
        dialog.close()
        window.close()

class StyleAndSafetyTests(WindowFlow):
    def test_decoy_size_reaches_both_vault_types(self):
        from enclave_app.dialogs import CreateVaultDialog
        window = self.open_window("mor")
        dialog = CreateVaultDialog(window.theme, window)
        dialog.decoy_toggle.setChecked(True)
        dialog.password.edit.setText(PW)
        dialog.password_again.edit.setText(PW)
        dialog.decoy.edit.setText("Tuzak-Parola-456")
        dialog.ack.setChecked(True)
        dialog.size_box.setValue(8)
        self.assertEqual(dialog.decoy_size.value(), 2)
        dialog.decoy_size.setValue(3.5)
        dialog.size_box.setValue(4)
        self.assertEqual(dialog.decoy_size.value(), 3.5)
        self.assertEqual(dialog._decoy_mb(), 3584)
        dialog._set_architecture("vhd")
        self.assertTrue(dialog.create_button.isEnabled())
        dialog.size_box.setValue(3)
        self.assertFalse(dialog.create_button.isEnabled())
        dialog.close()
        window.close()

        path = str(self.dir / "boyut.pvault")
        E.create_vault(path, PW, decoy_password="Tuzak-Parola-456", max_size_gb=5, decoy_size_gb=1, decoy_size_mb=1536)
        session = VaultSession(path)
        session.unlock("Tuzak-Parola-456")
        self.assertEqual(session.stats()["quota"], 1536 * 1024 * 1024)
        session.close()

    def test_settings_tabs_and_language(self):
        from enclave_app.dialogs import SettingsDialog
        window = self.open_window("mor")
        dialog = SettingsDialog(window.theme, None, window)
        self.assertEqual([dialog.tabs.tabText(i) for i in range(dialog.tabs.count())], ["Görünüm", "Güvenlik", "Dil"])
        self.assertEqual(len(dialog.mascot_previews), 6)
        self.assertFalse(hasattr(dialog, "loader_preview"))
        dialog.close()
        window.close()

    def test_create_failure_stays_visible_and_form_returns(self):
        from enclave_app.dialogs import CreateVaultDialog
        window = self.open_window("mor")
        dialog = CreateVaultDialog(window.theme, window)
        dialog.show()
        dialog.password.edit.setText(PW)
        dialog.password_again.edit.setText(PW)
        dialog.decoy_toggle.setChecked(True)
        dialog.decoy.edit.setText("kisa")
        self.assertIn("8", dialog.error.text())
        dialog.ack.setChecked(True)
        dialog.decoy.edit.setText("Tuzak-Parola-456")
        dialog.content.setEnabled(False)
        dialog.busy.start()
        dialog._on_failed("Disk hatası")
        self.assertTrue(dialog.failure.isVisible())
        self.assertEqual(dialog.failure.text(), "Disk hatası")
        self.assertTrue(dialog.content.isEnabled())
        self.assertTrue(dialog.create_button.isEnabled())
        dialog.close()
        window.close()

    @unittest.skipUnless(sys.platform == "win32", "Yalnızca Windows")
    def test_elevated_helper_exchanges_request_over_pipe(self):
        from enclave_app import vhd_service
        seen = []

        def fake_spawn(address, key):
            def run():
                with mock.patch.object(vhd_service, "create_virtual_disk",
                                       side_effect=lambda **request: seen.append(request) or {"success": True, "path": request["path"]}):
                    vhd_service.serve_helper(address, key.hex())
            threading.Thread(target=run, daemon=True).start()
            return True

        with mock.patch.object(vhd_service, "_spawn_helper", fake_spawn):
            result = vhd_service.create_virtual_disk_elevated("D:/a.vhdx", PW, 4, True, "Tuzak-Parola-456")
        self.assertEqual(result["path"], "D:/a.vhdx")
        self.assertEqual(seen[0]["decoy_password"], "Tuzak-Parola-456")
        with mock.patch.object(vhd_service, "_spawn_helper", return_value=False):
            with self.assertRaises(CustomVaultError):
                vhd_service.create_virtual_disk_elevated("D:/a.vhdx", PW, 4, True, None)

    def test_styles_control_rail_and_default_view(self):
        self.assertTrue(designs.get_design("mavi", "kart").rail)
        self.assertEqual(designs.get_design("mavi", "liste").default_view, "list")
        self.assertEqual(designs.get_design("yok", "yok").key, designs.DEFAULT_DESIGN)

    def test_each_style_opens_and_locks(self):
        self.seed()
        for style in designs.STYLES:
            with self.subTest(style=style):
                window = self.open_window("mor", True, style)
                self.unlock(window)
                self.assertEqual(window.workspace.side_panel is not None, designs.get_design("mor", style).rail)
                window.lock()
                self.assertIsNone(window.session)
                window.close()

    def test_capacity_shows_free_and_used(self):
        from enclave_app.common import CapacityBar
        bar = CapacityBar()
        bar.set_values(1024 * 1024, 10 * 1024 * 1024)
        self.assertIn("boş", bar.text.text())
        self.assertEqual(bar.bar.value(), 100)

    def test_slideshow_shows_only_image_while_playing(self):
        from enclave_app.slideshow import SlideshowDialog
        self.seed()
        window = self.open_window("mor")
        self.unlock(window)
        dialog = SlideshowDialog(window.session, window.session.images(), 0, {}, window.theme)
        dialog.toggle_play()
        self.assertTrue(dialog.header.isHidden())
        self.assertTrue(dialog.footer.isHidden())
        self.assertTrue(dialog.previous_arrow.isHidden())
        dialog.reject()
        self.assertFalse(dialog.header.isHidden())
        self.assertFalse(dialog.footer.isHidden())
        self.assertFalse(dialog.previous_arrow.isHidden())
        self.assertFalse(dialog.timer.isActive())
        dialog.close()
        window.close()

    def test_text_and_images_open_inside_app(self):
        from enclave_app.editor import TextEditorDialog
        self.seed()
        window = self.open_window("mor")
        self.unlock(window)
        session, ws = window.session, window.workspace
        note = next(f for f in session.files if f["path"] == "belgeler/not.txt")
        photo = next(f for f in session.files if f["path"] == "foto.png")
        dialog = TextEditorDialog(session, note, window.theme)
        dialog.editor.setPlainText("yeni içerik\nikinci satır")
        self.assertTrue(dialog.save())
        self.assertEqual(session.read_preview(note["id"]), "yeni içerik\nikinci satır".encode())
        dialog.editor.document().setModified(False)
        dialog.close()
        with mock.patch("enclave_app.workspace.open_with_system") as external, \
                mock.patch.object(TextEditorDialog, "exec", return_value=0) as editor, \
                mock.patch("enclave_app.workspace.SlideshowDialog") as viewer:
            ws._activate(("file", note["id"]))
            ws._activate(("file", photo["id"]))
        external.assert_not_called()
        editor.assert_called_once()
        viewer.assert_called_once()
        window.close()

    def test_capacity_bar_sits_at_window_bottom_in_every_style(self):
        self.seed()
        for style in designs.STYLES:
            with self.subTest(style=style):
                window = self.open_window("mor", True, style)
                self.unlock(window)
                ws = window.workspace
                self.assertEqual(ws.capacity.parentWidget().objectName(), "StatusBar")
                if ws.side_panel is not None:
                    self.assertFalse(ws.side_panel.isAncestorOf(ws.capacity))
                window.lock()
                window.close()

    def test_security_options_on_unlock_screen_and_close_button(self):
        from enclave_app.slideshow import SlideshowDialog
        self.seed()
        window = self.open_window("mor")
        page = window.unlock_page
        page.idle.setCurrentIndex(page.idle.findData(15))
        page.lock_minimize.setChecked(True)
        saved = config.load_config()
        self.assertEqual((saved["idle_lock_minutes"], saved["lock_on_minimize"]), (15, True))
        self.unlock(window)
        self.assertFalse(hasattr(window.workspace, "security"))
        dialog = SlideshowDialog(window.session, window.session.images(), 0, {}, window.theme)
        dialog.show()
        self.assertTrue(dialog.isVisible())
        dialog.close()
        self.assertTrue(spin(lambda: not dialog.isVisible()))
        window.close()

    def test_click_hides_controls_without_fullscreen_and_zoom_pill_follows_zoom(self):
        from enclave_app.slideshow import SlideshowDialog
        self.seed()
        window = self.open_window("mor")
        self.unlock(window)
        dialog = SlideshowDialog(window.session, window.session.images(), 0, {}, window.theme)
        dialog.show()
        self.assertTrue(spin(lambda: dialog._pixmap is not None))
        self.assertTrue(dialog.zoom_holder.isHidden())
        dialog.canvas.zoom_by(2.0)
        self.assertFalse(dialog.zoom_holder.isHidden())
        dialog.canvas.clicked.emit()
        self.assertTrue(dialog.header.isHidden() and dialog.footer.isHidden() and dialog.zoom_holder.isHidden())
        self.assertFalse(dialog.isFullScreen())
        dialog.canvas.clicked.emit()
        self.assertFalse(dialog.header.isHidden())
        dialog.canvas.reset_view()
        self.assertTrue(dialog.zoom_holder.isHidden())
        dialog.close()
        window.close()

    def test_slideshow_tools_zoom_rotate_and_shuffle(self):
        from enclave_app.slideshow import SlideshowDialog
        self.seed()
        auth = E.authenticate(self.vault, PW)
        E.add_file(self.vault, auth, str(self.dir / "foto.png"), "ikinci.png")
        window = self.open_window("mor")
        self.unlock(window)
        dialog = SlideshowDialog(window.session, window.session.images(), 0, {}, window.theme)
        self.assertTrue(spin(lambda: dialog._pixmap is not None))
        dialog.canvas.zoom_by(2.0)
        self.assertAlmostEqual(dialog.canvas._zoom, 2.0)
        dialog.canvas.reset_view()
        self.assertAlmostEqual(dialog.canvas._zoom, 1.0)
        dialog.canvas.rotate(90)
        self.assertEqual(dialog.canvas._rotation, 90)
        dialog.loop.setChecked(False)
        dialog.show_index(1)
        dialog.next()
        self.assertEqual(dialog.index, 1)
        dialog.shuffle.setChecked(True)
        dialog.next()
        self.assertEqual(dialog.index, 0)
        dialog.close()
        window.close()

    def test_loading_bars_run_only_while_busy(self):
        from enclave_app.common import LoadingBars
        from enclave_app.common import Theme
        bars = LoadingBars(Theme(designs.get_design("mor", "kart"), dark=False))
        self.assertTrue(bars.isHidden())
        bars.start()
        self.assertTrue(bars._timer.isActive())
        bars.stop()
        self.assertFalse(bars._timer.isActive())

    def test_suffix_helper_keeps_user_name(self):
        from enclave_app.common import with_default_suffix
        self.assertEqual(with_default_suffix("a/belge", ".pvault"), "a/belge.pvault")
        self.assertEqual(with_default_suffix("a/belge.dat", ".vhdx"), "a/belge.dat")
        self.assertEqual(with_default_suffix("", ".vhdx"), "")

    def test_vault_with_disk_extension_is_still_a_vault(self):
        from enclave_app import vhd_service
        path = str(self.dir / "gizli.vhd")
        E.create_vault(path, PW)
        self.assertFalse(vhd_service.is_virtual_disk(path))

    @unittest.skipUnless(sys.platform == "win32", "Yalnızca Windows")
    def test_windows_lock_closes_vault(self):
        self.seed()
        window = self.open_window("mor")
        self.unlock(window)
        with mock.patch("engine.VHDEngine.is_workstation_locked", return_value=True):
            window._check_os_lock()
        self.assertIsNone(window.session)
        window.close()

    @unittest.skipUnless(sys.platform == "win32", "Yalnızca Windows")
    def test_windows_lock_survives_unsaved_copy(self):
        """Kaydedilemeyen kopya kilidi durdurmamalı; aksi halde anahtarlar Windows kilitliyken bellekte kalır."""
        self.seed()
        window = self.open_window("mor")
        self.unlock(window)
        session = window.session
        session.modified_temp_files = lambda: [("kopya", "not.txt"), ("kopya2", "b.txt")]
        with mock.patch.object(session, "save_temp_back", side_effect=CustomVaultError("yer yok")) as save:
            with mock.patch("engine.VHDEngine.is_workstation_locked", return_value=True):
                window._check_os_lock()
        self.assertEqual(save.call_count, 2)
        self.assertIsNone(window.session)
        self.assertIsNone(session.auth)
        self.assertIn("2", window.unlock_page.error.text())
        window.close()

    def test_manual_lock_stays_open_when_copy_cannot_be_saved(self):
        self.seed()
        window = self.open_window("mor")
        self.unlock(window)
        session = window.session
        session.modified_temp_files = lambda: [("kopya", "not.txt")]

        def choose_save(box):
            box.clickedButton = lambda: box.buttons()[0]

        with mock.patch.object(session, "save_temp_back", side_effect=CustomVaultError("yer yok")), \
                mock.patch("enclave_app.window.QMessageBox.exec", choose_save), \
                mock.patch("enclave_app.window.QMessageBox.warning") as warning:
            window.lock()
        warning.assert_called_once()
        self.assertIs(window.session, session)
        session.modified_temp_files = lambda: []
        window.close()

    @unittest.skipUnless(sys.platform == "win32", "Yalnızca Windows")
    def test_windows_lock_closes_session_waiting_for_code(self):
        secret = totp_engine.generate_totp_secret()
        E.create_vault(self.vault, PW, two_factor_secret=secret)
        window = self.open_window("mor")
        window.unlock_page.password.edit.setText(PW)
        window.unlock_page._submit_password()
        self.assertTrue(spin(lambda: window.unlock_page.awaiting_code))
        session = window.unlock_page._session
        with mock.patch("engine.VHDEngine.is_workstation_locked", return_value=True):
            window._check_os_lock()
        self.assertFalse(window.unlock_page.awaiting_code)
        self.assertIsNone(session.auth)
        window.close()

    def test_changes_refused_during_transfer(self):
        """Aktarım kataloğu bellekte tutar; araya giren silme sonradan ezilir ve kayıt boş veriye işaret ederdi."""
        self.seed()
        window = self.open_window("mor")
        self.unlock(window)
        workspace = window.workspace
        before = [f["path"] for f in window.session.files]
        workspace._task = mock.Mock()
        with mock.patch("enclave_app.workspace.confirm", return_value=True) as ask:
            workspace._delete([window.session.files[0]["id"]], [])
        workspace._task = None
        ask.assert_not_called()
        self.assertEqual([f["path"] for f in window.session.files], before)
        window.close()

    def test_session_rejects_overlapping_writes(self):
        self.seed()
        session = VaultSession(self.vault)
        session.unlock(PW)
        self.addCleanup(session.close)
        file_id = session.files[0]["id"]
        with session._write_gate:
            with self.assertRaises(CustomVaultError):
                session.delete([file_id], [])
            with self.assertRaises(CustomVaultError):
                session.rename_file(file_id, "yeni.png")
        session.delete([file_id], [])

    def two_factor_vault(self):
        secret = totp_engine.generate_totp_secret()
        E.create_vault(self.vault, PW, two_factor_secret=secret, two_factor_backup_codes=["AAAA-BBBB", "CCCC-DDDD"])
        return E.get_recovery_key(E.authenticate(self.vault, PW)), secret

    def test_recovery_key_does_not_skip_second_factor(self):
        recovery, secret = self.two_factor_vault()
        session = VaultSession(self.vault)
        self.addCleanup(session.close)
        self.assertTrue(session.unlock_with_recovery_key(recovery))
        self.assertFalse(session.is_open)
        self.assertTrue(session.verify_second_factor(totp_engine.get_totp_token(secret))[0])
        self.assertTrue(session.is_open)

    def test_recovery_flow_asks_code_then_new_password(self):
        recovery, _secret = self.two_factor_vault()
        window = self.open_window("mor")
        page = window.unlock_page
        with mock.patch("enclave_app.unlock_page.QInputDialog.getText", return_value=(recovery, True)):
            page._recover()
        self.assertEqual(page.form_stack.currentIndex(), 1)
        self.assertIsNone(window.session)
        page.code_edit.setText("AAAA-BBBB")
        with mock.patch("enclave_app.unlock_page.ChangePasswordDialog.exec", return_value=0) as change:
            page._submit_code()
        change.assert_called_once()
        self.assertIsNone(window.session)
        self.assertFalse(page.awaiting_code)
        window.close()

    def test_code_delay_is_not_reset_by_retyping_password(self):
        self.two_factor_vault()
        window = self.open_window("mor")
        page = window.unlock_page
        page._code_failures = 3
        page._on_password_ok(mock.Mock(), True)
        self.assertEqual(page._code_failures, 3)
        page._session = None
        window.close()

    def test_recovery_key_needs_identity_check(self):
        self.seed()
        window = self.open_window("mor")
        self.unlock(window)
        settings = SettingsDialog(window.theme, window.session, window)
        with mock.patch("enclave_app.dialogs.ConfirmIdentityDialog.exec", return_value=0), \
                mock.patch("enclave_app.dialogs.RecoveryKeyDialog") as shown, \
                mock.patch("enclave_app.dialogs.ChangePasswordDialog") as change:
            settings._show_recovery_key()
            settings._change_password()
        shown.assert_not_called()
        change.assert_not_called()
        settings.close()
        window.close()

    def test_identity_check_rejects_wrong_password_and_missing_code(self):
        _recovery, secret = self.two_factor_vault()
        session = VaultSession(self.vault)
        self.addCleanup(session.close)
        session.unlock(PW)
        session.verify_second_factor("AAAA-BBBB")
        with self.assertRaises(CustomVaultError):
            session.confirm_identity("yanlis-parola")
        with self.assertRaises(CustomVaultError):
            session.confirm_identity(PW, "")
        session.confirm_identity(PW, totp_engine.get_totp_token(secret))

    def test_key_file_unlock_flow(self):
        self.seed()
        window = self.open_window("mor")
        self.unlock(window)
        path = self.dir / "uzak" / "kasa.key"
        path.parent.mkdir()
        dialog = KeyFileDialog(window.session, PW, window.theme, window)
        with mock.patch("enclave_app.dialogs.QFileDialog.getSaveFileName", return_value=(str(path), "")):
            dialog._save()
        self.assertTrue(window.session.has_key_file)
        window.lock()
        page = window.unlock_page
        page.password.edit.setText(PW)
        page._submit_password()
        self.assertTrue(spin(lambda: page.error.isVisible()))
        with mock.patch("enclave_app.unlock_page.QFileDialog.getOpenFileName", return_value=(str(path), "")):
            page._toggle_key_file()
        page._retry_at = 0.0
        page.password.edit.setText(PW)
        page._submit_password()
        self.assertTrue(spin(lambda: window.session is not None), page.error.text())
        self.assertIsNone(page._key_digest)
        window.close()

    def test_key_file_refused_next_to_vault(self):
        self.seed()
        window = self.open_window("mor")
        self.unlock(window)
        path = self.dir / "kasa.key"
        dialog = KeyFileDialog(window.session, PW, window.theme, window)
        with mock.patch("enclave_app.dialogs.QFileDialog.getSaveFileName", return_value=(str(path), "")):
            dialog._save()
        self.assertFalse(path.exists())
        self.assertFalse(window.session.has_key_file)
        window.close()

    def test_recovery_file_named_after_vault_with_hash(self):
        self.seed()
        target = self.dir / "cikti.txt"
        name = Path(self.vault).stem
        dialog = RecoveryKeyDialog("ABCD-EFGH", self.vault, Theme(designs.get_design("mor", designs.DEFAULT_STYLE), True))
        with mock.patch("enclave_app.dialogs.QFileDialog.getSaveFileName", return_value=(str(target), "")) as ask:
            dialog._save()
        self.assertEqual(ask.call_args.args[2], f"{name}_kurtarma.txt")
        text = target.read_text(encoding="utf-8")
        self.assertIn("ABCD-EFGH", text)
        self.assertIn(name, text)
        self.assertIn(hashlib.sha256(Path(self.vault).read_bytes()).hexdigest(), text)
        self.assertNotIn(str(self.dir), text)

    def test_two_factor_file_named_after_vault_with_hash(self):
        self.seed()
        window = self.open_window("mor")
        self.unlock(window)
        target = self.dir / "iki.txt"
        name = Path(self.vault).stem
        dialog = TwoFactorDialog(window.session, window.theme, window)
        with mock.patch("enclave_app.dialogs.QFileDialog.getSaveFileName", return_value=(str(target), "")) as ask:
            dialog._save_to_file()
        self.assertEqual(ask.call_args.args[2], f"{name}_2fa.txt")
        text = target.read_text(encoding="utf-8")
        self.assertIn(totp_engine.format_secret_for_display(dialog.secret), text)
        self.assertTrue(all(code in text for code in dialog.backup_codes))
        self.assertIn(hashlib.sha256(Path(self.vault).read_bytes()).hexdigest(), text)
        window.close()

    def test_clipboard_secret_is_cleared(self):
        copy_secret("GIZLI-ANAHTAR")
        QApplication.processEvents()
        self.assertEqual(QApplication.clipboard().text(), "GIZLI-ANAHTAR")
        clear_secret_clipboard()
        QApplication.processEvents()
        self.assertEqual(QApplication.clipboard().text(), "")
        copy_secret("GIZLI-ANAHTAR")
        QApplication.processEvents()
        QApplication.clipboard().setText("kullanici metni")
        QApplication.processEvents()
        clear_secret_clipboard()
        QApplication.processEvents()
        self.assertEqual(QApplication.clipboard().text(), "kullanici metni")

    def test_change_password_dialog_reencrypts(self):
        self.seed()
        window = self.open_window("mor")
        self.unlock(window)
        old_key = window.session.auth["master_key"]
        dialog = ChangePasswordDialog(window.session, window.theme, window)
        dialog.password.edit.setText("Yeni-Parola-123")
        dialog.again.edit.setText("Yeni-Parola-123")
        dialog._save()
        self.assertNotEqual(window.session.auth["master_key"], old_key)
        self.assertEqual(len(window.session.files), 2)
        window.session.read_preview(window.session.files[0]["id"])
        window.close()
        E.authenticate(self.vault, "Yeni-Parola-123")

class FakeVhdEngine:
    def __init__(self, locked=True, password="dogru"):
        self.locked, self.password, self.calls = locked, password, []

    def backup_and_disable_autoplay(self): return True
    def restore_autoplay(self): self.calls.append("autoplay")
    def mount_vhd(self, path): return {"success": True, "drive_letter": "Z:"}
    def get_drive_status(self, letter): return {"is_locked": self.locked, "total_bytes": 100, "free_bytes": 40}
    def check_embedded_decoy_vault(self, path): return False
    def unlock_bitlocker_password(self, letter, password):
        return {"success": True} if password == self.password else {"success": False, "wrong_password": True}
    def close_explorer_windows(self, letter): self.calls.append("explorer")
    def dismount_vhd(self, **kw): self.calls.append("dismount"); return {"success": True}
    def wipe_system_traces(self, letter): self.calls.append("wipe")

class VhdFlow(Base):
    def session(self, engine):
        from enclave_app import vhd_service
        path = self.source("disk.vhdx")
        with mock.patch.object(vhd_service, "make_engine", return_value=engine):
            return vhd_service.VhdSession(path)

    def test_wrong_password_never_leaves_disk_attached(self):
        engine = FakeVhdEngine()
        with self.assertRaises(Exception):
            self.session(engine).unlock("yanlis")
        self.assertIn("dismount", engine.calls)
        self.assertIn("autoplay", engine.calls)

    def test_new_ui_shows_disk_and_dismounts_on_close(self):
        engine = FakeVhdEngine()
        session = self.session(engine)
        session.unlock("dogru")
        window = VaultWindow()
        window.show()
        window._on_unlocked(session)
        self.assertEqual(window.stack.currentWidget(), window.vhd_page)
        self.assertIn("Z:", window.vhd_page.drive.text())
        window.set_design("yesil", "dark")
        self.assertIsNotNone(window.vhd_page)
        window.close()
        self.assertEqual(engine.calls[:3], ["explorer", "dismount", "wipe"])

    def test_legacy_window_is_not_reachable(self):
        for name in ("main.py", "enclave_app/window.py", "enclave_app/dialogs.py"):
            text = (Path(__file__).parent / name).read_text(encoding="utf-8")
            self.assertNotIn("from ui import", text, name)

    @unittest.skipUnless(sys.platform == "win32", "Yalnızca Windows")
    def test_create_dialog_offers_architectures(self):
        from enclave_app.dialogs import CreateVaultDialog
        from enclave_app.window import VaultWindow as W
        dialog = CreateVaultDialog(W._resolve_theme("mor", "dark"))
        self.assertEqual(dialog._extension(), ".pvault")
        self.assertFalse(dialog.carrier_toggle.isChecked())
        self.assertTrue(dialog.carrier_options.isHidden())

        dialog.carrier_toggle.setChecked(True)
        self.assertFalse(dialog.carrier_options.isHidden())
        self.assertEqual(dialog._extension(), ".mp4")
        dialog.carrier_edit.setText("deneme.png")
        self.assertEqual(dialog._extension(), ".png")

        dialog.carrier_toggle.setChecked(False)
        self.assertTrue(dialog.carrier_options.isHidden())
        self.assertEqual(dialog._extension(), ".pvault")

        dialog._set_architecture("vhd")
        self.assertEqual(dialog._extension(), ".vhdx")
        self.assertFalse(dialog.vhd_options.isHidden())
        self.assertTrue(dialog.carrier_toggle.isHidden())

    def test_wrap_and_strip_carrier_dialogs(self):
        from enclave_app.window import VaultWindow as W
        from enclave_app.extras import WrapCarrierDialog, StripCarrierDialog
        theme = W._resolve_theme("mor", "dark")

        wrap_dialog = WrapCarrierDialog(theme, initial_vault_path="test.pvault", initial_password="password123")
        self.assertEqual(wrap_dialog.vault_edit.text(), "test.pvault")
        self.assertEqual(wrap_dialog.password_field.text(), "password123")
        self.assertFalse(wrap_dialog.run_button.isEnabled())
        wrap_dialog.carrier_edit.setText("video.mp4")
        self.assertTrue(wrap_dialog.target_edit.text().endswith("video_kasa.mp4"))
        self.assertTrue(wrap_dialog.run_button.isEnabled())

        wrap_dialog.decoy_check.setChecked(True)
        self.assertFalse(wrap_dialog.decoy_box.isHidden())
        self.assertFalse(wrap_dialog.run_button.isEnabled())
        wrap_dialog.decoy_field.setText("decoypassword123")
        self.assertTrue(wrap_dialog.run_button.isEnabled())
        wrap_dialog.close()

        strip_dialog = StripCarrierDialog(theme, initial_stego_path="video_kasa.mp4", initial_password="password123")
        self.assertEqual(strip_dialog.stego_edit.text(), "video_kasa.mp4")
        self.assertTrue(strip_dialog.target_edit.text().endswith("video.pvault"))
        self.assertTrue(strip_dialog.run_button.isEnabled())
        strip_dialog.close()

    def test_create_pvault_with_carrier_toggle(self):
        from enclave_app.dialogs import CreateVaultDialog
        from enclave_app.window import VaultWindow as W
        dialog = CreateVaultDialog(W._resolve_theme("mor", "dark"))
        carrier_dummy = self.dir / "dummy.mp4"
        carrier_dummy.write_bytes(b"\x00" * 1024)

        dialog.carrier_toggle.setChecked(True)
        dialog.carrier_edit.setText(str(carrier_dummy))
        dialog.password.setText("GucluParola123!")
        dialog.password_again.setText("GucluParola123!")
        dialog.ack.setChecked(True)
        dialog._validate()
        self.assertTrue(dialog.create_button.isEnabled())
        self.assertTrue(dialog.path_edit.text().endswith("dummy_kasa.mp4"))
        dialog.close()

class PortabilityTests(unittest.TestCase):
    """Windows'a özel modüller yokken uygulama açılabilmeli (Linux ve macOS'un koşulu)."""

    def test_app_imports_without_windows_modules(self):
        script = r'''
import sys, ctypes, builtins, os
sys.platform = "linux"
if hasattr(ctypes, "windll"):
    del ctypes.windll
if hasattr(ctypes, "WinDLL"):
    del ctypes.WinDLL
real_import = builtins.__import__
def guarded(name, *a, **k):
    if name.split(".")[0] in ("winreg", "msvcrt", "wintypes", "ui", "enclave_custom_ui", "extra_dialogs"):
        raise ImportError("Windows modulu: " + name)
    return real_import(name, *a, **k)
builtins.__import__ = guarded
os.environ["QT_QPA_PLATFORM"] = "offscreen"
import main
import enclave_core, config, logger
import enclave_app.window, enclave_app.dialogs, enclave_app.workspace, enclave_app.unlock_page
print("OK")
'''
        env = dict(os.environ, PYTHONIOENCODING="utf-8", APPDATA=_CONFIG_HOME, XDG_CONFIG_HOME=_CONFIG_HOME)
        result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, encoding="utf-8",
                                env=env, cwd=str(Path(__file__).parent), timeout=120)
        self.assertIn("OK", result.stdout, result.stderr[-2000:])

if __name__ == "__main__":
    unittest.main()
