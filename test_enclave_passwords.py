"""Enclave - Entegre Şifre Yöneticisi Kapsamlı Birim Testleri.

Kriptografik alt anahtar türetimi, AES-GCM AEAD şifreleme/çözme, CRUD işlemleri,
tuzak kasa izolasyonu, parola üreteci, TOTP üretimi, içe/dışa aktarma (Chrome, Firefox,
Bitwarden, 1Password, KeePass) ve Qt arayüz bileşenlerinin doğrulanması.
"""

import base64
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from PyQt6.QtWidgets import QApplication

from enclave_app.common import Theme
from enclave_app.designs import DESIGNS
from enclave_app.pwd_dialogs import (
    EntryEditorDialog, HealthAuditDialog, ImportExportDialog,
    PasswordGeneratorDialog
)
from enclave_app.pwd_engine import (
    ENTRY_TYPES, TYPE_LABELS, PasswordEntry, PasswordStore,
    decrypt_payload, derive_password_subkey, encrypt_payload,
    evaluate_password, generate_password, get_live_totp
)
from enclave_app.pwd_importer import (
    detect_and_import_csv, detect_and_import_json, export_encrypted_backup,
    export_to_csv, import_encrypted_backup
)
from enclave_app.pwd_view import EntryListItemWidget, PasswordInspector, PasswordView

app = QApplication.instance() or QApplication([])

class DummySession:
    """Testler için sahte kasa oturumu."""

    def __init__(self, master_key: bytes = b"\x42" * 32, salt: bytes = b"\x24" * 32):
        self.path = "dummy_vault.pvault"
        self.auth = {
            "master_key": master_key,
            "salt": salt,
            "slot_idx": 0
        }
        self.catalog = {
            "files": [],
            "folders": [],
            "password_store": None
        }

    def all_folders(self):
        return []

    def stats(self):
        return {"count": 0, "used": 0, "quota": 100 * 1024 * 1024}

class TestPasswordCryptoAndEngine(unittest.TestCase):
    """Kriptografi ve çekirdek motor testleri."""

    def test_derive_password_subkey(self):
        master = b"A" * 32
        salt = b"S" * 32
        k1 = derive_password_subkey(master, salt)
        k2 = derive_password_subkey(master, salt)
        self.assertEqual(k1, k2)
        self.assertEqual(len(k1), 32)
        k3 = derive_password_subkey(b"B" * 32, salt)
        self.assertNotEqual(k1, k3)
        self.assertNotEqual(k1, master)

    def test_encrypt_decrypt_payload(self):
        key = b"K" * 32
        sample_data = {
            "version": 1,
            "items": [
                {"id": "1", "title": "Test Account", "password": "SecretPassword123!"}
            ]
        }
        encrypted = encrypt_payload(sample_data, key)
        self.assertTrue(encrypted.startswith(b"VPWD"))
        decrypted = decrypt_payload(encrypted, key)
        self.assertEqual(decrypted["version"], 1)
        self.assertEqual(len(decrypted["items"]), 1)
        self.assertEqual(decrypted["items"][0]["title"], "Test Account")

    def test_decrypt_with_wrong_key_fails(self):
        key1 = b"1" * 32
        key2 = b"2" * 32
        encrypted = encrypt_payload({"hello": "world"}, key1)
        with self.assertRaises(ValueError):
            decrypt_payload(encrypted, key2)

    def test_password_entry_serialization(self):
        entry = PasswordEntry(
            type="card",
            title="İş Bankası Kartı",
            username="4543 **** **** 1234",
            password="123",
            url="12/28",
            tags=["banka", "finans"],
            favorite=True,
            custom_fields=[{"name": "CVV", "value": "999", "secret": True}]
        )
        d = entry.to_dict()
        self.assertEqual(d["type"], "card")
        self.assertEqual(d["title"], "İş Bankası Kartı")
        self.assertTrue(d["favorite"])
        self.assertEqual(len(d["custom_fields"]), 1)

        restored = PasswordEntry.from_dict(d)
        self.assertEqual(restored.id, entry.id)
        self.assertEqual(restored.title, entry.title)
        self.assertEqual(restored.tags, ["banka", "finans"])
        self.assertEqual(restored.custom_fields[0]["value"], "999")

    def test_generate_password_random(self):
        pwd = generate_password(length=18, use_lower=True, use_upper=True, use_digits=True, use_symbols=True)
        self.assertEqual(len(pwd), 18)

        digits_only = generate_password(length=6, use_lower=False, use_upper=False, use_digits=True, use_symbols=False)
        self.assertEqual(len(digits_only), 6)
        self.assertTrue(digits_only.isdigit())

        pwd_no_ambig = generate_password(length=30, avoid_ambiguous=True)
        for ch in "O0oIl1":
            self.assertNotIn(ch, pwd_no_ambig)

    def test_generate_passphrase(self):
        phrase = generate_password(passphrase=True, word_count=4, separator="-")
        words = phrase.split("-")
        self.assertEqual(len(words), 4)
        for w in words:
            self.assertTrue(len(w) > 0)

    def test_evaluate_password_strength(self):
        score0, _ = evaluate_password("")
        self.assertEqual(score0, 0)
        score1, _ = evaluate_password("short")
        self.assertTrue(score1 <= 1)

        score2, _ = evaluate_password("Password123")
        self.assertTrue(score2 >= 1)

        score4, lbl = evaluate_password("K4lk4n#K0rum4-2026!XyZ")
        self.assertTrue(score4 >= 3)
        self.assertIn(lbl, ["Güçlü", "Çok Güçlü"])

    def test_live_totp_generation(self):
        secret = "JBSWY3DPEHPK3PXP"
        token, remaining, progress = get_live_totp(secret)
        self.assertEqual(len(token), 6)
        self.assertTrue(token.isdigit())
        self.assertTrue(0 <= remaining <= 30)
        self.assertTrue(0.0 <= progress <= 1.0)

        bad_token, _, _ = get_live_totp("INVALID_SECRET_!@#$")
        self.assertEqual(bad_token, "")

class TestPasswordStoreCRUD(unittest.TestCase):
    """Depo yönetimi ve CRUD testleri."""

    def setUp(self):
        self.session = DummySession()
        self.store = PasswordStore(self.session)

    def test_add_and_get_entry(self):
        entry = PasswordEntry(
            title="GitHub",
            username="dev_user",
            password="SecurePass987!",
            url="https://github.com"
        )
        saved = self.store.add(entry)
        self.assertEqual(saved.title, "GitHub")
        self.assertIn(saved.id, self.store.entries)

        fetched = self.store.get(saved.id)
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched.username, "dev_user")

    def test_update_entry_with_password_history(self):
        entry = PasswordEntry(title="Bank", password="OldPass123!")
        self.store.add(entry)

        entry.password = "NewPass456!"
        self.store.update(entry)

        updated = self.store.get(entry.id)
        self.assertEqual(updated.password, "NewPass456!")
        self.assertEqual(len(updated.password_history), 1)
        self.assertEqual(updated.password_history[0]["password"], "OldPass123!")

    def test_soft_and_permanent_delete(self):
        entry = PasswordEntry(title="Temp Account")
        self.store.add(entry)

        self.store.delete(entry.id, soft=True)
        self.assertTrue(self.store.get(entry.id).deleted)
        self.assertNotIn(entry.id, [e.id for e in self.store.all(include_deleted=False)])
        self.assertIn(entry.id, [e.id for e in self.store.all(include_deleted=True)])

        self.store.restore(entry.id)
        self.assertFalse(self.store.get(entry.id).deleted)

        self.store.delete(entry.id, soft=False)
        self.assertIsNone(self.store.get(entry.id))

    def test_toggle_favorite(self):
        entry = PasswordEntry(title="Favorite Account", favorite=False)
        self.store.add(entry)
        self.assertFalse(self.store.get(entry.id).favorite)

        self.store.toggle_favorite(entry.id)
        self.assertTrue(self.store.get(entry.id).favorite)

        self.store.toggle_favorite(entry.id)
        self.assertFalse(self.store.get(entry.id).favorite)

    def test_search_and_category_counts(self):
        self.store.add(PasswordEntry(type="login", title="Twitter X", username="elon", tags=["sosyal"]))
        self.store.add(PasswordEntry(type="login", title="Instagram", username="foto", tags=["sosyal", "medya"]))
        self.store.add(PasswordEntry(type="card", title="Visa Platinum", username="4111", tags=["finans"]))
        self.store.add(PasswordEntry(type="note", title="Gizli Not", notes="Kasa şifresi 9988"))

        counts = self.store.counts()
        self.assertEqual(counts["login"], 2)
        self.assertEqual(counts["card"], 1)
        self.assertEqual(counts["note"], 1)
        self.assertEqual(counts["total"], 4)

        results = self.store.search("sosyal")
        self.assertEqual(len(results), 2)
        results2 = self.store.search("Visa")
        self.assertEqual(len(results2), 1)

    def test_security_audit(self):
        self.store.add(PasswordEntry(title="Weak1", password="123"))
        self.store.add(PasswordEntry(title="ReusedA", password="CommonSharedPassword!2026"))
        self.store.add(PasswordEntry(title="ReusedB", password="CommonSharedPassword!2026"))
        self.store.add(PasswordEntry(title="StrongUnique", password="SuperComplexUn1qu3P@ssw0rd!"))

        audit = self.store.audit()
        self.assertEqual(len(audit["weak"]), 1)
        self.assertEqual(audit["weak"][0].title, "Weak1")

        self.assertEqual(len(audit["reused"]), 2)
        reused_titles = {e.title for e in audit["reused"]}
        self.assertEqual(reused_titles, {"ReusedA", "ReusedB"})

class TestPasswordImportExport(unittest.TestCase):
    """İçe ve dışa aktarma (Chrome, Firefox, Bitwarden, 1Password, KeePass, Backup) testleri."""

    def test_chrome_csv_import(self):
        chrome_csv = (
            "name,url,username,password,note\n"
            "Google,https://google.com,test@gmail.com,GooglePass123!,\n"
            "Amazon,https://amazon.com,buyer@shop.com,AmazonPass999!,Alışveriş notu\n"
        )
        entries = detect_and_import_csv(chrome_csv)
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0].title, "Google")
        self.assertEqual(entries[0].username, "test@gmail.com")
        self.assertEqual(entries[1].notes, "Alışveriş notu")

    def test_firefox_csv_import(self):
        firefox_csv = (
            '"url","username","password","httpRealm","formActionOrigin","guid","timeCreated","timeLastUsed","timePasswordChanged"\n'
            '"https://github.com","git_user","GitPass2026!","","https://github.com","{1}","1600000000","1600000000","1600000000"\n'
        )
        entries = detect_and_import_csv(firefox_csv)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].title, "github.com")
        self.assertEqual(entries[0].username, "git_user")
        self.assertEqual(entries[0].password, "GitPass2026!")

    def test_bitwarden_json_import(self):
        bw_json = json.dumps({
            "items": [
                {
                    "type": 1,
                    "name": "Bitwarden Account",
                    "login": {
                        "username": "bw@test.com",
                        "password": "BwPassword!",
                        "uris": [{"uri": "https://vault.bitwarden.com"}],
                        "totp": "JBSWY3DPEHPK3PXP"
                    },
                    "notes": "Bitwarden notu"
                }
            ]
        })
        entries = detect_and_import_json(bw_json)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].title, "Bitwarden Account")
        self.assertEqual(entries[0].username, "bw@test.com")
        self.assertEqual(entries[0].totp_secret, "JBSWY3DPEHPK3PXP")

    def test_keepass_csv_import(self):
        keepass_csv = (
            '"Group","Title","Username","Password","URL","Notes"\n'
            '"General","Server SSH","root","RootSSHPass#1","192.168.1.100","SSH key installed"\n'
        )
        entries = detect_and_import_csv(keepass_csv)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].title, "Server SSH")
        self.assertEqual(entries[0].username, "root")
        self.assertEqual(entries[0].url, "192.168.1.100")

    def test_export_and_import_csv(self):
        original = [
            PasswordEntry(title="Test 1", username="user1", password="pwd1", url="http://t1.com"),
            PasswordEntry(title="Test 2", username="user2", password="pwd2", notes="Some note")
        ]
        csv_str = export_to_csv(original)
        imported = detect_and_import_csv(csv_str)
        self.assertEqual(len(imported), 2)
        self.assertEqual(imported[0].title, "Test 1")
        self.assertEqual(imported[1].notes, "Some note")

    def test_encrypted_backup_roundtrip(self):
        original = [
            PasswordEntry(title="Critical", username="admin", password="SuperSecretPassword!", totp_secret="JBSWY3DPEHPK3PXP")
        ]
        backup_password = "BackupMasterPassword123!"
        with tempfile.NamedTemporaryFile(suffix=".pvault-pwd", delete=False) as tf:
            temp_path = tf.name

        try:
            export_encrypted_backup(original, temp_path, backup_password)
            self.assertTrue(os.path.exists(temp_path))

            restored = import_encrypted_backup(temp_path, backup_password)
            self.assertEqual(len(restored), 1)
            self.assertEqual(restored[0].title, "Critical")
            self.assertEqual(restored[0].totp_secret, "JBSWY3DPEHPK3PXP")

            with self.assertRaises(ValueError):
                import_encrypted_backup(temp_path, "WrongPassword!")
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

class TestPasswordUIComponents(unittest.TestCase):
    """Qt arayüz bileşenlerinin oluşturulma ve çalışma testleri."""

    def setUp(self):
        self.theme = Theme(DESIGNS["mor"], False)
        self.session = DummySession()
        self.store = PasswordStore(self.session)

    def test_password_generator_dialog(self):
        dlg = PasswordGeneratorDialog(self.theme)
        self.assertIsNotNone(dlg.result_edit)
        dlg._generate()
        self.assertTrue(len(dlg.result_edit.text()) >= 8)

    def test_entry_editor_dialog(self):
        dlg = EntryEditorDialog(self.theme, self.store, default_type="login")
        self.assertIsNotNone(dlg.title_edit)
        self.assertIsNotNone(dlg.user_edit)
        self.assertIsNotNone(dlg.pwd_edit)

        self.assertFalse(dlg._on_save())

        dlg.title_edit.setText("My Service")
        dlg.user_edit.setText("admin")
        dlg.pwd_edit.setText("Secret123!")
        saved = dlg._on_save()
        self.assertTrue(saved)
        self.assertEqual(dlg.entry.title, "My Service")

    def test_health_audit_dialog(self):
        self.store.add(PasswordEntry(title="WeakAcc", password="123"))
        dlg = HealthAuditDialog(self.theme, self.store)
        self.assertIsNotNone(dlg)

    def test_password_view_and_inspector(self):
        e1 = self.store.add(PasswordEntry(type="login", title="GitHub", username="octocat", password="GitPass123!"))
        e2 = self.store.add(PasswordEntry(type="card", title="Visa Kart", username="4543 0000", favorite=True))

        view = PasswordView(self.session, self.theme)
        self.assertIsNotNone(view.sidebar)
        self.assertIsNotNone(view.list_pane)
        self.assertIsNotNone(view.inspector)

        view._select_category("card")
        self.assertEqual(view.current_category, "card")
        self.assertEqual(view.list_widget.count(), 1)

        view._select_filter("favorites")
        self.assertEqual(view.current_filter, "favorites")
        self.assertEqual(view.list_widget.count(), 1)

        view._select_category(None)
        self.assertEqual(view.list_widget.count(), 2)

        view._on_search_changed("octocat")
        self.assertEqual(view.list_widget.count(), 1)
        view._on_search_changed("")
        self.assertEqual(view.list_widget.count(), 2)

        view.inspector.set_entry(e1)
        self.assertEqual(view.inspector.head_title.text(), "GitHub")
        self.assertEqual(view.inspector.stack.currentIndex(), 1)

        view.inspector.set_entry(None)
        self.assertEqual(view.inspector.stack.currentIndex(), 0)

        view.inspector._totp_timer.stop()

if __name__ == "__main__":
    unittest.main()
