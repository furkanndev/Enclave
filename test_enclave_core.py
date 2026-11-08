"""
Enclave - Kasa motoru regresyon testleri (Windows, macOS, Linux)
Her test gerçekte yaşanmış bir veri kaybı veya güvenlik hatasını kilitler.
Çalıştırma: python -m unittest test_enclave_core -v
"""

import base64
import builtins
import hashlib
import os
import shutil
import struct
import sys
import tempfile
import time
import unicodedata
import unittest
import zlib
from pathlib import Path

import totp_engine

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

import enclave_core
from enclave_core import (
    CustomVaultEngine as E,
    CustomVaultError,
    InvalidPasswordError,
    VaultFileLock,
    VaultTamperedError,
    safe_vault_name,
)

PW = "Parola@12345"
DECOY_PW = "Tuzak@12345"

class Base(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="vault_core_"))
        self.vault = str(self.dir / "kasa.pvault")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)

    def create(self, **kw):
        E.create_vault(self.vault, kw.pop("password", PW), **kw)
        return E.authenticate(self.vault, PW)

class FixedVault(Base):
    def test_files_survive_each_other(self):
        """Sabit boyutlu kasada ikinci dosya birincinin üzerine yazılıyordu."""
        auth = self.create(max_size_mb=8, is_dynamic=False)
        one, two, three = os.urandom(5000), os.urandom(5000), os.urandom(9000)
        E.write_file_bytes(self.vault, auth, "bir.bin", one)
        E.write_file_bytes(self.vault, auth, "iki.bin", two)
        E.write_file_bytes(self.vault, auth, "uc.bin", three)
        fresh = E.authenticate(self.vault, PW)
        self.assertEqual(E.extract_file_bytes(self.vault, fresh, "bir.bin")[0], one)
        self.assertEqual(E.extract_file_bytes(self.vault, fresh, "iki.bin")[0], two)
        self.assertEqual(E.extract_file_bytes(self.vault, fresh, "uc.bin")[0], three)

    def test_rewrites_stay_inside_compartment(self):
        """Dosyanın tekrar tekrar yazılması komşu bölmeye taşıyordu."""
        auth = self.create(decoy_password=DECOY_PW, max_size_mb=1, decoy_size_mb=1, is_dynamic=False)
        decoy = E.authenticate(self.vault, DECOY_PW)
        E.write_file_bytes(self.vault, decoy, "tuzak.bin", b"T" * 1000)
        for _ in range(8):
            E.write_file_bytes(self.vault, auth, "dongu.bin", os.urandom(400_000))
        self.assertEqual(os.path.getsize(self.vault), 256 + 2 * 1024 * 1024)
        decoy = E.authenticate(self.vault, DECOY_PW)
        self.assertEqual(E.extract_file_bytes(self.vault, decoy, "tuzak.bin")[0], b"T" * 1000)

    def test_full_compartment_reports_capacity(self):
        auth = self.create(max_size_mb=1, is_dynamic=False)
        E.write_file_bytes(self.vault, auth, "a.bin", os.urandom(600_000))
        with self.assertRaisesRegex(CustomVaultError, "kapasitesi"):
            E.write_file_bytes(self.vault, auth, "b.bin", os.urandom(600_000))
        fresh = E.authenticate(self.vault, PW)
        self.assertEqual(len(E.load_catalog(self.vault, fresh)["files"]), 1)

class Compartments(Base):
    def test_compact_requires_consent_and_preserves_real_data(self):
        """Sıkıştırma tuzak bölmeyi sessizce yok ediyordu."""
        auth = self.create(decoy_password=DECOY_PW)
        decoy = E.authenticate(self.vault, DECOY_PW)
        E.write_file_bytes(self.vault, decoy, "tuzak.txt", b"tuzak")
        E.write_file_bytes(self.vault, auth, "gercek.txt", b"gercek")
        with self.assertRaises(CustomVaultError):
            E.compact_vault(self.vault, auth)
        fresh = E.authenticate(self.vault, DECOY_PW)
        self.assertEqual(E.extract_file_bytes(self.vault, fresh, "tuzak.txt")[0], b"tuzak")
        E.compact_vault(self.vault, auth, discard_other_compartment=True)
        fresh = E.authenticate(self.vault, PW)
        self.assertEqual(E.extract_file_bytes(self.vault, fresh, "gercek.txt")[0], b"gercek")

    def test_slot_position_reveals_nothing(self):
        """Gerçek bölme hep ilk yuvadaydı; ikinci yuvayı açan parola kendini ele veriyordu."""
        slots = set()
        for i in range(12):
            path = str(self.dir / f"s{i}.pvault")
            enclave_core._derive_key, real = (lambda p, s, k=None: hashlib.sha256(p.encode() + s).digest()), enclave_core._derive_key
            try:
                E.create_vault(path, PW, decoy_password=DECOY_PW)
                slots.add(E.authenticate(path, PW)["slot_idx"])
            finally:
                enclave_core._derive_key = real
        self.assertEqual(slots, {1, 2})

    def test_second_compartment_is_indistinguishable_from_inside(self):
        self.create(decoy_password=DECOY_PW)
        decoy = E.authenticate(self.vault, DECOY_PW)
        catalog = E.load_catalog(self.vault, decoy)
        self.assertFalse(decoy["is_decoy"])
        self.assertNotIn("is_decoy", catalog)
        self.assertNotIn("has_decoy", catalog)

    def test_two_factor_flag_not_in_public_header(self):
        """Açık 2FA bayrağı, 2FA sormayan bölmeyi ele veriyordu."""
        self.create(two_factor_secret="JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP")
        self.assertEqual(E.read_header_flags(self.vault), 0)
        auth = E.authenticate(self.vault, PW)
        self.assertTrue(E.get_vault_2fa_config(self.vault, auth)["enabled"])

    def test_same_password_rejected(self):
        with self.assertRaises(CustomVaultError):
            E.create_vault(self.vault, PW, decoy_password=PW)

class CrashSafety(Base):
    def _crash_on_write(self, nth):
        """nth. yazmada elektrik kesilmiş gibi kaydı keser."""
        class Crash(Exception):
            pass

        real_open = builtins.open
        vault = self.vault

        class Tracked:
            count = 0

            def __init__(self, f):
                self.f = f

            def __getattr__(self, name):
                return getattr(self.f, name)

            def __enter__(self):
                self.f.__enter__()
                return self

            def __exit__(self, *exc):
                return self.f.__exit__(*exc)

            def write(self, data):
                Tracked.count += 1
                if Tracked.count == nth:
                    self.f.flush()
                    raise Crash()
                return self.f.write(data)

        def fake_open(path, mode="r", *a, **k):
            f = real_open(path, mode, *a, **k)
            return Tracked(f) if str(path) == vault and mode == "r+b" else f

        return Crash, fake_open

    def test_interrupted_save_keeps_last_good_state(self):
        """Eski katalog yenisi yazılmadan sıfırlanıyordu; kesinti kasanın tamamını kaybettiriyordu."""
        auth = self.create()
        E.write_file_bytes(self.vault, auth, "onemli.txt", b"onemli veri")
        for nth in range(1, 6):
            session = dict(auth)
            catalog = E.load_catalog(self.vault, session)
            Crash, fake_open = self._crash_on_write(nth)
            builtins.open = fake_open
            try:
                E._save_catalog(self.vault, session, catalog)
            except Crash:
                pass
            finally:
                builtins.open = __import__("io").open
            fresh = E.authenticate(self.vault, PW)
            self.assertEqual(E.extract_file_bytes(self.vault, fresh, "onemli.txt")[0], b"onemli veri", nth)
            auth = fresh

    def test_missing_slot_key_fails_loudly(self):
        """Yuva anahtarı yoksa katalog yazılıp yuva çevrilmiyor, kasa bozuluyordu."""
        auth = self.create()
        auth.pop("kdf_key")
        with self.assertRaises(CustomVaultError):
            E.add_folder(self.vault, auth, "klasor")
        self.assertEqual(E.load_catalog(self.vault, E.authenticate(self.vault, PW))["folders"], [])

class Streaming(Base):
    def test_large_file_roundtrip_without_ram_copy(self):
        auth = self.create(max_size_mb=512)
        big = self.dir / "buyuk.bin"
        block = os.urandom(1024 * 1024)
        with open(big, "wb") as f:
            for _ in range(40):
                f.write(block)
        digest = hashlib.sha256(big.read_bytes()).hexdigest()
        entry = E.add_file(self.vault, auth, str(big), "video/buyuk.bin")["entry"]
        self.assertEqual(entry["chunk_size"], enclave_core.STREAM_CHUNK_SIZE)
        out = self.dir / "cikti.bin"
        fresh = E.authenticate(self.vault, PW)
        result = E.extract_file(self.vault, fresh, entry["id"], str(out))
        self.assertEqual(result["sha256"], digest)
        self.assertEqual(hashlib.sha256(out.read_bytes()).hexdigest(), digest)

    def test_empty_and_chunk_boundary_files(self):
        auth = self.create(max_size_mb=64)
        for size in (0, enclave_core.STREAM_CHUNK_SIZE, enclave_core.STREAM_CHUNK_SIZE + 1):
            src = self.dir / f"f{size}.bin"
            src.write_bytes(b"x" * size)
            E.add_files(self.vault, auth, [(str(src), src.name)])
            self.assertEqual(E.extract_file_bytes(self.vault, auth, src.name)[0], b"x" * size)

    def test_chunk_reorder_and_tamper_rejected(self):
        auth = self.create(max_size_mb=64)
        src = self.dir / "s.bin"
        src.write_bytes(os.urandom(enclave_core.STREAM_CHUNK_SIZE * 2 + 10))
        entry = E.add_files(self.vault, auth, [(str(src), "s.bin")])["entries"][0]
        chunk = enclave_core.STREAM_CHUNK_SIZE + 16
        with open(self.vault, "r+b") as f:
            f.seek(entry["offset"])
            first = f.read(chunk)
            second = f.read(chunk)
            f.seek(entry["offset"])
            f.write(second + first)
        out = self.dir / "o.bin"
        with self.assertRaises(VaultTamperedError):
            E.extract_file(self.vault, auth, entry["id"], str(out))
        self.assertFalse(out.exists())
        self.assertEqual([p.name for p in self.dir.glob("*.part")], [])

    def test_batch_stores_one_catalog(self):
        auth = self.create()
        items = []
        for i in range(50):
            src = self.dir / f"k{i}.txt"
            src.write_bytes(b"veri")
            items.append((str(src), f"k/{i}.txt"))
        E.add_files(self.vault, auth, items)
        self.assertLess(os.path.getsize(self.vault), 40_000)
        self.assertEqual(len(E.load_catalog(self.vault, auth)["files"]), 50)

class SpaceReuse(Base):
    def test_metadata_edits_do_not_grow_file(self):
        """Her katalog kaydı dosyayı şişiriyordu."""
        auth = self.create()
        for i in range(10):
            E.add_folder(self.vault, auth, f"k{i}")
        before = os.path.getsize(self.vault)
        for i in range(200):
            E.add_folder(self.vault, auth, f"m{i}")
        self.assertLess(os.path.getsize(self.vault), before + 40_000)
        fresh = E.authenticate(self.vault, PW)
        self.assertEqual(len(E.load_catalog(self.vault, fresh)["folders"]), 210)

    def test_deleted_space_is_reused_and_zeroed(self):
        auth = self.create()
        secret = os.urandom(300_000)
        entry = E.write_file_bytes(self.vault, auth, "a.bin", secret)["entry"]
        sealed = Path(self.vault).read_bytes()[entry["offset"]:entry["offset"] + 64]
        size = os.path.getsize(self.vault)
        E.delete_file(self.vault, auth, entry["id"])
        self.assertNotIn(sealed, Path(self.vault).read_bytes())
        E.write_file_bytes(self.vault, auth, "b.bin", os.urandom(290_000))
        self.assertLessEqual(os.path.getsize(self.vault), size + 8192)

    def test_overwrite_and_folder_delete_release_space(self):
        auth = self.create()
        for _ in range(5):
            E.write_file_bytes(self.vault, auth, "x/a.bin", os.urandom(200_000))
        self.assertLess(os.path.getsize(self.vault), 900_000)
        E.delete_folder(self.vault, auth, "x")
        self.assertGreater(sum(l for _, l in E.load_catalog(self.vault, auth)["free"]), 190_000)

class Names(Base):
    def test_rename_is_validated(self):
        auth = self.create()
        a = E.write_file_bytes(self.vault, auth, "a.txt", b"1")["entry"]
        E.write_file_bytes(self.vault, auth, "b.txt", b"2")
        for bad in ("C:/Windows/evil.txt", "../kacis.txt", "CON.txt", "b.txt"):
            with self.assertRaises(CustomVaultError, msg=bad):
                E.rename_file(self.vault, auth, a["id"], bad)

    def test_folder_cannot_move_into_itself(self):
        auth = self.create()
        E.add_folder(self.vault, auth, "a")
        with self.assertRaises(CustomVaultError):
            E.rename_folder(self.vault, auth, "a", "a/b")

    def test_foreign_names_become_portable(self):
        self.assertEqual(safe_vault_name('soru?: "evet".txt'), 'soru__ _evet_.txt')
        self.assertEqual(safe_vault_name("CON.txt"), "_CON.txt")
        self.assertEqual(safe_vault_name("nokta. "), "nokta")
        enclave_core._sanitize_vault_rel_path(safe_vault_name('a<b>:c|d?.txt'))

class Passwords(Base):
    def test_unicode_form_does_not_lock_user_out(self):
        """macOS ayrışık (NFD) Unicode gönderebilir; aynı parola farklı baytlara dönüşüyordu."""
        password = "şifre-çöğüş-İ"
        E.create_vault(self.vault, unicodedata.normalize("NFC", password))
        E.authenticate(self.vault, unicodedata.normalize("NFD", password))

    def test_change_password(self):
        auth = self.create(decoy_password=DECOY_PW)
        E.write_file_bytes(self.vault, auth, "a.txt", b"veri")
        E.change_password(self.vault, auth, "YeniParola@999")
        with self.assertRaises(InvalidPasswordError):
            E.authenticate(self.vault, PW)
        fresh = E.authenticate(self.vault, "YeniParola@999")
        self.assertEqual(E.extract_file_bytes(self.vault, fresh, "a.txt")[0], b"veri")
        E.authenticate(self.vault, DECOY_PW)
        E.add_folder(self.vault, auth, "sonra")
        self.assertIn("sonra", E.load_catalog(self.vault, E.authenticate(self.vault, "YeniParola@999"))["folders"])

    def test_change_password_revokes_old_master_key(self):
        """Eski başlık ve eski parola, parola değişiminden sonraki kasadaki hiçbir veriyi açmamalı."""
        auth = self.create()
        E.write_file_bytes(self.vault, auth, "a.txt", b"eski veri")
        old_key = auth["master_key"]
        E.change_password(self.vault, auth, "YeniParola@999")
        E.write_file_bytes(self.vault, auth, "b.txt", b"yeni veri")
        self.assertNotEqual(auth["master_key"], old_key)
        fresh = E.authenticate(self.vault, "YeniParola@999")
        catalog = E.load_catalog(self.vault, fresh)
        blob = Path(self.vault).read_bytes()
        for entry in catalog["files"]:
            prefix = bytes.fromhex(entry["nonce"])
            sealed = blob[entry["offset"]:entry["offset"] + entry["len"]]
            nonce = E._stream_nonce(prefix, 0, True) if entry.get("chunk_size") else prefix
            with self.assertRaises(InvalidTag):
                AESGCM(old_key).decrypt(nonce, sealed, entry["id"].encode("ascii"))
        self.assertEqual(E.extract_file_bytes(self.vault, fresh, "a.txt")[0], b"eski veri")

    def test_change_password_keeps_large_files_and_mtime(self):
        auth = self.create()
        data = os.urandom(enclave_core.STREAM_THRESHOLD + 5000)
        source = self.dir / "buyuk.bin"
        source.write_bytes(data)
        E.add_file(self.vault, auth, str(source), "buyuk.bin")
        mtime = E.load_catalog(self.vault, auth)["files"][0]["mtime"]
        E.change_password(self.vault, auth, "YeniParola@999")
        fresh = E.authenticate(self.vault, "YeniParola@999")
        self.assertEqual(E.extract_file_bytes(self.vault, fresh, "buyuk.bin")[0], data)
        self.assertEqual(E.load_catalog(self.vault, fresh)["files"][0]["mtime"], mtime)

    def test_interrupted_change_password_leaves_vault_unchanged(self):
        auth = self.create()
        E.write_file_bytes(self.vault, auth, "a.txt", b"veri")
        size = os.path.getsize(self.vault)
        with self.assertRaises(CustomVaultError):
            E.change_password(self.vault, auth, "YeniParola@999", should_cancel=lambda: True)
        self.assertEqual(os.path.getsize(self.vault), size)
        self.assertEqual(E.extract_file_bytes(self.vault, auth, "a.txt")[0], b"veri")
        self.assertEqual(E.extract_file_bytes(self.vault, E.authenticate(self.vault, PW), "a.txt")[0], b"veri")

    def test_fixed_vault_without_room_refuses_change_password(self):
        auth = self.create(max_size_mb=1, is_dynamic=False)
        E.write_file_bytes(self.vault, auth, "a.bin", os.urandom(700 * 1024))
        with self.assertRaises(CustomVaultError):
            E.change_password(self.vault, auth, "YeniParola@999")
        fresh = E.authenticate(self.vault, PW)
        self.assertEqual(len(E.extract_file_bytes(self.vault, fresh, "a.bin")[0]), 700 * 1024)

    def test_transfer_stops_inside_a_large_file(self):
        auth = self.create()
        source = self.dir / "buyuk.bin"
        source.write_bytes(os.urandom(3 * enclave_core.STREAM_CHUNK_SIZE))
        calls = []
        with self.assertRaises(CustomVaultError):
            E.add_files(self.vault, auth, [(str(source), "buyuk.bin")], should_cancel=lambda: calls.append(1) or len(calls) > 2)
        self.assertEqual(E.load_catalog(self.vault, E.authenticate(self.vault, PW))["files"], [])

    @unittest.skipUnless(sys.platform == "win32", "PowerShell yalnızca Windows'ta")
    def test_powershell_quotes_cannot_break_out(self):
        from engine import VHDEngine, _ps_literal
        for quote in "'\u2018\u2019\u201a\u201b":
            marker = self.dir / f"izi{ord(quote)}"
            value = f"a{quote}; New-Item -Path '{marker}'; {quote}b"
            code, out, _err = VHDEngine._run_powershell(f"Write-Output '{_ps_literal(value)}'")
            self.assertEqual((code, out), (0, value))
            self.assertFalse(marker.exists())

    @unittest.skipUnless(sys.platform == "win32", "Yalnızca Windows sürücü harfleri")
    def test_drive_letter_filter(self):
        from engine import _clean_drive_letter
        self.assertEqual(_clean_drive_letter("z:\\"), "Z")
        self.assertEqual(_clean_drive_letter("Z'; calc; '"), "")
        self.assertEqual(_clean_drive_letter(None), "")

    def test_key_file_is_required_with_password(self):
        auth = self.create(decoy_password=DECOY_PW)
        E.write_file_bytes(self.vault, auth, "a.txt", b"veri")
        path = str(self.dir / "kasa.key")
        digest = enclave_core.create_key_file(path)
        E.change_password(self.vault, auth, PW, key_digest=digest)
        with self.assertRaises(InvalidPasswordError):
            E.authenticate(self.vault, PW)
        with self.assertRaises(InvalidPasswordError):
            E.authenticate(self.vault, PW, hashlib.sha256(b"baska dosya").digest())
        fresh = E.authenticate(self.vault, PW, enclave_core.read_key_file(path))
        self.assertEqual(E.extract_file_bytes(self.vault, fresh, "a.txt")[0], b"veri")
        self.assertTrue(E.load_catalog(self.vault, fresh)["key_file"])
        E.authenticate(self.vault, DECOY_PW)

    def test_key_file_survives_password_change_and_can_be_removed(self):
        auth = self.create()
        digest = enclave_core.create_key_file(str(self.dir / "kasa.key"))
        E.change_password(self.vault, auth, PW, key_digest=digest)
        E.change_password(self.vault, auth, "YeniParola@999")
        with self.assertRaises(InvalidPasswordError):
            E.authenticate(self.vault, "YeniParola@999")
        fresh = E.authenticate(self.vault, "YeniParola@999", digest)
        E.change_password(self.vault, fresh, "YeniParola@999", key_digest=None)
        self.assertFalse(E.load_catalog(self.vault, E.authenticate(self.vault, "YeniParola@999"))["key_file"])

    def test_recovery_key_works_without_key_file(self):
        """Dosya kaybolursa tek yol kurtarma anahtarıdır; yeni parola dosyasız çalışmalı."""
        auth = self.create()
        E.write_file_bytes(self.vault, auth, "a.txt", b"veri")
        digest = enclave_core.create_key_file(str(self.dir / "kasa.key"))
        E.change_password(self.vault, auth, PW, key_digest=digest)
        recovered = E.authenticate_with_recovery_key(self.vault, E.get_recovery_key(auth))
        E.change_password(self.vault, recovered, "YeniParola@999")
        fresh = E.authenticate(self.vault, "YeniParola@999")
        self.assertEqual(E.extract_file_bytes(self.vault, fresh, "a.txt")[0], b"veri")

    def test_key_file_never_overwrites_and_rejects_empty(self):
        path = self.dir / "kasa.key"
        enclave_core.create_key_file(str(path))
        original = path.read_bytes()
        with self.assertRaises(CustomVaultError):
            enclave_core.create_key_file(str(path))
        self.assertEqual(path.read_bytes(), original)
        empty = self.dir / "bos.key"
        empty.write_bytes(b"")
        with self.assertRaises(CustomVaultError):
            enclave_core.read_key_file(str(empty))

    def test_totp_code_works_only_once(self):
        secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
        auth = self.create(two_factor_secret=secret)
        code = totp_engine.get_totp_token(secret)
        self.assertTrue(E.verify_vault_2fa(self.vault, auth, code)[0])
        self.assertFalse(E.verify_vault_2fa(self.vault, auth, code)[0])
        fresh = E.authenticate(self.vault, PW)
        self.assertFalse(E.verify_vault_2fa(self.vault, fresh, code)[0])
        newer = totp_engine.get_totp_token(secret, for_time=int(time.time()) + 30)
        self.assertTrue(E.verify_vault_2fa(self.vault, fresh, newer)[0])

    def test_new_vault_uses_argon2id(self):
        auth = self.create()
        self.assertEqual(auth["version"], enclave_core.VERSION)
        self.assertEqual(auth["kdf_params"], (3, 4, 18))

    def test_hostile_kdf_parameters_rejected(self):
        self.create()
        with open(self.vault, "r+b") as f:
            f.seek(enclave_core.HEADER_KDF_OFFSET + 3)
            f.write(bytes([40]))
        with self.assertRaises(CustomVaultError):
            E.authenticate(self.vault, PW)

class LegacyFormat(Base):
    """Kullanıcının mevcut biçim 1 kasaları açılmaya ve yazılmaya devam etmelidir."""

    def make_v1(self, decoy=None):
        salt, master, nonce = os.urandom(32), os.urandom(32), os.urandom(12)

        def derive(pw):
            return PBKDF2HMAC(hashes.SHA256(), 32, salt, 600000).derive(pw.encode())

        toc = {"label": "Eski", "is_decoy": False, "is_dynamic": True, "max_size_gb": 1,
               "max_size_mb": 1024, "base_offset": 256, "files": []}
        cipher = AESGCM(master).encrypt(nonce, zlib.compress(__import__("json").dumps(toc).encode()), b"TOC_REAL")
        payload = master + struct.pack("<QQ", 256, len(cipher)) + nonce
        slot_nonce = os.urandom(12)
        slot1 = slot_nonce + AESGCM(derive(PW)).encrypt(slot_nonce, payload, b"SLOT1")
        slot2 = os.urandom(88)
        header = b"PVAULT01" + struct.pack("<I", 1) + salt + slot1 + slot2 + struct.pack("<I", 1) + bytes(3) + os.urandom(29)
        Path(self.vault).write_bytes(header + cipher)

    def test_open_write_reopen(self):
        self.make_v1()
        auth = E.authenticate(self.vault, PW)
        self.assertEqual(auth["version"], 1)
        E.write_file_bytes(self.vault, auth, "a.txt", b"eski kasa")
        E.add_folder(self.vault, auth, "yeni")
        fresh = E.authenticate(self.vault, PW)
        self.assertEqual(E.extract_file_bytes(self.vault, fresh, "a.txt")[0], b"eski kasa")
        self.assertTrue(E.verify_header(self.vault)["valid"])

    def test_change_password_keeps_format(self):
        self.make_v1()
        auth = E.authenticate(self.vault, PW)
        E.change_password(self.vault, auth, "Yeni@12345")
        self.assertEqual(E.authenticate(self.vault, "Yeni@12345")["version"], 1)

class Locking(Base):
    def test_second_opener_refused_until_release(self):
        self.create()
        first, second = VaultFileLock(self.vault), VaultFileLock(self.vault)
        first.acquire()
        self.addCleanup(first.release)
        with self.assertRaises(CustomVaultError):
            second.acquire()
        Path(self.vault).read_bytes()
        first.release()
        second.acquire()
        second.release()

class TempFiles(Base):
    def test_view_copy_is_private_and_wiped(self):
        auth = self.create()
        E.write_file_bytes(self.vault, auth, "a.txt", b"gizli")
        path, _ = E.extract_to_temp_for_viewing(self.vault, auth, "a.txt")
        self.assertTrue(path.startswith(enclave_core.secure_temp_root()))
        self.assertEqual(Path(path).read_bytes(), b"gizli")
        self.assertEqual(sorted(p.name for p in Path(path).parent.iterdir()), ["a.txt"])
        enclave_core.purge_all_vault_temp_forensics()
        self.assertFalse(Path(path).exists())

if __name__ == "__main__":
    unittest.main()
