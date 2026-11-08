"""
Enclave - Steganografik / Poliglot Kamuflaj Kasa Test Paketi
"""

import os
import shutil
import tempfile
import unittest
from pathlib import Path

from enclave_core import CustomVaultEngine as E, InvalidPasswordError, CustomVaultError
from stego_enclave import create_stego_vault, inspect_stego_anchor, STEGO_ANCHOR_SIZE

class TestStegoVault(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="pvault_stego_test_")
        self.dir = Path(self.temp_dir)
        self.carrier_path = self.dir / "sample_video.mp4"
        ftyp_atom = b"\x00\x00\x00\x18ftypisom\x00\x00\x02\x00isomiso2mp41"
        media_payload = os.urandom(16 * 1024 - len(ftyp_atom))
        self.carrier_bytes = ftyp_atom + media_payload
        self.carrier_path.write_bytes(self.carrier_bytes)
        self.vault_path = self.dir / "kasa_video.mp4"
        self.pw = "Guv3nli!P@ssw0rd99"
        self.decoy_pw = "Tuz@kP@ssw0rd12"

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_create_and_authenticate_stego_vault(self):
        res = create_stego_vault(
            carrier_source_path=str(self.carrier_path),
            target_vault_path=str(self.vault_path),
            password=self.pw,
            max_size_gb=1,
            is_dynamic=True
        )
        self.assertTrue(res["success"])
        self.assertTrue(self.vault_path.exists())

        vault_raw = self.vault_path.read_bytes()
        self.assertNotIn(b"PVAULT01", vault_raw)
        self.assertNotIn(b"PSTG01", vault_raw)

        carrier_len = len(self.carrier_bytes)
        self.assertEqual(vault_raw[:carrier_len], self.carrier_bytes)

        auth = E.authenticate(str(self.vault_path), self.pw)
        self.assertTrue(auth["authenticated"])
        self.assertTrue(auth.get("is_stego"))
        self.assertEqual(auth.get("carrier_offset"), carrier_len)

        with self.assertRaises((InvalidPasswordError, CustomVaultError)):
            E.authenticate(str(self.vault_path), "YanlisParola123")

    def test_stego_vault_file_operations(self):
        create_stego_vault(
            carrier_source_path=str(self.carrier_path),
            target_vault_path=str(self.vault_path),
            password=self.pw,
            max_size_gb=1,
            is_dynamic=True
        )
        auth = E.authenticate(str(self.vault_path), self.pw)

        secret_content = b"Cok gizli kamuflaj verisi 1234567890" * 100
        write_res = E.write_file_bytes(str(self.vault_path), auth, "notlar/gizli.txt", secret_content)
        self.assertTrue(write_res["success"])

        read_data, entry = E.extract_file_bytes(str(self.vault_path), auth, "notlar/gizli.txt")
        self.assertEqual(read_data, secret_content)
        self.assertEqual(entry["path"], "notlar/gizli.txt")

        re_auth = E.authenticate(str(self.vault_path), self.pw)
        catalog = E.load_catalog(str(self.vault_path), re_auth)
        self.assertEqual(len(catalog["files"]), 1)
        self.assertEqual(catalog["files"][0]["path"], "notlar/gizli.txt")

        vault_raw = self.vault_path.read_bytes()
        self.assertEqual(vault_raw[:len(self.carrier_bytes)], self.carrier_bytes)

    def test_stego_vault_decoy_compartment(self):
        create_stego_vault(
            carrier_source_path=str(self.carrier_path),
            target_vault_path=str(self.vault_path),
            password=self.pw,
            decoy_password=self.decoy_pw,
            max_size_gb=1,
            is_dynamic=True
        )

        auth_real = E.authenticate(str(self.vault_path), self.pw)
        E.write_file_bytes(str(self.vault_path), auth_real, "ana.txt", b"ana bolme verisi")

        auth_decoy = E.authenticate(str(self.vault_path), self.decoy_pw)
        E.write_file_bytes(str(self.vault_path), auth_decoy, "tuzak.txt", b"tuzak bolme verisi")

        cat_real = E.load_catalog(str(self.vault_path), E.authenticate(str(self.vault_path), self.pw))
        self.assertEqual([f["path"] for f in cat_real["files"]], ["ana.txt"])

        cat_decoy = E.load_catalog(str(self.vault_path), E.authenticate(str(self.vault_path), self.decoy_pw))
        self.assertEqual([f["path"] for f in cat_decoy["files"]], ["tuzak.txt"])

    def test_stego_vault_change_password(self):
        create_stego_vault(
            carrier_source_path=str(self.carrier_path),
            target_vault_path=str(self.vault_path),
            password=self.pw,
            max_size_gb=1,
            is_dynamic=True
        )
        auth = E.authenticate(str(self.vault_path), self.pw)
        E.write_file_bytes(str(self.vault_path), auth, "belge.txt", b"gizli veri icerigi")

        new_pw = "Yen1!Parola_9988"
        E.change_password(str(self.vault_path), auth, new_pw)

        with self.assertRaises((InvalidPasswordError, CustomVaultError)):
            E.authenticate(str(self.vault_path), self.pw)

        new_auth = E.authenticate(str(self.vault_path), new_pw)
        data, _ = E.extract_file_bytes(str(self.vault_path), new_auth, "belge.txt")
        self.assertEqual(data, b"gizli veri icerigi")

        vault_raw = self.vault_path.read_bytes()
        self.assertEqual(vault_raw[:len(self.carrier_bytes)], self.carrier_bytes)

    def test_stego_vault_tampering_detected(self):
        create_stego_vault(
            carrier_source_path=str(self.carrier_path),
            target_vault_path=str(self.vault_path),
            password=self.pw,
            max_size_gb=1,
            is_dynamic=True
        )
        auth = E.authenticate(str(self.vault_path), self.pw)
        res = E.write_file_bytes(str(self.vault_path), auth, "test.txt", b"guvenli icerik")
        entry = res["entry"]

        raw = bytearray(self.vault_path.read_bytes())
        raw[entry["offset"] + 5] ^= 0xFF
        self.vault_path.write_bytes(bytes(raw))

        re_auth = E.authenticate(str(self.vault_path), self.pw)
        with self.assertRaises(Exception):
            E.extract_file_bytes(str(self.vault_path), re_auth, "test.txt")

    def test_wrap_and_strip_carrier(self):
        from stego_enclave import wrap_vault_into_carrier, strip_carrier_from_vault
        standalone_path = self.dir / "orijinal.pvault"
        E.create_vault(str(standalone_path), self.pw, decoy_password=self.decoy_pw)
        auth = E.authenticate(str(standalone_path), self.pw)
        E.write_file_bytes(str(standalone_path), auth, "belge1.txt", b"ana bolme verisi 12345")
        auth_decoy = E.authenticate(str(standalone_path), self.decoy_pw)
        E.write_file_bytes(str(standalone_path), auth_decoy, "tuzak1.txt", b"tuzak bolme verisi 67890")

        stego_target = self.dir / "kamuflaj.mp4"
        wrap_res = wrap_vault_into_carrier(
            source_vault_path=str(standalone_path),
            carrier_source_path=str(self.carrier_path),
            target_vault_path=str(stego_target),
            password=self.pw,
            decoy_password=self.decoy_pw
        )
        self.assertTrue(wrap_res["success"])
        self.assertEqual(wrap_res["files_transferred"], 1)

        raw_stego = stego_target.read_bytes()
        self.assertEqual(raw_stego[:len(self.carrier_bytes)], self.carrier_bytes)
        self.assertNotIn(b"PVAULT01", raw_stego)

        stego_auth = E.authenticate(str(stego_target), self.pw)
        data, _ = E.extract_file_bytes(str(stego_target), stego_auth, "belge1.txt")
        self.assertEqual(data, b"ana bolme verisi 12345")

        stego_decoy_auth = E.authenticate(str(stego_target), self.decoy_pw)
        decoy_data, _ = E.extract_file_bytes(str(stego_target), stego_decoy_auth, "tuzak1.txt")
        self.assertEqual(decoy_data, b"tuzak bolme verisi 67890")

        stripped_target = self.dir / "saf_kasa.pvault"
        strip_res = strip_carrier_from_vault(
            stego_vault_path=str(stego_target),
            target_vault_path=str(stripped_target),
            password=self.pw,
            decoy_password=self.decoy_pw
        )
        self.assertTrue(strip_res["success"])

        raw_stripped = stripped_target.read_bytes()
        self.assertTrue(raw_stripped.startswith(b"PVAULT01"))

        stripped_auth = E.authenticate(str(stripped_target), self.pw)
        s_data, _ = E.extract_file_bytes(str(stripped_target), stripped_auth, "belge1.txt")
        self.assertEqual(s_data, b"ana bolme verisi 12345")

        stripped_decoy_auth = E.authenticate(str(stripped_target), self.decoy_pw)
        sd_data, _ = E.extract_file_bytes(str(stripped_target), stripped_decoy_auth, "tuzak1.txt")
        self.assertEqual(sd_data, b"tuzak bolme verisi 67890")

if __name__ == "__main__":
    unittest.main()
