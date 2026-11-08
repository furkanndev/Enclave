"""
Enclave - Bağımsız AES-256 Kasa Motoru Kapsamlı Test Paketi
Tüm şifreleme, tuzak kasa (decoy), dosya ekleme/çıkarma, bütünlük ve sıkıştırma fonksiyonlarını test eder.
"""

import os
import sys
import base64
import struct
import shutil
import tempfile
import hashlib
from pathlib import Path

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from enclave_core import (
    CustomVaultEngine,
    InvalidPasswordError,
    VaultTamperedError,
    secure_wipe_file
)

def run_all_tests():
    print("=== BAĞIMSIZ AES-256 KASA MOTORU TESTLERİ BAŞLIYOR ===")
    test_dir = Path(tempfile.mkdtemp(prefix="pvault_test_"))
    try:
        vault_file = test_dir / "test_secure.pvault"
        main_pw = "AnaParola@2026!Secret"
        decoy_pw = "TuzakParola@999!Decoy"
        wrong_pw = "TamamenYanlisSifre123"

        print("\n[TEST 1] Kasa oluşturuluyor (Ana + Tuzak şifreli)...")
        res_create = CustomVaultEngine.create_vault(
            vault_path=str(vault_file),
            password=main_pw,
            label="Gizli Belgeler",
            decoy_password=decoy_pw
        )
        assert res_create["success"], "Kasa oluşturma başarısız!"
        assert vault_file.exists(), "Kasa dosyası diske yazılamadı!"
        print(f"  -> Başarılı: {vault_file.name} ({vault_file.stat().st_size} bayt)")

        print("\n[TEST 2] Yanlış parola denemesi...")
        try:
            CustomVaultEngine.authenticate(str(vault_file), wrong_pw)
            assert False, "Yanlış parola kabul edildi, GÜVENLİK AÇIĞI!"
        except InvalidPasswordError:
            print("  -> Başarılı: Yanlış parola doğru şekilde anında reddedildi.")

        print("\n[TEST 3] Ana parola ile kimlik doğrulama...")
        auth_main = CustomVaultEngine.authenticate(str(vault_file), main_pw)
        assert auth_main["authenticated"], "Ana kasa açılamadı!"
        print("  -> Başarılı: Ana kasa doğrulandı")

        print("\n[TEST 4] Tuzak parola ile kimlik doğrulama...")
        auth_decoy = CustomVaultEngine.authenticate(str(vault_file), decoy_pw)
        assert auth_decoy["authenticated"], "Tuzak kasa açılamadı!"
        assert auth_decoy["master_key"] != auth_main["master_key"], "Bölmeler aynı anahtarı kullanıyor!"
        print("  -> Başarılı: İkinci bölme ayrı anahtarla doğrulandı")

        print("\n[TEST 5] Ana kasaya dosyalar ekleniyor...")
        f1 = test_dir / "rapor.txt"
        f1.write_text("Bu çok gizli ana kasa raporudur. Türkçe karakterler: ğüşıöç ĞÜŞİÖÇ", encoding="utf-8")
        
        f2 = test_dir / "resim.bin"
        f2.write_bytes(os.urandom(65536))
        f2_sha = hashlib.sha256(f2.read_bytes()).hexdigest()

        CustomVaultEngine.add_file(str(vault_file), auth_main, str(f1), "belgeler/rapor.txt")
        CustomVaultEngine.add_file(str(vault_file), auth_main, str(f2), "fotolar/resim.bin")

        cat_main = CustomVaultEngine.load_catalog(str(vault_file), auth_main)
        assert len(cat_main["files"]) == 2, f"Ana kasada 2 dosya olmalıydı, {len(cat_main['files'])} var!"
        print(f"  -> Başarılı: 2 dosya şifrelendi ve eklendi: {[f['path'] for f in cat_main['files']]}")

        print("\n[TEST 6] Tuzak kasaya sahte dosya ekleniyor...")
        f_decoy = test_dir / "alisveris.txt"
        f_decoy.write_text("Süt, Ekmek, Peynir, Elma", encoding="utf-8")
        CustomVaultEngine.add_file(str(vault_file), auth_decoy, str(f_decoy), "notlar/alisveris.txt")

        cat_decoy = CustomVaultEngine.load_catalog(str(vault_file), auth_decoy)
        assert len(cat_decoy["files"]) == 1, "Tuzak kasada tam 1 dosya olmalı!"
        assert cat_decoy["files"][0]["path"] == "notlar/alisveris.txt", "Tuzak dosya adı uyuşmuyor!"
        print("  -> Başarılı: Tuzak kasaya yalnızca sahte dosya eklendi, ana dosyalar tuzak kasada ASLA görünmüyor!")

        cat_main_check = CustomVaultEngine.load_catalog(str(vault_file), auth_main)
        assert len(cat_main_check["files"]) == 2, "Tuzak dosya ana kasaya karıştı!"
        print("  -> Başarılı: Ana kasa ve tuzak kasa tamamen birbirinden izole!")

        print("\n[TEST 7] Şifreli dosya çözülüyor ve SHA-256 doğrulanıyor...")
        out_f2 = test_dir / "cikarilan_resim.bin"
        res_ext = CustomVaultEngine.extract_file(str(vault_file), auth_main, "fotolar/resim.bin", str(out_f2))
        assert res_ext["sha256"] == f2_sha, "Çözülen dosyanın SHA-256 özeti eşleşmiyor!"
        assert out_f2.read_bytes() == f2.read_bytes(), "Dosya içeriği bayt bayt uyuşmuyor!"
        print("  -> Başarılı: 64 KB ikili veri bayt bayt kusursuz çözüldü ve doğrulandı.")

        print("\n[TEST 8] Geçici güvenli önizleme ve imha (shredding)...")
        temp_view_path, _ = CustomVaultEngine.extract_to_temp_for_viewing(str(vault_file), auth_main, "belgeler/rapor.txt")
        assert Path(temp_view_path).exists(), "Geçici dosya oluşturulamadı!"
        
        wiped = secure_wipe_file(temp_view_path, passes=2)
        assert wiped, "Güvenli silme işlemi başarısız!"
        assert not Path(temp_view_path).exists(), "Geçici dosya imha edilemedi!"
        print("  -> Başarılı: Geçici dosya bellekten okundu ve DoD standardında güvenle parçalandı.")

        print("\n[TEST 9] Dosya silme ve kasa sıkıştırma...")
        size_before = vault_file.stat().st_size
        CustomVaultEngine.delete_file(str(vault_file), auth_main, "belgeler/rapor.txt")
        cat_after_del = CustomVaultEngine.load_catalog(str(vault_file), auth_main)
        assert len(cat_after_del["files"]) == 1, "Dosya silinemedi!"

        res_compact = CustomVaultEngine.compact_vault(str(vault_file), auth_main, discard_other_compartment=True)
        size_after = vault_file.stat().st_size
        print(f"  -> Başarılı: Dosya silindi, kasa sıkıştırıldı (Eski: {size_before} bayt -> Yeni: {size_after} bayt)")

        print("\n[TEST 10] Kasa dosyasına rastgele tahrifat enjekte ediliyor (Bozulma testi)...")
        with open(vault_file, "r+b") as f:
            f.seek(300)
            b = f.read(1)
            f.seek(300)
            f.write(bytes([b[0] ^ 0xFF]))

        try:
            CustomVaultEngine.extract_file(str(vault_file), auth_main, "fotolar/resim.bin", str(test_dir / "tampered.bin"))
            assert False, "Tahrif edilmiş dosya içeriği kabul edildi, AEAD dosya güvenliği çalışmıyor!"
        except VaultTamperedError:
            print("  -> Başarılı: Dosya gövdesi tahrifatı derhal yakalandı (AEAD Tag Mismatch).")

        with open(vault_file, "r+b") as f:
            f.seek(auth_main["toc_offset"] + 2)
            b = f.read(1)
            f.seek(auth_main["toc_offset"] + 2)
            f.write(bytes([b[0] ^ 0xFF]))

        try:
            CustomVaultEngine.load_catalog(str(vault_file), auth_main)
            assert False, "Tahrif edilmiş katalog kabul edildi, AEAD katalog güvenliği çalışmıyor!"
        except VaultTamperedError:
            print("  -> Başarılı: Katalog tahrifatı derhal yakalandı (AEAD Tag Mismatch).")

        print("\n[TEST 11] Kapasite boyutu (5 GB) ve kota aşım testi...")
        v_quota_file = test_dir / "quota_vault.pvault"
        res_q = CustomVaultEngine.create_vault(
            str(v_quota_file),
            password="KotaParolasi@123",
            label="Kota Test Kasa",
            max_size_gb=5
        )
        assert res_q["success"], "Kota kasası oluşturulamadı!"
        
        import struct
        with open(v_quota_file, "rb") as qf:
            qf.seek(220)
            sz_raw = qf.read(4)
            sz_unpacked = struct.unpack("<I", sz_raw)[0]
            assert sz_unpacked == 5, f"Offset 220'deki boyut {sz_unpacked} GB, 5 olmalıydı!"
        print("  -> Başarılı: Başlık offset 220'de 5 GB kapasite bilgisi doğrulandı.")

        if sys.platform == "win32":
            from engine import VHDEngine
            v_info = VHDEngine.get_vhd_virtual_size(str(v_quota_file))
            assert v_info["virtual_mb"] == 5120.0, f"Sanal boyut 5120 MB olmalıydı, {v_info.get('virtual_mb')} geldi!"
            assert v_info["virtual_gb"] == 5.0, f"Sanal boyut 5 GB olmalıydı, {v_info.get('virtual_gb')} geldi!"
            print("  -> Başarılı: VHDEngine.get_vhd_virtual_size bağımsız kasanın 5 GB kapasitesini anında tanıdı.")

        v_small = test_dir / "small_vault.pvault"
        CustomVaultEngine.create_vault(str(v_small), "Small@123", max_size_mb=1)
        auth_s = CustomVaultEngine.authenticate(str(v_small), "Small@123")

        f_huge = test_dir / "huge.bin"
        f_huge.write_bytes(os.urandom(2 * 1024 * 1024))
        try:
            from enclave_core import CustomVaultError
            CustomVaultEngine.add_file(str(v_small), auth_s, str(f_huge), "huge.bin")
            assert False, "Kota aşımı yakalanamadı, yetersiz alan kontrolü çalışmıyor!"
        except CustomVaultError as ce:
            assert "kapasitesi" in str(ce).lower() or "kota" in str(ce).lower(), f"Beklenmeyen hata mesajı: {ce}"
            print("  -> Başarılı: Kota aşımı tespit edildi ve dosya ekleme engellendi.")

        print("\n[TEST 12] Klasör yönetimi, yeniden adlandırma ve bellekten okuma...")
        v_folder = test_dir / "folder_test.pvault"
        CustomVaultEngine.create_vault(str(v_folder), "Folder@123")
        auth_f = CustomVaultEngine.authenticate(str(v_folder), "Folder@123")

        CustomVaultEngine.add_folder(str(v_folder), auth_f, "Müzikler")
        CustomVaultEngine.add_folder(str(v_folder), auth_f, "Resimler/Doğa")

        sample_audio = test_dir / "sample.mp3"
        sample_audio.write_bytes(b"ID3" + os.urandom(1024))
        CustomVaultEngine.add_file(str(v_folder), auth_f, str(sample_audio), "Müzikler/sample.mp3")

        cat_f = CustomVaultEngine.load_catalog(str(v_folder), auth_f)
        assert "Müzikler" in cat_f.get("folders", []), "Müzikler klasörü katalogda yok!"
        assert "Resimler/Doğa" in cat_f.get("folders", []), "Resimler/Doğa klasörü katalogda yok!"
        print("  -> Başarılı: Sanal klasör hiyerarşisi oluşturuldu.")

        raw_b, entry = CustomVaultEngine.extract_file_bytes(str(v_folder), auth_f, "Müzikler/sample.mp3")
        assert raw_b == sample_audio.read_bytes(), "Bellekten okunan baytlar kaynakla uyuşmuyor!"
        print("  -> Başarılı: extract_file_bytes ile diske yazmadan bellekten bayt okuma doğrulandı.")

        CustomVaultEngine.rename_file(str(v_folder), auth_f, entry["id"], "Müzikler/sarki_yeni.mp3")
        cat_f2 = CustomVaultEngine.load_catalog(str(v_folder), auth_f)
        assert any(f["path"] == "Müzikler/sarki_yeni.mp3" for f in cat_f2.get("files", [])), "Dosya yeniden adlandırılamadı!"
        print("  -> Başarılı: Dosya yeniden adlandırma doğrulandı.")

        CustomVaultEngine.rename_folder(str(v_folder), auth_f, "Müzikler", "Ses_Dosyalari")
        cat_f3 = CustomVaultEngine.load_catalog(str(v_folder), auth_f)
        assert "Ses_Dosyalari" in cat_f3.get("folders", []), "Klasör yeniden adlandırılamadı!"
        assert any(f["path"] == "Ses_Dosyalari/sarki_yeni.mp3" for f in cat_f3.get("files", [])), "Klasör altındaki dosya yolu güncellenmedi!"
        print("  -> Başarılı: Klasör yeniden adlandırma ve alt dosya yolu güncelleme doğrulandı.")

        CustomVaultEngine.delete_folder(str(v_folder), auth_f, "Ses_Dosyalari")
        cat_f4 = CustomVaultEngine.load_catalog(str(v_folder), auth_f)
        assert "Ses_Dosyalari" not in cat_f4.get("folders", []), "Klasör silinmedi!"
        assert not any("Ses_Dosyalari" in f["path"] for f in cat_f4.get("files", [])), "Klasör altındaki dosyalar silinmedi!"
        print("\n[TEST 13] Ayrılmış başlık yedeği oluşturma, tahrifat ve kurtarma testi...")
        v_bak_test = test_dir / "backup_test.pvault"
        CustomVaultEngine.create_vault(str(v_bak_test), "BackupVaultPw@123", "Yedek Test Kasa")
        auth_bak = CustomVaultEngine.authenticate(str(v_bak_test), "BackupVaultPw@123")
        CustomVaultEngine.write_file_bytes(str(v_bak_test), auth_bak, "guvenli_belge.txt", b"Gizli Belge Verisi 2026")

        bak_unprot = test_dir / "header_yedek.vheader"
        bak_prot = test_dir / "header_yedek_sifreli.vheader"

        exp1 = CustomVaultEngine.export_header_backup(str(v_bak_test), str(bak_unprot))
        assert exp1["success"] and not exp1["is_protected"], "Parolasız başlık yedeği alınamadı!"
        insp1 = CustomVaultEngine.inspect_header_backup(str(bak_unprot))
        assert insp1["valid"] and insp1["header_size"] == 256, "Başlık yedeği doğrulanamadı!"

        exp2 = CustomVaultEngine.export_header_backup(str(v_bak_test), str(bak_prot), backup_password="HeaderBackupSecret99!")
        assert exp2["success"] and exp2["is_protected"], "Parola korumalı başlık yedeği alınamadı!"
        insp2_bad = CustomVaultEngine.inspect_header_backup(str(bak_prot), "YanlisParola!")
        assert not insp2_bad["valid"], "Yanlış parola ile yedek açılmamalıdır!"
        insp2_good = CustomVaultEngine.inspect_header_backup(str(bak_prot), "HeaderBackupSecret99!")
        assert insp2_good["valid"] and insp2_good["is_protected"], "Parola korumalı yedek doğrulanamadı!"

        with open(v_bak_test, "r+b") as f:
            f.seek(0)
            f.write(b"\x00" * 256)
        hdr_chk = CustomVaultEngine.verify_header(str(v_bak_test))
        assert not hdr_chk["valid"], "Hasarlı başlık tespit edilemedi!"
        print("  -> Başarılı: Başlık hasarı ve geçersiz imza derhal yakalandı.")

        rest_res = CustomVaultEngine.restore_header_backup(str(v_bak_test), str(bak_prot), backup_password="HeaderBackupSecret99!")
        assert rest_res["success"], "Başlık yedeği geri yüklenemedi!"
        hdr_chk2 = CustomVaultEngine.verify_header(str(v_bak_test))
        assert hdr_chk2["valid"], "Geri yüklenen başlık doğrulanamadı!"

        auth_recovered = CustomVaultEngine.authenticate(str(v_bak_test), "BackupVaultPw@123")
        recovered_data, _ = CustomVaultEngine.extract_file_bytes(str(v_bak_test), auth_recovered, "guvenli_belge.txt")
        assert recovered_data == b"Gizli Belge Verisi 2026", "Kurtarılan kasa verisi orijinal veriyle eşleşmiyor!"
        print("\n[TEST 14] Derin Kurtarma ve Windows Hello DPAPI Kapsamlı Testi...")
        v_trunc = test_dir / "trunc_test.pvault"
        with open(v_trunc, "wb") as f:
            pass
        rest_trunc = CustomVaultEngine.restore_header_backup(str(v_trunc), str(bak_unprot))
        assert rest_trunc["success"] and v_trunc.stat().st_size == 256, "0-baytlık dosyaya başlık geri yüklenemedi!"
        print("  -> Başarılı: 0-baytlık kesintiye uğramış PVAULT başlığı onarıldı.")

        if sys.platform != "win32":
            print("  -> Atlandı: VHD ve DPAPI testleri yalnızca Windows içindir.")
        else:
            from engine import VHDEngine
            mock_vhd = test_dir / "mock_test.vhd"
            footer = bytearray(512)
            footer[:8] = b"conectix"
            footer[60:64] = struct.pack(">I", 3)
            footer[48:56] = struct.pack(">Q", 10485760)
            calc_sum = sum(footer[:64]) + sum(footer[68:])
            footer[64:68] = struct.pack(">I", (~calc_sum) & 0xFFFFFFFF)
            dyn_hdr = bytearray(1024)
            dyn_hdr[:8] = b"cxsparse"
            vhd_body = bytes(footer) + bytes(dyn_hdr) + (b"\x00" * 65536) + bytes(footer)
            with open(mock_vhd, "wb") as f:
                f.write(vhd_body)

            vhd_bak = test_dir / "mock_vhd.vhdheader"
            b_res = VHDEngine.backup_vhd_header_footer(str(mock_vhd), str(vhd_bak))
            assert b_res["success"], "VHD başlık/altbilgi yedeği alınamadı!"

            v_insp = VHDEngine.inspect_vhd_header_footer(str(vhd_bak))
            assert v_insp["valid"] and v_insp["vhd_filename"] == "mock_test.vhd", "VHD yedek denetimi başarısız!"

            with open(mock_vhd, "r+b") as f:
                f.truncate(2000)
            assert mock_vhd.stat().st_size == 2000
            v_corrupt = VHDEngine.verify_vhd_structure(str(mock_vhd))
            assert not v_corrupt["valid"], "Kesilmiş VHD hasarı tespit edilemedi!"

            r_vhd = VHDEngine.restore_vhd_header_footer(str(mock_vhd), str(vhd_bak))
            assert r_vhd["success"], "Kesilmiş VHD onarılamadı!"
            v_fixed = VHDEngine.verify_vhd_structure(str(mock_vhd))
            assert v_fixed["valid"] and v_fixed["checksum_ok"], "Onarılan VHD yapısal doğrulamadan geçemedi!"
            print("  -> Başarılı: Kesilmiş VHD diski ayrılmış yedekten kusursuz onarıldı ve doğrulandı.")

            import windows_hello
            plain_secret = "VaultMasterKey_SuperSecret_2026!"
            dummy_vault = str(test_dir / "dpapi_vault.pvault")
            assert not windows_hello.has_vault_biometric_credential(dummy_vault)

            saved = windows_hello.save_vault_biometric_credential(dummy_vault, plain_secret, "Test Kasa")
            assert saved and windows_hello.has_vault_biometric_credential(dummy_vault)

            cfg = windows_hello.load_config()
            key_id = windows_hello._get_vault_key_id(dummy_vault)
            cred_stored = cfg["windows_hello_credentials"][key_id]
            assert "vault_path" not in cred_stored, "Kritik Güvenlik Zaafiyeti: config.json içinde mutlak dosya yolu sızıyor!"

            entropy = windows_hello._get_vault_entropy(dummy_vault)
            cipher_bytes = base64.b64decode(cred_stored["cipher"].encode("ascii"))
            decrypted_pw = windows_hello.dpapi_decrypt(cipher_bytes, entropy=entropy).decode("utf-8")
            assert decrypted_pw == plain_secret, "DPAPI şifre çözme uyuşmazlığı!"

            assert windows_hello.remove_vault_biometric_credential(dummy_vault)
            assert not windows_hello.has_vault_biometric_credential(dummy_vault)
            print("  -> Başarılı: Windows Hello DPAPI ve sıfır-adli-iz gizlilik koruması doğrulandı.")

        print("\n[BASARILI] TUM TESTLER %100 BASARIYLA TAMAMLANDI! SIFIR HATA!")

    finally:
        shutil.rmtree(test_dir, ignore_errors=True)

if __name__ == "__main__":
    run_all_tests()
