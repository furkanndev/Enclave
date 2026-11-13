"""
Enclave - Başlangıç Giriş Noktası (Main Entry Point)
Komut satırı argümanlarını çözümler, yüksek DPI ölçeklendirmesini ayarlar,
headless otomasyon komutlarını veya GUI'yi başlatır.
Şifreli kasa arayüzü üç işletim sisteminde çalışır. VHD ve BitLocker kodu Windows'a özeldir
(winreg, ctypes.windll), bu yüzden yalnızca Windows'ta ve gerektiğinde yüklenir.
"""

import sys
import os
import argparse
import ctypes
from pathlib import Path

try:
    ATTACH_PARENT_PROCESS = -1
    if ctypes.windll.kernel32.AttachConsole(ATTACH_PARENT_PROCESS):
        try:
            sys.stdout = open("CONOUT$", "w", encoding="utf-8", errors="replace")
            sys.stderr = open("CONOUT$", "w", encoding="utf-8", errors="replace")
        except Exception:
            pass
except Exception:
    pass

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

try:
    myappid = 'enclave.security.vault'
    ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)
except Exception:
    pass

def _inherit_data_dir() -> None:
    """Yükseltilmiş süreç, ilk oturumun ayar dizinini --data-dir ile alır; logger içe aktarılmadan önce çalışmalıdır."""
    if "--data-dir" in sys.argv:
        position = sys.argv.index("--data-dir")
        if position + 1 < len(sys.argv):
            os.environ["ENCLAVE_DATA_DIR"] = sys.argv[position + 1]
            del sys.argv[position:position + 2]

_inherit_data_dir()

from PyQt6.QtWidgets import QApplication, QMessageBox
from PyQt6.QtCore import Qt

def wants_windows_tools(args, target_file) -> bool:
    """Komut satırı Windows'a özel VHD/BitLocker işlevini mi istiyor?"""
    return bool(
        args.expand or args.mount or args.dismount or args.backup or args.shred
        or args.register_shell or args.unregister_shell
    )

def handle_cli_commands(args, engine) -> bool:
    """Headless CLI komutları verilmişse bunları terminalde çalıştırır ve True döner."""
    needs_admin = (
        bool(args.register_shell)
        or bool(args.unregister_shell)
        or bool(args.expand and args.size)
        or bool(getattr(args, "mount", None))
        or bool(args.dismount)
    )
    if needs_admin and not is_admin():
        elevate_if_not_admin()

    if args.register_shell:
        res = engine.register_shell_context_menu()
        print(res.get("message") if res.get("success") else f"HATA: {res.get('error')}")
        return True

    if args.unregister_shell:
        res = engine.unregister_shell_context_menu()
        print(res.get("message") if res.get("success") else f"HATA: {res.get('error')}")
        return True

    if args.expand and args.size:
        res = engine.expand_vdisk(args.expand, int(args.size))
        if res.get("success"):
            print(f"[BAŞARILI] {res.get('message')}")
        else:
            print(f"[HATA] {res.get('error')}")
        return True

    if args.backup:
        res = engine.backup_vault(args.backup)
        if res.get("success"):
            print(f"[BAŞARILI] Yedek alındı: {res.get('backup_path')} ({res.get('file_size_mb')} MB)")
        else:
            print(f"[HATA] {res.get('error')}")
        return True

    if getattr(args, "mount", None):
        pref = getattr(args, "letter", None)
        res = engine.mount_vhd(args.mount, preferred_letter=pref)
        if res.get("success"):
            print(f"[BAŞARILI] Kasa başarıyla bağlandı: Sürücü -> {res.get('drive_letter')}")
        else:
            print(f"[HATA] {res.get('error')}")
        return True

    if args.dismount:
        res = engine.dismount_vhd(mount_target=args.dismount, force=True)
        if res.get("success"):
            print(f"[BAŞARILI] {res.get('message', 'Kasa ayrıldı.')}")
        else:
            print(f"[HATA] Ayırma işlemi başarısız: {res.get('error')}")
        return True

    return False

def handle_shred_dialog(target_path: str, engine):
    """Sağ tık veya CLI üzerinden çağrılan DoD parçalama işlemini görsel onay ile yürütür."""
    p = Path(target_path).resolve()
    if not p.exists():
        QMessageBox.critical(None, "Hata", f"Parçalanacak dosya veya klasör bulunamadı:\n{target_path}")
        return

    reply = QMessageBox.warning(
        None,
        "Güvenli Parçalama Onayı (DoD Shred)",
        f"DİKKAT: Seçilen öğe geri getirilemez şekilde parçalanacaktır!\n\n"
        f"Hedef: {p.name}\n"
        f"Konum: {p}\n\n"
        f"Bu işlem dosya sektörlerinin üzerine sıfır ve rastgele baytlar yazarak "
        f"kurtarılmasını tamamen engeller.\n\nDevam etmek istiyor musunuz?",
        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        QMessageBox.StandardButton.No
    )
    if reply == QMessageBox.StandardButton.Yes:
        res = engine.shred_item(str(p), passes=1)
        if res.get("success"):
            QMessageBox.information(
                None, "İşlem Tamamlandı",
                f"Güvenle parçalandı!\n"
                f"Silinen dosya sayısı: {res.get('files_shredded')}\n"
                f"Temizlenen veri: {res.get('bytes_shredded_mb')} MB"
            )
        else:
            QMessageBox.critical(None, "Hata", f"Parçalama hatası:\n{res.get('error')}")

def is_admin() -> bool:
    """Mevcut sürecin yönetici haklarına sahip olup olmadığını denetler."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def elevate_if_not_admin():
    """Uygulamanın her zaman yönetici ayrıcalıklarıyla (UAC Administrator) açılmasını sağlar."""
    if os.name == 'nt' and not is_admin():
        try:
            if getattr(sys, 'frozen', False):
                exe = sys.executable
                params = " ".join([f'"{arg}"' for arg in sys.argv[1:]])
            else:
                exe = sys.executable
                params = " ".join([f'"{arg}"' for arg in sys.argv])
            ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
            if int(ret) > 32:
                sys.exit(0)
        except Exception:
            pass

def main():
    if "--vhd-helper" in sys.argv:
        from enclave_app.vhd_service import serve_helper
        position = sys.argv.index("--vhd-helper")
        serve_helper(sys.argv[position + 1], sys.argv[position + 2])
        return
    if sys.platform == "win32":
        try:
            ctypes.windll.kernel32.SetDefaultDllDirectories(0x00000800)
        except Exception:
            pass
        try:
            user32 = ctypes.windll.user32
            MSGFLT_ADD = 1
            for msg_id in (0x0233, 0x0049, 0x004A, 0x0047):
                user32.ChangeWindowMessageFilter(msg_id, MSGFLT_ADD)
        except Exception:
            pass
    parser = argparse.ArgumentParser(description="Enclave - Modern Sanal Disk ve BitLocker Yöneticisi")
    parser.add_argument("file_pos", nargs="?", type=str, help="Doğrudan açılacak sanal disk veya kasa dosyası yolu (Explorer kısayolu)")
    parser.add_argument("--file", "-f", type=str, help="Doğrudan açılacak sanal disk veya kasa dosyası yolu")
    parser.add_argument("--auto", "-a", action="store_true", help="Başlangıçta otomatik olarak diski bağla")
    parser.add_argument("--minimized", "-m", action="store_true", help="Başlangıçta sistem tepsisine küçültülmüş olarak başlat")
    parser.add_argument("--shred", "-s", type=str, help="Belirtilen dosya veya klasörü DoD standardında güvenle parçala")
    parser.add_argument("--expand", type=str, help="Genişletilecek VHD dosya yolu")
    parser.add_argument("--size", type=int, help="Genişletme için yeni maksimum boyut (MB)")
    parser.add_argument("--mount", type=str, help="Belirtilen kasanın bağlantısını komut satırından (headless) yap")
    parser.add_argument("--letter", "-l", type=str, help="Bağlama için tercih edilen sürücü harfi (örn: Z)")
    parser.add_argument("--backup", "-b", type=str, help="Belirtilen kasanın zaman damgalı yedeğini al")
    parser.add_argument("--dismount", "-d", type=str, help="Belirtilen kasanın bağlantısını güvenle kes")
    parser.add_argument("--register-shell", action="store_true", help="Windows Gezgini sağ tık menüsüne ekle")
    parser.add_argument("--unregister-shell", action="store_true", help="Windows Gezgini sağ tık menüsünden kaldır")

    args, unknown = parser.parse_known_args()
    target_file = args.file or args.file_pos
    use_windows_tools = wants_windows_tools(args, target_file)

    if use_windows_tools and sys.platform != "win32":
        print("HATA: VHD ve BitLocker işlevleri yalnızca Windows'ta çalışır. .pvault kasaları tüm sistemlerde açılır.")
        sys.exit(2)

    engine = None
    if use_windows_tools:
        from engine import VHDEngine
        engine = VHDEngine()
        if handle_cli_commands(args, engine):
            sys.exit(0)

    if hasattr(Qt, "HighDpiScaleFactorRoundingPolicy"):
        QApplication.setHighDpiScaleFactorRoundingPolicy(
            Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
        )

    import traceback

    def global_exception_handler(exc_type, exc_value, exc_traceback):
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_value, exc_traceback)
            return
        err_msg = "".join(traceback.format_exception(exc_type, exc_value, exc_traceback))
        try:
            from logger import get_logger
            logger = get_logger("Enclave")
            logger.error(f"Kritik Hata (Unhandled):\n{err_msg}")
        except Exception:
            pass

    sys.excepthook = global_exception_handler

    app = QApplication(sys.argv)

    try:
        from enclave_core import purge_all_vault_temp_forensics
        purge_all_vault_temp_forensics()
        app.aboutToQuit.connect(purge_all_vault_temp_forensics)
    except Exception:
        pass

    app.setQuitOnLastWindowClosed(False)

    from enclave_app.common import app_icon
    app.setApplicationName("Enclave")
    app.setApplicationDisplayName("Enclave")
    app.setApplicationVersion("2.0.1")
    app.setWindowIcon(app_icon())

    if use_windows_tools:
        if args.shred:
            handle_shred_dialog(args.shred, engine)
            sys.exit(0)

    from enclave_app.window import VaultWindow, load_bundled_fonts
    load_bundled_fonts()
    window = VaultWindow(initial_path=target_file or "")
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
