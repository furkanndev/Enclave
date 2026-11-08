"""
Enclave - Derleme Betiği (PyInstaller)
Windows'ta tek dosya .exe, macOS'ta .app paketi, Linux'ta tek dosya çalıştırılabilir üretir.
Her sistem kendi paketini kendisi derler; çapraz derleme yoktur.
Windows'ta dist/ klasöründe sadece tek 1 adet güncel 'Enclave.exe' bırakır.
"""

import os
import subprocess
import sys
import time
from pathlib import Path

try:
    from config import APP_VERSION
except Exception:
    APP_VERSION = "2.0"

TARGET_EXE_NAME = "Enclave.exe"

def kill_running_instances():
    """Eğer Enclave arka planda veya masaüstünde açıksa zorla kapatır."""
    targets = [
        TARGET_EXE_NAME,
        "Enclave.exe",
    ]
    for exe_name in set(targets):
        try:
            res = subprocess.run(
                ["taskkill", "/F", "/IM", exe_name, "/T"],
                capture_output=True, text=True, timeout=5
            )
            if res.returncode == 0:
                print(f"[BILGI] Calisan {exe_name} sureci zorla sonlandirildi.")
                time.sleep(1)
                continue
        except Exception:
            pass

        try:
            clean_name = exe_name.replace(".exe", "")
            ps_cmd = f"Stop-Process -Name '{clean_name}' -Force -ErrorAction SilentlyContinue"
            subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True, timeout=6
            )
            time.sleep(0.5)
        except Exception:
            pass

        try:
            import ctypes
            out = subprocess.check_output(f'tasklist /FI "IMAGENAME eq {exe_name}" /FO CSV /NH', shell=True, text=True, errors="ignore")
            for line in out.splitlines():
                parts = line.strip().split('","')
                if len(parts) >= 2:
                    pid_str = parts[1].replace('"', '').strip()
                    if pid_str.isdigit():
                        pid = int(pid_str)
                        h = ctypes.windll.kernel32.OpenProcess(1, False, pid)
                        if h:
                            ctypes.windll.kernel32.TerminateProcess(h, 0)
                            ctypes.windll.kernel32.CloseHandle(h)
                            print(f"[BILGI] PID {pid} ({exe_name}) Win32 API ile sonlandirildi.")
        except Exception:
            pass

    time.sleep(1)

def wait_for_file_release(filepath: Path, max_wait: int = 15) -> bool:
    """EXE dosyasinin baska surec tarafindan serbest birakilmasini bekler."""
    for i in range(max_wait):
        try:
            if not filepath.exists():
                return True
            with open(filepath, "r+b"):
                pass
            return True
        except (PermissionError, OSError):
            if i == 0:
                print(f"[BEKLE] {filepath.name} serbest birakilmasi bekleniyor", end="", flush=True)
            else:
                print(".", end="", flush=True)
            time.sleep(1)
    print()
    return False

def cleanup_dist_folder(keep_exe_name: str = TARGET_EXE_NAME):
    """dist/ klasöründeki tüm fazla veya eski exe kopyalarını siler, sadece tek 1 adet hedef exe bırakır."""
    dist_dir = Path("dist")
    if not dist_dir.exists():
        return
    for item in dist_dir.glob("*.exe"):
        if item.name.lower() != keep_exe_name.lower():
            try:
                item.unlink(missing_ok=True)
                print(f"[TEMIZLIK] Fazla kopya silindi: {item.name}")
            except Exception as e:
                print(f"[UYARI] {item.name} silinemedi: {e}")

def build_other_platform():
    """macOS ve Linux: süreç sonlandırma ve .exe temizliği gerekmez."""
    res = subprocess.run([sys.executable, "-m", "PyInstaller", "--clean", "--noconfirm", "Enclave.spec"])
    if res.returncode:
        sys.exit(res.returncode)
    print(f"\n[BASARILI] Paket hazir: {Path('dist').resolve()}")

def build():
    if sys.platform != "win32":
        build_other_platform()
        return

    print(f"=== Enclave EXE Derleme Basliyor (Hedef: {TARGET_EXE_NAME}) ===")

    kill_running_instances()

    cleanup_dist_folder(TARGET_EXE_NAME)

    exe_path = Path("dist") / TARGET_EXE_NAME
    if exe_path.exists():
        released = wait_for_file_release(exe_path, max_wait=15)
        if not released:
            print(f"\n[UYARI] {exe_path.name} hala kilitli. Silme/Yeniden adlandırma deneniyor...")
            try:
                backup = exe_path.with_name(f"{exe_path.stem}_old.exe")
                if backup.exists():
                    backup.unlink(missing_ok=True)
                exe_path.rename(backup)
                print(f"[BILGI] Eski EXE yeniden adlandirildi: {backup.name}")
            except Exception as e:
                print(f"[HATA] Eski EXE taşınamadı: {e}")
                print("Lütfen açık uygulamayı kapatıp tekrar deneyin.")
                sys.exit(1)

    spec_file = Path("Enclave.spec")
    if spec_file.exists():
        cmd = [sys.executable, "-m", "PyInstaller", "--clean", "--noconfirm", str(spec_file)]
    else:
        cmd = [
            sys.executable,
            "-m", "PyInstaller",
            "--noconsole",
            "--onefile",
            f"--name={Path(TARGET_EXE_NAME).stem}",
            "--icon=app_icon.ico",
            "--add-data=app_icon.ico;.",
            "--add-data=assets;assets",
            "--hidden-import=cryptography",
            "--hidden-import=cryptography.hazmat.primitives.ciphers.aead",
            "--hidden-import=extra_dialogs",
            "--hidden-import=audit_logger",
            "--clean",
            "main.py"
        ]

    print("Komut calistiriliyor:", " ".join(cmd))
    res = subprocess.run(cmd)

    cleanup_dist_folder(TARGET_EXE_NAME)

    build_dir = Path("build")
    if build_dir.exists():
        try:
            import shutil
            shutil.rmtree(build_dir, ignore_errors=True)
            print("[TEMIZLIK] build/ geçici derleme klasörü temizlendi.")
        except Exception:
            pass

    if res.returncode == 0:
        print(f"\n[BASARILI] dist/ klasorunde yalnizca tek guncel EXE hazir: {exe_path.resolve()}")
    else:
        print("\n[HATA] Derleme basarisiz oldu.")
        sys.exit(res.returncode)

if __name__ == "__main__":
    build()
