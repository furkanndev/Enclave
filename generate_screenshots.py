"""
Enclave - Automated English Screenshot Generator
Generates clean, professional English screenshots showcasing the card UI design
without exposing local machine paths or personal identifiers.
"""

import os
import sys
import shutil
import tempfile
from pathlib import Path
from PIL import Image, ImageDraw

from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import Qt, QTimer

app = QApplication.instance()
if not app:
    app = QApplication(sys.argv)

import config
import enclave_app.i18n as i18n

# Hard lock language to English
i18n._language = "en"
def enforce_english(*args, **kwargs):
    i18n._language = "en"
i18n.set_language = enforce_english

# Realistic, generic mock paths for secondary remembered vaults
MOCK_RECENT = [
    r"D:\Backups\SecureArchive.pvault",
    r"E:\EncryptedUSB\Keys.pvault"
]

def mock_load_config():
    return {
        "language": "en",
        "design": "purple",
        "appearance": "dark",
        "remembered_vaults": MOCK_RECENT,
        "recent_vaults": MOCK_RECENT,
        "mascot": "shield",
        "idle_lock_minutes": 5,
        "lock_on_minimize": False,
    }

config.load_config = mock_load_config

import enclave_app.window as win_mod
import enclave_app.unlock_page as unl_mod
import enclave_app.dialogs as dlg_mod
import enclave_app.workspace as ws_mod

win_mod.load_config = mock_load_config
unl_mod.load_config = mock_load_config
dlg_mod.load_config = mock_load_config
ws_mod.load_config = mock_load_config

from enclave_core import CustomVaultEngine as Engine
from enclave_app.common import Theme
import enclave_app.designs as designs
from enclave_app.window import VaultWindow, load_bundled_fonts
from enclave_app.workspace import Workspace
from enclave_app.session import VaultSession
from enclave_app.pwd_engine import PasswordEntry
from enclave_app.pwd_dialogs import PasswordGeneratorDialog, HealthAuditDialog
from enclave_app.dialogs import SettingsDialog

# Load fonts
load_bundled_fonts()

# Mock Path.exists and os.path.exists for mock paths
orig_exists = Path.exists
orig_os_exists = os.path.exists
orig_getsize = os.path.getsize

def mock_exists(self):
    s = str(self).lower()
    for m in MOCK_RECENT:
        if s == m.lower() or Path(m).stem.lower() in s:
            return True
    if "personalvault.pvault" in s:
        return True
    return orig_exists(self)

def mock_os_exists(p):
    s = str(p).lower()
    for m in MOCK_RECENT:
        if s == m.lower() or Path(m).stem.lower() in s:
            return True
    if "personalvault.pvault" in s:
        return True
    return orig_os_exists(p)

Path.exists = mock_exists
os.path.exists = mock_os_exists

theme = Theme(designs.get_design("purple", "card"), dark=True)
app.setStyleSheet(designs.build_stylesheet(theme.design, theme.dark))

out_dir = Path("assets/screenshots")
out_dir.mkdir(parents=True, exist_ok=True)

print("[1/6] Generating 01_unlock_screen_en.png...")
win = VaultWindow(r"C:\Users\Alex\Documents\Vaults\PersonalVault.pvault")
win.unlock_page.path_edit.setText(r"C:\Users\Alex\Documents\Vaults\PersonalVault.pvault")
win.unlock_page.password.setText("SuperSecretPassword123!")
win.unlock_page.remember.setChecked(True)
win.unlock_page._load_remembered()
win.unlock_page._set_recent_open(False)
win.resize(1160, 740)
win.show()
app.processEvents()

pix01 = win.grab()
pix01.save(str(out_dir / "01_unlock_screen_en.png"))
print("Saved 01_unlock_screen_en.png")

print("[2/6] Generating 02_workspace_files_en.png...")
temp_dir = tempfile.mkdtemp(prefix="pvault_sc_")
try:
    real_vault_path = os.path.join(temp_dir, "actual_store.pvault")
    Engine.create_vault(real_vault_path, "DemoPassword123!")
    
    # Create valid sample PNG image
    valid_png_path = os.path.join(temp_dir, "System_Architecture.png")
    im = Image.new("RGBA", (320, 240), "#1E1E2E")
    draw = ImageDraw.Draw(im)
    draw.rectangle([20, 20, 300, 220], outline="#AFA9EC", width=3)
    im.save(valid_png_path, "PNG")

    # Create sample files
    sample_files = [
        ("Client_Master_Contracts.docx", b"PK\x03\x04" + b"A" * 152000),
        ("Confidential_Whitepaper.pdf", b"%PDF-1.7\n" + b"B" * 2450000),
        ("Financial_Ledger_Q4.xlsx", b"PK\x03\x04" + b"C" * 860000),
        ("Production_Keys_Backup.pem", b"-----BEGIN PRIVATE KEY-----\n" + b"E" * 4200 + b"\n-----END PRIVATE KEY-----"),
        ("Encrypted_Database_Dump.sql", b"-- PostgreSQL database dump\n" + b"F" * 16200000),
    ]
    
    plan = [(valid_png_path, "System_Architecture.png")]
    for fname, data in sample_files:
        src = os.path.join(temp_dir, fname)
        with open(src, "wb") as f:
            f.write(data)
        plan.append((src, fname))
    
    session = VaultSession(real_vault_path)
    session.unlock("DemoPassword123!")
    session.import_files(plan)
    
    # Set session name to clean presentation
    session.name = "PersonalVault"
    
    ws = Workspace(session, theme)
    ws.resize(1160, 740)
    ws.show()
    app.processEvents()
    
    pix02 = ws.grab()
    pix02.save(str(out_dir / "02_workspace_files_en.png"))
    print("Saved 02_workspace_files_en.png")

    print("[3/6] Generating 03_password_manager_en.png...")
    ws.set_mode("passwords")
    
    store = ws.pwd_view.store
    # Clear any previous demo entries
    store.entries.clear()
    
    # Add high quality entries
    e1 = PasswordEntry(
        title="AWS Production Cloud Console",
        type="login",
        username="root-audit@corporate-cloud.io",
        password="s3Cur3#P@ssw0rd!2026-XyZ",
        url="https://aws.amazon.com/console",
        totp_secret="JBSWY3DPEHPK3PXP",
        favorite=True,
        tags=["Cloud", "Production", "Infrastructure"],
        notes="Root credentials and IAM policy audit keys. Hardware MFA configured."
    )
    e2 = PasswordEntry(
        title="GitHub Enterprise",
        type="login",
        username="security-lead@enclave.internal",
        password="ghp_K98xL21mN09qW45yZ678vU12345",
        url="https://github.com/organizations/enclave",
        totp_secret="HXDMVJECJJWSRB3H",
        favorite=True,
        tags=["DevOps", "SourceCode"],
        notes="Team owner access token with repo, workflow and admin scopes."
    )
    e3 = PasswordEntry(
        title="Cold Storage Master Seed",
        type="key",
        username="Hardware Wallet 01",
        password="seed-phrase-hidden-in-secure-enclave",
        favorite=True,
        tags=["Crypto", "Treasury"],
        notes="24-word BIP39 seed phrase for corporate treasury multi-sig reserve."
    )
    e4 = PasswordEntry(
        title="Bitwarden Recovery Vault",
        type="login",
        username="user@backup-store.io",
        password="Password123",
        url="https://vault.bitwarden.com",
        favorite=False,
        tags=["Backup"],
        notes="Secondary emergency backup vault for legacy exports."
    )
    e5 = PasswordEntry(
        title="ProtonMail Core Security",
        type="login",
        username="admin@enclave-security.org",
        password="pr0t0n_M@il_9988_!x",
        url="https://mail.proton.me",
        favorite=True,
        tags=["Email", "Executive"],
        notes="Encrypted communications channel for executive board."
    )
    
    for e in [e1, e2, e3, e4, e5]:
        store.add(e)
        
    ws.pwd_view.refresh()
    # Select AWS entry
    ws.pwd_view.list_widget.setCurrentRow(0)
    ws.pwd_view._on_item_selected(ws.pwd_view.list_widget.currentItem(), None)
    app.processEvents()
    
    pix03 = ws.grab()
    pix03.save(str(out_dir / "03_password_manager_en.png"))
    print("Saved 03_password_manager_en.png")

    print("[4/6] Generating 04_password_generator_en.png...")
    pwd_gen = PasswordGeneratorDialog(theme)
    pwd_gen.result_edit.setText("kP9#vX2$mQ8@wL5&zR")
    pwd_gen.strength_lbl.setText("Password Strength: Strong (4/4)")
    pwd_gen.resize(540, 520)
    pwd_gen.show()
    app.processEvents()
    
    pix04 = pwd_gen.grab()
    pix04.save(str(out_dir / "04_password_generator_en.png"))
    pwd_gen.close()
    print("Saved 04_password_generator_en.png")

    print("[5/6] Generating 05_security_audit_en.png...")
    audit = HealthAuditDialog(theme, store)
    audit.resize(640, 600)
    audit.show()
    app.processEvents()
    
    pix05 = audit.grab()
    pix05.save(str(out_dir / "05_security_audit_en.png"))
    audit.close()
    print("Saved 05_security_audit_en.png")

    print("[6/6] Generating 06_settings_theme_en.png...")
    settings = SettingsDialog(theme, session)
    settings.tabs.setCurrentIndex(0)
    settings.resize(800, 760)
    settings.show()
    app.processEvents()
    
    pix06 = settings.grab()
    pix06.save(str(out_dir / "06_settings_theme_en.png"))
    settings.close()
    print("Saved 06_settings_theme_en.png")

    # Cleanup workspace and session
    ws.close()
    session.close()

finally:
    win.close()
    Path.exists = orig_exists
    os.path.exists = orig_os_exists
    os.path.getsize = orig_getsize
    shutil.rmtree(temp_dir, ignore_errors=True)

print("All 6 screenshots successfully generated in assets/screenshots/!")
