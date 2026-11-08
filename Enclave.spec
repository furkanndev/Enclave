# -*- mode: python ; coding: utf-8 -*-

import sys

IS_WINDOWS = sys.platform == "win32"
IS_MAC = sys.platform == "darwin"
APP_NAME = "Enclave"

common_imports = [
    'cryptography', 'cryptography.hazmat.primitives.ciphers.aead', 'cryptography.hazmat.primitives.kdf.argon2',
    'enclave_core', 'stego_enclave', 'totp_engine', 'qrcode', 'PyQt6.QtSvg',
    'enclave_app.window', 'enclave_app.dialogs', 'enclave_app.workspace', 'enclave_app.unlock_page', 'enclave_app.session', 'enclave_app.extras',
    'enclave_app.pwd_engine', 'enclave_app.pwd_view', 'enclave_app.pwd_dialogs', 'enclave_app.pwd_importer',
]
windows_imports = [
    'engine', 'enclave_app.vhd_page', 'enclave_app.vhd_service', 'enclave_app.slideshow',
]

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=[('app_icon.ico', '.'), ('app_icon.png', '.'), ('assets', 'assets')],
    hiddenimports=common_imports + (windows_imports if IS_WINDOWS else []),
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['ui', 'extra_dialogs', 'enclave_custom_ui', 'audit_logger', 'PyQt6.QtMultimedia'] + ([] if IS_WINDOWS else ['engine']),
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

if IS_MAC:
    exe = EXE(
        pyz, a.scripts, [], exclude_binaries=True, name=APP_NAME, console=False,
        argv_emulation=False, target_arch=None, codesign_identity=None, entitlements_file=None,
    )
    coll = COLLECT(exe, a.binaries, a.datas, strip=False, upx=False, name=APP_NAME)
    app = BUNDLE(coll, name='Enclave.app', icon='app_icon.png', bundle_identifier='com.security.enclave')
else:
    exe = EXE(
        pyz,
        a.scripts,
        a.binaries,
        a.datas,
        [],
        name=APP_NAME,
        debug=False,
        bootloader_ignore_signals=False,
        strip=False,
        upx=IS_WINDOWS,
        upx_exclude=[],
        runtime_tmpdir=None,
        console=False,
        disable_windowed_traceback=False,
        argv_emulation=False,
        target_arch=None,
        codesign_identity=None,
        entitlements_file=None,
        uac_admin=False,
        icon=['app_icon.ico'] if IS_WINDOWS else None,
    )
