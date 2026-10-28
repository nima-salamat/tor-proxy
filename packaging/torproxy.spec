# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for portable Windows and Linux desktop builds."""

import os
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_dynamic_libs, collect_submodules

ROOT = Path(SPECPATH).resolve().parent

datas = [
    (str(ROOT / "assets" / "icon.png"), "assets"),
    (str(ROOT / "assets" / "icon.ico"), "assets"),
]
datas += collect_data_files("qdarkstyle")
datas += collect_data_files("qtawesome")

# The pyzbar decoder is optional at runtime; collect packaged native binaries
# when the platform's pyzbar wheel provides them (notably on Windows).
binaries = collect_dynamic_libs("pyzbar")
hiddenimports = collect_submodules("qtawesome")

# Keep this a focused desktop package. OpenCV's headless wheel already avoids
# bundling a duplicate GUI toolkit; the app does not use Qt WebEngine.
excludes = [
    "PyQt5",
    "PyQt6",
    "PySide2",
    "PySide6.QtWebEngineCore",
    "PySide6.QtWebEngineWidgets",
    "matplotlib",
    "pandas",
    "scipy",
    "tkinter",
    "pytest",
    "tests",
]

analysis = Analysis(
    [str(ROOT / "main.py")],
    pathex=[str(ROOT), str(ROOT / "src")],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excludes,
    noarchive=False,
)

pyz = PYZ(analysis.pure)

executable = EXE(
    pyz,
    analysis.scripts,
    [],
    exclude_binaries=True,
    name="TorProxy",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(ROOT / "assets" / "icon.ico") if os.name == "nt" else None,
)

COLLECT(
    executable,
    analysis.binaries,
    analysis.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="TorProxy",
)
