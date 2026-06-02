# PyInstaller spec for MLX Log Collector
a = Analysis(
    ['collector.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=['requests', 'urllib3', 'certifi', 'charset_normalizer', 'idna'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='MLX-Log-Collector',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    icon=None,
)
