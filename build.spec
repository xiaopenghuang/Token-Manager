# -*- mode: python ; coding: utf-8 -*-
from pathlib import Path

project_root = Path(SPECPATH)
icon_path = Path(r"I:\\xianyu_op\\openai-token-manager\\build_assets\\openai.ico")

a = Analysis(
    [r'main.py'],
    pathex=[str(project_root)],
    binaries=[
        (r'G:\\MiniConda3\\envs\\exe_env\\Library\\bin\\tcl86t.dll', '.'),
        (r'G:\\MiniConda3\\envs\\exe_env\\Library\\bin\\tk86t.dll', '.'),
        (r'G:\\MiniConda3\\envs\\exe_env\\Library\\bin\\liblzma.dll', '.'),
        (r'G:\\MiniConda3\\envs\\exe_env\\Library\\bin\\libbz2.dll', '.'),
        (r'G:\\MiniConda3\\envs\\exe_env\\Library\\bin\\ffi-8.dll', '.'),
        (r'G:\\MiniConda3\\envs\\exe_env\\Library\\bin\\libcrypto-3-x64.dll', '.'),
        (r'G:\\MiniConda3\\envs\\exe_env\\Library\\bin\\libssl-3-x64.dll', '.'),
        (r'G:\\MiniConda3\\envs\\exe_env\\Library\\bin\\zlib.dll', '.'),
        (r'G:\\MiniConda3\\envs\\exe_env\\Library\\bin\\zlib1.dll', '.'),
    ],
    datas=[
        (r'I:\\xianyu_op\\openai-token-manager\\ico\\openai.png', 'ico'),
        (r'I:\\xianyu_op\\openai-token-manager\\build_assets\\openai.ico', 'build_assets'),
        (r'G:\\MiniConda3\\envs\\exe_env\\Library\\lib\\tcl8.6', '_tcl_data'),
        (r'G:\\MiniConda3\\envs\\exe_env\\Library\\lib\\tk8.6', '_tk_data'),
    ],
    hiddenimports=[
        '_tkinter',
        'tkinter',
        'tkinter.ttk',
        'tkinter.scrolledtext',
        'tkinter.messagebox',
        'tkinter.filedialog',
        'requests',
        'websocket',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[r'I:\\xianyu_op\\openai-token-manager\\build_assets\\runtime_hook_tk.py'],
    excludes=[],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='OpenAI-Token-Manager',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    icon=str(icon_path),
)
