#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import struct
import subprocess
import sys
from pathlib import Path

from PIL import Image


PROJECT_ROOT = Path(__file__).resolve().parent
ICON_PNG = PROJECT_ROOT / "ico" / "openai.png"
BUILD_ASSETS_DIR = PROJECT_ROOT / "build_assets"
ICON_ICO = BUILD_ASSETS_DIR / "openai.ico"
TK_RUNTIME_HOOK = BUILD_ASSETS_DIR / "runtime_hook_tk.py"
SPEC_FILE = PROJECT_ROOT / "build.spec"
DIST_DIR = PROJECT_ROOT / "dist"
BUILD_DIR = PROJECT_ROOT / "build"


def project_python() -> str:
    return sys.executable


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="OpenAI Token Manager 打包工具")
    parser.add_argument("--prepare-only", action="store_true", help="只生成图标和 build.spec，不执行打包")
    parser.add_argument("--clean", action="store_true", help="打包前清理 build/dist")
    parser.add_argument("--console", action="store_true", help="生成带控制台的程序")
    parser.add_argument("--name", default="OpenAI-Token-Manager", help="输出程序名")
    return parser.parse_args()


def log(message: str) -> None:
    print(f"[build] {message}")


def ensure_pyinstaller() -> None:
    try:
        import PyInstaller  # noqa: F401
    except ImportError as exc:
        raise RuntimeError("未安装 PyInstaller，请先执行: pip install pyinstaller") from exc
    try:
        import PIL  # noqa: F401
    except ImportError as exc:
        raise RuntimeError("未安装 Pillow，请先执行: pip install pillow") from exc


def png_dimensions(data: bytes) -> tuple[int, int]:
    if len(data) < 24 or data[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError("图标文件不是有效 PNG")
    width = struct.unpack(">I", data[16:20])[0]
    height = struct.unpack(">I", data[20:24])[0]
    return width, height


def png_to_ico(png_path: Path, ico_path: Path) -> Path:
    ico_path.parent.mkdir(parents=True, exist_ok=True)
    with Image.open(png_path) as image:
        rgba = image.convert("RGBA")
        background = Image.new("RGBA", rgba.size, (255, 255, 255, 255))
        flattened = Image.alpha_composite(background, rgba).convert("RGB")
        flattened.save(ico_path, format="ICO", sizes=[(256, 256), (128, 128), (64, 64), (32, 32), (16, 16)])
    return ico_path


def ensure_icon() -> Path:
    if not ICON_PNG.exists():
        raise FileNotFoundError(f"未找到图标 PNG: {ICON_PNG}")
    png_to_ico(ICON_PNG, ICON_ICO)
    log(f"已生成图标: {ICON_ICO}")
    return ICON_ICO


def locate_tk_assets() -> dict[str, Path]:
    env_root = Path(sys.executable).resolve().parent
    candidates = {
        "tcl_dll": env_root / "Library" / "bin" / "tcl86t.dll",
        "tk_dll": env_root / "Library" / "bin" / "tk86t.dll",
        "tcl_lib": env_root / "Library" / "lib" / "tcl8.6",
        "tk_lib": env_root / "Library" / "lib" / "tk8.6",
    }
    missing = [name for name, path in candidates.items() if not path.exists()]
    if missing:
        raise FileNotFoundError(f"未找到 Tk 运行时资源: {', '.join(missing)}")
    return candidates


def locate_optional_runtime_dlls() -> list[Path]:
    env_root = Path(sys.executable).resolve().parent
    dll_dir = env_root / "Library" / "bin"
    names = ["liblzma.dll", "libbz2.dll", "ffi-8.dll"]
    return [dll_dir / name for name in names if (dll_dir / name).exists()]


def write_tk_runtime_hook() -> Path:
    BUILD_ASSETS_DIR.mkdir(parents=True, exist_ok=True)
    TK_RUNTIME_HOOK.write_text(
        "import os\n"
        "import sys\n"
        "base = getattr(sys, '_MEIPASS', '')\n"
        "if base:\n"
        "    os.environ['TCL_LIBRARY'] = os.path.join(base, '_tcl_data')\n"
        "    os.environ['TK_LIBRARY'] = os.path.join(base, '_tk_data')\n",
        encoding="utf-8",
    )
    return TK_RUNTIME_HOOK


def render_spec(
    app_name: str,
    console: bool,
    icon_path: Path,
    tk_assets: dict[str, Path],
    runtime_hook: Path,
    extra_dlls: list[Path],
) -> str:
    icon_literal = str(icon_path).replace("\\", "\\\\")
    data_png = str(ICON_PNG).replace("\\", "\\\\")
    tcl_dll = str(tk_assets["tcl_dll"]).replace("\\", "\\\\")
    tk_dll = str(tk_assets["tk_dll"]).replace("\\", "\\\\")
    tcl_lib = str(tk_assets["tcl_lib"]).replace("\\", "\\\\")
    tk_lib = str(tk_assets["tk_lib"]).replace("\\", "\\\\")
    runtime_hook_literal = str(runtime_hook).replace("\\", "\\\\")
    escaped_extra_dlls = [str(path).replace("\\", "\\\\") for path in extra_dlls]
    extra_binaries = "".join(
        f"        (r'{path}', '.'),\n"
        for path in escaped_extra_dlls
    )
    return f"""# -*- mode: python ; coding: utf-8 -*-
from pathlib import Path

project_root = Path(SPECPATH)
icon_path = Path(r"{icon_literal}")

a = Analysis(
    ['main.py'],
    pathex=[str(project_root)],
    binaries=[
        (r'{tcl_dll}', '.'),
        (r'{tk_dll}', '.'),
{extra_binaries}    ],
    datas=[
        (r'{data_png}', 'ico'),
        (r'{icon_literal}', 'build_assets'),
        (r'{tcl_lib}', '_tcl_data'),
        (r'{tk_lib}', '_tk_data'),
    ],
    hiddenimports=[
        '_tkinter',
        'tkinter',
        'tkinter.ttk',
        'tkinter.scrolledtext',
        'tkinter.messagebox',
        'requests',
    ],
    hookspath=[],
    hooksconfig={{}},
    runtime_hooks=[r'{runtime_hook_literal}'],
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
    name='{app_name}',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console={str(console)},
    disable_windowed_traceback=False,
    icon=str(icon_path),
)
"""


def write_spec(
    app_name: str,
    console: bool,
    icon_path: Path,
    tk_assets: dict[str, Path],
    runtime_hook: Path,
    extra_dlls: list[Path],
) -> Path:
    SPEC_FILE.write_text(
        render_spec(app_name, console, icon_path, tk_assets, runtime_hook, extra_dlls),
        encoding="utf-8",
    )
    log(f"已生成 spec: {SPEC_FILE}")
    return SPEC_FILE


def clean_dirs() -> None:
    for path in (BUILD_DIR, DIST_DIR, BUILD_ASSETS_DIR):
        if path.exists():
            if path.is_dir():
                for child in sorted(path.glob("**/*"), reverse=True):
                    if child.is_file():
                        child.unlink()
                for child in sorted(path.glob("**/*"), reverse=True):
                    if child.is_dir():
                        try:
                            child.rmdir()
                        except OSError:
                            pass
                try:
                    path.rmdir()
                except OSError:
                    pass
            else:
                path.unlink()
    log("已清理旧的打包目录")


def build_app(spec_path: Path) -> None:
    cmd = [project_python(), "-m", "PyInstaller", "--noconfirm", "--clean", str(spec_path)]
    log("开始执行 PyInstaller")
    subprocess.run(cmd, cwd=str(PROJECT_ROOT), check=True)
    log("打包完成")


def main() -> None:
    args = parse_args()
    os.chdir(PROJECT_ROOT)
    ensure_pyinstaller()
    if args.clean:
        clean_dirs()
    icon_path = ensure_icon()
    tk_assets = locate_tk_assets()
    extra_dlls = locate_optional_runtime_dlls()
    runtime_hook = write_tk_runtime_hook()
    spec_path = write_spec(args.name, args.console, icon_path, tk_assets, runtime_hook, extra_dlls)
    if args.prepare_only:
        log("已完成准备，不执行打包")
        return
    build_app(spec_path)
    log(f"输出目录: {DIST_DIR}")


if __name__ == "__main__":
    main()
