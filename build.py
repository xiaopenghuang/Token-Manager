#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import struct
import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent
ICON_PNG = PROJECT_ROOT / "ico" / "openai.png"
BUILD_ASSETS_DIR = PROJECT_ROOT / "build_assets"
ICON_ICO = BUILD_ASSETS_DIR / "openai.ico"
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


def png_dimensions(data: bytes) -> tuple[int, int]:
    if len(data) < 24 or data[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError("图标文件不是有效 PNG")
    width = struct.unpack(">I", data[16:20])[0]
    height = struct.unpack(">I", data[20:24])[0]
    return width, height


def png_to_ico(png_path: Path, ico_path: Path) -> Path:
    png_bytes = png_path.read_bytes()
    width, height = png_dimensions(png_bytes)
    width_byte = 0 if width >= 256 else width
    height_byte = 0 if height >= 256 else height
    header = struct.pack("<HHH", 0, 1, 1)
    entry = struct.pack(
        "<BBBBHHII",
        width_byte,
        height_byte,
        0,
        0,
        1,
        32,
        len(png_bytes),
        6 + 16,
    )
    ico_path.parent.mkdir(parents=True, exist_ok=True)
    ico_path.write_bytes(header + entry + png_bytes)
    return ico_path


def ensure_icon() -> Path:
    if not ICON_PNG.exists():
        raise FileNotFoundError(f"未找到图标 PNG: {ICON_PNG}")
    png_to_ico(ICON_PNG, ICON_ICO)
    log(f"已生成图标: {ICON_ICO}")
    return ICON_ICO


def render_spec(app_name: str, console: bool, icon_path: Path) -> str:
    icon_literal = str(icon_path).replace("\\", "\\\\")
    data_png = str(ICON_PNG).replace("\\", "\\\\")
    return f"""# -*- mode: python ; coding: utf-8 -*-
from pathlib import Path

project_root = Path(SPECPATH)
icon_path = Path(r"{icon_literal}")

a = Analysis(
    ['main.py'],
    pathex=[str(project_root)],
    binaries=[],
    datas=[(r'{data_png}', 'ico')],
    hiddenimports=[
        'tkinter',
        'tkinter.ttk',
        'tkinter.scrolledtext',
        'tkinter.messagebox',
        'requests',
    ],
    hookspath=[],
    hooksconfig={{}},
    runtime_hooks=[],
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


def write_spec(app_name: str, console: bool, icon_path: Path) -> Path:
    SPEC_FILE.write_text(render_spec(app_name, console, icon_path), encoding="utf-8")
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
    spec_path = write_spec(args.name, args.console, icon_path)
    if args.prepare_only:
        log("已完成准备，不执行打包")
        return
    build_app(spec_path)
    log(f"输出目录: {DIST_DIR}")


if __name__ == "__main__":
    main()
