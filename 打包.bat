@echo off
chcp 65001 >nul
set "PYTHON_EXE="
if exist "%USERPROFILE%\.codegeex\mamba\envs\codegeex-agent\python.exe" set "PYTHON_EXE=%USERPROFILE%\.codegeex\mamba\envs\codegeex-agent\python.exe"
if not defined PYTHON_EXE if exist "%USERPROFILE%\miniconda3\python.exe" set "PYTHON_EXE=%USERPROFILE%\miniconda3\python.exe"
if not defined PYTHON_EXE if exist "%USERPROFILE%\anaconda3\python.exe" set "PYTHON_EXE=%USERPROFILE%\anaconda3\python.exe"
if not defined PYTHON_EXE set "PYTHON_EXE=python"

"%PYTHON_EXE%" build.py --clean

if errorlevel 1 (
    echo.
    echo 打包失败，请检查 Python 环境、PyInstaller 和图标文件
    pause
)
