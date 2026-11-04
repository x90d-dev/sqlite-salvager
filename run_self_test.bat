@echo off
cd /d "%~dp0"
python sqlite_salvager.py --self-test
pause
