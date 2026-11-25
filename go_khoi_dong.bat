@echo off
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v GiamSat /f >nul 2>&1
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v FolderMonitorApp /f >nul 2>&1
echo Da go dang ky khoi dong cung Windows.
echo (File ung dung van con o %LOCALAPPDATA%\GiamSat, ban co the xoa thu cong.)
pause
