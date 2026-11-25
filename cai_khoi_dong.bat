@echo off
setlocal
cd /d "%~dp0"
set "SRC=%~dp0dist\GiamSat.exe"
if not exist "%SRC%" set "SRC=%~dp0GiamSat.exe"
if not exist "%SRC%" (
  echo Khong tim thay GiamSat.exe. Hay chay build_exe.bat truoc.
  pause
  exit /b 1
)
set "DEST=%LOCALAPPDATA%\GiamSat"
if not exist "%DEST%" mkdir "%DEST%"
copy /Y "%SRC%" "%DEST%\GiamSat.exe" >nul
if errorlevel 1 (
  echo Khong copy duoc. Neu ung dung dang chay, hay thoat ung dung roi chay lai file nay.
  pause
  exit /b 1
)
start /wait "" "%DEST%\GiamSat.exe" --install-startup
echo.
echo Da dang ky khoi dong cung Windows.
echo Vi tri file: %DEST%\GiamSat.exe
echo (Tu lan khoi dong may sau, ung dung se tu chay va thu nho xuong thanh taskbar.)
start "" "%DEST%\GiamSat.exe"
pause
