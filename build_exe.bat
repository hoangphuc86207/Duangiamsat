@echo off
cd /d "%~dp0"
if not exist "giamsat.py" (
  echo Khong tim thay giamsat.py trong thu muc nay.
  echo Hay dat giamsat.py, requirements.txt va build_exe.bat chung mot thu muc.
  pause
  exit /b 1
)
echo === 1/2: Cai thu vien ===
python -m pip install --upgrade -r requirements.txt
if errorlevel 1 (
  echo Cai thu vien that bai. Kiem tra Python da them vao PATH chua.
  pause
  exit /b 1
)
echo.
echo === 2/2: Dong goi thanh file exe ===
python -m PyInstaller --noconfirm --onefile --windowed --name GiamSat --collect-all customtkinter --collect-submodules watchdog --hidden-import psutil giamsat.py
if errorlevel 1 (
  echo Dong goi that bai. Xem thong bao loi o tren.
  pause
  exit /b 1
)
echo.
echo XONG! File exe nam o: dist\GiamSat.exe
echo Buoc tiep theo: chay cai_khoi_dong.bat de ung dung tu chay cung Windows.
pause
