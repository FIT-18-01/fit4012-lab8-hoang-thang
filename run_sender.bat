@echo off
cd /d d:\ATBMTT\fit4012-lab8-hoang-thang
echo ==================================
echo   SENDER - Gui du lieu an toan
echo ==================================
set SERVER_IP=127.0.0.1
set DATA_PORT=6000
set RECEIVER_PUBLIC_KEY=keys/receiver_public.pem
set SENDER_PRIVATE_KEY=keys/sender_private.pem
echo Nhap message roi nhan Enter:
python sender.py
echo.
echo Da ghi log vao logs/sender_success.log
pause