@echo off
cd /d d:\ATBMTT\fit4012-lab8-hoang-thang
echo ==================================
echo   RECEIVER - Lang nghe port 6000
echo ==================================
set DATA_PORT=6000
set RECEIVER_PRIVATE_KEY=keys/receiver_private.pem
set SENDER_PUBLIC_KEY=keys/sender_public.pem
set OUTPUT_FILE=sample_output.txt
python receiver.py
echo.
echo Da ghi log vao logs/receiver_success.log
echo Da ghi output vao sample_output.txt
pause