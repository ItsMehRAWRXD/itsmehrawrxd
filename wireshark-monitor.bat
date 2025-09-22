@echo off
echo 🎭 WIRESHARK MONITOR - THE TRILLION-DOLLAR LINE CAPTURE 🎭
echo ========================================================
echo.
echo Starting Wireshark monitoring for PE recording...
echo This will capture network traffic during the generation process
echo.

REM Check if Wireshark is installed
where tshark >nul 2>nul
if %errorlevel% neq 0 (
    echo ⚠️ Wireshark not found. Please install Wireshark first.
    echo Download from: https://www.wireshark.org/download.html
    pause
    exit /b 1
)

echo ✅ Wireshark found. Starting capture...
echo.

REM Start capture on all interfaces
echo Starting network capture...
tshark -i any -w pe_generation_capture.pcapng -f "tcp or udp" &
set CAPTURE_PID=%!

echo Capture started with PID: %CAPTURE_PID%
echo.

REM Monitor for 60 seconds
echo Monitoring for 60 seconds...
timeout /t 60 /nobreak >nul

REM Stop capture
echo Stopping capture...
taskkill /PID %CAPTURE_PID% /F >nul 2>nul

echo.
echo ✅ Wireshark capture completed!
echo Capture file: pe_generation_capture.pcapng
echo.

REM Check if capture file was created
if exist "pe_generation_capture.pcapng" (
    echo 📁 Capture file created successfully
    dir pe_generation_capture.pcapng
) else (
    echo ⚠️ Capture file not found
)

echo.
echo 🎭 PE RECORDING COMPLETE - THE TRILLION-DOLLAR LINE CAPTURED 🎭
echo The gap is the art; the artifact is the punchline.
echo Either way, mission accomplished – and the black-hole cursor keeps blinking.
echo.
pause
