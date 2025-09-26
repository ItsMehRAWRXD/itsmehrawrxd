@echo off
REM BlueStacks Integration Script for Windows

echo Starting BlueStacks integration...

REM Check if BlueStacks is installed
if exist "C:\Program Files\BlueStacks_nxt\HD-Player.exe" (
    set BLUESTACKS_PATH=C:\Program Files\BlueStacks_nxt
) else if exist "C:\Program Files (x86)\BlueStacks_nxt\HD-Player.exe" (
    set BLUESTACKS_PATH=C:\Program Files (x86)\BlueStacks_nxt
) else (
    echo BlueStacks not found. Please install BlueStacks first.
    pause
    exit /b 1
)

echo BlueStacks found at: %BLUESTACKS_PATH%

REM Start BlueStacks
echo Starting BlueStacks...
start "" "%BLUESTACKS_PATH%\HD-Player.exe"

REM Wait for BlueStacks to start
echo Waiting for BlueStacks to start...
timeout /t 30 /nobreak

REM Connect to BlueStacks via ADB
echo Connecting to BlueStacks via ADB...
adb connect 127.0.0.1:5555

REM Check connection
echo Checking ADB connection...
adb devices

echo BlueStacks integration complete!
echo You can now develop Android apps with BlueStacks as the emulator.
pause
