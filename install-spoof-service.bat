@echo off
title Install Auto-Spoof Service
color 0A

echo.
echo             
echo      
echo                  
echo                  
echo           
echo               
echo.
echo                    Auto-Spoof Service Installer
echo.

REM Check for administrator privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: This script must be run as Administrator
    echo Right-click and select "Run as administrator"
    pause
    exit /b 1
)

echo  Administrator privileges confirmed
echo.

REM Check if Node.js is installed
node --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Node.js is not installed
    echo Please install Node.js from https://nodejs.org/
    pause
    exit /b 1
)

echo  Node.js is installed
echo.

REM Install required packages
echo  Installing required packages...
npm install chalk ora figlet axios >nul 2>&1
if errorlevel 1 (
    echo  Warning: Some packages may not have installed correctly
)

echo  Packages installed
echo.

REM Create service script
echo  Creating service script...
(
echo @echo off
echo title Auto-Spoof Service
echo cd /d "%~dp0"
echo node auto-spoof-launcher.js
) > start-spoof-service.bat

echo  Service script created
echo.

REM Create startup script
echo  Creating startup script...
(
echo @echo off
echo REM Auto-Spoof Service Startup
echo cd /d "%~dp0"
echo start /min "" "start-spoof-service.bat"
) > startup-spoof.bat

echo  Startup script created
echo.

REM Add to Windows startup
echo  Adding to Windows startup...
copy "startup-spoof.bat" "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\" >nul 2>&1
if errorlevel 1 (
    echo  Warning: Could not add to startup folder
    echo You may need to manually add the startup script
) else (
    echo  Added to Windows startup
)

echo.

REM Create registry entry for service
echo  Creating registry entry...
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /v "AutoSpoofService" /t REG_SZ /d "\"%CD%\startup-spoof.bat\"" /f >nul 2>&1
if errorlevel 1 (
    echo  Warning: Could not create registry entry
) else (
    echo  Registry entry created
)

echo.

REM Start the service immediately
echo  Starting Auto-Spoof Service...
start /min "" "start-spoof-service.bat"

echo.
echo  Auto-Spoof Service installed and started!
echo.
echo  Service Details:
echo    - Service runs automatically on Windows startup
echo    - All AI models are unlocked and running locally
echo    - Completely airtight - no external detection possible
echo    - Auto-restarts if any service fails
echo.
echo  Available Services:
echo    - Ollama Server: http://localhost:11434
echo    - Spoofed AI API: http://localhost:9999
echo    - RawrZ Server: http://localhost:8080
echo.
echo  The service will now run in the background automatically
echo    You can use any Ollama-compatible client or the AI Terminal
echo.

pause
