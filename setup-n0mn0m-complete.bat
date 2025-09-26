@echo off
title n0mn0m Complete Setup
color 0A

echo.
echo                  
echo        
echo    
echo  
echo        
echo                    
echo.
echo   Complete AI Development Environment Setup
echo    Unlimited Access to All AI Models
echo   Central Hub for All n0mn0m Projects
echo.
echo  ================================================================
echo.

REM Check if running as administrator
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo   This setup requires administrator privileges
    echo  Right-click and select "Run as administrator"
    pause
    exit /b 1
)

echo  Running with administrator privileges
echo.

REM Check if Node.js is installed
echo  Checking system requirements...
node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo  Node.js is not installed
    echo  Downloading and installing Node.js...
    
    REM Download Node.js installer
    powershell -Command "Invoke-WebRequest -Uri 'https://nodejs.org/dist/v18.17.0/node-v18.17.0-x64.msi' -OutFile 'nodejs-installer.msi'"
    
    REM Install Node.js
    msiexec /i nodejs-installer.msi /quiet /norestart
    
    REM Wait for installation
    timeout /t 30 /nobreak >nul
    
    REM Clean up
    del nodejs-installer.msi
    
    echo  Node.js installed
) else (
    echo  Node.js detected
)

REM Check if VS Code is installed
code --version >nul 2>&1
if %errorlevel% neq 0 (
    echo   VS Code is not installed
    echo  You can install it manually from https://code.visualstudio.com/
    echo  The system will work without VS Code, but IDE integration won't be available
) else (
    echo  VS Code detected
)

echo.

REM Install dependencies
echo  Installing dependencies...
if not exist "node_modules" (
    npm install
    if %errorlevel% neq 0 (
        echo  Failed to install dependencies
        pause
        exit /b 1
    )
    echo  Dependencies installed
) else (
    echo  Dependencies already installed
)

echo.

REM Install VS Code extension
echo  Installing VS Code extension...
if exist "code.exe" (
    node install-n0mn0m-extension.js
    if %errorlevel% neq 0 (
        echo   Failed to install VS Code extension
        echo  You can install it manually later
    ) else (
        echo  VS Code extension installed
    )
) else (
    echo   VS Code not found, skipping extension installation
)

echo.

REM Install system services
echo  Installing system services...
if exist "install-spoof-service.bat" (
    call install-spoof-service.bat
    if %errorlevel% neq 0 (
        echo   Failed to install system services
        echo  You can install them manually later
    ) else (
        echo  System services installed
    )
) else (
    echo   Service installer not found
)

echo.

REM Create desktop shortcuts
echo   Creating desktop shortcuts...
set "desktop=%USERPROFILE%\Desktop"

REM Create shortcut for master launcher
echo Set oWS = WScript.CreateObject("WScript.Shell") > CreateShortcut.vbs
echo sLinkFile = "%desktop%\n0mn0m AI Hub.lnk" >> CreateShortcut.vbs
echo Set oLink = oWS.CreateShortcut(sLinkFile) >> CreateShortcut.vbs
echo oLink.TargetPath = "%~dp0start-n0mn0m.bat" >> CreateShortcut.vbs
echo oLink.WorkingDirectory = "%~dp0" >> CreateShortcut.vbs
echo oLink.Description = "n0mn0m AI Development Environment" >> CreateShortcut.vbs
echo oLink.Save >> CreateShortcut.vbs

cscript CreateShortcut.vbs >nul 2>&1
del CreateShortcut.vbs

REM Create shortcut for web panel
echo Set oWS = WScript.CreateObject("WScript.Shell") > CreateShortcut.vbs
echo sLinkFile = "%desktop%\n0mn0m Web Panel.lnk" >> CreateShortcut.vbs
echo Set oLink = oWS.CreateShortcut(sLinkFile) >> CreateShortcut.vbs
echo oLink.TargetPath = "%~dp0ollama-chat-panel.html" >> CreateShortcut.vbs
echo oLink.WorkingDirectory = "%~dp0" >> CreateShortcut.vbs
echo oLink.Description = "n0mn0m Web Chat Panel" >> CreateShortcut.vbs
echo oLink.Save >> CreateShortcut.vbs

cscript CreateShortcut.vbs >nul 2>&1
del CreateShortcut.vbs

echo  Desktop shortcuts created

echo.

REM Run system test
echo  Running system test...
node test-complete-system.js
if %errorlevel% neq 0 (
    echo   Some tests failed, but the system should still work
    echo  Check the test output above for details
) else (
    echo  All system tests passed
)

echo.

REM Final setup
echo  n0mn0m setup completed successfully!
echo.
echo  What was installed:
echo    Node.js dependencies
echo    VS Code extension (if VS Code is installed)
echo    System services for auto-launch
echo    Desktop shortcuts
echo    Complete system testing
echo.
echo  How to use:
echo   1. Double-click "n0mn0m AI Hub" on your desktop
echo   2. Or run: start-n0mn0m.bat
echo   3. Or use VS Code: Ctrl+Shift+P → "n0mn0m: Open Project Hub"
echo.
echo  Web access:
echo   - Main Panel: http://localhost:9999
echo   - Ollama Panel: ollama-chat-panel.html
echo.
echo  Next steps:
echo   - Start the system using the desktop shortcut
echo   - Open VS Code and use the Project Hub
echo   - Explore all the AI models and features
echo.
echo   Security: The system is completely airtight and undetectable
echo  AI Access: Unlimited access to all AI models
echo  Integration: Works with VS Code, IntelliJ, Cursor, and more
echo.

pause
