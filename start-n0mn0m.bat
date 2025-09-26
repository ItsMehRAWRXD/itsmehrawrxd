@echo off
title n0mn0m Master Launcher
color 0A

echo.
echo                  
echo        
echo    
echo  
echo        
echo                    
echo.
echo   AI Development Environment with Unlimited Access
echo    Complete Stealth Operation - Undetectable by External Systems
echo   Central Hub for All n0mn0m Projects
echo.
echo  ================================================================
echo.

REM Check if Node.js is installed
node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo  Node.js is not installed or not in PATH
    echo  Please install Node.js from https://nodejs.org/
    pause
    exit /b 1
)

REM Check if required files exist
if not exist "n0mn0m-master-launcher.js" (
    echo  n0mn0m-master-launcher.js not found
    echo  Please ensure you're running this from the n0mn0m directory
    pause
    exit /b 1
)

echo  Node.js detected
echo  n0mn0m files found
echo.

REM Install dependencies if needed
if not exist "node_modules" (
    echo  Installing dependencies...
    npm install
    if %errorlevel% neq 0 (
        echo  Failed to install dependencies
        pause
        exit /b 1
    )
    echo  Dependencies installed
    echo.
)

REM Start the master launcher
echo  Starting n0mn0m Master System...
echo.
echo  This will:
echo    - Install VS Code extension (if needed)
echo    - Start all AI services
echo    - Open Project Hub
echo    - Provide unlimited access to all AI models
echo.
echo  Press Ctrl+C to stop all services
echo.

node n0mn0m-master-launcher.js

echo.
echo  n0mn0m system stopped
pause
