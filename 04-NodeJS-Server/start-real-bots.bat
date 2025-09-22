@echo off
echo Starting RawrZ Real Bot Server...
echo.

REM Check if Node.js is installed
node --version >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo ❌ Node.js is not installed or not in PATH
    echo Please install Node.js from https://nodejs.org/
    pause
    exit /b 1
)

REM Check if package.json exists
if not exist "package.json" (
    echo ❌ package.json not found
    echo Please run this from the RawrZ project directory
    pause
    exit /b 1
)

REM Install dependencies if node_modules doesn't exist
if not exist "node_modules" (
    echo 📦 Installing dependencies...
    npm install
    if %ERRORLEVEL% neq 0 (
        echo ❌ Failed to install dependencies
        pause
        exit /b 1
    )
)

echo 🚀 Starting Real Bot Server...
echo.
echo ✅ Real bot implementations connected:
echo    • HTTP Bot Manager
echo    • IRC Bot Generator  
echo    • HTTP Bot Generator
echo    • RawrZ Engine
echo.
echo 🌐 Panel available at: http://localhost:8080/panel
echo 🤖 OhGee Chat Assistant will connect to real bot data
echo.
echo Press Ctrl+C to stop the server
echo.

node server-real-bots.js
