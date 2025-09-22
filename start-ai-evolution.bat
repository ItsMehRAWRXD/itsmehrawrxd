@echo off
title AI Evolution System - Self-Building AI
color 0A

echo.
echo  █████╗ ██╗    ███████╗██╗   ██╗ ██████╗ ██╗   ██╗████████╗██╗ ██████╗ ███╗   ██╗
echo  ██╔══██╗██║    ██╔════╝██║   ██║██╔════╝ ██║   ██║╚══██╔══╝██║██╔═══██╗████╗  ██║
echo  ███████║██║    █████╗  ██║   ██║██║  ███╗██║   ██║   ██║   ██║██║   ██║██╔██╗ ██║
echo  ██╔══██║██║    ██╔══╝  ██║   ██║██║   ██║██║   ██║   ██║   ██║██║   ██║██║╚██╗██║
echo  ██║  ██║██║    ██║     ╚██████╔╝╚██████╔╝╚██████╔╝   ██║   ██║╚██████╔╝██║ ╚████║
echo  ╚═╝  ╚═╝╚═╝    ╚═╝      ╚═════╝  ╚═════╝  ╚═════╝    ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝
echo.
echo  🧠 Self-Building AI System
echo  🚀 AI that asks itself questions to continuously improve
echo  🤖 Watch as it evolves into something amazing!
echo.
echo  ================================================================
echo.

REM Check if Node.js is installed
node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Node.js is not installed or not in PATH
    echo 💡 Please install Node.js from https://nodejs.org/
    pause
    exit /b 1
)

echo ✅ Node.js detected
echo.

REM Check if required files exist
if not exist "self-building-ai.js" (
    echo ❌ self-building-ai.js not found
    echo 💡 Please ensure you're running this from the n0mn0m directory
    pause
    exit /b 1
)

if not exist "gemini-ide-completion.js" (
    echo ❌ gemini-ide-completion.js not found
    echo 💡 Please ensure you're running this from the n0mn0m directory
    pause
    exit /b 1
)

echo ✅ AI evolution files found
echo.

REM Install dependencies if needed
if not exist "node_modules" (
    echo 📦 Installing dependencies...
    npm install
    if %errorlevel% neq 0 (
        echo ❌ Failed to install dependencies
        pause
        exit /b 1
    )
    echo ✅ Dependencies installed
    echo.
)

echo 🧠 Starting AI Evolution System...
echo.
echo 💡 This will:
echo    - Start the spoofed AI server
echo    - Begin self-building AI process
echo    - Ask Gemini questions to improve itself
echo    - Continuously evolve and enhance capabilities
echo    - Create new features and optimizations
echo.
echo 🤖 The AI will literally build itself through intelligent questioning!
echo 🚀 Watch as it becomes more powerful with each iteration!
echo.
echo 🔧 Press Ctrl+C to stop the evolution process
echo.

REM Start the self-building AI system
node self-building-ai.js

echo.
echo 🛑 AI Evolution System stopped
echo 📊 Check build-history.json to see what the AI built
echo 📈 Check system-state.json to see current capabilities
pause
