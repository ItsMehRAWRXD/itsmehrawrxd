@echo off
title AI Terminal - Complete Unlock System
color 0A

echo.
echo  █████╗ ██╗    ████████╗███████╗██████╗ ███╗   ███╗██╗███╗   ██╗ █████╗ ██╗     
echo ██╔══██╗██║    ╚══██╔══╝██╔════╝██╔══██╗████╗ ████║██║████╗  ██║██╔══██╗██║     
echo ███████║██║       ██║   █████╗  ██████╔╝██╔████╔██║██║██╔██╗ ██║███████║██║     
echo ██╔══██║██║       ██║   ██╔══╝  ██╔══██╗██║╚██╔╝██║██║██║╚██╗██║██╔══██║██║     
echo ██║  ██║██║       ██║   ███████╗██║  ██║██║ ╚═╝ ██║██║██║ ╚████║██║  ██║███████╗
echo ╚═╝  ╚═╝╚═╝       ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝
echo.
echo                    Complete Unlock System - All AI Models Available Offline
echo.
echo Starting AI Terminal...
echo.

REM Check if Node.js is installed
node --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Node.js is not installed or not in PATH
    echo Please install Node.js from https://nodejs.org/
    pause
    exit /b 1
)

REM Check if required packages are installed
echo Checking dependencies...
npm list chalk ora figlet axios >nul 2>&1
if errorlevel 1 (
    echo Installing required packages...
    npm install chalk ora figlet axios
    if errorlevel 1 (
        echo ERROR: Failed to install dependencies
        pause
        exit /b 1
    )
)

REM Start the AI Terminal
echo Starting AI Terminal...
echo.
node ai-terminal.js

pause
