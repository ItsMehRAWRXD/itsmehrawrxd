@echo off
title n0mn0m IDE Completion System
color 0A

echo.
echo  ███╗   ██╗ ██████╗ ███╗   ███╗███╗   ██╗ ██████╗ ███╗   ██╗ ██████╗ ███╗   ███╗
echo  ████╗  ██║██╔═══██╗████╗ ████║████╗  ██║██╔═══██╗████╗  ██║██╔═══██╗████╗ ████║
echo  ██╔██╗ ██║██║   ██║██╔████╔██║██╔██╗ ██║██║   ██║██╔██╗ ██║██║   ██║██╔████╔██║
echo  ██║╚██╗██║██║   ██║██║╚██╔╝██║██║╚██╗██║██║   ██║██║╚██╗██║██║   ██║██║╚██╔╝██║
echo  ██║ ╚████║╚██████╔╝██║ ╚═╝ ██║██║ ╚████║╚██████╔╝██║ ╚████║╚██████╔╝██║ ╚═╝ ██║
echo  ╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝
echo.
echo                    IDE Completion System with AI Integration
echo.

echo Starting n0mn0m IDE Completion System...
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
npm list axios >nul 2>&1
if errorlevel 1 (
    echo Installing required packages...
    npm install axios
    if errorlevel 1 (
        echo ERROR: Failed to install dependencies
        pause
        exit /b 1
    )
)

REM Start the IDE Completion System
echo Starting IDE Completion System...
echo.
node n0mn0m-ide-completion.js

pause
