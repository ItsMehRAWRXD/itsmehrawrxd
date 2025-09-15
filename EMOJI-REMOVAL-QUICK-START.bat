@echo off
echo ========================================
echo RawrZ Emoji Removal - Quick Start
echo ========================================
echo.
echo This will remove all emojis from your project
echo to prevent ROE (Rate of Error) and malformities.
echo.
echo Files that will be processed:
echo - All .js files in src directory
echo - All .html files in src directory
echo - All .bat files in project
echo - All .md files in project
echo.
set /p confirm="Continue with emoji removal? (y/N): "
if /i "%confirm%" neq "y" (
    echo Emoji removal cancelled.
    exit /b 0
)
echo.
echo Starting emoji removal...
echo.

REM Check if Node.js is available
node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Node.js is not installed or not in PATH
    echo Please install Node.js from https://nodejs.org/
    echo.
    echo Alternative: Use remove-emojis-simple.bat instead
    pause
    exit /b 1
)

REM Run the portable emoji removal script
node emoji-removal-portable.js

echo.
echo ========================================
echo Emoji Removal Complete!
echo ========================================
echo.
echo Your project is now emoji-free and ROE-safe!
echo.
pause
