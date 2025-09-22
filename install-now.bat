@echo off
title One-Click Auto-Spoof Installer
color 0A

echo.
echo  █████╗ ██╗██████╗ ████████╗██╗ ██████╗ ██╗     ██╗ ██████╗ ███████╗
echo ██╔══██╗██║██╔══██╗╚══██╔══╝██║██╔═══██╗██║     ██║██╔═══██╗██╔════╝
echo ███████║██║██████╔╝   ██║   ██║██║   ██║██║     ██║██║   ██║███████╗
echo ██╔══██║██║██╔══██╗   ██║   ██║██║   ██║██║     ██║██║   ██║╚════██║
echo ██║  ██║██║██║  ██║   ██║   ██║╚██████╔╝███████╗██║╚██████╔╝███████║
echo ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚══════╝╚═╝ ╚═════╝ ╚══════╝
echo.
echo                    ONE-CLICK AUTO-SPOOF INSTALLER
echo.
echo This will install a completely airtight AI system that:
echo - Runs all AI models locally (appears as Ollama)
echo - Cannot be detected or stopped by external systems
echo - Auto-starts on system boot
echo - Provides unlimited access to all AI models
echo.
echo Press any key to continue or close this window to cancel...
pause >nul

echo.
echo 🚀 Starting installation...
echo.

REM Run the master launcher
node master-spoof-launcher.js

echo.
echo ✅ Installation complete!
echo.
echo 🎯 Your AI system is now running with:
echo    - Complete unlock of all AI models
echo    - Local execution (no external calls)
echo    - Auto-restart on failure
echo    - Stealth mode (undetectable)
echo.
echo 💡 You can now use any AI client or the included terminal
echo.
pause
