@echo off
title AI-Enhanced Safe Hybrid IDE - Installation
echo.
echo 🤖 AI-Enhanced Safe Hybrid IDE Installation
echo ==========================================
echo.
echo This script will install the required dependencies for the AI-enhanced IDE.
echo.
echo Required packages:
echo - aiohttp (async HTTP for AI APIs)
echo - requests (HTTP for service checks)
echo - typing-extensions (type hints)
echo.
pause
echo.
echo 📦 Installing dependencies...
echo.

pip install -r requirements.txt

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ✅ Installation completed successfully!
    echo.
    echo 🚀 You can now run the AI-Enhanced IDE with:
    echo    python safe_hybrid_ide.py
    echo.
    echo 💡 Quick start:
    echo 1. Run the IDE
    echo 2. Click "🔑 AI Settings" to configure your API keys
    echo 3. Use "🤖 AI Analyze" (F7) to get multi-AI code suggestions
    echo.
    echo 📖 Read README_AI_INTEGRATION.md for detailed setup instructions.
    echo.
) else (
    echo.
    echo ❌ Installation failed. Please check your Python and pip installation.
    echo.
    echo 🛠️ Troubleshooting:
    echo - Make sure Python 3.7+ is installed
    echo - Try: python -m pip install -r requirements.txt
    echo - Check internet connection
    echo.
)

pause
