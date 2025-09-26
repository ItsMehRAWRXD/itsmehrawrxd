@echo off
echo Installing Docker Services for AI IDE...
echo.

REM Check if Python is available
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Python is not installed or not in PATH
    echo Please install Python 3.8+ and try again
    pause
    exit /b 1
)

echo ✅ Python is available

REM Install Flask for Docker services
echo 📦 Installing Flask for Docker services...
pip install flask>=2.0.0
if %errorlevel% neq 0 (
    echo ❌ Failed to install Flask
    echo Docker services will not work without Flask
    pause
    exit /b 1
)

echo ✅ Flask installed successfully

REM Install requests for HTTP testing
echo 📦 Installing requests for HTTP testing...
pip install requests>=2.28.0
if %errorlevel% neq 0 (
    echo ❌ Failed to install requests
    echo HTTP testing will not work without requests
    pause
    exit /b 1
)

echo ✅ Requests installed successfully

echo.
echo 🎉 Docker services installation completed!
echo.
echo 🚀 You can now:
echo   - Run the IDE: python safe_hybrid_ide.py
echo   - Test Docker services: python test_docker_services.py
echo   - Use Model Manager (F8) to manage Docker services
echo.
echo 📋 Available Docker services:
echo   - ChatGPT API Server (port 5001)
echo   - Claude API Server (port 5002)
echo   - Ollama Server (port 11434)
echo   - Code Analyzer (port 5003)
echo   - AI Copilot (port 5004)
echo.
pause
