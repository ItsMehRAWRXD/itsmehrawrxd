@echo off
echo ========================================
echo   RawrZ Security Platform Desktop
echo   Offline Desktop Edition v2.0.0
echo ========================================
echo.

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found. Please install Python 3.8+
    pause
    exit /b 1
)

REM Check if .NET is available
dotnet --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: .NET not found. Please install .NET 6.0+
    pause
    exit /b 1
)

echo Starting RawrZ Desktop Backend...
echo.

REM Start Python backend in background
start /B "RawrZ Backend" python python_backend_integration.py

REM Wait a moment for backend to start
timeout /t 3 /nobreak >nul

echo Backend started. Launching Desktop App...
echo.

REM Build and run .NET desktop app
cd RawrZDesktop
dotnet build --configuration Release
if errorlevel 1 (
    echo ERROR: Failed to build .NET desktop app
    pause
    exit /b 1
)

echo Starting RawrZ Desktop Application...
echo.
dotnet run --configuration Release

echo.
echo RawrZ Desktop Application closed.
pause
