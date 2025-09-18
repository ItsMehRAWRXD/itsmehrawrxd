@echo off
echo ========================================
echo RawrZ Compiler Installation Script
echo ========================================
echo.
echo This script will help you install NASM and GCC compilers
echo required for assembly compilation in RawrZ.
echo.

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% == 0 (
    echo [OK] Running with administrator privileges
) else (
    echo [WARN] Not running as administrator. Some installations may require admin rights.
    echo.
)

echo [INFO] Checking current compiler status...
echo [INFO] Java is now the preferred compilation method for RawrZ engines.
echo.

REM Check for NASM
where nasm >nul 2>&1
if %errorLevel% == 0 (
    echo [OK] NASM is already installed
    nasm -v
) else (
    echo [WARN] NASM is not installed
    echo.
    echo [INFO] To install NASM:
    echo 1. Download from: https://www.nasm.us/pub/nasm/releasebuilds/
    echo 2. Run the installer
    echo 3. Add NASM to your PATH environment variable
    echo.
)

echo.

REM Check for GCC
where gcc >nul 2>&1
if %errorLevel% == 0 (
    echo [OK] GCC is already installed
    gcc --version
) else (
    echo [WARN] GCC is not installed
    echo.
    echo [INFO] To install GCC on Windows:
    echo Option 1 - MSYS2 (Recommended):
    echo 1. Download MSYS2 from: https://www.msys2.org/
    echo 2. Install MSYS2
    echo 3. Open MSYS2 terminal and run: pacman -S mingw-w64-x86_64-gcc
    echo 4. Add C:\msys64\mingw64\bin to your PATH
    echo.
    echo Option 2 - MinGW-w64:
    echo 1. Download from: https://www.mingw-w64.org/downloads/
    echo 2. Install and add to PATH
    echo.
)

echo.

REM Check for Chocolatey (package manager for Windows)
where choco >nul 2>&1
if %errorLevel% == 0 (
    echo [OK] Chocolatey is available
    echo.
    echo [INFO] You can install compilers using Chocolatey:
    echo choco install nasm
    echo choco install mingw
    echo.
) else (
    echo [INFO] Chocolatey package manager not found
    echo [INFO] You can install it from: https://chocolatey.org/install
    echo.
)

echo ========================================
echo Installation Instructions Summary:
echo ========================================
echo.
echo 1. Install NASM:
echo    - Download from: https://www.nasm.us/pub/nasm/releasebuilds/
echo    - Run installer and add to PATH
echo.
echo 2. Install GCC:
echo    - Use MSYS2 (recommended) or MinGW-w64
echo    - Add compiler bin directory to PATH
echo.
echo 3. Verify installation:
echo    - Open new command prompt
echo    - Run: nasm -v
echo    - Run: gcc --version
echo.
echo 4. Restart RawrZ after installation
echo.
echo ========================================

pause
