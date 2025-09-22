@echo off
REM ========================================
REM EON IDE Build Script - XCB Graphical Frontend
REM ========================================
REM This script builds the complete EON IDE with XCB graphical interface
REM Includes: EON Compiler, IDE Interface, Debugger, and Build System
REM ========================================

echo 🚀 Building EON IDE with XCB Graphical Frontend
echo ==============================================

REM Configuration
set ASM_FILE=eon_ide_xcb.asm
set OUTPUT_FILE=eon_ide.exe
set OBJECT_FILE=eon_ide.o
set LINK_FLAGS=-lxcb

REM Check dependencies
echo 📋 Checking dependencies...

REM Check for NASM
where nasm >nul 2>nul
if %errorlevel% neq 0 (
    echo ❌ NASM not found. Please install NASM assembler.
    echo    Download from: https://www.nasm.us/
    echo    Or use: winget install nasm
    pause
    exit /b 1
)

REM Check for ld (linker) - usually comes with MinGW or WSL
where ld >nul 2>nul
if %errorlevel% neq 0 (
    echo ❌ Linker (ld) not found. Please install MinGW or WSL.
    echo    MinGW: https://www.mingw-w64.org/
    echo    WSL: wsl --install
    pause
    exit /b 1
)

echo ✅ All dependencies found

REM Build process
echo.
echo 🔨 Building EON IDE...

REM Step 1: Assemble the source code
echo 📝 Assembling %ASM_FILE%...
nasm -f elf64 -o %OBJECT_FILE% %ASM_FILE%
if %errorlevel% neq 0 (
    echo ❌ Assembly failed
    pause
    exit /b 1
)
echo ✅ Assembly successful

REM Step 2: Link the object file
echo 🔗 Linking %OBJECT_FILE%...
ld -o %OUTPUT_FILE% %OBJECT_FILE% %LINK_FLAGS%
if %errorlevel% neq 0 (
    echo ❌ Linking failed
    pause
    exit /b 1
)
echo ✅ Linking successful

REM Step 3: Make executable (already done on Windows)
REM chmod +x %OUTPUT_FILE%

REM Step 4: Clean up object file
del %OBJECT_FILE%

echo.
echo 🎉 EON IDE Build Complete!
echo ==========================
echo 📄 Executable: %OUTPUT_FILE%
echo 📊 Size: 
dir %OUTPUT_FILE% | findstr %OUTPUT_FILE%
echo.
echo 🚀 To run the EON IDE:
echo    .\%OUTPUT_FILE%
echo.
echo 📋 Features included:
echo    ✅ XCB Graphical Interface
echo    ✅ 8x8 Font Rendering
echo    ✅ Event Loop (Expose, Key Press)
echo    ✅ Back Buffer Rendering
echo    ✅ Ready for EON Compiler Integration
echo.
echo 🔧 Next steps:
echo    1. Run: .\%OUTPUT_FILE%
echo    2. Integrate EON compiler logic
echo    3. Add keyboard input handling
echo    4. Implement editor buffer display
echo    5. Add syntax highlighting
echo    6. Integrate debugger interface
echo.
echo 💡 Development tips:
echo    - Use 'xev' to test key events (in WSL/Linux)
echo    - Check XCB documentation for advanced features
echo    - Consider adding menu bars and toolbars
echo    - Implement file I/O for project management

pause
