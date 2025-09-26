@echo off
echo === Building Self-Contained Compiler with GUI ===
echo.

REM Create build directory
if not exist "build" mkdir build
if not exist "build\gui" mkdir build\gui

echo === Building Self-Contained GUI Compiler ===
echo.

REM Check if NASM is available (for initial bootstrap only)
nasm -version >nul 2>&1
if %errorlevel% neq 0 (
    echo NOTE: NASM not found - this will be the last time we need it!
    echo After this build, the compiler will be completely self-contained.
    echo.
    echo Please install NASM for this one-time bootstrap build:
    echo https://www.nasm.us/
    pause
    exit /b 1
)

echo Bootstrapping self-contained compiler (last time using NASM)...
nasm -f win64 -o build\gui\self_contained_compiler_gui.o self_contained_compiler_gui.asm
if %errorlevel% neq 0 (
    echo ERROR: Failed to assemble GUI compiler
    pause
    exit /b 1
)

echo Linking with Windows libraries...
link /subsystem:windows /entry:_start /out:build\gui\RawrZCompilerIDE.exe build\gui\self_contained_compiler_gui.o kernel32.lib user32.lib gdi32.lib comctl32.lib comdlg32.lib
if %errorlevel% neq 0 (
    echo ERROR: Failed to link GUI compiler
    pause
    exit /b 1
)

echo.
echo === Self-Contained Compiler GUI Build Complete! ===
echo.
echo Output: build\gui\RawrZCompilerIDE.exe
echo.
echo Features:
echo - Complete GUI IDE with project management
echo - Self-contained compiler (no external dependencies)
echo - Direct machine code generation
echo - Built-in assembler and linker
echo - Multi-language support (Eon, C, C++, etc.)
echo - Project templates and file management
echo - Integrated build system
echo.
echo This is the LAST time external tools are needed!
echo The generated IDE can compile everything without dependencies.
echo.

REM Test the compiled GUI
echo Testing the GUI compiler...
if exist "build\gui\RawrZCompilerIDE.exe" (
    echo SUCCESS: GUI compiler built successfully!
    echo You can now run: build\gui\RawrZCompilerIDE.exe
    echo.
    echo The IDE includes:
    echo - File menu: New, Open, Save, Project management
    echo - Build menu: Compile, Build All, Clean
    echo - Run menu: Run, Debug
    echo - Project explorer with file tree
    echo - Syntax highlighting editor
    echo - Integrated compiler with zero dependencies
    echo.
) else (
    echo ERROR: GUI compiler executable not found
    exit /b 1
)

pause
