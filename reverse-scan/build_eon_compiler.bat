@echo off
echo Building Eon Compiler for Windows...

REM Set up MSVC environment
call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat" 2>nul
if errorlevel 1 (
    call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" 2>nul
    if errorlevel 1 (
        echo Error: Visual Studio not found. Please install Visual Studio or set up MSVC environment.
        pause
        exit /b 1
    )
)

REM Create output directory
if not exist "bin" mkdir bin

REM Compile the complete Eon compiler
echo Compiling eon_compiler_complete.c...
cl /nologo /O2 /I. eon_compiler_complete.c /Fe:bin\eon.exe /link /SUBSYSTEM:CONSOLE

if errorlevel 1 (
    echo Compilation failed!
    pause
    exit /b 1
)

echo Compilation successful! Eon compiler created: bin\eon.exe

REM Test the compiler
echo Testing compiler with simple program...
bin\eon.exe test_simple.eon

if exist "output.s" (
    echo Assembly generated successfully: output.s
    echo.
    echo To complete the test:
    echo 1. Install NASM: https://www.nasm.us/
    echo 2. Run: nasm -f win64 output.s -o output.obj
    echo 3. Run: link output.obj /SUBSYSTEM:CONSOLE /OUT:test.exe
    echo 4. Run: test.exe
) else (
    echo Error: No assembly output generated
)

pause
