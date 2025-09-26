@echo off
setlocal enabledelayedexpansion

echo ========================================
echo    Eon Compiler Windows Build System
echo ========================================
echo.

REM Check for Visual Studio installation
set "VS_FOUND=0"
set "VS_PATH="

REM Try Visual Studio 2022
if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" (
    set "VS_PATH=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
    set "VS_FOUND=1"
    echo Found Visual Studio 2022 Community
) else if exist "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat" (
    set "VS_PATH=C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat"
    set "VS_FOUND=1"
    echo Found Visual Studio 2022 Professional
) else if exist "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat" (
    set "VS_PATH=C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
    set "VS_FOUND=1"
    echo Found Visual Studio 2022 Enterprise
)

REM Try Visual Studio 2019
if "%VS_FOUND%"=="0" (
    if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat" (
        set "VS_PATH=C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat"
        set "VS_FOUND=1"
        echo Found Visual Studio 2019 Community
    ) else if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvars64.bat" (
        set "VS_PATH=C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvars64.bat"
        set "VS_FOUND=1"
        echo Found Visual Studio 2019 Professional
    ) else if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvars64.bat" (
        set "VS_PATH=C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
        set "VS_FOUND=1"
        echo Found Visual Studio 2019 Enterprise
    )
)

if "%VS_FOUND%"=="0" (
    echo Error: Visual Studio not found!
    echo Please install Visual Studio 2019 or 2022 with C++ support.
    echo Download from: https://visualstudio.microsoft.com/downloads/
    pause
    exit /b 1
)

echo Setting up MSVC environment...
call "%VS_PATH%"

REM Create directories
if not exist "bin" mkdir bin
if not exist "obj" mkdir obj
if not exist "test_output" mkdir test_output

echo.
echo Building Eon Compiler...
echo.

REM Compile the complete Eon compiler
echo [1/3] Compiling eon_compiler_complete.c...
cl /nologo /O2 /I. eon_compiler_complete.c /Fe:bin\eon.exe /link /SUBSYSTEM:CONSOLE
if errorlevel 1 (
    echo Error: Failed to compile eon_compiler_complete.c
    pause
    exit /b 1
)

REM Compile the test suite
echo [2/3] Compiling test suite...
cl /nologo /O2 /I. eon_compiler_test_suite.c /Fe:bin\test_suite.exe /link /SUBSYSTEM:CONSOLE
if errorlevel 1 (
    echo Error: Failed to compile test suite
    pause
    exit /b 1
)

REM Compile missing functions
echo [3/3] Compiling missing functions...
cl /nologo /O2 /I. eon_compiler_missing_functions.c /Fe:bin\missing_functions.exe /link /SUBSYSTEM:CONSOLE
if errorlevel 1 (
    echo Error: Failed to compile missing functions
    pause
    exit /b 1
)

echo.
echo ========================================
echo    Build Complete!
echo ========================================
echo.
echo Generated files:
echo   bin\eon.exe              - Eon Compiler
echo   bin\test_suite.exe       - Test Suite
echo   bin\missing_functions.exe - Missing Functions
echo.

REM Test the compiler
echo Testing Eon Compiler...
echo.

if exist "bin\eon.exe" (
    echo [TEST] Basic compilation test...
    echo def main() { let x = 5; ret x; } > test_output\basic_test.eon
    bin\eon.exe test_output\basic_test.eon
    if exist "output.s" (
        echo  Basic compilation successful
        move output.s test_output\basic_test.s
    ) else (
        echo  Basic compilation failed
    )
    
    echo.
    echo [TEST] Function test...
    echo def add(a, b) { ret a + b; } def main() { let result = add(5, 3); ret result; } > test_output\function_test.eon
    bin\eon.exe test_output\function_test.eon
    if exist "output.s" (
        echo  Function compilation successful
        move output.s test_output\function_test.s
    ) else (
        echo  Function compilation failed
    )
    
    echo.
    echo [TEST] Control flow test...
    echo def main() { let x = 10; if (x > 5) { ret 1; } else { ret 0; } } > test_output\control_test.eon
    bin\eon.exe test_output\control_test.eon
    if exist "output.s" (
        echo  Control flow compilation successful
        move output.s test_output\control_test.s
    ) else (
        echo  Control flow compilation failed
    )
    
    echo.
    echo ========================================
    echo    Test Results
    echo ========================================
    echo.
    echo Generated assembly files in test_output\:
    dir test_output\*.s
    echo.
    echo To complete the test:
    echo 1. Install NASM: https://www.nasm.us/
    echo 2. Run: nasm -f win64 test_output\basic_test.s -o test_output\basic_test.obj
    echo 3. Run: link test_output\basic_test.obj /SUBSYSTEM:CONSOLE /OUT:test_output\basic_test.exe
    echo 4. Run: test_output\basic_test.exe
    echo.
    
) else (
    echo Error: Eon compiler not found!
)

echo.
echo Build and test complete!
echo.
pause
