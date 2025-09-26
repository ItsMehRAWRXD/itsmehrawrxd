@echo off
REM Test script for Eon compiler
REM Verifies that the compiler can process Eon source files

echo Testing Eon Compiler...
echo.

set COMPILER_PATH=C:\Users\Garre\Desktop\RawrZApp\Eon-ASM\bin\eon_compiler.exe
set TEST_DIR=C:\Users\Garre\Desktop\RawrZApp\Eon-ASM\examples
set OUTPUT_DIR=C:\Users\Garre\Desktop\RawrZApp\Eon-ASM\test-output

REM Create output directory
if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"

REM Check if compiler exists
if not exist "%COMPILER_PATH%" (
    echo Error: Eon compiler not found at %COMPILER_PATH%
    echo Please run build_eon_compiler_nasm.bat first
    pause
    exit /b 1
)

echo Compiler found: %COMPILER_PATH%
echo.

REM Test 1: Basic syntax test
echo Test 1: Basic syntax test...
"%COMPILER_PATH%" "%TEST_DIR%\hello_world.eon" -o "%OUTPUT_DIR%\hello_world.asm"
if %errorlevel% equ 0 (
    echo  Basic syntax test passed
) else (
    echo  Basic syntax test failed
)

echo.

REM Test 2: Simple arithmetic
echo Test 2: Simple arithmetic...
echo "def func test() -> int { ret 1 + 2 * 3 }" > "%OUTPUT_DIR%\arithmetic.eon"
"%COMPILER_PATH%" "%OUTPUT_DIR%\arithmetic.eon" -o "%OUTPUT_DIR%\arithmetic.asm"
if %errorlevel% equ 0 (
    echo  Arithmetic test passed
) else (
    echo  Arithmetic test failed
)

echo.

REM Test 3: String interpolation
echo Test 3: String interpolation...
echo "def func test() -> string { let name = \"World\"; ret \"Hello ${name}!\" }" > "%OUTPUT_DIR%\strings.eon"
"%COMPILER_PATH%" "%OUTPUT_DIR%\strings.eon" -o "%OUTPUT_DIR%\strings.asm"
if %errorlevel% equ 0 (
    echo  String interpolation test passed
) else (
    echo  String interpolation test failed
)

echo.

REM Test 4: Control flow
echo Test 4: Control flow...
echo "def func test() -> int { if true { ret 1 } else { ret 0 } }" > "%OUTPUT_DIR%\control_flow.eon"
"%COMPILER_PATH%" "%OUTPUT_DIR%\control_flow.eon" -o "%OUTPUT_DIR%\control_flow.asm"
if %errorlevel% equ 0 (
    echo  Control flow test passed
) else (
    echo  Control flow test failed
)

echo.

REM Test 5: Function calls
echo Test 5: Function calls...
echo "def func add(a: int, b: int) -> int { ret a + b }" > "%OUTPUT_DIR%\functions.eon"
echo "def func test() -> int { ret add(1, 2) }" >> "%OUTPUT_DIR%\functions.eon"
"%COMPILER_PATH%" "%OUTPUT_DIR%\functions.eon" -o "%OUTPUT_DIR%\functions.asm"
if %errorlevel% equ 0 (
    echo  Function calls test passed
) else (
    echo  Function calls test failed
)

echo.

REM Display test results
echo Test Results Summary:
echo ====================
echo Output files generated in: %OUTPUT_DIR%
echo.

REM List generated files
echo Generated files:
dir "%OUTPUT_DIR%\*.asm" /b
echo.

REM Check for any error files
if exist "%OUTPUT_DIR%\*.err" (
    echo Error files found:
    dir "%OUTPUT_DIR%\*.err" /b
    echo.
)

echo Testing complete!
pause
