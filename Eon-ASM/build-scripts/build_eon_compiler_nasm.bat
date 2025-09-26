@echo off
REM Eon Compiler NASM Build Script
REM Builds the complete Eon compiler using NASM and GCC

echo Building Eon Compiler with NASM...

REM Set paths
set NASM_PATH=C:\Users\Garre\Desktop\RawrZApp\Eon-ASM\compilers
set BUILD_PATH=C:\Users\Garre\Desktop\RawrZApp\Eon-ASM\build
set OUTPUT_PATH=C:\Users\Garre\Desktop\RawrZApp\Eon-ASM\bin

REM Create build directories
if not exist "%BUILD_PATH%" mkdir "%BUILD_PATH%"
if not exist "%OUTPUT_PATH%" mkdir "%OUTPUT_PATH%"

REM Check for NASM
where nasm >nul 2>nul
if %errorlevel% neq 0 (
    echo Error: NASM not found in PATH
    echo Please install NASM or add it to your PATH
    pause
    exit /b 1
)

REM Check for GCC
where gcc >nul 2>nul
if %errorlevel% neq 0 (
    echo Error: GCC not found in PATH
    echo Please install MinGW-w64 or add GCC to your PATH
    pause
    exit /b 1
)

echo Assembling Eon compiler components...

REM Assemble the lexer
echo Assembling lexer...
nasm -f win64 -o "%BUILD_PATH%\eon_lexer.o" "%NASM_PATH%\eon_lexer_complete.cpp"
if %errorlevel% neq 0 (
    echo Error assembling lexer
    pause
    exit /b 1
)

REM Assemble the parser
echo Assembling parser...
nasm -f win64 -o "%BUILD_PATH%\eon_parser.o" "%NASM_PATH%\eon_parser_complete.cpp"
if %errorlevel% neq 0 (
    echo Error assembling parser
    pause
    exit /b 1
)

REM Assemble the Pratt parser
echo Assembling Pratt parser...
nasm -f win64 -o "%BUILD_PATH%\eon_pratt_parser.o" "%NASM_PATH%\eon_pratt_parser.asm"
if %errorlevel% neq 0 (
    echo Error assembling Pratt parser
    pause
    exit /b 1
)

REM Assemble the main compiler
echo Assembling main compiler...
nasm -f win64 -o "%BUILD_PATH%\eon_compiler_main.o" "%NASM_PATH%\eon_compiler.c"
if %errorlevel% neq 0 (
    echo Error assembling main compiler
    pause
    exit /b 1
)

REM Assemble the semantic analyzer
echo Assembling semantic analyzer...
nasm -f win64 -o "%BUILD_PATH%\eon_semantic.o" "%NASM_PATH%\eon_compiler_semantic.c"
if %errorlevel% neq 0 (
    echo Error assembling semantic analyzer
    pause
    exit /b 1
)

REM Assemble the code generator
echo Assembling code generator...
nasm -f win64 -o "%BUILD_PATH%\eon_codegen.o" "%NASM_PATH%\eon_assembly_generator.c"
if %errorlevel% neq 0 (
    echo Error assembling code generator
    pause
    exit /b 1
)

echo Linking Eon compiler...

REM Link all objects into final executable
gcc -o "%OUTPUT_PATH%\eon_compiler.exe" ^
    "%BUILD_PATH%\eon_lexer.o" ^
    "%BUILD_PATH%\eon_parser.o" ^
    "%BUILD_PATH%\eon_pratt_parser.o" ^
    "%BUILD_PATH%\eon_compiler_main.o" ^
    "%BUILD_PATH%\eon_semantic.o" ^
    "%BUILD_PATH%\eon_codegen.o" ^
    -static-libgcc -static-libstdc++

if %errorlevel% neq 0 (
    echo Error linking Eon compiler
    pause
    exit /b 1
)

echo.
echo Eon compiler built successfully!
echo Executable: %OUTPUT_PATH%\eon_compiler.exe
echo.

REM Test the compiler with a simple Eon program
echo Testing compiler with sample program...
"%OUTPUT_PATH%\eon_compiler.exe" "%NASM_PATH%\..\source\basic_test.eon" -o "%OUTPUT_PATH%\test_output.asm"

if %errorlevel% equ 0 (
    echo Test compilation successful!
    echo Output: %OUTPUT_PATH%\test_output.asm
) else (
    echo Test compilation failed
)

echo.
echo Build complete!
pause
