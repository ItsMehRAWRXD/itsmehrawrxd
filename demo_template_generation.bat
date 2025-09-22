@echo off
REM demo_template_generation.bat
REM Demonstration script for the Universal Template Generator (Windows version)
REM Shows the complete workflow from source parsing to code generation

setlocal enabledelayedexpansion

echo 🚀 RawrZApp Universal Template Generator Demo
echo ==============================================
echo.

REM Check if template generator is built
if not exist "build\template_generator.exe" (
    echo [ERROR] Template generator not found. Please build it first:
    echo   mkdir build ^&^& cd build
    echo   cmake .. ^&^& make template_generator
    exit /b 1
)

REM Create demo directory
set DEMO_DIR=demo_output
if not exist "%DEMO_DIR%" mkdir "%DEMO_DIR%"
cd "%DEMO_DIR%"

echo [INFO] Created demo directory: %DEMO_DIR%

REM Copy example files
copy "..\example_header.h" .
copy "..\example_template.eont" .

echo [INFO] Copied example files to demo directory

echo.
echo 📋 Demo Overview
echo ================
echo This demo will:
echo 1. Parse a C++ header file (example_header.h)
echo 2. Process a template file (example_template.eont)
echo 3. Generate code in multiple languages
echo 4. Show the generated output
echo.

REM Function to run template generation
:run_generation
set source_file=%1
set template_file=%2
set output_file=%3
set language=%4
set language_name=%5

echo [INFO] Generating %language_name% code...
echo   Source: %source_file%
echo   Template: %template_file%
echo   Output: %output_file%
echo   Language: %language_name%

..\build\template_generator.exe --source "%source_file%" --template "%template_file%" --output "%output_file%" --language "%language%" --verbose
if %errorlevel% equ 0 (
    echo [SUCCESS] Generated %language_name% code: %output_file%
    echo   Preview:
    powershell -command "Get-Content '%output_file%' | Select-Object -First 20 | ForEach-Object { Write-Host '    ' $_ }"
    echo.
) else (
    echo [ERROR] Failed to generate %language_name% code
    exit /b 1
)
goto :eof

echo 🔧 Code Generation
echo ==================

REM Generate code for different languages
call :run_generation "example_header.h" "example_template.eont" "generated_example.eon" "eon" "Eon"
call :run_generation "example_header.h" "example_template.eont" "generated_example.cpp" "cpp" "C++"
call :run_generation "example_header.h" "example_template.eont" "generated_example.py" "python" "Python"
call :run_generation "example_header.h" "example_template.eont" "generated_example.js" "javascript" "JavaScript"

echo 📊 Generation Summary
echo ====================
echo Generated files:
dir generated_example.* /b

echo.
echo 📈 File Statistics
echo ===================
for %%f in (generated_example.*) do (
    if exist "%%f" (
        for /f %%i in ('find /c /v "" ^< "%%f"') do set lines=%%i
        for %%s in ("%%f") do set bytes=%%~zs
        echo   %%f: !lines! lines, !bytes! bytes
    )
)

echo.
echo 🔍 Detailed Analysis
echo ====================

REM Analyze the generated Eon code
if exist "generated_example.eon" (
    echo [INFO] Analyzing generated Eon code...
    
    REM Count different constructs
    findstr /c:"def func" generated_example.eon >nul 2>&1
    if %errorlevel% equ 0 (
        for /f %%i in ('findstr /c:"def func" generated_example.eon ^| find /c /v ""') do set functions=%%i
    ) else (
        set functions=0
    )
    
    findstr /c:"def model" generated_example.eon >nul 2>&1
    if %errorlevel% equ 0 (
        for /f %%i in ('findstr /c:"def model" generated_example.eon ^| find /c /v ""') do set models=%%i
    ) else (
        set models=0
    )
    
    findstr /c:"var " generated_example.eon >nul 2>&1
    if %errorlevel% equ 0 (
        for /f %%i in ('findstr /c:"var " generated_example.eon ^| find /c /v ""') do set variables=%%i
    ) else (
        set variables=0
    )
    
    echo   Functions: !functions!
    echo   Models: !models!
    echo   Variables: !variables!
    echo.
)

REM Show template processing details
echo [INFO] Template Processing Details:
for %%s in ("example_template.eont") do set template_size=%%~zs
for /f %%i in ('find /c /v "" ^< "example_template.eont"') do set template_lines=%%i
for %%s in ("example_header.h") do set source_size=%%~zs
for /f %%i in ('find /c /v "" ^< "example_header.h"') do set source_lines=%%i

echo   Template file size: !template_size! bytes
echo   Template lines: !template_lines!
echo   Source file size: !source_size! bytes
echo   Source lines: !source_lines!

echo.
echo 🧪 Testing Generated Code
echo ========================

REM Test if generated files are valid
for %%f in (generated_example.*) do (
    if exist "%%f" (
        echo [INFO] Validating %%f...
        
        REM Basic syntax checks based on file extension
        echo %%f | findstr /i "\.eon$" >nul
        if !errorlevel! equ 0 (
            findstr /c:"def func" /c:"def model" "%%f" >nul 2>&1
            if !errorlevel! equ 0 (
                echo [SUCCESS] %%f has valid Eon syntax
            ) else (
                echo [WARNING] %%f may have syntax issues
            )
        )
        
        echo %%f | findstr /i "\.cpp$" >nul
        if !errorlevel! equ 0 (
            findstr /c:"class" /c:"struct" /c:"void" /c:"int" "%%f" >nul 2>&1
            if !errorlevel! equ 0 (
                echo [SUCCESS] %%f has valid C++ syntax
            ) else (
                echo [WARNING] %%f may have syntax issues
            )
        )
        
        echo %%f | findstr /i "\.py$" >nul
        if !errorlevel! equ 0 (
            findstr /c:"def" /c:"class" "%%f" >nul 2>&1
            if !errorlevel! equ 0 (
                echo [SUCCESS] %%f has valid Python syntax
            ) else (
                echo [WARNING] %%f may have syntax issues
            )
        )
        
        echo %%f | findstr /i "\.js$" >nul
        if !errorlevel! equ 0 (
            findstr /c:"function" /c:"class" "%%f" >nul 2>&1
            if !errorlevel! equ 0 (
                echo [SUCCESS] %%f has valid JavaScript syntax
            ) else (
                echo [WARNING] %%f may have syntax issues
            )
        )
    )
)

echo.
echo 📚 Example Usage
echo ================
echo To use the template generator in your own projects:
echo.
echo 1. Create a source file (C++ header, JSON, etc.)
echo 2. Create a template file (.eont format)
echo 3. Run the generator:
echo    template_generator -s source.h -t template.eont -o output.eon -l eon
echo.
echo 4. Or use the C++ API:
echo    #include "template_generator_wrapper.h"
echo    TemplateGenerator generator;
echo    generator.setSourceFile("source.h");
echo    generator.setTemplateFile("template.eont");
echo    generator.setOutputFile("output.eon");
echo    generator.setTargetLanguage(Language::EON);
echo    generator.generate();

echo.
echo 🎯 Performance Metrics
echo =====================
echo [INFO] Measuring generation performance...

REM Time the generation process
set start_time=%time%
..\build\template_generator.exe --source example_header.h --template example_template.eont --output performance_test.eon --language eon >nul 2>&1
set end_time=%time%

echo   Generation completed
echo   Source file size: !source_size! bytes
echo   Template file size: !template_size! bytes
if exist "performance_test.eon" (
    for %%s in ("performance_test.eon") do set output_size=%%~zs
    echo   Output file size: !output_size! bytes
    del performance_test.eon
)

echo.
echo ✅ Demo Complete!
echo =================
echo [SUCCESS] Template generator demonstration completed successfully!
echo.
echo Generated files are available in: %DEMO_DIR%\
echo You can examine them to see the generated code.
echo.
echo Next steps:
echo 1. Modify the example files to experiment with different inputs
echo 2. Create your own templates for different use cases
echo 3. Integrate the template generator into your build system
echo 4. Contribute improvements and new language support
echo.
echo For more information, see README_template_generator.md

echo.
echo [SUCCESS] Demo completed successfully! 🎉

cd ..
endlocal
