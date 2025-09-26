@echo off
REM Compiler Generator Randomizer Runner
REM Runs the randomizer and tests generated compilers

echo ========================================
echo Compiler Generator Randomizer Runner
echo ========================================
echo.

REM Check if Python is available
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Python not found. Please install Python.
    pause
    exit /b 1
)

echo Python found. Starting randomizer...
echo.

REM Run the main test runner
python run_compiler_randomizer.py

echo.
echo ========================================
echo Randomizer completed!
echo ========================================

REM Show results
if exist compiler_randomizer_report.json (
    echo.
    echo Results saved to compiler_randomizer_report.json
    echo.
    echo Working compilers found:
    for %%f in (*compiler*.py) do echo   %%f
    for %%f in (*compiler*.js) do echo   %%f
    for %%f in (*compiler*.cpp) do echo   %%f
    for %%f in (*compiler*.asm) do echo   %%f
)

echo.
pause
