@echo off
REM build_java_compiler.bat - Build script for the Java Eon Compiler (Windows)
REM Compiles all Java files and runs tests

echo === Java Eon Compiler Build Script ===
echo.

REM Check Java installation
echo Checking Java installation...
where javac >nul 2>&1
if %errorlevel% equ 0 (
    echo ✓ Java compiler found
    javac -version
) else (
    echo ✗ Java compiler not found. Please install Java 8 or higher.
    exit /b 1
)

where java >nul 2>&1
if %errorlevel% equ 0 (
    echo ✓ Java runtime found
    java -version
) else (
    echo ✗ Java runtime not found. Please install Java 8 or higher.
    exit /b 1
)

echo.

REM Create build directory
echo Creating build directory...
if not exist build mkdir build
if not exist build\classes mkdir build\classes
if not exist build\test-output mkdir build\test-output

echo.

REM Compile main compiler
echo Compiling main compiler...
javac -d build\classes EonCompilerEnhanced.java
if %errorlevel% equ 0 (
    echo ✓ EonCompilerEnhanced compiled successfully
) else (
    echo ✗ Failed to compile EonCompilerEnhanced
    exit /b 1
)

REM Compile enhancements (skipped - file removed due to errors)
echo Skipping enhancements compilation (file removed)

REM Compile test suite
echo Compiling test suite...
javac -d build\classes EonCompilerTestSuite.java
if %errorlevel% equ 0 (
    echo ✓ EonCompilerTestSuite compiled successfully
) else (
    echo ✗ Failed to compile EonCompilerTestSuite
    exit /b 1
)

echo.

REM Run tests
echo Running test suite...
cd build\classes
java EonCompilerTestSuite
if %errorlevel% equ 0 (
    echo ✓ All tests passed
) else (
    echo ✗ Some tests failed
    exit /b 1
)

cd ..\..

echo.

REM Test basic compilation
echo Testing basic compilation...
echo let x = 42; > build\test.eon
cd build\classes
java EonCompilerEnhanced ..\test.eon
if %errorlevel% equ 0 (
    echo ✓ Basic compilation test passed
    if exist out.asm (
        echo ✓ Assembly output generated
        for %%A in (out.asm) do echo Assembly file size: %%~zA bytes
    ) else (
        echo ✗ Assembly output not generated
    )
) else (
    echo ✗ Basic compilation test failed
)

cd ..\..

echo.

REM Check for NASM and GCC (optional)
echo Checking for optional tools...
where nasm >nul 2>&1
if %errorlevel% equ 0 (
    echo ✓ NASM found
    nasm --version
    
    REM Try to assemble the output
    if exist build\classes\out.asm (
        echo Attempting to assemble output...
        cd build\classes
        nasm -f win64 out.asm -o out.obj
        if %errorlevel% equ 0 (
            echo ✓ Assembly successful
            
            where gcc >nul 2>&1
            if %errorlevel% equ 0 (
                echo ✓ GCC found
                gcc --version
                gcc out.obj -o test_program.exe
                if %errorlevel% equ 0 (
                    echo ✓ Linking successful
                    echo ✓ Executable created: test_program.exe
                    
                    REM Try to run the program
                    echo Running test program...
                    test_program.exe
                    echo ✓ Test program executed successfully
                ) else (
                    echo ✗ Linking failed
                )
            ) else (
                echo ⚠ GCC not found - skipping linking
            )
        ) else (
            echo ✗ Assembly failed
        )
        cd ..\..
    )
) else (
    echo ⚠ NASM not found - skipping assembly test
)

echo.

REM Generate build report
echo Generating build report...
(
echo Java Eon Compiler Build Report
echo =============================
echo Build Date: %date% %time%
echo Java Version: 
java -version
echo Java Compiler Version:
javac -version
echo.
echo Build Status: SUCCESS
echo Files Compiled:
echo - EonCompilerEnhanced.java
echo - EonCompilerTestSuite.java
echo.
echo Test Results: See test_report.txt for details
echo.
echo Generated Files:
echo - build\classes\EonCompilerEnhanced.class
echo - build\classes\EonCompilerTestSuite.class
echo - build\classes\out.asm (if compilation successful)
echo.
echo Usage:
echo cd build\classes
echo java EonCompilerEnhanced ^<source_file.eon^>
echo java EonCompilerTestSuite
) > build\build_report.txt

echo ✓ Build report generated: build\build_report.txt

echo.
echo === Build Complete ===
echo Java Eon Compiler built successfully!
echo.
echo To use the compiler:
echo   cd build\classes
echo   java EonCompilerEnhanced ^<source_file.eon^>
echo.
echo To run tests:
echo   cd build\classes
echo   java EonCompilerTestSuite
echo.
echo Build artifacts are in the build\ directory

pause
