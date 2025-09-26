@echo off
REM build.bat - Windows build script for RawrZApp compiler suite
REM Provides easy access to CMake build system with various configurations

setlocal EnableDelayedExpansion

REM Default values
set "BUILD_TYPE=Release"
set "BUILD_DIR=build"
set "CLEAN=false"
set "TESTS=false"
set "BENCHMARK=false"
set "INSTALL=false"
set "PACKAGE=false"
set "DOCS=false"
set "VERBOSE=false"
set "JOBS=%NUMBER_OF_PROCESSORS%"
set "CMAKE_OPTIONS="

REM Parse command line arguments
:parse_args
if "%~1"=="" goto end_parse
if "%~1"=="-h" goto show_usage
if "%~1"=="--help" goto show_usage
if "%~1"=="-t" (
    set "BUILD_TYPE=%~2"
    shift
    shift
    goto parse_args
)
if "%~1"=="--type" (
    set "BUILD_TYPE=%~2"
    shift
    shift
    goto parse_args
)
if "%~1"=="-d" (
    set "BUILD_DIR=%~2"
    shift
    shift
    goto parse_args
)
if "%~1"=="--dir" (
    set "BUILD_DIR=%~2"
    shift
    shift
    goto parse_args
)
if "%~1"=="-c" (
    set "CLEAN=true"
    shift
    goto parse_args
)
if "%~1"=="--clean" (
    set "CLEAN=true"
    shift
    goto parse_args
)
if "%~1"=="-j" (
    set "JOBS=%~2"
    shift
    shift
    goto parse_args
)
if "%~1"=="--jobs" (
    set "JOBS=%~2"
    shift
    shift
    goto parse_args
)
if "%~1"=="-T" (
    set "TESTS=true"
    shift
    goto parse_args
)
if "%~1"=="--tests" (
    set "TESTS=true"
    shift
    goto parse_args
)
if "%~1"=="-b" (
    set "BENCHMARK=true"
    shift
    goto parse_args
)
if "%~1"=="--benchmark" (
    set "BENCHMARK=true"
    shift
    goto parse_args
)
if "%~1"=="-i" (
    set "INSTALL=true"
    shift
    goto parse_args
)
if "%~1"=="--install" (
    set "INSTALL=true"
    shift
    goto parse_args
)
if "%~1"=="-p" (
    set "PACKAGE=true"
    shift
    goto parse_args
)
if "%~1"=="--package" (
    set "PACKAGE=true"
    shift
    goto parse_args
)
if "%~1"=="--docs" (
    set "DOCS=true"
    shift
    goto parse_args
)
if "%~1"=="-v" (
    set "VERBOSE=true"
    shift
    goto parse_args
)
if "%~1"=="--verbose" (
    set "VERBOSE=true"
    shift
    goto parse_args
)
if "%~1"=="--asan" (
    set "CMAKE_OPTIONS=%CMAKE_OPTIONS% -DENABLE_ASAN=ON"
    shift
    goto parse_args
)
if "%~1"=="--tsan" (
    set "CMAKE_OPTIONS=%CMAKE_OPTIONS% -DENABLE_TSAN=ON"
    shift
    goto parse_args
)
if "%~1"=="--ubsan" (
    set "CMAKE_OPTIONS=%CMAKE_OPTIONS% -DENABLE_UBSAN=ON"
    shift
    goto parse_args
)
if "%~1"=="--coverage" (
    set "CMAKE_OPTIONS=%CMAKE_OPTIONS% -DENABLE_COVERAGE=ON"
    shift
    goto parse_args
)
if "%~1"=="--static" (
    set "CMAKE_OPTIONS=%CMAKE_OPTIONS% -DSTATIC_BUILD=ON"
    shift
    goto parse_args
)
echo [ERROR] Unknown option: %~1
goto show_usage

:end_parse

REM Validate build type
if "%BUILD_TYPE%"=="Debug" goto valid_type
if "%BUILD_TYPE%"=="Release" goto valid_type
if "%BUILD_TYPE%"=="RelWithDebInfo" goto valid_type
if "%BUILD_TYPE%"=="MinSizeRel" goto valid_type
echo [ERROR] Invalid build type: %BUILD_TYPE%
echo [INFO] Valid types: Debug, Release, RelWithDebInfo, MinSizeRel
exit /b 1

:valid_type

REM Print build configuration
echo [INFO] RawrZApp Build Configuration:
echo [INFO]   Build Type: %BUILD_TYPE%
echo [INFO]   Build Directory: %BUILD_DIR%
echo [INFO]   Parallel Jobs: %JOBS%
echo [INFO]   Clean Build: %CLEAN%
echo [INFO]   Run Tests: %TESTS%
echo [INFO]   Run Benchmarks: %BENCHMARK%
echo [INFO]   Install: %INSTALL%
echo [INFO]   Create Package: %PACKAGE%
echo [INFO]   Generate Docs: %DOCS%
if not "%CMAKE_OPTIONS%"=="" (
    echo [INFO]   CMake Options: %CMAKE_OPTIONS%
)

REM Clean build directory if requested
if "%CLEAN%"=="true" (
    echo [INFO] Cleaning build directory...
    if exist "%BUILD_DIR%" rmdir /s /q "%BUILD_DIR%"
)

REM Create build directory
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"
cd "%BUILD_DIR%"

REM Configure with CMake
echo [INFO] Configuring with CMake...
set "CMAKE_CMD=cmake -DCMAKE_BUILD_TYPE=%BUILD_TYPE% %CMAKE_OPTIONS% .."
if "%VERBOSE%"=="true" (
    echo [INFO] Running: %CMAKE_CMD%
)
%CMAKE_CMD%
if errorlevel 1 (
    echo [ERROR] CMake configuration failed!
    exit /b 1
)

REM Build
echo [INFO] Building...
set "BUILD_CMD=cmake --build . --config %BUILD_TYPE% -j %JOBS%"
if "%VERBOSE%"=="true" (
    set "BUILD_CMD=%BUILD_CMD% --verbose"
    echo [INFO] Running: %BUILD_CMD%
)
%BUILD_CMD%
if errorlevel 1 (
    echo [ERROR] Build failed!
    exit /b 1
)

echo [SUCCESS] Build completed successfully!

REM Run tests if requested
if "%TESTS%"=="true" (
    echo [INFO] Running tests...
    cmake --build . --target run_tests
    if errorlevel 1 (
        echo [ERROR] Some tests failed!
        exit /b 1
    ) else (
        echo [SUCCESS] All tests passed!
    )
)

REM Run benchmarks if requested
if "%BENCHMARK%"=="true" (
    echo [INFO] Running benchmarks...
    cmake --build . --target benchmark
    if errorlevel 1 (
        echo [WARNING] Benchmarks failed or not available
    ) else (
        echo [SUCCESS] Benchmarks completed!
    )
)

REM Generate documentation if requested
if "%DOCS%"=="true" (
    echo [INFO] Generating documentation...
    cmake --build . --target docs
    if errorlevel 1 (
        echo [WARNING] Documentation generation failed or Doxygen not available
    ) else (
        echo [SUCCESS] Documentation generated!
    )
)

REM Install if requested
if "%INSTALL%"=="true" (
    echo [INFO] Installing...
    cmake --install .
    if errorlevel 1 (
        echo [ERROR] Installation failed!
        exit /b 1
    ) else (
        echo [SUCCESS] Installation completed!
    )
)

REM Create package if requested
if "%PACKAGE%"=="true" (
    echo [INFO] Creating package...
    cpack
    if errorlevel 1 (
        echo [ERROR] Package creation failed!
        exit /b 1
    ) else (
        echo [SUCCESS] Package created successfully!
        echo [INFO] Package files:
        dir *.zip *.exe 2>nul
    )
)

echo [SUCCESS] Build script completed successfully!
echo [INFO] Build artifacts are in: %BUILD_DIR%
echo [INFO]
echo [INFO] Available executables:
echo [INFO]   - reverser_lexer.exe: Reverser language lexer
echo [INFO]   - reverser_parser.exe: Reverser language parser
echo [INFO]   - reverser_runtime_test.exe: Reverser runtime tests
echo [INFO]   - reverser_vtable_test.exe: Reverser vtable tests
echo [INFO]   - reverser_bootstrap.exe: Reverser self-hosting compiler
echo [INFO]   - eon_compiler.exe: Eon compiler (C version)
echo [INFO]   - eon_llvm_compiler.exe: Eon LLVM compiler (C version)
echo [INFO]
echo [INFO] To run a quick test:
echo [INFO]   cd %BUILD_DIR% ^&^& reverser_lexer.exe
echo [INFO]   cd %BUILD_DIR% ^&^& eon_compiler.exe ..\test_program.eon

goto end

:show_usage
echo Usage: %~nx0 [OPTIONS]
echo.
echo Build script for RawrZApp compiler suite
echo.
echo OPTIONS:
echo     -h, --help          Show this help message
echo     -t, --type TYPE     Build type: Debug, Release, RelWithDebInfo, MinSizeRel (default: Release)
echo     -d, --dir DIR       Build directory (default: build)
echo     -c, --clean         Clean build directory before building
echo     -j, --jobs N        Number of parallel jobs (default: %NUMBER_OF_PROCESSORS%)
echo     -T, --tests         Run tests after building
echo     -b, --benchmark     Run benchmarks after building
echo     -i, --install       Install after building
echo     -p, --package       Create package after building
echo     --docs              Generate documentation
echo     -v, --verbose       Verbose build output
echo     --asan              Enable AddressSanitizer (if supported)
echo     --tsan              Enable ThreadSanitizer (if supported)
echo     --ubsan             Enable UndefinedBehaviorSanitizer (if supported)
echo     --coverage          Enable code coverage (if supported)
echo     --static            Build static executables
echo.
echo EXAMPLES:
echo     %~nx0                          # Build release version
echo     %~nx0 -t Debug -T              # Build debug version and run tests
echo     %~nx0 -c -t Release -i         # Clean, build release, and install
echo     %~nx0 --static -t Release      # Build static release version
echo     %~nx0 -b -p                    # Build, benchmark, and create package
echo.

:end
cd ..
endlocal
