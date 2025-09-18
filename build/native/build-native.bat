@echo off
echo Building encrypted native root engine...

if not exist "" (
    echo Error: ANDROID_NDK_ROOT not set!
    echo Please set ANDROID_NDK_ROOT to your NDK installation path
    pause
    exit /b 1
)

cd /d "C:\Users\Garre\Desktop\RawrZApp\"
"\ndk-build.cmd"

if 0 equ 0 (
    echo.
    echo ========================================
    echo SUCCESS! Native library built
    echo ========================================
    echo.
    echo Libraries created in:
    echo - libs\arm64-v8a\libencrypted_root_engine.so
    echo - libs\armeabi-v7a\libencrypted_root_engine.so
    echo - libs\x86\libencrypted_root_engine.so
    echo - libs\x86_64\libencrypted_root_engine.so
    echo.
) else (
    echo.
    echo ========================================
    echo BUILD FAILED!
    echo ========================================
    echo.
    echo Please check:
    echo 1. ANDROID_NDK_ROOT is set correctly
    echo 2. OpenSSL is installed
    echo 3. All source files are present
    echo.
)

pause
