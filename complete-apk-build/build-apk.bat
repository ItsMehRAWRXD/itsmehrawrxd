@echo off
echo ========================================
echo Building Samsung Root Tool APK
echo ========================================
echo.

echo Step 1: Setting Java environment...
set JAVA_HOME=C:\Program Files\Java\jdk-17
set PATH=%JAVA_HOME%\bin;%PATH%

echo Using Java: %JAVA_HOME%
java -version
echo.

echo Step 2: Checking Android SDK...
if not exist "%USERPROFILE%\AppData\Local\Android\Sdk" (
    echo Android SDK not found. Downloading command line tools...
    echo Please download Android SDK from: https://developer.android.com/studio#command-tools
    echo Extract to: %USERPROFILE%\AppData\Local\Android\Sdk
    pause
    exit /b 1
)

echo Android SDK found at: %USERPROFILE%\AppData\Local\Android\Sdk
echo.

echo Step 3: Building APK with Gradle...
echo This may take a few minutes on first build...
echo.

gradlew.bat assembleDebug

if %ERRORLEVEL% equ 0 (
    echo.
    echo ========================================
    echo BUILD SUCCESSFUL!
    echo ========================================
    echo.
    echo APK location: app\build\outputs\apk\debug\app-debug.apk
    echo.
    echo Your Samsung Root Tool APK is ready!
    echo.
    echo Features:
    echo - 9 different rooting methods
    echo - OpenSSL AES-256-GCM encrypted native engine
    echo - Device-specific Samsung Tab S10+ 5G support
    echo - AT&T carrier bypass techniques
    echo - Real system calls (no simulations)
    echo.
    echo To install on your tablet:
    echo 1. Enable "Unknown Sources" in security settings
    echo 2. Transfer APK to tablet
    echo 3. Install and run "Samsung Root Tool"
    echo.
) else (
    echo.
    echo ========================================
    echo BUILD FAILED!
    echo ========================================
    echo.
    echo Check the error messages above.
    echo Common solutions:
    echo 1. Make sure Java 17 is installed
    echo 2. Make sure Android SDK is installed
    echo 3. Try running as Administrator
    echo.
)

echo.
pause