@echo off
echo ========================================
echo Samsung Root Tool - Drag & Drop ZIP Builder
echo ========================================
echo.

rem Check if a file was dropped
if "%~1"=="" (
    echo.
    echo USAGE: Drag and drop a ZIP file onto this script!
    echo.
    echo This script will:
    echo 1. Extract the ZIP file
    echo 2. Set up the Android project
    echo 3. Build the APK using Gradle
    echo 4. Create a working APK file
    echo.
    echo Supported ZIP files:
    echo - samsung-root-project.zip
    echo - Any Android project ZIP
    echo - Online builder packages
    echo.
    pause
    exit /b 1
)

set "ZIP_FILE=%~1"
set "ZIP_NAME=%~n1"
set "BUILD_DIR=build-from-%ZIP_NAME%"

echo Processing ZIP file: %ZIP_FILE%
echo.

echo Step 1: Setting Java environment...
set JAVA_HOME=C:\Program Files\Java\jdk-17
set PATH=%JAVA_HOME%\bin;%PATH%

echo Using Java: %JAVA_HOME%
java -version
echo.

echo Step 2: Creating build directory...
if exist "%BUILD_DIR%" rmdir /s /q "%BUILD_DIR%"
mkdir "%BUILD_DIR%"

echo Step 3: Extracting ZIP file...
powershell -command "Expand-Archive -Path '%ZIP_FILE%' -DestinationPath '%BUILD_DIR%' -Force"

echo Step 4: Analyzing project structure...
cd "%BUILD_DIR%"

rem Check if it's a complete Android project
if exist "app\src\main\java" (
    echo Found complete Android project structure
    set "PROJECT_TYPE=complete"
) else if exist "MainActivity.java" (
    echo Found basic project files, creating structure...
    set "PROJECT_TYPE=basic"
    
    rem Create proper Android project structure
    mkdir app\src\main\java\com\android\simpleroot
    mkdir app\src\main\res\layout
    mkdir app\src\main\res\values
    mkdir app\src\main\res\drawable
    mkdir gradle\wrapper
    
    rem Move files to correct locations
    if exist "MainActivity.java" move "MainActivity.java" "app\src\main\java\com\android\simpleroot\"
    if exist "AndroidManifest.xml" move "AndroidManifest.xml" "app\src\main\"
    if exist "activity_main.xml" move "activity_main.xml" "app\src\main\res\layout\"
    if exist "main.xml" move "main.xml" "app\src\main\res\layout\activity_main.xml"
    if exist "strings.xml" move "strings.xml" "app\src\main\res\values\"
    if exist "build.gradle" move "build.gradle" "app\"
    
    rem Create missing files
    if not exist "app\build.gradle" (
        echo Creating app build.gradle...
        (
        echo plugins {
        echo     id 'com.android.application'
        echo }
        echo.
        echo android {
        echo     namespace 'com.android.simpleroot'
        echo     compileSdk 34
        echo.
        echo     defaultConfig {
        echo         applicationId "com.android.simpleroot"
        echo         minSdk 21
        echo         targetSdk 34
        echo         versionCode 1
        echo         versionName "1.0"
        echo     }
        echo.
        echo     buildTypes {
        echo         release {
        echo             minifyEnabled false
        echo             proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'^), 'proguard-rules.pro'
        echo         }
        echo     }
        echo }
        echo.
        echo dependencies {
        echo     implementation 'androidx.appcompat:appcompat:1.6.1'
        echo     implementation 'com.google.android.material:material:1.10.0'
        echo }
        ) > app\build.gradle
    )
    
    if not exist "build.gradle" (
        echo Creating project build.gradle...
        (
        echo buildscript {
        echo     repositories {
        echo         google^(^)
        echo         mavenCentral^(^)
        echo     }
        echo     dependencies {
        echo         classpath 'com.android.tools.build:gradle:8.1.4'
        echo     }
        echo }
        echo.
        echo allprojects {
        echo     repositories {
        echo         google^(^)
        echo         mavenCentral^(^)
        echo     }
        echo }
        ) > build.gradle
    )
    
    if not exist "settings.gradle" (
        echo Creating settings.gradle...
        (
        echo pluginManagement {
        echo     repositories {
        echo         google^(^)
        echo         mavenCentral^(^)
        echo         gradlePluginPortal^(^)
        echo     }
        echo }
        echo dependencyResolutionManagement {
        echo     repositoriesMode.set^(RepositoriesMode.FAIL_ON_PROJECT_REPOS^)
        echo     repositories {
        echo         google^(^)
        echo         mavenCentral^(^)
        echo     }
        echo }
        echo.
        echo rootProject.name = "Samsung Root Tool"
        echo include ':app'
        ) > settings.gradle
    )
    
    if not exist "gradle.properties" (
        echo Creating gradle.properties...
        (
        echo org.gradle.jvmargs=-Xmx2048m -Dfile.encoding=UTF-8
        echo android.useAndroidX=true
        echo android.enableJetifier=true
        ) > gradle.properties
    )
    
    if not exist "local.properties" (
        echo Creating local.properties...
        (
        echo sdk.dir=C\:\\Users\\Garre\\AppData\\Local\\Android\\Sdk
        ) > local.properties
    )
    
    if not exist "gradle\wrapper\gradle-wrapper.properties" (
        echo Creating gradle wrapper...
        (
        echo distributionBase=GRADLE_USER_HOME
        echo distributionPath=wrapper/dists
        echo distributionUrl=https\://services.gradle.org/distributions/gradle-8.0-bin.zip
        echo zipStoreBase=GRADLE_USER_HOME
        echo zipStorePath=wrapper/dists
        ) > gradle\wrapper\gradle-wrapper.properties
    )
    
    if not exist "gradlew.bat" (
        echo Creating gradlew.bat...
        copy "..\complete-apk-build\gradlew.bat" "gradlew.bat"
    )
    
    if not exist "app\proguard-rules.pro" (
        echo Creating proguard rules...
        (
        echo # Add project specific ProGuard rules here.
        echo -keep class com.android.simpleroot.** { *; }
        ) > app\proguard-rules.pro
    )
    
) else (
    echo Unknown project structure, attempting to build anyway...
    set "PROJECT_TYPE=unknown"
)

echo Step 5: Building APK...
echo Project type: %PROJECT_TYPE%
echo.

rem Try to build the APK
gradlew.bat assembleDebug

if %ERRORLEVEL% equ 0 (
    echo.
    echo ========================================
    echo BUILD SUCCESSFUL!
    echo ========================================
    echo.
    
    if exist "app\build\outputs\apk\debug\app-debug.apk" (
        echo APK location: app\build\outputs\apk\debug\app-debug.apk
        
        rem Copy APK to main directory with descriptive name
        set "FINAL_APK=samsung-root-tool-from-%ZIP_NAME%.apk"
        copy "app\build\outputs\apk\debug\app-debug.apk" "..\%FINAL_APK%"
        
        echo.
        echo Final APK: %FINAL_APK%
        echo.
        echo ========================================
        echo SUCCESS! Your APK is ready!
        echo ========================================
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
        echo Build completed but APK not found in expected location
    )
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
    echo 4. Check that the ZIP contains valid Android project files
    echo.
)

cd ..
echo.
echo Build directory: %BUILD_DIR%
echo You can examine the project structure there if needed.
echo.
pause
