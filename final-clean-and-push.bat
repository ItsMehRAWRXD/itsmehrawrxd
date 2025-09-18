@echo off
echo ========================================
echo Final Clean - Encryptor + APK Builder Only
echo ========================================
echo.
echo This will:
echo 1. Remove all Samsung rooting documentation
echo 2. Remove all Android rooting files
echo 3. Keep only encryptor project and APK builder
echo 4. Commit and push clean repository
echo.

set /p confirm="Proceed with final cleanup? (y/N): "
if /i not "%confirm%"=="y" (
    echo Operation cancelled.
    pause
    exit /b 0
)

echo.
echo Step 1: Removing Samsung rooting documentation...
del "SAMSUNG_GALAXY_TAB_S10_PLUS_5G_GUIDE.md" 2>nul
del "SAMSUNG_ROOT_TOOL_V2_SUMMARY.md" 2>nul
del "SAMSUNG_ROOT_TOOL_V3_ENHANCED_SUMMARY.md" 2>nul
del "SAMSUNG_ROOT_TOOL_V5_WORKING_SUMMARY.md" 2>nul
del "SAMSUNG_ROOT_TOOL_V6_DOWNLOAD_MODE_SUMMARY.md" 2>nul
del "SIMPLE_ROOT_README.md" 2>nul
del "README_ROOTING_TOOL.md" 2>nul
del "COMPREHENSIVE_ROOTING_APP_README.md" 2>nul
del "ENHANCED_ROOTING_SUMMARY.md" 2>nul
del "ZERO_DAY_RESEARCH_METHODOLOGY.md" 2>nul

echo Step 2: Removing Android rooting files...
del "AndroidManifest.xml" 2>nul
del "native-root-bruteforce.cpp" 2>nul
del "payload-*.java" 2>nul
del "demo-android-zero-day.js" 2>nul
del "test-android-zero-day.js" 2>nul
del "gradle-wrapper.jar" 2>nul

echo Step 3: Removing Android project folders...
rmdir /s /q "src\android" 2>nul
rmdir /s /q "gradle" 2>nul

echo Step 4: Removing other unnecessary files...
del "About" 2>nul
del "SDK" 2>nul
del "Security" 2>nul

echo Step 5: Staging all changes...
git add -A

echo Step 6: Checking what will be committed...
echo.
echo Files to be committed:
git diff --cached --name-only

echo.
echo Files to be deleted:
git diff --cached --name-only --diff-filter=D

echo.
set /p commit_confirm="Commit these changes? (y/N): "
if /i not "%commit_confirm%"=="y" (
    echo Commit cancelled.
    pause
    exit /b 0
)

echo Step 7: Committing final clean state...
git commit -m "🎯 Final cleanup - Pure encryptor project with APK builder

✅ KEPT:
- Complete encryptor project (all encryption engines and tools)
- APK builder system (APK-Creation-Folder, complete-apk-build)
- Web interface and CLI tools
- All encryption algorithms and scanners

🗑️ REMOVED:
- All Samsung rooting documentation
- All Android rooting files and payloads
- All rooting-related scripts and tools
- Android project files and manifests

🎯 RESULT: Clean repository focused on encryption project with drag-and-drop APK builder"

echo Step 8: Pushing to GitHub...
git push origin main

if %ERRORLEVEL% equ 0 (
    echo.
    echo ========================================
    echo 🎉 SUCCESS! Repository is now clean!
    echo ========================================
    echo.
    echo Your GitHub repository now contains:
    echo ✅ Pure encryptor project
    echo ✅ APK builder system (drag-and-drop ZIP to APK)
    echo ✅ All encryption engines and tools
    echo ✅ Web interface and CLI
    echo.
    echo 🗑️ Removed all Samsung/Android rooting stuff
    echo.
    echo Repository is now focused and clean! 🎯
    echo.
) else (
    echo.
    echo ========================================
    echo ❌ PUSH FAILED!
    echo ========================================
    echo.
    echo Check your git configuration and try again.
    echo.
)

pause
