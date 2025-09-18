@echo off
echo ========================================
echo Clean Repository and Push Encryptor Only
echo ========================================
echo.
echo This will:
echo 1. Remove all Android rooting files from git
echo 2. Keep only encryptor project and APK builder
echo 3. Commit the clean state
echo 4. Push to GitHub
echo.

set /p confirm="Are you sure you want to proceed? (y/N): "
if /i not "%confirm%"=="y" (
    echo Operation cancelled.
    pause
    exit /b 0
)

echo.
echo Step 1: Staging all deletions...
git add -A

echo Step 2: Unstaging files we want to keep...
git reset HEAD -- APK-Creation-Folder/
git reset HEAD -- complete-apk-build/
git reset HEAD -- src/engines/
git reset HEAD -- examples/
git reset HEAD -- public/
git reset HEAD -- cli/
git reset HEAD -- data/
git reset HEAD -- logs/
git reset HEAD -- backups/
git reset HEAD -- scans/
git reset HEAD -- scan-results/
git reset HEAD -- loot/
git reset HEAD -- deploy/
git reset HEAD -- build/
git reset HEAD -- node_modules/
git reset HEAD -- package.json
git reset HEAD -- package-lock.json
git reset HEAD -- server.js
git reset HEAD -- config.js
git reset HEAD -- production.config.js
git reset HEAD -- rawrz-standalone.js
git reset HEAD -- *.js
git reset HEAD -- *.md
git reset HEAD -- *.json
git reset HEAD -- *.yml
git reset HEAD -- *.yaml
git reset HEAD -- Dockerfile
git reset HEAD -- nginx.conf
git reset HEAD -- env.example
git reset HEAD -- calc.exe
git reset HEAD -- cleanup-rooting-scripts.bat

echo Step 3: Adding back the files we want to keep...
git add APK-Creation-Folder/
git add complete-apk-build/
git add src/engines/
git add examples/
git add public/
git add cli/
git add data/
git add logs/
git add backups/
git add scans/
git add scan-results/
git add loot/
git add deploy/
git add build/
git add node_modules/
git add package.json
git add package-lock.json
git add server.js
git add config.js
git add production.config.js
git add rawrz-standalone.js
git add *.js
git add *.md
git add *.json
git add *.yml
git add *.yaml
git add Dockerfile
git add nginx.conf
git add env.example
git add calc.exe
git add cleanup-rooting-scripts.bat

echo Step 4: Checking what will be committed...
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

echo Step 5: Committing clean encryptor project...
git commit -m "🧹 Clean repository - Keep only encryptor project and APK builder

- Removed all Android rooting scripts and files
- Preserved encryptor project components
- Preserved APK builder system (APK-Creation-Folder, complete-apk-build)
- Clean workspace focused on encryption project"

echo Step 6: Pushing to GitHub...
git push origin main

if %ERRORLEVEL% equ 0 (
    echo.
    echo ========================================
    echo SUCCESS! Repository cleaned and pushed!
    echo ========================================
    echo.
    echo Your GitHub repository now contains:
    echo - Clean encryptor project
    echo - APK builder system
    echo - All encryption engines and tools
    echo - No Android rooting files
    echo.
) else (
    echo.
    echo ========================================
    echo PUSH FAILED!
    echo ========================================
    echo.
    echo Check your git configuration and try again.
    echo.
)

pause
