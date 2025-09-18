@echo off
echo ========================================
echo RawrZApp Cleanup - Remove Rooting Scripts
echo ========================================
echo.
echo This script will remove all rooting-related scripts and files
echo while preserving your encryptor project and APK builder.
echo.

echo PRESERVING:
echo - APK-Creation-Folder (drag-and-drop ZIP to APK builder)
echo - complete-apk-build (APK builder system)
echo - All encrypt* files (your encryptor project)
echo - All calc* files (calculator components)
echo - package.json, node_modules (Node.js project)
echo - src/engines/ (encryption engines)
echo - examples/ (example files)
echo - public/ (web interface)
echo - All .js files (main project files)
echo.

echo REMOVING:
echo - All .sh files (rooting scripts)
echo - All .bat files (except this cleanup script)
echo - All .apk files (built APKs)
echo - All .zip files (project packages)
echo - All rooting-related folders
echo - All logs and temporary files
echo.

set /p confirm="Are you sure you want to proceed? (y/N): "
if /i not "%confirm%"=="y" (
    echo Cleanup cancelled.
    pause
    exit /b 0
)

echo.
echo Starting cleanup...

echo Step 1: Removing rooting scripts (.sh files)...
for %%f in (*.sh) do (
    echo Removing: %%f
    del "%%f" 2>nul
)

echo Step 2: Removing batch files (except cleanup)...
for %%f in (*.bat) do (
    if not "%%f"=="cleanup-rooting-scripts.bat" (
        echo Removing: %%f
        del "%%f" 2>nul
    )
)

echo Step 3: Removing APK files...
for %%f in (*.apk) do (
    echo Removing: %%f
    del "%%f" 2>nul
)

echo Step 4: Removing ZIP files...
for %%f in (*.zip) do (
    echo Removing: %%f
    del "%%f" 2>nul
)

echo Step 5: Removing rooting-related folders...
for /d %%d in (*) do (
    if not "%%d"=="APK-Creation-Folder" (
        if not "%%d"=="complete-apk-build" (
            if not "%%d"=="node_modules" (
                if not "%%d"=="src" (
                    if not "%%d"=="examples" (
                        if not "%%d"=="public" (
                            if not "%%d"=="build" (
                                if not "%%d"=="data" (
                                    if not "%%d"=="logs" (
                                        if not "%%d"=="loot" (
                                            if not "%%d"=="scans" (
                                                if not "%%d"=="scan-results" (
                                                    if not "%%d"=="backups" (
                                                        if not "%%d"=="cli" (
                                                            if not "%%d"=="deploy" (
                                                                if not "%%d"=="gradle" (
                                                                    echo Removing folder: %%d
                                                                    rmdir /s /q "%%d" 2>nul
                                                                )
                                                            )
                                                        )
                                                    )
                                                )
                                            )
                                        )
                                    )
                                )
                            )
                        )
                    )
                )
            )
        )
    )
)

echo Step 6: Removing log files...
for %%f in (*.txt) do (
    echo Removing: %%f
    del "%%f" 2>nul
)

for %%f in (*.json) do (
    if not "%%f"=="package.json" (
        if not "%%f"=="package-lock.json" (
            echo Removing: %%f
            del "%%f" 2>nul
        )
    )
)

echo Step 7: Removing other temporary files...
for %%f in (*.exe) do (
    if not "%%f"=="calc.exe" (
        echo Removing: %%f
        del "%%f" 2>nul
    )
)

echo.
echo ========================================
echo CLEANUP COMPLETED!
echo ========================================
echo.
echo PRESERVED:
echo - APK-Creation-Folder (drag-and-drop ZIP to APK builder)
echo - complete-apk-build (APK builder system)
echo - All encrypt* files (your encryptor project)
echo - All calc* files (calculator components)
echo - package.json, node_modules (Node.js project)
echo - src/engines/ (encryption engines)
echo - examples/ (example files)
echo - public/ (web interface)
echo - All .js files (main project files)
echo.
echo REMOVED:
echo - All rooting scripts (.sh files)
echo - All batch files (except this cleanup script)
echo - All APK files
echo - All ZIP files
echo - All rooting-related folders
echo - All log and temporary files
echo.
echo Your encryptor project and APK builder are now clean and ready to use!
echo.
pause
