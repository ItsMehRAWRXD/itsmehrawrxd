@echo off
echo Uninstalling OhGee AI Assistant Service...
echo.

REM Stop the service
echo Stopping service...
sc stop "OhGeeAIService"
if %ERRORLEVEL% neq 0 (
    echo Service stop failed or service not running.
)

REM Delete the service
echo Removing service...
sc delete "OhGeeAIService"
if %ERRORLEVEL% neq 0 (
    echo Service removal failed!
    pause
    exit /b 1
)

REM Clean up publish folder
echo Cleaning up...
if exist "publish-service" (
    rmdir /s /q "publish-service"
)

echo.
echo  OhGee AI Assistant Service uninstalled successfully!
echo.
pause
