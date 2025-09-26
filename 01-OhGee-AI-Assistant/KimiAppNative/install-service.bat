@echo off
echo Installing OhGee AI Assistant Service...
echo.

REM Build the service
echo Building service...
dotnet build OhGeeService.csproj --configuration Release
if %ERRORLEVEL% neq 0 (
    echo Build failed!
    pause
    exit /b 1
)

REM Publish the service
echo Publishing service...
dotnet publish OhGeeService.csproj --configuration Release --runtime win-x64 --self-contained true --output ./publish-service
if %ERRORLEVEL% neq 0 (
    echo Publish failed!
    pause
    exit /b 1
)

REM Install the service
echo Installing Windows Service...
sc create "OhGeeAIService" binPath="%~dp0publish-service\OhGeeService.exe" start=auto
if %ERRORLEVEL% neq 0 (
    echo Service installation failed!
    pause
    exit /b 1
)

REM Start the service
echo Starting service...
sc start "OhGeeAIService"
if %ERRORLEVEL% neq 0 (
    echo Service start failed!
    pause
    exit /b 1
)

echo.
echo  OhGee AI Assistant Service installed and started successfully!
echo.
echo The service will now run in the background and respond to hotkeys:
echo Ctrl+Shift+Numpad1 - Kimi AI
echo Ctrl+Shift+Numpad2 - Cursor
echo Ctrl+Shift+Numpad3 - ChatGPT
echo Ctrl+Shift+Numpad4 - Native Chat
echo.
echo To uninstall: run uninstall-service.bat
echo To check status: sc query OhGeeAIService
echo.
pause
