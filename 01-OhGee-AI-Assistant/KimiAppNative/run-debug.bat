@echo off
echo Starting OhGee in Debug Mode...
echo.
echo This will show debug output for hotkey registration and usage.
echo.
echo Hotkeys to test:
echo Ctrl+Shift+G - Kimi AI
echo Ctrl+Shift+C - Cursor
echo Ctrl+Shift+H - ChatGPT  
echo Ctrl+Shift+A - Native Chat
echo.
echo Press Ctrl+C to stop the application
echo.

cd /d "%~dp0"
dotnet run --configuration Debug
