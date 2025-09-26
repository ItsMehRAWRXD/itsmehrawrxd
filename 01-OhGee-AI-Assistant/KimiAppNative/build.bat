@echo off
echo Building AI Assistant Hub...

REM Clean previous builds
if exist "bin" rmdir /s /q "bin"
if exist "obj" rmdir /s /q "obj"

REM Restore packages
echo Restoring packages...
dotnet restore

REM Build the application
echo Building application...
dotnet build --configuration Release

REM Publish the application
echo Publishing application...
dotnet publish --configuration Release --runtime win-x64 --self-contained true --output "publish"

echo Build completed successfully!
echo Output directory: publish\
echo.
echo To run the application:
echo cd publish
echo AIAssistantHub.exe
pause
