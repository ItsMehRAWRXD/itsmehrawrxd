@echo off
REM Portable DotNet Setup Script
REM Generated: 2025-09-15T15:34:34.842Z

echo ========================================
echo   Portable DotNet Compilation Setup
echo ========================================
echo.

REM Check for .NET SDK
echo Checking for .NET SDK...
dotnet --version >nul 2>&1
if %errorlevel% == 0 (
    echo [OK] .NET SDK found
    echo.
    echo Creating project...
    dotnet new console -n MyApp --force
    copy Program.cs MyApp\Program.cs
    cd MyApp
    echo.
    echo Building project...
    dotnet build -c Release
    if %errorlevel% == 0 (
        echo.
        echo [SUCCESS] Compilation completed!
        echo Output: bin\Release\net6.0\MyApp.exe
        echo.
        echo Publishing standalone executable...
        dotnet publish -c Release -r win-x64 --self-contained true
        if %errorlevel% == 0 (
            echo [SUCCESS] Standalone executable created!
            echo Output: bin\Release\net6.0\win-x64\publish\MyApp.exe
        )
    ) else (
        echo [ERROR] Compilation failed!
    )
    cd ..
    goto :end
)

REM Check for CSC
echo Checking for C# Compiler...
csc /? >nul 2>&1
if %errorlevel% == 0 (
    echo [OK] C# Compiler found
    echo.
    echo Compiling...
    csc Program.cs /out:Program.exe /target:exe
    if %errorlevel% == 0 (
        echo [SUCCESS] Compilation completed!
        echo Output: Program.exe
    ) else (
        echo [ERROR] Compilation failed!
    )
    goto :end
)

echo [WARNING] No .NET compiler found!
echo.
echo Please install one of the following:
echo 1. .NET SDK: https://dotnet.microsoft.com/download
echo 2. Visual Studio Build Tools: https://visualstudio.microsoft.com/downloads/
echo.
echo After installation, run this script again.

:end
echo.
pause
