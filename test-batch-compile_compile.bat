@echo off
REM DotNet Compilation Batch Script
REM Generated: 2025-09-15T15:34:34.836Z

echo Starting DotNet compilation...

REM Check for .NET SDK
dotnet --version >nul 2>&1
if %errorlevel% == 0 (
    echo .NET SDK found, using dotnet build...
    dotnet new console -n TempApp --force
    copy "test-batch-compile.exe" TempApp\Program.cs
    cd TempApp
    dotnet build -c Release
    if %errorlevel% == 0 (
        echo Compilation successful!
        copy bin\Release\net6.0\TempApp.exe ..\test-batch-compile.exe
        cd ..
        rmdir /s /q TempApp
    ) else (
        echo Compilation failed!
        cd ..
        rmdir /s /q TempApp
    )
    goto :end
)

REM Check for CSC
csc /? >nul 2>&1
if %errorlevel% == 0 (
    echo C# Compiler found, using csc...
    csc "test-batch-compile.exe" /out:"test-batch-compile.exe" /target:exe
    if %errorlevel% == 0 (
        echo Compilation successful!
    ) else (
        echo Compilation failed!
    )
    goto :end
)

echo No .NET compiler found!
echo Please install .NET SDK or Visual Studio Build Tools
echo Download from: https://dotnet.microsoft.com/download

:end
pause
