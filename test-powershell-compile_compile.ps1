# DotNet Compilation PowerShell Script
# Generated: 2025-09-15T15:34:34.838Z

Write-Host "Starting DotNet compilation..." -ForegroundColor Green

# Check for .NET SDK
try {
    $dotnetVersion = dotnet --version 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host ".NET SDK found: $dotnetVersion" -ForegroundColor Green
        Write-Host "Using dotnet build..." -ForegroundColor Yellow
        
        # Create temporary project
        dotnet new console -n TempApp --force
        Copy-Item "test-powershell-compile.exe" "TempApp\Program.cs"
        Set-Location TempApp
        
        # Build project
        dotnet build -c Release
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Compilation successful!" -ForegroundColor Green
            Copy-Item "bin\Release\net6.0\TempApp.exe" "..\test-powershell-compile.exe"
            Set-Location ..
            Remove-Item -Recurse -Force TempApp
        } else {
            Write-Host "Compilation failed!" -ForegroundColor Red
            Set-Location ..
            Remove-Item -Recurse -Force TempApp
        }
        exit
    }
} catch {
    Write-Host ".NET SDK not found" -ForegroundColor Yellow
}

# Check for CSC
try {
    $cscVersion = csc /? 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "C# Compiler found, using csc..." -ForegroundColor Green
        csc "test-powershell-compile.exe" /out:"test-powershell-compile.exe" /target:exe
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Compilation successful!" -ForegroundColor Green
        } else {
            Write-Host "Compilation failed!" -ForegroundColor Red
        }
        exit
    }
} catch {
    Write-Host "C# Compiler not found" -ForegroundColor Yellow
}

Write-Host "No .NET compiler found!" -ForegroundColor Red
Write-Host "Please install .NET SDK or Visual Studio Build Tools" -ForegroundColor Yellow
Write-Host "Download from: https://dotnet.microsoft.com/download" -ForegroundColor Cyan

Read-Host "Press Enter to continue"
