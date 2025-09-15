# Portable DotNet Compilation Package

This package contains everything needed to compile the C# source code.

## Contents

- `Program.cs` - Source code
- `setup.bat` - Automated setup script
- `README.md` - This file

## Quick Start

1. Run `setup.bat` to automatically detect and use available compilers
2. Or follow the manual instructions below

## Manual Compilation

### Method 1: .NET SDK (Recommended)
```bash
dotnet new console -n MyApp
dotnet build -c Release
dotnet publish -c Release -r win-x64 --self-contained true
```

### Method 2: Visual Studio Build Tools
```bash
csc Program.cs /out:Program.exe /target:exe
```

### Method 3: Mono (Linux/Mac)
```bash
mcs Program.cs -out:Program.exe -target:exe
```

## Requirements

- Windows: .NET SDK or Visual Studio Build Tools
- Linux: .NET SDK or Mono
- macOS: .NET SDK or Mono

## Download Links

- .NET SDK: https://dotnet.microsoft.com/download
- Visual Studio Build Tools: https://visualstudio.microsoft.com/downloads/
- Mono: https://www.mono-project.com/download/

## Source Code

```csharp
using System;

class Program
{
    static void Main(string[] args)
    {
        Console.WriteLine("Hello from RawrZ DotNet Workaround Test!");
        Console.WriteLine("This is a test of the workaround system.");
        Console.WriteLine("Current time: " + DateTime.Now);
    }
}
```

Generated: 2025-09-15T15:34:34.842Z
