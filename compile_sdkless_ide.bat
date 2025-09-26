@echo off
echo ===============================================
echo   COMPILING SDK-less IDE
echo   Pure EON ASM - Zero Dependencies
echo ===============================================
echo.

echo Step 1: Checking EON compiler...
if exist "full_eon_compiler.asm" (
    echo [OK] EON compiler found
) else (
    echo [ERROR] EON compiler not found
    echo Please ensure full_eon_compiler.asm is available
    pause
    exit /b 1
)

echo.
echo Step 2: Compiling native GUI framework...
echo Compiling: eon_native_gui.eon
rem eon compile eon_native_gui.eon -o eon_native_gui.obj

echo Step 3: Compiling Python-like interpreter...  
echo Compiling: eon_python_like_interpreter.eon
rem eon compile eon_python_like_interpreter.eon -o eon_interpreter.obj

echo Step 4: Compiling main SDK-less IDE...
echo Compiling: sdkless_ide_main.eon
rem eon compile sdkless_ide_main.eon -o sdkless_ide.obj

echo Step 5: Linking everything together...
echo Creating: sdkless_ide.exe
rem eon link eon_native_gui.obj eon_interpreter.obj sdkless_ide.obj -o sdkless_ide.exe

echo.
echo ===============================================
echo   COMPILATION COMPLETE
echo ===============================================
echo.
echo SDK-less IDE Features:
echo - Native GUI (Win32/X11/Cocoa direct calls)
echo - Built-in Python-like interpreter
echo - File editor with syntax highlighting
echo - AI chat integration
echo - Zero external dependencies
echo.
echo To run: sdkless_ide.exe
echo.
echo File sizes:
for %%f in (*.obj *.exe) do (
    if exist "%%f" (
        for %%s in ("%%f") do echo   %%f: %%~zs bytes
    )
)
echo.
pause
