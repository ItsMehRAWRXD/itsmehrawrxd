#!/usr/bin/env node

/**
 * Simple Cursor Test - Direct Ctrl+Enter to Cursor
 */

const { exec } = require('child_process');

function sendCtrlEnterToCursor() {
    console.log('🎯 Sending Ctrl+Enter to Cursor IDE...\n');
    
    const psScript = `
        # Simple approach - find Cursor process and send keystroke
        $cursorProcess = Get-Process -Name "Cursor" -ErrorAction SilentlyContinue | Select-Object -First 1
        
        if ($cursorProcess) {
            Write-Output "Found Cursor process: PID $($cursorProcess.Id)"
            
            # Bring Cursor to front
            Add-Type -TypeDefinition @"
                using System;
                using System.Runtime.InteropServices;
                public class Win32 {
                    [DllImport("user32.dll")]
                    public static extern bool SetForegroundWindow(IntPtr hWnd);
                    [DllImport("user32.dll")]
                    public static extern IntPtr FindWindow(string lpClassName, string lpWindowName);
                    [DllImport("user32.dll")]
                    public static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);
                }
"@
            
            # Find Cursor window
            $cursorHwnd = [Win32]::FindWindow($null, "Cursor")
            if ($cursorHwnd -eq [IntPtr]::Zero) {
                $cursorHwnd = [Win32]::FindWindow("Chrome_WidgetWin_1", $null)
            }
            
            if ($cursorHwnd -ne [IntPtr]::Zero) {
                Write-Output "Found Cursor window, bringing to front..."
                [Win32]::SetForegroundWindow($cursorHwnd) | Out-Null
                Start-Sleep -Milliseconds 500
                
                Write-Output "Sending Ctrl+Enter..."
                [Win32]::keybd_event(0x11, 0, 0, [UIntPtr]::Zero)  # Ctrl down
                Start-Sleep -Milliseconds 50
                [Win32]::keybd_event(0x0D, 0, 0, [UIntPtr]::Zero)  # Enter down
                Start-Sleep -Milliseconds 50
                [Win32]::keybd_event(0x0D, 0, 2, [UIntPtr]::Zero)  # Enter up
                Start-Sleep -Milliseconds 50
                [Win32]::keybd_event(0x11, 0, 2, [UIntPtr]::Zero)  # Ctrl up
                
                Write-Output "SUCCESS: Ctrl+Enter sent to Cursor"
            } else {
                Write-Output "ERROR: Could not find Cursor window"
            }
        } else {
            Write-Output "ERROR: Cursor process not found"
        }
    `;
    
    exec(`powershell -Command "${psScript}"`, (error, stdout, stderr) => {
        console.log('📋 Results:');
        console.log(stdout);
        if (stderr) {
            console.log('⚠️  Errors:');
            console.log(stderr);
        }
        if (error) {
            console.error('❌ Execution failed:', error.message);
        }
    });
}

// Run the test
sendCtrlEnterToCursor();
