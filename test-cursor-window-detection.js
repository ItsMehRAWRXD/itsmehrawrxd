#!/usr/bin/env node

/**
 * Test Cursor Window Detection
 * This script tests if we can find and interact with Cursor windows
 */

const { exec } = require('child_process');

function testCursorWindowDetection() {
    console.log('🧪 Testing Cursor Window Detection...\n');
    
    const psScript = `
        Add-Type -TypeDefinition @"
            using System;
            using System.Runtime.InteropServices;
            using System.Text;
            public class Win32 {
                [DllImport("user32.dll")]
                public static extern IntPtr FindWindow(string lpClassName, string lpWindowName);
                [DllImport("user32.dll")]
                public static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);
                [DllImport("user32.dll")]
                public static extern int GetWindowTextLength(IntPtr hWnd);
                [DllImport("user32.dll")]
                public static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);
                [DllImport("user32.dll")]
                public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);
                public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);
            }
"@

        # Find all Cursor windows
        $cursorWindows = @()
        
        $enumProc = {
            param([IntPtr]$hWnd, [IntPtr]$lParam)
            
            $textLength = [Win32]::GetWindowTextLength($hWnd)
            if ($textLength -gt 0) {
                $sb = New-Object System.Text.StringBuilder -ArgumentList ($textLength + 1)
                [Win32]::GetWindowText($hWnd, $sb, $sb.Capacity) | Out-Null
                $windowText = $sb.ToString()
                
                if ($windowText -like "*Cursor*") {
                    $processId = 0
                    [Win32]::GetWindowThreadProcessId($hWnd, [ref]$processId) | Out-Null
                    $cursorWindows += @{
                        Handle = $hWnd.ToString()
                        Title = $windowText
                        ProcessId = $processId
                    }
                }
            }
            return $true
        }
        
        [Win32]::EnumWindows($enumProc, [IntPtr]::Zero) | Out-Null
        
        Write-Output "Found $($cursorWindows.Count) Cursor windows:"
        foreach ($window in $cursorWindows) {
            Write-Output "  Handle: $($window.Handle), Title: '$($window.Title)', PID: $($window.ProcessId)"
        }
        
        # Try to find the main Cursor window
        $mainWindow = $cursorWindows | Where-Object { $_.Title -like "*Cursor*" -and $_.Title -notlike "*Cursor* - *" } | Select-Object -First 1
        
        if ($mainWindow) {
            Write-Output "Main Cursor window found: $($mainWindow.Title)"
            Write-Output "SUCCESS: Window detection working"
        } else {
            Write-Output "ERROR: Main Cursor window not found"
        }
    `;
    
    exec(`powershell -Command "${psScript}"`, (error, stdout, stderr) => {
        if (error) {
            console.error('❌ PowerShell execution failed:', error.message);
        } else {
            console.log('📋 Window Detection Results:');
            console.log(stdout);
            if (stderr) {
                console.log('⚠️  PowerShell Errors:');
                console.log(stderr);
            }
        }
    });
}

// Run the test
testCursorWindowDetection();
