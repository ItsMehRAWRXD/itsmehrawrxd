#!/usr/bin/env node

/**
 * Test Ctrl+Enter functionality
 * This script tests if we can send Ctrl+Enter to Cursor IDE
 */

const { exec } = require('child_process');

function testCtrlEnter() {
    console.log('🧪 Testing Ctrl+Enter functionality...\n');
    
    const psScript = `
        Add-Type -TypeDefinition @"
            using System;
            using System.Runtime.InteropServices;
            public class Win32 {
                [DllImport("user32.dll")]
                public static extern IntPtr FindWindow(string lpClassName, string lpWindowName);
                [DllImport("user32.dll")]
                public static extern bool SetForegroundWindow(IntPtr hWnd);
                [DllImport("user32.dll")]
                public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
                [DllImport("user32.dll")]
                public static extern bool BringWindowToTop(IntPtr hWnd);
                [DllImport("user32.dll")]
                public static extern bool SetActiveWindow(IntPtr hWnd);
                [DllImport("user32.dll")]
                public static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);
                [DllImport("user32.dll")]
                public static extern bool AttachThreadInput(uint idAttach, uint idAttachTo, bool fAttach);
                [DllImport("user32.dll")]
                public static extern uint GetCurrentThreadId();
                [DllImport("user32.dll")]
                public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);
            }
"@

        # Find Cursor IDE window
        $cursorHwnd = [IntPtr]::Zero
        $windowTitles = @("Cursor", "Cursor -", "Cursor IDE")
        
        foreach ($title in $windowTitles) {
            $hwnd = [Win32]::FindWindow($null, $title)
            if ($hwnd -ne [IntPtr]::Zero) {
                $cursorHwnd = $hwnd
                Write-Output "Found Cursor window with title: $title"
                break
            }
        }
        
        # If not found by title, try to find by class name
        if ($cursorHwnd -eq [IntPtr]::Zero) {
            $cursorHwnd = [Win32]::FindWindow("Chrome_WidgetWin_1", $null)
            if ($cursorHwnd -ne [IntPtr]::Zero) {
                Write-Output "Found Cursor window by class name: Chrome_WidgetWin_1"
            }
        }
        
        if ($cursorHwnd -ne [IntPtr]::Zero) {
            Write-Output "Cursor window found, attempting to focus and send Ctrl+Enter..."
            
            # Get window thread and attach to it for proper focus
            $windowThreadId = [Win32]::GetWindowThreadProcessId($cursorHwnd, [ref]$null)
            $currentThreadId = [Win32]::GetCurrentThreadId()
            
            if ($windowThreadId -ne $currentThreadId) {
                [Win32]::AttachThreadInput($currentThreadId, $windowThreadId, $true) | Out-Null
            }
            
            # Bring window to front and activate
            [Win32]::ShowWindow($cursorHwnd, 9) | Out-Null  # SW_RESTORE
            [Win32]::BringWindowToTop($cursorHwnd) | Out-Null
            [Win32]::SetActiveWindow($cursorHwnd) | Out-Null
            [Win32]::SetForegroundWindow($cursorHwnd) | Out-Null
            
            # Detach thread input
            if ($windowThreadId -ne $currentThreadId) {
                [Win32]::AttachThreadInput($currentThreadId, $windowThreadId, $false) | Out-Null
            }
            
            Start-Sleep -Milliseconds 1000
            
            # Send Ctrl+Enter
            Write-Output "Sending Ctrl+Enter..."
            [Win32]::keybd_event(0x11, 0, 0, [UIntPtr]::Zero)  # VK_CONTROL down
            Start-Sleep -Milliseconds 100
            [Win32]::keybd_event(0x0D, 0, 0, [UIntPtr]::Zero)  # VK_RETURN down
            Start-Sleep -Milliseconds 100
            [Win32]::keybd_event(0x0D, 0, 2, [UIntPtr]::Zero)  # VK_RETURN up
            Start-Sleep -Milliseconds 100
            [Win32]::keybd_event(0x11, 0, 2, [UIntPtr]::Zero)  # VK_CONTROL up
            
            Write-Output "SUCCESS: Ctrl+Enter sent to Cursor"
        } else {
            Write-Output "ERROR: Cursor window not found"
        }
    `;
    
    exec(`powershell -Command "${psScript}"`, (error, stdout, stderr) => {
        if (error) {
            console.error('❌ PowerShell execution failed:', error.message);
        } else {
            console.log('📋 PowerShell Output:');
            console.log(stdout);
            if (stderr) {
                console.log('⚠️  PowerShell Errors:');
                console.log(stderr);
            }
        }
    });
}

// Run the test
testCtrlEnter();
