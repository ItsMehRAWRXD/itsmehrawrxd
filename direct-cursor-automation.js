#!/usr/bin/env node

/**
 * Direct Cursor Automation - More Aggressive Approach
 * This script directly monitors and handles Cursor dialogs
 */

const { exec, spawn } = require('child_process');
const os = require('os');

class DirectCursorAutomation {
    constructor() {
        this.isRunning = false;
        this.checkInterval = 2000; // Check every 2 seconds
        this.intervalId = null;
        this.platform = os.platform();
    }
    
    async start() {
        if (this.isRunning) {
            console.log('Bot is already running');
            return;
        }
        
        console.log('🚀 Starting Direct Cursor Automation...');
        console.log(`Platform: ${this.platform}`);
        console.log('👀 Monitoring for Cursor dialogs...');
        
        this.isRunning = true;
        
        // Start monitoring loop
        this.intervalId = setInterval(async () => {
            await this.checkAndHandleDialogs();
        }, this.checkInterval);
        
        console.log('✅ Direct automation started successfully');
    }
    
    async stop() {
        if (!this.isRunning) {
            console.log('Bot is not running');
            return;
        }
        
        console.log('🛑 Stopping Direct Cursor Automation...');
        this.isRunning = false;
        
        if (this.intervalId) {
            clearInterval(this.intervalId);
            this.intervalId = null;
        }
        
        console.log('✅ Direct automation stopped');
    }
    
    async checkAndHandleDialogs() {
        try {
            // Check if Cursor is running
            const cursorRunning = await this.isCursorRunning();
            if (!cursorRunning) {
                return;
            }
            
            // Try to handle any dialogs
            await this.handleDialogs();
            
        } catch (error) {
            // Silently continue - don't spam console with errors
        }
    }
    
    async isCursorRunning() {
        return new Promise((resolve) => {
            exec('tasklist /FI "IMAGENAME eq Cursor.exe"', (error, stdout) => {
                resolve(stdout.includes('Cursor.exe'));
            });
        });
    }
    
    async handleDialogs() {
        if (this.platform !== 'win32') {
            return;
        }
        
        // Try multiple approaches to handle dialogs
        await this.tryButtonClick();
        await this.tryCtrlEnter();
    }
    
    async tryButtonClick() {
        return new Promise((resolve) => {
            const psScript = `
                Add-Type -TypeDefinition @"
                    using System;
                    using System.Runtime.InteropServices;
                    using System.Text;
                    public class Win32 {
                        [DllImport("user32.dll")]
                        public static extern IntPtr FindWindow(string lpClassName, string lpWindowName);
                        [DllImport("user32.dll")]
                        public static extern IntPtr FindWindowEx(IntPtr hwndParent, IntPtr hwndChildAfter, string lpszClass, string lpszWindow);
                        [DllImport("user32.dll")]
                        public static extern bool SetForegroundWindow(IntPtr hWnd);
                        [DllImport("user32.dll")]
                        public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
                        [DllImport("user32.dll")]
                        public static extern bool BringWindowToTop(IntPtr hWnd);
                        [DllImport("user32.dll")]
                        public static extern bool SetActiveWindow(IntPtr hWnd);
                        [DllImport("user32.dll")]
                        public static extern bool SendMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);
                        [DllImport("user32.dll")]
                        public static extern bool PostMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);
                        [DllImport("user32.dll")]
                        public static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);
                        [DllImport("user32.dll")]
                        public static extern int GetWindowTextLength(IntPtr hWnd);
                        [DllImport("user32.dll")]
                        public static extern bool EnumChildWindows(IntPtr hWndParent, EnumWindowsProc lpEnumFunc, IntPtr lParam);
                        public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);
                    }
"@

                # Find Cursor window
                $cursorHwnd = [IntPtr]::Zero
                $windowTitles = @("Cursor", "Cursor -", "Cursor IDE")
                
                foreach ($title in $windowTitles) {
                    $hwnd = [Win32]::FindWindow($null, $title)
                    if ($hwnd -ne [IntPtr]::Zero) {
                        $cursorHwnd = $hwnd
                        break
                    }
                }
                
                if ($cursorHwnd -eq [IntPtr]::Zero) {
                    $cursorHwnd = [Win32]::FindWindow("Chrome_WidgetWin_1", $null)
                }
                
                if ($cursorHwnd -ne [IntPtr]::Zero) {
                    # Bring window to front
                    [Win32]::ShowWindow($cursorHwnd, 9) | Out-Null
                    [Win32]::BringWindowToTop($cursorHwnd) | Out-Null
                    [Win32]::SetActiveWindow($cursorHwnd) | Out-Null
                    [Win32]::SetForegroundWindow($cursorHwnd) | Out-Null
                    
                    Start-Sleep -Milliseconds 500
                    
                    # Try to find and click buttons
                    $buttonTexts = @("Keep all", "Keep All", "Keep", "Accept", "OK", "Yes", "Apply", "Confirm")
                    $clicked = $false
                    
                    foreach ($btnText in $buttonTexts) {
                        $buttonHwnd = [Win32]::FindWindowEx($cursorHwnd, [IntPtr]::Zero, "Button", $btnText)
                        if ($buttonHwnd -ne [IntPtr]::Zero) {
                            [Win32]::PostMessage($buttonHwnd, 0x0201, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null
                            Start-Sleep -Milliseconds 50
                            [Win32]::PostMessage($buttonHwnd, 0x0202, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null
                            Start-Sleep -Milliseconds 50
                            [Win32]::SendMessage($buttonHwnd, 0x00F5, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null
                            $clicked = $true
                            break
                        }
                    }
                    
                    if ($clicked) {
                        Write-Output "BUTTON_CLICKED"
                    } else {
                        Write-Output "NO_BUTTON_FOUND"
                    }
                } else {
                    Write-Output "CURSOR_NOT_FOUND"
                }
            `;
            
            exec(`powershell -Command "${psScript}"`, (error, stdout) => {
                if (!error && stdout.includes('BUTTON_CLICKED')) {
                    console.log('✅ Button clicked successfully');
                }
                resolve();
            });
        });
    }
    
    async tryCtrlEnter() {
        return new Promise((resolve) => {
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
                    }
"@

                # Find Cursor window
                $cursorHwnd = [IntPtr]::Zero
                $windowTitles = @("Cursor", "Cursor -", "Cursor IDE")
                
                foreach ($title in $windowTitles) {
                    $hwnd = [Win32]::FindWindow($null, $title)
                    if ($hwnd -ne [IntPtr]::Zero) {
                        $cursorHwnd = $hwnd
                        break
                    }
                }
                
                if ($cursorHwnd -eq [IntPtr]::Zero) {
                    $cursorHwnd = [Win32]::FindWindow("Chrome_WidgetWin_1", $null)
                }
                
                if ($cursorHwnd -ne [IntPtr]::Zero) {
                    # Bring window to front
                    [Win32]::ShowWindow($cursorHwnd, 9) | Out-Null
                    [Win32]::BringWindowToTop($cursorHwnd) | Out-Null
                    [Win32]::SetActiveWindow($cursorHwnd) | Out-Null
                    [Win32]::SetForegroundWindow($cursorHwnd) | Out-Null
                    
                    Start-Sleep -Milliseconds 500
                    
                    # Send Ctrl+Enter
                    [Win32]::keybd_event(0x11, 0, 0, [UIntPtr]::Zero)  # Ctrl down
                    Start-Sleep -Milliseconds 50
                    [Win32]::keybd_event(0x0D, 0, 0, [UIntPtr]::Zero)  # Enter down
                    Start-Sleep -Milliseconds 50
                    [Win32]::keybd_event(0x0D, 0, 2, [UIntPtr]::Zero)  # Enter up
                    Start-Sleep -Milliseconds 50
                    [Win32]::keybd_event(0x11, 0, 2, [UIntPtr]::Zero)  # Ctrl up
                    
                    Write-Output "CTRL_ENTER_SENT"
                } else {
                    Write-Output "CURSOR_NOT_FOUND"
                }
            `;
            
            exec(`powershell -Command "${psScript}"`, (error, stdout) => {
                if (!error && stdout.includes('CTRL_ENTER_SENT')) {
                    console.log('✅ Ctrl+Enter sent successfully');
                }
                resolve();
            });
        });
    }
}

// CLI interface
if (require.main === module) {
    const automation = new DirectCursorAutomation();
    
    // Handle process signals
    process.on('SIGINT', async () => {
        console.log('\n🛑 Received SIGINT, shutting down...');
        await automation.stop();
        process.exit(0);
    });
    
    process.on('SIGTERM', async () => {
        console.log('\n🛑 Received SIGTERM, shutting down...');
        await automation.stop();
        process.exit(0);
    });
    
    // Start the automation
    automation.start().catch(console.error);
    
    // Keep the process alive
    setInterval(() => {}, 1000);
}

module.exports = DirectCursorAutomation;
