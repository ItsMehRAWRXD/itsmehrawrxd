/**
 * Cursor Automation Bot - Auto-click "Keep all" when source is updated
 * Integrates with the existing RawrZ bot system architecture
 * 
 * Features:
 * - Automatic detection of Cursor IDE updates
 * - Auto-click "Keep all" functionality
 * - Configurable delay and retry mechanisms
 * - Integration with existing bot infrastructure
 * - Cross-platform support (Windows, macOS, Linux)
 */

const EventEmitter = require('events');
const fs = require('fs');
const path = require('path');
const { spawn, exec } = require('child_process');
const os = require('os');

class CursorAutomationBot extends EventEmitter {
    constructor(config = {}) {
        super();
        
        this.config = {
            // Default configuration
            autoClickDelay: 1000, // 1 second delay before clicking
            maxRetries: 3,
            retryDelay: 2000, // 2 seconds between retries
            checkInterval: 5000, // Check every 5 seconds
            enableLogging: true,
            enableNotifications: true,
            platform: os.platform(),
            
            // Cursor-specific paths
            cursorPaths: {
                win32: [
                    'C:\\Users\\%USERNAME%\\AppData\\Local\\Programs\\cursor\\Cursor.exe',
                    'C:\\Program Files\\Cursor\\Cursor.exe',
                    'C:\\Program Files (x86)\\Cursor\\Cursor.exe'
                ],
                darwin: [
                    '/Applications/Cursor.app/Contents/MacOS/Cursor',
                    '/Applications/Cursor.app'
                ],
                linux: [
                    '/usr/bin/cursor',
                    '/usr/local/bin/cursor',
                    '/opt/cursor/cursor',
                    '/snap/bin/cursor'
                ]
            },
            
            // UI automation settings
            uiSettings: {
                buttonText: 'Keep all',
                dialogTitle: 'Source updated',
                timeout: 10000, // 10 seconds timeout
                confidence: 0.8 // Image recognition confidence
            },
            
            // Integration settings
            integration: {
                enableHTTPBot: true,
                enableIRCBot: false,
                enableDiscordBot: false,
                webhookUrl: null,
                ircChannel: '#cursor-automation'
            },
            
            ...config
        };
        
        this.isRunning = false;
        this.cursorProcess = null;
        this.automationEngine = null;
        this.logger = this.initializeLogger();
        
        // Platform-specific automation engines
        this.automationEngines = {
            win32: 'windows-automation',
            darwin: 'macos-automation', 
            linux: 'linux-automation'
        };
        
        this.initializeAutomationEngine();
    }
    
    initializeLogger() {
        return {
            info: (msg) => {
                if (this.config.enableLogging) {
                    console.log(`[CursorBot][INFO] ${new Date().toISOString()}: ${msg}`);
                }
            },
            error: (msg) => {
                if (this.config.enableLogging) {
                    console.error(`[CursorBot][ERROR] ${new Date().toISOString()}: ${msg}`);
                }
            },
            warn: (msg) => {
                if (this.config.enableLogging) {
                    console.warn(`[CursorBot][WARN] ${new Date().toISOString()}: ${msg}`);
                }
            }
        };
    }
    
    async initializeAutomationEngine() {
        try {
            const platform = this.config.platform;
            this.logger.info(`Initializing automation engine for platform: ${platform}`);
            
            switch (platform) {
                case 'win32':
                    await this.initializeWindowsAutomation();
                    break;
                case 'darwin':
                    await this.initializeMacOSAutomation();
                    break;
                case 'linux':
                    await this.initializeLinuxAutomation();
                    break;
                default:
                    throw new Error(`Unsupported platform: ${platform}`);
            }
            
            this.logger.info('Automation engine initialized successfully');
        } catch (error) {
            this.logger.error(`Failed to initialize automation engine: ${error.message}`);
            throw error;
        }
    }
    
    async initializeWindowsAutomation() {
        // Windows automation using PowerShell and Windows API
        this.automationEngine = {
            type: 'windows',
            methods: {
                findWindow: this.findWindowWindows.bind(this),
                clickButton: this.clickButtonWindows.bind(this),
                waitForDialog: this.waitForDialogWindows.bind(this),
                takeScreenshot: this.takeScreenshotWindows.bind(this)
            }
        };
    }
    
    async initializeMacOSAutomation() {
        // macOS automation using AppleScript and Accessibility API
        this.automationEngine = {
            type: 'macos',
            methods: {
                findWindow: this.findWindowMacOS.bind(this),
                clickButton: this.clickButtonMacOS.bind(this),
                waitForDialog: this.waitForDialogMacOS.bind(this),
                takeScreenshot: this.takeScreenshotMacOS.bind(this)
            }
        };
    }
    
    async initializeLinuxAutomation() {
        // Linux automation using xdotool and other utilities
        this.automationEngine = {
            type: 'linux',
            methods: {
                findWindow: this.findWindowLinux.bind(this),
                clickButton: this.clickButtonLinux.bind(this),
                waitForDialog: this.waitForDialogLinux.bind(this),
                takeScreenshot: this.takeScreenshotLinux.bind(this)
            }
        };
    }
    
    // Windows automation methods
    async findWindowWindows(title) {
        return new Promise((resolve, reject) => {
            const psScript = `
                Add-Type -TypeDefinition @"
                    using System;
                    using System.Runtime.InteropServices;
                    public class Win32 {
                        [DllImport("user32.dll")]
                        public static extern IntPtr FindWindow(string lpClassName, string lpWindowName);
                        [DllImport("user32.dll")]
                        public static extern bool IsWindowVisible(IntPtr hWnd);
                        [DllImport("user32.dll")]
                        public static extern int GetWindowText(IntPtr hWnd, System.Text.StringBuilder lpString, int nMaxCount);
                    }
"@
                $hwnd = [Win32]::FindWindow($null, "${title}")
                if ($hwnd -ne [IntPtr]::Zero -and [Win32]::IsWindowVisible($hwnd)) {
                    Write-Output $hwnd.ToString()
                } else {
                    Write-Output "0"
                }
            `;
            
            exec(`powershell -Command "${psScript}"`, (error, stdout, stderr) => {
                if (error) {
                    reject(error);
                } else {
                    const hwnd = stdout.trim();
                    resolve(hwnd !== "0" ? hwnd : null);
                }
            });
        });
    }
    
    async clickButtonWindows(buttonText) {
        return new Promise((resolve, reject) => {
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

                function Find-ButtonInWindow {
                    param([IntPtr]$parentHwnd, [string]$buttonText)
                    
                    $foundButton = [IntPtr]::Zero
                    
                    $enumProc = {
                        param([IntPtr]$hWnd, [IntPtr]$lParam)
                        
                        $textLength = [Win32]::GetWindowTextLength($hWnd)
                        if ($textLength -gt 0) {
                            $sb = New-Object System.Text.StringBuilder -ArgumentList ($textLength + 1)
                            [Win32]::GetWindowText($hWnd, $sb, $sb.Capacity) | Out-Null
                            $windowText = $sb.ToString()
                            
                            if ($windowText -like "*${buttonText}*") {
                                $foundButton = $hWnd
                                return $false
                            }
                        }
                        return $true
                    }
                    
                    [Win32]::EnumChildWindows($parentHwnd, $enumProc, [IntPtr]::Zero) | Out-Null
                    return $foundButton
                }

                # Try multiple window title variations
                $windowTitles = @("Cursor", "Source updated", "Update available", "File changed", "Review change", "Review changes", "Review file")
                $cursorHwnd = [IntPtr]::Zero
                
                foreach ($title in $windowTitles) {
                    $hwnd = [Win32]::FindWindow($null, $title)
                    if ($hwnd -ne [IntPtr]::Zero) {
                        $cursorHwnd = $hwnd
                        break
                    }
                }
                
                if ($cursorHwnd -ne [IntPtr]::Zero) {
                    # Bring window to front and activate
                    [Win32]::ShowWindow($cursorHwnd, 9) | Out-Null  # SW_RESTORE
                    [Win32]::BringWindowToTop($cursorHwnd) | Out-Null
                    [Win32]::SetActiveWindow($cursorHwnd) | Out-Null
                    [Win32]::SetForegroundWindow($cursorHwnd) | Out-Null
                    
                    Start-Sleep -Milliseconds 1000
                    
                    # Try multiple button text variations
                    $buttonTexts = @("${buttonText}", "Keep all", "Keep All", "Keep", "Accept", "OK", "Yes", "Apply", "Confirm")
                    $buttonHwnd = [IntPtr]::Zero
                    
                    foreach ($btnText in $buttonTexts) {
                        # First try direct button search
                        $buttonHwnd = [Win32]::FindWindowEx($cursorHwnd, [IntPtr]::Zero, "Button", $btnText)
                        if ($buttonHwnd -ne [IntPtr]::Zero) {
                            break
                        }
                        
                        # Try searching in child windows
                        $buttonHwnd = Find-ButtonInWindow -parentHwnd $cursorHwnd -buttonText $btnText
                        if ($buttonHwnd -ne [IntPtr]::Zero) {
                            break
                        }
                    }
                    
                    if ($buttonHwnd -ne [IntPtr]::Zero) {
                        # Click the button using multiple methods
                        [Win32]::PostMessage($buttonHwnd, 0x0201, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null  # WM_LBUTTONDOWN
                        Start-Sleep -Milliseconds 50
                        [Win32]::PostMessage($buttonHwnd, 0x0202, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null  # WM_LBUTTONUP
                        Start-Sleep -Milliseconds 50
                        [Win32]::SendMessage($buttonHwnd, 0x00F5, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null  # BM_CLICK
                        
                        Write-Output "SUCCESS"
                    } else {
                        # If no button found, try Ctrl+Enter as fallback
                        Write-Output "BUTTON_NOT_FOUND_TRYING_CTRL_ENTER"
                    }
                } else {
                    Write-Output "WINDOW_NOT_FOUND"
                }
            `;
            
            exec(`powershell -Command "${psScript}"`, async (error, stdout, stderr) => {
                if (error) {
                    reject(error);
                } else {
                    const result = stdout.trim();
                    if (result === "SUCCESS") {
                        resolve(true);
                    } else if (result === "BUTTON_NOT_FOUND_TRYING_CTRL_ENTER") {
                        // Try Ctrl+Enter as fallback
                        try {
                            await this.sendCtrlEnterWindows();
                            resolve(true);
                        } catch (ctrlError) {
                            reject(new Error(`Failed to click button and Ctrl+Enter: ${ctrlError.message}`));
                        }
                    } else {
                        reject(new Error(`Failed to click button: ${result}`));
                    }
                }
            });
        });
    }
    
    async sendCtrlEnterWindows() {
        return new Promise((resolve, reject) => {
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

                # Find Cursor IDE window (main application window)
                $cursorHwnd = [IntPtr]::Zero
                $windowTitles = @("Cursor", "Cursor -", "Cursor IDE")
                
                foreach ($title in $windowTitles) {
                    $hwnd = [Win32]::FindWindow($null, $title)
                    if ($hwnd -ne [IntPtr]::Zero) {
                        $cursorHwnd = $hwnd
                        break
                    }
                }
                
                # If not found by title, try to find by class name
                if ($cursorHwnd -eq [IntPtr]::Zero) {
                    $cursorHwnd = [Win32]::FindWindow("Chrome_WidgetWin_1", $null)  # Cursor uses Chromium
                }
                
                if ($cursorHwnd -ne [IntPtr]::Zero) {
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
                    
                    # Send Ctrl+Enter to the focused Cursor window
                    [Win32]::keybd_event(0x11, 0, 0, [UIntPtr]::Zero)  # VK_CONTROL down
                    Start-Sleep -Milliseconds 100
                    [Win32]::keybd_event(0x0D, 0, 0, [UIntPtr]::Zero)  # VK_RETURN down
                    Start-Sleep -Milliseconds 100
                    [Win32]::keybd_event(0x0D, 0, 2, [UIntPtr]::Zero)  # VK_RETURN up
                    Start-Sleep -Milliseconds 100
                    [Win32]::keybd_event(0x11, 0, 2, [UIntPtr]::Zero)  # VK_CONTROL up
                    
                    Write-Output "CTRL_ENTER_SENT"
                } else {
                    Write-Output "WINDOW_NOT_FOUND"
                }
            `;
            
            exec(`powershell -Command "${psScript}"`, (error, stdout, stderr) => {
                if (error) {
                    reject(error);
                } else {
                    const result = stdout.trim();
                    if (result === "CTRL_ENTER_SENT") {
                        resolve(true);
                    } else {
                        reject(new Error(`Failed to send Ctrl+Enter: ${result}`));
                    }
                }
            });
        });
    }
    
    async waitForDialogWindows(timeout = 10000) {
        const startTime = Date.now();
        
        while (Date.now() - startTime < timeout) {
            try {
                // Try multiple dialog title variations
                const dialogTitles = [
                    'Source updated',
                    'Update available', 
                    'File changed',
                    'Changes detected',
                    'Review change',
                    'Review changes',
                    'Review file',
                    'Cursor',
                    'Update'
                ];
                
                for (const title of dialogTitles) {
                    const hwnd = await this.findWindowWindows(title);
                    if (hwnd) {
                        this.logger.info(`Found dialog with title: ${title}`);
                        return hwnd;
                    }
                }
            } catch (error) {
                // Continue checking
            }
            
            await this.sleep(500);
        }
        
        return null;
    }
    
    async takeScreenshotWindows() {
        return new Promise((resolve, reject) => {
            const psScript = `
                Add-Type -AssemblyName System.Windows.Forms
                Add-Type -AssemblyName System.Drawing
                $screen = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
                $bitmap = New-Object System.Drawing.Bitmap $screen.Width, $screen.Height
                $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
                $graphics.CopyFromScreen($screen.Left, $screen.Top, 0, 0, $screen.Size)
                $graphics.Dispose()
                $bitmap.Save("${path.join(__dirname, '..', '..', 'temp', 'cursor_screenshot.png')}")
                $bitmap.Dispose()
                Write-Output "SUCCESS"
            `;
            
            exec(`powershell -Command "${psScript}"`, (error, stdout, stderr) => {
                if (error) {
                    reject(error);
                } else {
                    resolve(stdout.trim() === "SUCCESS");
                }
            });
        });
    }
    
    // macOS automation methods
    async findWindowMacOS(title) {
        return new Promise((resolve, reject) => {
            const script = `
                tell application "System Events"
                    try
                        set cursorApp to first application process whose name contains "Cursor"
                        set windowList to windows of cursorApp
                        repeat with win in windowList
                            if title of win contains "${title}" then
                                return "FOUND"
                            end if
                        end repeat
                        return "NOT_FOUND"
                    on error
                        return "ERROR"
                    end try
                end tell
            `;
            
            exec(`osascript -e '${script}'`, (error, stdout, stderr) => {
                if (error) {
                    reject(error);
                } else {
                    const result = stdout.trim();
                    resolve(result === "FOUND");
                }
            });
        });
    }
    
    async clickButtonMacOS(buttonText) {
        return new Promise((resolve, reject) => {
            const script = `
                tell application "System Events"
                    try
                        set cursorApp to first application process whose name contains "Cursor"
                        set buttonList to buttons of cursorApp
                        repeat with btn in buttonList
                            if title of btn contains "${buttonText}" then
                                click btn
                                return "SUCCESS"
                            end if
                        end repeat
                        return "BUTTON_NOT_FOUND"
                    on error
                        return "ERROR"
                    end try
                end tell
            `;
            
            exec(`osascript -e '${script}'`, (error, stdout, stderr) => {
                if (error) {
                    reject(error);
                } else {
                    const result = stdout.trim();
                    if (result === "SUCCESS") {
                        resolve(true);
                    } else {
                        reject(new Error(`Failed to click button: ${result}`));
                    }
                }
            });
        });
    }
    
    async waitForDialogMacOS(timeout = 10000) {
        const startTime = Date.now();
        
        while (Date.now() - startTime < timeout) {
            try {
                const found = await this.findWindowMacOS('Source updated');
                if (found) {
                    return true;
                }
            } catch (error) {
                // Continue checking
            }
            
            await this.sleep(500);
        }
        
        return false;
    }
    
    async takeScreenshotMacOS() {
        return new Promise((resolve, reject) => {
            const screenshotPath = path.join(__dirname, '..', '..', 'temp', 'cursor_screenshot.png');
            exec(`screencapture "${screenshotPath}"`, (error, stdout, stderr) => {
                if (error) {
                    reject(error);
                } else {
                    resolve(true);
                }
            });
        });
    }
    
    // Linux automation methods
    async findWindowLinux(title) {
        return new Promise((resolve, reject) => {
            exec(`xdotool search --name "${title}"`, (error, stdout, stderr) => {
                if (error) {
                    resolve(null);
                } else {
                    const windowId = stdout.trim();
                    resolve(windowId || null);
                }
            });
        });
    }
    
    async clickButtonLinux(buttonText) {
        return new Promise((resolve, reject) => {
            // First find the Cursor window
            exec('xdotool search --name "Cursor"', (error, stdout, stderr) => {
                if (error) {
                    reject(new Error('Cursor window not found'));
                    return;
                }
                
                const windowId = stdout.trim().split('\n')[0];
                if (!windowId) {
                    reject(new Error('Cursor window not found'));
                    return;
                }
                
                // Focus the window
                exec(`xdotool windowactivate ${windowId}`, (error2, stdout2, stderr2) => {
                    if (error2) {
                        reject(error2);
                        return;
                    }
                    
                    // Try to find and click the button
                    exec(`xdotool search --name "${buttonText}" windowactivate --sync click 1`, (error3, stdout3, stderr3) => {
                        if (error3) {
                            reject(new Error(`Failed to click button: ${error3.message}`));
                        } else {
                            resolve(true);
                        }
                    });
                });
            });
        });
    }
    
    async waitForDialogLinux(timeout = 10000) {
        const startTime = Date.now();
        
        while (Date.now() - startTime < timeout) {
            try {
                const windowId = await this.findWindowLinux('Source updated');
                if (windowId) {
                    return windowId;
                }
            } catch (error) {
                // Continue checking
            }
            
            await this.sleep(500);
        }
        
        return null;
    }
    
    async takeScreenshotLinux() {
        return new Promise((resolve, reject) => {
            const screenshotPath = path.join(__dirname, '..', '..', 'temp', 'cursor_screenshot.png');
            exec(`import -window root "${screenshotPath}"`, (error, stdout, stderr) => {
                if (error) {
                    reject(error);
                } else {
                    resolve(true);
                }
            });
        });
    }
    
    // Core automation methods
    async start() {
        if (this.isRunning) {
            this.logger.warn('Bot is already running');
            return;
        }
        
        try {
            this.logger.info('Starting Cursor Automation Bot...');
            this.isRunning = true;
            
            // Start monitoring loop
            this.monitoringInterval = setInterval(async () => {
                await this.checkForUpdates();
            }, this.config.checkInterval);
            
            this.logger.info('Cursor Automation Bot started successfully');
            this.emit('started');
            
        } catch (error) {
            this.logger.error(`Failed to start bot: ${error.message}`);
            this.isRunning = false;
            throw error;
        }
    }
    
    async stop() {
        if (!this.isRunning) {
            this.logger.warn('Bot is not running');
            return;
        }
        
        try {
            this.logger.info('Stopping Cursor Automation Bot...');
            this.isRunning = false;
            
            if (this.monitoringInterval) {
                clearInterval(this.monitoringInterval);
                this.monitoringInterval = null;
            }
            
            this.logger.info('Cursor Automation Bot stopped successfully');
            this.emit('stopped');
            
        } catch (error) {
            this.logger.error(`Failed to stop bot: ${error.message}`);
            throw error;
        }
    }
    
    async checkForUpdates() {
        try {
            // Check if Cursor is running
            const cursorRunning = await this.isCursorRunning();
            if (!cursorRunning) {
                return;
            }
            
            // Wait for update dialog
            const dialogFound = await this.automationEngine.methods.waitForDialog(
                this.config.uiSettings.timeout
            );
            
            if (dialogFound) {
                this.logger.info('Update dialog detected, attempting to click "Keep all"');
                await this.handleUpdateDialog();
            }
            
        } catch (error) {
            this.logger.error(`Error checking for updates: ${error.message}`);
        }
    }
    
    async handleUpdateDialog() {
        let retries = 0;
        
        while (retries < this.config.maxRetries) {
            try {
                // Wait for the configured delay
                await this.sleep(this.config.autoClickDelay);
                
                // Take screenshot for debugging
                if (this.config.enableLogging) {
                    await this.automationEngine.methods.takeScreenshot();
                }
                
                // Check if this is a "Review file" dialog that needs two-step process
                const isReviewFileDialog = await this.isReviewFileDialog();
                
                let success = false;
                
                if (isReviewFileDialog) {
                    // Handle "Review file" dialog with two-step process
                    success = await this.handleReviewFileDialog();
                } else {
                    // Handle regular dialogs
                    success = await this.handleRegularDialog();
                }
                
                if (success) {
                    this.emit('updateHandled', { success: true, retries, method: isReviewFileDialog ? 'review_file_two_step' : 'regular_dialog' });
                    
                    // Send notification if enabled
                    if (this.config.enableNotifications) {
                        await this.sendNotification('Cursor update handled successfully');
                    }
                    
                    return;
                } else {
                    throw new Error('Dialog handling failed');
                }
                
            } catch (error) {
                retries++;
                this.logger.warn(`Attempt ${retries} failed: ${error.message}`);
                
                if (retries < this.config.maxRetries) {
                    await this.sleep(this.config.retryDelay);
                } else {
                    this.logger.error(`Failed to handle update dialog after ${retries} attempts`);
                    this.emit('updateHandled', { success: false, retries, error: error.message });
                    
                    if (this.config.enableNotifications) {
                        await this.sendNotification(`Failed to handle Cursor update after ${retries} attempts`);
                    }
                }
            }
        }
    }
    
    async isReviewFileDialog() {
        try {
            // Since the dialog appears in the middle of Cursor IDE, we'll check if Cursor is running
            // and assume any dialog detection means it's likely a review dialog
            const cursorRunning = await this.isCursorRunning();
            if (!cursorRunning) {
                return false;
            }
            
            // Check for any dialog-like windows or just assume it's a review dialog
            // when Cursor is running and we detect a dialog
            const reviewTitles = [
                'Review file', 'Review change', 'Review changes', 
                'File changed', 'Source updated', 'Update available',
                'Changes detected', 'Cursor', 'Update'
            ];
            
            for (const title of reviewTitles) {
                const hwnd = await this.findWindowWindows(title);
                if (hwnd) {
                    this.logger.info(`Detected potential Review file dialog: ${title}`);
                    return true;
                }
            }
            
            // If Cursor is running, we can also assume any dialog is likely a review dialog
            // since that's the most common case when files are updated
            this.logger.info('Cursor is running, assuming any dialog is a review dialog');
            return true;
        } catch (error) {
            return false;
        }
    }
    
    async handleReviewFileDialog() {
        try {
            this.logger.info('Handling Review file dialog - attempting multiple methods');
            
            let success = false;
            
            // Method 1: Try to find and click "Keep all" button
            try {
                await this.automationEngine.methods.clickButton("Keep all");
                this.logger.info('Method 1: Successfully clicked "Keep all" button');
                success = true;
            } catch (buttonError) {
                this.logger.warn(`Method 1 failed: ${buttonError.message}`);
                
                // Method 2: Try Ctrl+Enter as fallback
                try {
                    if (this.config.platform === 'win32') {
                        await this.sendCtrlEnterWindows();
                        this.logger.info('Method 2: Sent Ctrl+Enter to Cursor IDE');
                        success = true;
                    }
                } catch (ctrlError) {
                    this.logger.warn(`Method 2 failed: ${ctrlError.message}`);
                    
                    // Method 3: Try other common button texts
                    const alternativeButtons = ["Keep", "Accept", "OK", "Yes", "Apply"];
                    for (const buttonText of alternativeButtons) {
                        try {
                            await this.automationEngine.methods.clickButton(buttonText);
                            this.logger.info(`Method 3: Successfully clicked "${buttonText}" button`);
                            success = true;
                            break;
                        } catch (altError) {
                            this.logger.warn(`Method 3 "${buttonText}" failed: ${altError.message}`);
                        }
                    }
                }
            }
            
            return success;
        } catch (error) {
            this.logger.error(`Review file dialog handling failed: ${error.message}`);
            return false;
        }
    }
    
    async handleRegularDialog() {
        try {
            // First try to click button
            try {
                await this.automationEngine.methods.clickButton(this.config.uiSettings.buttonText);
                this.logger.info('Successfully clicked "Keep all" button');
                return true;
            } catch (buttonError) {
                this.logger.warn(`Button click failed: ${buttonError.message}`);
                
                // Try Ctrl+Enter as fallback
                try {
                    if (this.config.platform === 'win32') {
                        await this.sendCtrlEnterWindows();
                        this.logger.info('Successfully sent Ctrl+Enter as fallback');
                        return true;
                    }
                } catch (ctrlError) {
                    this.logger.warn(`Ctrl+Enter failed: ${ctrlError.message}`);
                }
            }
            
            return false;
        } catch (error) {
            this.logger.error(`Regular dialog handling failed: ${error.message}`);
            return false;
        }
    }
    
    async isCursorRunning() {
        return new Promise((resolve) => {
            const platform = this.config.platform;
            let command;
            
            switch (platform) {
                case 'win32':
                    command = 'tasklist /FI "IMAGENAME eq Cursor.exe"';
                    break;
                case 'darwin':
                    command = 'pgrep -f "Cursor"';
                    break;
                case 'linux':
                    command = 'pgrep -f "cursor"';
                    break;
                default:
                    resolve(false);
                    return;
            }
            
            exec(command, (error, stdout, stderr) => {
                if (error) {
                    resolve(false);
                } else {
                    resolve(stdout.trim().length > 0);
                }
            });
        });
    }
    
    async sendNotification(message) {
        try {
            if (this.config.integration.enableHTTPBot) {
                await this.sendHTTPNotification(message);
            }
            
            if (this.config.integration.enableIRCBot) {
                await this.sendIRCNotification(message);
            }
            
            if (this.config.integration.enableDiscordBot) {
                await this.sendDiscordNotification(message);
            }
            
        } catch (error) {
            this.logger.error(`Failed to send notification: ${error.message}`);
        }
    }
    
    async sendHTTPNotification(message) {
        if (!this.config.integration.webhookUrl) {
            return;
        }
        
        const payload = {
            text: `[Cursor Bot] ${message}`,
            timestamp: new Date().toISOString(),
            source: 'cursor-automation-bot'
        };
        
        // Send HTTP POST request to webhook
        const https = require('https');
        const url = require('url');
        
        const parsedUrl = url.parse(this.config.integration.webhookUrl);
        const postData = JSON.stringify(payload);
        
        const options = {
            hostname: parsedUrl.hostname,
            port: parsedUrl.port || 443,
            path: parsedUrl.path,
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(postData)
            }
        };
        
        return new Promise((resolve, reject) => {
            const req = https.request(options, (res) => {
                resolve();
            });
            
            req.on('error', (error) => {
                reject(error);
            });
            
            req.write(postData);
            req.end();
        });
    }
    
    async sendIRCNotification(message) {
        // Integration with existing IRC bot system
        this.emit('ircMessage', {
            channel: this.config.integration.ircChannel,
            message: `[Cursor Bot] ${message}`
        });
    }
    
    async sendDiscordNotification(message) {
        // Integration with Discord bot system
        this.emit('discordMessage', {
            channel: 'cursor-automation',
            message: `[Cursor Bot] ${message}`
        });
    }
    
    // Utility methods
    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
    
    // Configuration methods
    updateConfig(newConfig) {
        this.config = { ...this.config, ...newConfig };
        this.logger.info('Configuration updated');
        this.emit('configUpdated', this.config);
    }
    
    getConfig() {
        return { ...this.config };
    }
    
    // Status methods
    getStatus() {
        return {
            isRunning: this.isRunning,
            platform: this.config.platform,
            automationEngine: this.automationEngine?.type,
            uptime: this.isRunning ? Date.now() - this.startTime : 0
        };
    }
}

// Export the class
module.exports = CursorAutomationBot;

// CLI interface
if (require.main === module) {
    const bot = new CursorAutomationBot();
    
    // Handle command line arguments
    const args = process.argv.slice(2);
    
    if (args.includes('--start')) {
        bot.start().catch(console.error);
    } else if (args.includes('--stop')) {
        bot.stop().catch(console.error);
    } else if (args.includes('--status')) {
        console.log('Status:', bot.getStatus());
    } else if (args.includes('--config')) {
        console.log('Configuration:', JSON.stringify(bot.getConfig(), null, 2));
    } else {
        console.log(`
Cursor Automation Bot - Auto-click "Keep all" when source is updated

Usage:
  node cursor-automation-bot.js --start     Start the automation bot
  node cursor-automation-bot.js --stop      Stop the automation bot
  node cursor-automation-bot.js --status    Show bot status
  node cursor-automation-bot.js --config    Show current configuration

Features:
  - Cross-platform support (Windows, macOS, Linux)
  - Automatic detection of Cursor IDE updates
  - Auto-click "Keep all" functionality
  - Configurable delays and retry mechanisms
  - Integration with existing bot infrastructure
  - Screenshot capture for debugging
  - Notification system (HTTP, IRC, Discord)
        `);
    }
}
