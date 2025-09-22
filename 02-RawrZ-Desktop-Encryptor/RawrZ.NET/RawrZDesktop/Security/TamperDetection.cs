using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Diagnostics;

namespace RawrZDesktop.Security
{
    public class TamperDetection
    {
        private static readonly byte[] _expectedHash = new byte[]
        {
            0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
        };

        private static readonly string _integrityMarker = "RAWRZ_INTEGRITY_CHECK";
        private static readonly string _tamperDetectedMessage = "TAMPER_DETECTED";

        /// <summary>
        /// Verifies the integrity of the current executable
        /// </summary>
        public static bool VerifyExecutableIntegrity()
        {
            try
            {
                // Get the current executable path
                string executablePath = Assembly.GetExecutingAssembly().Location;
                
                if (string.IsNullOrEmpty(executablePath))
                {
                    // For single-file deployments, use the process path
                    executablePath = Process.GetCurrentProcess().MainModule?.FileName;
                }

                if (string.IsNullOrEmpty(executablePath) || !File.Exists(executablePath))
                {
                    return false;
                }

                // Calculate hash of the executable
                byte[] currentHash = CalculateFileHash(executablePath);
                
                // Compare with expected hash (in production, this would be stored securely)
                return CompareHashes(currentHash, _expectedHash);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Verifies the integrity of an encrypted file
        /// </summary>
        public static bool VerifyFileIntegrity(string filePath, string? expectedChecksum = null)
        {
            try
            {
                if (!File.Exists(filePath))
                    return false;

                // Check if file has integrity marker
                if (HasIntegrityMarker(filePath))
                {
                    return VerifyIntegrityMarker(filePath);
                }

                // If expected checksum provided, verify against it
                if (!string.IsNullOrEmpty(expectedChecksum))
                {
                    string actualChecksum = CalculateFileChecksum(filePath);
                    return string.Equals(actualChecksum, expectedChecksum, StringComparison.OrdinalIgnoreCase);
                }

                return true; // No integrity check available
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Adds integrity protection to an encrypted file
        /// </summary>
        public static void AddIntegrityProtection(string filePath)
        {
            try
            {
                if (!File.Exists(filePath))
                    return;

                // Calculate file hash
                string fileHash = CalculateFileChecksum(filePath);
                
                // Create integrity data
                string integrityData = $"{_integrityMarker}:{fileHash}:{DateTime.UtcNow.Ticks}";
                byte[] integrityBytes = Encoding.UTF8.GetBytes(integrityData);
                
                // Append integrity data to file
                using (var fs = new FileStream(filePath, FileMode.Append, FileAccess.Write))
                {
                    fs.Write(integrityBytes, 0, integrityBytes.Length);
                }
            }
            catch
            {
                // Silently fail to avoid revealing tamper detection
            }
        }

        /// <summary>
        /// Detects if the application is running in a debugger
        /// </summary>
        public static bool IsDebuggerPresent()
        {
            try
            {
                // Check for debugger using multiple methods
                if (Debugger.IsAttached)
                    return true;

                if (IsDebuggerPresentAPI())
                    return true;

                // Check for common debugging tools
                if (IsCommonDebuggerRunning())
                    return true;

                return false;
            }
            catch
            {
                return true; // Assume debugger present if we can't check
            }
        }

        /// <summary>
        /// Detects if the application is running in a virtual machine
        /// </summary>
        public static bool IsVirtualMachine()
        {
            try
            {
                // Check for VM-specific registry keys
                if (CheckVMRegistryKeys())
                    return true;

                // Check for VM-specific processes
                if (CheckVMProcesses())
                    return true;

                // Check for VM-specific hardware
                if (CheckVMHardware())
                    return true;

                return false;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Performs comprehensive tamper detection
        /// </summary>
        public static TamperDetectionResult PerformTamperDetection()
        {
            var result = new TamperDetectionResult();

            try
            {
                // Check executable integrity
                result.ExecutableTampered = !VerifyExecutableIntegrity();
                
                // Check for debugger
                result.DebuggerDetected = IsDebuggerPresent();
                
                // Check for virtual machine
                result.VirtualMachineDetected = IsVirtualMachine();
                
                // Check for common analysis tools
                result.AnalysisToolsDetected = IsAnalysisToolRunning();
                
                // Check memory integrity
                result.MemoryTampered = IsMemoryTampered();
                
                // Overall tamper status
                result.IsTampered = result.ExecutableTampered || 
                                  result.DebuggerDetected || 
                                  result.AnalysisToolsDetected || 
                                  result.MemoryTampered;

                return result;
            }
            catch
            {
                result.IsTampered = true;
                result.ErrorOccurred = true;
                return result;
            }
        }

        /// <summary>
        /// Handles tamper detection response
        /// </summary>
        public static void HandleTamperDetection(TamperDetectionResult result)
        {
            if (result.IsTampered)
            {
                // Log tamper detection (in production, send to secure logging service)
                LogTamperDetection(result);
                
                // Perform anti-tamper actions
                PerformAntiTamperActions(result);
            }
        }

        #region Private Methods

        private static byte[] CalculateFileHash(string filePath)
        {
            using (var sha256 = SHA256.Create())
            using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
            {
                return sha256.ComputeHash(fs);
            }
        }

        private static string CalculateFileChecksum(string filePath)
        {
            using (var sha256 = SHA256.Create())
            using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
            {
                byte[] hash = sha256.ComputeHash(fs);
                return Convert.ToHexString(hash);
            }
        }

        private static bool CompareHashes(byte[] hash1, byte[] hash2)
        {
            if (hash1.Length != hash2.Length)
                return false;

            for (int i = 0; i < hash1.Length; i++)
            {
                if (hash1[i] != hash2[i])
                    return false;
            }

            return true;
        }

        private static bool HasIntegrityMarker(string filePath)
        {
            try
            {
                using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
                {
                    fs.Seek(-1024, SeekOrigin.End); // Check last 1KB
                    byte[] buffer = new byte[1024];
                    int bytesRead = fs.Read(buffer, 0, buffer.Length);
                    
                    string content = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                    return content.Contains(_integrityMarker);
                }
            }
            catch
            {
                return false;
            }
        }

        private static bool VerifyIntegrityMarker(string filePath)
        {
            try
            {
                using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
                {
                    fs.Seek(-1024, SeekOrigin.End);
                    byte[] buffer = new byte[1024];
                    int bytesRead = fs.Read(buffer, 0, buffer.Length);
                    
                    string content = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                    
                    if (content.Contains(_integrityMarker))
                    {
                        // Extract and verify hash
                        int markerIndex = content.IndexOf(_integrityMarker);
                        string integrityData = content.Substring(markerIndex);
                        string[] parts = integrityData.Split(':');
                        
                        if (parts.Length >= 3)
                        {
                            string storedHash = parts[1];
                            
                            // Calculate current file hash (excluding integrity marker)
                            fs.Seek(0, SeekOrigin.Begin);
                            byte[] fileData = new byte[fs.Length - (bytesRead - markerIndex)];
                            fs.Read(fileData, 0, fileData.Length);
                            
                            string currentHash = Convert.ToHexString(SHA256.Create().ComputeHash(fileData));
                            return string.Equals(currentHash, storedHash, StringComparison.OrdinalIgnoreCase);
                        }
                    }
                }
            }
            catch
            {
                return false;
            }

            return false;
        }


        [DllImport("kernel32.dll")]
        private static extern bool IsDebuggerPresentNative();

        private static bool IsDebuggerPresentAPI()
        {
            try
            {
                return IsDebuggerPresentNative();
            }
            catch
            {
                return false;
            }
        }

        private static bool IsCommonDebuggerRunning()
        {
            try
            {
                string[] debuggerProcesses = {
                    "ollydbg", "x64dbg", "windbg", "idaq", "idaq64",
                    "wireshark", "fiddler", "procmon", "regmon",
                    "cheatengine", "artmoney", "tsearch", "gameguardian"
                };

                Process[] processes = Process.GetProcesses();
                foreach (Process process in processes)
                {
                    try
                    {
                        string processName = process.ProcessName.ToLower();
                        foreach (string debugger in debuggerProcesses)
                        {
                            if (processName.Contains(debugger))
                                return true;
                        }
                    }
                    catch
                    {
                        // Ignore access denied errors
                    }
                }

                return false;
            }
            catch
            {
                return false;
            }
        }

        private static bool CheckVMRegistryKeys()
        {
            try
            {
                // Check for common VM registry keys
                string[] vmKeys = {
                    @"HKEY_LOCAL_MACHINE\SOFTWARE\VMware, Inc.\VMware Tools",
                    @"HKEY_LOCAL_MACHINE\SOFTWARE\Oracle\VirtualBox Guest Additions",
                    @"HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\VBoxService",
                    @"HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\VMTools"
                };

                foreach (string key in vmKeys)
                {
                    try
                    {
                        var regKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(key.Replace(@"HKEY_LOCAL_MACHINE\", ""));
                        if (regKey != null)
                        {
                            regKey.Close();
                            return true;
                        }
                    }
                    catch
                    {
                        // Ignore registry access errors
                    }
                }

                return false;
            }
            catch
            {
                return false;
            }
        }

        private static bool CheckVMProcesses()
        {
            try
            {
                string[] vmProcesses = {
                    "vmtoolsd", "vboxservice", "vboxtray", "vmwaretray",
                    "vmwareuser", "vmsrvc", "vmusrvc", "prl_cc", "prl_tools"
                };

                Process[] processes = Process.GetProcesses();
                foreach (Process process in processes)
                {
                    try
                    {
                        string processName = process.ProcessName.ToLower();
                        foreach (string vmProcess in vmProcesses)
                        {
                            if (processName.Contains(vmProcess))
                                return true;
                        }
                    }
                    catch
                    {
                        // Ignore access denied errors
                    }
                }

                return false;
            }
            catch
            {
                return false;
            }
        }

        private static bool CheckVMHardware()
        {
            try
            {
                // Check for VM-specific hardware identifiers
                string[] vmHardware = {
                    "VMware", "VirtualBox", "QEMU", "Xen", "Microsoft Corporation",
                    "innotek GmbH", "Parallels", "Red Hat", "KVM"
                };

                // Check BIOS information
                try
                {
                    string biosInfo = GetWmiProperty("Win32_BIOS", "Manufacturer");
                    foreach (string vm in vmHardware)
                    {
                        if (biosInfo.Contains(vm))
                            return true;
                    }
                }
                catch { }

                // Check system manufacturer
                try
                {
                    string systemInfo = GetWmiProperty("Win32_ComputerSystem", "Manufacturer");
                    foreach (string vm in vmHardware)
                    {
                        if (systemInfo.Contains(vm))
                            return true;
                    }
                }
                catch { }

                return false;
            }
            catch
            {
                return false;
            }
        }

        private static string GetWmiProperty(string className, string propertyName)
        {
            // WMI functionality disabled - requires System.Management reference
            return "";
        }

        private static bool IsAnalysisToolRunning()
        {
            try
            {
                string[] analysisTools = {
                    "procmon", "regmon", "filemon", "wireshark", "fiddler",
                    "charles", "burpsuite", "metasploit", "nmap", "zenmap",
                    "wireshark", "tcpdump", "netstat", "netmon", "ethereal"
                };

                Process[] processes = Process.GetProcesses();
                foreach (Process process in processes)
                {
                    try
                    {
                        string processName = process.ProcessName.ToLower();
                        foreach (string tool in analysisTools)
                        {
                            if (processName.Contains(tool))
                                return true;
                        }
                    }
                    catch
                    {
                        // Ignore access denied errors
                    }
                }

                return false;
            }
            catch
            {
                return false;
            }
        }

        private static bool IsMemoryTampered()
        {
            try
            {
                // Check for memory patching by comparing critical sections
                // This is a simplified check - in production, you'd implement more sophisticated checks
                
                // Check if critical methods have been modified
                var method = typeof(TamperDetection).GetMethod(nameof(VerifyExecutableIntegrity), BindingFlags.Public | BindingFlags.Static);
                if (method != null)
                {
                    // Get method body hash and compare with expected
                    // This is a placeholder - actual implementation would be more complex
                    return false;
                }

                return false;
            }
            catch
            {
                return true; // Assume tampered if we can't check
            }
        }

        private static void LogTamperDetection(TamperDetectionResult result)
        {
            try
            {
                string logMessage = $"[{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}] TAMPER DETECTED - " +
                                  $"Executable: {result.ExecutableTampered}, " +
                                  $"Debugger: {result.DebuggerDetected}, " +
                                  $"VM: {result.VirtualMachineDetected}, " +
                                  $"Analysis: {result.AnalysisToolsDetected}, " +
                                  $"Memory: {result.MemoryTampered}";

                // In production, send to secure logging service
                // For now, we'll just write to a secure location
                string logPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), 
                                            "RawrZ", "security.log");
                
                Directory.CreateDirectory(Path.GetDirectoryName(logPath));
                File.AppendAllText(logPath, logMessage + Environment.NewLine);
            }
            catch
            {
                // Silently fail to avoid revealing tamper detection
            }
        }

        private static void PerformAntiTamperActions(TamperDetectionResult result)
        {
            try
            {
                // Perform various anti-tamper actions based on the type of tampering detected
                
                if (result.DebuggerDetected)
                {
                    // Exit immediately if debugger detected
                    Environment.Exit(0);
                }
                
                if (result.ExecutableTampered)
                {
                    // Corrupt critical data and exit
                    CorruptCriticalData();
                    Environment.Exit(0);
                }
                
                if (result.AnalysisToolsDetected)
                {
                    // Delay execution and add noise
                    System.Threading.Thread.Sleep(new Random().Next(5000, 15000));
                }
                
                if (result.VirtualMachineDetected)
                {
                    // Reduce functionality in VM environment
                    // This could be implemented by setting a flag that limits features
                }
            }
            catch
            {
                // Silently fail
            }
        }

        private static void CorruptCriticalData()
        {
            try
            {
                // Overwrite sensitive data in memory
                // This is a placeholder - actual implementation would be more sophisticated
                GC.Collect();
                GC.WaitForPendingFinalizers();
                GC.Collect();
            }
            catch
            {
                // Silently fail
            }
        }

        #endregion
    }

    public class TamperDetectionResult
    {
        public bool IsTampered { get; set; }
        public bool ExecutableTampered { get; set; }
        public bool DebuggerDetected { get; set; }
        public bool VirtualMachineDetected { get; set; }
        public bool AnalysisToolsDetected { get; set; }
        public bool MemoryTampered { get; set; }
        public bool ErrorOccurred { get; set; }
        public DateTime DetectionTime { get; set; } = DateTime.UtcNow;
    }
}
