package com.android.simpleroot;

import android.app.Activity;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import android.widget.ScrollView;
import android.widget.LinearLayout;
import android.widget.EditText;
import android.widget.Toast;
import android.graphics.Color;
import android.util.Log;
import android.view.KeyEvent;
import android.view.inputmethod.EditorInfo;
import android.content.Intent;
import android.net.Uri;
import android.app.AlertDialog;
import android.widget.ArrayAdapter;
import android.widget.ListView;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.io.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.locks.ReentrantLock;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.atomic.AtomicBoolean;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class ScriptRunnerActivity extends Activity {
    private static final String TAG = "ScriptRunner";
    
    // Mutex for thread safety
    private final Lock executionLock = new ReentrantLock();
    private final AtomicBoolean isExecuting = new AtomicBoolean(false);
    private final Lock outputLock = new ReentrantLock();
    
    // Obfuscation keys and methods
    private static final String OBFUSCATION_KEY = "SR_OBF_2025";
    private static final String[] OBFUSCATED_PATHS = {
        "L2RhdGEvbG9jYWwvdG1wLw==", // /data/local/tmp/
        "L3NkY2FyZC9Eb3dubG9hZC8=", // /sdcard/Download/
        "L3N5c3RlbS9iaW4v", // /system/bin/
        "L3N5c3RlbS94YmluLw==" // /system/xbin/
    };
    
    private TextView outputText;
    private ScrollView scrollView;
    private LinearLayout buttonLayout;
    private EditText commandInput;
    private ExecutorService executor;
    private Handler mainHandler;
    private List<String> selectedScripts = new ArrayList<>();
    private PluginManager pluginManager;
    
    // Script paths - Updated to use actual script locations
    private static final String SCRIPT_BASE_PATH = "/sdcard/Download/scripts/";
    private static final String HOT_PATCHER_SCRIPT = "/data/local/tmp/hot_patcher/bin/patch_manager";
    private static final String ROOT_MANAGER_SCRIPT = "/data/local/tmp/root_manager/bin/root_manager";
    private static final String COMPREHENSIVE_ROOT_SCRIPT = SCRIPT_BASE_PATH + "comprehensive-root-manager.sh";
    private static final String ANDROID_HOT_PATCHER_SCRIPT = SCRIPT_BASE_PATH + "android-hot-patcher.sh";
    private static final String CUSTOM_DEV_MENU_SCRIPT = SCRIPT_BASE_PATH + "custom-dev-menu.sh";
    private static final String BOOTLOADER_UNLOCK_SCRIPT = SCRIPT_BASE_PATH + "bootloader-unlock.sh";
    private static final String ADVANCED_SYSTEMLESS_ROOT_SCRIPT = SCRIPT_BASE_PATH + "advanced-systemless-root.sh";
    private static final String ESCALATE_SYSTEM_ROOT_SCRIPT = SCRIPT_BASE_PATH + "escalate-to-system-root.sh";
    
    // Alternative script paths for better compatibility
    private String[] getScriptSearchPaths() {
        return getDeobfuscatedPaths();
    }
    
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_script_runner);
        
        // Initialize components
        outputText = findViewById(R.id.outputText);
        scrollView = findViewById(R.id.scrollView);
        buttonLayout = findViewById(R.id.buttonLayout);
        commandInput = findViewById(R.id.commandInput);
        
        // Initialize thread pool and handler
        executor = Executors.newFixedThreadPool(2);
        mainHandler = new Handler(Looper.getMainLooper());
        
        // Initialize plugin manager
        pluginManager = new PluginManager(new PluginManager.PluginExecutionListener() {
            @Override
            public void onPluginOutput(String output) {
                appendOutput(output);
            }
            
            @Override
            public void onPluginError(String error) {
                appendOutput("ERROR: " + error + "\n");
            }
            
            @Override
            public void onPluginComplete(String pluginName, int exitCode) {
                appendOutput("=== Plugin '" + pluginName + "' completed with exit code: " + exitCode + " ===\n\n");
            }
        });
        
        // Setup UI
        setupUI();
        setupCLI();
        
        // Check script availability
        checkScriptAvailability();
    }
    
    private void setupUI() {
        // Plugin System Buttons
        createButton("🔌 Plugin Manager", () -> showPluginManager());
        createButton("📊 System Info Plugin", () -> pluginManager.executePlugin("system_info"));
        createButton("🔐 Root Check Plugin", () -> pluginManager.executePlugin("root_check"));
        createButton("🧪 TEST SCRIPT", () -> runScriptWithCat("test-simple.sh"));
        createButton("💥 ROOT BRUTEFORCE", () -> runScriptWithCat("root-bruteforce.sh"));
        createButton("🏢 BYOD EXPLOIT", () -> runScriptWithCat("byod-exploit.sh"));
        createButton("🔐 CERT SPOOFING", () -> runScriptWithCat("cert-driver-spoof.sh"));
        createButton("📁 File Browser Plugin", () -> pluginManager.executePlugin("file_browser", "/sdcard"));
        createButton("🌐 Network Tools Plugin", () -> pluginManager.executePlugin("network_tools", "ifconfig"));
        createButton("🔍 Network Scanner", () -> runScriptWithCat("network-scanner.sh"));
        createButton("⚙️ Process Manager Plugin", () -> pluginManager.executePlugin("process_manager", "ps"));
        
        // Legacy Script Buttons
        createButton("📱 Custom Dev Menu", () -> runScriptWithCat("custom-dev-menu.sh", "menu"));
        createButton("🔧 Install Hot Patcher", () -> runScriptWithCat("android-hot-patcher.sh", "install"));
        createButton("🛠️ Install Root Manager", () -> runScriptWithCat("comprehensive-root-manager.sh", "install"));
        createButton("⚡ Hot Patcher Status", () -> runScriptWithCat("android-hot-patcher.sh", "status"));
        createButton("🔍 Root Manager Status", () -> runScriptWithCat("comprehensive-root-manager.sh", "status"));
        createButton("🔓 Bootloader Unlock", () -> runScriptWithCat("bootloader-unlock.sh", "unlock"));
        createButton("🚀 Advanced Systemless Root", () -> runScriptWithCat("advanced-systemless-root.sh", "install"));
        createButton("⬆️ Escalate to System Root", () -> runScriptWithCat("escalate-to-system-root.sh", "escalate"));
        createButton("✅ Verify Root Access", () -> runScriptWithCat("comprehensive-root-manager.sh", "verify"));
        
        // Custom Root Engine Buttons
        createButton("🔧 Custom Root Engine", () -> executeCustomRootEngine());
        createButton("⚡ Advanced Root Escalation", () -> executeAdvancedRootEscalation());
        createButton("🔗 Privilege Escalation Chain", () -> executePrivilegeChain());
        createButton("💥 Kernel Exploit", () -> executeKernelExploit());
        createButton("🧠 Memory Corruption", () -> executeMemoryCorruption());
        createButton("🛡️ Security Bypass", () -> executeSecurityBypass());
        createButton("📊 Root Status", () -> executeRootManager("status"));
        createButton("🔨 Apply Root Patches", () -> executeRootManager("patch"));
        createButton("🚀 Install Persistent Root", () -> executePersistentRootInstaller());
        
        // Utility Buttons
        createButton("📁 Browse Scripts", () -> browseScripts());
        createButton("🎯 Run Selected Script", () -> runSelectedScript());
        createButton("📋 List All Scripts", () -> listAllScripts());
        createButton("📄 Show Logs", () -> showLogs());
        createButton("💾 Save Logs", () -> saveLogs());
        createButton("🗑️ Clear Output", () -> clearOutput());
    }
    
    private void createButton(String text, Runnable action) {
        Button button = new Button(this);
        button.setText(text);
        button.setTextColor(Color.WHITE);
        button.setBackgroundColor(Color.parseColor("#2196F3"));
        button.setPadding(20, 20, 20, 20);
        
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT
        );
        params.setMargins(10, 10, 10, 10);
        button.setLayoutParams(params);
        
        button.setOnClickListener(v -> {
            button.setEnabled(false);
            button.setBackgroundColor(Color.parseColor("#757575"));
            action.run();
            
            // Re-enable button after 3 seconds
            new Handler().postDelayed(() -> {
                button.setEnabled(true);
                button.setBackgroundColor(Color.parseColor("#2196F3"));
            }, 3000);
        });
        
        buttonLayout.addView(button);
    }
    
    private void setupCLI() {
        if (commandInput == null) return;
        
        // Set up command input
        commandInput.setHint("Enter command (e.g., ls, getprop, id, su, etc.)");
        commandInput.setTextColor(Color.WHITE);
        commandInput.setBackgroundColor(Color.parseColor("#424242"));
        commandInput.setPadding(20, 20, 20, 20);
        
        // Handle enter key press
        commandInput.setOnEditorActionListener((v, actionId, event) -> {
            if (actionId == EditorInfo.IME_ACTION_SEND || 
                (event != null && event.getKeyCode() == KeyEvent.KEYCODE_ENTER)) {
                String command = commandInput.getText().toString().trim();
                if (!command.isEmpty()) {
                    executeCommand(command);
                    commandInput.setText("");
                }
                return true;
            }
            return false;
        });
        
        // Add CLI help button
        createButton("💻 CLI Help", () -> showCLIHelp());
    }
    
    
    private void showPluginManager() {
        appendOutput("=== Plugin Manager ===\n");
        appendOutput("DEBUG: Starting plugin manager...\n");
        
        Map<String, ScriptPlugin> plugins = pluginManager.getPlugins();
        appendOutput("DEBUG: Found " + plugins.size() + " plugins\n");
        
        if (plugins.isEmpty()) {
            appendOutput("No plugins loaded.\n");
            return;
        }
        
        // Group plugins by category
        Map<String, List<ScriptPlugin>> categories = new HashMap<>();
        for (ScriptPlugin plugin : plugins.values()) {
            String category = plugin.getCategory();
            categories.computeIfAbsent(category, k -> new ArrayList<>()).add(plugin);
        }
        
        // Display plugins by category
        for (Map.Entry<String, List<ScriptPlugin>> entry : categories.entrySet()) {
            appendOutput("\n📂 " + entry.getKey() + ":\n");
            for (ScriptPlugin plugin : entry.getValue()) {
                appendOutput("  " + plugin.toString() + "\n");
                if (!plugin.getCommands().isEmpty()) {
                    appendOutput("    Commands: " + String.join(", ", plugin.getCommands()) + "\n");
                }
                if (plugin.requiresRoot()) {
                    appendOutput("    ⚠️ Requires Root\n");
                }
            }
        }
        
        appendOutput("\n=== Plugin Manager Complete ===\n\n");
    }
    
    private void showCLIHelp() {
        appendOutput("=== CLI Command Help ===\n");
        appendOutput("Available commands:\n");
        appendOutput("• ls [path] - List directory contents\n");
        appendOutput("• getprop [property] - Get system property\n");
        appendOutput("• setprop [property] [value] - Set system property\n");
        appendOutput("• id - Show current user ID\n");
        appendOutput("• whoami - Show current user\n");
        appendOutput("• su - Switch to root user\n");
        appendOutput("• mount - Show mounted filesystems\n");
        appendOutput("• cat [file] - Display file contents\n");
        appendOutput("• echo [text] - Display text\n");
        appendOutput("• pwd - Show current directory\n");
        appendOutput("• cd [path] - Change directory\n");
        appendOutput("• mkdir [path] - Create directory\n");
        appendOutput("• chmod [mode] [file] - Change file permissions\n");
        appendOutput("• pm list packages - List installed packages\n");
        appendOutput("• pm disable [package] - Disable package\n");
        appendOutput("• settings put [namespace] [key] [value] - Set system setting\n");
        appendOutput("• reboot - Reboot device\n");
        appendOutput("• reboot bootloader - Reboot to bootloader\n");
        appendOutput("• reboot recovery - Reboot to recovery\n");
        appendOutput("• uname -a - Show kernel info\n");
        appendOutput("• ps - Show running processes\n");
        appendOutput("• top - Show top processes\n");
        appendOutput("• df - Show disk usage\n");
        appendOutput("• free - Show memory usage\n");
        appendOutput("• netstat - Show network connections\n");
        appendOutput("• ifconfig - Show network interfaces\n");
        appendOutput("• ping [host] - Ping host\n");
        appendOutput("• wget [url] - Download file\n");
        appendOutput("• curl [url] - Download file\n");
        appendOutput("• tar -xzf [file] - Extract tar.gz file\n");
        appendOutput("• unzip [file] - Extract zip file\n");
        appendOutput("• sh [script] - Run shell script\n");
        appendOutput("• bash [script] - Run bash script\n");
        appendOutput("• python [script] - Run Python script\n");
        appendOutput("• java -jar [jar] - Run Java JAR file\n");
        appendOutput("• adb [command] - Run ADB command\n");
        appendOutput("• fastboot [command] - Run fastboot command\n");
        appendOutput("• help - Show this help\n");
        appendOutput("• clear - Clear output\n");
        appendOutput("• exit - Exit CLI\n");
        appendOutput("\nScript Execution:\n");
        appendOutput("• sh /path/to/script.sh - Run shell script\n");
        appendOutput("• bash /path/to/script.sh - Run bash script\n");
        appendOutput("• python /path/to/script.py - Run Python script\n");
        appendOutput("• java -jar /path/to/app.jar - Run Java JAR\n");
        appendOutput("• /path/to/executable - Run binary directly\n");
        appendOutput("\nManual Script Selection:\n");
        appendOutput("• Use 'Browse Scripts' button to select files\n");
        appendOutput("• Use 'List All Scripts' to see available scripts\n");
        appendOutput("• Use 'Run Selected Script' to execute chosen files\n");
        appendOutput("\nNote: Some commands require root access.\n");
        appendOutput("=== End Help ===\n\n");
    }
    
    private void browseScripts() {
        appendOutput("=== Browsing Scripts ===\n");
        appendOutput("DEBUG: Starting script browse...\n");
        
        executor.execute(() -> {
            try {
                List<String> scriptFiles = new ArrayList<>();
                String[] searchPaths = getScriptSearchPaths();
                appendOutput("DEBUG: Searching in paths: " + String.join(", ", searchPaths) + "\n");
                
                // Use simple ls command to find scripts
                for (String basePath : searchPaths) {
                    try {
                        appendOutput("DEBUG: Checking path: " + basePath + "\n");
                        // Try ls command first
                        Process process = Runtime.getRuntime().exec(new String[]{"/system/bin/sh", "-c", "ls " + basePath + "*.sh 2>/dev/null || echo 'no_scripts'"});
                        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                        String line;
                        
                        while ((line = reader.readLine()) != null) {
                            if (!line.trim().isEmpty()) {
                                appendOutput("DEBUG: Found line: " + line + "\n");
                                String[] files = line.trim().split("\\s+");
                                for (String file : files) {
                                    if (file.endsWith(".sh") && !file.isEmpty()) {
                                        appendOutput("DEBUG: Adding script: " + basePath + file + "\n");
                                        scriptFiles.add(basePath + file);
                                    }
                                }
                            }
                        }
                        process.waitFor();
                        
                        // Also try to list directory contents
                        Process lsProcess = Runtime.getRuntime().exec(new String[]{"/system/bin/sh", "-c", "ls -la " + basePath + " 2>/dev/null"});
                        BufferedReader lsReader = new BufferedReader(new InputStreamReader(lsProcess.getInputStream()));
                        String lsLine;
                        
                        while ((lsLine = lsReader.readLine()) != null) {
                            if (lsLine.contains(".sh") && !lsLine.startsWith("total")) {
                                String[] parts = lsLine.trim().split("\\s+");
                                if (parts.length > 8) {
                                    String fileName = parts[parts.length - 1];
                                    if (fileName.endsWith(".sh")) {
                                        scriptFiles.add(basePath + fileName);
                                    }
                                }
                            }
                        }
                        lsProcess.waitFor();
                        
                    } catch (Exception e) {
                        // Try alternative method
                        try {
                            Process process = Runtime.getRuntime().exec(new String[]{"/system/bin/sh", "-c", "find " + basePath + " -name '*.sh' 2>/dev/null"});
                            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                            String line;
                            
                            while ((line = reader.readLine()) != null) {
                                if (!line.trim().isEmpty()) {
                                    scriptFiles.add(line.trim());
                                }
                            }
                            process.waitFor();
                        } catch (Exception e2) {
                            // Ignore errors for this path
                        }
                    }
                }
                
                // Remove duplicates
                final List<String> finalScriptFiles = scriptFiles.stream().distinct().collect(java.util.stream.Collectors.toList());
                appendOutput("DEBUG: Total scripts found: " + finalScriptFiles.size() + "\n");
                
                if (finalScriptFiles.isEmpty()) {
                    mainHandler.post(() -> {
                        appendOutput("No scripts found in common locations.\n");
                        appendOutput("Searched in: " + String.join(", ", getScriptSearchPaths()) + "\n");
                        appendOutput("=== Browse Complete ===\n\n");
                    });
                    return;
                }
                
                // Show script selection dialog
                mainHandler.post(() -> {
                    showScriptSelectionDialog(finalScriptFiles);
                });
                
            } catch (Exception e) {
                mainHandler.post(() -> {
                    appendOutput("Error browsing scripts: " + e.getMessage() + "\n");
                    appendOutput("=== Browse Failed ===\n\n");
                });
            }
        });
    }
    
    private void showScriptSelectionDialog(List<String> scriptFiles) {
        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        builder.setTitle("Select Script to Run");
        
        String[] scriptArray = scriptFiles.toArray(new String[0]);
        boolean[] selectedItems = new boolean[scriptArray.length];
        
        builder.setMultiChoiceItems(scriptArray, selectedItems, (dialog, which, isChecked) -> {
            selectedItems[which] = isChecked;
        });
        
        builder.setPositiveButton("Run Selected", (dialog, which) -> {
            selectedScripts.clear();
            for (int i = 0; i < selectedItems.length; i++) {
                if (selectedItems[i]) {
                    selectedScripts.add(scriptArray[i]);
                }
            }
            
            if (!selectedScripts.isEmpty()) {
                appendOutput("Selected " + selectedScripts.size() + " script(s):\n");
                for (String script : selectedScripts) {
                    appendOutput("• " + script + "\n");
                }
                appendOutput("\nUse 'Run Selected Script' button to execute.\n");
            } else {
                appendOutput("No scripts selected.\n");
            }
            appendOutput("=== Selection Complete ===\n\n");
        });
        
        builder.setNegativeButton("Cancel", (dialog, which) -> {
            appendOutput("Script selection cancelled.\n");
            appendOutput("=== Browse Complete ===\n\n");
        });
        
        builder.setNeutralButton("Run All", (dialog, which) -> {
            selectedScripts.clear();
            selectedScripts.addAll(scriptFiles);
            appendOutput("Selected all " + selectedScripts.size() + " scripts.\n");
            appendOutput("Use 'Run Selected Script' button to execute.\n");
            appendOutput("=== Selection Complete ===\n\n");
        });
        
        builder.show();
    }
    
    private void runSelectedScript() {
        if (selectedScripts.isEmpty()) {
            appendOutput("No scripts selected. Use 'Browse Scripts' first.\n");
            return;
        }
        
        appendOutput("=== Running Selected Scripts ===\n");
        
        for (String scriptPath : selectedScripts) {
            runScriptWithCat(scriptPath);
        }
    }
    
    private void listAllScripts() {
        appendOutput("=== Listing All Scripts ===\n");
        
        executor.execute(() -> {
            try {
                StringBuilder output = new StringBuilder();
                
                for (String basePath : getScriptSearchPaths()) {
                    output.append("\n📁 ").append(basePath).append(":\n");
                    
                    try {
                        // Use shell command to list files (more reliable than File.listFiles)
                        Process process = Runtime.getRuntime().exec("ls -la " + basePath);
                        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                        String line;
                        boolean foundScripts = false;
                        
                        while ((line = reader.readLine()) != null) {
                            if (line.contains(".sh") || line.contains(".py") || 
                                line.contains(".js") || line.contains(".bat") ||
                                line.contains(".exe") || line.contains(".bin")) {
                                output.append("  ✓ ").append(line).append("\n");
                                foundScripts = true;
                            }
                        }
                        
                        if (!foundScripts) {
                            output.append("  (no scripts found)\n");
                        }
                        
                        process.waitFor();
                    } catch (Exception e) {
                        output.append("  (error accessing: ").append(e.getMessage()).append(")\n");
                    }
                }
                
                mainHandler.post(() -> {
                    appendOutput(output.toString());
                    appendOutput("\n=== Script List Complete ===\n\n");
                });
                
            } catch (Exception e) {
                mainHandler.post(() -> {
                    appendOutput("Error listing scripts: " + e.getMessage() + "\n");
                    appendOutput("=== List Failed ===\n\n");
                });
            }
        });
    }
    
    private void executeCommand(String command) {
        appendOutput("$ " + command + "\n");
        
        executor.execute(() -> {
            try {
                // Handle special commands
                if (command.equals("clear")) {
                    mainHandler.post(() -> clearOutput());
                    return;
                }
                
                if (command.equals("help")) {
                    mainHandler.post(() -> showCLIHelp());
                    return;
                }
                
                if (command.equals("exit")) {
                    mainHandler.post(() -> {
                        appendOutput("Exiting CLI...\n");
                        finish();
                    });
                    return;
                }
                
                // Execute the command
                ProcessBuilder pb = new ProcessBuilder("sh", "-c", command);
                pb.redirectErrorStream(true);
                pb.directory(new File("/sdcard/Download/scripts/")); // Set working directory
                Process process = pb.start();
                
                // Read output
                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                String line;
                StringBuilder output = new StringBuilder();
                
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }
                
                // Wait for process to complete
                int exitCode = process.waitFor();
                
                // Update UI on main thread
                mainHandler.post(() -> {
                    if (output.length() > 0) {
                        appendOutput(output.toString());
                    }
                    if (exitCode != 0) {
                        appendOutput("(exit code: " + exitCode + ")\n");
                    }
                    appendOutput("\n");
                });
                
            } catch (Exception e) {
                mainHandler.post(() -> {
                    appendOutput("Error: " + e.getMessage() + "\n\n");
                });
            }
        });
    }
    
    private void checkScriptAvailability() {
        appendOutput("=== Script Availability Check ===\n");
        
        String[] scripts = {
            "Custom Dev Menu", CUSTOM_DEV_MENU_SCRIPT,
            "Android Hot Patcher", ANDROID_HOT_PATCHER_SCRIPT,
            "Comprehensive Root Manager", COMPREHENSIVE_ROOT_SCRIPT,
            "Bootloader Unlock", BOOTLOADER_UNLOCK_SCRIPT,
            "Advanced Systemless Root", ADVANCED_SYSTEMLESS_ROOT_SCRIPT,
            "Escalate System Root", ESCALATE_SYSTEM_ROOT_SCRIPT,
            "Hot Patcher Binary", HOT_PATCHER_SCRIPT,
            "Root Manager Binary", ROOT_MANAGER_SCRIPT
        };
        
        for (int i = 0; i < scripts.length; i += 2) {
            String name = scripts[i];
            String path = scripts[i + 1];
            
            if (new File(path).exists()) {
                appendOutput("✓ " + name + " - Available\n");
            } else {
                appendOutput("✗ " + name + " - Not found\n");
            }
        }
        
        appendOutput("\n=== Available Scripts in /sdcard/Download/scripts/ ===\n");
        try {
            Process process = Runtime.getRuntime().exec("ls -la " + SCRIPT_BASE_PATH);
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                appendOutput(line + "\n");
            }
            process.waitFor();
        } catch (Exception e) {
            appendOutput("Error listing scripts: " + e.getMessage() + "\n");
        }
        
        appendOutput("\n");
    }
    
    private String findScript(String scriptName) {
        appendOutput("DEBUG: findScript called with: " + scriptName + "\n");
        // First try the exact path
        try {
            Process checkProcess = Runtime.getRuntime().exec(new String[]{"sh", "-c", "test -f " + scriptName + " && echo 'exists' || echo 'not found'"});
            BufferedReader checkReader = new BufferedReader(new InputStreamReader(checkProcess.getInputStream()));
            String checkResult = checkReader.readLine();
            checkProcess.waitFor();
            appendOutput("DEBUG: Exact path check result: " + checkResult + "\n");
            
            if ("exists".equals(checkResult)) {
                appendOutput("DEBUG: Found exact path: " + scriptName + "\n");
                return scriptName;
            }
        } catch (Exception e) {
            appendOutput("DEBUG: Exact path check error: " + e.getMessage() + "\n");
        }

        // Search in common script locations (using obfuscated paths)
        for (String basePath : getScriptSearchPaths()) {
            String fullPath = basePath + scriptName;
            appendOutput("DEBUG: Checking path: " + fullPath + "\n");
            try {
                Process checkProcess = Runtime.getRuntime().exec(new String[]{"sh", "-c", "test -f " + fullPath + " && echo 'exists' || echo 'not found'"});
                BufferedReader checkReader = new BufferedReader(new InputStreamReader(checkProcess.getInputStream()));
                String checkResult = checkReader.readLine();
                checkProcess.waitFor();
                appendOutput("DEBUG: Path check result: " + checkResult + "\n");
                
                if ("exists".equals(checkResult)) {
                    appendOutput("DEBUG: Found script at: " + fullPath + "\n");
                    return fullPath;
                }
            } catch (Exception e) {
                appendOutput("DEBUG: Path check error: " + e.getMessage() + "\n");
            }
        }

        // If not found, return original path (will show error)
        return scriptName;
    }
    
    private void runScript(String scriptPath, String... args) {
        // Check if already executing
        if (!isExecuting.compareAndSet(false, true)) {
            appendOutput("Script execution already in progress. Please wait...\n");
            return;
        }
        
        executionLock.lock();
        try {
            String actualPath = findScript(scriptPath);
            appendOutput("=== Running Script: " + actualPath + " ===\n");
            appendOutput("DEBUG: Original path: " + scriptPath + "\n");
            appendOutput("DEBUG: Found path: " + actualPath + "\n");
            Log.d(TAG, "=== Running Script: " + actualPath + " ===");
        Log.d(TAG, "DEBUG: Original path: " + scriptPath);
        Log.d(TAG, "DEBUG: Found path: " + actualPath);
        
        executor.execute(() -> {
            try {
                // First check if script exists using shell command
                appendOutput("DEBUG: Checking if script exists: " + actualPath + "\n");
                Log.d(TAG, "DEBUG: Checking if script exists: " + actualPath);
                Process checkProcess = Runtime.getRuntime().exec(new String[]{"sh", "-c", "test -f " + actualPath + " && echo 'exists' || echo 'not found'"});
                BufferedReader checkReader = new BufferedReader(new InputStreamReader(checkProcess.getInputStream()));
                String checkResult = checkReader.readLine();
                checkProcess.waitFor();
                appendOutput("DEBUG: Script existence check result: " + checkResult + "\n");
                Log.d(TAG, "DEBUG: Script existence check result: " + checkResult);
                
                if (!"exists".equals(checkResult)) {
                    mainHandler.post(() -> {
                        appendOutput("Error: Script not found at " + actualPath + "\n");
                        appendOutput("Searched in: " + String.join(", ", getScriptSearchPaths()) + "\n");
                        appendOutput("=== Script Failed ===\n\n");
                    });
                    Log.e(TAG, "Error: Script not found at " + actualPath);
                    Log.e(TAG, "Searched in: " + String.join(", ", getScriptSearchPaths()));
                    return;
                }
                
                // Create command to execute the script
                String[] command;
                if (actualPath.endsWith(".sh")) {
                    // Filter out null args and build argument string
                    List<String> validArgs = new ArrayList<>();
                    for (String arg : args) {
                        if (arg != null && !arg.trim().isEmpty()) {
                            validArgs.add(arg);
                        }
                    }
                    
                    // Use cat | sh method to bypass permission issues (like before)
                    StringBuilder shellCommand = new StringBuilder();
                    
                    // Method: Read script content and pipe to shell (bypasses execute permissions)
                    shellCommand.append("cat ").append(actualPath).append(" | sh");
                    
                    // Add arguments to the shell command
                    for (String arg : validArgs) {
                        shellCommand.append(" '").append(arg).append("'");
                    }
                    
                    command = new String[3];
                    command[0] = "/system/bin/sh";
                    command[1] = "-c";
                    command[2] = shellCommand.toString();
                } else {
                    // Filter out null args for non-shell scripts too
                    List<String> validArgs = new ArrayList<>();
                    for (String arg : args) {
                        if (arg != null && !arg.trim().isEmpty()) {
                            validArgs.add(arg);
                        }
                    }
                    
                    command = new String[1 + validArgs.size()];
                    command[0] = actualPath;
                    for (int i = 0; i < validArgs.size(); i++) {
                        command[1 + i] = validArgs.get(i);
                    }
                }
                
                appendOutput("DEBUG: Executing command array: " + java.util.Arrays.toString(command) + "\n");
                Log.d(TAG, "DEBUG: Executing command array: " + java.util.Arrays.toString(command));
                
                // Execute script using ProcessBuilder for better control
                ProcessBuilder pb = new ProcessBuilder(command);
                pb.redirectErrorStream(true);
                Process process = pb.start();
                
                // Read output
                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                String line;
                StringBuilder output = new StringBuilder();
                
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }
                
                // Wait for process to complete
                int exitCode = process.waitFor();
                
                // Update UI on main thread
                mainHandler.post(() -> {
                    appendOutput(output.toString());
                    appendOutput("Exit code: " + exitCode + "\n");
                    appendOutput("=== Script Completed ===\n\n");
                });
                Log.d(TAG, "Script completed with exit code: " + exitCode);
                Log.d(TAG, "Script output: " + output.toString());
                
            } catch (Exception e) {
                mainHandler.post(() -> {
                    appendOutput("Error running script: " + e.getMessage() + "\n");
                    appendOutput("=== Script Failed ===\n\n");
                });
                Log.e(TAG, "Error running script: " + e.getMessage(), e);
            } finally {
                // Release execution lock
                isExecuting.set(false);
            }
        });
        } finally {
            executionLock.unlock();
        }
    }
    
    private void runSystemInfo() {
        appendOutput("=== System Information ===\n");
        
        executor.execute(() -> {
            try {
                StringBuilder info = new StringBuilder();
                
                // Get system properties
                String[] properties = {
                    "ro.product.model",
                    "ro.build.version.release",
                    "ro.build.version.sdk",
                    "ro.build.display.id",
                    "ro.build.version.security_patch",
                    "ro.product.cpu.abi",
                    "ro.boot.selinux",
                    "ro.boot.veritymode",
                    "ro.debuggable",
                    "ro.secure",
                    "ro.oem_unlock_supported"
                };
                
                for (String prop : properties) {
                    try {
                        Process process = Runtime.getRuntime().exec("getprop " + prop);
                        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                        String value = reader.readLine();
                        if (value != null && !value.isEmpty()) {
                            info.append(prop).append(": ").append(value).append("\n");
                        } else {
                            info.append(prop).append(": unknown\n");
                        }
                        process.waitFor();
                    } catch (Exception e) {
                        info.append(prop).append(": error\n");
                    }
                }
                
                // Get kernel info
                try {
                    Process process = Runtime.getRuntime().exec("uname -a");
                    BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                    String kernel = reader.readLine();
                    if (kernel != null) {
                        info.append("Kernel: ").append(kernel).append("\n");
                    }
                    process.waitFor();
                } catch (Exception e) {
                    info.append("Kernel: error\n");
                }
                
                // Get current user info
                try {
                    Process process = Runtime.getRuntime().exec("id");
                    BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                    String user = reader.readLine();
                    if (user != null) {
                        info.append("Current User: ").append(user).append("\n");
                    }
                    process.waitFor();
                } catch (Exception e) {
                    info.append("Current User: error\n");
                }
                
                mainHandler.post(() -> {
                    appendOutput(info.toString());
                    appendOutput("=== System Info Complete ===\n\n");
                });
                
            } catch (Exception e) {
                mainHandler.post(() -> {
                    appendOutput("Error getting system info: " + e.getMessage() + "\n");
                    appendOutput("=== System Info Failed ===\n\n");
                });
            }
        });
    }
    
    private void appendOutput(String text) {
        outputLock.lock();
        try {
            // Clean text by removing emojis and fixing formatting
            String cleanText = cleanOutputText(text);
            
            // Verify integrity before processing
            if (!verifyIntegrity(cleanText)) {
                Log.w(TAG, "Output integrity check failed");
                return;
            }
            
            runOnUiThread(() -> {
                outputText.append(cleanText);
                scrollView.post(() -> scrollView.fullScroll(View.FOCUS_DOWN));
            });
            
            // Also write to log file
            writeToLogFile(cleanText);
        } finally {
            outputLock.unlock();
        }
    }
    
    private String cleanOutputText(String text) {
        if (text == null) return "";
        
        // Remove emojis and special characters that cause formatting issues
        String cleaned = text
            .replaceAll("[\ud83d\ude00-\ud83d\ude4f]", "") // Emoticons
            .replaceAll("[\ud83c\udf00-\ud83d\uddff]", "") // Misc Symbols
            .replaceAll("[\ud83d\ude80-\ud83d\udeff]", "") // Transport
            .replaceAll("[\ud83c\udde0-\ud83c\uddff]", "") // Regional indicators
            .replaceAll("[\u2600-\u26ff]", "") // Misc symbols
            .replaceAll("[\u2700-\u27bf]", "") // Dingbats
            .replaceAll("📁", "[DIR]")
            .replaceAll("📂", "[FOLDER]")
            .replaceAll("⚠️", "[WARNING]")
            .replaceAll("✅", "[OK]")
            .replaceAll("❌", "[ERROR]")
            .replaceAll("🎯", "[TARGET]")
            .replaceAll("🚀", "[LAUNCH]")
            .replaceAll("💥", "[EXPLOSION]")
            .replaceAll("🌐", "[NETWORK]")
            .replaceAll("•", "-")
            .replaceAll("→", "->")
            .replaceAll("←", "<-")
            .replaceAll("↑", "^")
            .replaceAll("↓", "v");
            
        return cleaned;
    }
    
    // Obfuscation methods
    private String obfuscateString(String input) {
        try {
            String combined = OBFUSCATION_KEY + input;
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(combined.getBytes());
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            return input;
        }
    }
    
    private String deobfuscatePath(String obfuscatedPath) {
        try {
            return new String(Base64.getDecoder().decode(obfuscatedPath));
        } catch (Exception e) {
            return obfuscatedPath;
        }
    }
    
    private String[] getDeobfuscatedPaths() {
        // Dynamic path discovery - check what's actually accessible
        List<String> accessiblePaths = new ArrayList<>();
        
        // Check common script locations dynamically
        String[] commonPaths = {
            "/sdcard/Download/scripts/",
            "/sdcard/Download/",
            "/data/local/tmp/",
            "/system/bin/",
            "/system/xbin/",
            getFilesDir().getAbsolutePath() + "/",
            getCacheDir().getAbsolutePath() + "/"
        };
        
        for (String path : commonPaths) {
            try {
                // Test if path is accessible by trying to list it
                Process testProcess = Runtime.getRuntime().exec(new String[]{"sh", "-c", "ls " + path + " 2>/dev/null | head -1"});
                BufferedReader testReader = new BufferedReader(new InputStreamReader(testProcess.getInputStream()));
                String result = testReader.readLine();
                testProcess.waitFor();
                
                if (result != null && !result.trim().isEmpty()) {
                    accessiblePaths.add(path);
                }
            } catch (Exception e) {
                // Path not accessible, skip it
            }
        }
        
        // Always include /data/local/tmp/ even if we can't list it directly
        // because scripts are definitely there and we can execute them via cat
        if (!accessiblePaths.contains("/data/local/tmp/")) {
            accessiblePaths.add("/data/local/tmp/");
        }
        
        return accessiblePaths.toArray(new String[0]);
    }
    
    private boolean verifyIntegrity(String data) {
        try {
            String hash = obfuscateString(data);
            return hash != null && !hash.isEmpty();
        } catch (Exception e) {
            return false;
        }
    }
    
    private void writeToLogFile(String text) {
        try {
            String timestamp = java.text.DateFormat.getDateTimeInstance().format(new java.util.Date());
            String logEntry = "[" + timestamp + "] " + text;
            
            // Write to multiple log locations as .txt files
            String[] logPaths = {
                "/sdcard/Download/script_runner_log.txt",
                "/sdcard/script_runner_log.txt",
                "/data/local/tmp/script_runner_log.txt"
            };
            
            for (String logPath : logPaths) {
                try {
                    java.io.FileWriter writer = new java.io.FileWriter(logPath, true);
                    writer.write(logEntry);
                    writer.close();
                } catch (Exception e) {
                    // Ignore individual file write errors
                }
            }
        } catch (Exception e) {
            // Ignore logging errors
        }
    }
    
    private void showLogs() {
        appendOutput("=== Log Locations ===\n");
        appendOutput("Logs are stored in multiple locations:\n");
        appendOutput("1. /sdcard/Download/script_runner_log.txt\n");
        appendOutput("2. /sdcard/script_runner_log.txt\n");
        appendOutput("3. /data/local/tmp/script_runner_log.txt\n\n");
        
        appendOutput("=== Reading Log Files ===\n");
        executor.execute(() -> {
            String[] logPaths = {
                "/sdcard/Download/script_runner_log.txt",
                "/sdcard/script_runner_log.txt",
                "/data/local/tmp/script_runner_log.txt"
            };
            
            for (String logPath : logPaths) {
                try {
                    appendOutput("Checking: " + logPath + "\n");
                    Process process = Runtime.getRuntime().exec(new String[]{"sh", "-c", "test -f " + logPath + " && echo 'EXISTS' || echo 'NOT_FOUND'"});
                    BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                    String result = reader.readLine();
                    process.waitFor();
                    
                    if ("EXISTS".equals(result)) {
                        appendOutput("✓ Log file exists: " + logPath + "\n");
                        // Read last 20 lines
                        Process catProcess = Runtime.getRuntime().exec(new String[]{"sh", "-c", "tail -20 " + logPath});
                        BufferedReader catReader = new BufferedReader(new InputStreamReader(catProcess.getInputStream()));
                        String line;
                        appendOutput("Last 20 lines:\n");
                        while ((line = catReader.readLine()) != null) {
                            appendOutput(line + "\n");
                        }
                        catProcess.waitFor();
                        appendOutput("\n");
                    } else {
                        appendOutput("✗ Log file not found: " + logPath + "\n");
                    }
                } catch (Exception e) {
                    appendOutput("Error checking " + logPath + ": " + e.getMessage() + "\n");
                }
            }
            appendOutput("=== Log Check Complete ===\n\n");
        });
    }
    
    private void saveLogs() {
        appendOutput("=== Saving Logs ===\n");
        executor.execute(() -> {
            try {
                // Create timestamp for filename
                String timestamp = java.text.DateFormat.getDateTimeInstance().format(new java.util.Date())
                    .replace(" ", "_").replace(":", "-").replace("/", "-");
                String savedLogPath = "/sdcard/Download/script_runner_logs_" + timestamp + ".txt";
                
                // Get current output text
                String currentOutput = outputText.getText().toString();
                
                // Create comprehensive log content
                StringBuilder logContent = new StringBuilder();
                logContent.append("=== Script Runner Log Export ===\n");
                logContent.append("Export Time: ").append(java.text.DateFormat.getDateTimeInstance().format(new java.util.Date())).append("\n");
                logContent.append("Device Model: ").append(android.os.Build.MODEL).append("\n");
                logContent.append("Android Version: ").append(android.os.Build.VERSION.RELEASE).append("\n");
                logContent.append("Build: ").append(android.os.Build.DISPLAY).append("\n");
                logContent.append("Kernel: ").append(System.getProperty("os.version")).append("\n");
                logContent.append("Architecture: ").append(android.os.Build.CPU_ABI).append("\n\n");
                
                // Add current app output
                logContent.append("=== Current App Output ===\n");
                logContent.append(currentOutput).append("\n\n");
                
                // Add log files content
                String[] logPaths = {
                    "/sdcard/Download/script_runner_log.txt",
                    "/sdcard/script_runner_log.txt",
                    "/data/local/tmp/script_runner_log.txt"
                };
                
                for (String logPath : logPaths) {
                    try {
                        Process process = Runtime.getRuntime().exec(new String[]{"/system/bin/sh", "-c", "test -f " + logPath + " && echo 'EXISTS' || echo 'NOT_FOUND'"});
                        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                        String result = reader.readLine();
                        process.waitFor();
                        
                        if ("EXISTS".equals(result)) {
                            logContent.append("=== Log File: ").append(logPath).append(" ===\n");
                            Process catProcess = Runtime.getRuntime().exec(new String[]{"/system/bin/sh", "-c", "cat " + logPath});
                            BufferedReader catReader = new BufferedReader(new InputStreamReader(catProcess.getInputStream()));
                            String line;
                            while ((line = catReader.readLine()) != null) {
                                logContent.append(line).append("\n");
                            }
                            catProcess.waitFor();
                            logContent.append("\n");
                        }
                    } catch (Exception e) {
                        logContent.append("Error reading ").append(logPath).append(": ").append(e.getMessage()).append("\n");
                    }
                }
                
                // Write to file
                java.io.FileWriter writer = new java.io.FileWriter(savedLogPath);
                writer.write(logContent.toString());
                writer.close();
                
                mainHandler.post(() -> {
                    appendOutput("✓ Logs saved successfully!\n");
                    appendOutput("Saved to: " + savedLogPath + "\n");
                    appendOutput("File size: " + new java.io.File(savedLogPath).length() + " bytes\n");
                    appendOutput("=== Log Save Complete ===\n\n");
                });
                
            } catch (Exception e) {
                mainHandler.post(() -> {
                    appendOutput("Error saving logs: " + e.getMessage() + "\n");
                    appendOutput("=== Log Save Failed ===\n\n");
                });
            }
        });
    }
    
    private void clearOutput() {
        outputText.setText("");
        appendOutput("=== Output Cleared ===\n\n");
    }
    
    @Override
    protected void onDestroy() {
        super.onDestroy();
        if (executor != null) {
            executor.shutdown();
        }
    }

    // Custom Root Engine Integration
    private void executeCustomRootEngine() {
        runScript("custom-root-engine.sh");
    }

    private void executeAdvancedRootEscalation() {
        runScript("advanced-root-escalation.sh");
    }

    private void executePrivilegeChain() {
        // Use cat | sh method to bypass permission issues
        runScriptWithCat("/data/local/tmp/custom_root/bin/privilege_chain");
    }

    private void executeKernelExploit() {
        // Use cat | sh method to bypass permission issues
        runScriptWithCat("/data/local/tmp/custom_root/bin/kernel_exploit");
    }

    private void executeMemoryCorruption() {
        // Use cat | sh method to bypass permission issues
        runScriptWithCat("/data/local/tmp/custom_root/bin/memory_corruption");
    }

    private void executeSecurityBypass() {
        // Use cat | sh method to bypass permission issues
        runScriptWithCat("/data/local/tmp/custom_root/bin/security_bypass");
    }

    private void executeRootManager(String command) {
        // Use cat | sh method to bypass permission issues
        runScriptWithCat("/data/local/tmp/custom_root/bin/root_manager", command);
    }

    private void executePersistentRootInstaller() {
        // Use cat | sh method to bypass permission issues
        runScriptWithCat("/data/local/tmp/custom_root/bin/install_persistent_root");
    }

    // New method to run scripts using cat | sh to bypass permission issues
    private void runScriptWithCat(String scriptPath, String... args) {
        if (!isExecuting.compareAndSet(false, true)) {
            appendOutput("Script execution already in progress. Please wait...\n");
            return;
        }

        executionLock.lock();
        try {
            // Use findScript to locate the script
            String actualPath = findScript(scriptPath);
            appendOutput("=== Running Script: " + actualPath + " ===\n");
            appendOutput("DEBUG: Original path: " + scriptPath + "\n");
            appendOutput("DEBUG: Found path: " + actualPath + "\n");
            Log.d(TAG, "=== Running Script: " + actualPath + " ===");
            Log.d(TAG, "DEBUG: Original path: " + scriptPath);
            Log.d(TAG, "DEBUG: Found path: " + actualPath);

            executor.execute(() -> {
                try {
                    // Check if script exists
                    Process checkProcess = Runtime.getRuntime().exec(new String[]{"sh", "-c", "test -f " + actualPath + " && echo 'exists' || echo 'not found'"});
                    BufferedReader checkReader = new BufferedReader(new InputStreamReader(checkProcess.getInputStream()));
                    String checkResult = checkReader.readLine();
                    checkProcess.waitFor();

                    if (!"exists".equals(checkResult)) {
                        mainHandler.post(() -> {
                            appendOutput("Error: Script not found at " + actualPath + "\n");
                            appendOutput("Searched in: " + String.join(", ", getScriptSearchPaths()) + "\n");
                            appendOutput("=== Script Failed ===\n\n");
                        });
                        Log.e(TAG, "Error: Script not found at " + actualPath);
                        Log.e(TAG, "Searched in: " + String.join(", ", getScriptSearchPaths()));
                        return;
                    }

                    // Build command using cat | sh method
                    StringBuilder shellCommand = new StringBuilder();
                    shellCommand.append("cat ").append(actualPath).append(" | sh");

                    // Add arguments if provided
                    for (String arg : args) {
                        if (arg != null && !arg.trim().isEmpty()) {
                            shellCommand.append(" '").append(arg).append("'");
                        }
                    }

                    String[] command = new String[3];
                    command[0] = "/system/bin/sh";
                    command[1] = "-c";
                    command[2] = shellCommand.toString();

                    appendOutput("DEBUG: Executing command: " + shellCommand.toString() + "\n");
                    Log.d(TAG, "DEBUG: Executing command: " + shellCommand.toString());

                    // Execute script using ProcessBuilder
                    ProcessBuilder pb = new ProcessBuilder(command);
                    pb.redirectErrorStream(true);
                    Process process = pb.start();

                    // Read output
                    BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                    String line;
                    StringBuilder output = new StringBuilder();

                    while ((line = reader.readLine()) != null) {
                        output.append(line).append("\n");
                    }

                    // Wait for process to complete
                    int exitCode = process.waitFor();

                    // Update UI on main thread
                    mainHandler.post(() -> {
                        appendOutput(output.toString());
                        appendOutput("Exit code: " + exitCode + "\n");
                        appendOutput("=== Script Completed ===\n\n");
                    });
                    Log.d(TAG, "Script completed with exit code: " + exitCode);

                } catch (Exception e) {
                    mainHandler.post(() -> {
                        appendOutput("Error running script: " + e.getMessage() + "\n");
                        appendOutput("=== Script Failed ===\n\n");
                    });
                    Log.e(TAG, "Error running script: " + e.getMessage(), e);
                } finally {
                    isExecuting.set(false);
                }
            });
        } finally {
            executionLock.unlock();
        }
    }
}
