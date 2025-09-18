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
import java.io.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MainActivity extends Activity {
    private static final String TAG = "ScriptRunner";
    private TextView outputText;
    private ScrollView scrollView;
    private LinearLayout buttonLayout;
    private EditText commandInput;
    private ExecutorService executor;
    private Handler mainHandler;
    private List<String> selectedScripts = new ArrayList<>();
    
    // Script paths - Updated to use actual script locations
    private static final String SCRIPT_BASE_PATH = "/data/local/tmp/";
    private static final String HOT_PATCHER_SCRIPT = "/data/local/tmp/hot_patcher/bin/patch_manager";
    private static final String ROOT_MANAGER_SCRIPT = "/data/local/tmp/root_manager/bin/root_manager";
    private static final String COMPREHENSIVE_ROOT_SCRIPT = SCRIPT_BASE_PATH + "create-samsung-exploits.sh";
    private static final String ANDROID_HOT_PATCHER_SCRIPT = SCRIPT_BASE_PATH + "advanced_root.sh";
    private static final String CUSTOM_DEV_MENU_SCRIPT = SCRIPT_BASE_PATH + "dev_menu_shortcut.sh";
    private static final String BOOTLOADER_UNLOCK_SCRIPT = SCRIPT_BASE_PATH + "bootloader_unlock_fixed.sh";
    private static final String ADVANCED_SYSTEMLESS_ROOT_SCRIPT = SCRIPT_BASE_PATH + "systemless_root.sh";
    private static final String ESCALATE_SYSTEM_ROOT_SCRIPT = SCRIPT_BASE_PATH + "system_root_manager.sh";
    
    // Alternative script paths for better compatibility
    private static final String[] SCRIPT_SEARCH_PATHS = {
        "/sdcard/Download/scripts/",
        "/sdcard/Download/",
        "/data/local/tmp/",
        "/system/bin/",
        "/system/xbin/"
    };
    
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        
        // Initialize components
        outputText = findViewById(R.id.output_text);
        scrollView = findViewById(R.id.output_scroll_view);
        buttonLayout = findViewById(R.id.button_layout);
        commandInput = new EditText(this);
        
        // Initialize thread pool and handler
        executor = Executors.newFixedThreadPool(2);
        mainHandler = new Handler(Looper.getMainLooper());
        
        // Setup UI
        setupUI();
        setupCLI();
        
        // Check script availability
        checkScriptAvailability();
    }
    
    private void setupUI() {
        // Create buttons for different scripts
        createButton("📱 Custom Dev Menu", () -> runScript(CUSTOM_DEV_MENU_SCRIPT, "menu"));
        createButton("🔧 Install Hot Patcher", () -> runScript(ANDROID_HOT_PATCHER_SCRIPT, "install"));
        createButton("🛠️ Install Root Manager", () -> runScript(COMPREHENSIVE_ROOT_SCRIPT, "install"));
        createButton("⚡ Hot Patcher Status", () -> runScript(HOT_PATCHER_SCRIPT, "status"));
        createButton("🔍 Root Manager Status", () -> runScript(ROOT_MANAGER_SCRIPT, "status"));
        createButton("🔓 Bootloader Unlock", () -> runScript(BOOTLOADER_UNLOCK_SCRIPT, "unlock"));
        createButton("🚀 Advanced Systemless Root", () -> runScript(ADVANCED_SYSTEMLESS_ROOT_SCRIPT, "install"));
        createButton("⬆️ Escalate to System Root", () -> runScript(ESCALATE_SYSTEM_ROOT_SCRIPT, "escalate"));
        createButton("✅ Verify Root Access", () -> runScript(ROOT_MANAGER_SCRIPT, "verify"));
        createButton("📊 Show System Info", () -> runSystemInfo());
        createButton("📁 Browse Scripts", () -> browseScripts());
        createButton("🎯 Run Selected Script", () -> runSelectedScript());
        createButton("📋 List All Scripts", () -> listAllScripts());
        createButton("🔍 Brute Force Dialer Codes", () -> runBruteForceDialerCodes());
        createButton("📞 AT&T NumberSync Access", () -> runATTNumberSyncAccess());
        createButton("📊 Simple Root Status", () -> runSimpleRootStatus());
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
        
        executor.execute(() -> {
            try {
                List<String> scriptFiles = new ArrayList<>();
                
                // Search for scripts in all common locations
                for (String basePath : SCRIPT_SEARCH_PATHS) {
                    File dir = new File(basePath);
                    if (dir.exists() && dir.isDirectory()) {
                        File[] files = dir.listFiles((d, name) -> 
                            name.endsWith(".sh") || name.endsWith(".py") || 
                            name.endsWith(".js") || name.endsWith(".bat") ||
                            name.endsWith(".exe") || name.endsWith(".bin"));
                        
                        if (files != null) {
                            for (File file : files) {
                                scriptFiles.add(file.getAbsolutePath());
                            }
                        }
                    }
                }
                
                if (scriptFiles.isEmpty()) {
                    mainHandler.post(() -> {
                        appendOutput("No scripts found in common locations.\n");
                        appendOutput("Searched in: " + String.join(", ", SCRIPT_SEARCH_PATHS) + "\n");
                        appendOutput("=== Browse Complete ===\n\n");
                    });
                    return;
                }
                
                // Show script selection dialog
                mainHandler.post(() -> {
                    showScriptSelectionDialog(scriptFiles);
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
            runScript(scriptPath);
        }
    }
    
    private void listAllScripts() {
        appendOutput("=== Listing All Scripts ===\n");
        
        executor.execute(() -> {
            try {
                StringBuilder output = new StringBuilder();
                
                for (String basePath : SCRIPT_SEARCH_PATHS) {
                    File dir = new File(basePath);
                    if (dir.exists() && dir.isDirectory()) {
                        output.append("\n📁 ").append(basePath).append(":\n");
                        
                        File[] files = dir.listFiles((d, name) -> 
                            name.endsWith(".sh") || name.endsWith(".py") || 
                            name.endsWith(".js") || name.endsWith(".bat") ||
                            name.endsWith(".exe") || name.endsWith(".bin"));
                        
                        if (files != null && files.length > 0) {
                            for (File file : files) {
                                output.append("  ✓ ").append(file.getName())
                                      .append(" (").append(file.length()).append(" bytes)\n");
                            }
                        } else {
                            output.append("  (no scripts found)\n");
                        }
                    } else {
                        output.append("\n📁 ").append(basePath).append(": (not found)\n");
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
        
        appendOutput("\n=== Available Scripts in All Locations ===\n");
        try {
            // Search for scripts in all common locations
            for (String basePath : SCRIPT_SEARCH_PATHS) {
                File dir = new File(basePath);
                if (dir.exists() && dir.isDirectory()) {
                    appendOutput("\n--- " + basePath + " ---\n");
                    Process process = Runtime.getRuntime().exec("ls -la " + basePath);
                    BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                    String line;
                    while ((line = reader.readLine()) != null) {
                        if (line.contains(".sh") || line.contains(".py") || line.contains(".js") || 
                            line.contains(".bat") || line.contains(".exe") || line.contains(".bin")) {
                            appendOutput(line + "\n");
                        }
                    }
                    process.waitFor();
                }
            }
        } catch (Exception e) {
            appendOutput("Error listing scripts: " + e.getMessage() + "\n");
        }
        
        appendOutput("\n");
    }
    
    private void runBruteForceDialerCodes() {
        appendOutput("=== Running Brute Force Dialer Codes ===\n");
        runScript("/data/local/tmp/quick_bruteforce.sh", "");
    }
    
    private void runATTNumberSyncAccess() {
        appendOutput("=== Running AT&T NumberSync Access ===\n");
        runScript("/data/local/tmp/att-numbersync-direct-access.sh", "");
    }
    
    private void runSimpleRootStatus() {
        appendOutput("=== Running Simple Root Status ===\n");
        runScript("/data/local/tmp/simple-root-status.sh", "");
    }
    
    private String findScript(String scriptName) {
        // First try the exact path
        if (new File(scriptName).exists()) {
            return scriptName;
        }
        
        // Search in common script locations
        for (String basePath : SCRIPT_SEARCH_PATHS) {
            String fullPath = basePath + scriptName;
            if (new File(fullPath).exists()) {
                return fullPath;
            }
        }
        
        // If not found, return original path (will show error)
        return scriptName;
    }
    
    private void runScript(String scriptPath, String... args) {
        String actualPath = findScript(scriptPath);
        appendOutput("=== Running Script: " + actualPath + " ===\n");
        
        if (!new File(actualPath).exists()) {
            appendOutput("Error: Script not found at " + actualPath + "\n");
            appendOutput("Searched in: " + String.join(", ", SCRIPT_SEARCH_PATHS) + "\n");
            appendOutput("=== Script Failed ===\n\n");
            return;
        }
        
        executor.execute(() -> {
            try {
                // Create command array - use advanced root manager for binaries, sh for scripts
                String[] command;
                if (actualPath.endsWith(".sh")) {
                    command = new String[args.length + 2];
                    command[0] = "sh";
                    command[1] = actualPath;
                    System.arraycopy(args, 0, command, 2, args.length);
                } else if (actualPath.contains("/bin/") || actualPath.endsWith("_manager") || actualPath.endsWith("_patcher")) {
                    // For binaries in bin directories, use shell with advanced root environment
                    StringBuilder fullCommand = new StringBuilder();
                    fullCommand.append("export PATH=\"/data/local/tmp/advanced_root/bin:/data/local/tmp/advanced_root/xbin:$PATH\"; ");
                    fullCommand.append("export LD_LIBRARY_PATH=\"/data/local/tmp/advanced_root/lib:$LD_LIBRARY_PATH\"; ");
                    fullCommand.append(actualPath);
                    for (String arg : args) {
                        fullCommand.append(" ").append(arg);
                    }
                    command = new String[3];
                    command[0] = "sh";
                    command[1] = "-c";
                    command[2] = fullCommand.toString();
                } else {
                    // For other files, execute through shell
                    StringBuilder fullCommand = new StringBuilder();
                    fullCommand.append(actualPath);
                    for (String arg : args) {
                        fullCommand.append(" ").append(arg);
                    }
                    command = new String[3];
                    command[0] = "sh";
                    command[1] = "-c";
                    command[2] = fullCommand.toString();
                }
                
                // Execute script
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
                
            } catch (Exception e) {
                mainHandler.post(() -> {
                    appendOutput("Error running script: " + e.getMessage() + "\n");
                    appendOutput("=== Script Failed ===\n\n");
                });
            }
        });
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
        runOnUiThread(() -> {
            outputText.append(text);
            scrollView.post(() -> scrollView.fullScroll(View.FOCUS_DOWN));
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
}