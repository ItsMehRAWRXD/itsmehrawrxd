package com.android.simpleroot;

import java.util.*;
import java.io.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;

/**
 * Plugin Manager for Script Runner
 * Handles loading, managing, and executing various types of plugins
 */
public class PluginManager {
    private static final String TAG = "PluginManager";
    private static final String PLUGIN_DIR = "/sdcard/Download/scripts/";
    private static final String NATIVE_PLUGIN_DIR = "/data/local/tmp/plugins/";
    private static final String PLUGIN_REGISTRY_FILE = PLUGIN_DIR + "plugin_registry.json";
    
    private Map<String, ScriptPlugin> plugins;
    private ExecutorService executor;
    private Handler mainHandler;
    private PluginExecutionListener listener;
    
    public interface PluginExecutionListener {
        void onPluginOutput(String output);
        void onPluginError(String error);
        void onPluginComplete(String pluginName, int exitCode);
    }
    
    public PluginManager(PluginExecutionListener listener) {
        this.plugins = new HashMap<>();
        this.executor = Executors.newFixedThreadPool(4);
        this.mainHandler = new Handler(Looper.getMainLooper());
        this.listener = listener;
        loadPlugins();
    }
    
    /**
     * Load all available plugins from the plugin directory
     */
    public void loadPlugins() {
        plugins.clear();
        
        // Load built-in plugins
        loadBuiltinPlugins();
        
        // Load external plugins from filesystem
        loadExternalPlugins();
        
        // Load native plugins
        loadNativePlugins();
        
        Log.d(TAG, "Loaded " + plugins.size() + " plugins");
    }
    
    /**
     * Load built-in plugins that are always available
     */
    private void loadBuiltinPlugins() {
        // System Information Plugin
        ScriptPlugin sysInfo = new ScriptPlugin(
            "System Info", 
            "Display comprehensive system information",
            "builtin://system_info",
            "System"
        );
        sysInfo.setIcon("📊");
        sysInfo.addCommand("info");
        sysInfo.addCommand("status");
        plugins.put("system_info", sysInfo);
        
        // Root Check Plugin
        ScriptPlugin rootCheck = new ScriptPlugin(
            "Root Checker",
            "Check root access and permissions",
            "builtin://root_check",
            "Security"
        );
        rootCheck.setIcon("🔐");
        rootCheck.setRequiresRoot(false);
        rootCheck.addCommand("check");
        rootCheck.addCommand("verify");
        plugins.put("root_check", rootCheck);
        
        // File Browser Plugin
        ScriptPlugin fileBrowser = new ScriptPlugin(
            "File Browser",
            "Browse and manage files on device",
            "builtin://file_browser",
            "File System"
        );
        fileBrowser.setIcon("📁");
        fileBrowser.addCommand("browse");
        fileBrowser.addCommand("ls");
        plugins.put("file_browser", fileBrowser);
        
        // Network Tools Plugin
        ScriptPlugin networkTools = new ScriptPlugin(
            "Network Tools",
            "Network diagnostics and tools",
            "builtin://network_tools",
            "Network"
        );
        networkTools.setIcon("🌐");
        networkTools.addCommand("ping");
        networkTools.addCommand("netstat");
        networkTools.addCommand("ifconfig");
        plugins.put("network_tools", networkTools);
        
        // Process Manager Plugin
        ScriptPlugin processManager = new ScriptPlugin(
            "Process Manager",
            "Manage running processes",
            "builtin://process_manager",
            "System"
        );
        processManager.setIcon("⚙️");
        processManager.setRequiresRoot(true);
        processManager.addCommand("ps");
        processManager.addCommand("kill");
        processManager.addCommand("top");
        plugins.put("process_manager", processManager);
    }
    
    /**
     * Load external plugins from the filesystem
     */
    private void loadExternalPlugins() {
        try {
            File pluginDir = new File(PLUGIN_DIR);
            if (!pluginDir.exists()) {
                pluginDir.mkdirs();
            }
            
            File[] files = pluginDir.listFiles();
            if (files != null) {
                for (File file : files) {
                    if (file.isFile() && isExecutableFile(file.getName())) {
                        ScriptPlugin plugin = createPluginFromFile(file);
                        if (plugin != null) {
                            plugins.put(plugin.getName().toLowerCase().replace(" ", "_"), plugin);
                        }
                    }
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "Error loading external plugins", e);
        }
    }
    
    /**
     * Load native plugins (compiled binaries)
     */
    private void loadNativePlugins() {
        try {
            File nativeDir = new File(NATIVE_PLUGIN_DIR);
            if (!nativeDir.exists()) {
                nativeDir.mkdirs();
            }
            
            File[] files = nativeDir.listFiles();
            if (files != null) {
                for (File file : files) {
                    if (file.isFile() && file.canExecute()) {
                        ScriptPlugin plugin = new ScriptPlugin(
                            file.getName(),
                            "Native plugin: " + file.getName(),
                            file.getAbsolutePath(),
                            "Native"
                        );
                        plugin.setIcon("⚡");
                        plugin.setRequiresRoot(true);
                        plugins.put(file.getName().toLowerCase().replace(".", "_"), plugin);
                    }
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "Error loading native plugins", e);
        }
    }
    
    /**
     * Create a plugin from a file
     */
    private ScriptPlugin createPluginFromFile(File file) {
        String name = file.getName();
        String extension = getFileExtension(name);
        
        ScriptPlugin plugin = new ScriptPlugin(
            name,
            "External plugin: " + name,
            file.getAbsolutePath(),
            getCategoryFromExtension(extension)
        );
        
        // Set appropriate icon and properties based on file type
        switch (extension) {
            case "sh":
                plugin.setIcon("🐚");
                plugin.setRequiresRoot(false);
                break;
            case "py":
                plugin.setIcon("🐍");
                plugin.setRequiresRoot(false);
                break;
            case "js":
                plugin.setIcon("📜");
                plugin.setRequiresRoot(false);
                break;
            case "bin":
            case "exe":
                plugin.setIcon("⚡");
                plugin.setRequiresRoot(true);
                break;
            default:
                plugin.setIcon("📄");
                break;
        }
        
        return plugin;
    }
    
    /**
     * Execute a plugin with given arguments
     */
    public void executePlugin(String pluginName, String... args) {
        ScriptPlugin plugin = plugins.get(pluginName.toLowerCase());
        if (plugin == null) {
            if (listener != null) {
                listener.onPluginError("Plugin not found: " + pluginName);
            }
            return;
        }
        
        executor.execute(() -> {
            try {
                int exitCode = executePluginInternal(plugin, args);
                if (listener != null) {
                    mainHandler.post(() -> listener.onPluginComplete(plugin.getName(), exitCode));
                }
            } catch (Exception e) {
                if (listener != null) {
                    mainHandler.post(() -> listener.onPluginError("Error executing plugin: " + e.getMessage()));
                }
            }
        });
    }
    
    /**
     * Internal plugin execution logic
     */
    private int executePluginInternal(ScriptPlugin plugin, String... args) throws Exception {
        String scriptPath = plugin.getScriptPath();
        
        if (scriptPath.startsWith("builtin://")) {
            return executeBuiltinPlugin(plugin, args);
        } else {
            return executeExternalPlugin(plugin, args);
        }
    }
    
    /**
     * Execute built-in plugins
     */
    private int executeBuiltinPlugin(ScriptPlugin plugin, String... args) throws Exception {
        String pluginType = plugin.getScriptPath().substring("builtin://".length());
        
        switch (pluginType) {
            case "system_info":
                return executeSystemInfo(args);
            case "root_check":
                return executeRootCheck(args);
            case "file_browser":
                return executeFileBrowser(args);
            case "network_tools":
                return executeNetworkTools(args);
            case "process_manager":
                return executeProcessManager(args);
            default:
                throw new Exception("Unknown built-in plugin: " + pluginType);
        }
    }
    
    /**
     * Execute external plugins (scripts, binaries)
     */
    private int executeExternalPlugin(ScriptPlugin plugin, String... args) throws Exception {
        String scriptPath = plugin.getScriptPath();
        File scriptFile = new File(scriptPath);
        
        if (!scriptFile.exists()) {
            throw new Exception("Script file not found: " + scriptPath);
        }
        
        // Build command array
        List<String> command = new ArrayList<>();
        
        if (scriptPath.endsWith(".sh")) {
            command.add("sh");
            command.add(scriptPath);
        } else if (scriptPath.endsWith(".py")) {
            command.add("python");
            command.add(scriptPath);
        } else if (scriptPath.endsWith(".js")) {
            command.add("node");
            command.add(scriptPath);
        } else {
            // Native binary
            command.add(scriptPath);
        }
        
        // Add arguments
        for (String arg : args) {
            command.add(arg);
        }
        
        // Execute command
        ProcessBuilder pb = new ProcessBuilder(command);
        pb.redirectErrorStream(true);
        Process process = pb.start();
        
        // Read output
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        String line;
        StringBuilder output = new StringBuilder();
        
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\n");
            if (listener != null) {
                final String finalLine = line;
                mainHandler.post(() -> listener.onPluginOutput(finalLine));
            }
        }
        
        return process.waitFor();
    }
    
    // Built-in plugin implementations
    private int executeSystemInfo(String... args) throws Exception {
        String[] commands = {
            "echo '=== System Information ==='",
            "echo 'Model: '$(getprop ro.product.model)",
            "echo 'Android: '$(getprop ro.build.version.release)",
            "echo 'Build: '$(getprop ro.build.id)",
            "echo 'Kernel: '$(uname -r)",
            "echo 'Architecture: '$(getprop ro.product.cpu.abi)",
            "echo 'Root Status: '$(id | grep -o 'uid=0' || echo 'Not Rooted')",
            "echo 'Available Storage:'",
            "df -h /sdcard",
            "echo 'Memory Info:'",
            "cat /proc/meminfo | head -5"
        };
        
        for (String cmd : commands) {
            Process process = Runtime.getRuntime().exec(new String[]{"sh", "-c", cmd});
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                if (listener != null) {
                    final String finalLine = line;
                    mainHandler.post(() -> listener.onPluginOutput(finalLine));
                }
            }
            process.waitFor();
        }
        return 0;
    }
    
    private int executeRootCheck(String... args) throws Exception {
        String[] commands = {
            "echo '=== Root Access Check ==='",
            "id",
            "echo 'SU binary locations:'",
            "which su || echo 'No su found'",
            "ls -la /system/bin/su 2>/dev/null || echo 'No su in /system/bin'",
            "ls -la /system/xbin/su 2>/dev/null || echo 'No su in /system/xbin'",
            "echo 'Root test:'",
            "su -c 'id' 2>/dev/null && echo 'Root access confirmed' || echo 'No root access'"
        };
        
        for (String cmd : commands) {
            Process process = Runtime.getRuntime().exec(new String[]{"sh", "-c", cmd});
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                if (listener != null) {
                    final String finalLine = line;
                    mainHandler.post(() -> listener.onPluginOutput(finalLine));
                }
            }
            process.waitFor();
        }
        return 0;
    }
    
    private int executeFileBrowser(String... args) throws Exception {
        String path = args.length > 0 ? args[0] : "/sdcard";
        String cmd = "ls -la " + path;
        
        Process process = Runtime.getRuntime().exec(new String[]{"sh", "-c", cmd});
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        String line;
        while ((line = reader.readLine()) != null) {
            if (listener != null) {
                final String finalLine = line;
                mainHandler.post(() -> listener.onPluginOutput(finalLine));
            }
        }
        return process.waitFor();
    }
    
    private int executeNetworkTools(String... args) throws Exception {
        String cmd = args.length > 0 ? args[0] : "ifconfig";
        
        Process process = Runtime.getRuntime().exec(new String[]{"sh", "-c", cmd});
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        String line;
        while ((line = reader.readLine()) != null) {
            if (listener != null) {
                final String finalLine = line;
                mainHandler.post(() -> listener.onPluginOutput(finalLine));
            }
        }
        return process.waitFor();
    }
    
    private int executeProcessManager(String... args) throws Exception {
        String cmd = args.length > 0 ? args[0] : "ps";
        
        Process process = Runtime.getRuntime().exec(new String[]{"sh", "-c", cmd});
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        String line;
        while ((line = reader.readLine()) != null) {
            if (listener != null) {
                final String finalLine = line;
                mainHandler.post(() -> listener.onPluginOutput(finalLine));
            }
        }
        return process.waitFor();
    }
    
    // Utility methods
    private boolean isExecutableFile(String filename) {
        String ext = getFileExtension(filename);
        return ext.equals("sh") || ext.equals("py") || ext.equals("js") || 
               ext.equals("bin") || ext.equals("exe") || ext.equals("so");
    }
    
    private String getFileExtension(String filename) {
        int lastDot = filename.lastIndexOf('.');
        return lastDot > 0 ? filename.substring(lastDot + 1) : "";
    }
    
    private String getCategoryFromExtension(String extension) {
        switch (extension) {
            case "sh": return "Shell Scripts";
            case "py": return "Python Scripts";
            case "js": return "JavaScript";
            case "bin":
            case "exe": return "Native Binaries";
            default: return "Other";
        }
    }
    
    // Public getters
    public Map<String, ScriptPlugin> getPlugins() {
        return new HashMap<>(plugins);
    }
    
    public List<ScriptPlugin> getPluginsByCategory(String category) {
        List<ScriptPlugin> result = new ArrayList<>();
        for (ScriptPlugin plugin : plugins.values()) {
            if (plugin.getCategory().equals(category)) {
                result.add(plugin);
            }
        }
        return result;
    }
    
    public ScriptPlugin getPlugin(String name) {
        return plugins.get(name.toLowerCase());
    }
    
    public void shutdown() {
        if (executor != null) {
            executor.shutdown();
        }
    }
}
