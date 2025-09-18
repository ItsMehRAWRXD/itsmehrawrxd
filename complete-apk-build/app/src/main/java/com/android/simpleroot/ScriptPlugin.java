package com.android.simpleroot;

import java.util.List;
import java.util.ArrayList;

/**
 * Script Plugin Interface
 * Defines the structure for script plugins
 */
public class ScriptPlugin {
    private String name;
    private String description;
    private String scriptPath;
    private String category;
    private List<String> commands;
    private boolean requiresRoot;
    private String icon;
    
    public ScriptPlugin(String name, String description, String scriptPath, String category) {
        this.name = name;
        this.description = description;
        this.scriptPath = scriptPath;
        this.category = category;
        this.commands = new ArrayList<>();
        this.requiresRoot = false;
        this.icon = "🔧";
    }
    
    // Getters and Setters
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    
    public String getScriptPath() { return scriptPath; }
    public void setScriptPath(String scriptPath) { this.scriptPath = scriptPath; }
    
    public String getCategory() { return category; }
    public void setCategory(String category) { this.category = category; }
    
    public List<String> getCommands() { return commands; }
    public void setCommands(List<String> commands) { this.commands = commands; }
    public void addCommand(String command) { this.commands.add(command); }
    
    public boolean requiresRoot() { return requiresRoot; }
    public void setRequiresRoot(boolean requiresRoot) { this.requiresRoot = requiresRoot; }
    
    public String getIcon() { return icon; }
    public void setIcon(String icon) { this.icon = icon; }
    
    @Override
    public String toString() {
        return icon + " " + name + " - " + description;
    }
}
