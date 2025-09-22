#pragma once

#include <string>
#include <map>
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <cctype>

namespace Settings {

// Configuration storage
class ConfigStore {
public:
    static ConfigStore& get_instance() {
        static ConfigStore instance;
        return instance;
    }
    
    void load_from_file(const std::string& filename) {
        std::ifstream file(filename);
        if (!file.is_open()) {
            std::cerr << "Warning: Could not open config file: " << filename << std::endl;
            return;
        }
        
        std::string line;
        std::string current_section;
        
        while (std::getline(file, line)) {
            // Remove comments
            size_t comment_pos = line.find('#');
            if (comment_pos != std::string::npos) {
                line = line.substr(0, comment_pos);
            }
            
            // Trim whitespace
            line = trim(line);
            
            if (line.empty()) continue;
            
            // Check for section header
            if (line.front() == '[' && line.back() == ']') {
                current_section = line.substr(1, line.length() - 2);
                continue;
            }
            
            // Parse key-value pair
            size_t equal_pos = line.find('=');
            if (equal_pos != std::string::npos) {
                std::string key = trim(line.substr(0, equal_pos));
                std::string value = trim(line.substr(equal_pos + 1));
                
                // Remove quotes if present
                if (value.front() == '"' && value.back() == '"') {
                    value = value.substr(1, value.length() - 2);
                }
                
                std::string full_key = current_section.empty() ? key : current_section + "." + key;
                config_[full_key] = value;
            }
        }
        
        file.close();
    }
    
    std::string get_string(const std::string& key, const std::string& default_value = "") const {
        auto it = config_.find(key);
        return (it != config_.end()) ? it->second : default_value;
    }
    
    bool get_bool(const std::string& key, bool default_value = false) const {
        auto it = config_.find(key);
        if (it == config_.end()) return default_value;
        
        std::string value = it->second;
        std::transform(value.begin(), value.end(), value.begin(), ::tolower);
        return value == "true" || value == "1" || value == "yes" || value == "on";
    }
    
    int get_int(const std::string& key, int default_value = 0) const {
        auto it = config_.find(key);
        if (it == config_.end()) return default_value;
        
        try {
            return std::stoi(it->second);
        } catch (const std::exception&) {
            return default_value;
        }
    }
    
    float get_float(const std::string& key, float default_value = 0.0f) const {
        auto it = config_.find(key);
        if (it == config_.end()) return default_value;
        
        try {
            return std::stof(it->second);
        } catch (const std::exception&) {
            return default_value;
        }
    }
    
    std::vector<std::string> get_providers_list(const std::string& key) const {
        auto it = config_.find(key);
        if (it == config_.end()) return {};
        
        std::vector<std::string> providers;
        std::string value = it->second;
        
        // Remove brackets if present
        if (value.front() == '[' && value.back() == ']') {
            value = value.substr(1, value.length() - 2);
        }
        
        // Split by comma
        std::stringstream ss(value);
        std::string provider;
        while (std::getline(ss, provider, ',')) {
            provider = trim(provider);
            if (!provider.empty()) {
                providers.push_back(provider);
            }
        }
        
        return providers;
    }
    
    void set_string(const std::string& key, const std::string& value) {
        config_[key] = value;
    }
    
    void set_bool(const std::string& key, bool value) {
        config_[key] = value ? "true" : "false";
    }
    
    void set_int(const std::string& key, int value) {
        config_[key] = std::to_string(value);
    }
    
    void set_float(const std::string& key, float value) {
        config_[key] = std::to_string(value);
    }
    
    void save_to_file(const std::string& filename) const {
        std::ofstream file(filename);
        if (!file.is_open()) {
            std::cerr << "Error: Could not save config file: " << filename << std::endl;
            return;
        }
        
        std::string current_section;
        for (const auto& [key, value] : config_) {
            size_t dot_pos = key.find('.');
            std::string section = (dot_pos != std::string::npos) ? key.substr(0, dot_pos) : "";
            std::string setting_key = (dot_pos != std::string::npos) ? key.substr(dot_pos + 1) : key;
            
            if (section != current_section) {
                if (!current_section.empty()) {
                    file << "\n";
                }
                file << "[" << section << "]\n";
                current_section = section;
            }
            
            file << setting_key << " = \"" << value << "\"\n";
        }
        
        file.close();
    }
    
    void print_all() const {
        std::cout << "Configuration:\n";
        for (const auto& [key, value] : config_) {
            std::cout << "  " << key << " = " << value << "\n";
        }
    }

private:
    std::string trim(const std::string& str) const {
        size_t first = str.find_first_not_of(' ');
        if (first == std::string::npos) return "";
        size_t last = str.find_last_not_of(' ');
        return str.substr(first, (last - first + 1));
    }
    
    std::map<std::string, std::string> config_;
};

// Convenience functions
inline std::string get_string(const std::string& key, const std::string& default_value = "") {
    return ConfigStore::get_instance().get_string(key, default_value);
}

inline bool get_bool(const std::string& key, bool default_value = false) {
    return ConfigStore::get_instance().get_bool(key, default_value);
}

inline int get_int(const std::string& key, int default_value = 0) {
    return ConfigStore::get_instance().get_int(key, default_value);
}

inline float get_float(const std::string& key, float default_value = 0.0f) {
    return ConfigStore::get_instance().get_float(key, default_value);
}

inline std::vector<std::string> get_providers_list(const std::string& key) {
    return ConfigStore::get_instance().get_providers_list(key);
}

inline void set_string(const std::string& key, const std::string& value) {
    ConfigStore::get_instance().set_string(key, value);
}

inline void set_bool(const std::string& key, bool value) {
    ConfigStore::get_instance().set_bool(key, value);
}

inline void set_int(const std::string& key, int value) {
    ConfigStore::get_instance().set_int(key, value);
}

inline void set_float(const std::string& key, float value) {
    ConfigStore::get_instance().set_float(key, value);
}

inline void load_config(const std::string& filename) {
    ConfigStore::get_instance().load_from_file(filename);
}

inline void save_config(const std::string& filename) {
    ConfigStore::get_instance().save_to_file(filename);
}

inline void print_config() {
    ConfigStore::get_instance().print_all();
}

} // namespace Settings
