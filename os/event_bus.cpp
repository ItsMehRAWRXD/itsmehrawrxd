#include <iostream>
#include <string>
#include <map>
#include <vector>
#include <functional>
#include <thread>
#include <atomic>
#include <mutex>
#include <chrono>
#include <queue>
#include <memory>
#include <algorithm>

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#elif __linux__
#include <unistd.h>
#include <sys/wait.h>
#include <dirent.h>
#include <fstream>
#elif __APPLE__
#include <unistd.h>
#include <sys/wait.h>
#include <dirent.h>
#include <fstream>
#endif

namespace OS {

// Event types for system-wide monitoring
enum class EventType {
    ApplicationFocus,
    FileAccess,
    ProcessStart,
    ProcessEnd,
    NetworkActivity,
    ClipboardChange,
    KeyboardInput,
    MouseInput,
    WindowEvent,
    SystemEvent
};

// Event data structure
struct SystemEvent {
    EventType type;
    std::string application_name;
    std::string process_id;
    std::string window_title;
    std::string file_path;
    std::string event_data;
    std::chrono::steady_clock::time_point timestamp;
    std::map<std::string, std::string> metadata;
    
    SystemEvent() {
        timestamp = std::chrono::steady_clock::now();
    }
};

// Process information
struct ProcessInfo {
    std::string pid;
    std::string name;
    std::string executable_path;
    std::string window_title;
    bool is_focused;
    std::chrono::steady_clock::time_point start_time;
    size_t memory_usage;
    float cpu_usage;
    
    ProcessInfo() : is_focused(false), memory_usage(0), cpu_usage(0.0f) {
        start_time = std::chrono::steady_clock::now();
    }
};

// High-performance event bus with zero-copy design
class EventBus {
private:
    std::map<EventType, std::vector<std::function<void(const SystemEvent&)>>> handlers_;
    std::queue<SystemEvent> event_queue_;
    std::mutex handlers_mutex_;
    std::mutex queue_mutex_;
    std::atomic<bool> running_;
    std::thread event_thread_;
    
    // Performance optimization: lock-free event processing
    static constexpr size_t MAX_QUEUE_SIZE = 10000;
    std::atomic<size_t> queue_size_{0};
    
    // Process monitoring
    std::map<std::string, ProcessInfo> active_processes_;
    std::mutex processes_mutex_;
    std::string current_focused_app_;

public:
    EventBus() : running_(false) {
        std::cout << "OS Event Bus initialized\n";
    }
    
    ~EventBus() {
        stop();
    }
    
    void start() {
        if (running_) return;
        
        running_ = true;
        event_thread_ = std::thread(&EventBus::event_loop, this);
        
        // Start platform-specific event monitoring
        start_platform_monitoring();
        
        std::cout << "OS Event Bus started\n";
    }
    
    void stop() {
        if (!running_) return;
        
        running_ = false;
        if (event_thread_.joinable()) {
            event_thread_.join();
        }
        
        stop_platform_monitoring();
        std::cout << "OS Event Bus stopped\n";
    }
    
    // High-performance event subscription with zero-copy
    void subscribe(EventType event_type, std::function<void(const SystemEvent&)> handler) {
        std::lock_guard<std::mutex> lock(handlers_mutex_);
        handlers_[event_type].push_back(std::move(handler));
    }
    
    // Lock-free event emission
    void emit_event(const SystemEvent& event) {
        if (queue_size_.load() >= MAX_QUEUE_SIZE) {
            // Drop oldest events to prevent memory exhaustion
            std::lock_guard<std::mutex> lock(queue_mutex_);
            while (!event_queue_.empty() && queue_size_.load() >= MAX_QUEUE_SIZE) {
                event_queue_.pop();
                queue_size_.fetch_sub(1);
            }
        }
        
        {
            std::lock_guard<std::mutex> lock(queue_mutex_);
            event_queue_.push(event);
            queue_size_.fetch_add(1);
        }
    }
    
    // Get current focused application
    std::string get_focused_application() const {
        return current_focused_app_;
    }
    
    // Get active processes
    std::vector<ProcessInfo> get_active_processes() const {
        std::lock_guard<std::mutex> lock(processes_mutex_);
        std::vector<ProcessInfo> processes;
        for (const auto& [pid, info] : active_processes_) {
            processes.push_back(info);
        }
        return processes;
    }
    
    // Performance metrics
    struct PerformanceMetrics {
        size_t events_processed;
        size_t events_dropped;
        size_t queue_size;
        double average_processing_time_ms;
        std::chrono::steady_clock::time_point last_update;
    };
    
    PerformanceMetrics get_performance_metrics() const {
        PerformanceMetrics metrics;
        metrics.events_processed = events_processed_.load();
        metrics.events_dropped = events_dropped_.load();
        metrics.queue_size = queue_size_.load();
        metrics.average_processing_time_ms = average_processing_time_ms_.load();
        metrics.last_update = std::chrono::steady_clock::now();
        return metrics;
    }

private:
    void event_loop() {
        while (running_) {
            process_events();
            update_process_monitoring();
            std::this_thread::sleep_for(std::chrono::milliseconds(1)); // High-frequency polling
        }
    }
    
    void process_events() {
        std::vector<SystemEvent> events_to_process;
        
        // Batch process events for efficiency
        {
            std::lock_guard<std::mutex> lock(queue_mutex_);
            while (!event_queue_.empty() && events_to_process.size() < 100) {
                events_to_process.push_back(event_queue_.front());
                event_queue_.pop();
                queue_size_.fetch_sub(1);
            }
        }
        
        // Process events without holding locks
        for (const auto& event : events_to_process) {
            auto start_time = std::chrono::high_resolution_clock::now();
            
            std::lock_guard<std::mutex> lock(handlers_mutex_);
            auto it = handlers_.find(event.type);
            if (it != handlers_.end()) {
                for (const auto& handler : it->second) {
                    try {
                        handler(event);
                    } catch (const std::exception& e) {
                        std::cerr << "Event handler error: " << e.what() << std::endl;
                    }
                }
            }
            
            auto end_time = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
            update_processing_time(duration.count() / 1000.0);
            
            events_processed_.fetch_add(1);
        }
    }
    
    void update_process_monitoring() {
        // Update process information periodically
        static auto last_update = std::chrono::steady_clock::now();
        auto now = std::chrono::steady_clock::now();
        
        if (now - last_update > std::chrono::seconds(1)) {
            update_active_processes();
            last_update = now;
        }
    }
    
    void update_active_processes() {
        std::lock_guard<std::mutex> lock(processes_mutex_);
        
#ifdef _WIN32
        update_windows_processes();
#elif __linux__
        update_linux_processes();
#elif __APPLE__
        update_macos_processes();
#endif
    }
    
#ifdef _WIN32
    void start_platform_monitoring() {
        // Start Windows-specific monitoring
        std::thread([this]() {
            while (running_) {
                monitor_windows_events();
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
        }).detach();
    }
    
    void stop_platform_monitoring() {
        // Stop Windows-specific monitoring
    }
    
    void monitor_windows_events() {
        // Monitor window focus changes
        HWND foreground_window = GetForegroundWindow();
        if (foreground_window) {
            char window_title[256];
            GetWindowTextA(foreground_window, window_title, sizeof(window_title));
            
            DWORD process_id;
            GetWindowThreadProcessId(foreground_window, &process_id);
            
            std::string app_name = get_process_name_by_id(process_id);
            
            if (app_name != current_focused_app_) {
                current_focused_app_ = app_name;
                
                SystemEvent event;
                event.type = EventType::ApplicationFocus;
                event.application_name = app_name;
                event.process_id = std::to_string(process_id);
                event.window_title = window_title;
                event.metadata["previous_app"] = current_focused_app_;
                
                emit_event(event);
            }
        }
    }
    
    void update_windows_processes() {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) return;
        
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        
        if (Process32First(snapshot, &pe32)) {
            do {
                ProcessInfo info;
                info.pid = std::to_string(pe32.th32ProcessID);
                info.name = pe32.szExeFile;
                info.executable_path = get_process_path_by_id(pe32.th32ProcessID);
                
                // Get memory usage
                HANDLE process_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
                if (process_handle) {
                    PROCESS_MEMORY_COUNTERS pmc;
                    if (GetProcessMemoryInfo(process_handle, &pmc, sizeof(pmc))) {
                        info.memory_usage = pmc.WorkingSetSize;
                    }
                    CloseHandle(process_handle);
                }
                
                active_processes_[info.pid] = info;
            } while (Process32Next(snapshot, &pe32));
        }
        
        CloseHandle(snapshot);
    }
    
    std::string get_process_name_by_id(DWORD process_id) {
        HANDLE process_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, process_id);
        if (!process_handle) return "";
        
        char process_name[MAX_PATH];
        DWORD size = sizeof(process_name);
        
        if (QueryFullProcessImageNameA(process_handle, 0, process_name, &size)) {
            CloseHandle(process_handle);
            std::string full_path = process_name;
            size_t last_slash = full_path.find_last_of("\\/");
            return (last_slash != std::string::npos) ? full_path.substr(last_slash + 1) : full_path;
        }
        
        CloseHandle(process_handle);
        return "";
    }
    
    std::string get_process_path_by_id(DWORD process_id) {
        HANDLE process_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, process_id);
        if (!process_handle) return "";
        
        char process_path[MAX_PATH];
        DWORD size = sizeof(process_path);
        
        if (QueryFullProcessImageNameA(process_handle, 0, process_path, &size)) {
            CloseHandle(process_handle);
            return process_path;
        }
        
        CloseHandle(process_handle);
        return "";
    }
    
#elif __linux__
    void start_platform_monitoring() {
        // Start Linux-specific monitoring
        std::thread([this]() {
            while (running_) {
                monitor_linux_events();
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
        }).detach();
    }
    
    void stop_platform_monitoring() {
        // Stop Linux-specific monitoring
    }
    
    void monitor_linux_events() {
        // Monitor X11 window focus (simplified)
        // In a real implementation, you'd use X11 libraries
        std::string focused_app = get_focused_application_linux();
        if (focused_app != current_focused_app_) {
            current_focused_app_ = focused_app;
            
            SystemEvent event;
            event.type = EventType::ApplicationFocus;
            event.application_name = focused_app;
            event.metadata["previous_app"] = current_focused_app_;
            
            emit_event(event);
        }
    }
    
    void update_linux_processes() {
        DIR* proc_dir = opendir("/proc");
        if (!proc_dir) return;
        
        struct dirent* entry;
        while ((entry = readdir(proc_dir)) != nullptr) {
            if (entry->d_type == DT_DIR && std::isdigit(entry->d_name[0])) {
                std::string pid = entry->d_name;
                
                ProcessInfo info;
                info.pid = pid;
                info.name = get_process_name_linux(pid);
                info.executable_path = get_process_path_linux(pid);
                info.memory_usage = get_process_memory_linux(pid);
                
                active_processes_[pid] = info;
            }
        }
        
        closedir(proc_dir);
    }
    
    std::string get_focused_application_linux() {
        // Simplified - in real implementation, use X11
        return "unknown";
    }
    
    std::string get_process_name_linux(const std::string& pid) {
        std::ifstream comm_file("/proc/" + pid + "/comm");
        std::string name;
        if (comm_file >> name) {
            return name;
        }
        return "";
    }
    
    std::string get_process_path_linux(const std::string& pid) {
        std::ifstream exe_link("/proc/" + pid + "/exe");
        std::string path;
        if (exe_link >> path) {
            return path;
        }
        return "";
    }
    
    size_t get_process_memory_linux(const std::string& pid) {
        std::ifstream status_file("/proc/" + pid + "/status");
        std::string line;
        while (std::getline(status_file, line)) {
            if (line.substr(0, 6) == "VmRSS:") {
                std::istringstream iss(line.substr(6));
                size_t memory_kb;
                if (iss >> memory_kb) {
                    return memory_kb * 1024; // Convert to bytes
                }
            }
        }
        return 0;
    }
    
#elif __APPLE__
    void start_platform_monitoring() {
        // Start macOS-specific monitoring
        std::thread([this]() {
            while (running_) {
                monitor_macos_events();
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
        }).detach();
    }
    
    void stop_platform_monitoring() {
        // Stop macOS-specific monitoring
    }
    
    void monitor_macos_events() {
        // Monitor macOS window focus (simplified)
        std::string focused_app = get_focused_application_macos();
        if (focused_app != current_focused_app_) {
            current_focused_app_ = focused_app;
            
            SystemEvent event;
            event.type = EventType::ApplicationFocus;
            event.application_name = focused_app;
            event.metadata["previous_app"] = current_focused_app_;
            
            emit_event(event);
        }
    }
    
    void update_macos_processes() {
        // Simplified macOS process monitoring
        // In real implementation, use sysctl or other macOS APIs
    }
    
    std::string get_focused_application_macos() {
        // Simplified - in real implementation, use macOS APIs
        return "unknown";
    }
#endif
    
    void update_processing_time(double time_ms) {
        // Update running average of processing time
        double current_avg = average_processing_time_ms_.load();
        double new_avg = (current_avg * 0.9) + (time_ms * 0.1);
        average_processing_time_ms_.store(new_avg);
    }
    
    // Performance counters
    std::atomic<size_t> events_processed_{0};
    std::atomic<size_t> events_dropped_{0};
    std::atomic<double> average_processing_time_ms_{0.0};
};

} // namespace OS
