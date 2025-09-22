#pragma once

#include <string>
#include <map>
#include <functional>
#include <memory>

namespace Network {

// HTTP request structure
struct HttpRequest {
    std::string method;
    std::string url;
    std::string body;
    std::map<std::string, std::string> headers;
    int timeout_seconds = 30;
};

// HTTP response structure
struct HttpResponse {
    int status_code;
    std::string body;
    std::map<std::string, std::string> headers;
    std::string error_message;
    bool success = false;
};

// HTTP client interface
class HttpClient {
public:
    virtual ~HttpClient() = default;
    virtual HttpResponse send_request(const HttpRequest& request) = 0;
    virtual void set_timeout(int seconds) = 0;
    virtual void set_default_headers(const std::map<std::string, std::string>& headers) = 0;
};

// Network monitoring system
class NetworkMonitor {
public:
    static NetworkMonitor& get_instance() {
        static NetworkMonitor instance;
        return instance;
    }
    
    // Register callbacks for network events
    void on_request(const std::string& domain, std::function<void(const HttpRequest&)> callback) {
        request_callbacks_[domain] = callback;
    }
    
    void on_response(const std::string& domain, std::function<void(const HttpResponse&)> callback) {
        response_callbacks_[domain] = callback;
    }
    
    void on_timeout(const std::string& domain, std::function<void(const std::string&)> callback) {
        timeout_callbacks_[domain] = callback;
    }
    
    // Trigger callbacks (called by HTTP client implementations)
    void trigger_request(const std::string& domain, const HttpRequest& request) {
        auto it = request_callbacks_.find(domain);
        if (it != request_callbacks_.end()) {
            it->second(request);
        }
    }
    
    void trigger_response(const std::string& domain, const HttpResponse& response) {
        auto it = response_callbacks_.find(domain);
        if (it != response_callbacks_.end()) {
            it->second(response);
        }
    }
    
    void trigger_timeout(const std::string& domain, const std::string& endpoint) {
        auto it = timeout_callbacks_.find(domain);
        if (it != timeout_callbacks_.end()) {
            it->second(endpoint);
        }
    }

private:
    std::map<std::string, std::function<void(const HttpRequest&)>> request_callbacks_;
    std::map<std::string, std::function<void(const HttpResponse&)>> response_callbacks_;
    std::map<std::string, std::function<void(const std::string&)>> timeout_callbacks_;
};

} // namespace Network
