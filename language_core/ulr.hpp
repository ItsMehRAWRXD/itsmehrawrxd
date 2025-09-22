#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <set>
#include <chrono>

namespace LanguageCore {

// Universal Language Representation (ULR) - Language-agnostic intermediate representation
class ULR {
public:
    // ULR Node structure
    struct ULRNode {
        std::string id;
        std::string type;
        std::string label;
        std::map<std::string, std::string> properties;
        std::vector<std::string> relationships;
        std::string semantic_role;
        std::string data_type;
        std::string scope;
        std::chrono::steady_clock::time_point created_at;
        
        ULRNode() {
            created_at = std::chrono::steady_clock::now();
        }
    };
    
    ULR() = default;
    virtual ~ULR() = default;
    
    // Node management
    virtual void add_node(const ULRNode& node) = 0;
    virtual void remove_node(const std::string& node_id) = 0;
    virtual ULRNode* get_node(const std::string& node_id) = 0;
    virtual std::vector<ULRNode> get_all_nodes() = 0;
    
    // Relationship management
    virtual void add_relationship(const std::string& from_id, const std::string& to_id, const std::string& relationship_type) = 0;
    virtual void remove_relationship(const std::string& from_id, const std::string& to_id) = 0;
    virtual std::vector<std::string> get_relationships(const std::string& node_id) = 0;
    
    // Query operations
    virtual std::vector<ULRNode> find_nodes_by_type(const std::string& type) = 0;
    virtual std::vector<ULRNode> find_nodes_by_property(const std::string& property, const std::string& value) = 0;
    virtual std::vector<ULRNode> find_nodes_by_semantic_role(const std::string& role) = 0;
    
    // Analysis operations
    virtual std::vector<ULRNode> get_dependencies(const std::string& node_id) = 0;
    virtual std::vector<ULRNode> get_dependents(const std::string& node_id) = 0;
    virtual bool has_cycle() = 0;
    virtual std::vector<std::vector<ULRNode>> get_strongly_connected_components() = 0;
    
    // Traversal operations
    virtual std::vector<ULRNode> depth_first_traversal(const std::string& start_id) = 0;
    virtual std::vector<ULRNode> breadth_first_traversal(const std::string& start_id) = 0;
    virtual std::vector<ULRNode> topological_sort() = 0;
    
    // Utility operations
    virtual void clear() = 0;
    virtual size_t get_node_count() const = 0;
    virtual size_t get_relationship_count() const = 0;
    virtual bool is_empty() const = 0;
};

} // namespace LanguageCore
