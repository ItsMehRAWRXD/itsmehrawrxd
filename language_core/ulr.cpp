#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <set>
#include <algorithm>
#include <iostream>

namespace LanguageCore {

// Universal Language Representation - language-agnostic intermediate representation
struct ULRNode {
    std::string id;
    std::string type; // e.g., "function", "variable", "class", "statement", "expression"
    std::string label; // The original code token or semantic label
    std::map<std::string, std::string> properties; // Language-specific properties
    std::vector<std::string> related_nodes; // IDs of related nodes
    std::string language_hint; // Hint about source language
    int line_number = -1;
    int column_number = -1;
    std::string scope; // Lexical scope information
    
    // Semantic information
    std::string semantic_role; // e.g., "declaration", "invocation", "assignment"
    std::string data_type; // Type information if available
    std::vector<std::string> modifiers; // e.g., "public", "static", "const"
    
    // Relationships
    std::map<std::string, std::vector<std::string>> relationships; // relationship_type -> node_ids
};

// Universal Language Representation
class ULR {
public:
    ULR() {
        nodes_.reserve(10000);
        relationships_.reserve(5000);
    }
    
    // Node management
    void add_node(const ULRNode& node) {
        nodes_[node.id] = node;
        
        // Update relationship indices
        for (const auto& related_id : node.related_nodes) {
            add_relationship(node.id, related_id, "related");
        }
        
        // Update relationship maps
        for (const auto& [rel_type, node_ids] : node.relationships) {
            for (const auto& node_id : node_ids) {
                add_relationship(node.id, node_id, rel_type);
            }
        }
    }
    
    void remove_node(const std::string& node_id) {
        auto it = nodes_.find(node_id);
        if (it != nodes_.end()) {
            // Remove all relationships involving this node
            remove_node_relationships(node_id);
            nodes_.erase(it);
        }
    }
    
    ULRNode* get_node(const std::string& node_id) {
        auto it = nodes_.find(node_id);
        return (it != nodes_.end()) ? &it->second : nullptr;
    }
    
    // Relationship management
    void add_relationship(const std::string& from_id, const std::string& to_id, const std::string& type) {
        std::string rel_key = from_id + "->" + to_id + ":" + type;
        relationships_[rel_key] = {from_id, to_id, type};
        
        // Update node relationships
        auto from_node = get_node(from_id);
        if (from_node) {
            from_node->relationships[type].push_back(to_id);
        }
    }
    
    void remove_relationship(const std::string& from_id, const std::string& to_id, const std::string& type) {
        std::string rel_key = from_id + "->" + to_id + ":" + type;
        relationships_.erase(rel_key);
        
        // Update node relationships
        auto from_node = get_node(from_id);
        if (from_node) {
            auto& rels = from_node->relationships[type];
            rels.erase(std::remove(rels.begin(), rels.end(), to_id), rels.end());
        }
    }
    
    void remove_node_relationships(const std::string& node_id) {
        // Remove all relationships where this node is involved
        auto it = relationships_.begin();
        while (it != relationships_.end()) {
            if (it->second[0] == node_id || it->second[1] == node_id) {
                it = relationships_.erase(it);
            } else {
                ++it;
            }
        }
    }
    
    // Query methods
    std::vector<ULRNode*> find_nodes_by_type(const std::string& type) {
        std::vector<ULRNode*> result;
        for (auto& [id, node] : nodes_) {
            if (node.type == type) {
                result.push_back(&node);
            }
        }
        return result;
    }
    
    std::vector<ULRNode*> find_nodes_by_property(const std::string& property, const std::string& value) {
        std::vector<ULRNode*> result;
        for (auto& [id, node] : nodes_) {
            auto it = node.properties.find(property);
            if (it != node.properties.end() && it->second == value) {
                result.push_back(&node);
            }
        }
        return result;
    }
    
    std::vector<ULRNode*> find_related_nodes(const std::string& node_id, const std::string& relationship_type) {
        std::vector<ULRNode*> result;
        auto node = get_node(node_id);
        if (node) {
            auto it = node->relationships.find(relationship_type);
            if (it != node->relationships.end()) {
                for (const auto& related_id : it->second) {
                    auto related_node = get_node(related_id);
                    if (related_node) {
                        result.push_back(related_node);
                    }
                }
            }
        }
        return result;
    }
    
    std::vector<ULRNode*> find_nodes_in_scope(const std::string& scope) {
        std::vector<ULRNode*> result;
        for (auto& [id, node] : nodes_) {
            if (node.scope == scope) {
                result.push_back(&node);
            }
        }
        return result;
    }
    
    // Traversal methods
    std::vector<ULRNode*> get_children(const std::string& node_id) {
        return find_related_nodes(node_id, "contains");
    }
    
    std::vector<ULRNode*> get_parents(const std::string& node_id) {
        std::vector<ULRNode*> result;
        for (auto& [id, node] : nodes_) {
            auto it = node.relationships.find("contains");
            if (it != node.relationships.end()) {
                for (const auto& child_id : it->second) {
                    if (child_id == node_id) {
                        result.push_back(&node);
                        break;
                    }
                }
            }
        }
        return result;
    }
    
    std::vector<ULRNode*> get_siblings(const std::string& node_id) {
        std::vector<ULRNode*> result;
        auto parents = get_parents(node_id);
        for (auto* parent : parents) {
            auto children = get_children(parent->id);
            for (auto* child : children) {
                if (child->id != node_id) {
                    result.push_back(child);
                }
            }
        }
        return result;
    }
    
    // Language analysis
    std::set<std::string> get_detected_languages() {
        std::set<std::string> languages;
        for (const auto& [id, node] : nodes_) {
            if (!node.language_hint.empty()) {
                languages.insert(node.language_hint);
            }
        }
        return languages;
    }
    
    std::vector<ULRNode*> get_language_nodes(const std::string& language) {
        std::vector<ULRNode*> result;
        for (auto& [id, node] : nodes_) {
            if (node.language_hint == language) {
                result.push_back(&node);
            }
        }
        return result;
    }
    
    // Semantic analysis
    std::vector<ULRNode*> find_declarations() {
        return find_nodes_by_semantic_role("declaration");
    }
    
    std::vector<ULRNode*> find_invocations() {
        return find_nodes_by_semantic_role("invocation");
    }
    
    std::vector<ULRNode*> find_assignments() {
        return find_nodes_by_semantic_role("assignment");
    }
    
    std::vector<ULRNode*> find_nodes_by_semantic_role(const std::string& role) {
        std::vector<ULRNode*> result;
        for (auto& [id, node] : nodes_) {
            if (node.semantic_role == role) {
                result.push_back(&node);
            }
        }
        return result;
    }
    
    // Type analysis
    std::vector<ULRNode*> find_nodes_by_type(const std::string& type) {
        std::vector<ULRNode*> result;
        for (auto& [id, node] : nodes_) {
            if (node.data_type == type) {
                result.push_back(&node);
            }
        }
        return result;
    }
    
    // Scope analysis
    std::vector<std::string> get_all_scopes() {
        std::set<std::string> scopes;
        for (const auto& [id, node] : nodes_) {
            if (!node.scope.empty()) {
                scopes.insert(node.scope);
            }
        }
        return std::vector<std::string>(scopes.begin(), scopes.end());
    }
    
    // Dependency analysis
    std::vector<ULRNode*> get_dependencies(const std::string& node_id) {
        return find_related_nodes(node_id, "depends_on");
    }
    
    std::vector<ULRNode*> get_dependents(const std::string& node_id) {
        std::vector<ULRNode*> result;
        for (auto& [id, node] : nodes_) {
            auto it = node.relationships.find("depends_on");
            if (it != node.relationships.end()) {
                for (const auto& dep_id : it->second) {
                    if (dep_id == node_id) {
                        result.push_back(&node);
                        break;
                    }
                }
            }
        }
        return result;
    }
    
    // Flow analysis
    std::vector<ULRNode*> get_control_flow_successors(const std::string& node_id) {
        return find_related_nodes(node_id, "next");
    }
    
    std::vector<ULRNode*> get_control_flow_predecessors(const std::string& node_id) {
        std::vector<ULRNode*> result;
        for (auto& [id, node] : nodes_) {
            auto it = node.relationships.find("next");
            if (it != node->relationships.end()) {
                for (const auto& next_id : it->second) {
                    if (next_id == node_id) {
                        result.push_back(&node);
                        break;
                    }
                }
            }
        }
        return result;
    }
    
    // Data flow analysis
    std::vector<ULRNode*> get_data_flow_sources(const std::string& node_id) {
        return find_related_nodes(node_id, "data_from");
    }
    
    std::vector<ULRNode*> get_data_flow_sinks(const std::string& node_id) {
        return find_related_nodes(node_id, "data_to");
    }
    
    // Utility methods
    size_t get_node_count() const {
        return nodes_.size();
    }
    
    size_t get_relationship_count() const {
        return relationships_.size();
    }
    
    void clear() {
        nodes_.clear();
        relationships_.clear();
    }
    
    // Serialization
    std::string to_string() const {
        std::string result = "ULR Graph:\n";
        result += "Nodes: " + std::to_string(nodes_.size()) + "\n";
        result += "Relationships: " + std::to_string(relationships_.size()) + "\n\n";
        
        for (const auto& [id, node] : nodes_) {
            result += "Node: " + id + "\n";
            result += "  Type: " + node.type + "\n";
            result += "  Label: " + node.label + "\n";
            result += "  Language: " + node.language_hint + "\n";
            result += "  Scope: " + node.scope + "\n";
            result += "  Semantic Role: " + node.semantic_role + "\n";
            result += "  Data Type: " + node.data_type + "\n";
            
            if (!node.properties.empty()) {
                result += "  Properties:\n";
                for (const auto& [key, value] : node.properties) {
                    result += "    " + key + ": " + value + "\n";
                }
            }
            
            if (!node.relationships.empty()) {
                result += "  Relationships:\n";
                for (const auto& [rel_type, node_ids] : node.relationships) {
                    result += "    " + rel_type + ": ";
                    for (const auto& node_id : node_ids) {
                        result += node_id + " ";
                    }
                    result += "\n";
                }
            }
            result += "\n";
        }
        
        return result;
    }
    
    // Validation
    bool validate() const {
        // Check for orphaned relationships
        for (const auto& [rel_key, rel_data] : relationships_) {
            if (nodes_.find(rel_data[0]) == nodes_.end() || nodes_.find(rel_data[1]) == nodes_.end()) {
                std::cerr << "Warning: Orphaned relationship: " << rel_key << std::endl;
                return false;
            }
        }
        
        // Check for circular dependencies
        for (const auto& [id, node] : nodes_) {
            if (has_circular_dependency(id, id, std::set<std::string>())) {
                std::cerr << "Warning: Circular dependency detected involving node: " << id << std::endl;
                return false;
            }
        }
        
        return true;
    }

private:
    bool has_circular_dependency(const std::string& start_id, const std::string& current_id, std::set<std::string> visited) const {
        if (visited.find(current_id) != visited.end()) {
            return current_id == start_id;
        }
        
        visited.insert(current_id);
        auto node = nodes_.find(current_id);
        if (node != nodes_.end()) {
            auto it = node->second.relationships.find("depends_on");
            if (it != node->second.relationships.end()) {
                for (const auto& dep_id : it->second) {
                    if (has_circular_dependency(start_id, dep_id, visited)) {
                        return true;
                    }
                }
            }
        }
        
        return false;
    }
    
    std::map<std::string, ULRNode> nodes_;
    std::map<std::string, std::vector<std::string>> relationships_; // key -> [from_id, to_id, type]
};

} // namespace LanguageCore
