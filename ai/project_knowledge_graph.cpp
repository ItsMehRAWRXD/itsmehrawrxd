// Project Knowledge Graph for advanced reasoning
#include <vector>
#include <map>
#include <string>
#include <memory>

namespace IDE_AI {

class ProjectKnowledgeGraph {
public:
    ProjectKnowledgeGraph() {}
    
    // Add entities and relationships
    void addEntity(const std::string& id, const std::string& type, const std::map<std::string, std::string>& properties) {
        entities_[id] = {type, properties};
    }
    
    void addRelationship(const std::string& from, const std::string& to, const std::string& type) {
        relationships_[from].push_back({to, type});
    }
    
    // Query the knowledge graph
    std::vector<std::string> findRelatedEntities(const std::string& entity_id, const std::string& relationship_type) {
        std::vector<std::string> related;
        
        if (relationships_.find(entity_id) != relationships_.end()) {
            for (const auto& rel : relationships_[entity_id]) {
                if (rel.type == relationship_type) {
                    related.push_back(rel.target);
                }
            }
        }
        
        return related;
    }
    
    // Get entity information
    std::map<std::string, std::string> getEntityProperties(const std::string& entity_id) {
        if (entities_.find(entity_id) != entities_.end()) {
            return entities_[entity_id].properties;
        }
        return {};
    }
    
private:
    struct Entity {
        std::string type;
        std::map<std::string, std::string> properties;
    };
    
    struct Relationship {
        std::string target;
        std::string type;
    };
    
    std::map<std::string, Entity> entities_;
    std::map<std::string, std::vector<Relationship>> relationships_;
};

} // namespace IDE_AI
