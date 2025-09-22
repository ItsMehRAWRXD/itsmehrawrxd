// AI-native vector database for semantic search and RAG
#include <vector>
#include <map>
#include <string>
#include <memory>

namespace IDE_AI {

class VectorDatabase {
public:
    VectorDatabase(size_t dimension) : dimension_(dimension) {}
    
    // Add document with embedding
    void addDocument(const std::string& id, const std::vector<float>& embedding, const std::string& content) {
        documents_[id] = {embedding, content};
    }
    
    // Search for similar documents
    std::vector<SearchResult> search(const std::vector<float>& query_embedding, size_t top_k = 10) {
        std::vector<SearchResult> results;
        
        for (const auto& [id, doc] : documents_) {
            float similarity = cosineSimilarity(query_embedding, doc.embedding);
            results.push_back({id, doc.content, similarity});
        }
        
        // Sort by similarity
        std::sort(results.begin(), results.end(), 
                 [](const SearchResult& a, const SearchResult& b) {
                     return a.similarity > b.similarity;
                 });
        
        if (results.size() > top_k) {
            results.resize(top_k);
        }
        
        return results;
    }
    
private:
    struct Document {
        std::vector<float> embedding;
        std::string content;
    };
    
    size_t dimension_;
    std::map<std::string, Document> documents_;
    
    float cosineSimilarity(const std::vector<float>& a, const std::vector<float>& b) {
        float dot_product = 0.0f;
        float norm_a = 0.0f;
        float norm_b = 0.0f;
        
        for (size_t i = 0; i < a.size(); ++i) {
            dot_product += a[i] * b[i];
            norm_a += a[i] * a[i];
            norm_b += b[i] * b[i];
        }
        
        return dot_product / (std::sqrt(norm_a) * std::sqrt(norm_b));
    }
};

struct SearchResult {
    std::string id;
    std::string content;
    float similarity;
};

} // namespace IDE_AI
