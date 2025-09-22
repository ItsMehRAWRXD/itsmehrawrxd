"""
Hybrid RAG System Implementation
Combines semantic search, keyword search, and quantum-inspired retrieval
"""

import os
import json
import math
import re
from typing import List, Dict, Any, Tuple, Optional
from dataclasses import dataclass
from collections import defaultdict, Counter
import numpy as np
from tokenizer import BPETokenizer
from quantum_inspired_llm import QuantumInspiredLLM, QuantumState, QuantumGate

@dataclass
class Document:
    """Document structure for RAG system"""
    id: str
    content: str
    metadata: Dict[str, Any]
    embedding: Optional[List[float]] = None
    keywords: Optional[List[str]] = None
    quantum_state: Optional[QuantumState] = None

@dataclass
class SearchResult:
    """Search result structure"""
    document: Document
    score: float
    match_type: str  # "semantic", "keyword", "quantum", "hybrid"
    explanation: str

class VectorStore:
    """Simple vector store for semantic search"""
    
    def __init__(self, dimension: int = 128):
        self.dimension = dimension
        self.documents = []
        self.embeddings = []
        self.id_to_index = {}
    
    def add_document(self, document: Document):
        """Add document to vector store"""
        if document.embedding is None:
            document.embedding = self._compute_embedding(document.content)
        
        self.documents.append(document)
        self.embeddings.append(document.embedding)
        self.id_to_index[document.id] = len(self.documents) - 1
    
    def _compute_embedding(self, text: str) -> List[float]:
        """Compute simple embedding for text"""
        # Simple bag-of-words embedding with TF-IDF-like weighting
        words = re.findall(r'\w+', text.lower())
        word_counts = Counter(words)
        
        # Create embedding vector
        embedding = [0.0] * self.dimension
        
        for i, word in enumerate(word_counts.keys()):
            if i < self.dimension:
                # Simple hash-based embedding
                word_hash = hash(word) % self.dimension
                embedding[word_hash] = word_counts[word] / len(words)
        
        # Normalize embedding
        norm = math.sqrt(sum(x ** 2 for x in embedding))
        if norm > 0:
            embedding = [x / norm for x in embedding]
        
        return embedding
    
    def search(self, query: str, top_k: int = 5) -> List[Tuple[Document, float]]:
        """Search for similar documents"""
        query_embedding = self._compute_embedding(query)
        
        # Compute similarities
        similarities = []
        for i, doc_embedding in enumerate(self.embeddings):
            similarity = self._cosine_similarity(query_embedding, doc_embedding)
            similarities.append((self.documents[i], similarity))
        
        # Sort by similarity
        similarities.sort(key=lambda x: x[1], reverse=True)
        
        return similarities[:top_k]
    
    def _cosine_similarity(self, vec1: List[float], vec2: List[float]) -> float:
        """Compute cosine similarity between two vectors"""
        if len(vec1) != len(vec2):
            return 0.0
        
        dot_product = sum(a * b for a, b in zip(vec1, vec2))
        norm1 = math.sqrt(sum(a ** 2 for a in vec1))
        norm2 = math.sqrt(sum(a ** 2 for a in vec2))
        
        if norm1 == 0 or norm2 == 0:
            return 0.0
        
        return dot_product / (norm1 * norm2)

class KeywordIndex:
    """Keyword-based search index"""
    
    def __init__(self):
        self.keyword_to_docs = defaultdict(set)
        self.doc_keywords = {}
    
    def add_document(self, document: Document):
        """Add document to keyword index"""
        if document.keywords is None:
            document.keywords = self._extract_keywords(document.content)
        
        self.doc_keywords[document.id] = document.keywords
        
        for keyword in document.keywords:
            self.keyword_to_docs[keyword].add(document.id)
    
    def _extract_keywords(self, text: str) -> List[str]:
        """Extract keywords from text"""
        # Simple keyword extraction
        words = re.findall(r'\w+', text.lower())
        
        # Filter out common stop words
        stop_words = {
            'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for',
            'of', 'with', 'by', 'is', 'are', 'was', 'were', 'be', 'been', 'have',
            'has', 'had', 'do', 'does', 'did', 'will', 'would', 'could', 'should',
            'may', 'might', 'must', 'can', 'this', 'that', 'these', 'those'
        }
        
        keywords = [word for word in words if word not in stop_words and len(word) > 2]
        
        # Return most frequent keywords
        word_counts = Counter(keywords)
        return [word for word, count in word_counts.most_common(10)]
    
    def search(self, query: str, top_k: int = 5) -> List[Tuple[Document, float]]:
        """Search for documents containing query keywords"""
        query_keywords = self._extract_keywords(query)
        
        # Find documents containing query keywords
        doc_scores = defaultdict(float)
        
        for keyword in query_keywords:
            if keyword in self.keyword_to_docs:
                for doc_id in self.keyword_to_docs[keyword]:
                    doc_scores[doc_id] += 1.0
        
        # Normalize scores
        for doc_id in doc_scores:
            doc_scores[doc_id] /= len(query_keywords)
        
        # Sort by score
        sorted_docs = sorted(doc_scores.items(), key=lambda x: x[1], reverse=True)
        
        # Convert to document objects (simplified)
        results = []
        for doc_id, score in sorted_docs[:top_k]:
            # In a real implementation, you'd look up the document
            # For now, create a placeholder
            doc = Document(
                id=doc_id,
                content=f"Document {doc_id}",
                metadata={},
                keywords=self.doc_keywords.get(doc_id, [])
            )
            results.append((doc, score))
        
        return results

class QuantumRetrieval:
    """Quantum-inspired document retrieval"""
    
    def __init__(self, quantum_dim: int = 8):
        self.quantum_dim = quantum_dim
        self.document_states = {}
    
    def add_document(self, document: Document):
        """Add document with quantum state"""
        if document.quantum_state is None:
            document.quantum_state = self._create_quantum_state(document.content)
        
        self.document_states[document.id] = document.quantum_state
    
    def _create_quantum_state(self, content: str) -> QuantumState:
        """Create quantum state from document content"""
        state = QuantumState(self.quantum_dim)
        
        # Apply quantum gates based on content
        words = re.findall(r'\w+', content.lower())
        
        for i, word in enumerate(words[:self.quantum_dim]):
            # Use word hash to determine gate parameters
            word_hash = hash(word)
            angle = (word_hash % 100) / 100.0 * math.pi
            QuantumGate.rotation(state, angle, i % self.quantum_dim)
        
        # Apply entanglement
        for i in range(0, self.quantum_dim - 1, 2):
            QuantumGate.entangle(state, i, i + 1)
        
        return state
    
    def search(self, query: str, documents: List[Document], top_k: int = 5) -> List[Tuple[Document, float]]:
        """Search using quantum-inspired retrieval"""
        query_state = self._create_quantum_state(query)
        
        # Compute quantum similarities
        similarities = []
        for doc in documents:
            if doc.id in self.document_states:
                doc_state = self.document_states[doc.id]
                similarity = self._quantum_similarity(query_state, doc_state)
                similarities.append((doc, similarity))
        
        # Sort by similarity
        similarities.sort(key=lambda x: x[1], reverse=True)
        
        return similarities[:top_k]
    
    def _quantum_similarity(self, state1: QuantumState, state2: QuantumState) -> float:
        """Compute quantum similarity between two states"""
        if state1.dimension != state2.dimension:
            return 0.0
        
        # Compute overlap
        overlap = 0.0
        for i in range(state1.dimension):
            overlap += abs(state1.amplitudes[i] * state2.amplitudes[i])
        
        return overlap

class HybridRAGSystem:
    """Hybrid RAG system combining multiple retrieval methods"""
    
    def __init__(self, vector_dim: int = 128, quantum_dim: int = 8):
        self.vector_store = VectorStore(vector_dim)
        self.keyword_index = KeywordIndex()
        self.quantum_retrieval = QuantumRetrieval(quantum_dim)
        self.documents = []
        
        # Weights for different retrieval methods
        self.weights = {
            'semantic': 0.4,
            'keyword': 0.3,
            'quantum': 0.3
        }
    
    def add_document(self, document: Document):
        """Add document to all retrieval systems"""
        self.documents.append(document)
        self.vector_store.add_document(document)
        self.keyword_index.add_document(document)
        self.quantum_retrieval.add_document(document)
    
    def add_documents_from_directory(self, directory: str, file_extensions: List[str] = None):
        """Add documents from a directory"""
        if file_extensions is None:
            file_extensions = ['.py', '.js', '.ts', '.cs', '.java', '.cpp', '.h', '.txt', '.md']
        
        for root, dirs, files in os.walk(directory):
            for file in files:
                if any(file.endswith(ext) for ext in file_extensions):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                        
                        doc = Document(
                            id=file_path,
                            content=content,
                            metadata={
                                'file_path': file_path,
                                'file_name': file,
                                'file_size': len(content),
                                'file_type': os.path.splitext(file)[1]
                            }
                        )
                        
                        self.add_document(doc)
                        print(f"Added document: {file_path}")
                        
                    except Exception as e:
                        print(f"Error reading file {file_path}: {e}")
    
    def search(self, query: str, top_k: int = 10) -> List[SearchResult]:
        """Hybrid search combining all retrieval methods"""
        # Semantic search
        semantic_results = self.vector_store.search(query, top_k)
        
        # Keyword search
        keyword_results = self.keyword_index.search(query, top_k)
        
        # Quantum search
        quantum_results = self.quantum_retrieval.search(query, self.documents, top_k)
        
        # Combine results
        combined_results = self._combine_results(
            semantic_results, keyword_results, quantum_results, query
        )
        
        # Sort by combined score
        combined_results.sort(key=lambda x: x.score, reverse=True)
        
        return combined_results[:top_k]
    
    def _combine_results(self, semantic_results: List[Tuple[Document, float]],
                        keyword_results: List[Tuple[Document, float]],
                        quantum_results: List[Tuple[Document, float]],
                        query: str) -> List[SearchResult]:
        """Combine results from different retrieval methods"""
        doc_scores = defaultdict(lambda: {
            'semantic': 0.0,
            'keyword': 0.0,
            'quantum': 0.0,
            'document': None
        })
        
        # Collect semantic scores
        for doc, score in semantic_results:
            doc_scores[doc.id]['semantic'] = score
            doc_scores[doc.id]['document'] = doc
        
        # Collect keyword scores
        for doc, score in keyword_results:
            doc_scores[doc.id]['keyword'] = score
            if doc_scores[doc.id]['document'] is None:
                doc_scores[doc.id]['document'] = doc
        
        # Collect quantum scores
        for doc, score in quantum_results:
            doc_scores[doc.id]['quantum'] = score
            if doc_scores[doc.id]['document'] is None:
                doc_scores[doc.id]['document'] = doc
        
        # Combine scores
        combined_results = []
        for doc_id, scores in doc_scores.items():
            if scores['document'] is None:
                continue
            
            # Weighted combination
            combined_score = (
                scores['semantic'] * self.weights['semantic'] +
                scores['keyword'] * self.weights['keyword'] +
                scores['quantum'] * self.weights['quantum']
            )
            
            # Determine match type
            if scores['semantic'] > scores['keyword'] and scores['semantic'] > scores['quantum']:
                match_type = "semantic"
            elif scores['keyword'] > scores['quantum']:
                match_type = "keyword"
            else:
                match_type = "quantum"
            
            # Create explanation
            explanation = f"Semantic: {scores['semantic']:.3f}, Keyword: {scores['keyword']:.3f}, Quantum: {scores['quantum']:.3f}"
            
            result = SearchResult(
                document=scores['document'],
                score=combined_score,
                match_type=match_type,
                explanation=explanation
            )
            
            combined_results.append(result)
        
        return combined_results
    
    def generate_with_rag(self, model: QuantumInspiredLLM, tokenizer: BPETokenizer,
                         query: str, max_length: int = 100, temperature: float = 1.0) -> str:
        """Generate response using RAG"""
        # Retrieve relevant documents
        search_results = self.search(query, top_k=5)
        
        # Build context
        context_parts = []
        for result in search_results:
            context_parts.append(f"Document: {result.document.id}")
            context_parts.append(f"Content: {result.document.content[:500]}...")
            context_parts.append(f"Match: {result.match_type} (score: {result.score:.3f})")
            context_parts.append("---")
        
        context = "\n".join(context_parts)
        
        # Create enhanced prompt
        enhanced_prompt = f"""Context from codebase:
{context}

User Query: {query}

Response:"""
        
        # Generate response
        response = model.generate(tokenizer, enhanced_prompt, max_length, temperature)
        
        return response
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get RAG system statistics"""
        return {
            'total_documents': len(self.documents),
            'vector_store_size': len(self.vector_store.documents),
            'keyword_index_size': len(self.keyword_index.doc_keywords),
            'quantum_states': len(self.quantum_retrieval.document_states),
            'weights': self.weights
        }

# Example usage
if __name__ == "__main__":
    # Create RAG system
    rag = HybridRAGSystem()
    
    # Add sample documents
    sample_docs = [
        Document(
            id="doc1",
            content="def hello_world(): print('Hello, World!')",
            metadata={"type": "function"}
        ),
        Document(
            id="doc2",
            content="class MyClass: def __init__(self): self.value = 42",
            metadata={"type": "class"}
        ),
        Document(
            id="doc3",
            content="import os import sys def main(): print('Main function')",
            metadata={"type": "script"}
        )
    ]
    
    for doc in sample_docs:
        rag.add_document(doc)
    
    # Test search
    query = "hello world function"
    results = rag.search(query, top_k=3)
    
    print(f"Search results for '{query}':")
    for result in results:
        print(f"  {result.document.id}: {result.score:.3f} ({result.match_type})")
        print(f"    {result.explanation}")
    
    # Test with directory
    # rag.add_documents_from_directory("./", ['.py'])
    
    print(f"\nRAG Statistics: {rag.get_statistics()}")
