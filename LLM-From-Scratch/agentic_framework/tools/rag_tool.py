"""
RAG (Retrieval-Augmented Generation) Tool for Codebase Search
"""

import os
import glob
import hashlib
from typing import List, Dict, Any, Optional
import json
import logging
from datetime import datetime

try:
    from langchain_community.vectorstores import Chroma
    from langchain_community.embeddings import OpenAIEmbeddings
    from langchain.text_splitter import RecursiveCharacterTextSplitter
    from langchain.schema import Document
    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False
    logging.warning("LangChain not available. RAG functionality will be limited.")

from .base_tool import BaseTool, FileSystemTool, tool_registry

logger = logging.getLogger(__name__)

class CodebaseIndexer:
    """Indexes codebase for RAG search"""
    
    def __init__(self, embedding_model: str = "text-embedding-ada-002", chunk_size: int = 1000, chunk_overlap: int = 200):
        self.embedding_model = embedding_model
        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap
        self.vector_store = None
        self.index_metadata = {}
        
        if LANGCHAIN_AVAILABLE:
            self.embeddings = OpenAIEmbeddings(model=embedding_model)
            self.text_splitter = RecursiveCharacterTextSplitter(
                chunk_size=chunk_size,
                chunk_overlap=chunk_overlap,
                separators=["\n\n", "\n", " ", ""]
            )
        else:
            self.embeddings = None
            self.text_splitter = None
    
    def index_codebase(self, root_path: str, file_patterns: List[str] = None) -> Dict[str, Any]:
        """Index the entire codebase"""
        if not LANGCHAIN_AVAILABLE:
            return {"error": "LangChain not available. Cannot perform vector indexing."}
        
        file_patterns = file_patterns or [
            "**/*.py", "**/*.js", "**/*.ts", "**/*.java", "**/*.cpp", "**/*.c",
            "**/*.cs", "**/*.go", "**/*.rs", "**/*.php", "**/*.rb", "**/*.swift",
            "**/*.kt", "**/*.scala", "**/*.r", "**/*.m", "**/*.sh", "**/*.ps1",
            "**/*.sql", "**/*.html", "**/*.css", "**/*.scss", "**/*.less",
            "**/*.xml", "**/*.json", "**/*.yaml", "**/*.yml", "**/*.toml",
            "**/*.ini", "**/*.cfg", "**/*.conf", "**/*.md", "**/*.txt"
        ]
        
        documents = []
        indexed_files = []
        total_size = 0
        
        logger.info(f"Starting codebase indexing from: {root_path}")
        
        for pattern in file_patterns:
            files = glob.glob(os.path.join(root_path, pattern), recursive=True)
            
            for file_path in files:
                try:
                    # Skip binary files and large files
                    if self._should_skip_file(file_path):
                        continue
                    
                    # Read file content
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    if not content.strip():
                        continue
                    
                    # Create document
                    doc = Document(
                        page_content=content,
                        metadata={
                            "source": file_path,
                            "file_name": os.path.basename(file_path),
                            "file_type": os.path.splitext(file_path)[1],
                            "file_size": len(content),
                            "last_modified": datetime.fromtimestamp(os.path.getmtime(file_path)).isoformat(),
                            "relative_path": os.path.relpath(file_path, root_path)
                        }
                    )
                    
                    # Split into chunks
                    chunks = self.text_splitter.split_documents([doc])
                    documents.extend(chunks)
                    
                    indexed_files.append(file_path)
                    total_size += len(content)
                    
                except Exception as e:
                    logger.warning(f"Failed to index file {file_path}: {str(e)}")
                    continue
        
        if not documents:
            return {"error": "No documents found to index"}
        
        # Create vector store
        try:
            self.vector_store = Chroma.from_documents(
                documents=documents,
                embedding=self.embeddings,
                persist_directory="./chroma_db"
            )
            
            # Save metadata
            self.index_metadata = {
                "root_path": root_path,
                "indexed_files": len(indexed_files),
                "total_documents": len(documents),
                "total_size": total_size,
                "indexed_at": datetime.now().isoformat(),
                "embedding_model": self.embedding_model,
                "chunk_size": self.chunk_size,
                "chunk_overlap": self.chunk_overlap
            }
            
            logger.info(f"Successfully indexed {len(indexed_files)} files into {len(documents)} documents")
            
            return {
                "success": True,
                "indexed_files": len(indexed_files),
                "total_documents": len(documents),
                "total_size": total_size,
                "metadata": self.index_metadata
            }
            
        except Exception as e:
            logger.error(f"Failed to create vector store: {str(e)}")
            return {"error": f"Failed to create vector store: {str(e)}"}
    
    def _should_skip_file(self, file_path: str) -> bool:
        """Determine if a file should be skipped"""
        # Skip binary files
        binary_extensions = {'.exe', '.dll', '.so', '.dylib', '.bin', '.dat', '.db', '.sqlite'}
        if os.path.splitext(file_path)[1].lower() in binary_extensions:
            return True
        
        # Skip large files (>1MB)
        try:
            if os.path.getsize(file_path) > 1024 * 1024:
                return True
        except:
            return True
        
        # Skip hidden files and directories
        if any(part.startswith('.') for part in os.path.split(file_path)):
            return True
        
        # Skip common build/cache directories
        skip_dirs = {'node_modules', '__pycache__', '.git', '.vscode', '.idea', 'build', 'dist', 'target'}
        if any(part in skip_dirs for part in os.path.split(file_path)):
            return True
        
        return False
    
    def search(self, query: str, k: int = 5, filter_metadata: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """Search the indexed codebase"""
        if not self.vector_store:
            return [{"error": "No index available. Please index the codebase first."}]
        
        try:
            # Perform similarity search
            results = self.vector_store.similarity_search(
                query=query,
                k=k,
                filter=filter_metadata
            )
            
            # Format results
            formatted_results = []
            for doc in results:
                formatted_results.append({
                    "content": doc.page_content,
                    "metadata": doc.metadata,
                    "relevance_score": getattr(doc, 'score', None)
                })
            
            return formatted_results
            
        except Exception as e:
            logger.error(f"Search failed: {str(e)}")
            return [{"error": f"Search failed: {str(e)}"}]

class FileSearchTool(FileSystemTool):
    """Tool for searching files in the codebase using RAG"""
    
    def __init__(self, root_path: str = "."):
        super().__init__(
            name="file_search",
            description="Search for code, functions, classes, or documentation in the codebase",
            allowed_extensions=[]
        )
        self.root_path = root_path
        self.indexer = CodebaseIndexer()
        self.is_indexed = False
    
    def validate_parameters(self, **kwargs) -> bool:
        """Validate search parameters"""
        required_params = ['query']
        return all(param in kwargs for param in required_params)
    
    def execute(self, query: str, k: int = 5, file_type: str = None, **kwargs) -> str:
        """Execute file search"""
        try:
            # Index codebase if not already indexed
            if not self.is_indexed:
                logger.info("Indexing codebase for first search...")
                index_result = self.indexer.index_codebase(self.root_path)
                if "error" in index_result:
                    return f"Failed to index codebase: {index_result['error']}"
                self.is_indexed = True
            
            # Prepare filter metadata
            filter_metadata = {}
            if file_type:
                filter_metadata["file_type"] = f".{file_type}"
            
            # Perform search
            results = self.indexer.search(query, k=k, filter_metadata=filter_metadata)
            
            if not results or "error" in results[0]:
                return f"No results found for query: '{query}'"
            
            # Format results
            formatted_results = []
            for i, result in enumerate(results, 1):
                if "error" in result:
                    continue
                
                content = result["content"]
                metadata = result["metadata"]
                
                # Truncate long content
                if len(content) > 500:
                    content = content[:500] + "..."
                
                formatted_results.append(f"""
Result {i}:
File: {metadata.get('relative_path', metadata.get('source', 'Unknown'))}
Type: {metadata.get('file_type', 'Unknown')}
Size: {metadata.get('file_size', 'Unknown')} bytes
Last Modified: {metadata.get('last_modified', 'Unknown')}

Content:
{content}
---""")
            
            return "\n".join(formatted_results) if formatted_results else f"No relevant results found for: '{query}'"
            
        except Exception as e:
            logger.error(f"File search error: {str(e)}")
            return f"Search error: {str(e)}"

class SimpleFileSearchTool(FileSystemTool):
    """Simple file search without vector embeddings (fallback)"""
    
    def __init__(self, root_path: str = "."):
        super().__init__(
            name="simple_file_search",
            description="Simple text-based file search in the codebase",
            allowed_extensions=[]
        )
        self.root_path = root_path
    
    def validate_parameters(self, **kwargs) -> bool:
        """Validate search parameters"""
        return 'query' in kwargs
    
    def execute(self, query: str, file_pattern: str = "**/*.py", max_results: int = 10, **kwargs) -> str:
        """Execute simple file search"""
        try:
            results = []
            query_lower = query.lower()
            
            # Search files
            files = glob.glob(os.path.join(self.root_path, file_pattern), recursive=True)
            
            for file_path in files[:50]:  # Limit to first 50 files for performance
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    if query_lower in content.lower():
                        # Find matching lines
                        lines = content.split('\n')
                        matching_lines = []
                        
                        for i, line in enumerate(lines):
                            if query_lower in line.lower():
                                matching_lines.append(f"  Line {i+1}: {line.strip()}")
                                if len(matching_lines) >= 3:  # Limit to 3 lines per file
                                    break
                        
                        if matching_lines:
                            relative_path = os.path.relpath(file_path, self.root_path)
                            results.append(f"""
File: {relative_path}
{chr(10).join(matching_lines)}
---""")
                            
                            if len(results) >= max_results:
                                break
                
                except Exception as e:
                    continue
            
            if not results:
                return f"No matches found for: '{query}'"
            
            return f"Found {len(results)} matching files:\n" + "\n".join(results)
            
        except Exception as e:
            logger.error(f"Simple file search error: {str(e)}")
            return f"Search error: {str(e)}"

# Register tools
if LANGCHAIN_AVAILABLE:
    tool_registry.register_tool(FileSearchTool(), "search")
else:
    tool_registry.register_tool(SimpleFileSearchTool(), "search")
