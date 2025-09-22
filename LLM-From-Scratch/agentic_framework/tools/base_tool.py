"""
Base Tool Interface and Abstract Classes
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class BaseTool(ABC):
    """Abstract base class for all tools"""
    
    def __init__(self, name: str, description: str, parameters: Dict[str, Any] = None):
        self.name = name
        self.description = description
        self.parameters = parameters or {}
        self.usage_count = 0
        self.last_used = None
        self.error_count = 0
    
    @abstractmethod
    def execute(self, **kwargs) -> Any:
        """Execute the tool with given parameters"""
        pass
    
    @abstractmethod
    def validate_parameters(self, **kwargs) -> bool:
        """Validate input parameters"""
        pass
    
    def get_schema(self) -> Dict[str, Any]:
        """Get the tool's parameter schema"""
        return {
            "name": self.name,
            "description": self.description,
            "parameters": self.parameters
        }
    
    def _log_usage(self):
        """Log tool usage"""
        self.usage_count += 1
        self.last_used = datetime.now()
        logger.info(f"Tool '{self.name}' used (count: {self.usage_count})")
    
    def _log_error(self, error: Exception):
        """Log tool error"""
        self.error_count += 1
        logger.error(f"Tool '{self.name}' error: {str(error)}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get tool usage statistics"""
        return {
            "name": self.name,
            "usage_count": self.usage_count,
            "error_count": self.error_count,
            "last_used": self.last_used.isoformat() if self.last_used else None,
            "success_rate": (self.usage_count - self.error_count) / max(self.usage_count, 1)
        }

class FileSystemTool(BaseTool):
    """Base class for file system operations"""
    
    def __init__(self, name: str, description: str, allowed_extensions: List[str] = None):
        super().__init__(name, description)
        self.allowed_extensions = allowed_extensions or []
    
    def validate_file_extension(self, file_path: str) -> bool:
        """Validate if file extension is allowed"""
        if not self.allowed_extensions:
            return True
        
        file_ext = file_path.split('.')[-1].lower()
        return file_ext in [ext.lower() for ext in self.allowed_extensions]

class NetworkTool(BaseTool):
    """Base class for network operations"""
    
    def __init__(self, name: str, description: str, rate_limit: int = 10):
        super().__init__(name, description)
        self.rate_limit = rate_limit
        self.request_times = []
    
    def check_rate_limit(self) -> bool:
        """Check if we're within rate limits"""
        now = datetime.now()
        # Remove requests older than 1 minute
        self.request_times = [t for t in self.request_times if (now - t).seconds < 60]
        
        return len(self.request_times) < self.rate_limit
    
    def record_request(self):
        """Record a request for rate limiting"""
        self.request_times.append(datetime.now())

class CodeAnalysisTool(BaseTool):
    """Base class for code analysis tools"""
    
    def __init__(self, name: str, description: str, supported_languages: List[str] = None):
        super().__init__(name, description)
        self.supported_languages = supported_languages or []
    
    def detect_language(self, file_path: str) -> str:
        """Detect programming language from file extension"""
        ext_to_lang = {
            '.py': 'python',
            '.js': 'javascript',
            '.ts': 'typescript',
            '.java': 'java',
            '.cpp': 'cpp',
            '.c': 'c',
            '.cs': 'csharp',
            '.go': 'go',
            '.rs': 'rust',
            '.php': 'php',
            '.rb': 'ruby',
            '.swift': 'swift',
            '.kt': 'kotlin',
            '.scala': 'scala',
            '.r': 'r',
            '.m': 'matlab',
            '.sh': 'bash',
            '.ps1': 'powershell',
            '.sql': 'sql',
            '.html': 'html',
            '.css': 'css',
            '.scss': 'scss',
            '.less': 'less',
            '.xml': 'xml',
            '.json': 'json',
            '.yaml': 'yaml',
            '.yml': 'yaml',
            '.toml': 'toml',
            '.ini': 'ini',
            '.cfg': 'config',
            '.conf': 'config'
        }
        
        import os
        _, ext = os.path.splitext(file_path)
        return ext_to_lang.get(ext.lower(), 'unknown')
    
    def validate_language(self, file_path: str) -> bool:
        """Validate if language is supported"""
        if not self.supported_languages:
            return True
        
        language = self.detect_language(file_path)
        return language in self.supported_languages

class ToolRegistry:
    """Registry for managing tools"""
    
    def __init__(self):
        self.tools: Dict[str, BaseTool] = {}
        self.categories: Dict[str, List[str]] = {}
    
    def register_tool(self, tool: BaseTool, category: str = "general"):
        """Register a tool"""
        self.tools[tool.name] = tool
        
        if category not in self.categories:
            self.categories[category] = []
        self.categories[category].append(tool.name)
        
        logger.info(f"Registered tool '{tool.name}' in category '{category}'")
    
    def get_tool(self, name: str) -> Optional[BaseTool]:
        """Get a tool by name"""
        return self.tools.get(name)
    
    def get_tools_by_category(self, category: str) -> List[BaseTool]:
        """Get all tools in a category"""
        tool_names = self.categories.get(category, [])
        return [self.tools[name] for name in tool_names if name in self.tools]
    
    def list_tools(self) -> List[Dict[str, Any]]:
        """List all registered tools"""
        return [tool.get_schema() for tool in self.tools.values()]
    
    def get_tool_stats(self) -> Dict[str, Any]:
        """Get statistics for all tools"""
        stats = {}
        for name, tool in self.tools.items():
            stats[name] = tool.get_stats()
        return stats
    
    def execute_tool(self, name: str, **kwargs) -> Any:
        """Execute a tool by name"""
        tool = self.get_tool(name)
        if not tool:
            raise ValueError(f"Tool '{name}' not found")
        
        if not tool.validate_parameters(**kwargs):
            raise ValueError(f"Invalid parameters for tool '{name}'")
        
        try:
            result = tool.execute(**kwargs)
            tool._log_usage()
            return result
        except Exception as e:
            tool._log_error(e)
            raise

# Global tool registry instance
tool_registry = ToolRegistry()
