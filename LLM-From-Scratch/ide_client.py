"""
IDE Client Implementation
Client-side integration for IDE with LLM server
"""

import socket
import json
import threading
import time
from typing import Dict, Any, Optional, Callable, List
from dataclasses import dataclass

@dataclass
class LLMRequest:
    """LLM request structure"""
    prompt: str
    max_length: int = 100
    temperature: float = 1.0
    stream: bool = False
    request_id: str = None

@dataclass
class LLMResponse:
    """LLM response structure"""
    success: bool
    generated_text: str = ""
    error: str = ""
    processing_time: float = 0.0
    tokens_generated: int = 0
    timestamp: float = 0.0
    request_id: str = None

class LLMClient:
    """LLM client for IDE integration"""
    
    def __init__(self, host: str = '127.0.0.1', port: int = 65432):
        self.host = host
        self.port = port
        self.socket = None
        self.connected = False
        self.request_id_counter = 0
        self.pending_requests = {}
        self.response_callbacks = {}
        
        # Connection settings
        self.connection_timeout = 5.0
        self.request_timeout = 30.0
        self.reconnect_attempts = 3
        self.reconnect_delay = 1.0
        
        # Statistics
        self.stats = {
            'requests_sent': 0,
            'responses_received': 0,
            'connection_errors': 0,
            'total_response_time': 0.0,
            'last_request_time': 0.0
        }
    
    def connect(self) -> bool:
        """Connect to the LLM server"""
        for attempt in range(self.reconnect_attempts):
            try:
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.settimeout(self.connection_timeout)
                self.socket.connect((self.host, self.port))
                self.connected = True
                print(f"Connected to LLM server at {self.host}:{self.port}")
                return True
                
            except Exception as e:
                print(f"Connection attempt {attempt + 1} failed: {e}")
                if attempt < self.reconnect_attempts - 1:
                    time.sleep(self.reconnect_delay)
                else:
                    self.connected = False
                    return False
        
        return False
    
    def disconnect(self):
        """Disconnect from the LLM server"""
        self.connected = False
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
            self.socket = None
        print("Disconnected from LLM server")
    
    def send_request(self, request: LLMRequest, callback: Optional[Callable] = None) -> Optional[LLMResponse]:
        """Send a request to the LLM server"""
        if not self.connected:
            if not self.connect():
                return LLMResponse(success=False, error="Failed to connect to server")
        
        # Generate request ID
        request.request_id = str(self.request_id_counter)
        self.request_id_counter += 1
        
        # Store callback
        if callback:
            self.response_callbacks[request.request_id] = callback
        
        try:
            # Send request
            request_data = json.dumps({
                'prompt': request.prompt,
                'max_length': request.max_length,
                'temperature': request.temperature,
                'stream': request.stream,
                'request_id': request.request_id
            }).encode('utf-8')
            
            self.socket.sendall(request_data)
            self.stats['requests_sent'] += 1
            self.stats['last_request_time'] = time.time()
            
            # Wait for response
            response_data = self.socket.recv(4096)
            if not response_data:
                return LLMResponse(success=False, error="No response from server")
            
            # Parse response
            response_dict = json.loads(response_data.decode('utf-8'))
            response = LLMResponse(
                success=response_dict.get('success', False),
                generated_text=response_dict.get('generated_text', ''),
                error=response_dict.get('error', ''),
                processing_time=response_dict.get('processing_time', 0.0),
                tokens_generated=response_dict.get('tokens_generated', 0),
                timestamp=response_dict.get('timestamp', 0.0),
                request_id=response_dict.get('request_id', request.request_id)
            )
            
            # Update statistics
            self.stats['responses_received'] += 1
            self.stats['total_response_time'] += response.processing_time
            
            # Call callback if provided
            if request.request_id in self.response_callbacks:
                callback = self.response_callbacks.pop(request.request_id)
                callback(response)
            
            return response
            
        except Exception as e:
            self.stats['connection_errors'] += 1
            return LLMResponse(success=False, error=f"Request failed: {str(e)}")
    
    def generate_text(self, prompt: str, max_length: int = 100, 
                     temperature: float = 1.0) -> LLMResponse:
        """Generate text from a prompt"""
        request = LLMRequest(
            prompt=prompt,
            max_length=max_length,
            temperature=temperature
        )
        return self.send_request(request)
    
    def generate_code_completion(self, context: str, language: str = "python") -> LLMResponse:
        """Generate code completion"""
        prompt = f"Complete the following {language} code:\n\n{context}"
        return self.generate_text(prompt, max_length=50, temperature=0.7)
    
    def generate_code_explanation(self, code: str, language: str = "python") -> LLMResponse:
        """Generate code explanation"""
        prompt = f"Explain the following {language} code:\n\n{code}\n\nExplanation:"
        return self.generate_text(prompt, max_length=200, temperature=0.5)
    
    def generate_code_refactor(self, code: str, language: str = "python") -> LLMResponse:
        """Generate refactored code"""
        prompt = f"Refactor the following {language} code to be more efficient and readable:\n\n{code}\n\nRefactored code:"
        return self.generate_text(prompt, max_length=300, temperature=0.3)
    
    def generate_documentation(self, code: str, language: str = "python") -> LLMResponse:
        """Generate documentation for code"""
        prompt = f"Generate comprehensive documentation for the following {language} code:\n\n{code}\n\nDocumentation:"
        return self.generate_text(prompt, max_length=400, temperature=0.4)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get client statistics"""
        return self.stats.copy()

class IDEExtension:
    """IDE extension for LLM integration"""
    
    def __init__(self, client: LLMClient):
        self.client = client
        self.active = False
        self.current_file = None
        self.current_line = 0
        self.current_column = 0
        
        # Extension settings
        self.auto_complete_enabled = True
        self.explanation_enabled = True
        self.refactor_enabled = True
        self.documentation_enabled = True
        
        # Callbacks
        self.on_completion = None
        self.on_explanation = None
        self.on_refactor = None
        self.on_documentation = None
    
    def activate(self):
        """Activate the IDE extension"""
        self.active = True
        print("IDE Extension activated")
    
    def deactivate(self):
        """Deactivate the IDE extension"""
        self.active = False
        print("IDE Extension deactivated")
    
    def set_cursor_position(self, file: str, line: int, column: int):
        """Set current cursor position"""
        self.current_file = file
        self.current_line = line
        self.current_column = column
    
    def get_context(self, lines_before: int = 5, lines_after: int = 5) -> str:
        """Get code context around current position"""
        # This would read the actual file content in a real implementation
        # For now, return a placeholder
        return f"# Context from {self.current_file} at line {self.current_line}"
    
    def request_completion(self, context: str = None) -> str:
        """Request code completion"""
        if not self.active or not self.auto_complete_enabled:
            return ""
        
        if context is None:
            context = self.get_context()
        
        response = self.client.generate_code_completion(context)
        
        if response.success:
            if self.on_completion:
                self.on_completion(response.generated_text)
            return response.generated_text
        else:
            print(f"Completion error: {response.error}")
            return ""
    
    def request_explanation(self, code: str = None) -> str:
        """Request code explanation"""
        if not self.active or not self.explanation_enabled:
            return ""
        
        if code is None:
            code = self.get_context()
        
        response = self.client.generate_code_explanation(code)
        
        if response.success:
            if self.on_explanation:
                self.on_explanation(response.generated_text)
            return response.generated_text
        else:
            print(f"Explanation error: {response.error}")
            return ""
    
    def request_refactor(self, code: str = None) -> str:
        """Request code refactoring"""
        if not self.active or not self.refactor_enabled:
            return ""
        
        if code is None:
            code = self.get_context()
        
        response = self.client.generate_code_refactor(code)
        
        if response.success:
            if self.on_refactor:
                self.on_refactor(response.generated_text)
            return response.generated_text
        else:
            print(f"Refactor error: {response.error}")
            return ""
    
    def request_documentation(self, code: str = None) -> str:
        """Request code documentation"""
        if not self.active or not self.documentation_enabled:
            return ""
        
        if code is None:
            code = self.get_context()
        
        response = self.client.generate_documentation(code)
        
        if response.success:
            if self.on_documentation:
                self.on_documentation(response.generated_text)
            return response.generated_text
        else:
            print(f"Documentation error: {response.error}")
            return ""

class TerminalIntegration:
    """Terminal integration for LLM client"""
    
    def __init__(self, client: LLMClient):
        self.client = client
        self.commands = {
            'llm': self._handle_llm_command,
            'complete': self._handle_complete_command,
            'explain': self._handle_explain_command,
            'refactor': self._handle_refactor_command,
            'doc': self._handle_doc_command,
            'stats': self._handle_stats_command
        }
    
    def handle_command(self, command: str, args: List[str]) -> str:
        """Handle terminal command"""
        if command in self.commands:
            return self.commands[command](args)
        else:
            return f"Unknown command: {command}"
    
    def _handle_llm_command(self, args: List[str]) -> str:
        """Handle 'llm' command"""
        if not args:
            return "Usage: llm <prompt>"
        
        prompt = " ".join(args)
        response = self.client.generate_text(prompt)
        
        if response.success:
            return response.generated_text
        else:
            return f"Error: {response.error}"
    
    def _handle_complete_command(self, args: List[str]) -> str:
        """Handle 'complete' command"""
        if not args:
            return "Usage: complete <code_context>"
        
        context = " ".join(args)
        response = self.client.generate_code_completion(context)
        
        if response.success:
            return response.generated_text
        else:
            return f"Error: {response.error}"
    
    def _handle_explain_command(self, args: List[str]) -> str:
        """Handle 'explain' command"""
        if not args:
            return "Usage: explain <code>"
        
        code = " ".join(args)
        response = self.client.generate_code_explanation(code)
        
        if response.success:
            return response.generated_text
        else:
            return f"Error: {response.error}"
    
    def _handle_refactor_command(self, args: List[str]) -> str:
        """Handle 'refactor' command"""
        if not args:
            return "Usage: refactor <code>"
        
        code = " ".join(args)
        response = self.client.generate_code_refactor(code)
        
        if response.success:
            return response.generated_text
        else:
            return f"Error: {response.error}"
    
    def _handle_doc_command(self, args: List[str]) -> str:
        """Handle 'doc' command"""
        if not args:
            return "Usage: doc <code>"
        
        code = " ".join(args)
        response = self.client.generate_documentation(code)
        
        if response.success:
            return response.generated_text
        else:
            return f"Error: {response.error}"
    
    def _handle_stats_command(self, args: List[str]) -> str:
        """Handle 'stats' command"""
        stats = self.client.get_stats()
        return f"LLM Client Statistics:\n" \
               f"  Requests sent: {stats['requests_sent']}\n" \
               f"  Responses received: {stats['responses_received']}\n" \
               f"  Connection errors: {stats['connection_errors']}\n" \
               f"  Average response time: {stats['total_response_time'] / max(stats['responses_received'], 1):.3f}s"

# Example usage
if __name__ == "__main__":
    # Create client
    client = LLMClient()
    
    # Connect to server
    if client.connect():
        print("Connected to LLM server")
        
        # Test basic generation
        response = client.generate_text("def hello_world():")
        if response.success:
            print(f"Generated: {response.generated_text}")
        else:
            print(f"Error: {response.error}")
        
        # Test code completion
        response = client.generate_code_completion("def add_numbers(a, b):")
        if response.success:
            print(f"Completion: {response.generated_text}")
        else:
            print(f"Error: {response.error}")
        
        # Test terminal integration
        terminal = TerminalIntegration(client)
        result = terminal.handle_command("llm", ["Write a Python function to calculate factorial"])
        print(f"Terminal result: {result}")
        
        # Disconnect
        client.disconnect()
    else:
        print("Failed to connect to LLM server")
