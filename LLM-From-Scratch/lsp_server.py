"""
Language Server Protocol (LSP) Server for Quantum-Inspired LLM
Provides IDE integration for code completion, analysis, and generation
"""

import json
import sys
import threading
import logging
from typing import Dict, Any, List, Optional
import asyncio
from datetime import datetime

# Import our quantum-inspired components
from quantum_inspired_llm import QuantumInspiredTransformer, VOCABULARY, EMBEDDING_DIM
from agentic_framework.agent_orchestrator import AgentOrchestrator
from agentic_framework.tools.base_tool import tool_registry

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class QuantumLSPModel:
    """Wrapper for quantum-inspired model with LSP-specific functionality"""
    
    def __init__(self):
        self.model = QuantumInspiredTransformer(
            vocab_size=len(VOCABULARY),
            d_model=EMBEDDING_DIM,
            num_heads=8,
            num_layers=6
        )
        self.agent_orchestrator = None
        self.initialized = False
    
    def initialize_agent(self):
        """Initialize the agentic framework"""
        try:
            # Create mock LLM client for the orchestrator
            class MockLLMClient:
                def generate(self, prompt: str, temperature: float = 0.7, max_tokens: int = 500) -> str:
                    return self.model.generate(prompt, max_length=50, temperature=temperature)
            
            llm_client = MockLLMClient()
            
            # Get tools from registry
            tools = {}
            for tool_name in tool_registry.tools:
                tools[tool_name] = tool_registry.get_tool(tool_name)
            
            self.agent_orchestrator = AgentOrchestrator(llm_client, tools)
            self.initialized = True
            logger.info("Agent orchestrator initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize agent: {str(e)}")
            self.initialized = False
    
    def generate_completion(self, code: str, position: Dict[str, int], language: str = "csharp") -> List[Dict[str, Any]]:
        """Generate code completions"""
        try:
            if not self.initialized:
                self.initialize_agent()
            
            # Create context-aware prompt
            context_prompt = self._create_completion_prompt(code, position, language)
            
            # Generate completion using the model
            completion = self.model.generate(context_prompt, max_length=30, temperature=0.3)
            
            # Parse completion into LSP format
            completions = self._parse_completion(completion, language)
            
            return completions
            
        except Exception as e:
            logger.error(f"Completion generation error: {str(e)}")
            return []
    
    def generate_code_explanation(self, code: str, language: str = "csharp") -> str:
        """Generate code explanation using agentic framework"""
        try:
            if not self.initialized:
                self.initialize_agent()
            
            # Use agentic framework for comprehensive analysis
            prompt = f"Explain this {language} code: {code}"
            result = self.agent_orchestrator.process_request(prompt)
            
            return result.get("response", "Unable to generate explanation")
            
        except Exception as e:
            logger.error(f"Code explanation error: {str(e)}")
            return f"Error generating explanation: {str(e)}"
    
    def generate_code_suggestion(self, code: str, language: str = "csharp") -> str:
        """Generate code improvement suggestions"""
        try:
            if not self.initialized:
                self.initialize_agent()
            
            prompt = f"Suggest improvements for this {language} code: {code}"
            result = self.agent_orchestrator.process_request(prompt)
            
            return result.get("response", "No suggestions available")
            
        except Exception as e:
            logger.error(f"Code suggestion error: {str(e)}")
            return f"Error generating suggestions: {str(e)}"
    
    def _create_completion_prompt(self, code: str, position: Dict[str, int], language: str) -> str:
        """Create context-aware prompt for code completion"""
        lines = code.split('\n')
        line_num = position.get('line', 0)
        char_num = position.get('character', 0)
        
        # Get context around cursor
        context_lines = []
        start_line = max(0, line_num - 5)
        end_line = min(len(lines), line_num + 5)
        
        for i in range(start_line, end_line):
            if i < len(lines):
                context_lines.append(lines[i])
        
        context = '\n'.join(context_lines)
        
        # Create language-specific prompt
        if language.lower() == 'csharp':
            prompt = f"C# code completion at line {line_num + 1}, character {char_num + 1}:\n{context}\nComplete the code:"
        elif language.lower() == 'python':
            prompt = f"Python code completion at line {line_num + 1}, character {char_num + 1}:\n{context}\nComplete the code:"
        else:
            prompt = f"{language} code completion at line {line_num + 1}, character {char_num + 1}:\n{context}\nComplete the code:"
        
        return prompt
    
    def _parse_completion(self, completion: str, language: str) -> List[Dict[str, Any]]:
        """Parse completion into LSP format"""
        completions = []
        
        # Split completion into potential items
        items = completion.split('\n')
        
        for i, item in enumerate(items[:5]):  # Limit to 5 completions
            item = item.strip()
            if item and len(item) > 1:
                completion_item = {
                    "label": item,
                    "kind": self._get_completion_kind(item, language),
                    "detail": f"Quantum LLM completion {i + 1}",
                    "insertText": item,
                    "sortText": f"{i:02d}_{item}"
                }
                completions.append(completion_item)
        
        return completions
    
    def _get_completion_kind(self, item: str, language: str) -> int:
        """Get LSP completion kind"""
        # LSP completion kinds
        kinds = {
            'Text': 1,
            'Method': 2,
            'Function': 3,
            'Constructor': 4,
            'Field': 5,
            'Variable': 6,
            'Class': 7,
            'Interface': 8,
            'Module': 9,
            'Property': 10,
            'Unit': 11,
            'Value': 12,
            'Enum': 13,
            'Keyword': 14,
            'Snippet': 15,
            'Color': 16,
            'File': 17,
            'Reference': 18,
            'Folder': 19,
            'EnumMember': 20,
            'Constant': 21,
            'Struct': 22,
            'Event': 23,
            'Operator': 24,
            'TypeParameter': 25
        }
        
        # Simple heuristics for completion kind
        if language.lower() == 'csharp':
            if item.startswith('public ') or item.startswith('private ') or item.startswith('protected '):
                return kinds['Method']
            elif item.startswith('class ') or item.startswith('interface '):
                return kinds['Class']
            elif item.startswith('var ') or item.startswith('int ') or item.startswith('string '):
                return kinds['Variable']
            elif item in ['if', 'for', 'while', 'foreach', 'switch', 'try', 'catch']:
                return kinds['Keyword']
        
        return kinds['Text']  # Default to text

class QuantumLSPServer:
    """Language Server Protocol server for quantum-inspired LLM"""
    
    def __init__(self):
        self.model = QuantumLSPModel()
        self.running = False
        self.request_id = 0
        self.capabilities = {
            "textDocumentSync": 1,  # Full document sync
            "completionProvider": {
                "resolveProvider": False,
                "triggerCharacters": ['.', ' ', '(', '{', '[']
            },
            "hoverProvider": True,
            "signatureHelpProvider": {
                "triggerCharacters": ['(', ',']
            },
            "definitionProvider": True,
            "referencesProvider": True,
            "documentHighlightProvider": True,
            "documentSymbolProvider": True,
            "codeActionProvider": True,
            "codeLensProvider": {
                "resolveProvider": False
            },
            "documentFormattingProvider": True,
            "documentRangeFormattingProvider": True,
            "documentOnTypeFormattingProvider": {
                "firstTriggerCharacter": '}',
                "moreTriggerCharacter": [';', '\n']
            },
            "renameProvider": True,
            "foldingRangeProvider": True
        }
    
    def start(self):
        """Start the LSP server"""
        self.running = True
        logger.info("Quantum LSP Server started")
        
        try:
            while self.running:
                # Read JSON-RPC message from stdin
                line = sys.stdin.readline()
                if not line:
                    break
                
                try:
                    message = json.loads(line.strip())
                    response = self._handle_message(message)
                    
                    if response:
                        print(json.dumps(response))
                        sys.stdout.flush()
                        
                except json.JSONDecodeError as e:
                    logger.error(f"JSON decode error: {str(e)}")
                    self._send_error_response(None, -32700, "Parse error", str(e))
                except Exception as e:
                    logger.error(f"Message handling error: {str(e)}")
                    self._send_error_response(None, -32603, "Internal error", str(e))
                    
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
        except Exception as e:
            logger.error(f"Server error: {str(e)}")
        finally:
            self.running = False
            logger.info("Quantum LSP Server stopped")
    
    def _handle_message(self, message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Handle incoming LSP message"""
        method = message.get('method')
        msg_id = message.get('id')
        params = message.get('params', {})
        
        logger.debug(f"Handling method: {method}")
        
        if method == 'initialize':
            return self._handle_initialize(msg_id, params)
        elif method == 'initialized':
            return self._handle_initialized(msg_id, params)
        elif method == 'textDocument/completion':
            return self._handle_completion(msg_id, params)
        elif method == 'textDocument/hover':
            return self._handle_hover(msg_id, params)
        elif method == 'textDocument/signatureHelp':
            return self._handle_signature_help(msg_id, params)
        elif method == 'textDocument/definition':
            return self._handle_definition(msg_id, params)
        elif method == 'textDocument/references':
            return self._handle_references(msg_id, params)
        elif method == 'textDocument/documentHighlight':
            return self._handle_document_highlight(msg_id, params)
        elif method == 'textDocument/documentSymbol':
            return self._handle_document_symbol(msg_id, params)
        elif method == 'textDocument/codeAction':
            return self._handle_code_action(msg_id, params)
        elif method == 'textDocument/formatting':
            return self._handle_formatting(msg_id, params)
        elif method == 'textDocument/rangeFormatting':
            return self._handle_range_formatting(msg_id, params)
        elif method == 'textDocument/onTypeFormatting':
            return self._handle_on_type_formatting(msg_id, params)
        elif method == 'textDocument/rename':
            return self._handle_rename(msg_id, params)
        elif method == 'textDocument/foldingRange':
            return self._handle_folding_range(msg_id, params)
        elif method == 'shutdown':
            return self._handle_shutdown(msg_id, params)
        elif method == 'exit':
            self.running = False
            return None
        else:
            logger.warning(f"Unknown method: {method}")
            return None
    
    def _handle_initialize(self, msg_id: Any, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle initialize request"""
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "capabilities": self.capabilities,
                "serverInfo": {
                    "name": "Quantum LLM Language Server",
                    "version": "1.0.0"
                }
            }
        }
    
    def _handle_initialized(self, msg_id: Any, params: Dict[str, Any]) -> None:
        """Handle initialized notification"""
        logger.info("Client initialized")
        # Initialize the model
        self.model.initialize_agent()
    
    def _handle_completion(self, msg_id: Any, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle completion request"""
        try:
            text_document = params.get('textDocument', {})
            position = params.get('position', {})
            
            # Get document content (simplified - in real implementation, you'd track document state)
            uri = text_document.get('uri', '')
            language = self._get_language_from_uri(uri)
            
            # For demo purposes, use a sample code
            code = "public class MyClass {\n    public void MyMethod() {\n        // cursor here\n    }\n}"
            
            completions = self.model.generate_completion(code, position, language)
            
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "isIncomplete": False,
                    "items": completions
                }
            }
            
        except Exception as e:
            logger.error(f"Completion error: {str(e)}")
            return self._send_error_response(msg_id, -32603, "Internal error", str(e))
    
    def _handle_hover(self, msg_id: Any, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle hover request"""
        try:
            text_document = params.get('textDocument', {})
            position = params.get('position', {})
            
            # Get code around cursor
            code = "public class MyClass {\n    public void MyMethod() {\n        // hover here\n    }\n}"
            language = self._get_language_from_uri(text_document.get('uri', ''))
            
            explanation = self.model.generate_code_explanation(code, language)
            
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "contents": {
                        "kind": "markdown",
                        "value": f"**Quantum LLM Analysis**\n\n{explanation}"
                    }
                }
            }
            
        except Exception as e:
            logger.error(f"Hover error: {str(e)}")
            return self._send_error_response(msg_id, -32603, "Internal error", str(e))
    
    def _handle_signature_help(self, msg_id: Any, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle signature help request"""
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "signatures": [
                    {
                        "label": "MyMethod(int param1, string param2)",
                        "documentation": "A method with parameters",
                        "parameters": [
                            {"label": "int param1", "documentation": "First parameter"},
                            {"label": "string param2", "documentation": "Second parameter"}
                        ]
                    }
                ],
                "activeSignature": 0,
                "activeParameter": 0
            }
        }
    
    def _handle_definition(self, msg_id: Any, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle definition request"""
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "uri": params.get('textDocument', {}).get('uri', ''),
                "range": {
                    "start": {"line": 0, "character": 0},
                    "end": {"line": 0, "character": 10}
                }
            }
        }
    
    def _handle_references(self, msg_id: Any, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle references request"""
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": []
        }
    
    def _handle_document_highlight(self, msg_id: Any, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle document highlight request"""
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": []
        }
    
    def _handle_document_symbol(self, msg_id: Any, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle document symbol request"""
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": [
                {
                    "name": "MyClass",
                    "kind": 7,  # Class
                    "range": {
                        "start": {"line": 0, "character": 0},
                        "end": {"line": 10, "character": 0}
                    },
                    "selectionRange": {
                        "start": {"line": 0, "character": 13},
                        "end": {"line": 0, "character": 20}
                    }
                }
            ]
        }
    
    def _handle_code_action(self, msg_id: Any, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle code action request"""
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": [
                {
                    "title": "Generate method implementation",
                    "kind": "quickfix",
                    "edit": {
                        "changes": {
                            params.get('textDocument', {}).get('uri', ''): [
                                {
                                    "range": {
                                        "start": {"line": 2, "character": 0},
                                        "end": {"line": 2, "character": 0}
                                    },
                                    "newText": "        // Generated implementation\n"
                                }
                            ]
                        }
                    }
                }
            ]
        }
    
    def _handle_formatting(self, msg_id: Any, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle document formatting request"""
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": []
        }
    
    def _handle_range_formatting(self, msg_id: Any, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle range formatting request"""
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": []
        }
    
    def _handle_on_type_formatting(self, msg_id: Any, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle on-type formatting request"""
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": []
        }
    
    def _handle_rename(self, msg_id: Any, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle rename request"""
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "changes": {}
            }
        }
    
    def _handle_folding_range(self, msg_id: Any, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle folding range request"""
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": []
        }
    
    def _handle_shutdown(self, msg_id: Any, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle shutdown request"""
        self.running = False
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": None
        }
    
    def _get_language_from_uri(self, uri: str) -> str:
        """Extract language from file URI"""
        if uri.endswith('.cs'):
            return 'csharp'
        elif uri.endswith('.py'):
            return 'python'
        elif uri.endswith('.js'):
            return 'javascript'
        elif uri.endswith('.ts'):
            return 'typescript'
        elif uri.endswith('.java'):
            return 'java'
        elif uri.endswith('.cpp') or uri.endswith('.c'):
            return 'cpp'
        else:
            return 'text'
    
    def _send_error_response(self, msg_id: Any, code: int, message: str, data: Any = None) -> Dict[str, Any]:
        """Send error response"""
        response = {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {
                "code": code,
                "message": message
            }
        }
        
        if data is not None:
            response["error"]["data"] = data
        
        return response

def main():
    """Main entry point for the LSP server"""
    server = QuantumLSPServer()
    server.start()

if __name__ == "__main__":
    main()
