"""
API Server for Agentic Framework
Provides REST API endpoints for agent communication and management
"""

import json
import logging
import asyncio
from typing import Dict, Any, List, Optional
from datetime import datetime
import traceback

from flask import Flask, request, jsonify, stream_with_context
from flask_cors import CORS
import threading

# Import our components
from agent_orchestrator import AgentOrchestrator
from tools.base_tool import tool_registry

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AgenticAPIServer:
    """API server for the agentic framework"""
    
    def __init__(self, host: str = "0.0.0.0", port: int = 8000):
        self.host = host
        self.port = port
        self.app = Flask(__name__)
        self.agent_orchestrator = None
        self.initialized = False
        
        # Configure CORS
        CORS(self.app, origins=["*"])
        
        # Setup routes
        self._setup_routes()
        
        # Initialize in background
        self._initialize_async()
    
    def _setup_routes(self):
        """Setup API routes"""
        
        @self.app.route('/api/health', methods=['GET'])
        def health_check():
            """Health check endpoint"""
            return jsonify({
                "status": "healthy",
                "timestamp": datetime.now().isoformat(),
                "initialized": self.initialized,
                "agent_available": self.agent_orchestrator is not None
            })
        
        @self.app.route('/api/agent/process', methods=['POST'])
        def process_request():
            """Process agent request"""
            try:
                if not self.initialized:
                    return jsonify({"error": "Agent not initialized"}), 503
                
                data = request.get_json()
                if not data or 'prompt' not in data:
                    return jsonify({"error": "Missing 'prompt' field"}), 400
                
                prompt = data['prompt']
                max_iterations = data.get('max_iterations', 10)
                temperature = data.get('temperature', 0.7)
                
                # Process request
                result = self.agent_orchestrator.process_request(prompt)
                
                return jsonify({
                    "success": True,
                    "result": result,
                    "timestamp": datetime.now().isoformat()
                })
                
            except Exception as e:
                logger.error(f"Error processing request: {str(e)}")
                return jsonify({
                    "error": str(e),
                    "traceback": traceback.format_exc()
                }), 500
        
        @self.app.route('/api/agent/stream', methods=['POST'])
        def process_request_stream():
            """Process agent request with streaming response"""
            try:
                if not self.initialized:
                    return jsonify({"error": "Agent not initialized"}), 503
                
                data = request.get_json()
                if not data or 'prompt' not in data:
                    return jsonify({"error": "Missing 'prompt' field"}), 400
                
                prompt = data['prompt']
                
                @stream_with_context
                def generate():
                    try:
                        # This is a simplified streaming implementation
                        # In a real implementation, you'd stream the reasoning steps
                        yield f"data: {json.dumps({'type': 'start', 'message': 'Processing request...'})}\n\n"
                        
                        result = self.agent_orchestrator.process_request(prompt)
                        
                        yield f"data: {json.dumps({'type': 'reasoning', 'steps': result.get('reasoning_steps', [])})}\n\n"
                        yield f"data: {json.dumps({'type': 'tools', 'results': result.get('tool_results', [])})}\n\n"
                        yield f"data: {json.dumps({'type': 'response', 'content': result.get('response', '')})}\n\n"
                        yield f"data: {json.dumps({'type': 'complete'})}\n\n"
                        
                    except Exception as e:
                        yield f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"
                
                return self.app.response_class(
                    generate(),
                    mimetype='text/plain',
                    headers={'Cache-Control': 'no-cache'}
                )
                
            except Exception as e:
                logger.error(f"Error in streaming request: {str(e)}")
                return jsonify({"error": str(e)}), 500
        
        @self.app.route('/api/tools/list', methods=['GET'])
        def list_tools():
            """List available tools"""
            try:
                tools = tool_registry.list_tools()
                return jsonify({
                    "success": True,
                    "tools": tools,
                    "count": len(tools)
                })
            except Exception as e:
                logger.error(f"Error listing tools: {str(e)}")
                return jsonify({"error": str(e)}), 500
        
        @self.app.route('/api/tools/execute', methods=['POST'])
        def execute_tool():
            """Execute a specific tool"""
            try:
                data = request.get_json()
                if not data or 'tool_name' not in data:
                    return jsonify({"error": "Missing 'tool_name' field"}), 400
                
                tool_name = data['tool_name']
                tool_params = data.get('params', {})
                
                # Execute tool
                result = tool_registry.execute_tool(tool_name, **tool_params)
                
                return jsonify({
                    "success": True,
                    "tool": tool_name,
                    "params": tool_params,
                    "result": result,
                    "timestamp": datetime.now().isoformat()
                })
                
            except Exception as e:
                logger.error(f"Error executing tool: {str(e)}")
                return jsonify({"error": str(e)}), 500
        
        @self.app.route('/api/tools/stats', methods=['GET'])
        def get_tool_stats():
            """Get tool usage statistics"""
            try:
                stats = tool_registry.get_tool_stats()
                return jsonify({
                    "success": True,
                    "stats": stats
                })
            except Exception as e:
                logger.error(f"Error getting tool stats: {str(e)}")
                return jsonify({"error": str(e)}), 500
        
        @self.app.route('/api/agent/status', methods=['GET'])
        def get_agent_status():
            """Get agent status and configuration"""
            try:
                status = {
                    "initialized": self.initialized,
                    "agent_available": self.agent_orchestrator is not None,
                    "tools_count": len(tool_registry.tools),
                    "timestamp": datetime.now().isoformat()
                }
                
                if self.agent_orchestrator:
                    status.update({
                        "max_iterations": self.agent_orchestrator.max_iterations,
                        "tools": list(self.agent_orchestrator.tools.keys())
                    })
                
                return jsonify({
                    "success": True,
                    "status": status
                })
                
            except Exception as e:
                logger.error(f"Error getting agent status: {str(e)}")
                return jsonify({"error": str(e)}), 500
        
        @self.app.route('/api/agent/configure', methods=['POST'])
        def configure_agent():
            """Configure agent parameters"""
            try:
                if not self.initialized:
                    return jsonify({"error": "Agent not initialized"}), 503
                
                data = request.get_json()
                if not data:
                    return jsonify({"error": "No configuration data provided"}), 400
                
                # Update agent configuration
                if 'max_iterations' in data:
                    self.agent_orchestrator.max_iterations = data['max_iterations']
                
                return jsonify({
                    "success": True,
                    "message": "Agent configuration updated",
                    "timestamp": datetime.now().isoformat()
                })
                
            except Exception as e:
                logger.error(f"Error configuring agent: {str(e)}")
                return jsonify({"error": str(e)}), 500
        
        @self.app.route('/api/search/codebase', methods=['POST'])
        def search_codebase():
            """Search codebase using RAG"""
            try:
                data = request.get_json()
                if not data or 'query' not in data:
                    return jsonify({"error": "Missing 'query' field"}), 400
                
                query = data['query']
                root_path = data.get('root_path', '.')
                max_results = data.get('max_results', 5)
                
                # Use file search tool
                file_search_tool = tool_registry.get_tool('file_search')
                if not file_search_tool:
                    return jsonify({"error": "File search tool not available"}), 503
                
                result = file_search_tool.execute(
                    query=query,
                    k=max_results,
                    file_type=data.get('file_type')
                )
                
                return jsonify({
                    "success": True,
                    "query": query,
                    "results": result,
                    "timestamp": datetime.now().isoformat()
                })
                
            except Exception as e:
                logger.error(f"Error searching codebase: {str(e)}")
                return jsonify({"error": str(e)}), 500
        
        @self.app.route('/api/search/web', methods=['POST'])
        def search_web():
            """Search web using DuckDuckGo"""
            try:
                data = request.get_json()
                if not data or 'query' not in data:
                    return jsonify({"error": "Missing 'query' field"}), 400
                
                query = data['query']
                max_results = data.get('max_results', 5)
                search_type = data.get('search_type', 'web')
                
                # Use web search tool
                web_search_tool = tool_registry.get_tool('web_search')
                if not web_search_tool:
                    return jsonify({"error": "Web search tool not available"}), 503
                
                result = web_search_tool.execute(
                    query=query,
                    max_results=max_results,
                    search_type=search_type
                )
                
                return jsonify({
                    "success": True,
                    "query": query,
                    "results": result,
                    "timestamp": datetime.now().isoformat()
                })
                
            except Exception as e:
                logger.error(f"Error searching web: {str(e)}")
                return jsonify({"error": str(e)}), 500
        
        @self.app.route('/api/explain/code', methods=['POST'])
        def explain_code():
            """Explain code using agentic framework"""
            try:
                if not self.initialized:
                    return jsonify({"error": "Agent not initialized"}), 503
                
                data = request.get_json()
                if not data or 'code' not in data:
                    return jsonify({"error": "Missing 'code' field"}), 400
                
                code = data['code']
                language = data.get('language', 'text')
                
                prompt = f"Explain this {language} code: {code}"
                result = self.agent_orchestrator.process_request(prompt)
                
                return jsonify({
                    "success": True,
                    "code": code,
                    "language": language,
                    "explanation": result.get('response', ''),
                    "reasoning_steps": result.get('reasoning_steps', []),
                    "timestamp": datetime.now().isoformat()
                })
                
            except Exception as e:
                logger.error(f"Error explaining code: {str(e)}")
                return jsonify({"error": str(e)}), 500
        
        @self.app.route('/api/suggest/code', methods=['POST'])
        def suggest_code():
            """Suggest code improvements using agentic framework"""
            try:
                if not self.initialized:
                    return jsonify({"error": "Agent not initialized"}), 503
                
                data = request.get_json()
                if not data or 'code' not in data:
                    return jsonify({"error": "Missing 'code' field"}), 400
                
                code = data['code']
                language = data.get('language', 'text')
                
                prompt = f"Suggest improvements for this {language} code: {code}"
                result = self.agent_orchestrator.process_request(prompt)
                
                return jsonify({
                    "success": True,
                    "code": code,
                    "language": language,
                    "suggestions": result.get('response', ''),
                    "reasoning_steps": result.get('reasoning_steps', []),
                    "timestamp": datetime.now().isoformat()
                })
                
            except Exception as e:
                logger.error(f"Error suggesting code: {str(e)}")
                return jsonify({"error": str(e)}), 500
        
        @self.app.route('/api/complete/code', methods=['POST'])
        def complete_code():
            """Complete code using quantum-inspired model"""
            try:
                data = request.get_json()
                if not data or 'code' not in data:
                    return jsonify({"error": "Missing 'code' field"}), 400
                
                code = data['code']
                language = data.get('language', 'text')
                max_length = data.get('max_length', 50)
                temperature = data.get('temperature', 0.7)
                
                # This would use the quantum-inspired model directly
                # For now, we'll use the agent orchestrator
                if self.initialized:
                    prompt = f"Complete this {language} code: {code}"
                    result = self.agent_orchestrator.process_request(prompt)
                    completion = result.get('response', '')
                else:
                    completion = "// Agent not initialized"
                
                return jsonify({
                    "success": True,
                    "code": code,
                    "language": language,
                    "completion": completion,
                    "timestamp": datetime.now().isoformat()
                })
                
            except Exception as e:
                logger.error(f"Error completing code: {str(e)}")
                return jsonify({"error": str(e)}), 500
    
    def _initialize_async(self):
        """Initialize the agent orchestrator asynchronously"""
        def init_worker():
            try:
                logger.info("Initializing agent orchestrator...")
                
                # Create mock LLM client
                class MockLLMClient:
                    def generate(self, prompt: str, temperature: float = 0.7, max_tokens: int = 500) -> str:
                        # Simple mock response
                        return f"Mock response to: {prompt[:50]}..."
                
                llm_client = MockLLMClient()
                
                # Get available tools
                tools = {}
                for tool_name in tool_registry.tools:
                    tool = tool_registry.get_tool(tool_name)
                    if tool:
                        tools[tool_name] = tool
                
                # Create agent orchestrator
                self.agent_orchestrator = AgentOrchestrator(llm_client, tools, max_iterations=10)
                self.initialized = True
                
                logger.info("Agent orchestrator initialized successfully")
                
            except Exception as e:
                logger.error(f"Failed to initialize agent orchestrator: {str(e)}")
                self.initialized = False
        
        # Start initialization in background thread
        thread = threading.Thread(target=init_worker, daemon=True)
        thread.start()
    
    def run(self, debug: bool = False):
        """Run the API server"""
        logger.info(f"Starting Agentic API Server on {self.host}:{self.port}")
        self.app.run(host=self.host, port=self.port, debug=debug, threaded=True)

def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Agentic Framework API Server')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=8000, help='Port to bind to')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    
    args = parser.parse_args()
    
    server = AgenticAPIServer(host=args.host, port=args.port)
    server.run(debug=args.debug)

if __name__ == "__main__":
    main()
