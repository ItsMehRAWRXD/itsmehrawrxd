"""
Inference Server Implementation
Socket-based server for LLM inference with IDE integration
"""

import socket
import threading
import json
import time
import signal
import sys
from typing import Dict, Any, Optional, List
from tokenizer import BPETokenizer
from transformer import Transformer
from training import Trainer

class LLMInferenceServer:
    """LLM Inference Server with socket communication"""
    
    def __init__(self, host: str = '127.0.0.1', port: int = 65432):
        self.host = host
        self.port = port
        self.socket = None
        self.running = False
        self.model = None
        self.tokenizer = None
        self.clients = []
        
        # Server statistics
        self.stats = {
            'requests_processed': 0,
            'total_tokens_generated': 0,
            'average_response_time': 0.0,
            'uptime': 0.0,
            'start_time': time.time()
        }
        
        # Request queue for handling multiple clients
        self.request_queue = []
        self.queue_lock = threading.Lock()
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        print(f"\nReceived signal {signum}, shutting down gracefully...")
        self.stop()
        sys.exit(0)
    
    def load_model(self, model_path: str, tokenizer_path: str):
        """Load the trained model and tokenizer"""
        try:
            print("Loading tokenizer...")
            self.tokenizer = BPETokenizer()
            self.tokenizer.load(tokenizer_path)
            
            print("Loading model...")
            # In a real implementation, you'd load the actual model weights
            # For now, we'll create a new model with the same architecture
            self.model = Transformer(
                vocab_size=self.tokenizer.get_vocab_size(),
                d_model=128,
                num_heads=4,
                num_layers=2,
                d_ff=512,
                max_seq_len=256
            )
            
            print(f"Model loaded successfully!")
            print(f"Vocabulary size: {self.tokenizer.get_vocab_size()}")
            
        except Exception as e:
            print(f"Error loading model: {e}")
            raise
    
    def start(self):
        """Start the inference server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.host, self.port))
            self.socket.listen(5)
            
            self.running = True
            print(f"LLM Inference Server started on {self.host}:{self.port}")
            print("Waiting for connections...")
            
            # Start statistics thread
            stats_thread = threading.Thread(target=self._stats_thread, daemon=True)
            stats_thread.start()
            
            # Start request processing thread
            processing_thread = threading.Thread(target=self._process_requests, daemon=True)
            processing_thread.start()
            
            # Main server loop
            while self.running:
                try:
                    client_socket, address = self.socket.accept()
                    print(f"New connection from {address}")
                    
                    # Handle client in a separate thread
                    client_thread = threading.Thread(
                        target=self._handle_client,
                        args=(client_socket, address),
                        daemon=True
                    )
                    client_thread.start()
                    
                except socket.error as e:
                    if self.running:
                        print(f"Socket error: {e}")
                    break
                    
        except Exception as e:
            print(f"Server error: {e}")
        finally:
            self.stop()
    
    def _handle_client(self, client_socket: socket.socket, address: tuple):
        """Handle individual client connection"""
        try:
            self.clients.append(client_socket)
            
            while self.running:
                # Receive request
                data = client_socket.recv(4096)
                if not data:
                    break
                
                try:
                    request = json.loads(data.decode('utf-8'))
                    response = self._process_request(request)
                    
                    # Send response
                    response_data = json.dumps(response).encode('utf-8')
                    client_socket.sendall(response_data)
                    
                except json.JSONDecodeError:
                    error_response = {
                        'success': False,
                        'error': 'Invalid JSON request'
                    }
                    client_socket.sendall(json.dumps(error_response).encode('utf-8'))
                
                except Exception as e:
                    error_response = {
                        'success': False,
                        'error': f'Processing error: {str(e)}'
                    }
                    client_socket.sendall(json.dumps(error_response).encode('utf-8'))
            
        except Exception as e:
            print(f"Client handling error: {e}")
        finally:
            if client_socket in self.clients:
                self.clients.remove(client_socket)
            client_socket.close()
            print(f"Client {address} disconnected")
    
    def _process_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Process a single inference request"""
        start_time = time.time()
        
        try:
            # Validate request
            if 'prompt' not in request:
                return {'success': False, 'error': 'Missing prompt field'}
            
            prompt = request['prompt']
            max_length = request.get('max_length', 100)
            temperature = request.get('temperature', 1.0)
            stream = request.get('stream', False)
            
            # Generate response
            if self.model is None or self.tokenizer is None:
                return {'success': False, 'error': 'Model not loaded'}
            
            generated_text = self.model.generate(
                self.tokenizer,
                prompt,
                max_length=max_length,
                temperature=temperature
            )
            
            # Update statistics
            processing_time = time.time() - start_time
            self.stats['requests_processed'] += 1
            self.stats['total_tokens_generated'] += len(generated_text.split())
            self.stats['average_response_time'] = (
                (self.stats['average_response_time'] * (self.stats['requests_processed'] - 1) + processing_time) /
                self.stats['requests_processed']
            )
            
            return {
                'success': True,
                'generated_text': generated_text,
                'prompt': prompt,
                'processing_time': processing_time,
                'tokens_generated': len(generated_text.split()),
                'timestamp': time.time()
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Generation error: {str(e)}',
                'processing_time': time.time() - start_time
            }
    
    def _process_requests(self):
        """Background thread for processing queued requests"""
        while self.running:
            time.sleep(0.1)  # Small delay to prevent busy waiting
    
    def _stats_thread(self):
        """Background thread for updating statistics"""
        while self.running:
            time.sleep(60)  # Update every minute
            self.stats['uptime'] = time.time() - self.stats['start_time']
    
    def get_stats(self) -> Dict[str, Any]:
        """Get server statistics"""
        self.stats['uptime'] = time.time() - self.stats['start_time']
        return self.stats.copy()
    
    def stop(self):
        """Stop the server"""
        print("Stopping server...")
        self.running = False
        
        # Close all client connections
        for client in self.clients:
            try:
                client.close()
            except:
                pass
        
        # Close server socket
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        
        print("Server stopped")

class IDEIntegration:
    """IDE integration utilities"""
    
    def __init__(self, server: LLMInferenceServer):
        self.server = server
    
    def generate_code_completion(self, context: str, language: str = "python") -> str:
        """Generate code completion for IDE"""
        prompt = f"Complete the following {language} code:\n\n{context}"
        
        request = {
            'prompt': prompt,
            'max_length': 50,
            'temperature': 0.7
        }
        
        response = self.server._process_request(request)
        
        if response['success']:
            return response['generated_text']
        else:
            return f"// Error: {response['error']}"
    
    def generate_code_explanation(self, code: str, language: str = "python") -> str:
        """Generate code explanation"""
        prompt = f"Explain the following {language} code:\n\n{code}\n\nExplanation:"
        
        request = {
            'prompt': prompt,
            'max_length': 200,
            'temperature': 0.5
        }
        
        response = self.server._process_request(request)
        
        if response['success']:
            return response['generated_text']
        else:
            return f"Error generating explanation: {response['error']}"
    
    def generate_code_refactor(self, code: str, language: str = "python") -> str:
        """Generate refactored code"""
        prompt = f"Refactor the following {language} code to be more efficient and readable:\n\n{code}\n\nRefactored code:"
        
        request = {
            'prompt': prompt,
            'max_length': 300,
            'temperature': 0.3
        }
        
        response = self.server._process_request(request)
        
        if response['success']:
            return response['generated_text']
        else:
            return f"Error generating refactored code: {response['error']}"
    
    def generate_documentation(self, code: str, language: str = "python") -> str:
        """Generate documentation for code"""
        prompt = f"Generate comprehensive documentation for the following {language} code:\n\n{code}\n\nDocumentation:"
        
        request = {
            'prompt': prompt,
            'max_length': 400,
            'temperature': 0.4
        }
        
        response = self.server._process_request(request)
        
        if response['success']:
            return response['generated_text']
        else:
            return f"Error generating documentation: {response['error']}"

# Example usage and testing
if __name__ == "__main__":
    # Create server
    server = LLMInferenceServer(host='127.0.0.1', port=65432)
    
    # Load model (you would need to train and save a model first)
    try:
        # For demonstration, we'll create a simple model
        from tokenizer import BPETokenizer
        from transformer import Transformer
        
        # Create a simple tokenizer
        tokenizer = BPETokenizer(vocab_size=1000)
        sample_text = "def hello_world(): print('Hello, World!')"
        tokenizer.train(sample_text)
        
        # Create a simple model
        model = Transformer(
            vocab_size=tokenizer.get_vocab_size(),
            d_model=64,
            num_heads=4,
            num_layers=2,
            d_ff=256,
            max_seq_len=128
        )
        
        server.model = model
        server.tokenizer = tokenizer
        
        print("Model and tokenizer loaded successfully!")
        
    except Exception as e:
        print(f"Error loading model: {e}")
        print("Starting server without model (for testing)")
    
    # Start server
    try:
        server.start()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.stop()
    except Exception as e:
        print(f"Server error: {e}")
        server.stop()
