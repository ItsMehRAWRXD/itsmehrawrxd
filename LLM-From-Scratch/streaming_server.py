"""
Streaming LLM Server Implementation
Real-time token streaming with WebSocket and socket support
"""

import socket
import threading
import json
import time
import signal
import sys
import asyncio
import websockets
from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass
from tokenizer import BPETokenizer
from quantum_inspired_llm import QuantumInspiredLLM

@dataclass
class StreamingRequest:
    """Streaming request structure"""
    prompt: str
    max_length: int = 100
    temperature: float = 1.0
    stream: bool = True
    request_id: str = None
    client_type: str = "socket"  # "socket" or "websocket"

@dataclass
class StreamingResponse:
    """Streaming response structure"""
    token: str
    request_id: str
    is_final: bool = False
    timestamp: float = 0.0

class StreamingLLMServer:
    """LLM server with real-time streaming capabilities"""
    
    def __init__(self, host: str = '127.0.0.1', port: int = 65432, websocket_port: int = 65433):
        self.host = host
        self.socket_port = port
        self.websocket_port = websocket_port
        
        # Server components
        self.socket_server = None
        self.websocket_server = None
        self.running = False
        
        # Model components
        self.model = None
        self.tokenizer = None
        
        # Client management
        self.socket_clients = []
        self.websocket_clients = set()
        self.active_requests = {}
        
        # Statistics
        self.stats = {
            'requests_processed': 0,
            'tokens_streamed': 0,
            'active_connections': 0,
            'start_time': time.time(),
            'streaming_sessions': 0
        }
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        print(f"\nReceived signal {signum}, shutting down gracefully...")
        self.stop()
        sys.exit(0)
    
    def load_model(self, model_path: str = None, tokenizer_path: str = None):
        """Load the quantum-inspired model and tokenizer"""
        try:
            print("Loading quantum-inspired model...")
            
            # Create tokenizer
            self.tokenizer = BPETokenizer(vocab_size=1000)
            
            # Create sample training data if needed
            sample_text = """
            def hello_world():
                print("Hello, World!")
                return "success"
            
            class MyClass:
                def __init__(self):
                    self.value = 42
                
                def get_value(self):
                    return self.value
            
            def add_numbers(a, b):
                return a + b
            
            def multiply_numbers(a, b):
                return a * b
            
            def factorial(n):
                if n <= 1:
                    return 1
                return n * factorial(n - 1)
            
            def fibonacci(n):
                if n <= 1:
                    return n
                return fibonacci(n - 1) + fibonacci(n - 2)
            
            def is_prime(n):
                if n < 2:
                    return False
                for i in range(2, int(n ** 0.5) + 1):
                    if n % i == 0:
                        return False
                return True
            
            def bubble_sort(arr):
                n = len(arr)
                for i in range(n):
                    for j in range(0, n - i - 1):
                        if arr[j] > arr[j + 1]:
                            arr[j], arr[j + 1] = arr[j + 1], arr[j]
                return arr
            
            def binary_search(arr, target):
                left, right = 0, len(arr) - 1
                while left <= right:
                    mid = (left + right) // 2
                    if arr[mid] == target:
                        return mid
                    elif arr[mid] < target:
                        left = mid + 1
                    else:
                        right = mid - 1
                return -1
            
            import os
            import sys
            import json
            import math
            import random
            import datetime
            
            def main():
                print("Hello from main function!")
                data = [1, 2, 3, 4, 5]
                result = [x * 2 for x in data]
                print(f"Processed data: {result}")
            
            if __name__ == '__main__':
                main()
            """
            
            self.tokenizer.train(sample_text)
            
            # Create quantum-inspired model
            self.model = QuantumInspiredLLM(
                vocab_size=self.tokenizer.get_vocab_size(),
                d_model=128,
                num_heads=4,
                num_layers=2,
                d_ff=512,
                max_seq_len=256,
                quantum_dim=8
            )
            
            print(f"Model loaded successfully!")
            print(f"Vocabulary size: {self.tokenizer.get_vocab_size()}")
            print(f"Model parameters: {self.model.get_quantum_metrics()}")
            
        except Exception as e:
            print(f"Error loading model: {e}")
            raise
    
    def start(self):
        """Start both socket and WebSocket servers"""
        try:
            # Start socket server
            self._start_socket_server()
            
            # Start WebSocket server
            self._start_websocket_server()
            
            self.running = True
            print(f"Streaming LLM Server started:")
            print(f"  Socket server: {self.host}:{self.socket_port}")
            print(f"  WebSocket server: {self.host}:{self.websocket_port}")
            print("Waiting for connections...")
            
            # Keep main thread alive
            while self.running:
                time.sleep(1)
                
        except Exception as e:
            print(f"Server error: {e}")
        finally:
            self.stop()
    
    def _start_socket_server(self):
        """Start the socket server"""
        self.socket_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket_server.bind((self.host, self.socket_port))
        self.socket_server.listen(5)
        
        # Start socket server thread
        socket_thread = threading.Thread(target=self._socket_server_loop, daemon=True)
        socket_thread.start()
    
    def _start_websocket_server(self):
        """Start the WebSocket server"""
        # Start WebSocket server thread
        websocket_thread = threading.Thread(target=self._websocket_server_loop, daemon=True)
        websocket_thread.start()
    
    def _socket_server_loop(self):
        """Socket server main loop"""
        while self.running:
            try:
                client_socket, address = self.socket_server.accept()
                print(f"New socket connection from {address}")
                
                # Handle client in separate thread
                client_thread = threading.Thread(
                    target=self._handle_socket_client,
                    args=(client_socket, address),
                    daemon=True
                )
                client_thread.start()
                
            except socket.error as e:
                if self.running:
                    print(f"Socket server error: {e}")
                break
    
    def _websocket_server_loop(self):
        """WebSocket server main loop"""
        async def websocket_handler(websocket, path):
            """Handle WebSocket connections"""
            self.websocket_clients.add(websocket)
            self.stats['active_connections'] = len(self.websocket_clients)
            print(f"New WebSocket connection from {websocket.remote_address}")
            
            try:
                async for message in websocket:
                    try:
                        request_data = json.loads(message)
                        await self._handle_websocket_request(websocket, request_data)
                    except json.JSONDecodeError:
                        await websocket.send(json.dumps({
                            'error': 'Invalid JSON request'
                        }))
                    except Exception as e:
                        await websocket.send(json.dumps({
                            'error': f'Processing error: {str(e)}'
                        }))
            except websockets.exceptions.ConnectionClosed:
                pass
            finally:
                self.websocket_clients.discard(websocket)
                self.stats['active_connections'] = len(self.websocket_clients)
                print(f"WebSocket connection closed")
        
        # Start WebSocket server
        start_server = websockets.serve(websocket_handler, self.host, self.websocket_port)
        
        # Run the event loop
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(start_server)
        loop.run_forever()
    
    def _handle_socket_client(self, client_socket: socket.socket, address: tuple):
        """Handle individual socket client"""
        try:
            self.socket_clients.append(client_socket)
            self.stats['active_connections'] = len(self.socket_clients)
            
            while self.running:
                # Receive request
                data = client_socket.recv(4096)
                if not data:
                    break
                
                try:
                    request = json.loads(data.decode('utf-8'))
                    self._handle_socket_request(client_socket, request)
                except json.JSONDecodeError:
                    error_response = json.dumps({
                        'error': 'Invalid JSON request'
                    })
                    client_socket.sendall(error_response.encode('utf-8'))
                except Exception as e:
                    error_response = json.dumps({
                        'error': f'Processing error: {str(e)}'
                    })
                    client_socket.sendall(error_response.encode('utf-8'))
            
        except Exception as e:
            print(f"Socket client handling error: {e}")
        finally:
            if client_socket in self.socket_clients:
                self.socket_clients.remove(client_socket)
            self.stats['active_connections'] = len(self.socket_clients)
            client_socket.close()
            print(f"Socket client {address} disconnected")
    
    def _handle_socket_request(self, client_socket: socket.socket, request: Dict[str, Any]):
        """Handle socket request with streaming"""
        try:
            # Parse request
            prompt = request.get('prompt', '')
            max_length = request.get('max_length', 100)
            temperature = request.get('temperature', 1.0)
            stream = request.get('stream', True)
            request_id = request.get('request_id', str(time.time()))
            
            if not prompt:
                client_socket.sendall(json.dumps({
                    'error': 'Missing prompt field'
                }).encode('utf-8'))
                return
            
            # Start streaming generation
            if stream:
                self._stream_generation_socket(client_socket, prompt, max_length, temperature, request_id)
            else:
                # Non-streaming response
                generated_text = self.model.generate(
                    self.tokenizer, prompt, max_length, temperature
                )
                
                response = {
                    'success': True,
                    'generated_text': generated_text,
                    'request_id': request_id,
                    'timestamp': time.time()
                }
                
                client_socket.sendall(json.dumps(response).encode('utf-8'))
            
        except Exception as e:
            error_response = json.dumps({
                'error': f'Request processing error: {str(e)}'
            })
            client_socket.sendall(error_response.encode('utf-8'))
    
    def _stream_generation_socket(self, client_socket: socket.socket, prompt: str, 
                                 max_length: int, temperature: float, request_id: str):
        """Stream generation to socket client"""
        try:
            # Encode prompt
            input_ids = self.tokenizer.encode(prompt)
            
            # Stream tokens
            for i in range(max_length):
                # Forward pass
                logits = self.model.forward(input_ids)
                
                # Get next token probabilities
                next_token_logits = logits.data[-1]
                
                # Apply quantum-inspired sampling
                next_token_id = self.model._quantum_sampling(next_token_logits, temperature)
                
                # Convert to text
                next_token_text = self.tokenizer.decode([next_token_id])
                
                # Send token immediately
                response = {
                    'token': next_token_text,
                    'request_id': request_id,
                    'is_final': False,
                    'timestamp': time.time()
                }
                
                client_socket.sendall(json.dumps(response).encode('utf-8'))
                
                # Add to sequence
                input_ids.append(next_token_id)
                
                # Update statistics
                self.stats['tokens_streamed'] += 1
                
                # Stop if EOS token
                if next_token_id == self.tokenizer.get_eos_token_id():
                    break
            
            # Send final token
            final_response = {
                'token': '',
                'request_id': request_id,
                'is_final': True,
                'timestamp': time.time()
            }
            
            client_socket.sendall(json.dumps(final_response).encode('utf-8'))
            
            # Update statistics
            self.stats['requests_processed'] += 1
            self.stats['streaming_sessions'] += 1
            
        except Exception as e:
            error_response = json.dumps({
                'error': f'Streaming error: {str(e)}'
            })
            client_socket.sendall(error_response.encode('utf-8'))
    
    async def _handle_websocket_request(self, websocket, request: Dict[str, Any]):
        """Handle WebSocket request with streaming"""
        try:
            # Parse request
            prompt = request.get('prompt', '')
            max_length = request.get('max_length', 100)
            temperature = request.get('temperature', 1.0)
            request_id = request.get('request_id', str(time.time()))
            
            if not prompt:
                await websocket.send(json.dumps({
                    'error': 'Missing prompt field'
                }))
                return
            
            # Start streaming generation
            await self._stream_generation_websocket(websocket, prompt, max_length, temperature, request_id)
            
        except Exception as e:
            await websocket.send(json.dumps({
                'error': f'Request processing error: {str(e)}'
            }))
    
    async def _stream_generation_websocket(self, websocket, prompt: str, 
                                         max_length: int, temperature: float, request_id: str):
        """Stream generation to WebSocket client"""
        try:
            # Encode prompt
            input_ids = self.tokenizer.encode(prompt)
            
            # Stream tokens
            for i in range(max_length):
                # Forward pass
                logits = self.model.forward(input_ids)
                
                # Get next token probabilities
                next_token_logits = logits.data[-1]
                
                # Apply quantum-inspired sampling
                next_token_id = self.model._quantum_sampling(next_token_logits, temperature)
                
                # Convert to text
                next_token_text = self.tokenizer.decode([next_token_id])
                
                # Send token immediately
                response = {
                    'token': next_token_text,
                    'request_id': request_id,
                    'is_final': False,
                    'timestamp': time.time()
                }
                
                await websocket.send(json.dumps(response))
                
                # Add to sequence
                input_ids.append(next_token_id)
                
                # Update statistics
                self.stats['tokens_streamed'] += 1
                
                # Stop if EOS token
                if next_token_id == self.tokenizer.get_eos_token_id():
                    break
            
            # Send final token
            final_response = {
                'token': '',
                'request_id': request_id,
                'is_final': True,
                'timestamp': time.time()
            }
            
            await websocket.send(json.dumps(final_response))
            
            # Update statistics
            self.stats['requests_processed'] += 1
            self.stats['streaming_sessions'] += 1
            
        except Exception as e:
            await websocket.send(json.dumps({
                'error': f'Streaming error: {str(e)}'
            }))
    
    def get_stats(self) -> Dict[str, Any]:
        """Get server statistics"""
        self.stats['uptime'] = time.time() - self.stats['start_time']
        return self.stats.copy()
    
    def stop(self):
        """Stop the server"""
        print("Stopping streaming server...")
        self.running = False
        
        # Close socket clients
        for client in self.socket_clients:
            try:
                client.close()
            except:
                pass
        
        # Close socket server
        if self.socket_server:
            try:
                self.socket_server.close()
            except:
                pass
        
        print("Streaming server stopped")

# Example usage
if __name__ == "__main__":
    # Create and start streaming server
    server = StreamingLLMServer(host='127.0.0.1', port=65432, websocket_port=65433)
    
    try:
        # Load model
        server.load_model()
        
        # Start server
        server.start()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.stop()
    except Exception as e:
        print(f"Server error: {e}")
        server.stop()
