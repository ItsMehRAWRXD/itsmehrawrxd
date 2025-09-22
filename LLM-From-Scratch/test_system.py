"""
Comprehensive Testing and Validation System
Tests for all LLM components and integration
"""

import unittest
import asyncio
import json
import time
import threading
import socket
from typing import List, Dict, Any
import numpy as np

# Import all LLM components
from tokenizer import BPETokenizer
from transformer import Transformer, Matrix, MathUtils
from quantum_inspired_llm import QuantumInspiredLLM, QuantumState, QuantumGate
from training import Trainer, CrossEntropyLoss, SGD, DataLoader
from inference_server import LLMInferenceServer
from streaming_server import StreamingLLMServer
from hybrid_rag_system import HybridRAGSystem, Document
from performance_optimizer import PerformanceOptimizer
from ide_client import LLMClient, IDEExtension, TerminalIntegration

class TestTokenizer(unittest.TestCase):
    """Test BPE tokenizer functionality"""
    
    def setUp(self):
        self.sample_text = """
        def hello_world():
            print("Hello, World!")
            return "success"
        
        class MyClass:
            def __init__(self):
                self.value = 42
        """
        self.tokenizer = BPETokenizer(vocab_size=500)
    
    def test_tokenizer_training(self):
        """Test tokenizer training"""
        self.tokenizer.train(self.sample_text)
        self.assertGreater(self.tokenizer.get_vocab_size(), 0)
    
    def test_encoding_decoding(self):
        """Test encoding and decoding"""
        self.tokenizer.train(self.sample_text)
        
        test_text = "def hello_world():"
        encoded = self.tokenizer.encode(test_text)
        decoded = self.tokenizer.decode(encoded)
        
        self.assertIsInstance(encoded, list)
        self.assertIsInstance(decoded, str)
        self.assertGreater(len(encoded), 0)
    
    def test_special_tokens(self):
        """Test special token handling"""
        self.tokenizer.train(self.sample_text)
        
        unk_id = self.tokenizer.get_unk_token_id()
        eos_id = self.tokenizer.get_eos_token_id()
        bos_id = self.tokenizer.get_bos_token_id()
        
        self.assertIsInstance(unk_id, int)
        self.assertIsInstance(eos_id, int)
        self.assertIsInstance(bos_id, int)

class TestTransformer(unittest.TestCase):
    """Test Transformer model functionality"""
    
    def setUp(self):
        self.vocab_size = 100
        self.model = Transformer(
            vocab_size=self.vocab_size,
            d_model=64,
            num_heads=4,
            num_layers=2,
            d_ff=256,
            max_seq_len=128
        )
    
    def test_forward_pass(self):
        """Test forward pass"""
        input_ids = [1, 2, 3, 4, 5]
        logits = self.model.forward(input_ids)
        
        self.assertEqual(logits.rows, len(input_ids))
        self.assertEqual(logits.cols, self.vocab_size)
    
    def test_matrix_operations(self):
        """Test matrix operations"""
        matrix_a = Matrix.random(3, 4, scale=0.1)
        matrix_b = Matrix.random(4, 2, scale=0.1)
        
        result = matrix_a.matmul(matrix_b)
        
        self.assertEqual(result.rows, 3)
        self.assertEqual(result.cols, 2)
    
    def test_softmax(self):
        """Test softmax function"""
        matrix = Matrix.random(2, 3, scale=1.0)
        softmax_result = matrix.softmax()
        
        # Check that rows sum to 1
        for i in range(softmax_result.rows):
            row_sum = sum(softmax_result.data[i])
            self.assertAlmostEqual(row_sum, 1.0, places=5)

class TestQuantumInspiredLLM(unittest.TestCase):
    """Test quantum-inspired LLM functionality"""
    
    def setUp(self):
        self.vocab_size = 100
        self.model = QuantumInspiredLLM(
            vocab_size=self.vocab_size,
            d_model=64,
            num_heads=4,
            num_layers=2,
            d_ff=256,
            max_seq_len=128,
            quantum_dim=8
        )
    
    def test_quantum_state(self):
        """Test quantum state operations"""
        state = QuantumState(4)
        
        # Test normalization
        state.normalize()
        norm = sum(abs(amp) ** 2 for amp in state.amplitudes)
        self.assertAlmostEqual(norm, 1.0, places=5)
        
        # Test measurement
        measurement = state.measure()
        self.assertIsInstance(measurement, int)
        self.assertGreaterEqual(measurement, 0)
        self.assertLess(measurement, state.dimension)
    
    def test_quantum_gates(self):
        """Test quantum gate operations"""
        state = QuantumState(4)
        initial_amplitudes = state.amplitudes.copy()
        
        # Test Hadamard gate
        QuantumGate.hadamard(state, 0)
        self.assertNotEqual(state.amplitudes, initial_amplitudes)
        
        # Test rotation gate
        QuantumGate.rotation(state, math.pi/4, 1)
        
        # Test entanglement
        QuantumGate.entangle(state, 0, 1)
    
    def test_forward_pass(self):
        """Test quantum-inspired forward pass"""
        input_ids = [1, 2, 3, 4, 5]
        logits = self.model.forward(input_ids)
        
        self.assertEqual(logits.rows, len(input_ids))
        self.assertEqual(logits.cols, self.vocab_size)
    
    def test_quantum_metrics(self):
        """Test quantum metrics"""
        metrics = self.model.get_quantum_metrics()
        
        self.assertIn('quantum_dimension', metrics)
        self.assertIn('num_quantum_layers', metrics)
        self.assertIn('quantum_entanglement_ratio', metrics)

class TestTraining(unittest.TestCase):
    """Test training functionality"""
    
    def setUp(self):
        self.sample_text = """
        def hello_world():
            print("Hello, World!")
            return "success"
        
        def add_numbers(a, b):
            return a + b
        
        def multiply_numbers(a, b):
            return a * b
        """
        
        self.tokenizer = BPETokenizer(vocab_size=200)
        self.tokenizer.train(self.sample_text)
        
        self.model = Transformer(
            vocab_size=self.tokenizer.get_vocab_size(),
            d_model=32,
            num_heads=2,
            num_layers=1,
            d_ff=128,
            max_seq_len=64
        )
    
    def test_cross_entropy_loss(self):
        """Test cross-entropy loss function"""
        predictions = Matrix.random(3, 5, scale=1.0)
        targets = [0, 1, 2]
        
        loss = CrossEntropyLoss().forward(predictions, targets)
        
        self.assertIsInstance(loss, float)
        self.assertGreaterEqual(loss, 0.0)
    
    def test_data_loader(self):
        """Test data loader"""
        data_loader = DataLoader(
            self.sample_text,
            self.tokenizer,
            batch_size=2,
            block_size=16
        )
        
        batch_count = 0
        for x_batch, y_batch in data_loader:
            batch_count += 1
            self.assertIsInstance(x_batch, list)
            self.assertIsInstance(y_batch, list)
            self.assertEqual(len(x_batch), len(y_batch))
            
            if batch_count >= 3:  # Limit test iterations
                break
        
        self.assertGreater(batch_count, 0)
    
    def test_trainer(self):
        """Test trainer functionality"""
        trainer = Trainer(
            model=self.model,
            tokenizer=self.tokenizer,
            learning_rate=0.01,
            batch_size=1,
            block_size=16
        )
        
        # Test parameter collection
        self.assertGreater(len(trainer.parameters), 0)
        
        # Test training epoch (simplified)
        data_loader = DataLoader(
            self.sample_text,
            self.tokenizer,
            batch_size=1,
            block_size=16
        )
        
        # Run one epoch
        loss = trainer.train_epoch(data_loader)
        self.assertIsInstance(loss, float)
        self.assertGreaterEqual(loss, 0.0)

class TestInferenceServer(unittest.TestCase):
    """Test inference server functionality"""
    
    def setUp(self):
        self.server = LLMInferenceServer(host='127.0.0.1', port=65432)
        self.server.load_model()
    
    def test_server_initialization(self):
        """Test server initialization"""
        self.assertIsNotNone(self.server.model)
        self.assertIsNotNone(self.server.tokenizer)
    
    def test_request_processing(self):
        """Test request processing"""
        request = {
            'prompt': 'def hello_world():',
            'max_length': 20,
            'temperature': 1.0
        }
        
        response = self.server._process_request(request)
        
        self.assertIn('success', response)
        self.assertIn('generated_text', response)
    
    def test_server_stats(self):
        """Test server statistics"""
        stats = self.server.get_stats()
        
        self.assertIn('requests_processed', stats)
        self.assertIn('total_tokens_generated', stats)
        self.assertIn('uptime', stats)

class TestStreamingServer(unittest.TestCase):
    """Test streaming server functionality"""
    
    def setUp(self):
        self.server = StreamingLLMServer(host='127.0.0.1', port=65432, websocket_port=65433)
        self.server.load_model()
    
    def test_streaming_generation(self):
        """Test streaming generation"""
        prompt = "def hello_world():"
        max_length = 10
        temperature = 1.0
        request_id = "test_request"
        
        # Mock client socket
        class MockSocket:
            def __init__(self):
                self.sent_data = []
            
            def sendall(self, data):
                self.sent_data.append(data)
        
        mock_socket = MockSocket()
        
        # Test streaming
        self.server._stream_generation_socket(
            mock_socket, prompt, max_length, temperature, request_id
        )
        
        self.assertGreater(len(mock_socket.sent_data), 0)
        
        # Verify JSON format
        for data in mock_socket.sent_data:
            try:
                parsed = json.loads(data.decode('utf-8'))
                self.assertIn('token', parsed)
                self.assertIn('request_id', parsed)
            except json.JSONDecodeError:
                self.fail("Invalid JSON sent to client")

class TestHybridRAGSystem(unittest.TestCase):
    """Test hybrid RAG system functionality"""
    
    def setUp(self):
        self.rag = HybridRAGSystem()
        
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
            self.rag.add_document(doc)
    
    def test_document_addition(self):
        """Test document addition"""
        self.assertEqual(len(self.rag.documents), 3)
        self.assertEqual(len(self.rag.vector_store.documents), 3)
        self.assertEqual(len(self.rag.keyword_index.doc_keywords), 3)
    
    def test_hybrid_search(self):
        """Test hybrid search"""
        query = "hello world function"
        results = self.rag.search(query, top_k=2)
        
        self.assertLessEqual(len(results), 2)
        
        for result in results:
            self.assertIsInstance(result.score, float)
            self.assertIn(result.match_type, ["semantic", "keyword", "quantum", "hybrid"])
            self.assertIsInstance(result.document, Document)
    
    def test_rag_generation(self):
        """Test RAG generation"""
        # Create a simple model for testing
        tokenizer = BPETokenizer(vocab_size=100)
        tokenizer.train("def hello_world(): print('Hello, World!')")
        
        model = QuantumInspiredLLM(
            vocab_size=tokenizer.get_vocab_size(),
            d_model=32,
            num_heads=2,
            num_layers=1,
            d_ff=128,
            max_seq_len=64,
            quantum_dim=4
        )
        
        query = "Write a hello world function"
        response = self.rag.generate_with_rag(model, tokenizer, query, max_length=20)
        
        self.assertIsInstance(response, str)
        self.assertGreater(len(response), 0)
    
    def test_statistics(self):
        """Test RAG statistics"""
        stats = self.rag.get_statistics()
        
        self.assertIn('total_documents', stats)
        self.assertIn('vector_store_size', stats)
        self.assertIn('keyword_index_size', stats)
        self.assertIn('quantum_states', stats)

class TestPerformanceOptimizer(unittest.TestCase):
    """Test performance optimizer functionality"""
    
    def setUp(self):
        self.optimizer = PerformanceOptimizer()
    
    def test_optimization_level(self):
        """Test optimization level detection"""
        self.assertIn(self.optimizer.optimization_level, ["cuda", "cpp", "python"])
    
    def test_matrix_multiplication(self):
        """Test optimized matrix multiplication"""
        matrix_a = [[1, 2], [3, 4]]
        matrix_b = [[5, 6], [7, 8]]
        
        result = self.optimizer.optimized_matrix_multiply(matrix_a, matrix_b)
        
        expected = [[19, 22], [43, 50]]
        
        for i in range(len(result)):
            for j in range(len(result[i])):
                self.assertAlmostEqual(result[i][j], expected[i][j], places=5)
    
    def test_softmax(self):
        """Test optimized softmax"""
        test_vector = [1.0, 2.0, 3.0, 4.0]
        result = self.optimizer.optimized_softmax(test_vector)
        
        # Check that result is a probability distribution
        self.assertAlmostEqual(sum(result), 1.0, places=5)
        
        for prob in result:
            self.assertGreaterEqual(prob, 0.0)
            self.assertLessEqual(prob, 1.0)
    
    def test_benchmark(self):
        """Test benchmarking"""
        results = self.optimizer.benchmark_operations(matrix_size=10)
        
        self.assertIsInstance(results, dict)
        self.assertIn('python_matrix_multiply', results)
        self.assertIn('python_softmax', results)
    
    def test_optimization_info(self):
        """Test optimization info"""
        info = self.optimizer.get_optimization_info()
        
        self.assertIn('optimization_level', info)
        self.assertIn('cuda_available', info)
        self.assertIn('cpp_extensions_available', info)
        self.assertIn('recommended_batch_size', info)
        self.assertIn('memory_usage', info)

class TestIDEClient(unittest.TestCase):
    """Test IDE client functionality"""
    
    def setUp(self):
        self.client = LLMClient(host='127.0.0.1', port=65432)
    
    def test_client_initialization(self):
        """Test client initialization"""
        self.assertEqual(self.client.host, '127.0.0.1')
        self.assertEqual(self.client.port, 65432)
        self.assertFalse(self.client.connected)
    
    def test_request_structure(self):
        """Test request structure"""
        from ide_client import LLMRequest
        
        request = LLMRequest(
            prompt="def hello_world():",
            max_length=50,
            temperature=1.0
        )
        
        self.assertEqual(request.prompt, "def hello_world():")
        self.assertEqual(request.max_length, 50)
        self.assertEqual(request.temperature, 1.0)
    
    def test_terminal_integration(self):
        """Test terminal integration"""
        terminal = TerminalIntegration(self.client)
        
        # Test command handling
        result = terminal.handle_command("llm", ["generate", "hello world"])
        self.assertIsInstance(result, str)
        
        result = terminal.handle_command("complete", ["def hello_world():"])
        self.assertIsInstance(result, str)
        
        result = terminal.handle_command("explain", ["def hello_world(): print('Hello')"])
        self.assertIsInstance(result, str)
        
        result = terminal.handle_command("stats", [])
        self.assertIsInstance(result, str)
    
    def test_client_stats(self):
        """Test client statistics"""
        stats = self.client.get_stats()
        
        self.assertIn('requests_sent', stats)
        self.assertIn('responses_received', stats)
        self.assertIn('connection_errors', stats)

class TestIntegration(unittest.TestCase):
    """Integration tests for the complete system"""
    
    def setUp(self):
        self.sample_text = """
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
        """
    
    def test_end_to_end_training(self):
        """Test end-to-end training pipeline"""
        # Create tokenizer
        tokenizer = BPETokenizer(vocab_size=500)
        tokenizer.train(self.sample_text)
        
        # Create model
        model = QuantumInspiredLLM(
            vocab_size=tokenizer.get_vocab_size(),
            d_model=64,
            num_heads=4,
            num_layers=2,
            d_ff=256,
            max_seq_len=128,
            quantum_dim=8
        )
        
        # Create trainer
        trainer = Trainer(
            model=model,
            tokenizer=tokenizer,
            learning_rate=0.01,
            batch_size=2,
            block_size=32
        )
        
        # Train for one epoch
        trainer.train(self.sample_text, num_epochs=1)
        
        # Test generation
        generated = model.generate(tokenizer, "def hello_world():", max_length=20)
        
        self.assertIsInstance(generated, str)
        self.assertGreater(len(generated), 0)
    
    def test_rag_integration(self):
        """Test RAG system integration"""
        # Create RAG system
        rag = HybridRAGSystem()
        
        # Add documents
        doc = Document(
            id="test_doc",
            content=self.sample_text,
            metadata={"type": "code"}
        )
        rag.add_document(doc)
        
        # Create model and tokenizer
        tokenizer = BPETokenizer(vocab_size=500)
        tokenizer.train(self.sample_text)
        
        model = QuantumInspiredLLM(
            vocab_size=tokenizer.get_vocab_size(),
            d_model=64,
            num_heads=4,
            num_layers=2,
            d_ff=256,
            max_seq_len=128,
            quantum_dim=8
        )
        
        # Test RAG generation
        query = "Write a hello world function"
        response = rag.generate_with_rag(model, tokenizer, query, max_length=30)
        
        self.assertIsInstance(response, str)
        self.assertGreater(len(response), 0)
    
    def test_performance_optimization(self):
        """Test performance optimization integration"""
        optimizer = PerformanceOptimizer()
        
        # Test with different matrix sizes
        for size in [10, 50, 100]:
            matrix_a = [[1.0 for _ in range(size)] for _ in range(size)]
            matrix_b = [[1.0 for _ in range(size)] for _ in range(size)]
            
            start_time = time.time()
            result = optimizer.optimized_matrix_multiply(matrix_a, matrix_b)
            end_time = time.time()
            
            self.assertEqual(len(result), size)
            self.assertEqual(len(result[0]), size)
            
            print(f"Matrix multiplication {size}x{size}: {end_time - start_time:.4f}s")

def run_performance_tests():
    """Run performance tests"""
    print("Running performance tests...")
    
    # Test tokenizer performance
    print("\n1. Tokenizer Performance:")
    tokenizer = BPETokenizer(vocab_size=1000)
    large_text = "def hello_world(): print('Hello, World!') " * 1000
    
    start_time = time.time()
    tokenizer.train(large_text)
    training_time = time.time() - start_time
    print(f"  Training time: {training_time:.4f}s")
    
    start_time = time.time()
    encoded = tokenizer.encode("def hello_world(): print('Hello, World!')")
    encoding_time = time.time() - start_time
    print(f"  Encoding time: {encoding_time:.4f}s")
    
    # Test model performance
    print("\n2. Model Performance:")
    model = QuantumInspiredLLM(
        vocab_size=tokenizer.get_vocab_size(),
        d_model=128,
        num_heads=4,
        num_layers=2,
        d_ff=512,
        max_seq_len=256,
        quantum_dim=8
    )
    
    start_time = time.time()
    logits = model.forward([1, 2, 3, 4, 5])
    forward_time = time.time() - start_time
    print(f"  Forward pass time: {forward_time:.4f}s")
    
    start_time = time.time()
    generated = model.generate(tokenizer, "def hello_world():", max_length=50)
    generation_time = time.time() - start_time
    print(f"  Generation time: {generation_time:.4f}s")
    
    # Test optimization performance
    print("\n3. Optimization Performance:")
    optimizer = PerformanceOptimizer()
    benchmark_results = optimizer.benchmark_operations(matrix_size=100)
    
    for operation, time_taken in benchmark_results.items():
        print(f"  {operation}: {time_taken:.4f}s")

if __name__ == "__main__":
    # Run unit tests
    print("Running unit tests...")
    unittest.main(argv=[''], exit=False, verbosity=2)
    
    # Run performance tests
    run_performance_tests()
    
    print("\nAll tests completed!")
