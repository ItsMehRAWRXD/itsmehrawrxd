"""
Main LLM Training and Inference Script
Complete pipeline for training and using the LLM from scratch
"""

import os
import sys
import argparse
import time
from typing import Optional

# Add current directory to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from tokenizer import BPETokenizer
from transformer import Transformer
from training import Trainer
from inference_server import LLMInferenceServer, IDEIntegration
from ide_client import LLMClient, IDEExtension, TerminalIntegration

def train_model(text_file: str, vocab_size: int = 1000, d_model: int = 128, 
                num_heads: int = 4, num_layers: int = 2, d_ff: int = 512,
                max_seq_len: int = 256, num_epochs: int = 10, 
                batch_size: int = 4, block_size: int = 64,
                learning_rate: float = 0.001, output_dir: str = "models"):
    """Train the LLM model"""
    
    print("=" * 60)
    print("LLM TRAINING PIPELINE")
    print("=" * 60)
    
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    
    # Load training text
    print(f"Loading training text from {text_file}...")
    try:
        with open(text_file, 'r', encoding='utf-8') as f:
            text = f.read()
        print(f"Loaded {len(text)} characters of training text")
    except FileNotFoundError:
        print(f"Error: Training file {text_file} not found")
        return False
    except Exception as e:
        print(f"Error loading training file: {e}")
        return False
    
    # Create and train tokenizer
    print("\n1. Training BPE Tokenizer...")
    tokenizer = BPETokenizer(vocab_size=vocab_size)
    tokenizer.train(text)
    
    # Save tokenizer
    tokenizer_path = os.path.join(output_dir, "tokenizer.json")
    tokenizer.save(tokenizer_path)
    print(f"Tokenizer saved to {tokenizer_path}")
    
    # Create model
    print("\n2. Creating Transformer Model...")
    model = Transformer(
        vocab_size=tokenizer.get_vocab_size(),
        d_model=d_model,
        num_heads=num_heads,
        num_layers=num_layers,
        d_ff=d_ff,
        max_seq_len=max_seq_len
    )
    print(f"Model created with {tokenizer.get_vocab_size()} vocabulary size")
    
    # Create trainer
    print("\n3. Setting up Trainer...")
    trainer = Trainer(
        model=model,
        tokenizer=tokenizer,
        learning_rate=learning_rate,
        batch_size=batch_size,
        block_size=block_size
    )
    
    # Train model
    print(f"\n4. Training Model for {num_epochs} epochs...")
    start_time = time.time()
    trainer.train(text, num_epochs=num_epochs)
    training_time = time.time() - start_time
    
    print(f"\nTraining completed in {training_time:.2f} seconds")
    
    # Save model
    model_path = os.path.join(output_dir, "model.json")
    trainer.save_model(model_path)
    print(f"Model saved to {model_path}")
    
    # Test generation
    print("\n5. Testing Model Generation...")
    test_prompts = [
        "def hello_world():",
        "class MyClass:",
        "import ",
        "# This is a comment",
        "if __name__ == '__main__':"
    ]
    
    for prompt in test_prompts:
        generated = model.generate(tokenizer, prompt, max_length=50)
        print(f"Prompt: {prompt}")
        print(f"Generated: {generated}")
        print("-" * 40)
    
    print("\nTraining pipeline completed successfully!")
    return True

def start_inference_server(model_dir: str = "models", host: str = "127.0.0.1", 
                          port: int = 65432):
    """Start the inference server"""
    
    print("=" * 60)
    print("LLM INFERENCE SERVER")
    print("=" * 60)
    
    # Create server
    server = LLMInferenceServer(host=host, port=port)
    
    # Load model
    tokenizer_path = os.path.join(model_dir, "tokenizer.json")
    model_path = os.path.join(model_dir, "model.json")
    
    if os.path.exists(tokenizer_path) and os.path.exists(model_path):
        try:
            server.load_model(model_path, tokenizer_path)
        except Exception as e:
            print(f"Error loading model: {e}")
            print("Starting server with default model...")
    else:
        print("Model files not found, starting server with default model...")
        # Create a simple default model
        from tokenizer import BPETokenizer
        from transformer import Transformer
        
        tokenizer = BPETokenizer(vocab_size=1000)
        sample_text = "def hello_world(): print('Hello, World!')"
        tokenizer.train(sample_text)
        
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
    
    # Start server
    try:
        server.start()
    except KeyboardInterrupt:
        print("\nShutting down server...")
        server.stop()
    except Exception as e:
        print(f"Server error: {e}")
        server.stop()

def test_client(host: str = "127.0.0.1", port: int = 65432):
    """Test the LLM client"""
    
    print("=" * 60)
    print("LLM CLIENT TEST")
    print("=" * 60)
    
    # Create client
    client = LLMClient(host=host, port=port)
    
    # Connect
    if not client.connect():
        print("Failed to connect to server")
        return False
    
    print("Connected to server successfully!")
    
    # Test various functions
    test_cases = [
        ("Basic generation", lambda: client.generate_text("def hello_world():")),
        ("Code completion", lambda: client.generate_code_completion("def add_numbers(a, b):")),
        ("Code explanation", lambda: client.generate_code_explanation("def factorial(n): return 1 if n <= 1 else n * factorial(n-1)")),
        ("Code refactoring", lambda: client.generate_code_refactor("x = 0\nfor i in range(10):\n    x = x + i")),
        ("Documentation", lambda: client.generate_documentation("def fibonacci(n): return n if n <= 1 else fibonacci(n-1) + fibonacci(n-2)"))
    ]
    
    for test_name, test_func in test_cases:
        print(f"\n{test_name}:")
        response = test_func()
        if response.success:
            print(f"Success: {response.generated_text[:100]}...")
        else:
            print(f"Error: {response.error}")
    
    # Test terminal integration
    print("\nTerminal Integration Test:")
    terminal = TerminalIntegration(client)
    result = terminal.handle_command("llm", ["Write a Python function to calculate the sum of a list"])
    print(f"Result: {result}")
    
    # Get statistics
    stats = client.get_stats()
    print(f"\nClient Statistics:")
    print(f"  Requests sent: {stats['requests_sent']}")
    print(f"  Responses received: {stats['responses_received']}")
    print(f"  Connection errors: {stats['connection_errors']}")
    
    # Disconnect
    client.disconnect()
    print("\nClient test completed!")
    return True

def create_sample_training_data(output_file: str = "sample_training_data.txt"):
    """Create sample training data for testing"""
    
    print("Creating sample training data...")
    
    sample_code = """
def hello_world():
    print("Hello, World!")
    return "success"

class MyClass:
    def __init__(self):
        self.value = 42
    
    def get_value(self):
        return self.value
    
    def set_value(self, new_value):
        self.value = new_value

def add_numbers(a, b):
    return a + b

def multiply_numbers(a, b):
    return a * b

def divide_numbers(a, b):
    if b == 0:
        raise ValueError("Cannot divide by zero")
    return a / b

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

def read_file(filename):
    try:
        with open(filename, 'r') as f:
            return f.read()
    except FileNotFoundError:
        print(f"File {filename} not found")
        return None

def write_file(filename, content):
    try:
        with open(filename, 'w') as f:
            f.write(content)
        return True
    except Exception as e:
        print(f"Error writing file: {e}")
        return False

def process_data(data):
    processed = []
    for item in data:
        if isinstance(item, (int, float)):
            processed.append(item * 2)
        elif isinstance(item, str):
            processed.append(item.upper())
    return processed

def validate_email(email):
    import re
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def format_currency(amount, currency="USD"):
    if currency == "USD":
        return f"${amount:.2f}"
    elif currency == "EUR":
        return f"€{amount:.2f}"
    else:
        return f"{amount:.2f} {currency}"

# This is a comment
x = 10
y = 20
z = x + y

if x > 5:
    print("x is greater than 5")
else:
    print("x is not greater than 5")

for i in range(10):
    print(f"Number: {i}")

while x < 100:
    x += 1
    print(x)

try:
    result = x / y
except ZeroDivisionError:
    print("Cannot divide by zero")

import os
import sys
import json
import math
import random
import datetime

def main():
    print("Hello from main function!")
    data = [1, 2, 3, 4, 5]
    result = process_data(data)
    print(f"Processed data: {result}")

if __name__ == '__main__':
    main()
"""
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(sample_code)
    
    print(f"Sample training data created: {output_file}")
    return output_file

def main():
    """Main function with command line interface"""
    
    parser = argparse.ArgumentParser(description="LLM From Scratch - Training and Inference")
    parser.add_argument("command", choices=["train", "serve", "test", "create-data"], 
                       help="Command to execute")
    parser.add_argument("--text-file", default="sample_training_data.txt", 
                       help="Training text file")
    parser.add_argument("--vocab-size", type=int, default=1000, 
                       help="Vocabulary size")
    parser.add_argument("--d-model", type=int, default=128, 
                       help="Model dimension")
    parser.add_argument("--num-heads", type=int, default=4, 
                       help="Number of attention heads")
    parser.add_argument("--num-layers", type=int, default=2, 
                       help="Number of transformer layers")
    parser.add_argument("--d-ff", type=int, default=512, 
                       help="Feed-forward dimension")
    parser.add_argument("--max-seq-len", type=int, default=256, 
                       help="Maximum sequence length")
    parser.add_argument("--num-epochs", type=int, default=10, 
                       help="Number of training epochs")
    parser.add_argument("--batch-size", type=int, default=4, 
                       help="Batch size")
    parser.add_argument("--block-size", type=int, default=64, 
                       help="Block size")
    parser.add_argument("--learning-rate", type=float, default=0.001, 
                       help="Learning rate")
    parser.add_argument("--output-dir", default="models", 
                       help="Output directory for models")
    parser.add_argument("--host", default="127.0.0.1", 
                       help="Server host")
    parser.add_argument("--port", type=int, default=65432, 
                       help="Server port")
    
    args = parser.parse_args()
    
    if args.command == "create-data":
        create_sample_training_data(args.text_file)
        
    elif args.command == "train":
        train_model(
            text_file=args.text_file,
            vocab_size=args.vocab_size,
            d_model=args.d_model,
            num_heads=args.num_heads,
            num_layers=args.num_layers,
            d_ff=args.d_ff,
            max_seq_len=args.max_seq_len,
            num_epochs=args.num_epochs,
            batch_size=args.batch_size,
            block_size=args.block_size,
            learning_rate=args.learning_rate,
            output_dir=args.output_dir
        )
        
    elif args.command == "serve":
        start_inference_server(
            model_dir=args.output_dir,
            host=args.host,
            port=args.port
        )
        
    elif args.command == "test":
        test_client(host=args.host, port=args.port)

if __name__ == "__main__":
    main()
