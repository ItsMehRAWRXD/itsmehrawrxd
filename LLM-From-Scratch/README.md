# Quantum-Inspired LLM from Scratch

A complete implementation of a Large Language Model (LLM) built from scratch using pure Python, featuring quantum-inspired architectures, streaming capabilities, and production-ready deployment infrastructure.

## 🚀 Features

### Core Components
- **BPE Tokenizer**: Complete Byte-Pair Encoding implementation with vocabulary management
- **Transformer Architecture**: Full multi-head attention and feed-forward networks
- **Quantum-Inspired Layers**: Hybrid classical-quantum attention mechanisms
- **Training Pipeline**: Complete training loop with backpropagation and optimization
- **Streaming Server**: Real-time token generation with WebSocket and socket support
- **Hybrid RAG System**: Combines semantic, keyword, and quantum-inspired retrieval
- **Performance Optimization**: C++ extensions and CUDA acceleration support
- **IDE Integration**: Complete integration with VS Code and terminal systems

### Advanced Features
- **Quantum State Operations**: Quantum gates, entanglement, and measurement
- **Multi-Provider Support**: OpenAI, Anthropic, and local model integration
- **Docker Deployment**: Complete containerization with scaling support
- **Monitoring**: Prometheus and Grafana integration
- **Load Balancing**: Nginx configuration for production deployment
- **Comprehensive Testing**: Unit tests, integration tests, and performance benchmarks

## 📁 Project Structure

```
LLM-From-Scratch/
├── tokenizer.py              # BPE tokenizer implementation
├── transformer.py            # Classical transformer architecture
├── quantum_inspired_llm.py   # Quantum-inspired hybrid model
├── training.py               # Training pipeline and optimization
├── inference_server.py       # Basic inference server
├── streaming_server.py       # Real-time streaming server
├── hybrid_rag_system.py      # Hybrid RAG with multiple retrieval methods
├── performance_optimizer.py  # C++/CUDA optimization layer
├── ide_client.py             # IDE integration client
├── main.py                   # Main training and inference script
├── test_system.py            # Comprehensive testing suite
├── Dockerfile                # Docker containerization
├── docker-compose.yml        # Multi-service deployment
├── nginx.conf                # Load balancer configuration
├── requirements.txt          # Python dependencies
└── README.md                 # This file
```

## 🛠️ Installation

### Prerequisites
- Python 3.9+
- CUDA 11.8+ (optional, for GPU acceleration)
- Docker and Docker Compose (for deployment)
- GCC/G++ (for C++ extensions)

### Local Installation

1. **Clone the repository**
```bash
git clone <repository-url>
cd LLM-From-Scratch
```

2. **Install dependencies**
```bash
pip install -r requirements.txt
```

3. **Compile C++ extensions (optional)**
```bash
python -c "from performance_optimizer import PerformanceOptimizer; PerformanceOptimizer()"
```

### Docker Installation

1. **Build and run with Docker Compose**
```bash
docker-compose up --build
```

2. **Run with GPU support**
```bash
docker-compose up --build llm-server-gpu
```

## 🚀 Quick Start

### 1. Create Training Data
```bash
python main.py create-data
```

### 2. Train the Model
```bash
python main.py train --text-file sample_training_data.txt --num-epochs 10
```

### 3. Start the Server
```bash
python main.py serve
```

### 4. Test the Client
```bash
python main.py test
```

### 5. Run Tests
```bash
python test_system.py
```

## 📖 Usage Examples

### Basic Text Generation
```python
from tokenizer import BPETokenizer
from quantum_inspired_llm import QuantumInspiredLLM

# Create and train tokenizer
tokenizer = BPETokenizer(vocab_size=1000)
tokenizer.train("Your training text here...")

# Create quantum-inspired model
model = QuantumInspiredLLM(
    vocab_size=tokenizer.get_vocab_size(),
    d_model=128,
    num_heads=4,
    num_layers=2,
    d_ff=512,
    quantum_dim=8
)

# Generate text
generated = model.generate(tokenizer, "def hello_world():", max_length=100)
print(generated)
```

### Streaming Generation
```python
from streaming_server import StreamingLLMServer

# Create streaming server
server = StreamingLLMServer(host='127.0.0.1', port=65432)
server.load_model()
server.start()
```

### RAG System
```python
from hybrid_rag_system import HybridRAGSystem, Document

# Create RAG system
rag = HybridRAGSystem()

# Add documents
doc = Document(
    id="code_doc",
    content="def hello_world(): print('Hello, World!')",
    metadata={"type": "function"}
)
rag.add_document(doc)

# Search and generate
results = rag.search("hello world function", top_k=5)
response = rag.generate_with_rag(model, tokenizer, "Write a hello function")
```

### IDE Integration
```python
from ide_client import LLMClient, TerminalIntegration

# Create client
client = LLMClient(host='127.0.0.1', port=65432)

# Terminal integration
terminal = TerminalIntegration(client)
result = terminal.handle_command("llm", ["generate", "Write a Python function"])
```

## 🔧 Configuration

### Model Configuration
```python
model = QuantumInspiredLLM(
    vocab_size=1000,        # Vocabulary size
    d_model=512,            # Model dimension
    num_heads=8,            # Number of attention heads
    num_layers=6,           # Number of transformer layers
    d_ff=2048,              # Feed-forward dimension
    max_seq_len=1024,       # Maximum sequence length
    quantum_dim=16          # Quantum dimension
)
```

### Server Configuration
```python
server = StreamingLLMServer(
    host='127.0.0.1',       # Server host
    port=65432,             # Socket port
    websocket_port=65433    # WebSocket port
)
```

### RAG Configuration
```python
rag = HybridRAGSystem(
    vector_dim=128,         # Vector embedding dimension
    quantum_dim=8           # Quantum retrieval dimension
)

# Set retrieval weights
rag.weights = {
    'semantic': 0.4,        # Semantic search weight
    'keyword': 0.3,         # Keyword search weight
    'quantum': 0.3          # Quantum search weight
}
```

## 🧪 Testing

### Run All Tests
```bash
python test_system.py
```

### Run Specific Test Categories
```bash
# Unit tests only
python -m unittest test_system.TestTokenizer
python -m unittest test_system.TestTransformer
python -m unittest test_system.TestQuantumInspiredLLM

# Performance tests
python -c "from test_system import run_performance_tests; run_performance_tests()"
```

### Test Coverage
```bash
pip install pytest-cov
pytest --cov=. test_system.py
```

## 📊 Performance Optimization

### CUDA Acceleration
```python
from performance_optimizer import PerformanceOptimizer

optimizer = PerformanceOptimizer()
if optimizer.optimization_level == "cuda":
    print("CUDA acceleration available!")
    
# Optimize model operations
optimizer.optimize_model_operations(model)
```

### C++ Extensions
```python
# Compile C++ extensions
optimizer = PerformanceOptimizer()

# Use optimized operations
result = optimizer.optimized_matrix_multiply(matrix_a, matrix_b)
softmax_result = optimizer.optimized_softmax(logits)
```

### Benchmarking
```python
# Run performance benchmarks
results = optimizer.benchmark_operations(matrix_size=100)
print(f"Matrix multiplication: {results['python_matrix_multiply']:.4f}s")
```

## 🐳 Deployment

### Docker Deployment
```bash
# Build and run
docker-compose up --build

# Run with GPU support
docker-compose up --build llm-server-gpu

# Scale services
docker-compose up --scale llm-server=3
```

### Production Configuration
```yaml
# docker-compose.prod.yml
version: '3.8'
services:
  llm-server:
    deploy:
      replicas: 3
      resources:
        limits:
          memory: 8G
        reservations:
          memory: 4G
```

### Monitoring
- **Prometheus**: http://localhost:9090
- **Grafana**: http://localhost:3000 (admin/admin)
- **Health Check**: http://localhost/health

## 🔌 API Endpoints

### Socket Server (Port 65432)
```json
{
  "prompt": "def hello_world():",
  "max_length": 100,
  "temperature": 1.0,
  "stream": true
}
```

### WebSocket Server (Port 65433)
```javascript
const ws = new WebSocket('ws://localhost:65433');
ws.send(JSON.stringify({
  prompt: "def hello_world():",
  max_length: 100,
  temperature: 1.0
}));
```

### HTTP API (Port 80/443)
```bash
curl -X POST http://localhost/api/generate \
  -H "Content-Type: application/json" \
  -d '{"prompt": "def hello_world():", "max_length": 100}'
```

## 🧠 Quantum-Inspired Features

### Quantum States
```python
from quantum_inspired_llm import QuantumState, QuantumGate

# Create quantum state
state = QuantumState(dimension=8)

# Apply quantum gates
QuantumGate.hadamard(state, qubit=0)
QuantumGate.rotation(state, angle=math.pi/4, qubit=1)
QuantumGate.entangle(state, qubit1=0, qubit2=1)

# Measure state
outcome = state.measure()
```

### Quantum-Inspired Attention
```python
# Quantum-enhanced attention mechanism
attention = QuantumInspiredAttention(
    d_model=512,
    num_heads=8,
    quantum_dim=16
)

# Forward pass with quantum processing
output = attention.forward(input_matrix)
```

### Quantum Metrics
```python
# Get quantum-inspired metrics
metrics = model.get_quantum_metrics()
print(f"Quantum dimension: {metrics['quantum_dimension']}")
print(f"Entanglement ratio: {metrics['quantum_entanglement_ratio']}")
print(f"State coherence: {metrics['quantum_state_coherence']}")
```

## 🔍 RAG System

### Document Management
```python
# Add documents from directory
rag.add_documents_from_directory("./codebase", ['.py', '.js', '.ts'])

# Add individual document
doc = Document(
    id="unique_id",
    content="Your document content",
    metadata={"type": "code", "language": "python"}
)
rag.add_document(doc)
```

### Hybrid Search
```python
# Search with multiple retrieval methods
results = rag.search("machine learning algorithm", top_k=10)

for result in results:
    print(f"Score: {result.score:.3f}")
    print(f"Match type: {result.match_type}")
    print(f"Document: {result.document.id}")
    print(f"Explanation: {result.explanation}")
```

### RAG Generation
```python
# Generate with retrieved context
response = rag.generate_with_rag(
    model=model,
    tokenizer=tokenizer,
    query="How to implement a neural network?",
    max_length=200,
    temperature=0.7
)
```

## 🛠️ Development

### Adding New Features
1. Create feature branch
2. Implement with tests
3. Update documentation
4. Submit pull request

### Code Style
```bash
# Format code
black *.py

# Lint code
flake8 *.py

# Type checking
mypy *.py
```

### Contributing
1. Fork the repository
2. Create feature branch
3. Add tests for new features
4. Ensure all tests pass
5. Submit pull request

## 📚 Documentation

### API Reference
- [Tokenizer API](docs/tokenizer.md)
- [Transformer API](docs/transformer.md)
- [Quantum LLM API](docs/quantum_llm.md)
- [RAG System API](docs/rag_system.md)
- [Server API](docs/server_api.md)

### Tutorials
- [Getting Started](docs/tutorials/getting_started.md)
- [Training Your Model](docs/tutorials/training.md)
- [Deployment Guide](docs/tutorials/deployment.md)
- [Performance Optimization](docs/tutorials/optimization.md)

### Examples
- [Basic Usage](examples/basic_usage.py)
- [Advanced Features](examples/advanced_features.py)
- [Custom Models](examples/custom_models.py)
- [Integration Examples](examples/integrations.py)

## 🐛 Troubleshooting

### Common Issues

1. **CUDA not available**
   ```bash
   # Check CUDA installation
   nvidia-smi
   
   # Install CUDA toolkit
   # Follow NVIDIA CUDA installation guide
   ```

2. **C++ compilation failed**
   ```bash
   # Install build tools
   sudo apt-get install build-essential
   
   # Or use conda
   conda install gcc_linux-64 gxx_linux-64
   ```

3. **Memory issues**
   ```python
   # Reduce model size
   model = QuantumInspiredLLM(
       d_model=64,      # Reduce from 512
       num_layers=2,    # Reduce from 6
       d_ff=256         # Reduce from 2048
   )
   ```

4. **Server connection issues**
   ```bash
   # Check if server is running
   netstat -tlnp | grep 65432
   
   # Check firewall
   sudo ufw status
   ```

### Performance Issues

1. **Slow training**
   - Use smaller batch sizes
   - Enable CUDA acceleration
   - Use C++ extensions

2. **High memory usage**
   - Reduce model dimensions
   - Use gradient checkpointing
   - Enable mixed precision training

3. **Slow inference**
   - Use streaming server
   - Enable GPU acceleration
   - Optimize with C++ extensions

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- OpenAI for transformer architecture inspiration
- Hugging Face for tokenizer implementations
- NVIDIA for CUDA acceleration support
- The open-source community for various libraries and tools

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/your-repo/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-repo/discussions)
- **Documentation**: [Project Wiki](https://github.com/your-repo/wiki)

## 🔮 Future Roadmap

- [ ] Multi-modal support (text, code, images)
- [ ] Distributed training across multiple GPUs
- [ ] Advanced quantum algorithms integration
- [ ] Real-time collaboration features
- [ ] Mobile and edge deployment
- [ ] Advanced prompt engineering tools
- [ ] Model compression and quantization
- [ ] Federated learning support

---

**Built with ❤️ using pure Python and quantum-inspired algorithms**
