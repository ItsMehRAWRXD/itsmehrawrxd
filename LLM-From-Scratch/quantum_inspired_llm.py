"""
Quantum-Inspired Hybrid LLM Implementation
Advanced hybrid model combining classical and quantum-inspired layers
"""

import math
import random
import time
from typing import List, Tuple, Dict, Any, Optional, Complex
from dataclasses import dataclass
import numpy as np
from tokenizer import BPETokenizer
from transformer import Transformer, Matrix, MathUtils

@dataclass
class QuantumState:
    """Represents a quantum state with complex amplitudes"""
    amplitudes: List[complex]
    dimension: int
    
    def __init__(self, dimension: int):
        self.dimension = dimension
        self.amplitudes = [complex(0.0, 0.0) for _ in range(dimension)]
        # Initialize to uniform superposition
        norm = 1.0 / math.sqrt(dimension)
        for i in range(dimension):
            self.amplitudes[i] = complex(norm, 0.0)
    
    def normalize(self):
        """Normalize the quantum state"""
        norm = sum(abs(amp) ** 2 for amp in self.amplitudes)
        if norm > 0:
            sqrt_norm = math.sqrt(norm)
            for i in range(self.dimension):
                self.amplitudes[i] /= sqrt_norm
    
    def measure(self) -> int:
        """Measure the quantum state and return the outcome"""
        probabilities = [abs(amp) ** 2 for amp in self.amplitudes]
        total_prob = sum(probabilities)
        
        if total_prob == 0:
            return random.randint(0, self.dimension - 1)
        
        # Normalize probabilities
        probabilities = [p / total_prob for p in probabilities]
        
        # Sample from the distribution
        rand_val = random.random()
        cumulative = 0.0
        
        for i, prob in enumerate(probabilities):
            cumulative += prob
            if rand_val <= cumulative:
                return i
        
        return self.dimension - 1

class QuantumGate:
    """Quantum gate operations for quantum-inspired computations"""
    
    @staticmethod
    def hadamard(state: QuantumState, qubit: int):
        """Apply Hadamard gate to a qubit"""
        if qubit >= state.dimension:
            return
        
        # Hadamard gate: |0⟩ → (|0⟩ + |1⟩)/√2, |1⟩ → (|0⟩ - |1⟩)/√2
        sqrt2 = 1.0 / math.sqrt(2)
        
        # For simplicity, we'll apply a rotation to the entire state
        for i in range(state.dimension):
            if i & (1 << qubit):  # If qubit is 1
                state.amplitudes[i] *= -sqrt2
            else:  # If qubit is 0
                state.amplitudes[i] *= sqrt2
    
    @staticmethod
    def rotation(state: QuantumState, angle: float, qubit: int):
        """Apply rotation gate to a qubit"""
        if qubit >= state.dimension:
            return
        
        cos_angle = math.cos(angle)
        sin_angle = math.sin(angle)
        
        for i in range(state.dimension):
            if i & (1 << qubit):  # If qubit is 1
                # Apply rotation matrix
                old_amp = state.amplitudes[i]
                state.amplitudes[i] = old_amp * complex(cos_angle, sin_angle)
    
    @staticmethod
    def entangle(state: QuantumState, qubit1: int, qubit2: int):
        """Create entanglement between two qubits"""
        if qubit1 >= state.dimension or qubit2 >= state.dimension:
            return
        
        # Create Bell state: (|00⟩ + |11⟩)/√2
        sqrt2 = 1.0 / math.sqrt(2)
        
        # Reset to Bell state
        for i in range(state.dimension):
            if i == 0 or i == (1 << qubit1) | (1 << qubit2):
                state.amplitudes[i] = complex(sqrt2, 0.0)
            else:
                state.amplitudes[i] = complex(0.0, 0.0)

class QuantumInspiredAttention:
    """Quantum-inspired attention mechanism"""
    
    def __init__(self, d_model: int, num_heads: int, quantum_dim: int = 8):
        self.d_model = d_model
        self.num_heads = num_heads
        self.quantum_dim = quantum_dim
        self.head_dim = d_model // num_heads
        
        # Classical attention weights
        self.W_q = Matrix.random(d_model, d_model, scale=0.1)
        self.W_k = Matrix.random(d_model, d_model, scale=0.1)
        self.W_v = Matrix.random(d_model, d_model, scale=0.1)
        self.W_o = Matrix.random(d_model, d_model, scale=0.1)
        
        # Quantum-inspired parameters
        self.quantum_weights = [random.uniform(0, 2 * math.pi) for _ in range(quantum_dim)]
        self.entanglement_matrix = Matrix.random(quantum_dim, quantum_dim, scale=0.1)
        
    def forward(self, x: Matrix, mask: Optional[Matrix] = None) -> Matrix:
        """Forward pass with quantum-inspired attention"""
        batch_size, seq_len = x.rows, x.cols
        
        # Classical linear transformations
        Q = x.matmul(self.W_q)
        K = x.matmul(self.W_k)
        V = x.matmul(self.W_v)
        
        # Quantum-inspired processing
        quantum_enhanced_Q = self._apply_quantum_processing(Q)
        quantum_enhanced_K = self._apply_quantum_processing(K)
        quantum_enhanced_V = self._apply_quantum_processing(V)
        
        # Multi-head attention
        attention_output = self._multi_head_attention(
            quantum_enhanced_Q, quantum_enhanced_K, quantum_enhanced_V, mask
        )
        
        # Output projection
        output = attention_output.matmul(self.W_o)
        
        return output
    
    def _apply_quantum_processing(self, x: Matrix) -> Matrix:
        """Apply quantum-inspired processing to input"""
        # Create quantum states for each position
        quantum_states = []
        for i in range(x.rows):
            state = QuantumState(self.quantum_dim)
            
            # Apply quantum gates based on input
            for j in range(min(x.cols, self.quantum_dim)):
                if x.data[i][j] > 0:
                    QuantumGate.rotation(state, self.quantum_weights[j], j)
            
            # Apply entanglement
            for j in range(0, self.quantum_dim - 1, 2):
                QuantumGate.entangle(state, j, j + 1)
            
            quantum_states.append(state)
        
        # Convert quantum states back to classical representation
        enhanced_x = Matrix.zeros(x.rows, x.cols)
        for i, state in enumerate(quantum_states):
            for j in range(x.cols):
                # Use quantum measurement to enhance classical values
                measurement = state.measure()
                quantum_factor = abs(state.amplitudes[measurement % len(state.amplitudes)])
                enhanced_x[i][j] = x.data[i][j] * (1.0 + quantum_factor)
        
        return enhanced_x
    
    def _multi_head_attention(self, Q: Matrix, K: Matrix, V: Matrix, mask: Optional[Matrix] = None) -> Matrix:
        """Multi-head attention mechanism"""
        # Simplified multi-head attention
        scores = Q.matmul(K.transpose())
        
        # Scale scores
        scale_factor = 1.0 / MathUtils.sqrt(self.head_dim)
        scores = scores * scale_factor
        
        # Apply mask if provided
        if mask is not None:
            for i in range(scores.rows):
                for j in range(scores.cols):
                    if mask.data[i][j] == 0:
                        scores[i][j] = float('-inf')
        
        # Apply softmax
        attention_weights = scores.softmax()
        
        # Apply attention to values
        output = attention_weights.matmul(V)
        
        return output

class QuantumInspiredFeedForward:
    """Quantum-inspired feed-forward network"""
    
    def __init__(self, d_model: int, d_ff: int, quantum_dim: int = 8):
        self.d_model = d_model
        self.d_ff = d_ff
        self.quantum_dim = quantum_dim
        
        # Classical weights
        self.W1 = Matrix.random(d_model, d_ff, scale=0.1)
        self.b1 = Matrix.zeros(1, d_ff)
        self.W2 = Matrix.random(d_ff, d_model, scale=0.1)
        self.b2 = Matrix.zeros(1, d_model)
        
        # Quantum-inspired parameters
        self.quantum_rotations = [random.uniform(0, 2 * math.pi) for _ in range(quantum_dim)]
        self.quantum_phases = [random.uniform(0, 2 * math.pi) for _ in range(quantum_dim)]
    
    def forward(self, x: Matrix) -> Matrix:
        """Forward pass with quantum-inspired processing"""
        # First linear transformation
        hidden = x.matmul(self.W1)
        hidden = hidden.add(self.b1)
        
        # Apply quantum-inspired activation
        quantum_enhanced = self._apply_quantum_activation(hidden)
        
        # ReLU activation
        activated = quantum_enhanced.apply_function(lambda val: max(0, val))
        
        # Second linear transformation
        output = activated.matmul(self.W2)
        output = output.add(self.b2)
        
        return output
    
    def _apply_quantum_activation(self, x: Matrix) -> Matrix:
        """Apply quantum-inspired activation function"""
        enhanced = Matrix.zeros(x.rows, x.cols)
        
        for i in range(x.rows):
            for j in range(x.cols):
                # Create quantum state
                state = QuantumState(self.quantum_dim)
                
                # Apply rotations based on input value
                input_val = x.data[i][j]
                for k in range(self.quantum_dim):
                    angle = self.quantum_rotations[k] * input_val
                    QuantumGate.rotation(state, angle, k)
                
                # Apply phase shifts
                for k in range(self.quantum_dim):
                    state.amplitudes[k] *= complex(math.cos(self.quantum_phases[k]), 
                                                 math.sin(self.quantum_phases[k]))
                
                # Measure and use as enhancement factor
                measurement = state.measure()
                quantum_factor = abs(state.amplitudes[measurement % len(state.amplitudes)])
                
                # Enhance the classical value
                enhanced[i][j] = x.data[i][j] * (1.0 + 0.1 * quantum_factor)
        
        return enhanced

class QuantumInspiredTransformerBlock:
    """Quantum-inspired transformer block"""
    
    def __init__(self, d_model: int, num_heads: int, d_ff: int, quantum_dim: int = 8):
        self.d_model = d_model
        self.num_heads = num_heads
        self.d_ff = d_ff
        self.quantum_dim = quantum_dim
        
        # Quantum-inspired components
        self.quantum_attention = QuantumInspiredAttention(d_model, num_heads, quantum_dim)
        self.quantum_feed_forward = QuantumInspiredFeedForward(d_model, d_ff, quantum_dim)
        
        # Layer normalization
        self.norm1 = self._create_layer_norm(d_model)
        self.norm2 = self._create_layer_norm(d_model)
    
    def _create_layer_norm(self, d_model: int):
        """Create layer normalization (simplified)"""
        class SimpleLayerNorm:
            def __init__(self, d_model):
                self.gamma = Matrix.random(1, d_model, scale=1.0)
                self.beta = Matrix.zeros(1, d_model)
            
            def forward(self, x: Matrix) -> Matrix:
                # Simplified layer normalization
                result = x.copy()
                for i in range(x.rows):
                    mean = sum(x.data[i]) / x.cols
                    variance = sum((val - mean) ** 2 for val in x.data[i]) / x.cols
                    std = MathUtils.sqrt(variance + 1e-6)
                    
                    for j in range(x.cols):
                        normalized = (x.data[i][j] - mean) / std
                        result[i][j] = normalized * self.gamma.data[0][j] + self.beta.data[0][j]
                return result
        
        return SimpleLayerNorm(d_model)
    
    def forward(self, x: Matrix, mask: Optional[Matrix] = None) -> Matrix:
        """Forward pass through quantum-inspired transformer block"""
        # Self-attention with residual connection
        attn_output = self.quantum_attention.forward(x, mask)
        x = x.add(attn_output)
        x = self.norm1.forward(x)
        
        # Feed-forward with residual connection
        ff_output = self.quantum_feed_forward.forward(x)
        x = x.add(ff_output)
        x = self.norm2.forward(x)
        
        return x

class QuantumInspiredLLM:
    """Complete quantum-inspired hybrid LLM"""
    
    def __init__(self, vocab_size: int, d_model: int = 512, num_heads: int = 8,
                 num_layers: int = 6, d_ff: int = 2048, max_seq_len: int = 1024,
                 quantum_dim: int = 8):
        self.vocab_size = vocab_size
        self.d_model = d_model
        self.num_heads = num_heads
        self.num_layers = num_layers
        self.d_ff = d_ff
        self.max_seq_len = max_seq_len
        self.quantum_dim = quantum_dim
        
        # Embedding layers
        self.token_embedding = Matrix.random(vocab_size, d_model, scale=0.1)
        self.position_embedding = Matrix.random(max_seq_len, d_model, scale=0.1)
        
        # Quantum-inspired transformer blocks
        self.quantum_blocks = [
            QuantumInspiredTransformerBlock(d_model, num_heads, d_ff, quantum_dim)
            for _ in range(num_layers)
        ]
        
        # Output layer
        self.output_projection = Matrix.random(d_model, vocab_size, scale=0.1)
        self.output_bias = Matrix.zeros(1, vocab_size)
        
        # Final layer normalization
        self.final_norm = self._create_layer_norm(d_model)
        
        # Quantum state for generation
        self.generation_state = QuantumState(quantum_dim)
    
    def _create_layer_norm(self, d_model: int):
        """Create layer normalization"""
        class SimpleLayerNorm:
            def __init__(self, d_model):
                self.gamma = Matrix.random(1, d_model, scale=1.0)
                self.beta = Matrix.zeros(1, d_model)
            
            def forward(self, x: Matrix) -> Matrix:
                result = x.copy()
                for i in range(x.rows):
                    mean = sum(x.data[i]) / x.cols
                    variance = sum((val - mean) ** 2 for val in x.data[i]) / x.cols
                    std = MathUtils.sqrt(variance + 1e-6)
                    
                    for j in range(x.cols):
                        normalized = (x.data[i][j] - mean) / std
                        result[i][j] = normalized * self.gamma.data[0][j] + self.beta.data[0][j]
                return result
        
        return SimpleLayerNorm(d_model)
    
    def forward(self, input_ids: List[int], mask: Optional[List[List[int]]] = None) -> Matrix:
        """Forward pass through the quantum-inspired model"""
        seq_len = len(input_ids)
        
        # Token embeddings
        token_emb = Matrix.zeros(seq_len, self.d_model)
        for i, token_id in enumerate(input_ids):
            if token_id < self.vocab_size:
                for j in range(self.d_model):
                    token_emb[i][j] = self.token_embedding[token_id][j]
        
        # Position embeddings
        pos_emb = Matrix.zeros(seq_len, self.d_model)
        for i in range(seq_len):
            if i < self.max_seq_len:
                for j in range(self.d_model):
                    pos_emb[i][j] = self.position_embedding[i][j]
        
        # Combine embeddings
        x = token_emb.add(pos_emb)
        
        # Create attention mask
        attention_mask = None
        if mask is not None:
            attention_mask = Matrix(mask)
        
        # Pass through quantum-inspired transformer blocks
        for block in self.quantum_blocks:
            x = block.forward(x, attention_mask)
        
        # Final layer normalization
        x = self.final_norm.forward(x)
        
        # Output projection
        logits = x.matmul(self.output_projection)
        logits = logits.add(self.output_bias)
        
        return logits
    
    def generate(self, tokenizer: BPETokenizer, prompt: str, max_length: int = 100,
                 temperature: float = 1.0, stream_callback: Optional[callable] = None) -> str:
        """Generate text with quantum-inspired sampling"""
        # Encode prompt
        input_ids = tokenizer.encode(prompt)
        
        # Generate tokens
        for _ in range(max_length):
            # Forward pass
            logits = self.forward(input_ids)
            
            # Get next token probabilities
            next_token_logits = logits.data[-1]  # Last position
            
            # Apply quantum-inspired sampling
            next_token_id = self._quantum_sampling(next_token_logits, temperature)
            
            # Convert to text
            next_token_text = tokenizer.decode([next_token_id])
            
            # Stream callback if provided
            if stream_callback:
                stream_callback(next_token_text)
            
            # Add to sequence
            input_ids.append(next_token_id)
            
            # Stop if EOS token
            if next_token_id == tokenizer.get_eos_token_id():
                break
        
        # Decode and return
        return tokenizer.decode(input_ids)
    
    def _quantum_sampling(self, logits: List[float], temperature: float) -> int:
        """Quantum-inspired sampling for token selection"""
        # Apply temperature
        if temperature != 1.0:
            logits = [logit / temperature for logit in logits]
        
        # Convert to probabilities
        max_logit = max(logits)
        exps = [MathUtils.exp(logit - max_logit) for logit in logits]
        exp_sum = sum(exps)
        probs = [exp / exp_sum for exp in exps]
        
        # Use quantum state for sampling
        self.generation_state = QuantumState(len(probs))
        
        # Apply quantum gates based on probabilities
        for i, prob in enumerate(probs):
            if prob > 0:
                angle = prob * math.pi
                QuantumGate.rotation(self.generation_state, angle, i)
        
        # Measure to get the selected token
        return self.generation_state.measure()
    
    def get_quantum_metrics(self) -> Dict[str, Any]:
        """Get quantum-inspired metrics"""
        return {
            'quantum_dimension': self.quantum_dim,
            'num_quantum_layers': self.num_layers,
            'quantum_entanglement_ratio': self.quantum_dim / self.d_model,
            'quantum_state_coherence': self._calculate_coherence(),
            'quantum_measurement_entropy': self._calculate_entropy()
        }
    
    def _calculate_coherence(self) -> float:
        """Calculate quantum state coherence"""
        if hasattr(self, 'generation_state'):
            coherence = 0.0
            for amp in self.generation_state.amplitudes:
                coherence += abs(amp) ** 2
            return coherence / len(self.generation_state.amplitudes)
        return 0.0
    
    def _calculate_entropy(self) -> float:
        """Calculate quantum measurement entropy"""
        if hasattr(self, 'generation_state'):
            entropy = 0.0
            for amp in self.generation_state.amplitudes:
                prob = abs(amp) ** 2
                if prob > 0:
                    entropy -= prob * MathUtils.log(prob)
            return entropy
        return 0.0

# Example usage and testing
if __name__ == "__main__":
    # Create a quantum-inspired model
    vocab_size = 1000
    model = QuantumInspiredLLM(
        vocab_size=vocab_size,
        d_model=128,
        num_heads=4,
        num_layers=2,
        d_ff=512,
        max_seq_len=256,
        quantum_dim=8
    )
    
    # Test forward pass
    input_ids = [1, 2, 3, 4, 5]
    logits = model.forward(input_ids)
    
    print(f"Quantum-Inspired LLM created successfully!")
    print(f"Input shape: {len(input_ids)}")
    print(f"Output shape: {logits.rows} x {logits.cols}")
    
    # Get quantum metrics
    metrics = model.get_quantum_metrics()
    print(f"Quantum metrics: {metrics}")
    
    # Test quantum state operations
    state = QuantumState(4)
    print(f"Initial state: {[abs(amp) for amp in state.amplitudes]}")
    
    QuantumGate.hadamard(state, 0)
    print(f"After Hadamard: {[abs(amp) for amp in state.amplitudes]}")
    
    measurement = state.measure()
    print(f"Measurement result: {measurement}")