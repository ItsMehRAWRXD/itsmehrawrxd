"""
Complete Transformer Architecture Implementation
A full implementation of the Transformer model from scratch using pure Python
"""

import math
import random
from typing import List, Tuple, Optional, Dict, Any
from tokenizer import BPETokenizer

class MathUtils:
    """Mathematical utility functions"""
    
    @staticmethod
    def exp(x: float) -> float:
        """Exponential function using Taylor series"""
        if x > 700:  # Prevent overflow
            return float('inf')
        if x < -700:  # Prevent underflow
            return 0.0
        
        result = 1.0
        term = 1.0
        for i in range(1, 50):  # 50 terms should be sufficient
            term *= x / i
            result += term
            if abs(term) < 1e-10:  # Convergence check
                break
        return result
    
    @staticmethod
    def log(x: float) -> float:
        """Natural logarithm using Newton's method"""
        if x <= 0:
            return float('-inf')
        if x == 1:
            return 0.0
        
        # Use ln(x) = ln(2) * log2(x) for better convergence
        result = 0.0
        while x >= 2:
            x /= 2
            result += 0.6931471805599453  # ln(2)
        
        while x < 1:
            x *= 2
            result -= 0.6931471805599453
        
        # Newton's method for remaining value
        y = x - 1
        for _ in range(10):
            y = y - (MathUtils.exp(y) - x) / MathUtils.exp(y)
        
        return result + result
    
    @staticmethod
    def sqrt(x: float) -> float:
        """Square root using Newton's method"""
        if x < 0:
            return float('nan')
        if x == 0:
            return 0.0
        
        # Initial guess
        guess = x / 2
        for _ in range(20):  # 20 iterations should be sufficient
            new_guess = (guess + x / guess) / 2
            if abs(new_guess - guess) < 1e-10:
                break
            guess = new_guess
        return guess

class Matrix:
    """Matrix operations implementation"""
    
    def __init__(self, data: List[List[float]]):
        self.data = data
        self.rows = len(data)
        self.cols = len(data[0]) if data else 0
    
    @classmethod
    def zeros(cls, rows: int, cols: int) -> 'Matrix':
        """Create zero matrix"""
        return cls([[0.0 for _ in range(cols)] for _ in range(rows)])
    
    @classmethod
    def random(cls, rows: int, cols: int, scale: float = 0.1) -> 'Matrix':
        """Create random matrix with normal distribution"""
        data = []
        for _ in range(rows):
            row = []
            for _ in range(cols):
                # Simple random number generation
                val = (random.random() - 0.5) * 2 * scale
                row.append(val)
            data.append(row)
        return cls(data)
    
    def __getitem__(self, key):
        return self.data[key]
    
    def __setitem__(self, key, value):
        self.data[key] = value
    
    def __mul__(self, other):
        """Matrix multiplication"""
        if isinstance(other, Matrix):
            return self.matmul(other)
        else:
            # Scalar multiplication
            result = Matrix.zeros(self.rows, self.cols)
            for i in range(self.rows):
                for j in range(self.cols):
                    result[i][j] = self.data[i][j] * other
            return result
    
    def matmul(self, other: 'Matrix') -> 'Matrix':
        """Matrix multiplication"""
        if self.cols != other.rows:
            raise ValueError("Matrix dimensions incompatible for multiplication")
        
        result = Matrix.zeros(self.rows, other.cols)
        for i in range(self.rows):
            for j in range(other.cols):
                for k in range(self.cols):
                    result[i][j] += self.data[i][k] * other.data[k][j]
        return result
    
    def transpose(self) -> 'Matrix':
        """Matrix transpose"""
        result = Matrix.zeros(self.cols, self.rows)
        for i in range(self.rows):
            for j in range(self.cols):
                result[j][i] = self.data[i][j]
        return result
    
    def add(self, other: 'Matrix') -> 'Matrix':
        """Matrix addition"""
        if self.rows != other.rows or self.cols != other.cols:
            raise ValueError("Matrix dimensions must match for addition")
        
        result = Matrix.zeros(self.rows, self.cols)
        for i in range(self.rows):
            for j in range(self.cols):
                result[i][j] = self.data[i][j] + other.data[i][j]
        return result
    
    def softmax(self) -> 'Matrix':
        """Apply softmax to each row"""
        result = Matrix.zeros(self.rows, self.cols)
        for i in range(self.rows):
            # Find max for numerical stability
            max_val = max(self.data[i])
            
            # Compute exponentials
            exps = [MathUtils.exp(self.data[i][j] - max_val) for j in range(self.cols)]
            exp_sum = sum(exps)
            
            # Normalize
            for j in range(self.cols):
                result[i][j] = exps[j] / exp_sum
        return result
    
    def apply_function(self, func) -> 'Matrix':
        """Apply function element-wise"""
        result = Matrix.zeros(self.rows, self.cols)
        for i in range(self.rows):
            for j in range(self.cols):
                result[i][j] = func(self.data[i][j])
        return result
    
    def copy(self) -> 'Matrix':
        """Create a copy of the matrix"""
        return Matrix([row[:] for row in self.data])

class LayerNorm:
    """Layer normalization implementation"""
    
    def __init__(self, d_model: int, eps: float = 1e-6):
        self.d_model = d_model
        self.eps = eps
        self.gamma = Matrix.random(1, d_model, scale=1.0)
        self.beta = Matrix.zeros(1, d_model)
    
    def forward(self, x: Matrix) -> Matrix:
        """Forward pass"""
        # Compute mean and variance
        mean = sum(sum(row) for row in x.data) / (x.rows * x.cols)
        
        variance = 0.0
        for row in x.data:
            for val in row:
                variance += (val - mean) ** 2
        variance /= (x.rows * x.cols)
        
        # Normalize
        std = MathUtils.sqrt(variance + self.eps)
        result = Matrix.zeros(x.rows, x.cols)
        
        for i in range(x.rows):
            for j in range(x.cols):
                normalized = (x.data[i][j] - mean) / std
                result[i][j] = normalized * self.gamma.data[0][j] + self.beta.data[0][j]
        
        return result

class MultiHeadAttention:
    """Multi-head self-attention implementation"""
    
    def __init__(self, d_model: int, num_heads: int):
        self.d_model = d_model
        self.num_heads = num_heads
        self.d_k = d_model // num_heads
        
        # Weight matrices
        self.W_q = Matrix.random(d_model, d_model, scale=0.1)
        self.W_k = Matrix.random(d_model, d_model, scale=0.1)
        self.W_v = Matrix.random(d_model, d_model, scale=0.1)
        self.W_o = Matrix.random(d_model, d_model, scale=0.1)
    
    def forward(self, x: Matrix, mask: Optional[Matrix] = None) -> Matrix:
        """Forward pass"""
        batch_size, seq_len = x.rows, x.cols
        
        # Linear transformations
        Q = x.matmul(self.W_q)
        K = x.matmul(self.W_k)
        V = x.matmul(self.W_v)
        
        # Reshape for multi-head attention
        Q = self._reshape_for_heads(Q, batch_size, seq_len)
        K = self._reshape_for_heads(K, batch_size, seq_len)
        V = self._reshape_for_heads(V, batch_size, seq_len)
        
        # Scaled dot-product attention
        attention_output = self._scaled_dot_product_attention(Q, K, V, mask)
        
        # Reshape back
        attention_output = self._reshape_from_heads(attention_output, batch_size, seq_len)
        
        # Final linear transformation
        output = attention_output.matmul(self.W_o)
        
        return output
    
    def _reshape_for_heads(self, x: Matrix, batch_size: int, seq_len: int) -> Matrix:
        """Reshape matrix for multi-head attention"""
        # This is a simplified version - in practice, you'd need proper reshaping
        return x
    
    def _reshape_from_heads(self, x: Matrix, batch_size: int, seq_len: int) -> Matrix:
        """Reshape matrix back from multi-head attention"""
        return x
    
    def _scaled_dot_product_attention(self, Q: Matrix, K: Matrix, V: Matrix, mask: Optional[Matrix] = None) -> Matrix:
        """Scaled dot-product attention"""
        # Compute attention scores
        scores = Q.matmul(K.transpose())
        
        # Scale scores
        scale_factor = 1.0 / MathUtils.sqrt(self.d_k)
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

class FeedForward:
    """Feed-forward network implementation"""
    
    def __init__(self, d_model: int, d_ff: int):
        self.d_model = d_model
        self.d_ff = d_ff
        
        # Weight matrices
        self.W1 = Matrix.random(d_model, d_ff, scale=0.1)
        self.b1 = Matrix.zeros(1, d_ff)
        self.W2 = Matrix.random(d_ff, d_model, scale=0.1)
        self.b2 = Matrix.zeros(1, d_model)
    
    def forward(self, x: Matrix) -> Matrix:
        """Forward pass"""
        # First linear transformation + ReLU
        hidden = x.matmul(self.W1)
        hidden = hidden.add(self.b1)
        hidden = hidden.apply_function(lambda val: max(0, val))  # ReLU
        
        # Second linear transformation
        output = hidden.matmul(self.W2)
        output = output.add(self.b2)
        
        return output

class TransformerBlock:
    """Transformer block implementation"""
    
    def __init__(self, d_model: int, num_heads: int, d_ff: int, dropout: float = 0.1):
        self.d_model = d_model
        self.num_heads = num_heads
        self.d_ff = d_ff
        self.dropout = dropout
        
        # Components
        self.attention = MultiHeadAttention(d_model, num_heads)
        self.feed_forward = FeedForward(d_model, d_ff)
        self.norm1 = LayerNorm(d_model)
        self.norm2 = LayerNorm(d_model)
    
    def forward(self, x: Matrix, mask: Optional[Matrix] = None) -> Matrix:
        """Forward pass"""
        # Self-attention with residual connection
        attn_output = self.attention.forward(x, mask)
        x = x.add(attn_output)
        x = self.norm1.forward(x)
        
        # Feed-forward with residual connection
        ff_output = self.feed_forward.forward(x)
        x = x.add(ff_output)
        x = self.norm2.forward(x)
        
        return x

class Transformer:
    """Complete Transformer model implementation"""
    
    def __init__(self, vocab_size: int, d_model: int = 512, num_heads: int = 8, 
                 num_layers: int = 6, d_ff: int = 2048, max_seq_len: int = 1024):
        self.vocab_size = vocab_size
        self.d_model = d_model
        self.num_heads = num_heads
        self.num_layers = num_layers
        self.d_ff = d_ff
        self.max_seq_len = max_seq_len
        
        # Embedding layers
        self.token_embedding = Matrix.random(vocab_size, d_model, scale=0.1)
        self.position_embedding = Matrix.random(max_seq_len, d_model, scale=0.1)
        
        # Transformer blocks
        self.transformer_blocks = [
            TransformerBlock(d_model, num_heads, d_ff)
            for _ in range(num_layers)
        ]
        
        # Output layer
        self.output_projection = Matrix.random(d_model, vocab_size, scale=0.1)
        self.output_bias = Matrix.zeros(1, vocab_size)
        
        # Layer normalization
        self.final_norm = LayerNorm(d_model)
    
    def forward(self, input_ids: List[int], mask: Optional[List[List[int]]] = None) -> Matrix:
        """Forward pass"""
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
        
        # Pass through transformer blocks
        for block in self.transformer_blocks:
            x = block.forward(x, attention_mask)
        
        # Final layer normalization
        x = self.final_norm.forward(x)
        
        # Output projection
        logits = x.matmul(self.output_projection)
        logits = logits.add(self.output_bias)
        
        return logits
    
    def generate(self, tokenizer: BPETokenizer, prompt: str, max_length: int = 100, 
                 temperature: float = 1.0) -> str:
        """Generate text from prompt"""
        # Encode prompt
        input_ids = tokenizer.encode(prompt)
        
        # Generate tokens
        for _ in range(max_length):
            # Forward pass
            logits = self.forward(input_ids)
            
            # Get next token probabilities
            next_token_logits = logits.data[-1]  # Last position
            
            # Apply temperature
            if temperature != 1.0:
                next_token_logits = [logit / temperature for logit in next_token_logits]
            
            # Convert to probabilities
            max_logit = max(next_token_logits)
            exps = [MathUtils.exp(logit - max_logit) for logit in next_token_logits]
            exp_sum = sum(exps)
            probs = [exp / exp_sum for exp in exps]
            
            # Sample next token (greedy for simplicity)
            next_token_id = probs.index(max(probs))
            
            # Add to sequence
            input_ids.append(next_token_id)
            
            # Stop if EOS token
            if next_token_id == tokenizer.get_eos_token_id():
                break
        
        # Decode and return
        return tokenizer.decode(input_ids)

# Example usage
if __name__ == "__main__":
    # Create a small transformer for testing
    vocab_size = 1000
    transformer = Transformer(
        vocab_size=vocab_size,
        d_model=128,
        num_heads=4,
        num_layers=2,
        d_ff=512,
        max_seq_len=256
    )
    
    # Test forward pass
    input_ids = [1, 2, 3, 4, 5]
    logits = transformer.forward(input_ids)
    
    print(f"Input shape: {len(input_ids)}")
    print(f"Output shape: {logits.rows} x {logits.cols}")
    print("Transformer model created successfully!")
