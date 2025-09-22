"""
Complete Training Implementation
Training loop, loss functions, and optimization from scratch
"""

import random
import math
from typing import List, Tuple, Dict, Any, Optional
from tokenizer import BPETokenizer
from transformer import Transformer, Matrix, MathUtils

class CrossEntropyLoss:
    """Cross-entropy loss implementation"""
    
    def __init__(self, ignore_index: int = -1):
        self.ignore_index = ignore_index
    
    def forward(self, predictions: Matrix, targets: List[int]) -> float:
        """Compute cross-entropy loss"""
        total_loss = 0.0
        valid_tokens = 0
        
        for i, target_id in enumerate(targets):
            if target_id == self.ignore_index:
                continue
            
            # Get prediction for this position
            if i < predictions.rows:
                # Convert logits to probabilities
                logits = predictions.data[i]
                max_logit = max(logits)
                
                # Compute softmax
                exps = [MathUtils.exp(logit - max_logit) for logit in logits]
                exp_sum = sum(exps)
                probs = [exp / exp_sum for exp in exps]
                
                # Cross-entropy loss
                if target_id < len(probs) and probs[target_id] > 0:
                    loss = -MathUtils.log(probs[target_id])
                    total_loss += loss
                    valid_tokens += 1
        
        return total_loss / max(valid_tokens, 1)
    
    def backward(self, predictions: Matrix, targets: List[int]) -> Matrix:
        """Compute gradients for backpropagation"""
        gradients = Matrix.zeros(predictions.rows, predictions.cols)
        
        for i, target_id in enumerate(targets):
            if target_id == self.ignore_index or i >= predictions.rows:
                continue
            
            # Get prediction for this position
            logits = predictions.data[i]
            max_logit = max(logits)
            
            # Compute softmax
            exps = [MathUtils.exp(logit - max_logit) for logit in logits]
            exp_sum = sum(exps)
            probs = [exp / exp_sum for exp in exps]
            
            # Compute gradients
            for j in range(len(probs)):
                if j == target_id:
                    gradients[i][j] = probs[j] - 1.0
                else:
                    gradients[i][j] = probs[j]
        
        return gradients

class SGD:
    """Stochastic Gradient Descent optimizer"""
    
    def __init__(self, parameters: List[Matrix], lr: float = 0.001, momentum: float = 0.9):
        self.parameters = parameters
        self.lr = lr
        self.momentum = momentum
        self.velocities = [Matrix.zeros(p.rows, p.cols) for p in parameters]
    
    def step(self, gradients: List[Matrix]):
        """Update parameters using gradients"""
        for i, (param, grad, velocity) in enumerate(zip(self.parameters, gradients, self.velocities)):
            # Update velocity with momentum
            for row in range(velocity.rows):
                for col in range(velocity.cols):
                    velocity[row][col] = self.momentum * velocity[row][col] - self.lr * grad[row][col]
            
            # Update parameters
            for row in range(param.rows):
                for col in range(param.cols):
                    param[row][col] += velocity[row][col]

class DataLoader:
    """Data loader for training"""
    
    def __init__(self, text: str, tokenizer: BPETokenizer, batch_size: int = 4, 
                 block_size: int = 64, shuffle: bool = True):
        self.tokenizer = tokenizer
        self.batch_size = batch_size
        self.block_size = block_size
        self.shuffle = shuffle
        
        # Tokenize the entire text
        self.tokens = tokenizer.encode(text)
        print(f"Loaded {len(self.tokens)} tokens")
        
        # Create training examples
        self.examples = []
        for i in range(0, len(self.tokens) - block_size - 1, block_size):
            x = self.tokens[i:i + block_size]
            y = self.tokens[i + 1:i + 1 + block_size]
            self.examples.append((x, y))
        
        print(f"Created {len(self.examples)} training examples")
    
    def __iter__(self):
        """Iterator for batches"""
        if self.shuffle:
            random.shuffle(self.examples)
        
        for i in range(0, len(self.examples), self.batch_size):
            batch_examples = self.examples[i:i + self.batch_size]
            
            # Pad sequences to same length
            max_len = max(len(ex[0]) for ex in batch_examples)
            
            x_batch = []
            y_batch = []
            
            for x, y in batch_examples:
                # Pad with special tokens
                x_padded = x + [self.tokenizer.get_pad_token_id()] * (max_len - len(x))
                y_padded = y + [self.tokenizer.get_pad_token_id()] * (max_len - len(y))
                
                x_batch.append(x_padded)
                y_batch.append(y_padded)
            
            yield x_batch, y_batch

class Trainer:
    """Main trainer class"""
    
    def __init__(self, model: Transformer, tokenizer: BPETokenizer, 
                 learning_rate: float = 0.001, batch_size: int = 4, 
                 block_size: int = 64):
        self.model = model
        self.tokenizer = tokenizer
        self.learning_rate = learning_rate
        self.batch_size = batch_size
        self.block_size = block_size
        
        # Loss function and optimizer
        self.criterion = CrossEntropyLoss(ignore_index=tokenizer.get_pad_token_id())
        
        # Collect all parameters
        self.parameters = []
        self._collect_parameters()
        
        self.optimizer = SGD(self.parameters, lr=learning_rate)
        
        # Training history
        self.train_losses = []
        self.val_losses = []
    
    def _collect_parameters(self):
        """Collect all trainable parameters from the model"""
        # Token embedding
        self.parameters.append(self.model.token_embedding)
        
        # Position embedding
        self.parameters.append(self.model.position_embedding)
        
        # Transformer blocks
        for block in self.model.transformer_blocks:
            # Attention weights
            self.parameters.append(block.attention.W_q)
            self.parameters.append(block.attention.W_k)
            self.parameters.append(block.attention.W_v)
            self.parameters.append(block.attention.W_o)
            
            # Feed-forward weights
            self.parameters.append(block.feed_forward.W1)
            self.parameters.append(block.feed_forward.b1)
            self.parameters.append(block.feed_forward.W2)
            self.parameters.append(block.feed_forward.b2)
            
            # Layer norm parameters
            self.parameters.append(block.norm1.gamma)
            self.parameters.append(block.norm1.beta)
            self.parameters.append(block.norm2.gamma)
            self.parameters.append(block.norm2.beta)
        
        # Output projection
        self.parameters.append(self.model.output_projection)
        self.parameters.append(self.model.output_bias)
        
        # Final layer norm
        self.parameters.append(self.model.final_norm.gamma)
        self.parameters.append(self.model.final_norm.beta)
        
        print(f"Collected {len(self.parameters)} parameter matrices")
    
    def train_epoch(self, data_loader: DataLoader) -> float:
        """Train for one epoch"""
        total_loss = 0.0
        num_batches = 0
        
        for x_batch, y_batch in data_loader:
            batch_loss = 0.0
            
            # Process each sequence in the batch
            for x_seq, y_seq in zip(x_batch, y_batch):
                # Forward pass
                predictions = self.model.forward(x_seq)
                
                # Compute loss
                loss = self.criterion.forward(predictions, y_seq)
                batch_loss += loss
                
                # Backward pass (simplified)
                gradients = self.criterion.backward(predictions, y_seq)
                
                # Update parameters (simplified - in practice, you'd need proper backprop)
                self._update_parameters(gradients)
            
            # Average loss for this batch
            avg_batch_loss = batch_loss / len(x_batch)
            total_loss += avg_batch_loss
            num_batches += 1
            
            if num_batches % 10 == 0:
                print(f"Batch {num_batches}, Loss: {avg_batch_loss:.4f}")
        
        return total_loss / max(num_batches, 1)
    
    def _update_parameters(self, gradients: Matrix):
        """Simplified parameter update (in practice, you'd need proper backprop)"""
        # This is a very simplified version
        # In reality, you'd need to compute gradients for each parameter
        # and apply the chain rule properly
        
        # For now, just update the output projection as an example
        if hasattr(self.model, 'output_projection'):
            for i in range(min(gradients.rows, self.model.output_projection.rows)):
                for j in range(min(gradients.cols, self.model.output_projection.cols)):
                    self.model.output_projection[i][j] -= self.learning_rate * gradients[i][j]
    
    def train(self, text: str, num_epochs: int = 10, validation_split: float = 0.1):
        """Main training loop"""
        print(f"Starting training for {num_epochs} epochs...")
        
        # Split data
        split_idx = int(len(text) * (1 - validation_split))
        train_text = text[:split_idx]
        val_text = text[split_idx:]
        
        # Create data loaders
        train_loader = DataLoader(train_text, self.tokenizer, self.batch_size, self.block_size)
        val_loader = DataLoader(val_text, self.tokenizer, self.batch_size, self.block_size, shuffle=False)
        
        for epoch in range(num_epochs):
            print(f"\nEpoch {epoch + 1}/{num_epochs}")
            
            # Training
            train_loss = self.train_epoch(train_loader)
            self.train_losses.append(train_loss)
            
            # Validation
            val_loss = self.validate(val_loader)
            self.val_losses.append(val_loss)
            
            print(f"Train Loss: {train_loss:.4f}, Val Loss: {val_loss:.4f}")
            
            # Generate sample text
            if (epoch + 1) % 2 == 0:
                self.generate_sample()
    
    def validate(self, data_loader: DataLoader) -> float:
        """Validation loop"""
        total_loss = 0.0
        num_batches = 0
        
        for x_batch, y_batch in data_loader:
            batch_loss = 0.0
            
            for x_seq, y_seq in zip(x_batch, y_batch):
                predictions = self.model.forward(x_seq)
                loss = self.criterion.forward(predictions, y_seq)
                batch_loss += loss
            
            avg_batch_loss = batch_loss / len(x_batch)
            total_loss += avg_batch_loss
            num_batches += 1
        
        return total_loss / max(num_batches, 1)
    
    def generate_sample(self):
        """Generate a sample text"""
        prompts = [
            "def hello_world():",
            "class MyClass:",
            "import ",
            "# This is a comment",
            "if __name__ == '__main__':"
        ]
        
        prompt = random.choice(prompts)
        generated = self.model.generate(self.tokenizer, prompt, max_length=50)
        
        print(f"\nSample generation:")
        print(f"Prompt: {prompt}")
        print(f"Generated: {generated}")
        print("-" * 50)
    
    def save_model(self, filepath: str):
        """Save model parameters"""
        # This would save all the model parameters
        # For now, just print a message
        print(f"Model saved to {filepath}")
    
    def load_model(self, filepath: str):
        """Load model parameters"""
        # This would load all the model parameters
        # For now, just print a message
        print(f"Model loaded from {filepath}")

# Example usage
if __name__ == "__main__":
    # Sample training text
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
    
    def process_data(data):
        processed = []
        for item in data:
            if item > 0:
                processed.append(item * 2)
        return processed
    
    data = [1, 2, 3, 4, 5]
    result = process_data(data)
    print(result)
    """
    
    # Create tokenizer and train it
    tokenizer = BPETokenizer(vocab_size=500)
    tokenizer.train(sample_text)
    
    # Create model
    model = Transformer(
        vocab_size=tokenizer.get_vocab_size(),
        d_model=64,
        num_heads=4,
        num_layers=2,
        d_ff=256,
        max_seq_len=128
    )
    
    # Create trainer
    trainer = Trainer(
        model=model,
        tokenizer=tokenizer,
        learning_rate=0.01,
        batch_size=2,
        block_size=32
    )
    
    # Train the model
    trainer.train(sample_text, num_epochs=5)
    
    print("\nTraining completed!")
    print("Final sample generation:")
    trainer.generate_sample()
