# Dockerfile for Quantum-Inspired LLM
FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    g++ \
    gcc \
    cmake \
    git \
    curl \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Install CUDA dependencies (if available)
RUN wget https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2004/x86_64/cuda-ubuntu2004.pin && \
    mv cuda-ubuntu2004.pin /etc/apt/preferences.d/cuda-repository-pin-600 && \
    wget https://developer.download.nvidia.com/compute/cuda/11.8.0/local_installers/cuda-repo-ubuntu2004-11-8-local_11.8.0-520.61.05-1_amd64.deb && \
    dpkg -i cuda-repo-ubuntu2004-11-8-local_11.8.0-520.61.05-1_amd64.deb && \
    cp /var/cuda-repo-ubuntu2004-11-8-local/cuda-*-keyring.gpg /usr/share/keyrings/ && \
    apt-get update && \
    apt-get -y install cuda || echo "CUDA installation failed, continuing without GPU support"

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Compile C++ extensions
RUN python -c "from performance_optimizer import PerformanceOptimizer; PerformanceOptimizer()" || echo "C++ compilation failed, using Python fallback"

# Create models directory
RUN mkdir -p models

# Expose ports
EXPOSE 65432 65433

# Set environment variables
ENV PYTHONPATH=/app
ENV CUDA_VISIBLE_DEVICES=0

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import socket; s = socket.socket(); s.connect(('localhost', 65432)); s.close()" || exit 1

# Default command
CMD ["python", "main.py", "serve"]
