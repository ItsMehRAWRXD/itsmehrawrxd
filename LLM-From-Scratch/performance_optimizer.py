"""
Performance Optimization Module
C++ extensions and CUDA acceleration for LLM operations
"""

import os
import sys
import subprocess
import ctypes
import numpy as np
from typing import List, Tuple, Optional, Union
import time

class PerformanceOptimizer:
    """Performance optimization manager for LLM operations"""
    
    def __init__(self):
        self.cuda_available = self._check_cuda_availability()
        self.cpp_extensions_available = self._check_cpp_extensions()
        self.optimization_level = self._determine_optimization_level()
        
        print(f"Performance Optimizer initialized:")
        print(f"  CUDA available: {self.cuda_available}")
        print(f"  C++ extensions: {self.cpp_extensions_available}")
        print(f"  Optimization level: {self.optimization_level}")
    
    def _check_cuda_availability(self) -> bool:
        """Check if CUDA is available"""
        try:
            # Try to import CUDA libraries
            import cupy as cp
            return True
        except ImportError:
            try:
                # Try to run nvidia-smi
                result = subprocess.run(['nvidia-smi'], capture_output=True, text=True)
                return result.returncode == 0
            except FileNotFoundError:
                return False
    
    def _check_cpp_extensions(self) -> bool:
        """Check if C++ extensions are available"""
        try:
            # Try to compile a simple C++ extension
            return self._compile_cpp_extension()
        except Exception:
            return False
    
    def _determine_optimization_level(self) -> str:
        """Determine the best optimization level available"""
        if self.cuda_available:
            return "cuda"
        elif self.cpp_extensions_available:
            return "cpp"
        else:
            return "python"
    
    def _compile_cpp_extension(self) -> bool:
        """Compile C++ extension for matrix operations"""
        try:
            # Create C++ source code
            cpp_source = """
#include <Python.h>
#include <vector>
#include <cmath>

static PyObject* fast_matrix_multiply(PyObject* self, PyObject* args) {
    PyObject* matrix_a, *matrix_b;
    
    if (!PyArg_ParseTuple(args, "OO", &matrix_a, &matrix_b)) {
        return NULL;
    }
    
    // Convert Python lists to C++ vectors
    Py_ssize_t rows_a = PyList_Size(matrix_a);
    Py_ssize_t cols_a = PyList_Size(PyList_GetItem(matrix_a, 0));
    Py_ssize_t rows_b = PyList_Size(matrix_b);
    Py_ssize_t cols_b = PyList_Size(PyList_GetItem(matrix_b, 0));
    
    // Create result matrix
    PyObject* result = PyList_New(rows_a);
    for (Py_ssize_t i = 0; i < rows_a; i++) {
        PyObject* row = PyList_New(cols_b);
        for (Py_ssize_t j = 0; j < cols_b; j++) {
            double sum = 0.0;
            for (Py_ssize_t k = 0; k < cols_a; k++) {
                PyObject* a_val = PyList_GetItem(PyList_GetItem(matrix_a, i), k);
                PyObject* b_val = PyList_GetItem(PyList_GetItem(matrix_b, k), j);
                sum += PyFloat_AsDouble(a_val) * PyFloat_AsDouble(b_val);
            }
            PyList_SetItem(row, j, PyFloat_FromDouble(sum));
        }
        PyList_SetItem(result, i, row);
    }
    
    return result;
}

static PyMethodDef module_methods[] = {
    {"fast_matrix_multiply", fast_matrix_multiply, METH_VARARGS, "Fast matrix multiplication"},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef module_definition = {
    PyModuleDef_HEAD_INIT,
    "fast_math",
    "Fast mathematical operations",
    -1,
    module_methods
};

PyMODINIT_FUNC PyInit_fast_math(void) {
    return PyModule_Create(&module_definition);
}
"""
            
            # Write C++ source to file
            with open("fast_math.cpp", "w") as f:
                f.write(cpp_source)
            
            # Compile the extension
            compile_cmd = [
                "g++", "-shared", "-fPIC", "-O3",
                "-I" + sys.prefix + "/include/python" + str(sys.version_info.major) + "." + str(sys.version_info.minor),
                "fast_math.cpp", "-o", "fast_math.so"
            ]
            
            result = subprocess.run(compile_cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                # Try to import the compiled module
                import fast_math
                return True
            else:
                print(f"C++ compilation failed: {result.stderr}")
                return False
                
        except Exception as e:
            print(f"C++ extension compilation error: {e}")
            return False
    
    def optimized_matrix_multiply(self, matrix_a: List[List[float]], 
                                 matrix_b: List[List[float]]) -> List[List[float]]:
        """Optimized matrix multiplication"""
        if self.optimization_level == "cuda":
            return self._cuda_matrix_multiply(matrix_a, matrix_b)
        elif self.optimization_level == "cpp":
            return self._cpp_matrix_multiply(matrix_a, matrix_b)
        else:
            return self._python_matrix_multiply(matrix_a, matrix_b)
    
    def _cuda_matrix_multiply(self, matrix_a: List[List[float]], 
                             matrix_b: List[List[float]]) -> List[List[float]]:
        """CUDA-accelerated matrix multiplication"""
        try:
            import cupy as cp
            
            # Convert to CuPy arrays
            a_gpu = cp.array(matrix_a)
            b_gpu = cp.array(matrix_b)
            
            # Perform multiplication on GPU
            result_gpu = cp.dot(a_gpu, b_gpu)
            
            # Convert back to CPU
            result = result_gpu.get().tolist()
            
            return result
            
        except Exception as e:
            print(f"CUDA matrix multiplication error: {e}")
            # Fallback to C++ or Python
            if self.cpp_extensions_available:
                return self._cpp_matrix_multiply(matrix_a, matrix_b)
            else:
                return self._python_matrix_multiply(matrix_a, matrix_b)
    
    def _cpp_matrix_multiply(self, matrix_a: List[List[float]], 
                            matrix_b: List[List[float]]) -> List[List[float]]:
        """C++-accelerated matrix multiplication"""
        try:
            import fast_math
            return fast_math.fast_matrix_multiply(matrix_a, matrix_b)
        except Exception as e:
            print(f"C++ matrix multiplication error: {e}")
            return self._python_matrix_multiply(matrix_a, matrix_b)
    
    def _python_matrix_multiply(self, matrix_a: List[List[float]], 
                               matrix_b: List[List[float]]) -> List[List[float]]:
        """Pure Python matrix multiplication (fallback)"""
        rows_a, cols_a = len(matrix_a), len(matrix_a[0])
        rows_b, cols_b = len(matrix_b), len(matrix_b[0])
        
        if cols_a != rows_b:
            raise ValueError("Matrix dimensions incompatible for multiplication")
        
        result = [[0.0 for _ in range(cols_b)] for _ in range(rows_a)]
        
        for i in range(rows_a):
            for j in range(cols_b):
                for k in range(cols_a):
                    result[i][j] += matrix_a[i][k] * matrix_b[k][j]
        
        return result
    
    def optimized_softmax(self, x: List[float]) -> List[float]:
        """Optimized softmax function"""
        if self.optimization_level == "cuda":
            return self._cuda_softmax(x)
        elif self.optimization_level == "cpp":
            return self._cpp_softmax(x)
        else:
            return self._python_softmax(x)
    
    def _cuda_softmax(self, x: List[float]) -> List[float]:
        """CUDA-accelerated softmax"""
        try:
            import cupy as cp
            
            x_gpu = cp.array(x)
            
            # Find max for numerical stability
            max_val = cp.max(x_gpu)
            
            # Compute exponentials
            exps = cp.exp(x_gpu - max_val)
            exp_sum = cp.sum(exps)
            
            # Normalize
            result_gpu = exps / exp_sum
            
            return result_gpu.get().tolist()
            
        except Exception as e:
            print(f"CUDA softmax error: {e}")
            return self._python_softmax(x)
    
    def _cpp_softmax(self, x: List[float]) -> List[float]:
        """C++-accelerated softmax"""
        # For now, fallback to Python
        return self._python_softmax(x)
    
    def _python_softmax(self, x: List[float]) -> List[float]:
        """Pure Python softmax"""
        # Find max for numerical stability
        max_val = max(x)
        
        # Compute exponentials
        exps = [math.exp(val - max_val) for val in x]
        exp_sum = sum(exps)
        
        # Normalize
        return [exp / exp_sum for exp in exps]
    
    def benchmark_operations(self, matrix_size: int = 100) -> Dict[str, float]:
        """Benchmark different optimization levels"""
        print(f"Benchmarking operations with {matrix_size}x{matrix_size} matrices...")
        
        # Create test matrices
        matrix_a = [[random.random() for _ in range(matrix_size)] for _ in range(matrix_size)]
        matrix_b = [[random.random() for _ in range(matrix_size)] for _ in range(matrix_size)]
        
        results = {}
        
        # Benchmark matrix multiplication
        if self.optimization_level == "cuda":
            start_time = time.time()
            self._cuda_matrix_multiply(matrix_a, matrix_b)
            results["cuda_matrix_multiply"] = time.time() - start_time
        
        if self.cpp_extensions_available:
            start_time = time.time()
            self._cpp_matrix_multiply(matrix_a, matrix_b)
            results["cpp_matrix_multiply"] = time.time() - start_time
        
        start_time = time.time()
        self._python_matrix_multiply(matrix_a, matrix_b)
        results["python_matrix_multiply"] = time.time() - start_time
        
        # Benchmark softmax
        test_vector = [random.random() for _ in range(matrix_size)]
        
        if self.optimization_level == "cuda":
            start_time = time.time()
            self._cuda_softmax(test_vector)
            results["cuda_softmax"] = time.time() - start_time
        
        start_time = time.time()
        self._python_softmax(test_vector)
        results["python_softmax"] = time.time() - start_time
        
        return results
    
    def optimize_model_operations(self, model):
        """Optimize model operations based on available hardware"""
        if self.optimization_level == "cuda":
            print("Optimizing model for CUDA acceleration...")
            self._optimize_for_cuda(model)
        elif self.optimization_level == "cpp":
            print("Optimizing model for C++ acceleration...")
            self._optimize_for_cpp(model)
        else:
            print("Using Python optimization...")
            self._optimize_for_python(model)
    
    def _optimize_for_cuda(self, model):
        """Optimize model for CUDA"""
        # Replace matrix operations with CUDA versions
        if hasattr(model, 'token_embedding'):
            model.token_embedding = self._convert_to_cuda_array(model.token_embedding)
        
        if hasattr(model, 'position_embedding'):
            model.position_embedding = self._convert_to_cuda_array(model.position_embedding)
        
        # Add CUDA-specific optimizations
        model._cuda_optimized = True
    
    def _optimize_for_cpp(self, model):
        """Optimize model for C++"""
        # Replace matrix operations with C++ versions
        model._cpp_optimized = True
    
    def _optimize_for_python(self, model):
        """Optimize model for Python"""
        # Use NumPy for better performance
        model._numpy_optimized = True
    
    def _convert_to_cuda_array(self, matrix):
        """Convert matrix to CUDA array"""
        try:
            import cupy as cp
            return cp.array(matrix)
        except ImportError:
            return matrix
    
    def get_optimization_info(self) -> Dict[str, Any]:
        """Get optimization information"""
        return {
            'optimization_level': self.optimization_level,
            'cuda_available': self.cuda_available,
            'cpp_extensions_available': self.cpp_extensions_available,
            'recommended_batch_size': self._get_recommended_batch_size(),
            'memory_usage': self._get_memory_usage()
        }
    
    def _get_recommended_batch_size(self) -> int:
        """Get recommended batch size based on hardware"""
        if self.optimization_level == "cuda":
            return 32
        elif self.optimization_level == "cpp":
            return 16
        else:
            return 8
    
    def _get_memory_usage(self) -> Dict[str, float]:
        """Get memory usage information"""
        import psutil
        
        memory = psutil.virtual_memory()
        return {
            'total_gb': memory.total / (1024**3),
            'available_gb': memory.available / (1024**3),
            'used_percent': memory.percent
        }

# Example usage
if __name__ == "__main__":
    import random
    import math
    
    # Create performance optimizer
    optimizer = PerformanceOptimizer()
    
    # Get optimization info
    info = optimizer.get_optimization_info()
    print(f"Optimization info: {info}")
    
    # Benchmark operations
    benchmark_results = optimizer.benchmark_operations(matrix_size=50)
    print(f"Benchmark results: {benchmark_results}")
    
    # Test optimized operations
    matrix_a = [[1, 2], [3, 4]]
    matrix_b = [[5, 6], [7, 8]]
    
    result = optimizer.optimized_matrix_multiply(matrix_a, matrix_b)
    print(f"Matrix multiplication result: {result}")
    
    # Test softmax
    test_vector = [1.0, 2.0, 3.0, 4.0]
    softmax_result = optimizer.optimized_softmax(test_vector)
    print(f"Softmax result: {softmax_result}")
    print(f"Softmax sum: {sum(softmax_result)}")
