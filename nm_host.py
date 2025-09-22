#!/usr/bin/env python3
"""
Elegant Python Native Host for Chrome Extension Communication
Class-based and extensible architecture for secure desktop integration
"""

import sys
import json
import struct
import logging
import os
import base64
from typing import Dict, Any, Callable, Optional
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.exceptions import InvalidTag
from pathlib import Path
import hashlib
import secrets

# Configure logging
logging.basicConfig(
    stream=sys.stderr, 
    level=logging.DEBUG, 
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class SecureFileManager:
    """Manages secure file operations with encryption"""
    
    def __init__(self, key: bytes):
        self._key = key
        self._safe_directory = Path.home() / 'AIDesktopHelper_Files'
        self._safe_directory.mkdir(exist_ok=True)
    
    def _encrypt_data(self, data: bytes) -> bytes:
        """Encrypts data using AES-256-CBC"""
        iv = os.urandom(16)
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        cipher = Cipher(algorithms.AES(self._key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return iv + ciphertext
    
    def _decrypt_data(self, data: bytes) -> bytes:
        """Decrypts data using AES-256-CBC"""
        iv = data[:16]
        ciphertext = data[16:]
        cipher = Cipher(algorithms.AES(self._key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        return unpadder.unpad(decrypted_padded_data)
    
    def save_file(self, filename: str, content: str) -> Dict[str, Any]:
        """Saves encrypted file to safe directory"""
        try:
            # Sanitize filename to prevent directory traversal
            safe_filename = os.path.basename(filename)
            if not safe_filename or safe_filename.startswith('.'):
                return {"error": "Invalid filename"}
            
            file_path = self._safe_directory / safe_filename
            encrypted_data = self._encrypt_data(content.encode('utf-8'))
            
            with open(file_path, 'wb') as f:
                f.write(encrypted_data)
            
            logger.info(f"Successfully saved file: {file_path}")
            return {"response": f"File saved to {file_path}", "filename": safe_filename}
            
        except Exception as e:
            logger.error(f"Error saving file: {e}")
            return {"error": "Could not save file"}
    
    def open_file(self, filename: str) -> Dict[str, Any]:
        """Opens and decrypts file from safe directory"""
        try:
            # Sanitize filename
            safe_filename = os.path.basename(filename)
            file_path = self._safe_directory / safe_filename
            
            if not file_path.exists():
                return {"error": "File not found"}
            
            with open(file_path, 'rb') as f:
                encrypted_data = f.read()
            
            decrypted_data = self._decrypt_data(encrypted_data)
            content = decrypted_data.decode('utf-8')
            
            logger.info(f"Successfully opened file: {file_path}")
            return {"response": content, "filename": safe_filename}
            
        except InvalidTag:
            logger.error("Decryption failed: Invalid authentication tag")
            return {"error": "Decryption failed: Invalid key or corrupted data"}
        except Exception as e:
            logger.error(f"Error opening file: {e}")
            return {"error": "Could not open file"}

class SystemInfoManager:
    """Manages system information gathering"""
    
    def get_system_info(self) -> Dict[str, Any]:
        """Gets comprehensive system information"""
        try:
            import platform
            import psutil
            
            return {
                "platform": platform.platform(),
                "system": platform.system(),
                "release": platform.release(),
                "version": platform.version(),
                "machine": platform.machine(),
                "processor": platform.processor(),
                "cpu_count": psutil.cpu_count(),
                "memory_total": psutil.virtual_memory().total,
                "memory_available": psutil.virtual_memory().available,
                "disk_usage": {
                    partition.device: {
                        "total": psutil.disk_usage(partition.mountpoint).total,
                        "used": psutil.disk_usage(partition.mountpoint).used,
                        "free": psutil.disk_usage(partition.mountpoint).free
                    }
                    for partition in psutil.disk_partitions()
                }
            }
        except ImportError:
            return {"error": "Required system libraries not available"}
        except Exception as e:
            logger.error(f"Error getting system info: {e}")
            return {"error": "Could not retrieve system information"}

class ProcessManager:
    """Manages process operations"""
    
    def list_processes(self) -> Dict[str, Any]:
        """Lists running processes"""
        try:
            import psutil
            
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    processes.append(proc.info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            return {"response": processes}
            
        except ImportError:
            return {"error": "psutil library not available"}
        except Exception as e:
            logger.error(f"Error listing processes: {e}")
            return {"error": "Could not list processes"}

class NativeHost:
    """
    Main native host class with extensible command architecture
    Handles secure communication between Chrome extension and desktop
    """
    
    def __init__(self, key: Optional[bytes] = None):
        # Generate secure key if not provided
        self._key = key or os.urandom(32)
        
        # Initialize managers
        self._file_manager = SecureFileManager(self._key)
        self._system_manager = SystemInfoManager()
        self._process_manager = ProcessManager()
        
        # Command registry - easily extensible
        self._commands: Dict[str, Callable[[Dict[str, Any]], Dict[str, Any]]] = {
            "sayHello": self._say_hello,
            "saveFile": self._save_file,
            "openFile": self._open_file,
            "getSystemInfo": self._get_system_info,
            "listProcesses": self._list_processes,
            "executeCommand": self._execute_command,
            "getFileList": self._get_file_list,
            "deleteFile": self._delete_file,
        }
        
        logger.info("Native host initialized with secure key")
    
    def _say_hello(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Simple hello command for testing"""
        return {"response": "Hello from Python native host! Ready for secure operations."}
    
    def _save_file(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Saves file with encryption"""
        filename = payload.get("filename")
        content = payload.get("content", "")
        
        if not filename:
            return {"error": "Filename is required"}
        
        return self._file_manager.save_file(filename, content)
    
    def _open_file(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Opens and decrypts file"""
        filename = payload.get("filename")
        
        if not filename:
            return {"error": "Filename is required"}
        
        return self._file_manager.open_file(filename)
    
    def _get_system_info(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Gets system information"""
        return self._system_manager.get_system_info()
    
    def _list_processes(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Lists running processes"""
        return self._process_manager.list_processes()
    
    def _execute_command(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Executes system command (with security restrictions)"""
        command = payload.get("command")
        
        if not command:
            return {"error": "Command is required"}
        
        # Security: Only allow whitelisted commands
        allowed_commands = ["dir", "ls", "pwd", "whoami", "date", "time"]
        if command.split()[0] not in allowed_commands:
            return {"error": "Command not allowed for security reasons"}
        
        try:
            import subprocess
            result = subprocess.run(
                command, 
                shell=True, 
                capture_output=True, 
                text=True, 
                timeout=30
            )
            
            return {
                "response": {
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "returncode": result.returncode
                }
            }
            
        except subprocess.TimeoutExpired:
            return {"error": "Command timed out"}
        except Exception as e:
            logger.error(f"Error executing command: {e}")
            return {"error": "Could not execute command"}
    
    def _get_file_list(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Gets list of files in safe directory"""
        try:
            files = []
            for file_path in self._file_manager._safe_directory.iterdir():
                if file_path.is_file():
                    files.append({
                        "name": file_path.name,
                        "size": file_path.stat().st_size,
                        "modified": file_path.stat().st_mtime
                    })
            
            return {"response": files}
            
        except Exception as e:
            logger.error(f"Error getting file list: {e}")
            return {"error": "Could not get file list"}
    
    def _delete_file(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Deletes file from safe directory"""
        filename = payload.get("filename")
        
        if not filename:
            return {"error": "Filename is required"}
        
        try:
            safe_filename = os.path.basename(filename)
            file_path = self._file_manager._safe_directory / safe_filename
            
            if not file_path.exists():
                return {"error": "File not found"}
            
            file_path.unlink()
            logger.info(f"Successfully deleted file: {file_path}")
            return {"response": f"File {safe_filename} deleted successfully"}
            
        except Exception as e:
            logger.error(f"Error deleting file: {e}")
            return {"error": "Could not delete file"}
    
    def process_message(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """
        Processes incoming messages and routes to appropriate command handlers
        """
        action = message.get("action")
        payload = message.get("payload", {})
        
        logger.info(f"Processing message: action={action}")
        
        if action in self._commands:
            try:
                return self._commands[action](payload)
            except Exception as e:
                logger.error(f"Error processing command {action}: {e}")
                return {"error": f"Command execution failed: {str(e)}"}
        
        return {"error": "Invalid or unauthorized command"}

def get_message() -> Optional[Dict[str, Any]]:
    """Reads a JSON message from stdin with 4-byte length prefix"""
    try:
        raw_length = sys.stdin.buffer.read(4)
        if not raw_length:
            return None
        
        length = struct.unpack('@I', raw_length)[0]
        message_bytes = sys.stdin.buffer.read(length)
        message_string = message_bytes.decode('utf-8')
        
        return json.loads(message_string)
        
    except (struct.error, json.JSONDecodeError) as e:
        logger.error(f"Failed to parse message: {e}")
        return None

def send_message(message: Dict[str, Any]) -> None:
    """Sends a JSON message to stdout with 4-byte length prefix"""
    try:
        message_string = json.dumps(message)
        message_bytes = message_string.encode('utf-8')
        
        sys.stdout.buffer.write(struct.pack('@I', len(message_bytes)))
        sys.stdout.buffer.write(message_bytes)
        sys.stdout.buffer.flush()
        
    except Exception as e:
        logger.error(f"Failed to send message: {e}")

def main():
    """Main entry point for the native host"""
    try:
        logger.info("Starting Python Native Host")
        
        # Initialize native host with secure key
        native_host = NativeHost()
        
        # Main message processing loop
        while True:
            message = get_message()
            if message is None:
                logger.info("No message received, exiting")
                break
            
            logger.info(f"Received message: {message}")
            
            # Process message and send response
            response = native_host.process_message(message)
            send_message(response)
            
    except KeyboardInterrupt:
        logger.info("Native host interrupted by user")
    except Exception as ex:
        logger.critical(f"Fatal error in native host: {ex}")
        sys.exit(1)

if __name__ == '__main__':
    main()
