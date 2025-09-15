'use strict';

const { EventEmitter } = require('events');
const { spawn } = require('child_process');
const { promisify } = require('util');

class CLIAntiFreeze extends EventEmitter {
    constructor(options = {}) {
        super();
        this.name = 'CLI Anti-Freeze Manager';
        this.version = '1.0.0';
        
        // Configuration
        this.config = {
            defaultTimeout: options.defaultTimeout || 30000, // 30 seconds
            maxTimeout: options.maxTimeout || 300000, // 5 minutes
            heartbeatInterval: options.heartbeatInterval || 1000, // 1 second
            maxRetries: options.maxRetries || 3,
            retryDelay: options.retryDelay || 1000,
            enableHeartbeat: options.enableHeartbeat !== false,
            enableTimeout: options.enableTimeout !== false,
            enableProcessMonitoring: options.enableProcessMonitoring !== false,
            ...options
        };
        
        // State tracking
        this.activeOperations = new Map();
        this.operationCount = 0;
        this.timeoutCount = 0;
        this.retryCount = 0;
        this.lastHeartbeat = Date.now();
        
        // Start heartbeat monitoring
        if (this.config.enableHeartbeat) {
            this.startHeartbeat();
        }
    }

    // Create a timeout wrapper for any async operation
    async withTimeout(operation, timeout = null, operationId = null) {
        const actualTimeout = timeout || this.config.defaultTimeout;
        const id = operationId || this.generateOperationId();
        
        if (actualTimeout > this.config.maxTimeout) {
            throw new Error(`Timeout ${actualTimeout}ms exceeds maximum allowed ${this.config.maxTimeout}ms`);
        }

        // Create timeout promise
        const timeoutPromise = new Promise((_, reject) => {
            const timer = setTimeout(() => {
                this.timeoutCount++;
                this.emit('timeout', { id, timeout: actualTimeout });
                reject(new Error(`Operation ${id} timed out after ${actualTimeout}ms`));
            }, actualTimeout);
            
            // Store timer for potential cleanup
            this.activeOperations.set(id, {
                id,
                startTime: Date.now(),
                timeout: actualTimeout,
                timer,
                status: 'running'
            });
            
            // Update heartbeat when operation starts
            this.updateHeartbeat();
        });

        // Create operation promise
        const operationPromise = this.wrapOperation(operation, id);

        try {
            // Race between operation and timeout
            const result = await Promise.race([operationPromise, timeoutPromise]);
            
            // Clean up successful operation
            this.cleanupOperation(id);
            this.emit('operation-complete', { id, result });
            
            return result;
        } catch (error) {
            // Clean up failed operation
            this.cleanupOperation(id);
            this.emit('operation-failed', { id, error });
            throw error;
        }
    }

    // Wrap an operation with monitoring and error handling
    async wrapOperation(operation, operationId) {
        const startTime = Date.now();
        
        try {
            // Execute the operation
            const result = await operation();
            
            const duration = Date.now() - startTime;
            this.emit('operation-success', { 
                id: operationId, 
                duration, 
                result: typeof result === 'object' ? 'object' : typeof result 
            });
            
            return result;
        } catch (error) {
            const duration = Date.now() - startTime;
            this.emit('operation-error', { 
                id: operationId, 
                duration, 
                error: error.message 
            });
            throw error;
        }
    }

    // Execute command with timeout and monitoring
    async executeCommand(command, args = [], options = {}) {
        const {
            timeout = this.config.defaultTimeout,
            cwd = process.cwd(),
            env = process.env,
            stdio = 'pipe',
            killSignal = 'SIGTERM',
            maxBuffer = 1024 * 1024, // 1MB
            retries = this.config.maxRetries
        } = options;

        const operationId = this.generateOperationId();
        
        for (let attempt = 1; attempt <= retries; attempt++) {
            try {
                return await this.withTimeout(async () => {
                    return await this.runCommand(command, args, {
                        cwd,
                        env,
                        stdio,
                        killSignal,
                        maxBuffer
                    });
                }, timeout, `${operationId}-attempt-${attempt}`);
            } catch (error) {
                if (attempt === retries) {
                    this.retryCount++;
                    throw new Error(`Command failed after ${retries} attempts: ${error.message}`);
                }
                
                // Wait before retry
                await this.delay(this.config.retryDelay * attempt);
                this.emit('retry', { operationId, attempt, error: error.message });
            }
        }
    }

    // Run a command with process monitoring
    async runCommand(command, args, options) {
        return new Promise((resolve, reject) => {
            const proc = spawn(command, args, {
                ...options,
                windowsHide: true
            });

            let stdout = '';
            let stderr = '';
            let killed = false;

            // Set up process monitoring
            const processId = proc.pid;
            this.emit('process-started', { command, args, pid: processId });

            // Handle stdout
            if (proc.stdout) {
                proc.stdout.on('data', (data) => {
                    stdout += data.toString();
                });
            }

            // Handle stderr
            if (proc.stderr) {
                proc.stderr.on('data', (data) => {
                    stderr += data.toString();
                });
            }

            // Handle process completion
            proc.on('close', (code, signal) => {
                if (killed) {
                    reject(new Error(`Process killed with signal: ${signal}`));
                } else if (code === 0) {
                    resolve({ stdout, stderr, code, signal });
                } else {
                    reject(new Error(`Process exited with code ${code}: ${stderr || stdout}`));
                }
                
                this.emit('process-completed', { 
                    command, 
                    args, 
                    pid: processId, 
                    code, 
                    signal,
                    stdout: stdout.length,
                    stderr: stderr.length
                });
            });

            // Handle process errors
            proc.on('error', (error) => {
                killed = true;
                reject(new Error(`Process error: ${error.message}`));
                
                this.emit('process-error', { 
                    command, 
                    args, 
                    pid: processId, 
                    error: error.message 
                });
            });

            // Handle process timeout
            const timeoutId = setTimeout(() => {
                if (!proc.killed) {
                    killed = true;
                    proc.kill(options.killSignal);
                    reject(new Error(`Process timeout after ${options.timeout || this.config.defaultTimeout}ms`));
                }
            }, options.timeout || this.config.defaultTimeout);

            // Clean up timeout on completion
            proc.on('close', () => {
                clearTimeout(timeoutId);
            });
        });
    }

    // Execute async function with retry logic
    async executeWithRetry(operation, options = {}) {
        const {
            retries = this.config.maxRetries,
            delay = this.config.retryDelay,
            backoff = true,
            timeout = this.config.defaultTimeout
        } = options;

        const operationId = this.generateOperationId();
        let lastError;

        for (let attempt = 1; attempt <= retries; attempt++) {
            try {
                return await this.withTimeout(operation, timeout, `${operationId}-retry-${attempt}`);
            } catch (error) {
                lastError = error;
                
                if (attempt === retries) {
                    break;
                }

                // Calculate delay with optional backoff
                const retryDelay = backoff ? delay * Math.pow(2, attempt - 1) : delay;
                await this.delay(retryDelay);
                
                this.emit('retry', { operationId, attempt, error: error.message, delay: retryDelay });
            }
        }

        throw new Error(`Operation failed after ${retries} attempts: ${lastError.message}`);
    }

    // Monitor long-running operations
    monitorOperation(operationId, operation, options = {}) {
        const {
            timeout = this.config.defaultTimeout,
            heartbeatInterval = this.config.heartbeatInterval,
            onHeartbeat = null,
            onProgress = null
        } = options;

        const startTime = Date.now();
        let lastHeartbeat = startTime;
        let heartbeatCount = 0;

        // Set up heartbeat monitoring
        const heartbeatTimer = setInterval(() => {
            const now = Date.now();
            const elapsed = now - startTime;
            const timeSinceLastHeartbeat = now - lastHeartbeat;

            heartbeatCount++;
            this.lastHeartbeat = now;

            // Check for operation timeout
            if (timeSinceLastHeartbeat > timeout) {
                clearInterval(heartbeatTimer);
                this.emit('operation-timeout', { 
                    operationId, 
                    elapsed, 
                    heartbeatCount 
                });
                return;
            }

            // Emit heartbeat
            this.emit('heartbeat', { 
                operationId, 
                elapsed, 
                heartbeatCount,
                timeSinceLastHeartbeat 
            });

            if (onHeartbeat) {
                onHeartbeat({ operationId, elapsed, heartbeatCount });
            }
        }, heartbeatInterval);

        // Wrap the operation
        const wrappedOperation = async () => {
            try {
                const result = await operation();
                clearInterval(heartbeatTimer);
                return result;
            } catch (error) {
                clearInterval(heartbeatTimer);
                throw error;
            }
        };

        return this.withTimeout(wrappedOperation, timeout, operationId);
    }

    // Start heartbeat monitoring
    startHeartbeat() {
        this.heartbeatInterval = setInterval(() => {
            const now = Date.now();
            const timeSinceLastHeartbeat = now - this.lastHeartbeat;
            
            // Update heartbeat if we have active operations or if it's been too long
            if (this.activeOperations.size > 0 || timeSinceLastHeartbeat > this.config.defaultTimeout) {
                this.updateHeartbeat();
            }
            
            // Only warn if we have active operations and heartbeat is stale
            if (this.activeOperations.size > 0 && timeSinceLastHeartbeat > this.config.defaultTimeout * 2) {
                this.emit('heartbeat-stale', { 
                    timeSinceLastHeartbeat,
                    activeOperations: this.activeOperations.size 
                });
            }
        }, this.config.heartbeatInterval);
    }

    // Update heartbeat timestamp
    updateHeartbeat() {
        this.lastHeartbeat = Date.now();
    }

    // Clean up operation tracking
    cleanupOperation(operationId) {
        const operation = this.activeOperations.get(operationId);
        if (operation) {
            if (operation.timer) {
                clearTimeout(operation.timer);
            }
            this.activeOperations.delete(operationId);
            
            // Update heartbeat when operation completes
            this.updateHeartbeat();
        }
    }

    // Generate unique operation ID
    generateOperationId() {
        return `op-${++this.operationCount}-${Date.now()}`;
    }

    // Utility delay function
    delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    // Force cleanup of all operations
    forceCleanup() {
        for (const [id, operation] of this.activeOperations) {
            if (operation.timer) {
                clearTimeout(operation.timer);
            }
        }
        this.activeOperations.clear();
        this.emit('force-cleanup', { 
            operationsCleaned: this.activeOperations.size 
        });
    }

    // Get statistics
    getStats() {
        return {
            name: this.name,
            version: this.version,
            activeOperations: this.activeOperations.size,
            totalOperations: this.operationCount,
            timeoutCount: this.timeoutCount,
            retryCount: this.retryCount,
            lastHeartbeat: this.lastHeartbeat,
            config: this.config
        };
    }

    // Health check
    isHealthy() {
        const now = Date.now();
        const timeSinceLastHeartbeat = now - this.lastHeartbeat;
        
        return {
            healthy: timeSinceLastHeartbeat < this.config.defaultTimeout * 2,
            timeSinceLastHeartbeat,
            activeOperations: this.activeOperations.size,
            stats: this.getStats()
        };
    }

    // Stop heartbeat monitoring
    stopHeartbeat() {
        if (this.heartbeatInterval) {
            clearInterval(this.heartbeatInterval);
            this.heartbeatInterval = null;
        }
    }

    // Cleanup and shutdown
    shutdown() {
        this.stopHeartbeat();
        this.forceCleanup();
        this.removeAllListeners();
    }
}

// Create and export singleton instance
const cliAntiFreeze = new CLIAntiFreeze();

module.exports = cliAntiFreeze;
