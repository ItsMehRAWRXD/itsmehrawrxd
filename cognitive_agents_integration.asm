; cognitive_agents_integration.asm
; Integration for C# and Python cognitive agents with the system
; Implements communication and coordination between different cognitive agents

section .data
    ; === Cognitive Agents Integration Information ===
    cognitive_info       db "Cognitive Agents Integration v1.0", 10, 0
    agent_types          db "Supported: C#, Python, Assembly, C++", 10, 0
    
    ; === Agent Types ===
    AGENT_TYPE_CSHARP    equ 0
    AGENT_TYPE_PYTHON    equ 1
    AGENT_TYPE_ASSEMBLY  equ 2
    AGENT_TYPE_CPP       equ 3
    AGENT_TYPE_JAVA      equ 4
    AGENT_TYPE_RUST      equ 5
    
    ; === Agent States ===
    AGENT_STATE_IDLE     equ 0
    AGENT_STATE_ACTIVE   equ 1
    AGENT_STATE_BUSY     equ 2
    AGENT_STATE_ERROR    equ 3
    AGENT_STATE_SLEEPING equ 4
    
    ; === Agent Capabilities ===
    CAPABILITY_LEXING    equ 0x01
    CAPABILITY_PARSING   equ 0x02
    CAPABILITY_SEMANTIC  equ 0x04
    CAPABILITY_OPTIMIZATION equ 0x08
    CAPABILITY_CODEGEN   equ 0x10
    CAPABILITY_ANALYSIS  equ 0x20
    CAPABILITY_DEBUGGING equ 0x40
    CAPABILITY_TESTING   equ 0x80
    
    ; === Agent Communication ===
    MESSAGE_TYPE_REQUEST equ 0
    MESSAGE_TYPE_RESPONSE equ 1
    MESSAGE_TYPE_NOTIFICATION equ 2
    MESSAGE_TYPE_ERROR   equ 3
    MESSAGE_TYPE_HEARTBEAT equ 4
    
    ; === Agent Registry ===
    agent_registry       resq 256     ; Agent registry (256 agents max)
    agent_count          resq 1       ; Number of registered agents
    active_agents        resq 1       ; Number of active agents
    
    ; === Agent Communication ===
    message_queue        resq 1024    ; Message queue (1024 messages max)
    message_queue_head   resq 1       ; Queue head pointer
    message_queue_tail   resq 1       ; Queue tail pointer
    message_queue_size   resq 1       ; Queue size
    
    ; === Agent Coordination ===
    coordination_state   resq 1       ; Global coordination state
    task_distribution    resq 1       ; Task distribution strategy
    load_balancing       resq 1       ; Load balancing enabled
    
    ; === Agent Performance ===
    agent_performance    resq 256     ; Performance metrics per agent
    total_tasks_processed resq 1      ; Total tasks processed
    average_response_time resq 1      ; Average response time
    system_throughput    resq 1       ; System throughput
    
    ; === Agent Security ===
    agent_authentication resq 256     ; Authentication status per agent
    security_level       resq 1       ; Global security level
    access_control       resq 1       ; Access control enabled
    
    ; === Agent Monitoring ===
    monitoring_enabled   resq 1       ; Monitoring enabled
    log_level            resq 1       ; Log level
    debug_mode           resq 1       ; Debug mode enabled

section .text
    global cognitive_agents_init
    global cognitive_agents_register
    global cognitive_agents_unregister
    global cognitive_agents_start
    global cognitive_agents_stop
    global cognitive_agents_send_message
    global cognitive_agents_receive_message
    global cognitive_agents_coordinate
    global cognitive_agents_distribute_task
    global cognitive_agents_balance_load
    global cognitive_agents_monitor
    global cognitive_agents_authenticate
    global cognitive_agents_authorize
    global cognitive_agents_get_status
    global cognitive_agents_get_performance
    global cognitive_agents_handle_error
    global cognitive_agents_cleanup
    global cognitive_agents_heartbeat
    global cognitive_agents_sync
    global cognitive_agents_backup
    global cognitive_agents_restore

; === Initialize Cognitive Agents ===
cognitive_agents_init:
    push rbp
    mov rbp, rsp
    
    ; Print cognitive agents info
    mov rdi, cognitive_info
    call print_string
    mov rdi, agent_types
    call print_string
    
    ; Initialize agent registry
    mov qword [agent_count], 0
    mov qword [active_agents], 0
    
    ; Initialize message queue
    mov qword [message_queue_head], 0
    mov qword [message_queue_tail], 0
    mov qword [message_queue_size], 0
    
    ; Initialize coordination
    mov qword [coordination_state], 0
    mov qword [task_distribution], 0
    mov qword [load_balancing], 1
    
    ; Initialize performance metrics
    mov qword [total_tasks_processed], 0
    mov qword [average_response_time], 0
    mov qword [system_throughput], 0
    
    ; Initialize security
    mov qword [security_level], 1
    mov qword [access_control], 1
    
    ; Initialize monitoring
    mov qword [monitoring_enabled], 1
    mov qword [log_level], 2
    mov qword [debug_mode], 0
    
    ; Clear agent registry
    mov rdi, agent_registry
    mov rsi, 256 * 8
    call zero_memory
    
    ; Clear message queue
    mov rdi, message_queue
    mov rsi, 1024 * 8
    call zero_memory
    
    ; Clear performance metrics
    mov rdi, agent_performance
    mov rsi, 256 * 8
    call zero_memory
    
    ; Clear authentication status
    mov rdi, agent_authentication
    mov rsi, 256 * 8
    call zero_memory
    
    leave
    ret

; === Register Agent ===
cognitive_agents_register:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = agent type, rsi = capabilities, rdx = agent ID
    
    ; Check if registry is full
    mov rax, [agent_count]
    cmp rax, 256
    jge .registry_full
    
    ; Find free slot
    mov rbx, agent_registry
    mov rcx, 0
    
.find_free_slot:
    cmp qword [rbx + rcx * 8], 0
    je .free_slot_found
    
    inc rcx
    cmp rcx, 256
    jl .find_free_slot
    
    ; No free slot found
    mov rax, 0
    jmp .done
    
.free_slot_found:
    ; Register agent
    mov [rbx + rcx * 8], rdx  ; Store agent ID
    
    ; Set agent capabilities
    mov rbx, agent_performance
    mov [rbx + rcx * 8], rsi  ; Store capabilities
    
    ; Set agent state
    mov rbx, agent_authentication
    mov qword [rbx + rcx * 8], AGENT_STATE_IDLE
    
    ; Increment agent count
    inc qword [agent_count]
    
    ; Set agent as active
    inc qword [active_agents]
    
    mov rax, 1
    jmp .done
    
.registry_full:
    mov rax, 0
    
.done:
    leave
    ret

; === Unregister Agent ===
cognitive_agents_unregister:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = agent ID
    
    ; Find agent in registry
    mov rbx, agent_registry
    mov rcx, 0
    
.find_agent:
    cmp qword [rbx + rcx * 8], rdi
    je .agent_found
    
    inc rcx
    cmp rcx, 256
    jl .find_agent
    
    ; Agent not found
    mov rax, 0
    jmp .done
    
.agent_found:
    ; Remove agent from registry
    mov qword [rbx + rcx * 8], 0
    
    ; Clear agent capabilities
    mov rbx, agent_performance
    mov qword [rbx + rcx * 8], 0
    
    ; Clear agent state
    mov rbx, agent_authentication
    mov qword [rbx + rcx * 8], 0
    
    ; Decrement agent count
    dec qword [agent_count]
    dec qword [active_agents]
    
    mov rax, 1
    
.done:
    leave
    ret

; === Start Agents ===
cognitive_agents_start:
    push rbp
    mov rbp, rsp
    
    ; Start all registered agents
    mov rbx, agent_registry
    mov rcx, 0
    
.start_agents_loop:
    cmp rcx, 256
    jge .start_agents_done
    
    cmp qword [rbx + rcx * 8], 0
    je .skip_agent
    
    ; Start agent
    mov rdi, rcx
    call cognitive_agents_start_agent
    
.skip_agent:
    inc rcx
    jmp .start_agents_loop
    
.start_agents_done:
    leave
    ret

; === Start Individual Agent ===
cognitive_agents_start_agent:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = agent index
    
    ; Set agent state to active
    mov rbx, agent_authentication
    mov qword [rbx + rdi * 8], AGENT_STATE_ACTIVE
    
    ; Send start message to agent
    mov rsi, MESSAGE_TYPE_NOTIFICATION
    mov rdx, 1  ; Start command
    call cognitive_agents_send_message
    
    leave
    ret

; === Stop Agents ===
cognitive_agents_stop:
    push rbp
    mov rbp, rsp
    
    ; Stop all active agents
    mov rbx, agent_registry
    mov rcx, 0
    
.stop_agents_loop:
    cmp rcx, 256
    jge .stop_agents_done
    
    cmp qword [rbx + rcx * 8], 0
    je .skip_agent
    
    ; Stop agent
    mov rdi, rcx
    call cognitive_agents_stop_agent
    
.skip_agent:
    inc rcx
    jmp .stop_agents_loop
    
.stop_agents_done:
    leave
    ret

; === Stop Individual Agent ===
cognitive_agents_stop_agent:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = agent index
    
    ; Set agent state to idle
    mov rbx, agent_authentication
    mov qword [rbx + rdi * 8], AGENT_STATE_IDLE
    
    ; Send stop message to agent
    mov rsi, MESSAGE_TYPE_NOTIFICATION
    mov rdx, 0  ; Stop command
    call cognitive_agents_send_message
    
    leave
    ret

; === Send Message ===
cognitive_agents_send_message:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = agent ID, rsi = message type, rdx = message data
    
    ; Check if message queue is full
    mov rax, [message_queue_size]
    cmp rax, 1024
    jge .queue_full
    
    ; Add message to queue
    mov rbx, message_queue
    mov rcx, [message_queue_tail]
    
    ; Store message (simplified - just store agent ID)
    mov [rbx + rcx * 8], rdi
    
    ; Update queue tail
    inc qword [message_queue_tail]
    cmp qword [message_queue_tail], 1024
    jl .queue_tail_ok
    
    mov qword [message_queue_tail], 0
    
.queue_tail_ok:
    ; Increment queue size
    inc qword [message_queue_size]
    
    mov rax, 1
    jmp .done
    
.queue_full:
    mov rax, 0
    
.done:
    leave
    ret

; === Receive Message ===
cognitive_agents_receive_message:
    push rbp
    mov rbp, rsp
    
    ; Returns: rax = message data, rbx = message type, rcx = sender ID
    
    ; Check if message queue is empty
    mov rax, [message_queue_size]
    cmp rax, 0
    je .queue_empty
    
    ; Get message from queue
    mov rbx, message_queue
    mov rcx, [message_queue_head]
    
    ; Retrieve message (simplified)
    mov rax, [rbx + rcx * 8]
    
    ; Update queue head
    inc qword [message_queue_head]
    cmp qword [message_queue_head], 1024
    jl .queue_head_ok
    
    mov qword [message_queue_head], 0
    
.queue_head_ok:
    ; Decrement queue size
    dec qword [message_queue_size]
    
    ; Return message data
    mov rbx, MESSAGE_TYPE_REQUEST  ; Default message type
    mov rcx, rax  ; Sender ID
    jmp .done
    
.queue_empty:
    mov rax, 0
    mov rbx, 0
    mov rcx, 0
    
.done:
    leave
    ret

; === Coordinate Agents ===
cognitive_agents_coordinate:
    push rbp
    mov rbp, rsp
    
    ; Coordinate all active agents
    mov rbx, agent_registry
    mov rcx, 0
    
.coordinate_agents_loop:
    cmp rcx, 256
    jge .coordinate_agents_done
    
    cmp qword [rbx + rcx * 8], 0
    je .skip_agent
    
    ; Coordinate agent
    mov rdi, rcx
    call cognitive_agents_coordinate_agent
    
.skip_agent:
    inc rcx
    jmp .coordinate_agents_loop
    
.coordinate_agents_done:
    leave
    ret

; === Coordinate Individual Agent ===
cognitive_agents_coordinate_agent:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = agent index
    
    ; Check agent state
    mov rbx, agent_authentication
    mov rcx, [rbx + rdi * 8]
    
    cmp rcx, AGENT_STATE_ACTIVE
    je .agent_active
    cmp rcx, AGENT_STATE_BUSY
    je .agent_busy
    cmp rcx, AGENT_STATE_ERROR
    je .agent_error
    
    ; Agent is idle or sleeping
    jmp .done
    
.agent_active:
    ; Agent is active and ready for tasks
    jmp .done
    
.agent_busy:
    ; Agent is busy, check if task is complete
    jmp .done
    
.agent_error:
    ; Agent has error, attempt recovery
    jmp .done
    
.done:
    leave
    ret

; === Distribute Task ===
cognitive_agents_distribute_task:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = task type, rsi = task data
    
    ; Find best agent for task
    mov rbx, agent_registry
    mov rcx, 0
    mov rdx, 0  ; Best agent index
    mov r8, 0   ; Best agent score
    
.find_best_agent:
    cmp rcx, 256
    jge .best_agent_found
    
    cmp qword [rbx + rcx * 8], 0
    je .skip_agent
    
    ; Check agent capabilities
    mov r9, agent_performance
    mov r10, [r9 + rcx * 8]
    
    ; Check if agent has required capability
    test r10, rdi
    jz .skip_agent
    
    ; Check agent state
    mov r9, agent_authentication
    mov r10, [r9 + rcx * 8]
    
    cmp r10, AGENT_STATE_ACTIVE
    jne .skip_agent
    
    ; Agent is suitable, calculate score
    mov r9, rcx  ; Use agent index as score (simplified)
    
    cmp r9, r8
    jle .skip_agent
    
    ; This agent is better
    mov rdx, rcx
    mov r8, r9
    
.skip_agent:
    inc rcx
    jmp .find_best_agent
    
.best_agent_found:
    ; Assign task to best agent
    mov rdi, rdx
    mov rsi, MESSAGE_TYPE_REQUEST
    mov rdx, rsi  ; Task data
    call cognitive_agents_send_message
    
    ; Update agent state
    mov rbx, agent_authentication
    mov qword [rbx + rdi * 8], AGENT_STATE_BUSY
    
    ; Update performance metrics
    inc qword [total_tasks_processed]
    
    leave
    ret

; === Balance Load ===
cognitive_agents_balance_load:
    push rbp
    mov rbp, rsp
    
    ; Check if load balancing is enabled
    mov rax, [load_balancing]
    cmp rax, 0
    je .load_balancing_disabled
    
    ; Calculate load distribution
    mov rax, [active_agents]
    cmp rax, 0
    je .no_active_agents
    
    ; Distribute load evenly
    mov rbx, agent_registry
    mov rcx, 0
    
.balance_load_loop:
    cmp rcx, 256
    jge .balance_load_done
    
    cmp qword [rbx + rcx * 8], 0
    je .skip_agent
    
    ; Check agent load
    mov rdi, rcx
    call cognitive_agents_check_agent_load
    
    ; Redistribute if necessary
    call cognitive_agents_redistribute_load
    
.skip_agent:
    inc rcx
    jmp .balance_load_loop
    
.balance_load_done:
    jmp .done
    
.load_balancing_disabled:
    ; Load balancing is disabled
    jmp .done
    
.no_active_agents:
    ; No active agents to balance
    
.done:
    leave
    ret

; === Check Agent Load ===
cognitive_agents_check_agent_load:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = agent index
    ; Returns: rax = load level (0=low, 1=medium, 2=high)
    
    ; Check agent state
    mov rbx, agent_authentication
    mov rcx, [rbx + rdi * 8]
    
    cmp rcx, AGENT_STATE_BUSY
    je .high_load
    cmp rcx, AGENT_STATE_ACTIVE
    je .medium_load
    cmp rcx, AGENT_STATE_IDLE
    je .low_load
    
    ; Default to low load
    mov rax, 0
    jmp .done
    
.high_load:
    mov rax, 2
    jmp .done
    
.medium_load:
    mov rax, 1
    jmp .done
    
.low_load:
    mov rax, 0
    jmp .done
    
.done:
    leave
    ret

; === Redistribute Load ===
cognitive_agents_redistribute_load:
    push rbp
    mov rbp, rsp
    
    ; Redistribute load between agents
    ; This is a simplified implementation
    
    leave
    ret

; === Monitor Agents ===
cognitive_agents_monitor:
    push rbp
    mov rbp, rsp
    
    ; Check if monitoring is enabled
    mov rax, [monitoring_enabled]
    cmp rax, 0
    je .monitoring_disabled
    
    ; Monitor all agents
    mov rbx, agent_registry
    mov rcx, 0
    
.monitor_agents_loop:
    cmp rcx, 256
    jge .monitor_agents_done
    
    cmp qword [rbx + rcx * 8], 0
    je .skip_agent
    
    ; Monitor agent
    mov rdi, rcx
    call cognitive_agents_monitor_agent
    
.skip_agent:
    inc rcx
    jmp .monitor_agents_loop
    
.monitor_agents_done:
    jmp .done
    
.monitoring_disabled:
    ; Monitoring is disabled
    
.done:
    leave
    ret

; === Monitor Individual Agent ===
cognitive_agents_monitor_agent:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = agent index
    
    ; Check agent health
    call cognitive_agents_check_agent_health
    
    ; Update performance metrics
    call cognitive_agents_update_performance_metrics
    
    ; Log agent status
    call cognitive_agents_log_agent_status
    
    leave
    ret

; === Check Agent Health ===
cognitive_agents_check_agent_health:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = agent index
    ; Returns: rax = health status (0=healthy, 1=warning, 2=error)
    
    ; Check agent state
    mov rbx, agent_authentication
    mov rcx, [rbx + rdi * 8]
    
    cmp rcx, AGENT_STATE_ERROR
    je .agent_error
    cmp rcx, AGENT_STATE_SLEEPING
    je .agent_warning
    cmp rcx, AGENT_STATE_ACTIVE
    je .agent_healthy
    cmp rcx, AGENT_STATE_BUSY
    je .agent_healthy
    cmp rcx, AGENT_STATE_IDLE
    je .agent_healthy
    
    ; Default to warning
    mov rax, 1
    jmp .done
    
.agent_error:
    mov rax, 2
    jmp .done
    
.agent_warning:
    mov rax, 1
    jmp .done
    
.agent_healthy:
    mov rax, 0
    jmp .done
    
.done:
    leave
    ret

; === Update Performance Metrics ===
cognitive_agents_update_performance_metrics:
    push rbp
    mov rbp, rsp
    
    ; Update system performance metrics
    ; This is a simplified implementation
    
    leave
    ret

; === Log Agent Status ===
cognitive_agents_log_agent_status:
    push rbp
    mov rbp, rsp
    
    ; Log agent status to monitoring system
    ; This is a simplified implementation
    
    leave
    ret

; === Authenticate Agent ===
cognitive_agents_authenticate:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = agent ID, rsi = credentials
    
    ; Check security level
    mov rax, [security_level]
    cmp rax, 0
    je .authentication_disabled
    
    ; Authenticate agent
    ; This is a simplified implementation
    mov rax, 1  ; Authentication successful
    
    jmp .done
    
.authentication_disabled:
    ; Authentication is disabled
    mov rax, 1
    
.done:
    leave
    ret

; === Authorize Agent ===
cognitive_agents_authorize:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = agent ID, rsi = requested capability
    
    ; Check access control
    mov rax, [access_control]
    cmp rax, 0
    je .authorization_disabled
    
    ; Authorize agent
    ; This is a simplified implementation
    mov rax, 1  ; Authorization successful
    
    jmp .done
    
.authorization_disabled:
    ; Authorization is disabled
    mov rax, 1
    
.done:
    leave
    ret

; === Get Agent Status ===
cognitive_agents_get_status:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = agent ID
    ; Returns: rax = agent status
    
    ; Find agent in registry
    mov rbx, agent_registry
    mov rcx, 0
    
.find_agent:
    cmp qword [rbx + rcx * 8], rdi
    je .agent_found
    
    inc rcx
    cmp rcx, 256
    jl .find_agent
    
    ; Agent not found
    mov rax, 0
    jmp .done
    
.agent_found:
    ; Get agent status
    mov rbx, agent_authentication
    mov rax, [rbx + rcx * 8]
    
.done:
    leave
    ret

; === Get Performance Metrics ===
cognitive_agents_get_performance:
    push rbp
    mov rbp, rsp
    
    ; Returns: rax = total tasks, rbx = average response time, rcx = throughput
    
    mov rax, [total_tasks_processed]
    mov rbx, [average_response_time]
    mov rcx, [system_throughput]
    
    leave
    ret

; === Handle Error ===
cognitive_agents_handle_error:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = agent ID, rsi = error code, rdx = error message
    
    ; Log error
    call cognitive_agents_log_error
    
    ; Attempt error recovery
    call cognitive_agents_recover_from_error
    
    ; Update agent state
    mov rbx, agent_authentication
    mov qword [rbx + rdi * 8], AGENT_STATE_ERROR
    
    leave
    ret

; === Log Error ===
cognitive_agents_log_error:
    push rbp
    mov rbp, rsp
    
    ; Log error to monitoring system
    ; This is a simplified implementation
    
    leave
    ret

; === Recover From Error ===
cognitive_agents_recover_from_error:
    push rbp
    mov rbp, rsp
    
    ; Attempt to recover from error
    ; This is a simplified implementation
    
    leave
    ret

; === Cleanup ===
cognitive_agents_cleanup:
    push rbp
    mov rbp, rsp
    
    ; Stop all agents
    call cognitive_agents_stop
    
    ; Clear message queue
    mov qword [message_queue_head], 0
    mov qword [message_queue_tail], 0
    mov qword [message_queue_size], 0
    
    ; Reset performance metrics
    mov qword [total_tasks_processed], 0
    mov qword [average_response_time], 0
    mov qword [system_throughput], 0
    
    ; Clear agent registry
    mov rdi, agent_registry
    mov rsi, 256 * 8
    call zero_memory
    
    ; Clear performance metrics
    mov rdi, agent_performance
    mov rsi, 256 * 8
    call zero_memory
    
    ; Clear authentication status
    mov rdi, agent_authentication
    mov rsi, 256 * 8
    call zero_memory
    
    leave
    ret

; === Heartbeat ===
cognitive_agents_heartbeat:
    push rbp
    mov rbp, rsp
    
    ; Send heartbeat to all agents
    mov rbx, agent_registry
    mov rcx, 0
    
.heartbeat_loop:
    cmp rcx, 256
    jge .heartbeat_done
    
    cmp qword [rbx + rcx * 8], 0
    je .skip_agent
    
    ; Send heartbeat to agent
    mov rdi, rcx
    mov rsi, MESSAGE_TYPE_HEARTBEAT
    mov rdx, 0
    call cognitive_agents_send_message
    
.skip_agent:
    inc rcx
    jmp .heartbeat_loop
    
.heartbeat_done:
    leave
    ret

; === Sync Agents ===
cognitive_agents_sync:
    push rbp
    mov rbp, rsp
    
    ; Synchronize all agents
    call cognitive_agents_coordinate
    call cognitive_agents_balance_load
    call cognitive_agents_monitor
    
    leave
    ret

; === Backup Agents ===
cognitive_agents_backup:
    push rbp
    mov rbp, rsp
    
    ; Backup agent state and data
    ; This is a simplified implementation
    
    leave
    ret

; === Restore Agents ===
cognitive_agents_restore:
    push rbp
    mov rbp, rsp
    
    ; Restore agent state and data
    ; This is a simplified implementation
    
    leave
    ret

; === Utility Functions ===
zero_memory:
    push rbp
    mov rbp, rsp
    push rbx
    push rcx
    
    ; Args: rdi = memory pointer, rsi = size
    mov rbx, rdi
    mov rcx, rsi
    
.zero_loop:
    cmp rcx, 0
    je .zero_done
    
    mov byte [rbx], 0
    inc rbx
    dec rcx
    jmp .zero_loop
    
.zero_done:
    pop rcx
    pop rbx
    leave
    ret

print_string:
    push rbp
    mov rbp, rsp
    push rbx
    
    mov rbx, rdi
    mov rdx, 0
    
    ; Calculate string length
.length_loop:
    cmp byte [rbx + rdx], 0
    je .print
    inc rdx
    jmp .length_loop
    
.print:
    mov rax, 1              ; sys_write
    mov rdi, 1              ; stdout
    mov rsi, rbx
    syscall
    
    pop rbx
    leave
    ret

; === Cognitive Agents Integration Demo ===
cognitive_agents_demo:
    push rbp
    mov rbp, rsp
    
    ; Initialize cognitive agents
    call cognitive_agents_init
    
    ; Register C# agent
    mov rdi, AGENT_TYPE_CSHARP
    mov rsi, CAPABILITY_LEXING | CAPABILITY_PARSING
    mov rdx, 1
    call cognitive_agents_register
    
    ; Register Python agent
    mov rdi, AGENT_TYPE_PYTHON
    mov rsi, CAPABILITY_SEMANTIC | CAPABILITY_ANALYSIS
    mov rdx, 2
    call cognitive_agents_register
    
    ; Register Assembly agent
    mov rdi, AGENT_TYPE_ASSEMBLY
    mov rsi, CAPABILITY_CODEGEN | CAPABILITY_OPTIMIZATION
    mov rdx, 3
    call cognitive_agents_register
    
    ; Start agents
    call cognitive_agents_start
    
    ; Distribute tasks
    mov rdi, CAPABILITY_LEXING
    mov rsi, "source code"
    call cognitive_agents_distribute_task
    
    ; Monitor agents
    call cognitive_agents_monitor
    
    ; Sync agents
    call cognitive_agents_sync
    
    ; Get performance metrics
    call cognitive_agents_get_performance
    
    ; Cleanup
    call cognitive_agents_cleanup
    
    leave
    ret
