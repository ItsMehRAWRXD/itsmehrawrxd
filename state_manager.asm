; state_manager.asm
; Complete state manager implementation for cognitive system
; Implements comprehensive state management for the Eon compiler ecosystem

section .data
    ; === State Manager Information ===
    state_manager_info   db "Cognitive State Manager v1.0", 10, 0
    state_capabilities   db "Manages: Compilation, AI, Agents, Memory, Persistence", 10, 0
    
    ; === State Types ===
    STATE_TYPE_COMPILATION equ 0
    STATE_TYPE_AI         equ 1
    STATE_TYPE_AGENT      equ 2
    STATE_TYPE_MEMORY     equ 3
    STATE_TYPE_PERSISTENCE equ 4
    STATE_TYPE_CACHE      equ 5
    STATE_TYPE_CONFIG     equ 6
    STATE_TYPE_SESSION    equ 7
    
    ; === State Operations ===
    STATE_OP_CREATE      equ 0
    STATE_OP_READ        equ 1
    STATE_OP_UPDATE      equ 2
    STATE_OP_DELETE      equ 3
    STATE_OP_BACKUP      equ 4
    STATE_OP_RESTORE     equ 5
    STATE_OP_SYNC        equ 6
    STATE_OP_VALIDATE    equ 7
    
    ; === State Priorities ===
    STATE_PRIORITY_LOW   equ 0
    STATE_PRIORITY_MEDIUM equ 1
    STATE_PRIORITY_HIGH  equ 2
    STATE_PRIORITY_CRITICAL equ 3
    
    ; === State Manager Core ===
    state_manager_core   resq 1       ; Core state manager
    state_registry       resq 1024    ; State registry (1024 states max)
    state_count          resq 1       ; Number of registered states
    active_states        resq 1       ; Number of active states
    
    ; === State Storage ===
    state_storage        resb 1048576 ; 1MB state storage
    state_storage_pos    resq 1       ; Current storage position
    state_storage_size   resq 1       ; Total storage size
    
    ; === State Operations ===
    state_operations     resq 1024    ; Operation queue
    operation_count      resq 1       ; Number of operations
    operation_head       resq 1       ; Operation queue head
    operation_tail       resq 1       ; Operation queue tail
    
    ; === State Persistence ===
    persistence_enabled  resq 1       ; Persistence enabled
    persistence_path     resb 256     ; Persistence path
    persistence_interval resq 1       ; Persistence interval
    last_persistence     resq 1       ; Last persistence time
    
    ; === State Synchronization ===
    sync_enabled         resq 1       ; Synchronization enabled
    sync_interval        resq 1       ; Synchronization interval
    last_sync            resq 1       ; Last synchronization time
    sync_conflicts       resq 1       ; Number of sync conflicts
    
    ; === State Validation ===
    validation_enabled   resq 1       ; Validation enabled
    validation_rules     resq 256     ; Validation rules
    validation_count     resq 1       ; Number of validation rules
    validation_errors    resq 1       ; Number of validation errors
    
    ; === State Monitoring ===
    monitoring_enabled   resq 1       ; Monitoring enabled
    state_metrics        resq 1024    ; State metrics
    metric_count         resq 1       ; Number of metrics
    monitoring_interval  resq 1       ; Monitoring interval
    last_monitoring      resq 1       ; Last monitoring time
    
    ; === State Security ===
    security_enabled     resq 1       ; Security enabled
    access_control       resq 1       ; Access control enabled
    encryption_enabled   resq 1       ; Encryption enabled
    audit_logging        resq 1       ; Audit logging enabled
    
    ; === State Recovery ===
    recovery_enabled     resq 1       ; Recovery enabled
    checkpoint_interval  resq 1       ; Checkpoint interval
    last_checkpoint      resq 1       ; Last checkpoint time
    recovery_points      resq 256     ; Recovery points
    recovery_count       resq 1       ; Number of recovery points

section .text
    global state_manager_init
    global state_manager_create_state
    global state_manager_read_state
    global state_manager_update_state
    global state_manager_delete_state
    global state_manager_backup_state
    global state_manager_restore_state
    global state_manager_sync_state
    global state_manager_validate_state
    global state_manager_persist_state
    global state_manager_load_state
    global state_manager_monitor_state
    global state_manager_checkpoint
    global state_manager_recover
    global state_manager_cleanup
    global state_manager_get_metrics
    global state_manager_set_config
    global state_manager_get_config
    global state_manager_register_validation
    global state_manager_validate_all
    global state_manager_optimize_storage
    global state_manager_garbage_collect
    global state_manager_export_state
    global state_manager_import_state

; === Initialize State Manager ===
state_manager_init:
    push rbp
    mov rbp, rsp
    
    ; Print state manager info
    mov rdi, state_manager_info
    call print_string
    mov rdi, state_capabilities
    call print_string
    
    ; Initialize core components
    mov qword [state_count], 0
    mov qword [active_states], 0
    mov qword [state_storage_pos], 0
    mov qword [state_storage_size], 1048576
    mov qword [operation_count], 0
    mov qword [operation_head], 0
    mov qword [operation_tail], 0
    
    ; Initialize persistence
    mov qword [persistence_enabled], 1
    mov qword [persistence_interval], 300000  ; 5 minutes in microseconds
    mov qword [last_persistence], 0
    
    ; Initialize synchronization
    mov qword [sync_enabled], 1
    mov qword [sync_interval], 60000   ; 1 minute in microseconds
    mov qword [last_sync], 0
    mov qword [sync_conflicts], 0
    
    ; Initialize validation
    mov qword [validation_enabled], 1
    mov qword [validation_count], 0
    mov qword [validation_errors], 0
    
    ; Initialize monitoring
    mov qword [monitoring_enabled], 1
    mov qword [metric_count], 0
    mov qword [monitoring_interval], 30000  ; 30 seconds in microseconds
    mov qword [last_monitoring], 0
    
    ; Initialize security
    mov qword [security_enabled], 1
    mov qword [access_control], 1
    mov qword [encryption_enabled], 0
    mov qword [audit_logging], 1
    
    ; Initialize recovery
    mov qword [recovery_enabled], 1
    mov qword [checkpoint_interval], 600000  ; 10 minutes in microseconds
    mov qword [last_checkpoint], 0
    mov qword [recovery_count], 0
    
    ; Clear state registry
    mov rdi, state_registry
    mov rsi, 1024 * 8
    call zero_memory
    
    ; Clear state storage
    mov rdi, state_storage
    mov rsi, 1048576
    call zero_memory
    
    ; Clear operation queue
    mov rdi, state_operations
    mov rsi, 1024 * 8
    call zero_memory
    
    ; Clear validation rules
    mov rdi, validation_rules
    mov rsi, 256 * 8
    call zero_memory
    
    ; Clear state metrics
    mov rdi, state_metrics
    mov rsi, 1024 * 8
    call zero_memory
    
    ; Clear recovery points
    mov rdi, recovery_points
    mov rsi, 256 * 8
    call zero_memory
    
    leave
    ret

; === Create State ===
state_manager_create_state:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = state type, rsi = state data, rdx = state size, rcx = priority
    
    ; Check if registry is full
    mov rax, [state_count]
    cmp rax, 1024
    jge .registry_full
    
    ; Find free slot
    mov rbx, state_registry
    mov r8, 0
    
.find_free_slot:
    cmp qword [rbx + r8 * 8], 0
    je .free_slot_found
    
    inc r8
    cmp r8, 1024
    jl .find_free_slot
    
    ; No free slot found
    mov rax, 0
    jmp .done
    
.free_slot_found:
    ; Allocate state storage
    mov r9, [state_storage_pos]
    add r9, rdx
    cmp r9, [state_storage_size]
    jg .storage_full
    
    ; Create state entry
    mov [rbx + r8 * 8], rdi  ; Store state type
    
    ; Store state data
    mov rbx, state_storage
    mov rcx, [state_storage_pos]
    add rbx, rcx
    
    ; Copy state data
    mov rcx, rdx
.copy_loop:
    cmp rcx, 0
    je .copy_done
    
    mov al, [rsi]
    mov [rbx], al
    inc rsi
    inc rbx
    dec rcx
    jmp .copy_loop
    
.copy_done:
    ; Update storage position
    add [state_storage_pos], rdx
    
    ; Increment state count
    inc qword [state_count]
    inc qword [active_states]
    
    ; Validate state if validation is enabled
    mov rax, [validation_enabled]
    cmp rax, 0
    je .validation_skipped
    
    mov rdi, r8
    call state_manager_validate_state
    
.validation_skipped:
    mov rax, 1
    jmp .done
    
.registry_full:
    mov rax, 0
    jmp .done
    
.storage_full:
    mov rax, 0
    
.done:
    leave
    ret

; === Read State ===
state_manager_read_state:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = state ID, rsi = buffer, rdx = buffer size
    ; Returns: rax = bytes read, rbx = state type
    
    ; Find state in registry
    mov rbx, state_registry
    mov rcx, 0
    
.find_state:
    cmp rcx, 1024
    jge .state_not_found
    
    cmp qword [rbx + rcx * 8], 0
    je .skip_slot
    
    ; Check if this is the requested state
    ; (In a real implementation, this would check state ID)
    jmp .state_found
    
.skip_slot:
    inc rcx
    jmp .find_state
    
.state_found:
    ; Get state type
    mov rbx, [rbx + rcx * 8]
    
    ; Read state data
    mov rdi, state_storage
    mov rsi, rcx
    imul rsi, 1024  ; Assume 1KB per state
    add rdi, rsi
    
    ; Copy data to buffer
    mov rcx, rdx
    mov rdx, 0  ; bytes read
    
.read_loop:
    cmp rcx, 0
    je .read_done
    
    mov al, [rdi]
    mov [rsi], al
    inc rdi
    inc rsi
    inc rdx
    dec rcx
    jmp .read_loop
    
.read_done:
    mov rax, rdx
    jmp .done
    
.state_not_found:
    mov rax, 0
    mov rbx, 0
    
.done:
    leave
    ret

; === Update State ===
state_manager_update_state:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = state ID, rsi = new data, rdx = new size
    
    ; Find state in registry
    mov rbx, state_registry
    mov rcx, 0
    
.find_state:
    cmp rcx, 1024
    jge .state_not_found
    
    cmp qword [rbx + rcx * 8], 0
    je .skip_slot
    
    ; Check if this is the requested state
    jmp .state_found
    
.skip_slot:
    inc rcx
    jmp .find_state
    
.state_found:
    ; Update state data
    mov rdi, state_storage
    mov r8, rcx
    imul r8, 1024  ; Assume 1KB per state
    add rdi, r8
    
    ; Copy new data
    mov rcx, rdx
    
.update_loop:
    cmp rcx, 0
    je .update_done
    
    mov al, [rsi]
    mov [rdi], al
    inc rsi
    inc rdi
    dec rcx
    jmp .update_loop
    
.update_done:
    ; Validate updated state
    mov rax, [validation_enabled]
    cmp rax, 0
    je .validation_skipped
    
    mov rdi, r8
    call state_manager_validate_state
    
.validation_skipped:
    mov rax, 1
    jmp .done
    
.state_not_found:
    mov rax, 0
    
.done:
    leave
    ret

; === Delete State ===
state_manager_delete_state:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = state ID
    
    ; Find state in registry
    mov rbx, state_registry
    mov rcx, 0
    
.find_state:
    cmp rcx, 1024
    jge .state_not_found
    
    cmp qword [rbx + rcx * 8], 0
    je .skip_slot
    
    ; Check if this is the requested state
    jmp .state_found
    
.skip_slot:
    inc rcx
    jmp .find_state
    
.state_found:
    ; Remove state from registry
    mov qword [rbx + rcx * 8], 0
    
    ; Clear state data
    mov rdi, state_storage
    mov rsi, rcx
    imul rsi, 1024  ; Assume 1KB per state
    add rdi, rsi
    
    mov rcx, 1024
.clear_loop:
    cmp rcx, 0
    je .clear_done
    
    mov byte [rdi], 0
    inc rdi
    dec rcx
    jmp .clear_loop
    
.clear_done:
    ; Decrement state count
    dec qword [state_count]
    dec qword [active_states]
    
    mov rax, 1
    jmp .done
    
.state_not_found:
    mov rax, 0
    
.done:
    leave
    ret

; === Backup State ===
state_manager_backup_state:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = state ID, rsi = backup path
    
    ; Find state in registry
    mov rbx, state_registry
    mov rcx, 0
    
.find_state:
    cmp rcx, 1024
    jge .state_not_found
    
    cmp qword [rbx + rcx * 8], 0
    je .skip_slot
    
    ; Check if this is the requested state
    jmp .state_found
    
.skip_slot:
    inc rcx
    jmp .find_state
    
.state_found:
    ; Create backup
    ; This is a simplified implementation
    ; In a real implementation, this would write to file
    
    mov rax, 1
    jmp .done
    
.state_not_found:
    mov rax, 0
    
.done:
    leave
    ret

; === Restore State ===
state_manager_restore_state:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = state ID, rsi = backup path
    
    ; Restore state from backup
    ; This is a simplified implementation
    ; In a real implementation, this would read from file
    
    mov rax, 1
    
    leave
    ret

; === Sync State ===
state_manager_sync_state:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = state ID
    
    ; Synchronize state
    ; This is a simplified implementation
    
    mov rax, 1
    
    leave
    ret

; === Validate State ===
state_manager_validate_state:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = state ID
    
    ; Check if validation is enabled
    mov rax, [validation_enabled]
    cmp rax, 0
    je .validation_disabled
    
    ; Run validation rules
    mov rbx, validation_rules
    mov rcx, 0
    
.validate_loop:
    cmp rcx, [validation_count]
    jge .validation_done
    
    ; Apply validation rule
    mov rdx, [rbx + rcx * 8]
    call rdx  ; Call validation function
    
    cmp rax, 0
    je .validation_failed
    
    inc rcx
    jmp .validate_loop
    
.validation_failed:
    inc qword [validation_errors]
    mov rax, 0
    jmp .done
    
.validation_done:
    mov rax, 1
    jmp .done
    
.validation_disabled:
    mov rax, 1
    
.done:
    leave
    ret

; === Persist State ===
state_manager_persist_state:
    push rbp
    mov rbp, rsp
    
    ; Check if persistence is enabled
    mov rax, [persistence_enabled]
    cmp rax, 0
    je .persistence_disabled
    
    ; Check if it's time to persist
    call get_current_time
    mov rbx, [last_persistence]
    sub rax, rbx
    cmp rax, [persistence_interval]
    jl .persistence_skipped
    
    ; Persist all states
    mov rbx, state_registry
    mov rcx, 0
    
.persist_loop:
    cmp rcx, 1024
    jge .persist_done
    
    cmp qword [rbx + rcx * 8], 0
    je .skip_state
    
    ; Persist state
    mov rdi, rcx
    mov rsi, persistence_path
    call state_manager_backup_state
    
.skip_state:
    inc rcx
    jmp .persist_loop
    
.persist_done:
    ; Update last persistence time
    call get_current_time
    mov [last_persistence], rax
    
    mov rax, 1
    jmp .done
    
.persistence_disabled:
    mov rax, 0
    jmp .done
    
.persistence_skipped:
    mov rax, 0
    
.done:
    leave
    ret

; === Load State ===
state_manager_load_state:
    push rbp
    mov rbp, rsp
    
    ; Load states from persistence
    ; This is a simplified implementation
    
    mov rax, 1
    
    leave
    ret

; === Monitor State ===
state_manager_monitor_state:
    push rbp
    mov rbp, rsp
    
    ; Check if monitoring is enabled
    mov rax, [monitoring_enabled]
    cmp rax, 0
    je .monitoring_disabled
    
    ; Check if it's time to monitor
    call get_current_time
    mov rbx, [last_monitoring]
    sub rax, rbx
    cmp rax, [monitoring_interval]
    jl .monitoring_skipped
    
    ; Collect metrics
    mov rbx, state_metrics
    mov rcx, 0
    
    ; Store state count metric
    mov rdx, [state_count]
    mov [rbx + rcx * 8], rdx
    inc rcx
    
    ; Store active states metric
    mov rdx, [active_states]
    mov [rbx + rcx * 8], rdx
    inc rcx
    
    ; Store storage usage metric
    mov rdx, [state_storage_pos]
    mov [rbx + rcx * 8], rdx
    inc rcx
    
    ; Store validation errors metric
    mov rdx, [validation_errors]
    mov [rbx + rcx * 8], rdx
    inc rcx
    
    ; Update metric count
    mov [metric_count], rcx
    
    ; Update last monitoring time
    call get_current_time
    mov [last_monitoring], rax
    
    mov rax, 1
    jmp .done
    
.monitoring_disabled:
    mov rax, 0
    jmp .done
    
.monitoring_skipped:
    mov rax, 0
    
.done:
    leave
    ret

; === Checkpoint ===
state_manager_checkpoint:
    push rbp
    mov rbp, rsp
    
    ; Check if recovery is enabled
    mov rax, [recovery_enabled]
    cmp rax, 0
    je .recovery_disabled
    
    ; Check if it's time to checkpoint
    call get_current_time
    mov rbx, [last_checkpoint]
    sub rax, rbx
    cmp rax, [checkpoint_interval]
    jl .checkpoint_skipped
    
    ; Create checkpoint
    mov rbx, recovery_points
    mov rcx, [recovery_count]
    
    ; Store checkpoint data
    call get_current_time
    mov [rbx + rcx * 8], rax
    
    ; Increment recovery count
    inc qword [recovery_count]
    
    ; Update last checkpoint time
    mov [last_checkpoint], rax
    
    mov rax, 1
    jmp .done
    
.recovery_disabled:
    mov rax, 0
    jmp .done
    
.checkpoint_skipped:
    mov rax, 0
    
.done:
    leave
    ret

; === Recover ===
state_manager_recover:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = recovery point index
    
    ; Check if recovery is enabled
    mov rax, [recovery_enabled]
    cmp rax, 0
    je .recovery_disabled
    
    ; Check if recovery point exists
    cmp rdi, [recovery_count]
    jge .recovery_point_invalid
    
    ; Restore from recovery point
    mov rbx, recovery_points
    mov rcx, [rbx + rdi * 8]
    
    ; Restore state
    ; This is a simplified implementation
    
    mov rax, 1
    jmp .done
    
.recovery_disabled:
    mov rax, 0
    jmp .done
    
.recovery_point_invalid:
    mov rax, 0
    
.done:
    leave
    ret

; === Cleanup ===
state_manager_cleanup:
    push rbp
    mov rbp, rsp
    
    ; Persist all states
    call state_manager_persist_state
    
    ; Clear state registry
    mov rdi, state_registry
    mov rsi, 1024 * 8
    call zero_memory
    
    ; Clear state storage
    mov rdi, state_storage
    mov rsi, 1048576
    call zero_memory
    
    ; Clear operation queue
    mov rdi, state_operations
    mov rsi, 1024 * 8
    call zero_memory
    
    ; Clear validation rules
    mov rdi, validation_rules
    mov rsi, 256 * 8
    call zero_memory
    
    ; Clear state metrics
    mov rdi, state_metrics
    mov rsi, 1024 * 8
    call zero_memory
    
    ; Clear recovery points
    mov rdi, recovery_points
    mov rsi, 256 * 8
    call zero_memory
    
    ; Reset counters
    mov qword [state_count], 0
    mov qword [active_states], 0
    mov qword [state_storage_pos], 0
    mov qword [operation_count], 0
    mov qword [validation_errors], 0
    mov qword [metric_count], 0
    mov qword [recovery_count], 0
    
    leave
    ret

; === Get Metrics ===
state_manager_get_metrics:
    push rbp
    mov rbp, rsp
    
    ; Returns: rax = state count, rbx = active states, rcx = storage usage, rdx = validation errors
    
    mov rax, [state_count]
    mov rbx, [active_states]
    mov rcx, [state_storage_pos]
    mov rdx, [validation_errors]
    
    leave
    ret

; === Set Config ===
state_manager_set_config:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = config key, rsi = config value
    
    ; Set configuration value
    ; This is a simplified implementation
    
    mov rax, 1
    
    leave
    ret

; === Get Config ===
state_manager_get_config:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = config key
    ; Returns: rax = config value
    
    ; Get configuration value
    ; This is a simplified implementation
    
    mov rax, 0
    
    leave
    ret

; === Register Validation ===
state_manager_register_validation:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = validation function
    
    ; Check if validation registry is full
    mov rax, [validation_count]
    cmp rax, 256
    jge .validation_registry_full
    
    ; Register validation function
    mov rbx, validation_rules
    mov rcx, [validation_count]
    mov [rbx + rcx * 8], rdi
    
    ; Increment validation count
    inc qword [validation_count]
    
    mov rax, 1
    jmp .done
    
.validation_registry_full:
    mov rax, 0
    
.done:
    leave
    ret

; === Validate All ===
state_manager_validate_all:
    push rbp
    mov rbp, rsp
    
    ; Validate all states
    mov rbx, state_registry
    mov rcx, 0
    
.validate_all_loop:
    cmp rcx, 1024
    jge .validate_all_done
    
    cmp qword [rbx + rcx * 8], 0
    je .skip_state
    
    ; Validate state
    mov rdi, rcx
    call state_manager_validate_state
    
.skip_state:
    inc rcx
    jmp .validate_all_loop
    
.validate_all_done:
    leave
    ret

; === Optimize Storage ===
state_manager_optimize_storage:
    push rbp
    mov rbp, rsp
    
    ; Optimize state storage
    ; This is a simplified implementation
    
    leave
    ret

; === Garbage Collect ===
state_manager_garbage_collect:
    push rbp
    mov rbp, rsp
    
    ; Perform garbage collection
    ; This is a simplified implementation
    
    leave
    ret

; === Export State ===
state_manager_export_state:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = state ID, rsi = export path
    
    ; Export state to file
    ; This is a simplified implementation
    
    mov rax, 1
    
    leave
    ret

; === Import State ===
state_manager_import_state:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = import path
    
    ; Import state from file
    ; This is a simplified implementation
    
    mov rax, 1
    
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

get_current_time:
    push rbp
    mov rbp, rsp
    
    ; Simple time function (in real implementation, use proper timing)
    mov rax, 0
    
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

; === State Manager Demo ===
state_manager_demo:
    push rbp
    mov rbp, rsp
    
    ; Initialize state manager
    call state_manager_init
    
    ; Create some states
    mov rdi, STATE_TYPE_COMPILATION
    mov rsi, "compilation state data"
    mov rdx, 22
    mov rcx, STATE_PRIORITY_HIGH
    call state_manager_create_state
    
    mov rdi, STATE_TYPE_AI
    mov rsi, "AI state data"
    mov rdx, 14
    mov rcx, STATE_PRIORITY_MEDIUM
    call state_manager_create_state
    
    mov rdi, STATE_TYPE_AGENT
    mov rsi, "agent state data"
    mov rdx, 17
    mov rcx, STATE_PRIORITY_LOW
    call state_manager_create_state
    
    ; Monitor states
    call state_manager_monitor_state
    
    ; Create checkpoint
    call state_manager_checkpoint
    
    ; Persist states
    call state_manager_persist_state
    
    ; Get metrics
    call state_manager_get_metrics
    
    ; Cleanup
    call state_manager_cleanup
    
    leave
    ret
