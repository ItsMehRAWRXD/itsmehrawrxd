; reverser_runtime.asm
; Stack-based runtime and memory management for Reverser language
; Implements a virtual stack machine with garbage collection

section .data
    ; Runtime constants
    STACK_SIZE        equ 65536    ; 64KB stack
    HEAP_SIZE         equ 1048576  ; 1MB heap
    MAX_OBJECTS       equ 1024     ; Maximum objects in heap
    OBJECT_HEADER_SIZE equ 16      ; Size of object header
    
    ; Runtime state
    runtime_initialized db 0
    stack_pointer      dq 0
    heap_pointer       dq 0
    object_count       dq 0
    gc_threshold       dq 512      ; Trigger GC when 512 objects
    
    ; Error messages
    error_stack_overflow db "Stack overflow", 0
    error_heap_overflow  db "Heap overflow", 0
    error_null_pointer   db "Null pointer access", 0
    error_invalid_object db "Invalid object access", 0

section .bss
    ; Runtime memory areas
    runtime_stack      resb STACK_SIZE
    runtime_heap       resb HEAP_SIZE
    object_table       resq MAX_OBJECTS * 2  ; [address, size] pairs
    gc_mark_bits       resb MAX_OBJECTS      ; Mark bits for garbage collection
    
    ; Runtime variables
    current_frame      resq 1      ; Current stack frame pointer
    frame_count        resq 1      ; Number of active frames
    temp_registers     resq 8      ; Temporary registers for operations

section .text
    global runtime_init
    global runtime_cleanup
    global stack_push
    global stack_pop
    global stack_peek
    global stack_dup
    global stack_swap
    global stack_rot
    global heap_alloc
    global heap_free
    global gc_collect
    global runtime_execute
    global runtime_call_function
    global runtime_return

; Initialize the runtime system
runtime_init:
    push rbx
    push rcx
    push rdx
    
    ; Check if already initialized
    cmp byte [runtime_initialized], 1
    je .already_init
    
    ; Initialize stack
    mov qword [stack_pointer], runtime_stack
    mov qword [current_frame], runtime_stack
    mov qword [frame_count], 0
    
    ; Initialize heap
    mov qword [heap_pointer], runtime_heap
    mov qword [object_count], 0
    
    ; Clear object table
    mov rcx, MAX_OBJECTS * 2
    mov rdi, object_table
    xor rax, rax
    rep stosq
    
    ; Clear GC mark bits
    mov rcx, MAX_OBJECTS
    mov rdi, gc_mark_bits
    xor rax, rax
    rep stosb
    
    ; Mark as initialized
    mov byte [runtime_initialized], 1
    
.already_init:
    pop rdx
    pop rcx
    pop rbx
    ret

; Cleanup runtime system
runtime_cleanup:
    push rbx
    
    ; Free all objects
    mov rbx, 0
.cleanup_loop:
    cmp rbx, [object_count]
    jge .cleanup_done
    
    ; Free object
    mov rdi, [object_table + rbx * 16]  ; Get object address
    call heap_free
    
    inc rbx
    jmp .cleanup_loop

.cleanup_done:
    mov byte [runtime_initialized], 0
    pop rbx
    ret

; Push value onto stack
; Input: rdi = value to push
stack_push:
    push rbx
    push rcx
    
    ; Check stack overflow
    mov rbx, [stack_pointer]
    mov rcx, runtime_stack
    add rcx, STACK_SIZE
    cmp rbx, rcx
    jge .stack_overflow
    
    ; Push value
    mov [rbx], rdi
    add rbx, 8
    mov [stack_pointer], rbx
    
    jmp .return

.stack_overflow:
    ; Handle stack overflow
    mov rdi, error_stack_overflow
    call runtime_error
    jmp .return

.return:
    pop rcx
    pop rbx
    ret

; Pop value from stack
; Output: rax = popped value
stack_pop:
    push rbx
    
    ; Check stack underflow
    mov rbx, [stack_pointer]
    mov rax, runtime_stack
    cmp rbx, rax
    jle .stack_underflow
    
    ; Pop value
    sub rbx, 8
    mov rax, [rbx]
    mov [stack_pointer], rbx
    
    jmp .return

.stack_underflow:
    ; Handle stack underflow
    mov rdi, error_stack_overflow
    call runtime_error
    xor rax, rax
    jmp .return

.return:
    pop rbx
    ret

; Peek at top of stack without popping
; Output: rax = top value
stack_peek:
    push rbx
    
    mov rbx, [stack_pointer]
    mov rax, runtime_stack
    cmp rbx, rax
    jle .stack_underflow
    
    sub rbx, 8
    mov rax, [rbx]
    jmp .return

.stack_underflow:
    xor rax, rax

.return:
    pop rbx
    ret

; Duplicate top of stack
stack_dup:
    push rdi
    
    call stack_peek
    mov rdi, rax
    call stack_push
    
    pop rdi
    ret

; Swap top two stack elements
stack_swap:
    push rdi
    push rsi
    
    call stack_pop
    mov rdi, rax
    call stack_pop
    mov rsi, rax
    
    push rdi
    push rsi
    call stack_push
    pop rsi
    call stack_push
    pop rdi
    
    pop rsi
    pop rdi
    ret

; Rotate top three stack elements (a b c -> c a b)
stack_rot:
    push rdi
    push rsi
    push rdx
    
    call stack_pop  ; c
    mov rdi, rax
    call stack_pop  ; b
    mov rsi, rax
    call stack_pop  ; a
    mov rdx, rax
    
    ; Push back in rotated order: c, a, b
    push rsi  ; b
    push rdi  ; c
    call stack_push
    pop rdi
    push rdx  ; a
    call stack_push
    pop rdx
    call stack_push
    pop rsi
    
    pop rdx
    pop rsi
    pop rdi
    ret

; Allocate memory on heap
; Input: rdi = size in bytes
; Output: rax = pointer to allocated memory or 0 if failed
heap_alloc:
    push rbx
    push rcx
    push rdx
    
    ; Check if we have space for new object
    mov rbx, [object_count]
    cmp rbx, MAX_OBJECTS
    jge .heap_full
    
    ; Check if heap has enough space
    mov rcx, [heap_pointer]
    mov rdx, runtime_heap
    add rdx, HEAP_SIZE
    sub rdx, rdi
    sub rdx, OBJECT_HEADER_SIZE
    cmp rcx, rdx
    jg .heap_full
    
    ; Allocate object
    mov rax, rcx
    add rcx, OBJECT_HEADER_SIZE
    
    ; Store object in table
    mov [object_table + rbx * 16], rax      ; Store address
    mov [object_table + rbx * 16 + 8], rdi  ; Store size
    
    ; Initialize object header
    mov [rax], rdi        ; Size
    mov qword [rax + 8], 0 ; Reference count
    
    ; Update heap pointer
    add rcx, rdi
    mov [heap_pointer], rcx
    
    ; Increment object count
    inc qword [object_count]
    
    ; Check if we need garbage collection
    mov rbx, [object_count]
    cmp rbx, [gc_threshold]
    jge .trigger_gc
    
    jmp .return

.heap_full:
    ; Try garbage collection
    call gc_collect
    
    ; Try allocation again
    mov rbx, [object_count]
    cmp rbx, MAX_OBJECTS
    jge .allocation_failed
    
    mov rcx, [heap_pointer]
    mov rdx, runtime_heap
    add rdx, HEAP_SIZE
    sub rdx, rdi
    sub rdx, OBJECT_HEADER_SIZE
    cmp rcx, rdx
    jg .allocation_failed
    
    ; Allocate object
    mov rax, rcx
    add rcx, OBJECT_HEADER_SIZE
    
    ; Store object in table
    mov [object_table + rbx * 16], rax
    mov [object_table + rbx * 16 + 8], rdi
    
    ; Initialize object header
    mov [rax], rdi
    mov qword [rax + 8], 0
    
    ; Update heap pointer
    add rcx, rdi
    mov [heap_pointer], rcx
    
    ; Increment object count
    inc qword [object_count]
    
    jmp .return

.trigger_gc:
    call gc_collect
    jmp .return

.allocation_failed:
    mov rdi, error_heap_overflow
    call runtime_error
    xor rax, rax
    jmp .return

.return:
    pop rdx
    pop rcx
    pop rbx
    ret

; Free memory on heap
; Input: rdi = pointer to memory to free
heap_free:
    push rbx
    push rcx
    push rdx
    
    ; Find object in table
    mov rbx, 0
.find_loop:
    cmp rbx, [object_count]
    jge .object_not_found
    
    mov rcx, [object_table + rbx * 16]
    cmp rcx, rdi
    je .found_object
    
    inc rbx
    jmp .find_loop

.found_object:
    ; Remove object from table (swap with last)
    mov rcx, [object_count]
    dec rcx
    mov [object_count], rcx
    
    ; If not the last object, swap
    cmp rbx, rcx
    je .remove_done
    
    ; Swap with last object
    mov rdx, [object_table + rcx * 16]
    mov [object_table + rbx * 16], rdx
    mov rdx, [object_table + rcx * 16 + 8]
    mov [object_table + rbx * 16 + 8], rdx

.remove_done:
    jmp .return

.object_not_found:
    mov rdi, error_invalid_object
    call runtime_error
    jmp .return

.return:
    pop rdx
    pop rcx
    pop rbx
    ret

; Garbage collection (mark and sweep)
gc_collect:
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    
    ; Mark phase: mark all reachable objects
    call gc_mark_phase
    
    ; Sweep phase: free unmarked objects
    call gc_sweep_phase
    
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    ret

; Mark phase of garbage collection
gc_mark_phase:
    push rbx
    push rcx
    push rdx
    
    ; Clear all mark bits
    mov rcx, MAX_OBJECTS
    mov rdi, gc_mark_bits
    xor rax, rax
    rep stosb
    
    ; Mark objects reachable from stack
    mov rbx, runtime_stack
.mark_stack_loop:
    cmp rbx, [stack_pointer]
    jge .mark_stack_done
    
    mov rcx, [rbx]
    call gc_mark_object
    add rbx, 8
    jmp .mark_stack_loop

.mark_stack_done:
    pop rdx
    pop rcx
    pop rbx
    ret

; Mark an object as reachable
; Input: rdi = object pointer
gc_mark_object:
    push rbx
    push rcx
    
    ; Find object in table
    mov rbx, 0
.find_mark_loop:
    cmp rbx, [object_count]
    jge .mark_done
    
    mov rcx, [object_table + rbx * 16]
    cmp rcx, rdi
    je .mark_found
    
    inc rbx
    jmp .find_mark_loop

.mark_found:
    ; Set mark bit
    mov byte [gc_mark_bits + rbx], 1

.mark_done:
    pop rcx
    pop rbx
    ret

; Sweep phase of garbage collection
gc_sweep_phase:
    push rbx
    push rcx
    push rdx
    
    mov rbx, 0
    mov rcx, 0  ; New object count
    
.sweep_loop:
    cmp rbx, [object_count]
    jge .sweep_done
    
    ; Check if object is marked
    cmp byte [gc_mark_bits + rbx], 1
    je .keep_object
    
    ; Free unmarked object
    mov rdx, [object_table + rbx * 16]
    ; Object will be removed by compaction
    jmp .next_object

.keep_object:
    ; Move object to new position if needed
    cmp rbx, rcx
    je .no_move_needed
    
    ; Move object entry
    mov rdx, [object_table + rbx * 16]
    mov [object_table + rcx * 16], rdx
    mov rdx, [object_table + rbx * 16 + 8]
    mov [object_table + rcx * 16 + 8], rdx

.no_move_needed:
    inc rcx

.next_object:
    inc rbx
    jmp .sweep_loop

.sweep_done:
    mov [object_count], rcx
    pop rdx
    pop rcx
    pop rbx
    ret

; Execute Reverser bytecode
; Input: rdi = pointer to bytecode, rsi = bytecode length
runtime_execute:
    push rbx
    push rcx
    push rdx
    
    mov rbx, rdi  ; Bytecode pointer
    mov rcx, rsi  ; Bytecode length
    mov rdx, 0    ; Instruction pointer
    
.execute_loop:
    cmp rdx, rcx
    jge .execute_done
    
    ; Get instruction
    mov al, [rbx + rdx]
    inc rdx
    
    ; Execute instruction
    cmp al, 0x01  ; PUSH_IMM
    je .push_imm
    cmp al, 0x02  ; PUSH_VAR
    je .push_var
    cmp al, 0x03  ; POP_VAR
    je .pop_var
    cmp al, 0x04  ; ADD
    je .add_op
    cmp al, 0x05  ; SUB
    je .sub_op
    cmp al, 0x06  ; MUL
    je .mul_op
    cmp al, 0x07  ; DIV
    je .div_op
    cmp al, 0x08  ; CALL
    je .call_func
    cmp al, 0x09  ; RET
    je .ret_func
    cmp al, 0x0A  ; JMP
    je .jmp_op
    cmp al, 0x0B  ; JZ
    je .jz_op
    cmp al, 0x0C  ; ALLOC
    je .alloc_op
    cmp al, 0x0D  ; FREE
    je .free_op
    cmp al, 0x0E  ; DUP
    je .dup_op
    cmp al, 0x0F  ; SWAP
    je .swap_op
    cmp al, 0x10  ; ROT
    je .rot_op
    
    ; Unknown instruction
    jmp .execute_done

.push_imm:
    ; Push immediate value (8 bytes)
    mov rdi, [rbx + rdx]
    call stack_push
    add rdx, 8
    jmp .execute_loop

.push_var:
    ; Push variable value (variable index in next byte)
    mov al, [rbx + rdx]
    inc rdx
    ; TODO: Implement variable access
    jmp .execute_loop

.pop_var:
    ; Pop to variable (variable index in next byte)
    mov al, [rbx + rdx]
    inc rdx
    call stack_pop
    ; TODO: Implement variable storage
    jmp .execute_loop

.add_op:
    call stack_pop
    mov rdi, rax
    call stack_pop
    add rax, rdi
    mov rdi, rax
    call stack_push
    jmp .execute_loop

.sub_op:
    call stack_pop
    mov rdi, rax
    call stack_pop
    sub rax, rdi
    mov rdi, rax
    call stack_push
    jmp .execute_loop

.mul_op:
    call stack_pop
    mov rdi, rax
    call stack_pop
    imul rax, rdi
    mov rdi, rax
    call stack_push
    jmp .execute_loop

.div_op:
    call stack_pop
    mov rdi, rax
    call stack_pop
    cqo
    idiv rdi
    mov rdi, rax
    call stack_push
    jmp .execute_loop

.call_func:
    ; Function call (function index in next 4 bytes)
    mov eax, [rbx + rdx]
    add rdx, 4
    ; TODO: Implement function calls
    jmp .execute_loop

.ret_func:
    ; Return from function
    ; TODO: Implement function returns
    jmp .execute_done

.jmp_op:
    ; Jump (offset in next 4 bytes)
    mov eax, [rbx + rdx]
    add rdx, 4
    add rdx, rax
    jmp .execute_loop

.jz_op:
    ; Jump if zero (offset in next 4 bytes)
    call stack_pop
    cmp rax, 0
    jne .jz_no_jump
    mov eax, [rbx + rdx]
    add rdx, 4
    add rdx, rax
    jmp .execute_loop
.jz_no_jump:
    add rdx, 4
    jmp .execute_loop

.alloc_op:
    call stack_pop
    mov rdi, rax
    call heap_alloc
    mov rdi, rax
    call stack_push
    jmp .execute_loop

.free_op:
    call stack_pop
    mov rdi, rax
    call heap_free
    jmp .execute_loop

.dup_op:
    call stack_dup
    jmp .execute_loop

.swap_op:
    call stack_swap
    jmp .execute_loop

.rot_op:
    call stack_rot
    jmp .execute_loop

.execute_done:
    pop rdx
    pop rcx
    pop rbx
    ret

; Call a function
; Input: rdi = function pointer, rsi = argument count
runtime_call_function:
    push rbx
    push rcx
    push rdx
    
    ; Save current frame
    push qword [current_frame]
    push qword [frame_count]
    
    ; Create new frame
    mov rbx, [stack_pointer]
    mov [current_frame], rbx
    inc qword [frame_count]
    
    ; TODO: Implement function call with arguments
    
    pop rdx
    pop rcx
    pop rbx
    ret

; Return from function
runtime_return:
    push rbx
    
    ; Restore previous frame
    dec qword [frame_count]
    pop qword [current_frame]
    
    ; TODO: Implement function return with value
    
    pop rbx
    ret

; Runtime error handler
; Input: rdi = error message
runtime_error:
    push rbx
    push rcx
    push rdx
    
    ; Print error message
    mov rbx, rdi
    mov rcx, 0
.count_loop:
    cmp byte [rbx + rcx], 0
    je .count_done
    inc rcx
    jmp .count_loop

.count_done:
    mov rax, 1      ; syscall number for write
    mov rdi, 2      ; file descriptor (stderr)
    mov rsi, rbx    ; string pointer
    mov rdx, rcx    ; string length
    syscall
    
    ; Exit with error code
    mov rax, 60     ; syscall number for exit
    mov rdi, 1      ; exit code 1
    syscall
    
    pop rdx
    pop rcx
    pop rbx
    ret
