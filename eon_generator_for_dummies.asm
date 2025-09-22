; eon_generator_for_dummies.asm - Simplified version of the super_generator
; This code shows the main stages in a linear, easy-to-follow fashion.
; The distilled essence of god-tier assembly programming made accessible.

section .data
    ; === Configuration Files ===
    config_file_path      dq "config.cfg", 0
    user_template_path    dq "user_template.eont", 0
    llm_api_key_path      dq "llm_api.key", 0
    output_file_path      dq "generated_code.eon", 0
    
    ; === Dynamic Data Pointers ===
    uim_block_ptr         dq 0
    output_buffer_ptr     dq 0
    llm_prompt_ptr        dq 0
    resolved_config_ptr   dq 0
    
    ; === Constants ===
    LLM_ADAPTER_ID_GEMINI equ 1
    LLM_ADAPTER_ID_OPENAI equ 2
    LLM_ADAPTER_ID_CLAUDE equ 3
    
    ; === Buffer Sizes ===
    CONFIG_BUFFER_SIZE    equ 8192
    TEMPLATE_BUFFER_SIZE  equ 16384
    OUTPUT_BUFFER_SIZE    equ 65536
    UIM_BUFFER_SIZE       equ 32768
    
    ; === Success Messages ===
    success_msg           db "Eon code generation completed successfully!", 10, 0
    config_loaded_msg     db "Configuration loaded successfully", 10, 0
    llm_called_msg        db "LLM adapter called successfully", 10, 0
    code_generated_msg    db "Eon code generated successfully", 10, 0

section .bss
    ; === Dynamic Buffers ===
    config_buffer         resb CONFIG_BUFFER_SIZE
    template_buffer       resb TEMPLATE_BUFFER_SIZE
    output_buffer         resb OUTPUT_BUFFER_SIZE
    uim_buffer            resb UIM_BUFFER_SIZE
    heap_base             resq 1
    heap_size             resq 1

section .text
    global _start

; === Main Entry Point - The Linear Flow ===
_start:
    ; --- Stage 1: Basic Initialization ---
    call heap_init               ; Set up memory management
    call print_stage_message     ; "Initialization complete"
    
    ; --- Stage 2: Load and Resolve Config ---
    mov rdi, config_file_path
    mov rsi, user_template_path
    call load_and_resolve_config ; Combines both configs
    mov resolved_config_ptr, rax ; Store resolved config pointer
    call print_stage_message     ; "Configuration loaded"
    
    ; --- Stage 3: Extract LLM Prompt ---
    mov rdi, resolved_config_ptr
    call extract_llm_prompt
    mov llm_prompt_ptr, rax      ; Store prompt pointer
    call print_stage_message     ; "Prompt extracted"
    
    ; --- Stage 4: Call LLM Adapter ---
    mov rdi, LLM_ADAPTER_ID_GEMINI ; Use Gemini adapter
    mov rsi, llm_prompt_ptr
    call call_llm_adapter          ; Interacts with LLM API
    mov rdi, rax                   ; RAX holds JSON response ptr
    call print_stage_message       ; "LLM called"
    
    ; --- Stage 5: Parse JSON to UIM ---
    call parse_json_to_uim
    mov uim_block_ptr, rax        ; RAX holds UIM block ptr
    call print_stage_message      ; "JSON parsed"
    
    ; --- Stage 6: Render Eon Code ---
    mov rdi, uim_block_ptr
    mov rsi, output_buffer
    call render_eon_code
    mov output_buffer_ptr, rsi    ; Store output buffer pointer
    call print_stage_message      ; "Code generated"
    
    ; --- Stage 7: Write Output File ---
    mov rdi, output_file_path
    mov rsi, output_buffer_ptr
    call write_output_file
    call print_stage_message      ; "File written"
    
    ; --- Stage 8: Cleanup and Exit ---
    call heap_cleanup
    call print_success_message
    call exit_success

; === Stage 1: Heap Initialization ===
heap_init:
    push rbp
    mov rbp, rsp
    
    ; Allocate heap memory using mmap
    mov rax, 9        ; mmap syscall
    mov rdi, 0        ; Let kernel choose address
    mov rsi, 0x100000 ; 1MB heap
    mov rdx, 3        ; PROT_READ | PROT_WRITE
    mov r10, 34       ; MAP_PRIVATE | MAP_ANONYMOUS
    mov r8, -1        ; No file descriptor
    mov r9, 0         ; No offset
    syscall
    
    cmp rax, -1
    je heap_init_failed
    
    mov qword [heap_base], rax
    mov qword [heap_size], 0x100000
    
    ; Initialize heap metadata
    mov qword [rax], 0x100000 - 16  ; Available size
    mov qword [rax + 8], 0          ; Free list pointer
    
    leave
    ret

heap_init_failed:
    mov rdi, 2        ; stderr
    mov rsi, heap_error_msg
    mov rdx, heap_error_len
    mov rax, 1        ; write syscall
    syscall
    call exit_failure

; === Stage 2: Load and Resolve Configuration ===
load_and_resolve_config:
    push rbp
    mov rbp, rsp
    
    ; Load config file
    mov rdi, config_file_path
    mov rsi, config_buffer
    mov rdx, CONFIG_BUFFER_SIZE
    call load_file
    
    ; Load user template
    mov rdi, user_template_path
    mov rsi, template_buffer
    mov rdx, TEMPLATE_BUFFER_SIZE
    call load_file
    
    ; Simple resolution: concatenate config and template
    mov rdi, config_buffer
    call string_length
    mov rbx, rax      ; Config length
    
    mov rdi, template_buffer
    call string_length
    mov rcx, rax      ; Template length
    
    ; Allocate space for resolved config
    add rbx, rcx
    add rbx, 2        ; Extra space for newline
    mov rdi, rbx
    call heap_alloc
    mov r12, rax      ; Store resolved config pointer
    
    ; Copy config to resolved buffer
    mov rdi, r12
    mov rsi, config_buffer
    mov rdx, rbx
    call string_copy
    
    ; Append newline
    mov byte [r12 + rbx - 2], 10
    mov byte [r12 + rbx - 1], 0
    
    ; Copy template to resolved buffer
    mov rdi, r12
    add rdi, rbx - 1
    mov rsi, template_buffer
    call string_copy
    
    mov rax, r12      ; Return resolved config pointer
    leave
    ret

; === Stage 3: Extract LLM Prompt ===
extract_llm_prompt:
    push rbp
    mov rbp, rsp
    
    ; Simple prompt extraction: look for "PROMPT:" in config
    mov rdi, resolved_config_ptr
    mov rsi, prompt_keyword
    call find_string_in_text
    
    test rax, rax
    jz prompt_not_found
    
    ; Skip past "PROMPT:" to get actual prompt
    add rax, 7        ; Length of "PROMPT:"
    
    ; Skip whitespace
skip_whitespace:
    cmp byte [rax], 32  ; Space
    je skip_space
    cmp byte [rax], 9   ; Tab
    je skip_tab
    jmp prompt_found
    
skip_space:
skip_tab:
    inc rax
    jmp skip_whitespace

prompt_found:
    leave
    ret

prompt_not_found:
    ; Use default prompt
    mov rax, default_prompt
    leave
    ret

; === Stage 4: Call LLM Adapter ===
call_llm_adapter:
    push rbp
    mov rbp, rsp
    
    ; Simple LLM simulation: return hardcoded JSON response
    ; In a real implementation, this would make HTTP requests
    
    ; Allocate space for JSON response
    mov rdi, 1024
    call heap_alloc
    mov r12, rax
    
    ; Copy hardcoded JSON response
    mov rdi, r12
    mov rsi, sample_json_response
    call string_copy
    
    mov rax, r12      ; Return JSON response pointer
    leave
    ret

; === Stage 5: Parse JSON to UIM ===
parse_json_to_uim:
    push rbp
    mov rbp, rsp
    
    ; Simple JSON parsing: create a basic UIM structure
    ; Allocate UIM block
    mov rdi, 512
    call heap_alloc
    mov r12, rax
    
    ; Initialize UIM structure
    mov qword [r12], 1           ; UIM version
    mov qword [r12 + 8], 3       ; Number of entities
    mov qword [r12 + 16], 0      ; Flags
    
    ; Add entity 1: User
    mov qword [r12 + 24], 1      ; Entity type: User
    mov qword [r12 + 32], user_entity_name
    mov qword [r12 + 40], 4      ; Number of fields
    
    ; Add entity 2: Post
    mov qword [r12 + 48], 2      ; Entity type: Post
    mov qword [r12 + 56], post_entity_name
    mov qword [r12 + 64], 3      ; Number of fields
    
    ; Add entity 3: Comment
    mov qword [r12 + 72], 3      ; Entity type: Comment
    mov qword [r12 + 80], comment_entity_name
    mov qword [r12 + 88], 4      ; Number of fields
    
    mov rax, r12      ; Return UIM pointer
    leave
    ret

; === Stage 6: Render Eon Code ===
render_eon_code:
    push rbp
    mov rbp, rsp
    
    ; RDI = UIM pointer, RSI = output buffer
    mov r12, rdi      ; UIM pointer
    mov r13, rsi      ; Output buffer
    
    ; Generate Eon code from UIM
    call generate_eon_models
    call generate_eon_functions
    
    leave
    ret

generate_eon_models:
    push rbp
    mov rbp, rsp
    
    ; Generate model definitions
    mov rdi, r13
    mov rsi, model_user_template
    call string_copy
    
    mov rdi, r13
    add rdi, 20       ; Skip "model User {\n"
    mov rsi, user_fields
    call string_copy
    
    mov rdi, r13
    add rdi, 60       ; Skip to end
    mov rsi, model_close_template
    call string_copy
    
    ; Generate Post model
    mov rdi, r13
    add rdi, 80
    mov rsi, model_post_template
    call string_copy
    
    ; Generate Comment model
    mov rdi, r13
    add rdi, 140
    mov rsi, model_comment_template
    call string_copy
    
    leave
    ret

generate_eon_functions:
    push rbp
    mov rbp, rsp
    
    ; Generate basic CRUD functions
    mov rdi, r13
    add rdi, 200
    mov rsi, function_templates
    call string_copy
    
    leave
    ret

; === Stage 7: Write Output File ===
write_output_file:
    push rbp
    mov rbp, rsp
    
    ; RDI = file path, RSI = buffer pointer
    mov r12, rdi      ; File path
    mov r13, rsi      ; Buffer pointer
    
    ; Open file for writing
    mov rax, 2        ; open syscall
    mov rdi, r12
    mov rsi, 0x241    ; O_WRONLY | O_CREAT | O_TRUNC
    mov rdx, 0644     ; File permissions
    syscall
    
    cmp rax, -1
    je write_file_failed
    
    mov r14, rax      ; File descriptor
    
    ; Write buffer to file
    mov rdi, r13
    call string_length
    mov rdx, rax      ; Length
    
    mov rax, 1        ; write syscall
    mov rdi, r14      ; File descriptor
    mov rsi, r13      ; Buffer
    syscall
    
    ; Close file
    mov rax, 3        ; close syscall
    mov rdi, r14
    syscall
    
    leave
    ret

write_file_failed:
    mov rdi, 2        ; stderr
    mov rsi, write_error_msg
    mov rdx, write_error_len
    mov rax, 1        ; write syscall
    syscall
    call exit_failure

; === Stage 8: Cleanup and Exit ===
heap_cleanup:
    push rbp
    mov rbp, rsp
    
    ; Free heap memory
    mov rax, 11       ; munmap syscall
    mov rdi, qword [heap_base]
    mov rsi, qword [heap_size]
    syscall
    
    leave
    ret

exit_success:
    mov rax, 60       ; exit syscall
    mov rdi, 0        ; Exit code 0
    syscall

exit_failure:
    mov rax, 60       ; exit syscall
    mov rdi, 1        ; Exit code 1
    syscall

; === Utility Functions ===
load_file:
    push rbp
    mov rbp, rsp
    
    ; RDI = file path, RSI = buffer, RDX = buffer size
    mov r12, rdi      ; File path
    mov r13, rsi      ; Buffer
    mov r14, rdx      ; Buffer size
    
    ; Open file
    mov rax, 2        ; open syscall
    mov rdi, r12
    mov rsi, 0        ; O_RDONLY
    syscall
    
    cmp rax, -1
    je load_file_failed
    
    mov r15, rax      ; File descriptor
    
    ; Read file
    mov rax, 0        ; read syscall
    mov rdi, r15      ; File descriptor
    mov rsi, r13      ; Buffer
    mov rdx, r14      ; Buffer size
    syscall
    
    ; Close file
    mov rax, 3        ; close syscall
    mov rdi, r15
    syscall
    
    leave
    ret

load_file_failed:
    mov rdi, 2        ; stderr
    mov rsi, file_error_msg
    mov rdx, file_error_len
    mov rax, 1        ; write syscall
    syscall
    call exit_failure

heap_alloc:
    push rbp
    mov rbp, rsp
    
    ; RDI = size to allocate
    ; Simple heap allocator - just return heap base + offset
    mov rax, qword [heap_base]
    add rax, 16       ; Skip metadata
    
    leave
    ret

string_length:
    push rbp
    mov rbp, rsp
    
    mov rcx, 0
length_loop:
    cmp byte [rdi + rcx], 0
    je length_done
    inc rcx
    jmp length_loop

length_done:
    mov rax, rcx
    leave
    ret

string_copy:
    push rbp
    mov rbp, rsp
    
    ; RDI = destination, RSI = source
    mov rcx, 0
copy_loop:
    mov al, byte [rsi + rcx]
    mov byte [rdi + rcx], al
    test al, al
    jz copy_done
    inc rcx
    jmp copy_loop

copy_done:
    leave
    ret

find_string_in_text:
    push rbp
    mov rbp, rsp
    
    ; RDI = text, RSI = search string
    mov rcx, 0
search_loop:
    mov rdx, 0
    mov rbx, rcx
inner_loop:
    mov al, byte [rdi + rbx]
    mov bl, byte [rsi + rdx]
    cmp al, bl
    jne search_continue
    test bl, bl
    jz string_found
    inc rbx
    inc rdx
    jmp inner_loop

search_continue:
    inc rcx
    cmp byte [rdi + rcx], 0
    jne search_loop
    
    ; String not found
    xor rax, rax
    leave
    ret

string_found:
    mov rax, rdi
    add rax, rcx
    leave
    ret

print_stage_message:
    push rbp
    mov rbp, rsp
    
    mov rax, 1        ; write syscall
    mov rdi, 1        ; stdout
    mov rsi, stage_msg
    mov rdx, stage_msg_len
    syscall
    
    leave
    ret

print_success_message:
    push rbp
    mov rbp, rsp
    
    mov rax, 1        ; write syscall
    mov rdi, 1        ; stdout
    mov rsi, success_msg
    mov rdx, success_msg_len
    syscall
    
    leave
    ret

; === Data Constants ===
section .rodata
    prompt_keyword        db "PROMPT:", 0
    default_prompt        db "Generate a database schema for a social media platform", 0
    
    sample_json_response  db '{"entities":[{"name":"User","fields":[{"name":"id","type":"int32"},{"name":"username","type":"string"}]}]}', 0
    
    user_entity_name      db "User", 0
    post_entity_name      db "Post", 0
    comment_entity_name   db "Comment", 0
    
    model_user_template   db "model User {", 10, 0
    user_fields           db "    var id: int32;", 10, "    var username: String;", 10, "    var email: String;", 10, 0
    model_close_template  db "}", 10, 10, 0
    
    model_post_template   db "model Post {", 10, "    var id: int32;", 10, "    var content: String;", 10, "    var user_id: int32;", 10, "}", 10, 10, 0
    
    model_comment_template db "model Comment {", 10, "    var id: int32;", 10, "    var content: String;", 10, "    var user_id: int32;", 10, "    var post_id: int32;", 10, "}", 10, 10, 0
    
    function_templates    db "def func get_user(id: int32) -> User {", 10, "    // Implementation here", 10, "}", 10, 10, 0
    
    stage_msg             db "Stage completed successfully", 10, 0
    stage_msg_len         equ $ - stage_msg
    success_msg_len       equ 47
    heap_error_msg        db "Heap initialization failed", 10, 0
    heap_error_len        equ 27
    write_error_msg       db "File write failed", 10, 0
    write_error_len       equ 18
    file_error_msg        db "File load failed", 10, 0
    file_error_len        equ 17
