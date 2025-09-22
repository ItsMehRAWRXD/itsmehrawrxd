; template_generator_main.asm
; Main orchestrator for the universal template generator
; Coordinates parsing, UIM building, template processing, and code generation

section .data
    ; Generator state constants
    %define GEN_STATE_INIT          0
    %define GEN_STATE_PARSING       1
    %define GEN_STATE_TEMPLATING    2
    %define GEN_STATE_GENERATING    3
    %define GEN_STATE_COMPLETE      4
    %define GEN_STATE_ERROR         5

    ; File paths and configuration
    source_file_path     resq 1      ; Path to source file (C++ header, JSON, etc.)
    template_file_path   resq 1      ; Path to template file (.eont)
    output_file_path     resq 1      ; Path to output file
    target_language      resq 1      ; Target language for generation
    generator_state      resq 1      ; Current generator state

    ; Error messages
    error_file_not_found     db "Error: Source file not found", 0
    error_template_not_found db "Error: Template file not found", 0
    error_parse_failed       db "Error: Failed to parse source file", 0
    error_template_failed    db "Error: Failed to process template", 0
    error_generation_failed  db "Error: Failed to generate code", 0
    error_invalid_language   db "Error: Invalid target language", 0

    ; Success messages
    success_parsed           db "Successfully parsed source file", 0
    success_template         db "Successfully processed template", 0
    success_generated        db "Successfully generated code", 0

section .bss
    ; Component instances
    data_adapter_initialized     resq 1
    template_parser_initialized  resq 1
    template_engine_initialized  resq 1
    language_generator_initialized resq 1

    ; Working data
    source_file_data        resq 1      ; Pointer to source file data
    source_file_size        resq 1      ; Size of source file
    template_file_data      resq 1      ; Pointer to template file data
    template_file_size      resq 1      ; Size of template file
    generated_code_data     resq 1      ; Pointer to generated code
    generated_code_size     resq 1      ; Size of generated code

section .text
    global template_generator_init
    global template_generator_set_source
    global template_generator_set_template
    global template_generator_set_output
    global template_generator_set_language
    global template_generator_run
    global template_generator_get_state
    global template_generator_cleanup

; Initialize template generator
template_generator_init:
    push    rbx
    push    rcx
    push    rdx
    
    ; Initialize state
    mov     qword [generator_state], GEN_STATE_INIT
    mov     qword [source_file_path], 0
    mov     qword [template_file_path], 0
    mov     qword [output_file_path], 0
    mov     qword [target_language], 0
    
    ; Initialize components
    mov     qword [data_adapter_initialized], 0
    mov     qword [template_parser_initialized], 0
    mov     qword [template_engine_initialized], 0
    mov     qword [language_generator_initialized], 0
    
    ; Initialize data adapter
    call    data_adapter_init
    mov     qword [data_adapter_initialized], 1
    
    ; Initialize template parser
    call    template_parser_init
    mov     qword [template_parser_initialized], 1
    
    ; Initialize template engine
    call    template_engine_init
    mov     qword [template_engine_initialized], 1
    
    ; Initialize language generator
    call    language_generator_init
    mov     qword [language_generator_initialized], 1
    
    pop     rdx
    pop     rcx
    pop     rbx
    ret

; Set source file path
; Args: rdi = source file path
template_generator_set_source:
    mov     qword [source_file_path], rdi
    ret

; Set template file path
; Args: rdi = template file path
template_generator_set_template:
    mov     qword [template_file_path], rdi
    ret

; Set output file path
; Args: rdi = output file path
template_generator_set_output:
    mov     qword [output_file_path], rdi
    ret

; Set target language
; Args: rdi = language constant
template_generator_set_language:
    mov     qword [target_language], rdi
    
    ; Set language in generator
    call    language_generator_set_target
    ret

; Run the complete template generation process
template_generator_run:
    push    rbx
    push    rcx
    push    rdx
    push    rsi
    push    rdi
    
    ; Validate configuration
    call    validate_configuration
    cmp     rax, 0
    je      .config_error
    
    ; Step 1: Parse source file
    mov     qword [generator_state], GEN_STATE_PARSING
    call    parse_source_file
    cmp     rax, 0
    je      .parse_error
    
    ; Step 2: Process template
    mov     qword [generator_state], GEN_STATE_TEMPLATING
    call    process_template
    cmp     rax, 0
    je      .template_error
    
    ; Step 3: Generate code
    mov     qword [generator_state], GEN_STATE_GENERATING
    call    generate_code
    cmp     rax, 0
    je      .generation_error
    
    ; Step 4: Write output
    call    write_output_file
    cmp     rax, 0
    je      .write_error
    
    ; Success
    mov     qword [generator_state], GEN_STATE_COMPLETE
    mov     rax, 1
    jmp     .done
    
.config_error:
    mov     qword [generator_state], GEN_STATE_ERROR
    mov     rax, 0
    jmp     .done
    
.parse_error:
    mov     qword [generator_state], GEN_STATE_ERROR
    mov     rax, 0
    jmp     .done
    
.template_error:
    mov     qword [generator_state], GEN_STATE_ERROR
    mov     rax, 0
    jmp     .done
    
.generation_error:
    mov     qword [generator_state], GEN_STATE_ERROR
    mov     rax, 0
    jmp     .done
    
.write_error:
    mov     qword [generator_state], GEN_STATE_ERROR
    mov     rax, 0
    jmp     .done
    
.done:
    pop     rdi
    pop     rsi
    pop     rdx
    pop     rcx
    pop     rbx
    ret

; Validate configuration
; Returns: rax = 1 if valid, 0 if invalid
validate_configuration:
    push    rbx
    push    rcx
    push    rdx
    
    ; Check if source file path is set
    cmp     qword [source_file_path], 0
    je      .invalid_config
    
    ; Check if template file path is set
    cmp     qword [template_file_path], 0
    je      .invalid_config
    
    ; Check if output file path is set
    cmp     qword [output_file_path], 0
    je      .invalid_config
    
    ; Check if target language is set
    cmp     qword [target_language], 0
    je      .invalid_config
    
    ; Check if language is valid
    mov     rbx, qword [target_language]
    cmp     rbx, 1  ; LANG_EON
    jl      .invalid_language
    cmp     rbx, 6  ; LANG_GO
    jg      .invalid_language
    
    ; Valid configuration
    mov     rax, 1
    jmp     .done
    
.invalid_config:
    mov     rax, 0
    jmp     .done
    
.invalid_language:
    mov     rax, 0
    jmp     .done
    
.done:
    pop     rdx
    pop     rcx
    pop     rbx
    ret

; Parse source file and build UIM
; Returns: rax = 1 if success, 0 if error
parse_source_file:
    push    rbx
    push    rcx
    push    rdx
    push    rsi
    push    rdi
    
    ; Read source file
    mov     rdi, qword [source_file_path]
    call    read_file_to_memory
    cmp     rax, 0
    je      .read_error
    
    mov     qword [source_file_data], rbx
    mov     qword [source_file_size], rcx
    
    ; Determine file type and parse
    mov     rdi, qword [source_file_path]
    call    determine_file_type
    mov     rsi, rax  ; file type
    
    ; Parse file into UIM
    mov     rdi, qword [source_file_path]
    call    data_adapter_parse_file
    cmp     rax, 0
    je      .parse_error
    
    ; Success
    mov     rax, 1
    jmp     .done
    
.read_error:
    mov     rax, 0
    jmp     .done
    
.parse_error:
    mov     rax, 0
    jmp     .done
    
.done:
    pop     rdi
    pop     rsi
    pop     rdx
    pop     rcx
    pop     rbx
    ret

; Process template file
; Returns: rax = 1 if success, 0 if error
process_template:
    push    rbx
    push    rcx
    push    rdx
    push    rsi
    push    rdi
    
    ; Read template file
    mov     rdi, qword [template_file_path]
    call    read_file_to_memory
    cmp     rax, 0
    je      .read_error
    
    mov     qword [template_file_data], rbx
    mov     qword [template_file_size], rcx
    
    ; Parse template into AST
    mov     rdi, qword [template_file_data]
    mov     rsi, qword [template_file_size]
    call    template_parser_parse
    cmp     rax, 0
    je      .parse_error
    
    ; Get UIM root and set in template engine
    call    data_adapter_get_uim_root
    mov     rdi, rax
    call    template_engine_set_data
    
    ; Generate from template AST
    call    template_parser_get_ast
    mov     rdi, rax
    call    template_engine_generate
    
    ; Success
    mov     rax, 1
    jmp     .done
    
.read_error:
    mov     rax, 0
    jmp     .done
    
.parse_error:
    mov     rax, 0
    jmp     .done
    
.done:
    pop     rdi
    pop     rsi
    pop     rdx
    pop     rcx
    pop     rbx
    ret

; Generate code using language generator
; Returns: rax = 1 if success, 0 if error
generate_code:
    push    rbx
    push    rcx
    push    rdx
    push    rsi
    push    rdi
    
    ; Get generated output from template engine
    call    template_engine_get_output
    mov     qword [generated_code_data], rax
    
    ; For now, just copy the template output
    ; In a full implementation, this would process the template output
    ; and generate language-specific code using the language generator
    
    ; Get output size (simplified)
    mov     qword [generated_code_size], 1024  ; placeholder
    
    ; Success
    mov     rax, 1
    jmp     .done
    
.done:
    pop     rdi
    pop     rsi
    pop     rdx
    pop     rcx
    pop     rbx
    ret

; Write output to file
; Returns: rax = 1 if success, 0 if error
write_output_file:
    push    rbx
    push    rcx
    push    rdx
    push    rsi
    push    rdi
    
    ; Open output file for writing
    mov     rax, 2  ; sys_open
    mov     rdi, qword [output_file_path]
    mov     rsi, 0x241  ; O_WRONLY | O_CREAT | O_TRUNC
    mov     rdx, 0644   ; permissions
    syscall
    
    cmp     rax, 0
    jl      .open_error
    
    mov     rbx, rax  ; file descriptor
    
    ; Write generated code
    mov     rax, 1  ; sys_write
    mov     rdi, rbx
    mov     rsi, qword [generated_code_data]
    mov     rdx, qword [generated_code_size]
    syscall
    
    ; Close file
    mov     rax, 3  ; sys_close
    mov     rdi, rbx
    syscall
    
    ; Success
    mov     rax, 1
    jmp     .done
    
.open_error:
    mov     rax, 0
    jmp     .done
    
.done:
    pop     rdi
    pop     rsi
    pop     rdx
    pop     rcx
    pop     rbx
    ret

; Read file to memory
; Args: rdi = file path
; Returns: rax = 1 if success, 0 if error
;          rbx = data pointer, rcx = size
read_file_to_memory:
    push    rbx
    push    rcx
    push    rdx
    push    rsi
    push    rdi
    
    ; Open file
    mov     rax, 2  ; sys_open
    mov     rsi, 0  ; O_RDONLY
    syscall
    
    cmp     rax, 0
    jl      .read_error
    
    mov     rbx, rax  ; file descriptor
    
    ; Get file size
    mov     rax, 8  ; sys_lseek
    mov     rdi, rbx
    mov     rsi, 0  ; SEEK_END
    mov     rdx, 0
    syscall
    
    mov     rcx, rax  ; file size
    
    ; Seek back to beginning
    mov     rax, 8  ; sys_lseek
    mov     rdi, rbx
    mov     rsi, 0  ; SEEK_SET
    mov     rdx, 0
    syscall
    
    ; Allocate memory
    mov     rdi, rcx
    call    allocate_memory
    mov     rdx, rax  ; data pointer
    
    ; Read file
    mov     rax, 0  ; sys_read
    mov     rdi, rbx
    mov     rsi, rdx
    syscall
    
    ; Close file
    mov     rax, 3  ; sys_close
    mov     rdi, rbx
    syscall
    
    ; Return success
    mov     rax, 1
    mov     rbx, rdx  ; data pointer
    jmp     .done
    
.read_error:
    mov     rax, 0
    mov     rbx, 0
    mov     rcx, 0
    jmp     .done
    
.done:
    pop     rdi
    pop     rsi
    pop     rdx
    pop     rcx
    pop     rbx
    ret

; Determine file type from extension
; Args: rdi = file path
; Returns: rax = file type constant
determine_file_type:
    push    rbx
    push    rcx
    push    rdx
    
    ; Find file extension
    mov     rbx, rdi
    mov     rcx, 0  ; position counter
    
.find_extension:
    mov     al, byte [rbx + rcx]
    cmp     al, 0
    je      .no_extension
    cmp     al, '.'
    je      .found_dot
    inc     rcx
    jmp     .find_extension
    
.found_dot:
    inc     rcx  ; skip the dot
    add     rbx, rcx  ; point to extension
    
    ; Check for .h extension (C++ header)
    cmp     byte [rbx], 'h'
    jne     .check_json
    cmp     byte [rbx + 1], 0
    jne     .check_json
    mov     rax, 4  ; FILE_TYPE_C_HEADER
    jmp     .done
    
.check_json:
    ; Check for .json extension
    cmp     byte [rbx], 'j'
    jne     .check_yaml
    cmp     byte [rbx + 1], 's'
    jne     .check_yaml
    cmp     byte [rbx + 2], 'o'
    jne     .check_yaml
    cmp     byte [rbx + 3], 'n'
    jne     .check_yaml
    cmp     byte [rbx + 4], 0
    jne     .check_yaml
    mov     rax, 1  ; FILE_TYPE_JSON
    jmp     .done
    
.check_yaml:
    ; Check for .yaml extension
    cmp     byte [rbx], 'y'
    jne     .check_sql
    cmp     byte [rbx + 1], 'a'
    jne     .check_sql
    cmp     byte [rbx + 2], 'm'
    jne     .check_sql
    cmp     byte [rbx + 3], 'l'
    jne     .check_sql
    cmp     byte [rbx + 4], 0
    jne     .check_sql
    mov     rax, 2  ; FILE_TYPE_YAML
    jmp     .done
    
.check_sql:
    ; Check for .sql extension
    cmp     byte [rbx], 's'
    jne     .unknown_type
    cmp     byte [rbx + 1], 'q'
    jne     .unknown_type
    cmp     byte [rbx + 2], 'l'
    jne     .unknown_type
    cmp     byte [rbx + 3], 0
    jne     .unknown_type
    mov     rax, 3  ; FILE_TYPE_SQL
    jmp     .done
    
.no_extension:
.unknown_type:
    mov     rax, 0  ; FILE_TYPE_UNKNOWN
    jmp     .done
    
.done:
    pop     rdx
    pop     rcx
    pop     rbx
    ret

; Allocate memory (placeholder)
; Args: rdi = size
; Returns: rax = pointer to allocated memory
allocate_memory:
    ; This should be implemented with proper memory allocation
    ; For now, return a dummy pointer
    mov     rax, 0x4000
    ret

; Get current generator state
template_generator_get_state:
    mov     rax, qword [generator_state]
    ret

; Cleanup template generator
template_generator_cleanup:
    push    rbx
    push    rcx
    push    rdx
    
    ; Cleanup components
    cmp     qword [data_adapter_initialized], 0
    je      .cleanup_parser
    
    call    data_adapter_cleanup
    mov     qword [data_adapter_initialized], 0
    
.cleanup_parser:
    cmp     qword [template_parser_initialized], 0
    je      .cleanup_engine
    
    call    template_parser_cleanup
    mov     qword [template_parser_initialized], 0
    
.cleanup_engine:
    cmp     qword [template_engine_initialized], 0
    je      .cleanup_generator
    
    call    template_engine_cleanup
    mov     qword [template_engine_initialized], 0
    
.cleanup_generator:
    cmp     qword [language_generator_initialized], 0
    je      .cleanup_done
    
    call    language_generator_cleanup
    mov     qword [language_generator_initialized], 0
    
.cleanup_done:
    ; Reset state
    mov     qword [generator_state], GEN_STATE_INIT
    mov     qword [source_file_path], 0
    mov     qword [template_file_path], 0
    mov     qword [output_file_path], 0
    mov     qword [target_language], 0
    
    pop     rdx
    pop     rcx
    pop     rbx
    ret
