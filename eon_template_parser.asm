; eon_template_parser.asm
; Parser for Eon Template (.eont) files
; Builds AST from template tokens for code generation

section .data
    ; Template AST node types
    %define TEMPLATE_AST_TEXT          1
    %define TEMPLATE_AST_PLACEHOLDER   2
    %define TEMPLATE_AST_IF            3
    %define TEMPLATE_AST_ELSE          4
    %define TEMPLATE_AST_FOR           5
    %define TEMPLATE_AST_EACH          6
    %define TEMPLATE_AST_ROOT          7

    ; Template AST node structure
    %define TEMPLATE_NODE_TYPE         0
    %define TEMPLATE_NODE_VALUE        8
    %define TEMPLATE_NODE_CHILDREN     16
    %define TEMPLATE_NODE_NEXT         24
    %define TEMPLATE_NODE_CONDITION    32
    %define TEMPLATE_NODE_ITERATOR     40
    %define TEMPLATE_NODE_SIZE         48

section .bss
    template_ast_root     resq 1      ; Root of template AST
    current_node          resq 1      ; Current AST node being built
    node_stack            resq 100    ; Stack for nested structures
    stack_top             resq 1      ; Top of node stack
    template_data         resq 1      ; Pointer to template data
    template_data_size    resq 1      ; Size of template data

section .text
    global template_parser_init
    global template_parser_parse
    global template_parser_get_ast
    global template_parser_cleanup

; Initialize template parser
template_parser_init:
    mov     qword [template_ast_root], 0
    mov     qword [current_node], 0
    mov     qword [stack_top], 0
    mov     qword [template_data], 0
    mov     qword [template_data_size], 0
    ret

; Parse template and build AST
; Args: rdi = template source, rsi = source length
template_parser_parse:
    push    rbx
    push    rcx
    push    rdx
    push    rsi
    push    rdi
    
    ; Initialize lexer
    call    template_lexer_init
    
    ; Create root node
    call    create_template_node
    mov     qword [template_ast_root], rax
    mov     qword [current_node], rax
    
    ; Parse template content
.parse_loop:
    call    template_lexer_next
    call    template_lexer_get_token
    
    cmp     rax, TEMPLATE_TOKEN_EOF
    je      .parse_done
    
    cmp     rax, TEMPLATE_TOKEN_ERROR
    je      .parse_error
    
    ; Process token based on type
    cmp     rax, TEMPLATE_TOKEN_TEXT
    je      .process_text
    
    cmp     rax, TEMPLATE_TOKEN_PLACEHOLDER
    je      .process_placeholder
    
    cmp     rax, TEMPLATE_TOKEN_IF
    je      .process_if
    
    cmp     rax, TEMPLATE_TOKEN_ELSE
    je      .process_else
    
    cmp     rax, TEMPLATE_TOKEN_ENDIF
    je      .process_endif
    
    cmp     rax, TEMPLATE_TOKEN_FOR
    je      .process_for
    
    cmp     rax, TEMPLATE_TOKEN_ENDFOR
    je      .process_endfor
    
    cmp     rax, TEMPLATE_TOKEN_EACH
    je      .process_each
    
    cmp     rax, TEMPLATE_TOKEN_COMMENT
    je      .parse_loop  ; Skip comments
    
    jmp     .parse_loop
    
.process_text:
    call    process_text_token
    jmp     .parse_loop
    
.process_placeholder:
    call    process_placeholder_token
    jmp     .parse_loop
    
.process_if:
    call    process_if_token
    jmp     .parse_loop
    
.process_else:
    call    process_else_token
    jmp     .parse_loop
    
.process_endif:
    call    process_endif_token
    jmp     .parse_loop
    
.process_for:
    call    process_for_token
    jmp     .parse_loop
    
.process_endfor:
    call    process_endfor_token
    jmp     .parse_loop
    
.process_each:
    call    process_each_token
    jmp     .parse_loop
    
.parse_done:
    pop     rdi
    pop     rsi
    pop     rdx
    pop     rcx
    pop     rbx
    mov     rax, 1  ; Success
    ret
    
.parse_error:
    pop     rdi
    pop     rsi
    pop     rdx
    pop     rcx
    pop     rbx
    mov     rax, 0  ; Error
    ret

; Create a new template AST node
; Args: rdi = node type, rsi = node value
; Returns: rax = pointer to new node
create_template_node:
    push    rbx
    push    rcx
    
    ; Allocate memory for node
    mov     rax, TEMPLATE_NODE_SIZE
    call    allocate_memory
    
    ; Initialize node
    mov     qword [rax + TEMPLATE_NODE_TYPE], rdi
    mov     qword [rax + TEMPLATE_NODE_VALUE], rsi
    mov     qword [rax + TEMPLATE_NODE_CHILDREN], 0
    mov     qword [rax + TEMPLATE_NODE_NEXT], 0
    mov     qword [rax + TEMPLATE_NODE_CONDITION], 0
    mov     qword [rax + TEMPLATE_NODE_ITERATOR], 0
    
    pop     rcx
    pop     rbx
    ret

; Process text token
process_text_token:
    push    rbx
    push    rcx
    push    rdx
    
    ; Get token value
    call    template_lexer_get_value
    mov     rbx, rax
    
    ; Create text node
    mov     rdi, TEMPLATE_AST_TEXT
    mov     rsi, rbx
    call    create_template_node
    
    ; Add to current node
    call    add_node_to_current
    
    pop     rdx
    pop     rcx
    pop     rbx
    ret

; Process placeholder token
process_placeholder_token:
    push    rbx
    push    rcx
    push    rdx
    
    ; Get token value
    call    template_lexer_get_value
    mov     rbx, rax
    
    ; Create placeholder node
    mov     rdi, TEMPLATE_AST_PLACEHOLDER
    mov     rsi, rbx
    call    create_template_node
    
    ; Add to current node
    call    add_node_to_current
    
    pop     rdx
    pop     rcx
    pop     rbx
    ret

; Process if token
process_if_token:
    push    rbx
    push    rcx
    push    rdx
    
    ; Get condition from token value
    call    template_lexer_get_value
    mov     rbx, rax
    
    ; Create if node
    mov     rdi, TEMPLATE_AST_IF
    mov     rsi, 0
    call    create_template_node
    
    ; Set condition
    mov     qword [rax + TEMPLATE_NODE_CONDITION], rbx
    
    ; Push current node to stack
    call    push_node_to_stack
    
    ; Set new current node
    mov     qword [current_node], rax
    
    pop     rdx
    pop     rcx
    pop     rbx
    ret

; Process else token
process_else_token:
    push    rbx
    push    rcx
    push    rdx
    
    ; Pop from stack to get if node
    call    pop_node_from_stack
    mov     rbx, rax
    
    ; Create else node
    mov     rdi, TEMPLATE_AST_ELSE
    mov     rsi, 0
    call    create_template_node
    
    ; Link else to if node
    mov     qword [rbx + TEMPLATE_NODE_NEXT], rax
    
    ; Push if node back to stack
    push    rax
    mov     rax, rbx
    call    push_node_to_stack
    pop     rax
    
    ; Set new current node
    mov     qword [current_node], rax
    
    pop     rdx
    pop     rcx
    pop     rbx
    ret

; Process endif token
process_endif_token:
    push    rbx
    push    rcx
    push    rdx
    
    ; Pop from stack to get if node
    call    pop_node_from_stack
    mov     rbx, rax
    
    ; Restore current node to parent
    call    get_parent_node
    mov     qword [current_node], rax
    
    pop     rdx
    pop     rcx
    pop     rbx
    ret

; Process for token
process_for_token:
    push    rbx
    push    rcx
    push    rdx
    
    ; Get iterator from token value
    call    template_lexer_get_value
    mov     rbx, rax
    
    ; Create for node
    mov     rdi, TEMPLATE_AST_FOR
    mov     rsi, 0
    call    create_template_node
    
    ; Set iterator
    mov     qword [rax + TEMPLATE_NODE_ITERATOR], rbx
    
    ; Push current node to stack
    call    push_node_to_stack
    
    ; Set new current node
    mov     qword [current_node], rax
    
    pop     rdx
    pop     rcx
    pop     rbx
    ret

; Process endfor token
process_endfor_token:
    push    rbx
    push    rcx
    push    rdx
    
    ; Pop from stack to get for node
    call    pop_node_from_stack
    mov     rbx, rax
    
    ; Restore current node to parent
    call    get_parent_node
    mov     qword [current_node], rax
    
    pop     rdx
    pop     rcx
    pop     rbx
    ret

; Process each token
process_each_token:
    push    rbx
    push    rcx
    push    rdx
    
    ; Get iterator from token value
    call    template_lexer_get_value
    mov     rbx, rax
    
    ; Create each node
    mov     rdi, TEMPLATE_AST_EACH
    mov     rsi, 0
    call    create_template_node
    
    ; Set iterator
    mov     qword [rax + TEMPLATE_NODE_ITERATOR], rbx
    
    ; Push current node to stack
    call    push_node_to_stack
    
    ; Set new current node
    mov     qword [current_node], rax
    
    pop     rdx
    pop     rcx
    pop     rbx
    ret

; Add node to current node's children
; Args: rax = node to add
add_node_to_current:
    push    rbx
    push    rcx
    
    mov     rbx, qword [current_node]
    mov     rcx, qword [rbx + TEMPLATE_NODE_CHILDREN]
    
    ; If no children, set as first child
    cmp     rcx, 0
    je      .set_first_child
    
    ; Find last child
.find_last_child:
    mov     rdx, qword [rcx + TEMPLATE_NODE_NEXT]
    cmp     rdx, 0
    je      .set_next
    mov     rcx, rdx
    jmp     .find_last_child
    
.set_next:
    mov     qword [rcx + TEMPLATE_NODE_NEXT], rax
    jmp     .done
    
.set_first_child:
    mov     qword [rbx + TEMPLATE_NODE_CHILDREN], rax
    
.done:
    pop     rcx
    pop     rbx
    ret

; Push node to stack
; Args: rax = node to push
push_node_to_stack:
    push    rbx
    push    rcx
    
    mov     rbx, qword [stack_top]
    mov     rcx, qword [node_stack + rbx * 8]
    mov     qword [node_stack + rbx * 8], rax
    inc     rbx
    mov     qword [stack_top], rbx
    
    pop     rcx
    pop     rbx
    ret

; Pop node from stack
; Returns: rax = popped node
pop_node_from_stack:
    push    rbx
    push    rcx
    
    mov     rbx, qword [stack_top]
    dec     rbx
    mov     qword [stack_top], rbx
    mov     rax, qword [node_stack + rbx * 8]
    
    pop     rcx
    pop     rbx
    ret

; Get parent node (from stack)
; Returns: rax = parent node
get_parent_node:
    push    rbx
    push    rcx
    
    mov     rbx, qword [stack_top]
    cmp     rbx, 0
    je      .no_parent
    
    dec     rbx
    mov     rax, qword [node_stack + rbx * 8]
    jmp     .done
    
.no_parent:
    mov     rax, qword [template_ast_root]
    
.done:
    pop     rcx
    pop     rbx
    ret

; Get template AST root
template_parser_get_ast:
    mov     rax, qword [template_ast_root]
    ret

; Cleanup template parser
template_parser_cleanup:
    push    rbx
    push    rcx
    
    ; Free AST nodes
    mov     rbx, qword [template_ast_root]
    cmp     rbx, 0
    je      .cleanup_done
    
    call    free_template_ast
    mov     qword [template_ast_root], 0
    
.cleanup_done:
    pop     rcx
    pop     rbx
    ret

; Free template AST recursively
; Args: rbx = node to free
free_template_ast:
    push    rbx
    push    rcx
    push    rdx
    
    ; Free children
    mov     rcx, qword [rbx + TEMPLATE_NODE_CHILDREN]
    cmp     rcx, 0
    je      .free_siblings
    
    call    free_template_ast
    
.free_siblings:
    ; Free siblings
    mov     rcx, qword [rbx + TEMPLATE_NODE_NEXT]
    cmp     rcx, 0
    je      .free_current
    
    push    rbx
    mov     rbx, rcx
    call    free_template_ast
    pop     rbx
    
.free_current:
    ; Free current node
    mov     rdi, rbx
    call    free_memory
    
    pop     rdx
    pop     rcx
    pop     rbx
    ret

; Allocate memory (placeholder - should be implemented)
allocate_memory:
    ; This should be implemented with proper memory allocation
    ; For now, return a dummy pointer
    mov     rax, 0x1000
    ret

; Free memory (placeholder - should be implemented)
free_memory:
    ; This should be implemented with proper memory deallocation
    ret
