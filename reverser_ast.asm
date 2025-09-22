; reverser_ast.asm
; Abstract Syntax Tree implementation for Reverser language
; Provides AST node structures and manipulation functions

section .data
    ; AST node type constants
    AST_PROGRAM        equ 0
    AST_FUNCTION       equ 1
    AST_MODEL          equ 2
    AST_BLOCK          equ 3
    AST_VARIABLE       equ 4
    AST_ASSIGNMENT     equ 5
    AST_RETURN         equ 6
    AST_IF             equ 7
    AST_LOOP           equ 8
    AST_BINARY_OP      equ 9
    AST_UNARY_OP       equ 10
    AST_LITERAL        equ 11
    AST_IDENTIFIER     equ 12
    AST_FUNCTION_CALL  equ 13
    AST_MEMBER_ACCESS  equ 14
    AST_ARRAY_ACCESS   equ 15

    ; Node size constants
    AST_NODE_SIZE      equ 64    ; Size of each AST node
    MAX_CHILDREN       equ 8     ; Maximum children per node
    MAX_STRING_LEN     equ 256   ; Maximum string length

section .bss
    ; AST storage
    ast_nodes          resb 65536  ; 1KB for AST nodes
    ast_node_count     resq 1      ; Number of allocated nodes
    ast_strings        resb 8192   ; String storage
    ast_string_count   resq 1      ; String count
    
    ; Current AST root
    ast_root           resq 1      ; Root of AST tree

section .text
    global ast_init
    global ast_create_node
    global ast_add_child
    global ast_set_value
    global ast_get_value
    global ast_get_type
    global ast_get_child
    global ast_get_child_count
    global ast_destroy_tree
    global ast_print_tree

; Initialize AST system
ast_init:
    push rbx
    push rcx
    
    ; Clear AST storage
    mov rcx, 65536
    mov rdi, ast_nodes
    xor rax, rax
    rep stosb
    
    mov rcx, 8192
    mov rdi, ast_strings
    xor rax, rax
    rep stosb
    
    ; Initialize counters
    mov qword [ast_node_count], 0
    mov qword [ast_string_count], 0
    mov qword [ast_root], 0
    
    pop rcx
    pop rbx
    ret

; Create a new AST node
; Input: rdi = node type
; Output: rax = pointer to new node or 0 if failed
ast_create_node:
    push rbx
    push rcx
    
    ; Check if we have space
    mov rbx, [ast_node_count]
    cmp rbx, 1024  ; Max 1024 nodes
    jge .create_failed
    
    ; Calculate node address
    mov rax, rbx
    imul rax, AST_NODE_SIZE
    add rax, ast_nodes
    
    ; Initialize node
    mov [rax], rdi        ; Node type
    mov qword [rax + 8], 0   ; Value pointer
    mov qword [rax + 16], 0  ; First child
    mov qword [rax + 24], 0  ; Next sibling
    mov qword [rax + 32], 0  ; Parent
    mov qword [rax + 40], 0  ; Child count
    mov qword [rax + 48], 0  ; Line number
    mov qword [rax + 56], 0  ; Column number
    
    ; Increment node count
    inc qword [ast_node_count]
    
    jmp .return

.create_failed:
    xor rax, rax

.return:
    pop rcx
    pop rbx
    ret

; Add a child node to parent
; Input: rdi = parent node, rsi = child node
ast_add_child:
    push rbx
    push rcx
    push rdx
    
    cmp rdi, 0
    je .add_failed
    cmp rsi, 0
    je .add_failed
    
    ; Set child's parent
    mov [rsi + 32], rdi
    
    ; Add to parent's child list
    mov rbx, [rdi + 16]  ; First child
    cmp rbx, 0
    je .first_child
    
    ; Find last child
    mov rcx, rbx
.find_last:
    mov rdx, [rcx + 24]  ; Next sibling
    cmp rdx, 0
    je .found_last
    mov rcx, rdx
    jmp .find_last

.found_last:
    mov [rcx + 24], rsi  ; Link to new child
    jmp .increment_count

.first_child:
    mov [rdi + 16], rsi  ; Set as first child

.increment_count:
    ; Increment child count
    inc qword [rdi + 40]
    
    mov rax, 1
    jmp .return

.add_failed:
    mov rax, 0

.return:
    pop rdx
    pop rcx
    pop rbx
    ret

; Set node value (string)
; Input: rdi = node, rsi = string pointer
ast_set_value:
    push rbx
    push rcx
    push rdx
    
    cmp rdi, 0
    je .set_failed
    
    ; Store string in string table
    mov rbx, rsi
    call add_string_to_ast_table
    cmp rax, 0
    je .set_failed
    
    ; Set node value pointer
    mov [rdi + 8], rax
    
    mov rax, 1
    jmp .return

.set_failed:
    mov rax, 0

.return:
    pop rdx
    pop rcx
    pop rbx
    ret

; Get node value
; Input: rdi = node
; Output: rax = value pointer or 0
ast_get_value:
    cmp rdi, 0
    je .get_failed
    
    mov rax, [rdi + 8]
    jmp .return

.get_failed:
    xor rax, rax

.return:
    ret

; Get node type
; Input: rdi = node
; Output: rax = node type
ast_get_type:
    cmp rdi, 0
    je .get_failed
    
    mov rax, [rdi]
    jmp .return

.get_failed:
    mov rax, -1

.return:
    ret

; Get child node by index
; Input: rdi = parent node, rsi = child index
; Output: rax = child node or 0
ast_get_child:
    push rbx
    push rcx
    
    cmp rdi, 0
    je .get_failed
    
    mov rbx, [rdi + 16]  ; First child
    mov rcx, 0           ; Current index
    
.find_child:
    cmp rbx, 0
    je .get_failed
    
    cmp rcx, rsi
    je .found_child
    
    mov rbx, [rbx + 24]  ; Next sibling
    inc rcx
    jmp .find_child

.found_child:
    mov rax, rbx
    jmp .return

.get_failed:
    xor rax, rax

.return:
    pop rcx
    pop rbx
    ret

; Get child count
; Input: rdi = node
; Output: rax = child count
ast_get_child_count:
    cmp rdi, 0
    je .get_failed
    
    mov rax, [rdi + 40]
    jmp .return

.get_failed:
    xor rax, rax

.return:
    ret

; Destroy AST tree
; Input: rdi = root node
ast_destroy_tree:
    push rbx
    push rcx
    
    cmp rdi, 0
    je .destroy_done
    
    ; Recursively destroy children
    mov rbx, [rdi + 16]  ; First child
.destroy_children:
    cmp rbx, 0
    je .destroy_siblings
    
    mov rcx, [rbx + 24]  ; Save next sibling
    push rcx
    mov rdi, rbx
    call ast_destroy_tree
    pop rbx
    jmp .destroy_children

.destroy_siblings:
    ; Node is automatically freed when we reset the system
    ; In a real implementation, you'd free individual nodes

.destroy_done:
    pop rcx
    pop rbx
    ret

; Print AST tree (for debugging)
; Input: rdi = root node, rsi = indent level
ast_print_tree:
    push rbx
    push rcx
    push rdx
    
    cmp rdi, 0
    je .print_done
    
    ; Print indentation
    mov rbx, rsi
.print_indent:
    cmp rbx, 0
    jle .print_node
    push rdi
    push rsi
    mov rdi, indent_str
    call print_string
    pop rsi
    pop rdi
    dec rbx
    jmp .print_indent

.print_node:
    ; Print node type
    mov rbx, [rdi]
    call get_ast_type_name
    mov rdi, rax
    call print_string
    
    ; Print value if present
    mov rbx, [rdi + 8]
    cmp rbx, 0
    je .print_children
    
    mov rdi, value_str
    call print_string
    mov rdi, rbx
    call print_string

.print_children:
    mov rdi, newline_str
    call print_string
    
    ; Print children
    mov rbx, [rdi + 16]  ; First child
    mov rcx, rsi
    inc rcx              ; Increment indent for children
.print_child:
    cmp rbx, 0
    je .print_done
    
    push rdi
    push rsi
    mov rdi, rbx
    mov rsi, rcx
    call ast_print_tree
    pop rsi
    pop rdi
    
    mov rbx, [rbx + 24]  ; Next sibling
    jmp .print_child

.print_done:
    pop rdx
    pop rcx
    pop rbx
    ret

; Add string to AST string table
; Input: rdi = string pointer
; Output: rax = string table offset or 0
add_string_to_ast_table:
    push rbx
    push rcx
    push rdx
    
    ; Calculate string length
    mov rbx, rdi
    mov rcx, 0
.calc_length:
    cmp byte [rbx + rcx], 0
    je .length_done
    inc rcx
    jmp .calc_length

.length_done:
    inc rcx  ; Include null terminator
    
    ; Check if we have space
    mov rdx, [ast_string_count]
    add rdx, rcx
    cmp rdx, 8192
    jg .add_failed
    
    ; Copy string
    mov rax, [ast_string_count]
    add rax, ast_strings
    mov rdx, rcx  ; Save length
    
    mov rcx, rdx
    mov rsi, rdi
    mov rdi, rax
    rep movsb
    
    ; Update string count
    add [ast_string_count], rdx
    
    ; Return offset
    mov rax, [ast_string_count]
    sub rax, rdx
    add rax, ast_strings
    jmp .return

.add_failed:
    xor rax, rax

.return:
    pop rdx
    pop rcx
    pop rbx
    ret

; Get AST type name for printing
; Input: rdi = node type
; Output: rax = type name string
get_ast_type_name:
    cmp rdi, AST_PROGRAM
    je .program
    cmp rdi, AST_FUNCTION
    je .function
    cmp rdi, AST_MODEL
    je .model
    cmp rdi, AST_BLOCK
    je .block
    cmp rdi, AST_VARIABLE
    je .variable
    cmp rdi, AST_ASSIGNMENT
    je .assignment
    cmp rdi, AST_RETURN
    je .return_stmt
    cmp rdi, AST_IF
    je .if_stmt
    cmp rdi, AST_LOOP
    je .loop
    cmp rdi, AST_BINARY_OP
    je .binary_op
    cmp rdi, AST_UNARY_OP
    je .unary_op
    cmp rdi, AST_LITERAL
    je .literal
    cmp rdi, AST_IDENTIFIER
    je .identifier
    cmp rdi, AST_FUNCTION_CALL
    je .function_call
    cmp rdi, AST_MEMBER_ACCESS
    je .member_access
    cmp rdi, AST_ARRAY_ACCESS
    je .array_access
    
    mov rax, unknown_type
    jmp .return

.program:
    mov rax, program_type
    jmp .return
.function:
    mov rax, function_type
    jmp .return
.model:
    mov rax, model_type
    jmp .return
.block:
    mov rax, block_type
    jmp .return
.variable:
    mov rax, variable_type
    jmp .return
.assignment:
    mov rax, assignment_type
    jmp .return
.return_stmt:
    mov rax, return_type
    jmp .return
.if_stmt:
    mov rax, if_type
    jmp .return
.loop:
    mov rax, loop_type
    jmp .return
.binary_op:
    mov rax, binary_op_type
    jmp .return
.unary_op:
    mov rax, unary_op_type
    jmp .return
.literal:
    mov rax, literal_type
    jmp .return
.identifier:
    mov rax, identifier_type
    jmp .return
.function_call:
    mov rax, function_call_type
    jmp .return
.member_access:
    mov rax, member_access_type
    jmp .return
.array_access:
    mov rax, array_access_type

.return:
    ret

; Print string helper
print_string:
    push rax
    push rdx
    push rcx
    push rsi
    
    mov rsi, rdi
    call string_length
    mov rdx, rax
    
    mov rax, 1      ; sys_write
    mov rdi, 1      ; stdout
    syscall
    
    pop rsi
    pop rcx
    pop rdx
    pop rax
    ret

; Get string length
string_length:
    push rbx
    push rcx
    
    mov rbx, rdi
    mov rcx, 0
    
.count_loop:
    cmp byte [rbx + rcx], 0
    je .count_done
    inc rcx
    jmp .count_loop

.count_done:
    mov rax, rcx
    
    pop rcx
    pop rbx
    ret

section .data
    ; Type name strings
    program_type        db "PROGRAM", 0
    function_type       db "FUNCTION", 0
    model_type          db "MODEL", 0
    block_type          db "BLOCK", 0
    variable_type       db "VARIABLE", 0
    assignment_type     db "ASSIGNMENT", 0
    return_type         db "RETURN", 0
    if_type             db "IF", 0
    loop_type           db "LOOP", 0
    binary_op_type      db "BINARY_OP", 0
    unary_op_type       db "UNARY_OP", 0
    literal_type        db "LITERAL", 0
    identifier_type     db "IDENTIFIER", 0
    function_call_type  db "FUNCTION_CALL", 0
    member_access_type  db "MEMBER_ACCESS", 0
    array_access_type   db "ARRAY_ACCESS", 0
    unknown_type        db "UNKNOWN", 0
    
    ; Format strings
    indent_str          db "  ", 0
    value_str           db ": ", 0
    newline_str         db 10, 0