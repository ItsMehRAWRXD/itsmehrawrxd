; reverser_vtable.asm
; Vtable support for object-oriented features in Reverser language
; Implements virtual function dispatch, inheritance, and polymorphism

%include "reverser_ast.asm"
%include "reverser_runtime.asm"

section .data
    ; Vtable constants
    VTABLE_ENTRY_SIZE  equ 16      ; Size of each vtable entry
    MAX_VTABLES        equ 64      ; Maximum number of vtables
    MAX_VTABLE_ENTRIES equ 32      ; Maximum entries per vtable
    MAX_CLASSES        equ 128     ; Maximum number of classes
    
    ; Object layout constants
    OBJECT_VTABLE_OFFSET equ 0     ; Vtable pointer at offset 0
    OBJECT_DATA_OFFSET   equ 8     ; Object data starts at offset 8
    
    ; Vtable structure
    ; [0-7]:   Function pointer
    ; [8-15]:  Function signature (for type checking)

section .bss
    ; Vtable storage
    vtable_storage      resb MAX_VTABLES * MAX_VTABLE_ENTRIES * VTABLE_ENTRY_SIZE
    vtable_count        resq 1      ; Number of vtables
    vtable_sizes        resq MAX_VTABLES  ; Size of each vtable
    
    ; Class information
    class_table         resq MAX_CLASSES * 4  ; [name, vtable_id, parent_id, size]
    class_count         resq 1      ; Number of classes
    
    ; Method table
    method_table        resq 1024   ; Method addresses
    method_count        resq 1      ; Number of methods
    
    ; Inheritance chain
    inheritance_chain   resq MAX_CLASSES * MAX_CLASSES  ; Inheritance relationships

section .text
    global vtable_init
    global vtable_create
    global vtable_add_method
    global vtable_get_method
    global class_define
    global class_inherit
    global object_create
    global object_destroy
    global virtual_call
    global method_register
    global method_lookup
    global inheritance_check
    global vtable_dump

; Initialize vtable system
vtable_init:
    push rbx
    push rcx
    push rdx
    
    ; Clear vtable storage
    mov rcx, MAX_VTABLES * MAX_VTABLE_ENTRIES * VTABLE_ENTRY_SIZE
    mov rdi, vtable_storage
    xor rax, rax
    rep stosb
    
    ; Initialize counters
    mov qword [vtable_count], 0
    mov qword [class_count], 0
    mov qword [method_count], 0
    
    ; Clear class table
    mov rcx, MAX_CLASSES * 4
    mov rdi, class_table
    xor rax, rax
    rep stosq
    
    ; Clear vtable sizes
    mov rcx, MAX_VTABLES
    mov rdi, vtable_sizes
    xor rax, rax
    rep stosq
    
    ; Clear inheritance chain
    mov rcx, MAX_CLASSES * MAX_CLASSES
    mov rdi, inheritance_chain
    xor rax, rax
    rep stosq
    
    pop rdx
    pop rcx
    pop rbx
    ret

; Create a new vtable
; Input: rdi = class name
; Output: rax = vtable ID or -1 if failed
vtable_create:
    push rbx
    push rcx
    push rdx
    
    ; Check if we have space for new vtable
    mov rbx, [vtable_count]
    cmp rbx, MAX_VTABLES
    jge .create_failed
    
    ; Initialize vtable size
    mov qword [vtable_sizes + rbx * 8], 0
    
    ; Increment vtable count
    inc qword [vtable_count]
    
    mov rax, rbx
    jmp .return

.create_failed:
    mov rax, -1

.return:
    pop rdx
    pop rcx
    pop rbx
    ret

; Add a method to a vtable
; Input: rdi = vtable ID, rsi = method name, rdx = method address
; Output: rax = success (1) or failure (0)
vtable_add_method:
    push rbx
    push rcx
    push rdx
    push rsi
    
    ; Check if vtable ID is valid
    cmp rdi, [vtable_count]
    jge .add_failed
    
    ; Check if vtable has space
    mov rbx, [vtable_sizes + rdi * 8]
    cmp rbx, MAX_VTABLE_ENTRIES
    jge .add_failed
    
    ; Calculate vtable entry address
    mov rcx, rdi
    imul rcx, MAX_VTABLE_ENTRIES * VTABLE_ENTRY_SIZE
    add rcx, vtable_storage
    mov rax, rbx
    imul rax, VTABLE_ENTRY_SIZE
    add rcx, rax
    
    ; Store method address
    mov [rcx], rdx
    
    ; Store method signature (simplified)
    mov qword [rcx + 8], 0
    
    ; Increment vtable size
    inc qword [vtable_sizes + rdi * 8]
    
    mov rax, 1
    jmp .return

.add_failed:
    mov rax, 0

.return:
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    ret

; Get a method from a vtable
; Input: rdi = vtable ID, rsi = method index
; Output: rax = method address or 0 if not found
vtable_get_method:
    push rbx
    push rcx
    push rdx
    
    ; Check if vtable ID is valid
    cmp rdi, [vtable_count]
    jge .get_failed
    
    ; Check if method index is valid
    cmp rsi, [vtable_sizes + rdi * 8]
    jge .get_failed
    
    ; Calculate vtable entry address
    mov rcx, rdi
    imul rcx, MAX_VTABLE_ENTRIES * VTABLE_ENTRY_SIZE
    add rcx, vtable_storage
    mov rax, rsi
    imul rax, VTABLE_ENTRY_SIZE
    add rcx, rax
    
    ; Get method address
    mov rax, [rcx]
    jmp .return

.get_failed:
    xor rax, rax

.return:
    pop rdx
    pop rcx
    pop rbx
    ret

; Define a new class
; Input: rdi = class name, rsi = vtable ID, rdx = parent class ID
; Output: rax = class ID or -1 if failed
class_define:
    push rbx
    push rcx
    push rdx
    push rsi
    
    ; Check if we have space for new class
    mov rbx, [class_count]
    cmp rbx, MAX_CLASSES
    jge .define_failed
    
    ; Store class information
    mov [class_table + rbx * 32], rdi      ; Class name
    mov [class_table + rbx * 32 + 8], rsi  ; Vtable ID
    mov [class_table + rbx * 32 + 16], rdx ; Parent class ID
    mov qword [class_table + rbx * 32 + 24], 0 ; Class size (to be calculated)
    
    ; Set up inheritance chain
    cmp rdx, -1
    je .no_parent
    
    ; Copy parent's inheritance chain
    mov rcx, 0
.copy_parent_loop:
    cmp rcx, MAX_CLASSES
    jge .copy_parent_done
    
    mov rax, [inheritance_chain + rdx * MAX_CLASSES * 8 + rcx * 8]
    mov [inheritance_chain + rbx * MAX_CLASSES * 8 + rcx * 8], rax
    
    inc rcx
    jmp .copy_parent_loop

.copy_parent_done:
    ; Add parent to inheritance chain
    mov qword [inheritance_chain + rbx * MAX_CLASSES * 8 + rdx * 8], 1

.no_parent:
    ; Add self to inheritance chain
    mov qword [inheritance_chain + rbx * MAX_CLASSES * 8 + rbx * 8], 1
    
    ; Increment class count
    inc qword [class_count]
    
    mov rax, rbx
    jmp .return

.define_failed:
    mov rax, -1

.return:
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    ret

; Set up inheritance relationship
; Input: rdi = child class ID, rsi = parent class ID
class_inherit:
    push rbx
    push rcx
    push rdx
    
    ; Check if class IDs are valid
    cmp rdi, [class_count]
    jge .inherit_failed
    cmp rsi, [class_count]
    jge .inherit_failed
    
    ; Set inheritance relationship
    mov qword [inheritance_chain + rdi * MAX_CLASSES * 8 + rsi * 8], 1
    
    ; Copy parent's inheritance chain
    mov rcx, 0
.copy_loop:
    cmp rcx, MAX_CLASSES
    jge .copy_done
    
    mov rax, [inheritance_chain + rsi * MAX_CLASSES * 8 + rcx * 8]
    cmp rax, 0
    je .next_class
    
    mov qword [inheritance_chain + rdi * MAX_CLASSES * 8 + rcx * 8], 1

.next_class:
    inc rcx
    jmp .copy_loop

.copy_done:
    mov rax, 1
    jmp .return

.inherit_failed:
    mov rax, 0

.return:
    pop rdx
    pop rcx
    pop rbx
    ret

; Create an object of a class
; Input: rdi = class ID
; Output: rax = object pointer or 0 if failed
object_create:
    push rbx
    push rcx
    push rdx
    
    ; Check if class ID is valid
    cmp rdi, [class_count]
    jge .create_failed
    
    ; Get class size
    mov rbx, [class_table + rdi * 32 + 24]
    cmp rbx, 0
    jne .size_known
    
    ; Calculate class size (vtable pointer + data)
    mov rbx, 8  ; Vtable pointer
    ; TODO: Add field sizes
    
.size_known:
    ; Allocate memory for object
    mov rdi, rbx
    call heap_alloc
    cmp rax, 0
    je .create_failed
    
    ; Store vtable pointer
    mov rbx, [class_table + rdi * 32 + 8]  ; Get vtable ID
    mov [rax], rbx  ; Store vtable ID at offset 0
    
    ; Initialize object data
    mov rcx, rax
    add rcx, 8  ; Skip vtable pointer
    mov rdx, [class_table + rdi * 32 + 24]
    sub rdx, 8  ; Subtract vtable pointer size
    cmp rdx, 0
    jle .init_done
    
    ; Clear object data
    mov rsi, rcx
    mov rdi, rdx
    xor rax, rax
    rep stosb
    mov rax, rsi
    sub rax, 8  ; Restore object pointer

.init_done:
    jmp .return

.create_failed:
    xor rax, rax

.return:
    pop rdx
    pop rcx
    pop rbx
    ret

; Destroy an object
; Input: rdi = object pointer
object_destroy:
    push rbx
    push rcx
    push rdx
    
    ; Free object memory
    call heap_free
    
    pop rdx
    pop rcx
    pop rbx
    ret

; Make a virtual function call
; Input: rdi = object pointer, rsi = method index
; Output: rax = return value
virtual_call:
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    
    ; Get vtable ID from object
    mov rbx, [rdi]
    
    ; Get method address from vtable
    mov rdi, rbx
    call vtable_get_method
    cmp rax, 0
    je .call_failed
    
    ; Call the method
    mov rbx, rax  ; Save method address
    pop rdi       ; Restore object pointer
    pop rsi       ; Restore method index
    call rbx      ; Call the method
    
    jmp .return

.call_failed:
    pop rdi
    pop rsi
    xor rax, rax

.return:
    pop rdx
    pop rcx
    pop rbx
    ret

; Register a method
; Input: rdi = method name, rsi = method address
; Output: rax = method ID or -1 if failed
method_register:
    push rbx
    push rcx
    push rdx
    
    ; Check if we have space for new method
    mov rbx, [method_count]
    cmp rbx, 1024
    jge .register_failed
    
    ; Store method information
    mov [method_table + rbx * 8], rdi  ; Method name
    mov [method_table + rbx * 8 + 4], rsi  ; Method address
    
    ; Increment method count
    inc qword [method_count]
    
    mov rax, rbx
    jmp .return

.register_failed:
    mov rax, -1

.return:
    pop rdx
    pop rcx
    pop rbx
    ret

; Look up a method by name
; Input: rdi = method name
; Output: rax = method address or 0 if not found
method_lookup:
    push rbx
    push rcx
    push rdx
    
    mov rbx, 0
.find_loop:
    cmp rbx, [method_count]
    jge .not_found
    
    mov rcx, [method_table + rbx * 8]
    cmp rcx, rdi
    je .found
    
    inc rbx
    jmp .find_loop

.found:
    mov rax, [method_table + rbx * 8 + 4]
    jmp .return

.not_found:
    xor rax, rax

.return:
    pop rdx
    pop rcx
    pop rbx
    ret

; Check if one class inherits from another
; Input: rdi = child class ID, rsi = parent class ID
; Output: rax = 1 if inherits, 0 if not
inheritance_check:
    push rbx
    push rcx
    push rdx
    
    ; Check if class IDs are valid
    cmp rdi, [class_count]
    jge .check_failed
    cmp rsi, [class_count]
    jge .check_failed
    
    ; Check inheritance chain
    mov rax, [inheritance_chain + rdi * MAX_CLASSES * 8 + rsi * 8]
    jmp .return

.check_failed:
    xor rax, rax

.return:
    pop rdx
    pop rcx
    pop rbx
    ret

; Dump vtable information (for debugging)
vtable_dump:
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    
    ; Print vtable count
    mov rdi, [vtable_count]
    call print_number
    
    ; Print class count
    mov rdi, [class_count]
    call print_number
    
    ; Print method count
    mov rdi, [method_count]
    call print_number
    
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    ret

; Print a number (helper function)
print_number:
    push rbx
    push rcx
    push rdx
    push rsi
    
    mov rbx, rdi    ; Save number
    mov rcx, 0      ; Digit count
    mov rsi, 10     ; Base
    
    ; Convert to string
    mov rax, rbx
.convert_loop:
    cmp rax, 0
    je .print_loop
    xor rdx, rdx
    div rsi
    add rdx, '0'
    push rdx
    inc rcx
    jmp .convert_loop

.print_loop:
    cmp rcx, 0
    je .done
    pop rdx
    mov [temp_registers], rdx
    mov rdi, temp_registers
    mov rsi, 1
    call print_string
    dec rcx
    jmp .print_loop

.done:
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    ret

; Print a string (helper function)
print_string:
    push rax
    push rdx
    push rcx
    
    mov rax, 1      ; syscall number for write
    mov rdx, rsi    ; string length
    mov rsi, rdi    ; string pointer
    mov rdi, 1      ; file descriptor (stdout)
    syscall
    
    pop rcx
    pop rdx
    pop rax
    ret
