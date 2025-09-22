; test_reverser_vtable.asm
; Test program for Reverser vtable system
; Demonstrates object-oriented features and virtual function dispatch

%include "reverser_vtable.asm"

section .data
    ; Test messages
    msg_vtable_init db "Initializing vtable system...", 10, 0
    msg_vtable_init_len equ $ - msg_vtable_init - 1
    
    msg_class_test db "Testing class definition...", 10, 0
    msg_class_test_len equ $ - msg_class_test - 1
    
    msg_inheritance_test db "Testing inheritance...", 10, 0
    msg_inheritance_test_len equ $ - msg_inheritance_test - 1
    
    msg_virtual_call_test db "Testing virtual function calls...", 10, 0
    msg_virtual_call_test_len equ $ - msg_virtual_call_test - 1
    
    msg_polymorphism_test db "Testing polymorphism...", 10, 0
    msg_polymorphism_test_len equ $ - msg_polymorphism_test - 1
    
    msg_test_complete db "Vtable tests completed successfully!", 10, 0
    msg_test_complete_len equ $ - msg_test_complete - 1
    
    ; Test class names
    class_animal db "Animal", 0
    class_dog db "Dog", 0
    class_cat db "Cat", 0
    
    ; Test method names
    method_speak db "speak", 0
    method_move db "move", 0
    method_eat db "eat", 0

section .bss
    ; Test variables
    test_vtable_id resq 1
    test_class_id resq 1
    test_object resq 1
    test_method_id resq 1

section .text
    global _start
    extern vtable_init
    extern vtable_create
    extern vtable_add_method
    extern class_define
    extern class_inherit
    extern object_create
    extern object_destroy
    extern virtual_call
    extern method_register
    extern inheritance_check
    extern vtable_dump

; Print a string
; Input: rdi = pointer to string, rsi = string length
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

; Test class definition
test_class_definition:
    push rbx
    push rcx
    push rdx
    
    ; Print test message
    mov rdi, msg_class_test
    mov rsi, msg_class_test_len
    call print_string
    
    ; Create vtable for Animal class
    mov rdi, class_animal
    call vtable_create
    mov [test_vtable_id], rax
    
    ; Add methods to Animal vtable
    mov rdi, [test_vtable_id]
    mov rsi, method_speak
    mov rdx, animal_speak_method
    call vtable_add_method
    
    mov rdi, [test_vtable_id]
    mov rsi, method_move
    mov rdx, animal_move_method
    call vtable_add_method
    
    mov rdi, [test_vtable_id]
    mov rsi, method_eat
    mov rdx, animal_eat_method
    call vtable_add_method
    
    ; Define Animal class
    mov rdi, class_animal
    mov rsi, [test_vtable_id]
    mov rdx, -1  ; No parent
    call class_define
    mov [test_class_id], rax
    
    pop rdx
    pop rcx
    pop rbx
    ret

; Test inheritance
test_inheritance:
    push rbx
    push rcx
    push rdx
    
    ; Print test message
    mov rdi, msg_inheritance_test
    mov rsi, msg_inheritance_test_len
    call print_string
    
    ; Create vtable for Dog class
    mov rdi, class_dog
    call vtable_create
    mov [test_vtable_id], rax
    
    ; Add methods to Dog vtable
    mov rdi, [test_vtable_id]
    mov rsi, method_speak
    mov rdx, dog_speak_method
    call vtable_add_method
    
    mov rdi, [test_vtable_id]
    mov rsi, method_move
    mov rdx, dog_move_method
    call vtable_add_method
    
    mov rdi, [test_vtable_id]
    mov rsi, method_eat
    mov rdx, dog_eat_method
    call vtable_add_method
    
    ; Define Dog class
    mov rdi, class_dog
    mov rsi, [test_vtable_id]
    mov rdx, [test_class_id]  ; Inherit from Animal
    call class_define
    mov [test_class_id], rax
    
    ; Set up inheritance relationship
    mov rdi, [test_class_id]
    mov rsi, 0  ; Animal class ID
    call class_inherit
    
    pop rdx
    pop rcx
    pop rbx
    ret

; Test virtual function calls
test_virtual_calls:
    push rbx
    push rcx
    push rdx
    
    ; Print test message
    mov rdi, msg_virtual_call_test
    mov rsi, msg_virtual_call_test_len
    call print_string
    
    ; Create Animal object
    mov rdi, 0  ; Animal class ID
    call object_create
    mov [test_object], rax
    
    ; Call virtual methods
    mov rdi, [test_object]
    mov rsi, 0  ; speak method index
    call virtual_call
    
    mov rdi, [test_object]
    mov rsi, 1  ; move method index
    call virtual_call
    
    mov rdi, [test_object]
    mov rsi, 2  ; eat method index
    call virtual_call
    
    ; Destroy object
    mov rdi, [test_object]
    call object_destroy
    
    pop rdx
    pop rcx
    pop rbx
    ret

; Test polymorphism
test_polymorphism:
    push rbx
    push rcx
    push rdx
    
    ; Print test message
    mov rdi, msg_polymorphism_test
    mov rsi, msg_polymorphism_test_len
    call print_string
    
    ; Create Dog object
    mov rdi, 1  ; Dog class ID
    call object_create
    mov [test_object], rax
    
    ; Call virtual methods (should use Dog implementations)
    mov rdi, [test_object]
    mov rsi, 0  ; speak method index
    call virtual_call
    
    mov rdi, [test_object]
    mov rsi, 1  ; move method index
    call virtual_call
    
    mov rdi, [test_object]
    mov rsi, 2  ; eat method index
    call virtual_call
    
    ; Test inheritance check
    mov rdi, 1  ; Dog class ID
    mov rsi, 0  ; Animal class ID
    call inheritance_check
    ; Result should be 1 (Dog inherits from Animal)
    
    ; Destroy object
    mov rdi, [test_object]
    call object_destroy
    
    pop rdx
    pop rcx
    pop rbx
    ret

; Animal class methods
animal_speak_method:
    push rbx
    push rcx
    push rdx
    
    ; Animal speaks
    mov rax, 1  ; Return value
    
    pop rdx
    pop rcx
    pop rbx
    ret

animal_move_method:
    push rbx
    push rcx
    push rdx
    
    ; Animal moves
    mov rax, 2  ; Return value
    
    pop rdx
    pop rcx
    pop rbx
    ret

animal_eat_method:
    push rbx
    push rcx
    push rdx
    
    ; Animal eats
    mov rax, 3  ; Return value
    
    pop rdx
    pop rcx
    pop rbx
    ret

; Dog class methods
dog_speak_method:
    push rbx
    push rcx
    push rdx
    
    ; Dog barks
    mov rax, 4  ; Return value
    
    pop rdx
    pop rcx
    pop rbx
    ret

dog_move_method:
    push rbx
    push rcx
    push rdx
    
    ; Dog runs
    mov rax, 5  ; Return value
    
    pop rdx
    pop rcx
    pop rbx
    ret

dog_eat_method:
    push rbx
    push rcx
    push rdx
    
    ; Dog eats dog food
    mov rax, 6  ; Return value
    
    pop rdx
    pop rcx
    pop rbx
    ret

; Main test function
_start:
    ; Print initialization message
    mov rdi, msg_vtable_init
    mov rsi, msg_vtable_init_len
    call print_string
    
    ; Initialize vtable system
    call vtable_init
    
    ; Run tests
    call test_class_definition
    call test_inheritance
    call test_virtual_calls
    call test_polymorphism
    
    ; Print completion message
    mov rdi, msg_test_complete
    mov rsi, msg_test_complete_len
    call print_string
    
    ; Dump vtable information
    call vtable_dump
    
    ; Exit
    mov rax, 60     ; syscall number for exit
    xor rdi, rdi    ; exit code 0
    syscall
