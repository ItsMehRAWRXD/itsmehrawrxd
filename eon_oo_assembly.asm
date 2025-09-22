; eon_oo_assembly.asm
; Object-oriented features in assembly: inheritance, polymorphism, vtables

section .data
    ; === VTable Structure ===
    vtable_size         equ 32      ; Size of vtable entry
    vtable_entry_size   equ 8       ; Size of function pointer
    
    ; === Object Structure ===
    object_header_size  equ 16      ; Size of object header
    vtable_offset       equ 0       ; Offset to vtable pointer
    ref_count_offset    equ 8       ; Offset to reference count
    
    ; === Class Information ===
    class_name_offset   equ 0       ; Offset to class name
    class_size_offset   equ 8       ; Offset to class size
    class_vtable_offset equ 16      ; Offset to vtable
    
    ; === Method Dispatch ===
    method_offset       equ 0       ; Offset to method in vtable
    
    ; === Inheritance Chain ===
    parent_class_offset equ 24      ; Offset to parent class pointer
    
    ; === Sample Classes ===
    ; Base class: Shape
    shape_vtable        resq 4      ; 4 methods: draw, area, perimeter, destroy
    shape_class_info    resq 4      ; class info for Shape
    
    ; Derived class: Circle
    circle_vtable       resq 4      ; 4 methods: draw, area, perimeter, destroy
    circle_class_info   resq 4      ; class info for Circle
    
    ; Derived class: Rectangle
    rectangle_vtable    resq 4      ; 4 methods: draw, area, perimeter, destroy
    rectangle_class_info resq 4     ; class info for Rectangle
    
    ; === Method Names ===
    method_draw         db "draw", 0
    method_area         db "area", 0
    method_perimeter    db "perimeter", 0
    method_destroy      db "destroy", 0
    
    ; === Class Names ===
    class_shape         db "Shape", 0
    class_circle        db "Circle", 0
    class_rectangle     db "Rectangle", 0

section .text
    global oo_init_vtables
    global oo_create_object
    global oo_destroy_object
    global oo_virtual_call
    global oo_get_vtable
    global oo_set_vtable
    global oo_inherit_from
    global oo_override_method
    global oo_allocate_object
    global oo_deallocate_object
    global oo_add_reference
    global oo_remove_reference

; === Initialize VTable System ===
oo_init_vtables:
    push rbp
    mov rbp, rsp
    
    ; Initialize Shape vtable
    mov qword [shape_vtable + 0], shape_draw
    mov qword [shape_vtable + 8], shape_area
    mov qword [shape_vtable + 16], shape_perimeter
    mov qword [shape_vtable + 24], shape_destroy
    
    ; Initialize Shape class info
    mov qword [shape_class_info + class_name_offset], class_shape
    mov qword [shape_class_info + class_size_offset], 32  ; Shape object size
    mov qword [shape_class_info + class_vtable_offset], shape_vtable
    mov qword [shape_class_info + parent_class_offset], 0  ; No parent
    
    ; Initialize Circle vtable
    mov qword [circle_vtable + 0], circle_draw
    mov qword [circle_vtable + 8], circle_area
    mov qword [circle_vtable + 16], circle_perimeter
    mov qword [circle_vtable + 24], circle_destroy
    
    ; Initialize Circle class info
    mov qword [circle_class_info + class_name_offset], class_circle
    mov qword [circle_class_info + class_size_offset], 40  ; Circle object size
    mov qword [circle_class_info + class_vtable_offset], circle_vtable
    mov qword [circle_class_info + parent_class_offset], shape_class_info
    
    ; Initialize Rectangle vtable
    mov qword [rectangle_vtable + 0], rectangle_draw
    mov qword [rectangle_vtable + 8], rectangle_area
    mov qword [rectangle_vtable + 16], rectangle_perimeter
    mov qword [rectangle_vtable + 24], rectangle_destroy
    
    ; Initialize Rectangle class info
    mov qword [rectangle_class_info + class_name_offset], class_rectangle
    mov qword [rectangle_class_info + class_size_offset], 48  ; Rectangle object size
    mov qword [rectangle_class_info + class_vtable_offset], rectangle_vtable
    mov qword [rectangle_class_info + parent_class_offset], shape_class_info
    
    leave
    ret

; === Create Object ===
; Args: rdi = class info pointer
; Returns: rax = object pointer
oo_create_object:
    push rbp
    mov rbp, rsp
    push rbx
    
    mov rbx, rdi
    
    ; Get class size
    mov rdi, [rbx + class_size_offset]
    call oo_allocate_object
    
    ; Set vtable pointer
    mov rdx, [rbx + class_vtable_offset]
    mov [rax + vtable_offset], rdx
    
    ; Initialize reference count
    mov qword [rax + ref_count_offset], 1
    
    ; Initialize object data (zero out)
    mov rcx, [rbx + class_size_offset]
    sub rcx, object_header_size
    mov rdi, rax
    add rdi, object_header_size
    call zero_memory
    
    pop rbx
    leave
    ret

; === Destroy Object ===
; Args: rdi = object pointer
oo_destroy_object:
    push rbp
    mov rbp, rsp
    push rbx
    
    mov rbx, rdi
    
    ; Decrement reference count
    dec qword [rbx + ref_count_offset]
    cmp qword [rbx + ref_count_offset], 0
    jg .done
    
    ; Call destructor
    mov rdx, [rbx + vtable_offset]
    mov rcx, [rdx + 24]  ; destroy method
    mov rdi, rbx
    call rcx
    
    ; Deallocate object
    mov rdi, rbx
    call oo_deallocate_object
    
.done:
    pop rbx
    leave
    ret

; === Virtual Method Call ===
; Args: rdi = object pointer, rsi = method offset
; Returns: rax = method result
oo_virtual_call:
    push rbp
    mov rbp, rsp
    push rbx
    push rcx
    
    mov rbx, rdi
    mov rcx, rsi
    
    ; Get vtable
    mov rdx, [rbx + vtable_offset]
    
    ; Get method address
    mov rdx, [rdx + rcx]
    
    ; Call method
    mov rdi, rbx
    call rdx
    
    pop rcx
    pop rbx
    leave
    ret

; === Get VTable ===
; Args: rdi = object pointer
; Returns: rax = vtable pointer
oo_get_vtable:
    push rbp
    mov rbp, rsp
    
    mov rax, [rdi + vtable_offset]
    
    leave
    ret

; === Set VTable ===
; Args: rdi = object pointer, rsi = vtable pointer
oo_set_vtable:
    push rbp
    mov rbp, rsp
    
    mov [rdi + vtable_offset], rsi
    
    leave
    ret

; === Inherit From ===
; Args: rdi = derived class info, rsi = base class info
oo_inherit_from:
    push rbp
    mov rbp, rsp
    push rbx
    push rcx
    push rdx
    
    mov rbx, rdi  ; derived class
    mov rcx, rsi  ; base class
    
    ; Set parent class
    mov [rbx + parent_class_offset], rcx
    
    ; Copy base vtable to derived vtable
    mov rdx, [rcx + class_vtable_offset]  ; base vtable
    mov rdi, [rbx + class_vtable_offset]  ; derived vtable
    
    ; Copy vtable entries (4 methods)
    mov rsi, [rdx + 0]
    mov [rdi + 0], rsi
    mov rsi, [rdx + 8]
    mov [rdi + 8], rsi
    mov rsi, [rdx + 16]
    mov [rdi + 16], rsi
    mov rsi, [rdx + 24]
    mov [rdi + 24], rsi
    
    pop rdx
    pop rcx
    pop rbx
    leave
    ret

; === Override Method ===
; Args: rdi = class info, rsi = method offset, rdx = new method
oo_override_method:
    push rbp
    mov rbp, rsp
    push rbx
    push rcx
    
    mov rbx, rdi
    mov rcx, rsi
    
    ; Get vtable
    mov rdi, [rbx + class_vtable_offset]
    
    ; Set new method
    mov [rdi + rcx], rdx
    
    pop rcx
    pop rbx
    leave
    ret

; === Allocate Object ===
; Args: rdi = size
; Returns: rax = allocated memory
oo_allocate_object:
    push rbp
    mov rbp, rsp
    
    ; Simple memory allocation (in real implementation, use proper allocator)
    mov rax, 9              ; sys_mmap
    mov rsi, rdi            ; size
    mov rdx, 3              ; PROT_READ | PROT_WRITE
    mov r10, 34             ; MAP_PRIVATE | MAP_ANONYMOUS
    mov r8, -1              ; fd
    mov r9, 0               ; offset
    syscall
    
    leave
    ret

; === Deallocate Object ===
; Args: rdi = object pointer
oo_deallocate_object:
    push rbp
    mov rbp, rsp
    
    ; Simple memory deallocation (in real implementation, use proper deallocator)
    ; For now, just return (memory will be freed when process exits)
    
    leave
    ret

; === Add Reference ===
; Args: rdi = object pointer
oo_add_reference:
    push rbp
    mov rbp, rsp
    
    inc qword [rdi + ref_count_offset]
    
    leave
    ret

; === Remove Reference ===
; Args: rdi = object pointer
oo_remove_reference:
    push rbp
    mov rbp, rsp
    
    dec qword [rdi + ref_count_offset]
    
    leave
    ret

; === Zero Memory ===
; Args: rdi = memory pointer, rsi = size
zero_memory:
    push rbp
    mov rbp, rsp
    push rbx
    push rcx
    
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

; === Shape Methods ===
shape_draw:
    push rbp
    mov rbp, rsp
    
    ; Shape draw implementation
    ; In real implementation, this would draw a generic shape
    
    leave
    ret

shape_area:
    push rbp
    mov rbp, rsp
    
    ; Shape area implementation
    ; In real implementation, this would calculate generic area
    mov rax, 0
    
    leave
    ret

shape_perimeter:
    push rbp
    mov rbp, rsp
    
    ; Shape perimeter implementation
    ; In real implementation, this would calculate generic perimeter
    mov rax, 0
    
    leave
    ret

shape_destroy:
    push rbp
    mov rbp, rsp
    
    ; Shape destroy implementation
    ; In real implementation, this would clean up shape resources
    
    leave
    ret

; === Circle Methods ===
circle_draw:
    push rbp
    mov rbp, rsp
    
    ; Circle draw implementation
    ; In real implementation, this would draw a circle
    
    leave
    ret

circle_area:
    push rbp
    mov rbp, rsp
    
    ; Circle area implementation
    ; In real implementation, this would calculate circle area
    ; For now, return a dummy value
    mov rax, 314  ; π * r² for r=10
    
    leave
    ret

circle_perimeter:
    push rbp
    mov rbp, rsp
    
    ; Circle perimeter implementation
    ; In real implementation, this would calculate circle perimeter
    ; For now, return a dummy value
    mov rax, 63   ; 2 * π * r for r=10
    
    leave
    ret

circle_destroy:
    push rbp
    mov rbp, rsp
    
    ; Circle destroy implementation
    ; In real implementation, this would clean up circle resources
    
    leave
    ret

; === Rectangle Methods ===
rectangle_draw:
    push rbp
    mov rbp, rsp
    
    ; Rectangle draw implementation
    ; In real implementation, this would draw a rectangle
    
    leave
    ret

rectangle_area:
    push rbp
    mov rbp, rsp
    
    ; Rectangle area implementation
    ; In real implementation, this would calculate rectangle area
    ; For now, return a dummy value
    mov rax, 200  ; width * height for 20x10
    
    leave
    ret

rectangle_perimeter:
    push rbp
    mov rbp, rsp
    
    ; Rectangle perimeter implementation
    ; In real implementation, this would calculate rectangle perimeter
    ; For now, return a dummy value
    mov rax, 60   ; 2 * (width + height) for 20x10
    
    leave
    ret

rectangle_destroy:
    push rbp
    mov rbp, rsp
    
    ; Rectangle destroy implementation
    ; In real implementation, this would clean up rectangle resources
    
    leave
    ret

; === Polymorphism Demo ===
; Args: rdi = shape object pointer
demo_polymorphism:
    push rbp
    mov rbp, rsp
    push rbx
    
    mov rbx, rdi
    
    ; Call draw method (polymorphic)
    mov rdi, rbx
    mov rsi, 0  ; draw method offset
    call oo_virtual_call
    
    ; Call area method (polymorphic)
    mov rdi, rbx
    mov rsi, 8  ; area method offset
    call oo_virtual_call
    
    ; Call perimeter method (polymorphic)
    mov rdi, rbx
    mov rsi, 16  ; perimeter method offset
    call oo_virtual_call
    
    pop rbx
    leave
    ret

; === Inheritance Demo ===
demo_inheritance:
    push rbp
    mov rbp, rsp
    push rbx
    push rcx
    
    ; Create a circle object
    mov rdi, circle_class_info
    call oo_create_object
    mov rbx, rax
    
    ; Demonstrate polymorphism
    mov rdi, rbx
    call demo_polymorphism
    
    ; Create a rectangle object
    mov rdi, rectangle_class_info
    call oo_create_object
    mov rcx, rax
    
    ; Demonstrate polymorphism
    mov rdi, rcx
    call demo_polymorphism
    
    ; Clean up
    mov rdi, rbx
    call oo_destroy_object
    
    mov rdi, rcx
    call oo_destroy_object
    
    pop rcx
    pop rbx
    leave
    ret
