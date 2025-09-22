; ========================================
; EON IDE Enhanced - XCB Graphical Frontend with EON Compiler Integration
; ========================================
; Enhanced version with editor buffer, syntax highlighting, and EON compiler
; integration. This builds upon the basic XCB skeleton to create a full IDE.
; ========================================

BITS 64

        ; Import XCB functions
        extern  xcb_connect, xcb_disconnect, xcb_get_setup
        extern  xcb_setup_roots_iterator, xcb_generate_id, xcb_create_window
        extern  xcb_map_window, xcb_flush, xcb_wait_for_event, free
        extern  xcb_create_gc, xcb_put_image, xcb_keysym_to_utf8

        ; EON Compiler functions (to be implemented)
        extern  eon_compile, eon_lex, eon_parse, eon_semantic_analyze

        ; XCB constants
%define XCB_COPY_FROM_PARENT      0
%define XCB_WINDOW_CLASS_INPUT_OUTPUT  1
%define XCB_EVENT_MASK_EXPOSURE   1
%define XCB_EVENT_MASK_KEY_PRESS  2
%define XCB_EVENT_MASK_STRUCTURE_NOTIFY  131072
%define XCB_EXPOSE                12
%define XCB_KEY_PRESS             2
%define XCB_IMAGE_FORMAT_Z_PIXMAP 2

        ; Editor constants
%define CHAR_WIDTH  8
%define CHAR_HEIGHT 8
%define MAX_LINES   1000
%define MAX_COLS    200
%define TAB_SIZE    4

        ; Color constants (BGRA format)
%define COLOR_BLACK     0x00000000
%define COLOR_WHITE     0x00FFFFFF
%define COLOR_RED       0x000000FF
%define COLOR_GREEN     0x0000FF00
%define COLOR_BLUE      0x00FF0000
%define COLOR_YELLOW    0x0000FFFF
%define COLOR_CYAN      0x00FFFF00
%define COLOR_MAGENTA   0x00FF00FF
%define COLOR_GRAY      0x00808080
%define COLOR_DARK_GRAY 0x00404040

section .data
    ; Window dimensions
    win_width   dd 1200
    win_height  dd 800
    
    ; Editor state
    cursor_x    dd 0
    cursor_y    dd 0
    scroll_x    dd 0
    scroll_y    dd 0
    current_line dd 0
    total_lines dd 1
    
    ; File information
    filename    db "untitled.eon", 0
    file_modified db 0
    
    ; Status messages
    status_msg  db "EON IDE - Ready", 0
    compile_msg db "Compiling...", 0
    error_msg   db "Error: ", 0
    
    ; EON keywords for syntax highlighting
    eon_keywords:
        db "let", 0, "const", 0, "fn", 0, "if", 0, "else", 0
        db "while", 0, "for", 0, "return", 0, "struct", 0
        db "match", 0, "case", 0, "try", 0, "catch", 0
        db "finally", 0, "throw", 0, "spawn", 0, "shared", 0
        db "alloc", 0, "free", 0, "sizeof", 0, 0

    ; Font atlas (same as before, truncated for brevity)
    font_atlas:
        db 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00   ; space
        db 0x18,0x3C,0x3C,0x18,0x18,0x00,0x18,0x00   ; !
        ; ... (rest of font data would go here)
        db 0x6E,0x3B,0x00,0x00,0x00,0x00,0x00,0x00   ; ~

section .bss
    ; XCB connection and window
    conn_ptr        resq 1
    screen_ptr      resq 1
    window_id       resd 1
    event_ptr       resq 1
    gc_id           resd 1
    
    ; Back buffer
    image_buffer    resb (1200 * 800 * 4)
    
    ; Editor buffer - array of lines
    editor_buffer   resb (MAX_LINES * MAX_COLS)
    line_lengths    resd MAX_LINES
    
    ; Compilation results
    compile_errors  resb 1000
    compile_output  resb 1000

section .text
global _start

_start:
    ; Initialize XCB connection and window (same as basic version)
    call init_xcb_window
    
    ; Initialize editor
    call init_editor
    
    ; Enter main event loop
    jmp event_loop

; ========================================
; XCB Initialization
; ========================================
init_xcb_window:
    ; Connect to X server
    xor rdi, rdi
    xor rsi, rsi
    call xcb_connect
    mov [conn_ptr], rax
    
    ; Get screen and create window (implementation details same as basic version)
    ; ... (XCB setup code)
    
    ; Create graphics context
    mov rdi, [conn_ptr]
    call xcb_generate_id
    mov [gc_id], eax
    
    mov rdi, [conn_ptr]
    mov esi, [gc_id]
    mov edx, [window_id]
    xor ecx, ecx
    xor r8, r8
    call xcb_create_gc
    
    mov rdi, [conn_ptr]
    call xcb_flush
    ret

; ========================================
; Editor Initialization
; ========================================
init_editor:
    ; Initialize editor buffer with sample EON code
    mov rdi, editor_buffer
    mov rsi, sample_eon_code
    mov rcx, sample_eon_code_len
    rep movsb
    
    ; Set initial cursor position
    mov dword [cursor_x], 0
    mov dword [cursor_y], 0
    mov dword [current_line], 0
    
    ; Calculate line lengths
    call calculate_line_lengths
    ret

; ========================================
; Main Event Loop
; ========================================
event_loop:
    mov rdi, [conn_ptr]
    call xcb_wait_for_event
    test rax, rax
    je exit_program
    mov [event_ptr], rax
    
    ; Check event type
    mov bl, [rax]
    and bl, 0x7F
    
    cmp bl, XCB_EXPOSE
    je handle_expose
    cmp bl, XCB_KEY_PRESS
    je handle_keypress
    
    jmp next_event

handle_expose:
    call draw_ui
    call flush_display
    jmp next_event

handle_keypress:
    call process_keypress
    jmp next_event

next_event:
    mov rdi, [event_ptr]
    call free
    jmp event_loop

; ========================================
; Key Processing
; ========================================
process_keypress:
    ; TODO: Implement key processing
    ; - Arrow keys for cursor movement
    ; - Character input
    ; - Special keys (Enter, Backspace, Tab, etc.)
    ; - Keyboard shortcuts (Ctrl+S, Ctrl+C, etc.)
    ret

; ========================================
; UI Drawing
; ========================================
draw_ui:
    ; Clear background
    call clear_background
    
    ; Draw editor area
    call draw_editor
    
    ; Draw status bar
    call draw_status_bar
    
    ; Draw cursor
    call draw_cursor
    ret

clear_background:
    mov rcx, 1200*800
    lea rdi, [rel image_buffer]
    mov eax, COLOR_DARK_GRAY
.clear_loop:
    mov dword [rdi], eax
    add rdi, 4
    dec rcx
    jnz .clear_loop
    ret

draw_editor:
    ; Draw editor content with syntax highlighting
    mov r8d, 0  ; line number
    mov r9d, 0  ; y position
    
.draw_line_loop:
    cmp r8d, [total_lines]
    jge .draw_done
    
    ; Calculate line start position
    mov eax, r8d
    imul eax, MAX_COLS
    lea rsi, [editor_buffer + rax]
    
    ; Draw line with syntax highlighting
    mov edi, 10  ; x position
    mov edx, r9d ; y position
    call draw_line_with_syntax
    
    add r9d, CHAR_HEIGHT
    inc r8d
    jmp .draw_line_loop
    
.draw_done:
    ret

draw_line_with_syntax:
    ; Draw a line with EON syntax highlighting
    ; TODO: Implement syntax highlighting logic
    ; - Keywords in blue
    ; - Strings in green
    ; - Comments in gray
    ; - Numbers in yellow
    ret

draw_status_bar:
    ; Draw status bar at bottom
    mov edi, 0
    mov esi, 0
    mov edx, [win_height]
    sub edx, CHAR_HEIGHT
    call draw_status_text
    ret

draw_status_text:
    ; Draw status message
    lea rsi, [rel status_msg]
    call draw_string
    ret

draw_cursor:
    ; Draw blinking cursor
    ; TODO: Implement cursor blinking
    ret

; ========================================
; Utility Functions
; ========================================
draw_char:
    ; Enhanced draw_char with color support
    ; Input: dil = character, esi = x, edx = y, ecx = color
    push rbp
    push rbx
    push rdx
    push rsi
    push rdi
    push rcx
    
    ; Character validation and font lookup (same as basic version)
    movzx eax, dil
    cmp al, 32
    jb .dc_done
    cmp al, 126
    ja .dc_done
    
    ; Use color from ecx instead of hardcoded white
    mov eax, ecx  ; color
    
    ; Font rendering logic (enhanced with color)
    ; ... (implementation details)
    
.dc_done:
    pop rcx
    pop rdi
    pop rsi
    pop rdx
    pop rbx
    pop rbp
    ret

draw_string:
    ; Draw a null-terminated string
    ; Input: rsi = string pointer, edi = x, edx = y, ecx = color
    push rdi
    push rdx
    push rcx
    
.string_loop:
    movzx eax, byte [rsi]
    test al, al
    jz .string_done
    
    call draw_char
    add edi, CHAR_WIDTH
    inc rsi
    jmp .string_loop
    
.string_done:
    pop rcx
    pop rdx
    pop rdi
    ret

flush_display:
    ; Send back buffer to X server
    mov eax, [win_width]
    imul eax, [win_height]
    shl rax, 2
    mov r14, rax
    
    mov rdi, [conn_ptr]
    mov rsi, XCB_IMAGE_FORMAT_Z_PIXMAP
    mov edx, [window_id]
    mov ecx, [gc_id]
    mov r8d, [win_width]
    mov r9d, [win_height]
    
    sub rsp, 48
    mov qword [rsp], 0
    mov qword [rsp+8], 0
    mov qword [rsp+16], 0
    mov qword [rsp+24], 24
    mov [rsp+32], r14
    lea rax, [rel image_buffer]
    mov [rsp+40], rax
    call xcb_put_image
    add rsp, 48
    
    mov rdi, [conn_ptr]
    call xcb_flush
    ret

calculate_line_lengths:
    ; Calculate length of each line in editor buffer
    ; TODO: Implement line length calculation
    ret

; ========================================
; Sample EON Code
; ========================================
sample_eon_code:
    db "// EON IDE Sample Code", 10
    db "fn main() {", 10
    db "    let x = 42;", 10
    db "    let y = x * 2;", 10
    db "    if y > 50 {", 10
    db "        println(\"Hello, EON!\");", 10
    db "    }", 10
    db "}", 10, 0
sample_eon_code_len equ $ - sample_eon_code

; ========================================
; Program Exit
; ========================================
exit_program:
    mov rdi, [conn_ptr]
    call xcb_disconnect
    mov rax, 60  ; SYS_exit
    xor rdi, rdi
    syscall
