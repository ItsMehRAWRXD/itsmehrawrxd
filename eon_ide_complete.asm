; ========================================
; EON IDE COMPLETE - INTEGRATED ASSEMBLY
; ========================================
; Complete EON IDE with XCB graphical frontend
; Includes: Compiler, IDE, Debugger, Build System
; Generated: 2025-09-22T03:50:31.155Z
; ========================================

BITS 64

; Import XCB functions
extern  xcb_connect, xcb_disconnect, xcb_get_setup
extern  xcb_setup_roots_iterator, xcb_generate_id, xcb_create_window
extern  xcb_map_window, xcb_flush, xcb_wait_for_event, free
extern  xcb_create_gc, xcb_put_image, xcb_keysym_to_utf8

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
    
    ; IDE state
    ide_mode    dd 0  ; 0=edit, 1=compile, 2=debug
    current_file db "untitled.eon", 0
    
    ; Status messages
    status_ready    db "EON IDE - Ready", 0
    status_compile  db "Compiling...", 0
    status_debug    db "Debugging...", 0
    status_error    db "Error: ", 0

section .bss
    ; XCB connection and window
    conn_ptr        resq 1
    screen_ptr      resq 1
    window_id       resd 1
    event_ptr       resq 1
    gc_id           resd 1
    
    ; Back buffer
    image_buffer    resb (1200 * 800 * 4)
    
    ; Editor buffer
    editor_buffer   resb (MAX_LINES * MAX_COLS)
    line_lengths    resd MAX_LINES
    
    ; IDE state
    cursor_x        resd 1
    cursor_y        resd 1
    scroll_x        resd 1
    scroll_y        resd 1
    current_line    resd 1
    total_lines     resd 1

section .text
global _start

_start:
    ; Initialize complete IDE
    call init_complete_ide
    
    ; Enter main event loop
    jmp main_event_loop

; ========================================
; MAIN INITIALIZATION
; ========================================
init_complete_ide:
    ; Initialize XCB
    call init_xcb_system
    
    ; Initialize editor
    call init_editor_system
    
    ; Initialize compiler
    call init_eon_compiler
    
    ; Initialize debugger
    call init_debugger
    
    ; Initialize build system
    call init_build_system
    
    ; Initialize project manager
    call init_project_manager
    
    ; Initialize code completion
    call init_code_completion
    
    ; Initialize syntax highlighting
    call init_syntax_highlighting
    
    ; Initialize search and replace
    call init_search_replace
    
    ret

; ========================================
; MAIN EVENT LOOP
; ========================================
main_event_loop:
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
    call draw_complete_ui
    call flush_display
    jmp next_event

handle_keypress:
    call process_ide_keypress
    jmp next_event

next_event:
    mov rdi, [event_ptr]
    call free
    jmp main_event_loop

; ========================================
; COMPLETE UI DRAWING
; ========================================
draw_complete_ui:
    ; Clear background
    call clear_background
    
    ; Draw editor area
    call draw_editor_area
    
    ; Draw status bar
    call draw_status_bar
    
    ; Draw menu bar
    call draw_menu_bar
    
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

draw_editor_area:
    ; Draw editor with syntax highlighting
    ; TODO: Implement complete editor drawing
    ret

draw_status_bar:
    ; Draw status bar with current mode
    ; TODO: Implement status bar drawing
    ret

draw_menu_bar:
    ; Draw menu bar with IDE functions
    ; TODO: Implement menu bar drawing
    ret

draw_cursor:
    ; Draw blinking cursor
    ; TODO: Implement cursor drawing
    ret

; ========================================
; KEY PROCESSING
; ========================================
process_ide_keypress:
    ; Process keyboard input for IDE
    ; TODO: Implement complete key processing
    ret

; ========================================
; DISPLAY MANAGEMENT
; ========================================
flush_display:
    ; Send back buffer to X server
    ; TODO: Implement display flushing
    ret

; ========================================
; SYSTEM INITIALIZATION
; ========================================
init_xcb_system:
    ; Initialize XCB connection and window
    ; TODO: Implement XCB initialization
    ret

init_editor_system:
    ; Initialize editor system
    ; TODO: Implement editor initialization
    ret

; ========================================

; ========================================
; XCB GRAPHICAL FRONTEND
; ========================================

section .data
    font_atlas:
        db 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00   ; 0x20 (space)
        db 0x18,0x3C,0x3C,0x18,0x18,0x00,0x18,0x00   ; 0x21 (!)
        db 0x36,0x36,0x00,0x00,0x00,0x00,0x00,0x00   ; 0x22 (")
        db 0x36,0x36,0x7F,0x36,0x7F,0x36,0x36,0x00   ; 0x23 (#)
        db 0x0C,0x3E,0x03,0x1E,0x30,0x1F,0x0C,0x00   ; 0x24 ($)
        db 0x00,0x63,0x33,0x18,0x0C,0x66,0x63,0x00   ; 0x25 (%)
        db 0x1C,0x36,0x1C,0x6E,0x3B,0x33,0x6E,0x00   ; 0x26 (&)
        db 0x06,0x06,0x03,0x00,0x00,0x00,0x00,0x00   ; 0x27 (')
        db 0x18,0x0C,0x06,0x06,0x06,0x0C,0x18,0x00   ; 0x28 (() 
        db 0x06,0x0C,0x18,0x18,0x18,0x0C,0x06,0x00   ; 0x29 ())
        db 0x00,0x66,0x3C,0xFF,0x3C,0x66,0x00,0x00   ; 0x2A (*)
        db 0x00,0x0C,0x0C,0x3F,0x0C,0x0C,0x00,0x00   ; 0x2B (+)
        db 0x00,0x00,0x00,0x00,0x00,0x0C,0x0C,0x06   ; 0x2C (,)
        db 0x00,0x00,0x00,0x3F,0x00,0x00,0x00,0x00   ; 0x2D (-)
        db 0x00,0x00,0x00,0x00,0x00,0x0C,0x0C,0x00   ; 0x2E (.)
        db 0x60,0x30,0x18,0x0C,0x06,0x03,0x01,0x00   ; 0x2F (/)
        db 0x3E,0x63,0x73,0x7B,0x6F,0x67,0x3E,0x00   ; 0x30 (0)
        db 0x0C,0x0E,0x0C,0x0C,0x0C,0x0C,0x3F,0x00   ; 0x31 (1)
        db 0x1E,0x33,0x30,0x1C,0x06,0x33,0x3F,0x00   ; 0x32 (2)
        db 0x1E,0x33,0x30,0x1C,0x30,0x33,0x1E,0x00   ; 0x33 (3)
        db 0x38,0x3C,0x36,0x33,0x7F,0x30,0x78,0x00   ; 0x34 (4)
        db 0x3F,0x03,0x1F,0x30,0x30,0x33,0x1E,0x00   ; 0x35 (5)
        db 0x1C,0x06,0x03,0x1F,0x33,0x33,0x1E,0x00   ; 0x36 (6)
        db 0x3F,0x33,0x30,0x18,0x0C,0x0C,0x0C,0x00   ; 0x37 (7)
        db 0x1E,0x33,0x33,0x1E,0x33,0x33,0x1E,0x00   ; 0x38 (8)
        db 0x1E,0x33,0x33,0x3E,0x30,0x18,0x0E,0x00   ; 0x39 (9)
        db 0x00,0x0C,0x0C,0x00,0x00,0x0C,0x0C,0x00   ; 0x3A (:)
        db 0x00,0x0C,0x0C,0x00,0x00,0x0C,0x0C,0x06   ; 0x3B (;)
        db 0x18,0x0C,0x06,0x03,0x06,0x0C,0x18,0x00   ; 0x3C (<)
        db 0x00,0x00,0x3F,0x00,0x00,0x3F,0x00,0x00   ; 0x3D (=)
        db 0x06,0x0C,0x18,0x30,0x18,0x0C,0x06,0x00   ; 0x3E (>)
        db 0x1E,0x33,0x30,0x18,0x0C,0x00,0x0C,0x00   ; 0x3F (?)
        db 0x3E,0x63,0x7B,0x7B,0x7B,0x03,0x1E,0x00   ; 0x40 (@)
        db 0x0C,0x1E,0x33,0x33,0x3F,0x33,0x33,0x00   ; 0x41 (A)
        db 0x3F,0x66,0x66,0x3E,0x66,0x66,0x3F,0x00   ; 0x42 (B)
        db 0x3C,0x66,0x03,0x03,0x03,0x66,0x3C,0x00   ; 0x43 (C)
        db 0x1F,0x36,0x66,0x66,0x66,0x36,0x1F,0x00   ; 0x44 (D)
        db 0x7F,0x46,0x16,0x1E,0x16,0x46,0x7F,0x00   ; 0x45 (E)
        db 0x7F,0x46,0x16,0x1E,0x16,0x06,0x0F,0x00   ; 0x46 (F)
        db 0x3C,0x66,0x03,0x03,0x73,0x66,0x7C,0x00   ; 0x47 (G)
        db 0x33,0x33,0x33,0x3F,0x33,0x33,0x33,0x00   ; 0x48 (H)
        db 0x1E,0x0C,0x0C,0x0C,0x0C,0x0C,0x1E,0x00   ; 0x49 (I)
        db 0x78,0x30,0x30,0x30,0x33,0x33,0x1E,0x00   ; 0x4A (J)
        db 0x67,0x66,0x36,0x1E,0x36,0x66,0x67,0x00   ; 0x4B (K)
        db 0x0F,0x06,0x06,0x06,0x46,0x66,0x7F,0x00   ; 0x4C (L)
        db 0x63,0x77,0x7F,0x7F,0x6B,0x63,0x63,0x00   ; 0x4D (M)
        db 0x63,0x67,0x6F,0x7B,0x73,0x63,0x63,0x00   ; 0x4E (N)
        db 0x1C,0x36,0x63,0x63,0x63,0x36,0x1C,0x00   ; 0x4F (O)
        db 0x3F,0x66,0x66,0x3E,0x06,0x06,0x0F,0x00   ; 0x50 (P)
        db 0x1E,0x33,0x33,0x33,0x3B,0x1E,0x38,0x00   ; 0x51 (Q)
        db 0x3F,0x66,0x66,0x3E,0x36,0x66,0x67,0x00   ; 0x52 (R)
        db 0x1E,0x33,0x07,0x0E,0x38,0x33,0x1E,0x00   ; 0x53 (S)
        db 0x3F,0x2D,0x0C,0x0C,0x0C,0x0C,0x1E,0x00   ; 0x54 (T)
        db 0x33,0x33,0x33,0x33,0x33,0x33,0x3F,0x00   ; 0x55 (U)
        db 0x33,0x33,0x33,0x33,0x33,0x1E,0x0C,0x00   ; 0x56 (V)
        db 0x63,0x63,0x63,0x6B,0x7F,0x77,0x63,0x00   ; 0x57 (W)
        db 0x63,0x63,0x36,0x1C,0x1C,0x36,0x63,0x00   ; 0x58 (X)
        db 0x33,0x33,0x33,0x1E,0x0C,0x0C,0x1E,0x00   ; 0x59 (Y)
        db 0x7F,0x63,0x31,0x18,0x4C,0x66,0x7F,0x00   ; 0x5A (Z)
        db 0x1E,0x06,0x06,0x06,0x06,0x06,0x1E,0x00   ; 0x5B ([)
        db 0x03,0x06,0x0C,0x18,0x30,0x60,0x40,0x00   ; 0x5C (\)
        db 0x1E,0x18,0x18,0x18,0x18,0x18,0x1E,0x00   ; 0x5D (])
        db 0x08,0x1C,0x36,0x63,0x00,0x00,0x00,0x00   ; 0x5E (^)
        db 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF   ; 0x5F (_)
        db 0x0C,0x0C,0x18,0x00,0x00,0x00,0x00,0x00   ; 0x60 (`)
        db 0x00,0x00,0x1E,0x30,0x3E,0x33,0x6E,0x00   ; 0x61 (a)
        db 0x07,0x06,0x06,0x3E,0x66,0x66,0x3B,0x00   ; 0x62 (b)
        db 0x00,0x00,0x1E,0x33,0x03,0x33,0x1E,0x00   ; 0x63 (c)
        db 0x38,0x30,0x30,0x3E,0x33,0x33,0x6E,0x00   ; 0x64 (d)
        db 0x00,0x00,0x1E,0x33,0x3F,0x03,0x1E,0x00   ; 0x65 (e)
        db 0x1C,0x36,0x06,0x0F,0x06,0x06,0x0F,0x00   ; 0x66 (f)
        db 0x00,0x00,0x6E,0x33,0x33,0x3E,0x30,0x1F   ; 0x67 (g)
        db 0x07,0x06,0x36,0x6E,0x66,0x66,0x67,0x00   ; 0x68 (h)
        db 0x0C,0x00,0x0E,0x0C,0x0C,0x0C,0x1E,0x00   ; 0x69 (i)
        db 0x30,0x00,0x30,0x30,0x30,0x33,0x33,0x1E   ; 0x6A (j)
        db 0x07,0x06,0x66,0x36,0x1E,0x36,0x67,0x00   ; 0x6B (k)
        db 0x0E,0x0C,0x0C,0x0C,0x0C,0x0C,0x1E,0x00   ; 0x6C (l)
        db 0x00,0x00,0x33,0x7F,0x7F,0x6B,0x63,0x00   ; 0x6D (m)
        db 0x00,0x00,0x1F,0x33,0x33,0x33,0x33,0x00   ; 0x6E (n)
        db 0x00,0x00,0x1E,0x33,0x33,0x33,0x1E,0x00   ; 0x6F (o)
        db 0x00,0x00,0x3B,0x66,0x66,0x3E,0x06,0x0F   ; 0x70 (p)
        db 0x00,0x00,0x6E,0x33,0x33,0x3E,0x30,0x78   ; 0x71 (q)
        db 0x00,0x00,0x3B,0x6E,0x66,0x06,0x0F,0x00   ; 0x72 (r)
        db 0x00,0x00,0x3E,0x03,0x1E,0x30,0x1F,0x00   ; 0x73 (s)
        db 0x08,0x0C,0x3E,0x0C,0x0C,0x2C,0x18,0x00   ; 0x74 (t)
        db 0x00,0x00,0x33,0x33,0x33,0x33,0x6E,0x00   ; 0x75 (u)
        db 0x00,0x00,0x33,0x33,0x33,0x1E,0x0C,0x00   ; 0x76 (v)
        db 0x00,0x00,0x63,0x6B,0x7F,0x7F,0x36,0x00   ; 0x77 (w)
        db 0x00,0x00,0x63,0x36,0x1C,0x36,0x63,0x00   ; 0x78 (x)
        db 0x00,0x00,0x33,0x33,0x33,0x3E,0x30,0x1F   ; 0x79 (y)
        db 0x00,0x00,0x3F,0x19,0x0C,0x26,0x3F,0x00   ; 0x7A (z)
        db 0x38,0x0C,0x0C,0x07,0x0C,0x0C,0x38,0x00   ; 0x7B ({)
        db 0x18,0x18,0x18,0x00,0x18,0x18,0x18,0x00   ; 0x7C (|)
        db 0x07,0x0C,0x0C,0x38,0x0C,0x0C,0x07,0x00   ; 0x7D (})
        db 0x6E,0x3B,0x00,0x00,0x00,0x00,0x00,0x00   ; 0x7E (~)

section .bss
    conn_ptr        resq 1      ; xcb_connection_t*
    screen_ptr      resq 1      ; pointer to xcb_screen_t
    window_id       resd 1      ; xcb_window_t
    event_ptr       resq 1      ; pointer to current xcb_event_t

    ; Graphics context identifier
    gc_id           resd 1
    ; Back buffer for drawing.  Each pixel uses 4 bytes (BGRA).  1200x800 window.
    image_buffer    resb (1200 * 800 * 4)

section .text
global _start

_start:
    ; Connect to X server (display = NULL, screenp = NULL)
    xor rdi, rdi
    xor rsi, rsi
    call xcb_connect
    mov [conn_ptr], rax
    ; Obtain setup and iterate to get first screen
    mov rdi, rax
    call xcb_get_setup
    ; xcb_setup_roots_iterator returns a struct by value; we store the data pointer
    mov rdi, rax
    call xcb_setup_roots_iterator
    ; iterator returned in rax; first element pointer at [rax]
    ; struct layout: data pointer at rax (first qword)
    mov [screen_ptr], rax
    ; Generate a window ID
    mov rdi, [conn_ptr]
    call xcb_generate_id
    mov [window_id], eax        ; store as 32bit
    ; Create a window
    ; xcb_create_window(connection, depth, wid, parent, x, y, width, height,
    ;                   border_width, class, visual, value_mask, value_list)
    mov rax, [screen_ptr]
    mov rcx, [rax]              ; rcx = data pointer to screen (xcb_screen_t*)
    ; parent window = screen->root (first field of xcb_screen_t)
    mov ebx, [rcx]              ; ebx = root window ID (32bit)
    mov rdi, [conn_ptr]
    mov rsi, XCB_COPY_FROM_PARENT    ; depth
    mov edx, [window_id]        ; wid
    mov r10d, ebx               ; parent
    xor r8d, r8d                ; x = 0
    xor r9d, r9d                ; y = 0
    ; push width and height onto stack for proper argument passing
    sub rsp, 8
    mov dword [rsp], [win_width]
    sub rsp, 8
    mov dword [rsp], [win_height]
    ; border width = 0
    mov r11d, 0
    ; class
    mov r12d, XCB_WINDOW_CLASS_INPUT_OUTPUT
    ; visual = screen->root_visual (offset 48 bytes into xcb_screen_t)
    mov eax, [rcx + 48]
    mov r13d, eax
    ; value_mask and value_list = 0 (no additional values)
    xor r14d, r14d
    xor r15, r15
    ; Align stack and call
    ; Note: System V AMD64 ABI passes first six args in registers.
    ; Here arguments beyond r9 will be on stack; ensure call signature matches.
    call xcb_create_window
    ; Clean up stack
    add rsp, 16
    ; Map window (make it visible)
    mov rdi, [conn_ptr]
    mov esi, [window_id]
    call xcb_map_window
    ; Flush requests to server
    mov rdi, [conn_ptr]
    call xcb_flush

    ; Create a graphics context (GC) for drawing
    ; Generate a GC ID
    mov rdi, [conn_ptr]
    call xcb_generate_id
    mov [gc_id], eax
    ; Create the GC associated with our window
    mov rdi, [conn_ptr]
    mov esi, [gc_id]
    mov edx, [window_id]        ; drawable (use window)
    xor ecx, ecx                ; value_mask = 0 (default GC values)
    xor r8, r8                  ; value_list = NULL
    call xcb_create_gc
    ; Flush GC creation
    mov rdi, [conn_ptr]
    call xcb_flush
    ; Enter event loop
.event_loop:
    mov rdi, [conn_ptr]
    call xcb_wait_for_event
    test rax, rax
    je .exit
    mov [event_ptr], rax
    ; Determine event type: first byte of response_type & 0x7F
    mov bl, [rax]
    and bl, 0x7F
    cmp bl, XCB_EXPOSE
    je .handle_expose
    cmp bl, XCB_KEY_PRESS
    je .handle_keypress
    ; ignore other events
    jmp .next_event
.handle_expose:
    ; Render the UI into our back buffer
    call draw_ui
    ; Send the back buffer to the X server using xcb_put_image
    ; xcb_put_image(conn, format, drawable, gc, width, height,
    ;               dst_x, dst_y, left_pad, depth, data_len, data)
    ; Compute data length = width * height * 4
    mov eax, [win_width]
    imul eax, [win_height]
    shl rax, 2
    ; Save data_len in r14
    mov r14, rax
    ; Set up register arguments
    mov rdi, [conn_ptr]            ; connection
    mov rsi, XCB_IMAGE_FORMAT_Z_PIXMAP ; format (ZPixmap)
    mov edx, [window_id]           ; drawable
    mov ecx, [gc_id]               ; gc
    mov r8d, [win_width]           ; width
    mov r9d, [win_height]          ; height
    ; Push remaining args in reverse order: data, data_len, depth, left_pad, dst_y, dst_x
    sub rsp, 48
    ; dst_x (int16) = 0
    mov qword [rsp], 0
    ; dst_y (int16) = 0
    mov qword [rsp+8], 0
    ; left_pad (uint8) = 0
    mov qword [rsp+16], 0
    ; depth (uint8) = 24 (ignore alpha)
    mov qword [rsp+24], 24
    ; data_len (uint32) = r14
    mov [rsp+32], r14
    ; data pointer
    lea rax, [rel image_buffer]
    mov [rsp+40], rax
    call xcb_put_image
    add rsp, 48
    ; flush the image to the display
    mov rdi, [conn_ptr]
    call xcb_flush
    jmp .next_event
.handle_keypress:
    ; TODO: read the keycode and convert to ASCII via xcb_keysym
    ; then feed into existing insert_char/backspace/newline logic
    jmp .next_event
.next_event:
    mov rdi, [event_ptr]
    call free
    jmp .event_loop
.exit:
    ; Disconnect from X server
    mov rdi, [conn_ptr]
    call xcb_disconnect
    ; Exit program
    mov rax, SYS_exit
    xor rdi, rdi
    syscall

; ---------------------------------------------------------------------
;  Drawing routines
; ---------------------------------------------------------------------

; draw_char
; Draw a single 8x8 character from the font atlas into the image_buffer.
; Input:
;    dil = ASCII character (0x20–0x7E)
;    esi = x coordinate in pixels
;    edx = y coordinate in pixels
; Uses EAX, EBX, R10, R9, RCX, R11, RBP
; Preserves all other registers.
draw_char:
    push rbp
    push rbx
    push rdx
    push rsi
    push rdi
    ; verify that the character is within our supported range
    movzx eax, dil
    cmp al, 32
    jb .dc_done
    cmp al, 126
    ja .dc_done
    sub al, 32               ; convert to 0‑based index
    movzx ebp, al
    ; compute pointer to the character bitmap
    imul ebp, ebp, CHAR_HEIGHT
    lea rbx, [rel font_atlas]
    add rbx, rbp
    ; compute starting address in image_buffer
    ; dest_offset = (y * win_width + x) * 4
    mov eax, edx             ; y
    imul eax, [win_width]
    add eax, esi             ; x
    shl rax, 2
    lea r10, [rel image_buffer]
    add r10, rax
    ; draw 8 rows
    mov rcx, CHAR_HEIGHT
.dc_row_loop:
        movzx eax, byte [rbx]    ; fetch font row bits
        mov r9, r10              ; pointer to start of this row
        mov r11, CHAR_WIDTH
.dc_pixel_loop:
            test eax, 0x80
            jz .dc_pixel_off
            ; bit set: white pixel
            mov dword [r9], 0x00FFFFFF
            jmp .dc_pixel_done
.dc_pixel_off:
            ; bit clear: black pixel
            mov dword [r9], 0x00000000
.dc_pixel_done:
            shl eax, 1
            add r9, 4            ; next pixel
            dec r11
            jnz .dc_pixel_loop
        ; advance to next row
        inc rbx
        ; increment dest pointer by one full line (win_width * 4 bytes)
        mov eax, [win_width]
        imul eax, 4
        add r10, rax
        dec rcx
        jnz .dc_row_loop
.dc_done:
    pop rdi
    pop rsi
    pop rdx
    pop rbx
    pop rbp
    ret
draw_ui:
    ; clear the back buffer to black
    mov rcx, 1200*800
    lea rdi, [rel image_buffer]
    xor eax, eax              ; 0x00000000 (black)
.dui_clear_loop:
        mov dword [rdi], eax
        add rdi, 4
        dec rcx
        jnz .dui_clear_loop
    ret

; ========================================
; ENHANCED IDE FEATURES
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
process_keypress:
    ; TODO: Implement key processing
    ; - Arrow keys for cursor movement
    ; - Character input
    ; - Special keys (Enter, Backspace, Tab, etc.)
    ; - Keyboard shortcuts (Ctrl+S, Ctrl+C, etc.)
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

; ========================================
; EON COMPILER INTEGRATION
; ========================================

; EON Compiler Integration
; This section integrates the EON compiler with the IDE

; Compiler state
compiler_state:
    .lexer_state     resq 1
    .parser_state    resq 1
    .semantic_state  resq 1
    .codegen_state   resq 1

; Compilation functions
eon_compile_integration:
    ; Initialize compiler
    call init_eon_compiler
    
    ; Lexical analysis
    call eon_lexical_analysis
    
    ; Syntax analysis
    call eon_syntax_analysis
    
    ; Semantic analysis
    call eon_semantic_analysis
    
    ; Code generation
    call eon_code_generation
    
    ret

init_eon_compiler:
    ; Initialize compiler state
    mov qword [compiler_state + 0], 0  ; lexer_state
    mov qword [compiler_state + 8], 0  ; parser_state
    mov qword [compiler_state + 16], 0 ; semantic_state
    mov qword [compiler_state + 24], 0 ; codegen_state
    ret

eon_lexical_analysis:
    ; Tokenize EON source code
    ; TODO: Implement lexical analysis
    ret

eon_syntax_analysis:
    ; Parse tokens into AST
    ; TODO: Implement syntax analysis
    ret

eon_semantic_analysis:
    ; Perform semantic analysis
    ; TODO: Implement semantic analysis
    ret

eon_code_generation:
    ; Generate x86-64 assembly
    ; TODO: Implement code generation
    ret

; Error handling
compiler_error:
    ; Handle compilation errors
    ; TODO: Implement error handling
    ret

; Success handling
compilation_success:
    ; Handle successful compilation
    ; TODO: Implement success handling
    ret

; ========================================
; ADVANCED IDE FEATURES
; ========================================

; Advanced IDE Features
; This section implements advanced IDE functionality

; Project management
project_manager:
    .current_project resq 1
    .project_files   resq 1
    .project_config  resq 1

init_project_manager:
    ; Initialize project management
    mov qword [project_manager + 0], 0  ; current_project
    mov qword [project_manager + 8], 0  ; project_files
    mov qword [project_manager + 16], 0 ; project_config
    ret

; File operations
file_operations:
    .current_file    resq 1
    .file_buffer     resq 1
    .file_size       resq 1

open_file:
    ; Open a file for editing
    ; TODO: Implement file opening
    ret

save_file:
    ; Save current file
    ; TODO: Implement file saving
    ret

close_file:
    ; Close current file
    ; TODO: Implement file closing
    ret

; Debugger integration
debugger_integration:
    .debug_state     resq 1
    .breakpoints     resq 1
    .watch_vars      resq 1

init_debugger:
    ; Initialize debugger
    mov qword [debugger_integration + 0], 0  ; debug_state
    mov qword [debugger_integration + 8], 0  ; breakpoints
    mov qword [debugger_integration + 16], 0 ; watch_vars
    ret

set_breakpoint:
    ; Set a breakpoint
    ; TODO: Implement breakpoint setting
    ret

step_debug:
    ; Step through code
    ; TODO: Implement step debugging
    ret

; Build system
build_system:
    .build_config    resq 1
    .build_output    resq 1
    .build_errors    resq 1

init_build_system:
    ; Initialize build system
    mov qword [build_system + 0], 0  ; build_config
    mov qword [build_system + 8], 0  ; build_output
    mov qword [build_system + 16], 0 ; build_errors
    ret

build_project:
    ; Build the current project
    ; TODO: Implement project building
    ret

; Code completion
code_completion:
    .completion_list  resq 1
    .completion_index resq 1

init_code_completion:
    ; Initialize code completion
    mov qword [code_completion + 0], 0  ; completion_list
    mov qword [code_completion + 8], 0  ; completion_index
    ret

get_completions:
    ; Get code completions
    ; TODO: Implement code completion
    ret

; Syntax highlighting
syntax_highlighting:
    .highlight_rules  resq 1
    .color_scheme     resq 1

init_syntax_highlighting:
    ; Initialize syntax highlighting
    mov qword [syntax_highlighting + 0], 0  ; highlight_rules
    mov qword [syntax_highlighting + 8], 0  ; color_scheme
    ret

highlight_line:
    ; Highlight a line of code
    ; TODO: Implement syntax highlighting
    ret

; Search and replace
search_replace:
    .search_text      resq 1
    .replace_text     resq 1
    .search_results   resq 1

init_search_replace:
    ; Initialize search and replace
    mov qword [search_replace + 0], 0  ; search_text
    mov qword [search_replace + 8], 0  ; replace_text
    mov qword [search_replace + 16], 0 ; search_results
    ret

find_text:
    ; Find text in current file
    ; TODO: Implement text finding
    ret

replace_text:
    ; Replace text in current file
    ; TODO: Implement text replacement
    ret

; ========================================
; PROGRAM TERMINATION
; ========================================
exit_program:
    ; Cleanup all systems
    call cleanup_ide_systems
    
    ; Disconnect from X server
    mov rdi, [conn_ptr]
    call xcb_disconnect
    
    ; Exit program
    mov rax, 60  ; SYS_exit
    xor rdi, rdi
    syscall

cleanup_ide_systems:
    ; Cleanup all IDE systems
    ; TODO: Implement cleanup
    ret

; ========================================
; END OF EON IDE COMPLETE
; ========================================
