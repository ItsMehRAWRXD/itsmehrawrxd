; object_file_gen.asm
; Object file generation support for ELF, PE, and Mach-O formats
; Supports cross-platform object file creation for linking

%include "reverser_platform.asm"

section .data
    ; Object file format constants
    FORMAT_ELF    equ 0
    FORMAT_PE     equ 1
    FORMAT_MACHO  equ 2
    
    ; ELF constants
    ELF_MAGIC     dd 0x464C457F  ; 0x7F, 'E', 'L', 'F'
    ELF_CLASS64   equ 2
    ELF_DATA2LSB  equ 1
    ELF_VERSION   equ 1
    ELF_OSABI     equ 0
    ELF_TYPE_REL  equ 1
    ELF_MACHINE_X86_64 equ 62
    ELF_MACHINE_AARCH64 equ 183
    
    ; PE constants
    PE_MAGIC      dw 0x5A4D      ; 'MZ'
    PE_SIGNATURE  dd 0x00004550  ; 'PE\0\0'
    PE_MACHINE_AMD64 equ 0x8664
    PE_MACHINE_ARM64 equ 0xAA64
    
    ; Mach-O constants
    MACHO_MAGIC_64     dd 0xFEEDFACF
    MACHO_CPU_X86_64   equ 0x01000007
    MACHO_CPU_ARM64    equ 0x0100000C
    MACHO_FILETYPE_OBJ equ 1
    
    ; Section types
    SECTION_TEXT   equ 0
    SECTION_DATA   equ 1
    SECTION_BSS    equ 2
    SECTION_RODATA equ 3
    
    ; Symbol types
    SYMBOL_FUNCTION equ 0
    SYMBOL_OBJECT   equ 1
    SYMBOL_SECTION  equ 2

section .bss
    ; Object file buffer
    object_buffer     resb 1048576  ; 1MB buffer
    object_size       resq 1        ; Current size
    object_capacity   resq 1        ; Buffer capacity
    
    ; Section information
    sections          resb 4096     ; Section table
    section_count     resq 1        ; Number of sections
    
    ; Symbol information
    symbols           resb 8192     ; Symbol table
    symbol_count      resq 1        ; Number of symbols
    
    ; String table
    string_table      resb 4096     ; String table
    string_table_size resq 1        ; String table size
    
    ; Relocation information
    relocations       resb 4096     ; Relocation table
    relocation_count  resq 1        ; Number of relocations
    
    ; Current format
    current_format    resq 1        ; Current object format

section .text
    global objgen_init
    global objgen_set_format
    global objgen_add_section
    global objgen_add_symbol
    global objgen_add_relocation
    global objgen_write_code
    global objgen_write_data
    global objgen_generate_object
    global objgen_save_to_file

; Initialize object file generator
objgen_init:
    push rbx
    push rcx
    
    ; Clear buffer
    mov rcx, 1048576
    mov rdi, object_buffer
    xor rax, rax
    rep stosb
    
    ; Initialize counters
    mov qword [object_size], 0
    mov qword [object_capacity], 1048576
    mov qword [section_count], 0
    mov qword [symbol_count], 0
    mov qword [string_table_size], 1  ; Start at 1 (null string)
    mov qword [relocation_count], 0
    
    ; Clear string table first byte
    mov byte [string_table], 0
    
    ; Detect platform and set default format
    call platform_get_os
    cmp rax, PLATFORM_WINDOWS
    je .set_pe
    cmp rax, PLATFORM_MACOS
    je .set_macho
    
    ; Default to ELF
    mov qword [current_format], FORMAT_ELF
    jmp .return

.set_pe:
    mov qword [current_format], FORMAT_PE
    jmp .return

.set_macho:
    mov qword [current_format], FORMAT_MACHO

.return:
    pop rcx
    pop rbx
    ret

; Set object file format
; Input: rdi = format (FORMAT_ELF, FORMAT_PE, FORMAT_MACHO)
objgen_set_format:
    mov [current_format], rdi
    ret

; Add a section to the object file
; Input: rdi = section name, rsi = section type, rdx = size, rcx = alignment
objgen_add_section:
    push rbx
    push r8
    push r9
    
    ; Get section entry
    mov rbx, [section_count]
    imul rbx, 64  ; Each section entry is 64 bytes
    add rbx, sections
    
    ; Store section name string
    mov r8, rdi
    call add_string_to_table
    mov [rbx], rax  ; Store string table offset
    
    ; Store section properties
    mov [rbx + 8], rsi   ; Section type
    mov [rbx + 16], rdx  ; Size
    mov [rbx + 24], rcx  ; Alignment
    mov qword [rbx + 32], 0  ; Offset (to be calculated)
    mov qword [rbx + 40], 0  ; File offset (to be calculated)
    mov qword [rbx + 48], 0  ; Flags
    mov qword [rbx + 56], 0  ; Link/Info
    
    ; Increment section count
    inc qword [section_count]
    
    mov rax, [section_count]
    dec rax  ; Return section index
    
    pop r9
    pop r8
    pop rbx
    ret

; Add a symbol to the object file
; Input: rdi = symbol name, rsi = symbol type, rdx = section index, rcx = value
objgen_add_symbol:
    push rbx
    push r8
    
    ; Get symbol entry
    mov rbx, [symbol_count]
    imul rbx, 32  ; Each symbol entry is 32 bytes
    add rbx, symbols
    
    ; Store symbol name string
    mov r8, rdi
    call add_string_to_table
    mov [rbx], rax  ; Store string table offset
    
    ; Store symbol properties
    mov [rbx + 8], rsi   ; Symbol type
    mov [rbx + 16], rdx  ; Section index
    mov [rbx + 24], rcx  ; Value/Address
    
    ; Increment symbol count
    inc qword [symbol_count]
    
    mov rax, [symbol_count]
    dec rax  ; Return symbol index
    
    pop r8
    pop rbx
    ret

; Add a relocation entry
; Input: rdi = offset, rsi = symbol index, rdx = type, rcx = addend
objgen_add_relocation:
    push rbx
    
    ; Get relocation entry
    mov rbx, [relocation_count]
    imul rbx, 32  ; Each relocation entry is 32 bytes
    add rbx, relocations
    
    ; Store relocation properties
    mov [rbx], rdi       ; Offset
    mov [rbx + 8], rsi   ; Symbol index
    mov [rbx + 16], rdx  ; Relocation type
    mov [rbx + 24], rcx  ; Addend
    
    ; Increment relocation count
    inc qword [relocation_count]
    
    mov rax, [relocation_count]
    dec rax  ; Return relocation index
    
    pop rbx
    ret

; Write code to object buffer
; Input: rdi = code data, rsi = size, rdx = section index
objgen_write_code:
    push rbx
    push rcx
    push r8
    
    ; Get section info
    mov rbx, rdx
    imul rbx, 64
    add rbx, sections
    
    ; Get current position in buffer
    mov rcx, [object_size]
    
    ; Store section file offset
    mov [rbx + 40], rcx
    
    ; Copy code data to buffer
    mov r8, rsi  ; Save size
    mov rsi, rdi ; Source
    mov rdi, object_buffer
    add rdi, rcx ; Destination
    mov rcx, r8  ; Size
    rep movsb
    
    ; Update object size
    add [object_size], r8
    
    pop r8
    pop rcx
    pop rbx
    ret

; Write data to object buffer
; Input: rdi = data, rsi = size, rdx = section index
objgen_write_data:
    ; Same implementation as write_code for now
    call objgen_write_code
    ret

; Generate complete object file
objgen_generate_object:
    push rbx
    push rcx
    push rdx
    
    ; Generate based on current format
    mov rax, [current_format]
    cmp rax, FORMAT_ELF
    je .generate_elf
    cmp rax, FORMAT_PE
    je .generate_pe
    cmp rax, FORMAT_MACHO
    je .generate_macho
    
    jmp .return

.generate_elf:
    call generate_elf_object
    jmp .return

.generate_pe:
    call generate_pe_object
    jmp .return

.generate_macho:
    call generate_macho_object

.return:
    pop rdx
    pop rcx
    pop rbx
    ret

; Generate ELF object file
generate_elf_object:
    push rbx
    push rcx
    push rdx
    
    ; Reset buffer position
    mov qword [object_size], 0
    
    ; Write ELF header
    call write_elf_header
    
    ; Write section headers
    call write_elf_section_headers
    
    ; Write symbol table
    call write_elf_symbol_table
    
    ; Write string table
    call write_elf_string_table
    
    ; Write relocations
    call write_elf_relocations
    
    pop rdx
    pop rcx
    pop rbx
    ret

; Write ELF header
write_elf_header:
    push rbx
    push rcx
    
    mov rdi, object_buffer
    mov rsi, [object_size]
    add rdi, rsi
    
    ; ELF identification
    mov eax, [ELF_MAGIC]
    stosd
    mov al, ELF_CLASS64
    stosb
    mov al, ELF_DATA2LSB
    stosb
    mov al, ELF_VERSION
    stosb
    mov al, ELF_OSABI
    stosb
    xor rax, rax
    stosq  ; Padding
    
    ; ELF header fields
    mov ax, ELF_TYPE_REL
    stosw
    
    ; Machine type
    call platform_get_arch
    cmp rax, ARCH_X86_64
    je .x86_64
    cmp rax, ARCH_ARM64
    je .arm64
    
.x86_64:
    mov ax, ELF_MACHINE_X86_64
    jmp .write_machine
    
.arm64:
    mov ax, ELF_MACHINE_AARCH64

.write_machine:
    stosw
    
    ; Version, entry, program header offset
    mov eax, ELF_VERSION
    stosd
    xor rax, rax
    stosq  ; Entry point
    stosq  ; Program header offset
    
    ; Section header offset (to be filled later)
    mov rax, 64  ; After ELF header
    stosq
    
    ; Flags, header size, program header size/count
    xor eax, eax
    stosd  ; Flags
    mov ax, 64
    stosw  ; ELF header size
    xor ax, ax
    stosw  ; Program header entry size
    stosw  ; Program header count
    
    ; Section header size/count
    mov ax, 64
    stosw  ; Section header entry size
    mov rax, [section_count]
    add rax, 3  ; +3 for null, symtab, strtab
    stosw
    
    ; String table index
    mov rax, [section_count]
    add rax, 2  ; String table is last
    stosw
    
    ; Update object size
    add qword [object_size], 64
    
    pop rcx
    pop rbx
    ret

; Write ELF section headers
write_elf_section_headers:
    push rbx
    push rcx
    push rdx
    
    ; Write null section header first
    mov rdi, object_buffer
    add rdi, [object_size]
    mov rcx, 64
    xor rax, rax
    rep stosb
    add qword [object_size], 64
    
    ; Write user sections
    mov rbx, 0
.section_loop:
    cmp rbx, [section_count]
    jge .write_symtab
    
    call write_elf_section_header
    inc rbx
    jmp .section_loop

.write_symtab:
    ; Write symbol table section header
    call write_elf_symtab_header
    
    ; Write string table section header
    call write_elf_strtab_header
    
    pop rdx
    pop rcx
    pop rbx
    ret

; Write ELF section header for section rbx
write_elf_section_header:
    push rdi
    push rsi
    push rcx
    
    ; Get section info
    mov rsi, rbx
    imul rsi, 64
    add rsi, sections
    
    ; Get buffer position
    mov rdi, object_buffer
    add rdi, [object_size]
    
    ; Write section header
    mov rax, [rsi]      ; Name offset
    stosd
    mov eax, 1          ; SHT_PROGBITS
    stosd
    mov rax, 6          ; SHF_ALLOC | SHF_EXECINSTR
    stosq
    xor rax, rax
    stosq               ; Address
    mov rax, [rsi + 40] ; File offset
    stosq
    mov rax, [rsi + 16] ; Size
    stosq
    xor rax, rax
    stosd               ; Link
    stosd               ; Info
    mov rax, [rsi + 24] ; Alignment
    stosq
    xor rax, rax
    stosq               ; Entry size
    
    add qword [object_size], 64
    
    pop rcx
    pop rsi
    pop rdi
    ret

; Write ELF symbol table
write_elf_symbol_table:
    push rbx
    push rcx
    push rdx
    
    ; Write null symbol first
    mov rdi, object_buffer
    add rdi, [object_size]
    mov rcx, 24
    xor rax, rax
    rep stosb
    add qword [object_size], 24
    
    ; Write user symbols
    mov rbx, 0
.symbol_loop:
    cmp rbx, [symbol_count]
    jge .done
    
    call write_elf_symbol
    inc rbx
    jmp .symbol_loop

.done:
    pop rdx
    pop rcx
    pop rbx
    ret

; Write ELF symbol for symbol rbx
write_elf_symbol:
    push rdi
    push rsi
    
    ; Get symbol info
    mov rsi, rbx
    imul rsi, 32
    add rsi, symbols
    
    ; Get buffer position
    mov rdi, object_buffer
    add rdi, [object_size]
    
    ; Write symbol
    mov rax, [rsi]      ; Name offset
    stosd
    mov al, 0x12        ; STB_GLOBAL | STT_FUNC
    stosb
    xor al, al
    stosb               ; Other
    mov ax, [rsi + 16]  ; Section index
    stosw
    mov rax, [rsi + 24] ; Value
    stosq
    mov rax, 0          ; Size (unknown)
    stosq
    
    add qword [object_size], 24
    
    pop rsi
    pop rdi
    ret

; Generate PE object file (simplified)
generate_pe_object:
    push rbx
    push rcx
    
    ; Write PE header
    call write_pe_header
    
    ; Write sections
    call write_pe_sections
    
    pop rcx
    pop rbx
    ret

; Write PE header (simplified)
write_pe_header:
    push rdi
    push rax
    
    mov rdi, object_buffer
    
    ; DOS header stub
    mov ax, [PE_MAGIC]
    stosw
    
    ; Skip to PE signature location (simplified)
    add rdi, 58
    mov eax, [PE_SIGNATURE]
    stosd
    
    ; COFF header
    call platform_get_arch
    cmp rax, ARCH_X86_64
    je .pe_x64
    
    mov ax, PE_MACHINE_ARM64
    jmp .write_pe_machine

.pe_x64:
    mov ax, PE_MACHINE_AMD64

.write_pe_machine:
    stosw
    
    mov rax, [section_count]
    stosw               ; Number of sections
    
    ; Timestamp, symbol table, etc.
    xor rax, rax
    stosd               ; Timestamp
    stosq               ; Symbol table offset
    mov rax, [symbol_count]
    stosd               ; Number of symbols
    
    add qword [object_size], 84  ; Approximate header size
    
    pop rax
    pop rdi
    ret

; Write PE sections (simplified)
write_pe_sections:
    ; Simplified implementation
    ret

; Generate Mach-O object file (simplified)
generate_macho_object:
    push rbx
    push rcx
    
    ; Write Mach-O header
    call write_macho_header
    
    ; Write load commands
    call write_macho_load_commands
    
    pop rcx
    pop rbx
    ret

; Write Mach-O header (simplified)
write_macho_header:
    push rdi
    push rax
    
    mov rdi, object_buffer
    
    ; Mach-O header
    mov eax, [MACHO_MAGIC_64]
    stosd
    
    call platform_get_arch
    cmp rax, ARCH_X86_64
    je .macho_x64
    
    mov eax, MACHO_CPU_ARM64
    jmp .write_macho_cpu

.macho_x64:
    mov eax, MACHO_CPU_X86_64

.write_macho_cpu:
    stosd               ; CPU type
    xor eax, eax
    stosd               ; CPU subtype
    mov eax, MACHO_FILETYPE_OBJ
    stosd               ; File type
    
    add qword [object_size], 20  ; Approximate header size
    
    pop rax
    pop rdi
    ret

; Write Mach-O load commands (simplified)
write_macho_load_commands:
    ; Simplified implementation
    ret

; Save object file to disk
; Input: rdi = filename
objgen_save_to_file:
    push rbx
    push rcx
    push rdx
    
    ; Open file for writing
    mov rax, 2          ; sys_open
    mov rsi, 0x241      ; O_WRONLY | O_CREAT | O_TRUNC
    mov rdx, 0644       ; File permissions
    syscall
    
    cmp rax, 0
    jl .save_failed
    
    mov rbx, rax        ; Save file descriptor
    
    ; Write object buffer to file
    mov rax, 1          ; sys_write
    mov rdi, rbx
    mov rsi, object_buffer
    mov rdx, [object_size]
    syscall
    
    ; Close file
    mov rax, 3          ; sys_close
    mov rdi, rbx
    syscall
    
    mov rax, 1          ; Success
    jmp .return

.save_failed:
    mov rax, 0          ; Failure

.return:
    pop rdx
    pop rcx
    pop rbx
    ret

; Add string to string table
; Input: rdi = string
; Output: rax = offset in string table
add_string_to_table:
    push rbx
    push rcx
    push rdx
    push rsi
    
    ; Get current string table position
    mov rax, [string_table_size]
    mov rbx, rax        ; Save offset to return
    
    ; Copy string to table
    mov rsi, rdi
    mov rdi, string_table
    add rdi, rax
    
    ; Calculate string length and copy
    mov rcx, 0
.copy_loop:
    mov al, [rsi + rcx]
    mov [rdi + rcx], al
    inc rcx
    cmp al, 0
    jne .copy_loop
    
    ; Update string table size
    add [string_table_size], rcx
    
    mov rax, rbx        ; Return offset
    
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    ret

; Write ELF symbol table header
write_elf_symtab_header:
    push rdi
    push rax
    
    mov rdi, object_buffer
    add rdi, [object_size]
    
    ; Symbol table section header
    mov rax, 0          ; Name (empty for now)
    stosd
    mov eax, 2          ; SHT_SYMTAB
    stosd
    xor rax, rax
    stosq               ; Flags
    stosq               ; Address
    mov rax, [object_size]
    add rax, 64         ; After this header
    stosq               ; Offset
    mov rax, [symbol_count]
    inc rax             ; +1 for null symbol
    imul rax, 24        ; Symbol size
    stosq               ; Size
    mov rax, [section_count]
    add rax, 2          ; String table section
    stosd               ; Link
    mov rax, 1          ; First global symbol
    stosd               ; Info
    mov rax, 8
    stosq               ; Alignment
    mov rax, 24
    stosq               ; Entry size
    
    add qword [object_size], 64
    
    pop rax
    pop rdi
    ret

; Write ELF string table header
write_elf_strtab_header:
    push rdi
    push rax
    
    mov rdi, object_buffer
    add rdi, [object_size]
    
    ; String table section header
    mov rax, 0          ; Name (empty for now)
    stosd
    mov eax, 3          ; SHT_STRTAB
    stosd
    xor rax, rax
    stosq               ; Flags
    stosq               ; Address
    mov rax, [object_size]
    add rax, 64         ; After this header
    mov rbx, [symbol_count]
    inc rbx
    imul rbx, 24
    add rax, rbx        ; After symbol table
    stosq               ; Offset
    mov rax, [string_table_size]
    stosq               ; Size
    xor rax, rax
    stosd               ; Link
    stosd               ; Info
    mov rax, 1
    stosq               ; Alignment
    xor rax, rax
    stosq               ; Entry size
    
    add qword [object_size], 64
    
    pop rax
    pop rdi
    ret

; Write ELF relocations
write_elf_relocations:
    ; TODO: Implement relocation writing
    ret
