; setjmp and longjmp for the MSVC x64 build. The CRT longjmp cannot leave translated code, which has no
; unwind data. Under CFG it refuses a jump buffer without a frame, and with a frame or a user shadow stack
; it unwinds.
;
; Buffer layout, inside the 256 bytes of jmp_buf:
;   00h SSP  08h RBX  10h RSP  18h RBP  20h RSI  28h RDI  30h R12  38h R13  40h R14  48h R15
;   50h RIP  58h MXCSR  5Ch x87 control word  60h XMM6 to XMM15

FAST_FAIL_INVALID_JUMP_BUFFER EQU 18

PUBLIC brov_setjmp
PUBLIC brov_longjmp

_TEXT SEGMENT

brov_setjmp PROC
    mov     rdx, [rsp]
    lea     r8, [rsp + 8]
    mov     [rcx + 08h], rbx
    mov     [rcx + 10h], r8
    mov     [rcx + 18h], rbp
    mov     [rcx + 20h], rsi
    mov     [rcx + 28h], rdi
    mov     [rcx + 30h], r12
    mov     [rcx + 38h], r13
    mov     [rcx + 40h], r14
    mov     [rcx + 48h], r15
    mov     [rcx + 50h], rdx
    stmxcsr dword ptr [rcx + 58h]
    fnstcw  word ptr [rcx + 5Ch]
    movdqu  xmmword ptr [rcx + 60h], xmm6
    movdqu  xmmword ptr [rcx + 70h], xmm7
    movdqu  xmmword ptr [rcx + 80h], xmm8
    movdqu  xmmword ptr [rcx + 90h], xmm9
    movdqu  xmmword ptr [rcx + 0A0h], xmm10
    movdqu  xmmword ptr [rcx + 0B0h], xmm11
    movdqu  xmmword ptr [rcx + 0C0h], xmm12
    movdqu  xmmword ptr [rcx + 0D0h], xmm13
    movdqu  xmmword ptr [rcx + 0E0h], xmm14
    movdqu  xmmword ptr [rcx + 0F0h], xmm15
    ; RDSSPQ is a NOP without a shadow stack, so 0 means none.
    xor     eax, eax
    rdsspq  rax
    mov     [rcx], rax
    xor     eax, eax
    ret
brov_setjmp ENDP

brov_longjmp PROC
    ; The target frame is an ancestor of this one, on this thread's stack.
    mov     r10, [rcx + 10h]
    cmp     r10, rsp
    jbe     invalid
    cmp     r10, qword ptr gs:[08h]
    ja      invalid

    mov     r8, [rcx]
    test    r8, r8
    jz      restore
    xor     r9d, r9d
    rdsspq  r9
    test    r9, r9
    jz      restore
    ; The saved SSP still holds the return address of brov_setjmp.
    add     r8, 8
    sub     r8, r9
    jb      invalid
    shr     r8, 3
    jz      restore
pop_entries:
    mov     r9d, 255
    cmp     r8, r9
    cmovb   r9, r8
    incsspq r9
    sub     r8, r9
    jnz     pop_entries

restore:
    mov     eax, edx
    test    eax, eax
    jnz     value_set
    inc     eax
value_set:
    mov     rbx, [rcx + 08h]
    mov     rsi, [rcx + 20h]
    mov     rdi, [rcx + 28h]
    mov     r12, [rcx + 30h]
    mov     r13, [rcx + 38h]
    mov     r14, [rcx + 40h]
    mov     r15, [rcx + 48h]
    ldmxcsr dword ptr [rcx + 58h]
    fnclex
    fldcw   word ptr [rcx + 5Ch]
    movdqu  xmm6, xmmword ptr [rcx + 60h]
    movdqu  xmm7, xmmword ptr [rcx + 70h]
    movdqu  xmm8, xmmword ptr [rcx + 80h]
    movdqu  xmm9, xmmword ptr [rcx + 90h]
    movdqu  xmm10, xmmword ptr [rcx + 0A0h]
    movdqu  xmm11, xmmword ptr [rcx + 0B0h]
    movdqu  xmm12, xmmword ptr [rcx + 0C0h]
    movdqu  xmm13, xmmword ptr [rcx + 0D0h]
    movdqu  xmm14, xmmword ptr [rcx + 0E0h]
    movdqu  xmm15, xmmword ptr [rcx + 0F0h]
    mov     rdx, [rcx + 50h]
    mov     rbp, [rcx + 18h]
    mov     rsp, r10
    jmp     rdx

invalid:
    mov     ecx, FAST_FAIL_INVALID_JUMP_BUFFER
    int     29h
brov_longjmp ENDP

_TEXT ENDS

END
