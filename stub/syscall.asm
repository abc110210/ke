; ============================================================================
; syscall.asm — 原生系统调用桩（x64 MASM）
; 目的：完全绕过 ntdll 的 Win32 / 用户态包装，直接执行 syscall 指令，
;       躲避 ScyllaHide / x64dbg 等工具在 ntdll 导出函数首部下的钩子。
;
; 调用约定（微软 x64）：
;   NtRawSyscall(ssn, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11)
;   参数位置（函数入口，返回地址在 [rsp]）：
;       rcx=ssn  rdx=a1  r8=a2  r9=a3
;       [rsp+0x28]=a4  [rsp+0x30]=a5  [rsp+0x38]=a6  [rsp+0x40]=a7
;       [rsp+0x48]=a8  [rsp+0x50]=a9  [rsp+0x58]=a10 [rsp+0x60]=a11
;
; syscall 指令会破坏 rcx（CPU 把返回地址写入 rcx），因此内核约定第一个参数
; 放在 r10。本桩做如下映射（aK 一一对应 syscall 第 K 个参数）：
;       r10 = a1         （arg1）
;       rdx = a2         （arg2：原在 r8，需搬过来）
;       r8  = a3         （arg3：原在 r9，需搬过来）
;       r9  = a4         （arg4：来自 [rsp+0x28]）
;       栈上 a5..a11 整体下移一格（0x08），对齐内核读取位置：
;           [rsp+0x28]=a5  [rsp+0x30]=a6  [rsp+0x38]=a7 ... [rsp+0x58]=a11
; ============================================================================
.code

NtRawSyscall PROC
    mov     rax, rcx            ; rax = 系统调用号 (ssn)
    mov     r10, rdx            ; r10 = a1（syscall 会破坏 rcx，故第一个参数走 r10）
    mov     rdx, r8             ; rdx = a2（syscall 第 2 个参数）
    mov     r8,  r9             ; r8  = a3（syscall 第 3 个参数）
    mov     r9,  [rsp + 028h]   ; r9  = a4（syscall 第 4 个参数）
    ; 把栈上 a5..a11 整体下移一格（0x08），对齐到内核读取的第 5..11 个参数位置。
    ; 内核在 syscall 时按 [rsp+0x28] 起读取第 5 个参数（[rsp+0x08..0x20] 是 4 个
    ; 寄存器参数的 shadow 区，不计入栈参数），故 a5 必须落到 [rsp+0x28]。
    mov     r11, [rsp + 030h]
    mov     [rsp + 028h], r11   ; [rsp+0x28] = a5
    mov     r11, [rsp + 038h]
    mov     [rsp + 030h], r11   ; [rsp+0x30] = a6
    mov     r11, [rsp + 040h]
    mov     [rsp + 038h], r11   ; [rsp+0x38] = a7
    mov     r11, [rsp + 048h]
    mov     [rsp + 040h], r11   ; [rsp+0x40] = a8
    mov     r11, [rsp + 050h]
    mov     [rsp + 048h], r11   ; [rsp+0x48] = a9
    mov     r11, [rsp + 058h]
    mov     [rsp + 050h], r11   ; [rsp+0x50] = a10
    mov     r11, [rsp + 060h]
    mov     [rsp + 058h], r11   ; [rsp+0x58] = a11
    syscall
    ret
NtRawSyscall ENDP

end
