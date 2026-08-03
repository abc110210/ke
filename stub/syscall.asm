; ============================================================================
; syscall.asm — 原生系统调用桩（x64 MASM）
; 目的：完全绕过 ntdll 的 Win32 / 用户态包装，直接执行 syscall 指令，
;       躲避 ScyllaHide / x64dbg 等工具在 ntdll 导出函数首部下的钩子。
;
; 调用约定（微软 x64）：
;   NtRawSyscall(ssn, a1, a2, a3, a4, a5, a6)
;   rcx=ssn  rdx=a1  r8=a2  r9=a3  [rsp+0x28]=a4  [rsp+0x30]=a5  [rsp+0x38]=a6
;
; syscall 指令会破坏 rcx（CPU 把返回地址写入 rcx），因此内核约定第一个参数
; 放在 r10。这里把 a1 搬进 r10，rdx/r8 不动，a4 搬进 r9，并把栈上 a5/a6
; 下移一格，使内核能按 (r10,rdx,r8,r9,[rsp+0x28],[rsp+0x30]) 读到全部参数。
; ============================================================================
.code

NtRawSyscall PROC
    mov     rax, rcx            ; rax = 系统调用号 (ssn)
    mov     r10, rdx            ; r10 = a1（syscall 会破坏 rcx，故用 r10 传第一个参数）
    mov     r9,  [rsp + 028h]   ; r9  = a4
    mov     r11, [rsp + 030h]
    mov     [rsp + 028h], r11   ; [rsp+0x28] = a5
    mov     r11, [rsp + 038h]
    mov     [rsp + 030h], r11   ; [rsp+0x30] = a6
    syscall
    ret
NtRawSyscall ENDP

end
