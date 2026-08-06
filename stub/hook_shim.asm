; ============================================================================
; hook_shim.asm — 注入拦截 inline hook 的汇编 shim（P3.4 修复版，CI 83）
;
; 为什么必须用汇编：
;   inline hook 跳转到 shim 时，调用者栈【原样保留】——系统调用第 5 个及以后
;   的参数位于调用者栈上（[rsp+0x28..]），内核在 syscall 时按 rsp+偏移读取。
;   若用 C 函数 call trampoline，会重排栈 → 内核读到错误参数（栈参数错位）。
;   shim 用【尾跳转】（jmp trampoline）保证进入 trampoline 时 rsp 与调用者
;   完全一致，栈参数原封不动。
;
; 旧实现 Bug（CI 82 实锤）：C handler 第一参数从 RCX 读当作 SSN，但 hook 跳转
;   后 RCX 是真实 API 参数（如 NtCreateThreadEx 的 ThreadHandle*），SSN 匹配
;   永远失败 → 兜底返回 STATUS_NOT_IMPLEMENTED → 业务所有线程创建/延迟加载
;   DLL 失败 → 抛 std::system_error(EAGAIN 11) → 0xE06D7363。
;
; 每个被 hook 的函数跳转到对应 shim，入口寄存器 = 该函数前 4 个参数：
;   InjectShim0 : NtMapViewOfSection  (ProcessHandle = RDX 第 2 参数)
;   InjectShim1 : NtCreateThreadEx    (ProcessHandle = R9  第 4 参数)
;   InjectShim2 : NtOpenProcess       (ClientId*     = R9  第 4 参数)
; shim 流程：
;   1. sub rsp,48h 保存 4 个寄存器参数（[rsp+20h..38h]；0x48=保存32B+影子32B+8B对齐，
;      满足 Windows x64「call 前 rsp ≡ 0 (mod 16)」——进入时 rsp ≡ 8，须补 8B 对齐）
;   2. call InjectShouldBlock(which, arg)   [C 决策，纯逻辑、无副作用、可重入]
;   3. 拦截 → add rsp,48h; mov eax,0xC0000022; ret   (STATUS_ACCESS_DENIED)
;   4. 放行 → 恢复 4 参数 + rsp → jmp [gTrampN]（尾跳转，栈参数原样）
; ============================================================================
.code

EXTERN InjectShouldBlock:PROC
; gTramp0/1/2 在本文件 .data 段定义（见文件末尾），C++ 侧 extern "C" 引用。
; 注意：不能同时 EXTERN + 定义（MASM A2005 符号重定义）。

; ---------------- NtMapViewOfSection ----------------
; RCX=SectionHandle RDX=ProcessHandle R8=BaseAddress* R9=ViewSize* ...
InjectShim0 PROC
    sub     rsp, 48h
    mov     [rsp+20h], rcx
    mov     [rsp+28h], rdx
    mov     [rsp+30h], r8
    mov     [rsp+38h], r9
    mov     ecx, 0            ; which = 0 (MapView)
    mov     rdx, rdx          ; arg = ProcessHandle（RDX 原值，此处显式）
    call    InjectShouldBlock
    test    eax, eax
    jnz     block0
    ; 放行：恢复寄存器参数 + 调用者栈，尾跳 trampoline
    mov     rcx, [rsp+20h]
    mov     rdx, [rsp+28h]
    mov     r8,  [rsp+30h]
    mov     r9,  [rsp+38h]
    add     rsp, 48h
    mov     rax, gTramp0
    jmp     rax
block0:
    add     rsp, 48h
    mov     eax, 0C0000022h   ; STATUS_ACCESS_DENIED
    ret
InjectShim0 ENDP

; ---------------- NtCreateThreadEx ----------------
; RCX=ThreadHandle* RDX=DesiredAccess R8=ObjectAttributes R9=ProcessHandle ...
InjectShim1 PROC
    sub     rsp, 48h
    mov     [rsp+20h], rcx
    mov     [rsp+28h], rdx
    mov     [rsp+30h], r8
    mov     [rsp+38h], r9
    mov     ecx, 1            ; which = 1 (CreateThreadEx)
    mov     rdx, r9           ; arg = ProcessHandle（第 4 参数）
    call    InjectShouldBlock
    test    eax, eax
    jnz     block1
    mov     rcx, [rsp+20h]
    mov     rdx, [rsp+28h]
    mov     r8,  [rsp+30h]
    mov     r9,  [rsp+38h]
    add     rsp, 48h
    mov     rax, gTramp1
    jmp     rax
block1:
    add     rsp, 48h
    mov     eax, 0C0000022h
    ret
InjectShim1 ENDP

; ---------------- NtOpenProcess ----------------
; RCX=ProcessHandle* RDX=DesiredAccess R8=ObjectAttributes R9=ClientId* ...
InjectShim2 PROC
    sub     rsp, 48h
    mov     [rsp+20h], rcx
    mov     [rsp+28h], rdx
    mov     [rsp+30h], r8
    mov     [rsp+38h], r9
    mov     ecx, 2            ; which = 2 (OpenProcess)
    mov     rdx, r9           ; arg = ClientId*（第 4 参数）
    call    InjectShouldBlock
    test    eax, eax
    jnz     block2
    mov     rcx, [rsp+20h]
    mov     rdx, [rsp+28h]
    mov     r8,  [rsp+30h]
    mov     r9,  [rsp+38h]
    add     rsp, 48h
    mov     rax, gTramp2
    jmp     rax
block2:
    add     rsp, 48h
    mov     eax, 0C0000022h
    ret
InjectShim2 ENDP

; ---------------- 全局 trampoline 指针（Install 时写入） ----------------
; 注意：MASM 数据符号默认 PRIVATE（不导出），必须 PUBLIC 供 C++ 链接。
.data
PUBLIC gTramp0, gTramp1, gTramp2
gTramp0 QWORD 0
gTramp1 QWORD 0
gTramp2 QWORD 0

end
