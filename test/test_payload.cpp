// ============================================================================
// test_payload.cpp — CI 自检用样例程序
// 加壳后应创建一个验证文件并退出码 0，用于验证「Stub 解密 + 手动加载 + OEP
// 跳转」整条链路是否正确。
// 注意：壳为 GUI 子系统且直接调用入口，样例避免 CRT 初始化依赖，纯 Win32 API。
// ============================================================================
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

int main()
{
    int rc = 0;
    HANDLE h = CreateFileA("pearmor_payload_ran.txt", GENERIC_WRITE, 0,
                           nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        const char msg[] = "payload OEP executed OK\r\n";
        DWORD written = 0;
        WriteFile(h, msg, (DWORD)(sizeof(msg) - 1), &written, nullptr);
        CloseHandle(h);
    } else {
        rc = 1;
    }
    // 入口由壳直接调用，无 CRT 收尾；显式结束进程并携带退出码
    ExitProcess((UINT)rc);
    return rc;
}
