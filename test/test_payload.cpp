// ============================================================================
// test_payload.cpp — CI 自检用样例程序（跨页解密压测版）
//
// 设计目标：强制执行流穿过【非入口代码页】，真实触发"VEH 按需解密"生产路径。
//   - .text 总代码量 > 4KB → 跨多个 4KB 页（入口页 RVA 0x1000 永不门控；
//     其后的代码页会被门控置 PAGE_NOACCESS，执行到即触发 VEH 缺页解密）；
//   - main 定义在源文件前部（落在入口页），Work0..N / BigWork 定义在 main 之后
//     （落在后续代码页），main 顺序调用全部函数 → 执行流必然跨页；
//   - __declspec(noinline) + volatile 防止优化器内联/常量折叠；
//   - 最终把跨页累加值写入验证文件，证明所有跨页函数真实执行、VEH 解密正常。
// 注意：壳为 GUI 子系统且直接调用入口，样例避免 CRT 初始化依赖，纯 Win32 API。
// ============================================================================
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

// ---- 跨页工作函数声明（定义在 main 之后，使其落在后续代码页）----
#define DECL_WORK(WN) __declspec(noinline) unsigned Work##WN(unsigned x);
DECL_WORK(0)  DECL_WORK(1)  DECL_WORK(2)  DECL_WORK(3)
DECL_WORK(4)  DECL_WORK(5)  DECL_WORK(6)  DECL_WORK(7)
DECL_WORK(8)  DECL_WORK(9)  DECL_WORK(10) DECL_WORK(11)
DECL_WORK(12) DECL_WORK(13) DECL_WORK(14) DECL_WORK(15)
DECL_WORK(16) DECL_WORK(17) DECL_WORK(18) DECL_WORK(19)
DECL_WORK(20) DECL_WORK(21) DECL_WORK(22) DECL_WORK(23)
__declspec(noinline) unsigned BigWork(unsigned x);

int main()
{
    unsigned x = (unsigned)GetTickCount();   // 运行时不确定值，防常量折叠
    unsigned total = 0;
    total += Work0(x);  total += Work1(x);  total += Work2(x);  total += Work3(x);
    total += Work4(x);  total += Work5(x);  total += Work6(x);  total += Work7(x);
    total += Work8(x);  total += Work9(x);  total += Work10(x); total += Work11(x);
    total += Work12(x); total += Work13(x); total += Work14(x); total += Work15(x);
    total += Work16(x); total += Work17(x); total += Work18(x); total += Work19(x);
    total += Work20(x); total += Work21(x); total += Work22(x); total += Work23(x);
    total += BigWork(x);

    int rc = 0;
    HANDLE h = CreateFileA("pearmor_payload_ran.txt", GENERIC_WRITE, 0,
                           nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        char msg[128];
        int n = wsprintfA(msg, "payload OEP executed OK total=0x%08X\r\n", total);
        DWORD written = 0;
        WriteFile(h, msg, (DWORD)n, &written, nullptr);
        CloseHandle(h);
    } else {
        rc = 1;
    }
    // 入口由壳直接调用，无 CRT 收尾；显式结束进程并携带退出码
    ExitProcess((UINT)rc);
    return rc;
}

// ---- 跨页工作函数定义（每个约 130-170B，24 个合计约 3.5KB）----
#define WORK_BODY(WN, seed)                                       \
__declspec(noinline) unsigned Work##WN(unsigned x) {              \
    volatile unsigned a = x + (seed);                             \
    volatile unsigned b = a * 0x11111111u;                        \
    volatile unsigned c = b ^ (x >> 3);                           \
    volatile unsigned d = c + b;                                  \
    volatile unsigned e = d * 0x22222222u;                        \
    volatile unsigned f = e ^ d;                                  \
    volatile unsigned g = f + e;                                  \
    volatile unsigned h = g * 0x33333333u;                        \
    volatile unsigned i = h ^ g;                                  \
    volatile unsigned j = i + h;                                  \
    volatile unsigned k = j * 0x44444444u;                        \
    volatile unsigned l = k ^ j;                                  \
    volatile unsigned m = l + k;                                  \
    volatile unsigned q = m * 0x55555555u;                        \
    volatile unsigned r = q ^ m;                                  \
    volatile unsigned s = r + q;                                  \
    return s;                                                     \
}

WORK_BODY(0,  0x101) WORK_BODY(1,  0x202) WORK_BODY(2,  0x303) WORK_BODY(3,  0x404)
WORK_BODY(4,  0x505) WORK_BODY(5,  0x606) WORK_BODY(6,  0x707) WORK_BODY(7,  0x808)
WORK_BODY(8,  0x909) WORK_BODY(9,  0xA0A) WORK_BODY(10, 0xB0B) WORK_BODY(11, 0xC0C)
WORK_BODY(12, 0xD0D) WORK_BODY(13, 0xE0E) WORK_BODY(14, 0xF0F) WORK_BODY(15, 0x111)
WORK_BODY(16, 0x212) WORK_BODY(17, 0x313) WORK_BODY(18, 0x414) WORK_BODY(19, 0x515)
WORK_BODY(20, 0x616) WORK_BODY(21, 0x717) WORK_BODY(22, 0x818) WORK_BODY(23, 0x919)

// ---- 大函数：96 路 switch，约 2.5-3KB，保证 .text 总量跨 2 页以上 ----
__declspec(noinline) unsigned BigWork(unsigned x)
{
    volatile unsigned r = 0xCAFEBABEu;
    switch (x & 0x7F) {
    case 0:  r = r * 3u + 0;  break;
    case 1:  r = r * 3u + 1;  break;
    case 2:  r = r * 3u + 2;  break;
    case 3:  r = r * 3u + 3;  break;
    case 4:  r = r * 3u + 4;  break;
    case 5:  r = r * 3u + 5;  break;
    case 6:  r = r * 3u + 6;  break;
    case 7:  r = r * 3u + 7;  break;
    case 8:  r = r * 3u + 8;  break;
    case 9:  r = r * 3u + 9;  break;
    case 10: r = r * 3u + 10; break;
    case 11: r = r * 3u + 11; break;
    case 12: r = r * 3u + 12; break;
    case 13: r = r * 3u + 13; break;
    case 14: r = r * 3u + 14; break;
    case 15: r = r * 3u + 15; break;
    case 16: r = r * 3u + 16; break;
    case 17: r = r * 3u + 17; break;
    case 18: r = r * 3u + 18; break;
    case 19: r = r * 3u + 19; break;
    case 20: r = r * 3u + 20; break;
    case 21: r = r * 3u + 21; break;
    case 22: r = r * 3u + 22; break;
    case 23: r = r * 3u + 23; break;
    case 24: r = r * 3u + 24; break;
    case 25: r = r * 3u + 25; break;
    case 26: r = r * 3u + 26; break;
    case 27: r = r * 3u + 27; break;
    case 28: r = r * 3u + 28; break;
    case 29: r = r * 3u + 29; break;
    case 30: r = r * 3u + 30; break;
    case 31: r = r * 3u + 31; break;
    case 32: r = r * 3u + 32; break;
    case 33: r = r * 3u + 33; break;
    case 34: r = r * 3u + 34; break;
    case 35: r = r * 3u + 35; break;
    case 36: r = r * 3u + 36; break;
    case 37: r = r * 3u + 37; break;
    case 38: r = r * 3u + 38; break;
    case 39: r = r * 3u + 39; break;
    case 40: r = r * 3u + 40; break;
    case 41: r = r * 3u + 41; break;
    case 42: r = r * 3u + 42; break;
    case 43: r = r * 3u + 43; break;
    case 44: r = r * 3u + 44; break;
    case 45: r = r * 3u + 45; break;
    case 46: r = r * 3u + 46; break;
    case 47: r = r * 3u + 47; break;
    case 48: r = r * 3u + 48; break;
    case 49: r = r * 3u + 49; break;
    case 50: r = r * 3u + 50; break;
    case 51: r = r * 3u + 51; break;
    case 52: r = r * 3u + 52; break;
    case 53: r = r * 3u + 53; break;
    case 54: r = r * 3u + 54; break;
    case 55: r = r * 3u + 55; break;
    case 56: r = r * 3u + 56; break;
    case 57: r = r * 3u + 57; break;
    case 58: r = r * 3u + 58; break;
    case 59: r = r * 3u + 59; break;
    case 60: r = r * 3u + 60; break;
    case 61: r = r * 3u + 61; break;
    case 62: r = r * 3u + 62; break;
    case 63: r = r * 3u + 63; break;
    case 64: r = r * 3u + 64; break;
    case 65: r = r * 3u + 65; break;
    case 66: r = r * 3u + 66; break;
    case 67: r = r * 3u + 67; break;
    case 68: r = r * 3u + 68; break;
    case 69: r = r * 3u + 69; break;
    case 70: r = r * 3u + 70; break;
    case 71: r = r * 3u + 71; break;
    case 72: r = r * 3u + 72; break;
    case 73: r = r * 3u + 73; break;
    case 74: r = r * 3u + 74; break;
    case 75: r = r * 3u + 75; break;
    case 76: r = r * 3u + 76; break;
    case 77: r = r * 3u + 77; break;
    case 78: r = r * 3u + 78; break;
    case 79: r = r * 3u + 79; break;
    case 80: r = r * 3u + 80; break;
    case 81: r = r * 3u + 81; break;
    case 82: r = r * 3u + 82; break;
    case 83: r = r * 3u + 83; break;
    case 84: r = r * 3u + 84; break;
    case 85: r = r * 3u + 85; break;
    case 86: r = r * 3u + 86; break;
    case 87: r = r * 3u + 87; break;
    case 88: r = r * 3u + 88; break;
    case 89: r = r * 3u + 89; break;
    case 90: r = r * 3u + 90; break;
    case 91: r = r * 3u + 91; break;
    case 92: r = r * 3u + 92; break;
    case 93: r = r * 3u + 93; break;
    case 94: r = r * 3u + 94; break;
    case 95: r = r * 3u + 95; break;
    default: r = r + x; break;
    }
    return r;
}
