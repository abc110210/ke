// ============================================================================
// pe_loader.h — 自研 PE64 手动内存加载器
//
// 原则：
//   * 不调用 LoadLibrary 加载目标 PE —— 完全自研内存映射
//   * 手动解析 DOS/NT 头、拷贝节、修复导入表、应用重定位
//   * 目标依赖的系统 DLL（kernel32 等）由我们自行用 NtCreateFile/NtMapViewOfSection
//     或直接解析 PEB 已加载模块，不经过 LoadLibraryA 的“加载目标”路径
// ============================================================================
#pragma once

#include <windows.h>
#include <winternl.h>
#include <delayimp.h>
#include <bcrypt.h>
#include <intrin.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <vector>

#pragma comment(lib, "ntdll.lib")

#define PEARMOR_PAGE_SIZE 0x1000

// SECTION_INHERIT 在 WIN32_LEAN_AND_MEAN 下不一定被 windows.h 暴露（与 psapi 同理），
// 自行定义一份独立枚举，避免依赖 SDK 的暴露情况。值取自 winnt.h：ViewShare=1 / ViewUnmap=2。
typedef enum _PEARMOR_SECTION_INHERIT {
    PearmorViewShare = 1,
    PearmorViewUnmap = 2
} PEARMOR_SECTION_INHERIT, *PPEARMOR_SECTION_INHERIT;

// ============================================================================
// 直接系统调用 / PEB 解析 —— 避免依赖 LoadLibraryA 加载目标
// ============================================================================

typedef NTSTATUS(NTAPI* pNtCreateFile)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
    PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);

typedef NTSTATUS(NTAPI* pNtMapViewOfSection)(
    HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T,
    PEARMOR_SECTION_INHERIT, ULONG, ULONG);

typedef NTSTATUS(NTAPI* pNtOpenSection)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)(HANDLE, PVOID);
typedef NTSTATUS(NTAPI* pNtClose)(HANDLE);
typedef NTSTATUS(NTAPI* pRtlInitUnicodeString)(PUNICODE_STRING, PCWSTR);
typedef NTSTATUS(NTAPI* pRtlInsertInvertedFunctionTable)(PVOID, ULONG, ULONG);
typedef NTSTATUS(NTAPI* pRtlDeleteInvertedFunctionTable)(PVOID);

// 判断模块是否已加载（PEB 链表），已加载则返回基址 —— 不调用 GetModuleHandle
static inline uintptr_t getLoadedModuleBase(const wchar_t* moduleName)
{
    _PEB* peb = reinterpret_cast<_PEB*>(__readgsqword(0x60));
    if (!peb || !peb->Ldr) return 0;
    LIST_ENTRY* head = &peb->Ldr->InMemoryOrderModuleList;
    for (LIST_ENTRY* e = head->Flink; e != head; e = e->Flink) {
        auto* entry = CONTAINING_RECORD(e, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (entry->DllBase && entry->FullDllName.Buffer) {
            const wchar_t* b = entry->FullDllName.Buffer;
            size_t n = entry->FullDllName.Length / sizeof(wchar_t);
            size_t p = n;
            while (p > 0 && b[p - 1] != L'\\' && b[p - 1] != L'/') p--;
            const wchar_t* tail = b + p;
            size_t tl = n - p;
            size_t want = wcslen(moduleName);
            if (tl == want && _wcsicmp(tail, moduleName) == 0)
                return reinterpret_cast<uintptr_t>(entry->DllBase);
        }
    }
    return 0;
}

namespace pearmor {

// 通过 PEB 找到 ntdll 的导出函数（不调用 LoadLibrary）
struct NtApiTable {
    pNtCreateFile      NtCreateFile = nullptr;
    pNtMapViewOfSection NtMapViewOfSection = nullptr;
    pNtOpenSection     NtOpenSection = nullptr;
    pNtUnmapViewOfSection NtUnmapViewOfSection = nullptr;
    pNtClose           NtClose = nullptr;
    pRtlInitUnicodeString RtlInitUnicodeString = nullptr;
    pRtlInsertInvertedFunctionTable RtlInsertInvertedFunctionTable = nullptr;
    pRtlDeleteInvertedFunctionTable RtlDeleteInvertedFunctionTable = nullptr;
};

static inline void* peExportAddress(uintptr_t base, const char* exportName)
{
    // 手工解析导出表（PEB 无 GetProcAddress 时使用）
    if (!base) return nullptr;
    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
    auto* nt  = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;
    DWORD expRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD expSz  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    if (!expRva) return nullptr;
    auto* exp = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(base + expRva);
    if (expSz < sizeof(IMAGE_EXPORT_DIRECTORY)) return nullptr;
    const DWORD* names = reinterpret_cast<const DWORD*>(base + exp->AddressOfNames);
    const WORD*  ords  = reinterpret_cast<const WORD*>(base + exp->AddressOfNameOrdinals);
    const DWORD* funcs = reinterpret_cast<const DWORD*>(base + exp->AddressOfFunctions);
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char* nm = reinterpret_cast<const char*>(base + names[i]);
        if (strcmp(nm, exportName) == 0) {
            DWORD fnRva = funcs[ords[i]];
            if (fnRva >= expRva && fnRva < expRva + expSz) {
                // 转发函数（forwarder）→ 简单返回 RVA（由调用方决定）
                return reinterpret_cast<void*>(base + fnRva);
            }
            return reinterpret_cast<void*>(base + fnRva);
        }
    }
    return nullptr;
}

static inline bool resolveNtApis(NtApiTable& t)
{
    uintptr_t ntdll = getLoadedModuleBase(L"ntdll.dll");
    if (!ntdll) return false;
    t.NtCreateFile       = reinterpret_cast<pNtCreateFile>(peExportAddress(ntdll, "NtCreateFile"));
    t.NtMapViewOfSection = reinterpret_cast<pNtMapViewOfSection>(peExportAddress(ntdll, "NtMapViewOfSection"));
    t.NtOpenSection      = reinterpret_cast<pNtOpenSection>(peExportAddress(ntdll, "NtOpenSection"));
    t.NtUnmapViewOfSection = reinterpret_cast<pNtUnmapViewOfSection>(peExportAddress(ntdll, "NtUnmapViewOfSection"));
    t.NtClose            = reinterpret_cast<pNtClose>(peExportAddress(ntdll, "NtClose"));
    t.RtlInitUnicodeString = reinterpret_cast<pRtlInitUnicodeString>(peExportAddress(ntdll, "RtlInitUnicodeString"));
    t.RtlInsertInvertedFunctionTable = reinterpret_cast<pRtlInsertInvertedFunctionTable>(
        peExportAddress(ntdll, "RtlInsertInvertedFunctionTable"));
    t.RtlDeleteInvertedFunctionTable = reinterpret_cast<pRtlDeleteInvertedFunctionTable>(
        peExportAddress(ntdll, "RtlDeleteInvertedFunctionTable"));
    return t.NtCreateFile && t.NtMapViewOfSection && t.NtClose && t.RtlInitUnicodeString;
}

// 解析模块基址：优先 PEB（已加载），否则自研 NtOpenSection+NtMapViewOfSection 映射
static inline uintptr_t resolveModuleBase(const wchar_t* moduleName, NtApiTable& nt)
{
    // 1) 已加载
    uintptr_t base = getLoadedModuleBase(moduleName);
    if (base) return base;

    // 2) 自研映射（system32 内搜索）
    if (!nt.NtOpenSection || !nt.NtMapViewOfSection || !nt.NtClose || !nt.RtlInitUnicodeString)
        return 0;

    wchar_t full[MAX_PATH];
    swprintf_s(full, L"\\??\\C:\\Windows\\System32\\%s", moduleName);
    UNICODE_STRING us;
    OBJECT_ATTRIBUTES oa;
    HANDLE section = nullptr;
    nt.RtlInitUnicodeString(&us, full);
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, nullptr, nullptr);
    if (nt.NtOpenSection(&section, SECTION_MAP_READ, &oa) != 0) return 0;

    PVOID baseAddr = nullptr;
    SIZE_T viewSize = 0;
    NTSTATUS st = nt.NtMapViewOfSection(section, GetCurrentProcess(), &baseAddr,
                                        0, 0, nullptr, &viewSize,
                                        PearmorViewUnmap, 0, PAGE_READONLY);
    nt.NtClose(section);
    if (st != 0) return 0;
    return reinterpret_cast<uintptr_t>(baseAddr);
}

// 从已映射的 DLL 基址解析导出函数地址（支持名字与 "序数" 两种形式）
static inline void* resolveExportFromBase(uintptr_t moduleBase, const char* exportName)
{
    if (!moduleBase) return nullptr;
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(moduleBase);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(moduleBase + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;
    const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.VirtualAddress || !dir.Size) return nullptr;
    const auto* exp = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(moduleBase + dir.VirtualAddress);
    if (dir.Size < sizeof(IMAGE_EXPORT_DIRECTORY)) return nullptr;
    const DWORD* names = reinterpret_cast<const DWORD*>(moduleBase + exp->AddressOfNames);
    const WORD*  ords  = reinterpret_cast<const WORD*>(moduleBase + exp->AddressOfNameOrdinals);
    const DWORD* funcs = reinterpret_cast<const DWORD*>(moduleBase + exp->AddressOfFunctions);

    // 序数形式 "#123" -> 按序号查 AddressOfFunctions
    if (exportName[0] == '#') {
        DWORD ord = (DWORD)strtoul(exportName + 1, nullptr, 10);
        if (ord >= exp->Base && (ord - exp->Base) < exp->NumberOfFunctions)
            return reinterpret_cast<void*>(moduleBase + funcs[ord - exp->Base]);
        return nullptr;
    }

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char* nm = reinterpret_cast<const char*>(moduleBase + names[i]);
        if (strcmp(nm, exportName) == 0) {
            DWORD fnRva = funcs[ords[i]];
            // CI 63 诊断：自研解析成功时打印关键值，便于核对是否把名字字符串 RVA 当函数 RVA
            DebugLog("[loader] 导出解析: %s -> rva=0x%X addr=%p (exp: funcs=0x%X names=0x%X ords=0x%X numF=%u numN=%u)",
                     exportName, fnRva, reinterpret_cast<void*>(moduleBase + fnRva),
                     (unsigned)exp->AddressOfFunctions, (unsigned)exp->AddressOfNames,
                     (unsigned)exp->AddressOfNameOrdinals,
                     (unsigned)exp->NumberOfFunctions, (unsigned)exp->NumberOfNames);
            return reinterpret_cast<void*>(moduleBase + fnRva);
        }
    }
    return nullptr;
}

// 独立 SEH 辅助：TLS 数据挂载——读 _tls_index + 拷贝模板 + 写入 TEB 槽。
// 参数全 POD、内部才用 __try（CI 37 教训：__try 不能进类内成员函数，否则 C2712；
// 本函数放命名空间作用域）。x64: TEB+0x58=ThreadLocalStoragePointer（指向槽数组），
// GS:[0x30]=TEB。失败（不可读/不可写）返回 false，调用方释放 tlsData。
static bool SafeTlsMount(uintptr_t idxAddr, uintptr_t tplAddr,
                         void* tlsData, size_t tlsSize, DWORD* outIndex)
{
    DWORD tlsIndex = 0;
    __try {
        if (idxAddr) tlsIndex = *(volatile DWORD*)idxAddr;
        memcpy(tlsData, reinterpret_cast<const void*>(tplAddr), tlsSize);
        NT_TIB* tib = reinterpret_cast<NT_TIB*>(__readgsqword(0x30));
        PVOID* tlsArr = *reinterpret_cast<PVOID**>(reinterpret_cast<BYTE*>(tib) + 0x58);
        if (tlsArr) tlsArr[tlsIndex] = tlsData;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    if (outIndex) *outIndex = tlsIndex;
    return true;
}

// 独立 SEH 辅助：调用 ntdll RtlAddFunctionTable 注册 .pdata 展开表。
// 参数全 POD、内部才用 __try（C2712 安全）。注册后 FunctionTable 必须保持有效
// （直接引用 payload 内存，payload 常驻故安全）。
static BOOLEAN SafeRtlAddFunctionTable(PRUNTIME_FUNCTION table, DWORD count, DWORD64 imageBase)
{
    if (!table || !count) return FALSE;
    using PFN = BOOLEAN (NTAPI*)(PRUNTIME_FUNCTION, DWORD, DWORD64);
    static PFN pAdd = nullptr;
    static bool resolved = false;
    if (!resolved) {
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        if (ntdll) pAdd = reinterpret_cast<PFN>(GetProcAddress(ntdll, "RtlAddFunctionTable"));
        resolved = true;
    }
    if (!pAdd) return FALSE;
    __try {
        return pAdd(table, count, imageBase);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}

// ============================================================================
// 手动加载目标 PE（PE32+）
// ============================================================================

struct LoadResult {
    bool     ok = false;
    void*    imageBase = nullptr;
    uint64_t entryRva = 0;
    uint32_t err = 0;
};

class ManualPeLoader {
public:
    ManualPeLoader() = default;

    // 把内存中的加密镜像解密后手动映射
    // cipher 指向 AES-256-CBC 密文，cipherLen 为密文长度，key 32 字节, iv 16 字节
    LoadResult LoadFromMemory(const unsigned char* cipher, size_t cipherLen,
                              const unsigned char* key, const unsigned char* iv)
    {
        LoadResult r;
        if (!cipher || cipherLen == 0) { r.err = 0x10; return r; }

        // 1) 解密到明文缓冲区
        size_t padded = (cipherLen + 15) & ~(size_t)15;
        std::vector<unsigned char> plain(padded, 0);
        if (!Aes256CbcDecrypt(cipher, cipherLen, key, iv, plain.data())) {
            r.err = 0x11;
            return r;
        }

        // 2) 手动映射明文 PE
        return MapManual(plain.data(), padded, r);
    }

    // 把明文 PE 数据手动映射（不调用 LoadLibrary）
    LoadResult MapManual(const unsigned char* peData, size_t peLen, LoadResult& r)
    {
        if (peLen < sizeof(IMAGE_DOS_HEADER)) { r.err = 0x20; return r; }
        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(peData);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) { r.err = 0x21; return r; }
        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(peData + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) { r.err = 0x22; return r; }
        if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) { r.err = 0x23; return r; }
        if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) { r.err = 0x24; return r; }

        const IMAGE_OPTIONAL_HEADER64& opt = nt->OptionalHeader;
        const uint64_t preferredBase = opt.ImageBase;
        const DWORD sizeOfImage     = opt.SizeOfImage;
        const DWORD sizeOfHeaders   = opt.SizeOfHeaders;

        // 优先在首选基址分配，失败则回退（此时需要重定位）
        void* imageBase = VirtualAlloc(
            reinterpret_cast<LPVOID>(preferredBase),
            sizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        bool relocated = (imageBase != reinterpret_cast<void*>(preferredBase));

        if (!imageBase) { r.err = 0x25; return r; }

        // 3) 拷贝头与节
        memcpy(imageBase, peData, (size_t)sizeOfHeaders < peLen ? sizeOfHeaders : peLen);

        IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
            DWORD va   = sec[i].VirtualAddress;
            DWORD vsz  = sec[i].Misc.VirtualSize;
            DWORD raw  = sec[i].PointerToRawData;
            DWORD rsz  = sec[i].SizeOfRawData;
            if (va + vsz > sizeOfImage) vsz = sizeOfImage - va;
            if (raw + rsz > peLen)      rsz = static_cast<DWORD>(peLen > raw ? peLen - raw : 0);
            if (rsz > 0)
                memcpy(reinterpret_cast<BYTE*>(imageBase) + va, peData + raw, rsz);
            if (vsz > rsz)
                memset(reinterpret_cast<BYTE*>(imageBase) + va + rsz, 0, vsz - rsz);
        }

        NtApiTable ntApis;   // 提前声明，避免 goto fail 跳过其初始化（C4533）

        // 4) 重定位
        if (relocated) {
            if (!ApplyRelocations(imageBase, preferredBase, opt)) { r.err = 0x26; goto fail; }
        }

        // 5) 修复导入表
        if (!FixImports(imageBase, opt)) { r.err = 0x27; goto fail; }

        // 6) 延迟导入（可选）
        FixDelayImports(imageBase, opt);

        // 7) TLS 回调
        if (opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress) {
            if (!RunTlsCallbacks(imageBase, opt)) { r.err = 0x28; goto fail; }
        }

        // 8) 按节设置内存保护（代码 EXECUTE_READ，数据不可执行）
        ProtectSections(imageBase, nt);

        // 9) 注册到系统异常展开表（使 CRT / SEH 展开能识别手动映射的镜像）
        if (resolveNtApis(ntApis) && ntApis.RtlInsertInvertedFunctionTable) {
            // 参数：镜像基址（64KB 对齐）+ 大小；返回 NTSTATUS
            uintptr_t aligned = reinterpret_cast<uintptr_t>(imageBase) & ~(uintptr_t)0xFFFF;
            ntApis.RtlInsertInvertedFunctionTable(
                reinterpret_cast<PVOID>(aligned), sizeOfImage, 0);
        }

        r.ok = true;
        r.imageBase = imageBase;
        r.entryRva  = opt.AddressOfEntryPoint;
        return r;

    fail:
        VirtualFree(imageBase, 0, MEM_RELEASE);
        return r;
    }

    // 跳转到原始入口 (OEP)
    static int CallEntry(void* imageBase, uint64_t entryRva)
    {
        using EntryFn = int(WINAPI*)();
        auto entry = reinterpret_cast<EntryFn>(
            reinterpret_cast<BYTE*>(imageBase) + entryRva);
        if (!entry) return -1;
        return entry();
    }

    // 清理：释放映射
    static void Release(void* imageBase)
    {
        if (imageBase) VirtualFree(imageBase, 0, MEM_RELEASE);
    }

private:
    // ---------- AES-256-CBC 解密（BCrypt，一次调用） ----------
    static bool Aes256CbcDecrypt(const unsigned char* cipher, size_t cipherLen,
                                 const unsigned char* key, const unsigned char* iv,
                                 unsigned char* out)
    {
        BCRYPT_ALG_HANDLE alg = nullptr;
        BCRYPT_KEY_HANDLE kh  = nullptr;
        bool ok = false;
        do {
            if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, nullptr, 0) != 0) break;
            if (BCryptSetProperty(alg, BCRYPT_CHAINING_MODE,
                    reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_CBC)),
                    sizeof(BCRYPT_CHAIN_MODE_CBC), 0) != 0) break;
            if (BCryptGenerateSymmetricKey(alg, &kh, nullptr, 0,
                    const_cast<PUCHAR>(key), 32, 0) != 0) break;
            ULONG done = 0;
            NTSTATUS st = BCryptDecrypt(kh, const_cast<PUCHAR>(cipher),
                static_cast<ULONG>(cipherLen), nullptr, const_cast<PUCHAR>(iv), 16,
                out, static_cast<ULONG>(cipherLen), &done, 0);
            if (st != 0) break;
            ok = true;
        } while (false);
        if (kh) BCryptDestroyKey(kh);
        if (alg) BCryptCloseAlgorithmProvider(alg, 0);
        return ok;
    }

public:
    // ---------- 重定位 ----------
    static bool ApplyRelocations(void* imageBase, uint64_t preferredBase,
                                 const IMAGE_OPTIONAL_HEADER64& opt)
    {
        auto& dir = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (!dir.VirtualAddress || !dir.Size) return true; // 无重定位表，容忍
        BYTE* base = reinterpret_cast<BYTE*>(imageBase);
        uint64_t delta = reinterpret_cast<uint64_t>(imageBase) - preferredBase;
        DWORD off = 0;
        while (off + sizeof(IMAGE_BASE_RELOCATION) <= dir.Size) {
            auto* blk = reinterpret_cast<IMAGE_BASE_RELOCATION*>(base + dir.VirtualAddress + off);
            if (blk->SizeOfBlock == 0) break;
            DWORD n = (blk->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD* entries = reinterpret_cast<WORD*>(
                reinterpret_cast<BYTE*>(blk) + sizeof(IMAGE_BASE_RELOCATION));
            for (DWORD i = 0; i < n; i++) {
                WORD type = entries[i] >> 12;
                DWORD pOff = entries[i] & 0x0FFF;
                if (type == IMAGE_REL_BASED_DIR64) {
                    uint64_t* p = reinterpret_cast<uint64_t*>(
                        base + blk->VirtualAddress + pOff);
                    *p += delta;
                } else if (type == IMAGE_REL_BASED_HIGHLOW) {
                    uint32_t* p = reinterpret_cast<uint32_t*>(
                        base + blk->VirtualAddress + pOff);
                    *p += static_cast<uint32_t>(delta & 0xFFFFFFFF);
                }
                // IMAGE_REL_BASED_ABSOLUTE(0) 忽略
            }
            off += blk->SizeOfBlock;
        }
        return true;
    }

    // ---------- 导入修复 ----------

    // ============ 模块伪装（CI 74） ============
    // 目标程序若调用 GetModuleFileNameW(NULL)/GetModuleHandle(NULL) 获取“自身”信息，
    // 手动映射的 payload 不在 PEB 模块表，系统会返回 stub 的路径/基址 → 业务判定
    // “自身异常”（如 exe 名/版本/路径不符）→ 主动 RaiseException(0xE06D7363)。
    // 解法：在 FixImports 阶段把 payload 导入的这 4 个 API 替换为下面的伪装实现。
    //   - GetModuleFileNameW/A(NULL) -> 返回 overlay 里记录的原版文件名
    //   - GetModuleHandleW/A(NULL)   -> 返回 payload 基址（手动映射的镜像）
    // 非 NULL 参数一律转发真函数（stub 自身仍是已注册模块）。
    namespace ModuleFake {
        // 全局：payload 基址 + 原版文件名（Load 时设置）
        inline uintptr_t gPayloadBase = 0;
        inline wchar_t    gOrigName[64] = {0};
        inline wchar_t    gFakePath[MAX_PATH] = {0}; // 原版路径（目录 + 原文件名）

        // 根据 payload 基址拼出“伪装路径”：<payload 所在目录>\<原文件名>
        // 目录取 stub 自身目录（两者同目录分发），文件名用原版名。
        inline void Init(uintptr_t payloadBase, const wchar_t* origName)
        {
            gPayloadBase = payloadBase;
            if (origName) {
                wcsncpy(gOrigName, origName, 63);
                gOrigName[63] = 0;
                wchar_t self[MAX_PATH] = {0};
                GetModuleFileNameW(nullptr, self, MAX_PATH);
                // 去掉 stub 文件名，保留目录
                wchar_t* slash = wcsrchr(self, L'\\');
                if (slash) *slash = 0; else self[0] = 0;
                swprintf(gFakePath, MAX_PATH, L"%s\\%s", self, gOrigName);
            }
        }

        inline HMODULE WINAPI FakeGetModuleHandleW(LPCWSTR name)
        {
            if (!name) return reinterpret_cast<HMODULE>(gPayloadBase);
            return GetModuleHandleW(name);
        }
        inline HMODULE WINAPI FakeGetModuleHandleA(LPCSTR name)
        {
            if (!name) return reinterpret_cast<HMODULE>(gPayloadBase);
            return GetModuleHandleA(name);
        }
        inline DWORD WINAPI FakeGetModuleFileNameW(HMODULE h, LPWSTR buf, DWORD sz)
        {
            if (!h || h == reinterpret_cast<HMODULE>(gPayloadBase)) {
                if (!buf || !sz) return 0;
                if (gFakePath[0]) {
                    DWORD n = (DWORD)wcslen(gFakePath);
                    if (n >= sz) n = sz - 1;
                    memcpy(buf, gFakePath, n * sizeof(wchar_t));
                    buf[n] = 0;
                    return n;
                }
                // 无原文件名（旧产物）：退化为 stub 自身路径
                return GetModuleFileNameW(nullptr, buf, sz);
            }
            return GetModuleFileNameW(h, buf, sz);
        }
        inline DWORD WINAPI FakeGetModuleFileNameA(HMODULE h, LPSTR buf, DWORD sz)
        {
            wchar_t tmp[MAX_PATH] = {0};
            DWORD n = FakeGetModuleFileNameW(h, tmp, MAX_PATH);
            if (!n) return 0;
            DWORD k = WideCharToMultiByte(CP_ACP, 0, tmp, (int)n, buf, (int)sz, nullptr, nullptr);
            return k;
        }
    } // namespace ModuleFake

    // 解析系统 DLL 模块基址：优先 PEB/自研映射（绕过钩子），失败退回系统 API。
    // 注意：LoadLibraryA 只用于【系统依赖 DLL】（kernel32/user32/gdi32 等），
    // 目标 PE 本体仍全程手动映射，不违背"不调用 LoadLibrary 加载目标"的原则。
    static uintptr_t ResolveSystemModule(const char* dllNameA, const wchar_t* dllNameW,
                                         NtApiTable& nt)
    {
        uintptr_t hMod = resolveModuleBase(dllNameW, nt);
        if (!hMod) {
            HMODULE h = GetModuleHandleA(dllNameA);
            if (!h) h = LoadLibraryA(dllNameA);
            if (h) hMod = reinterpret_cast<uintptr_t>(h);
        }
        return hMod;
    }

    // 解析系统 DLL 的单个导入项（名字或序数）：优先自研解析，失败退回 GetProcAddress。
    // ordinal != 0 表示序数导入；否则 name 是导入名（ASCII）。
    // 【CI 63 根因防御】自研解析结果必须落在【可执行页】——CI 63 实测：解析出的
    // SetEnvironmentVariableA 地址指向 KERNEL32 .rdata 的名字字符串（0xAAF6C，内容
    // "SetEnvironmentVariableA\0"），取指即 0xC0000005。凡不可执行的结果一律丢弃并
    // 退回 GetProcAddress（系统解析永远返回正确可执行地址），从根上消灭此类 bug。
    static void* ResolveSystemImport(uintptr_t hMod, const char* name, DWORD ordinal)
    {
        void* fn = nullptr;
        HMODULE hDll = reinterpret_cast<HMODULE>(hMod);
        if (ordinal) {
            char ordBuf[16];
            snprintf(ordBuf, sizeof(ordBuf), "#%u", ordinal);
            fn = resolveExportFromBase(hMod, ordBuf);
        } else {
            fn = resolveExportFromBase(hMod, name);
        }
        // 可执行性校验：COMMIT 且页保护含 EXECUTE 位才可信（防名字字符串/数据区/垃圾地址）
        if (fn) {
            MEMORY_BASIC_INFORMATION mbi;
            bool exec = (VirtualQuery(fn, &mbi, sizeof(mbi)) != 0 &&
                         mbi.State == MEM_COMMIT &&
                         (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                                         PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0);
            if (!exec) {
                DebugLog("[loader] 导入解析异常: %s=%p 不可执行(保护=0x%X), 退回 GetProcAddress",
                         name ? name : "#(ord)", fn,
                         (unsigned)(VirtualQuery(fn, &mbi, sizeof(mbi)) ? mbi.Protect : 0));
                fn = nullptr;
            }
        }
        if (!fn && hDll) {
            if (ordinal)
                fn = reinterpret_cast<void*>(GetProcAddress(hDll, MAKEINTRESOURCEA(ordinal)));
            else
                fn = reinterpret_cast<void*>(GetProcAddress(hDll, name));
        }
        return fn;
    }

    static bool FixImports(void* imageBase, const IMAGE_OPTIONAL_HEADER64& opt)
    {
        auto& dir = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (!dir.VirtualAddress || !dir.Size) return true; // 无导入表
        BYTE* base = reinterpret_cast<BYTE*>(imageBase);

        NtApiTable nt;
        resolveNtApis(nt);

        auto* desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + dir.VirtualAddress);
        for (; desc->Name; desc++) {
            const char* dllNameA = reinterpret_cast<const char*>(base + desc->Name);

            // 转宽字符
            wchar_t dllNameW[64];
            MultiByteToWideChar(CP_ACP, 0, dllNameA, -1, dllNameW, 64);

            uintptr_t hMod = ResolveSystemModule(dllNameA, dllNameW, nt);
            if (!hMod) {
                DebugLog("[loader] 导入解析失败: 模块不可用 dll=%s", dllNameA);
                return false;
            }

            // 遍历 OriginalFirstThunk / FirstThunk
            ULONGLONG* oft = desc->OriginalFirstThunk
                ? reinterpret_cast<ULONGLONG*>(base + desc->OriginalFirstThunk)
                : reinterpret_cast<ULONGLONG*>(base + desc->FirstThunk);
            ULONGLONG* ft  = reinterpret_cast<ULONGLONG*>(base + desc->FirstThunk);
            for (; *oft; oft++, ft++) {
                void* fn = nullptr;
                const char* fnName = "?";
                DWORD ordinal = 0;
                if (IMAGE_SNAP_BY_ORDINAL64(*oft)) {
                    // 序数导入
                    ordinal = (DWORD)(*oft & 0xFFFF);
                    fnName  = "ord";
                } else {
                    auto* imp = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(
                        base + static_cast<DWORD>(*oft));
                    fnName = reinterpret_cast<const char*>(imp->Name);
                }
                fn = ResolveSystemImport(hMod, fnName, ordinal);
                if (!fn) {
                    DebugLog("[loader] 导入解析失败: dll=%s fn=%s", dllNameA, fnName);
                    return false;
                }
                // CI 74 模块伪装：把 payload 对“自身信息”的查询替换成伪装实现。
                // 仅当 ModuleFake 已初始化（gPayloadBase != 0）时替换，且只针对 4 个函数名。
                if (ModuleFake::gPayloadBase != 0) {
                    if (fnName && fnName[0] != '?' &&
                        (strcmp(fnName, "GetModuleFileNameW") == 0 ||
                         strcmp(fnName, "GetModuleFileNameA") == 0 ||
                         strcmp(fnName, "GetModuleHandleW")   == 0 ||
                         strcmp(fnName, "GetModuleHandleA")   == 0)) {
                        if (strcmp(fnName, "GetModuleFileNameW") == 0) fn = reinterpret_cast<void*>(&ModuleFake::FakeGetModuleFileNameW);
                        else if (strcmp(fnName, "GetModuleFileNameA") == 0) fn = reinterpret_cast<void*>(&ModuleFake::FakeGetModuleFileNameA);
                        else if (strcmp(fnName, "GetModuleHandleW") == 0) fn = reinterpret_cast<void*>(&ModuleFake::FakeGetModuleHandleW);
                        else if (strcmp(fnName, "GetModuleHandleA") == 0) fn = reinterpret_cast<void*>(&ModuleFake::FakeGetModuleHandleA);
                        DebugLog("[loader] 模块伪装: %s -> Fake (原文件名=%ls)", fnName, ModuleFake::gOrigName);
                    }
                }
                *ft = reinterpret_cast<ULONGLONG>(fn);
            }
        }
        return true;
    }

    static void FixDelayImports(void* imageBase, const IMAGE_OPTIONAL_HEADER64& opt)
    {
        auto& dir = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
        if (!dir.VirtualAddress || !dir.Size) return;
        BYTE* base = reinterpret_cast<BYTE*>(imageBase);
        NtApiTable nt;
        resolveNtApis(nt);
        auto* desc = reinterpret_cast<ImgDelayDescr*>(base + dir.VirtualAddress);
        for (; desc->rvaDLLName; desc++) {
            const char* dllNameA = reinterpret_cast<const char*>(base + desc->rvaDLLName);
            wchar_t dllNameW[64];
            MultiByteToWideChar(CP_ACP, 0, dllNameA, -1, dllNameW, 64);
            uintptr_t hMod = ResolveSystemModule(dllNameA, dllNameW, nt);
            if (!hMod) continue;   // 延迟导入：模块不可用可容忍（惰性加载）
            if (desc->rvaIAT) {
                auto* iat = reinterpret_cast<ULONGLONG*>(base + desc->rvaIAT);
                auto* intn = reinterpret_cast<ULONGLONG*>(base + desc->rvaINT);
                for (ULONG i = 0; intn[i]; i++) {
                    void* fn = nullptr;
                    const char* fnName = "?";
                    if (IMAGE_SNAP_BY_ORDINAL64(intn[i])) {
                        fn = ResolveSystemImport(hMod, nullptr, (DWORD)(intn[i] & 0xFFFF));
                    } else {
                        auto* imp = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(
                            base + static_cast<DWORD>(intn[i]));
                        fnName = reinterpret_cast<const char*>(imp->Name);
                        fn = ResolveSystemImport(hMod, fnName, 0);
                    }
                    // CI 74 模块伪装（延迟导入同样替换）
                    if (fn && ModuleFake::gPayloadBase != 0 && fnName && fnName[0] != '?') {
                        if (strcmp(fnName, "GetModuleFileNameW") == 0) fn = reinterpret_cast<void*>(&ModuleFake::FakeGetModuleFileNameW);
                        else if (strcmp(fnName, "GetModuleFileNameA") == 0) fn = reinterpret_cast<void*>(&ModuleFake::FakeGetModuleFileNameA);
                        else if (strcmp(fnName, "GetModuleHandleW") == 0) fn = reinterpret_cast<void*>(&ModuleFake::FakeGetModuleHandleW);
                        else if (strcmp(fnName, "GetModuleHandleA") == 0) fn = reinterpret_cast<void*>(&ModuleFake::FakeGetModuleHandleA);
                    }
                    iat[i] = reinterpret_cast<ULONGLONG>(fn);
                }
            }
        }
    }

    // ---------- TLS 数据初始化 ----------
    // 系统 loader 对含 TLS 目录的模块必做三件事：① 分配 TLS 数据块并拷模板
    // （StartAddressOfRawData→EndAddressOfRawData）② 挂到当前线程
    // TEB->ThreadLocalStoragePointer[_tls_index] ③ 执行 TLS 回调。
    // 此前只做了 ③ —— CI 64 实测 Hanbot 崩在 payload 偏移 0x14E3A
    // （mov [rbx+rax*8+0x10],rsi 写野指针 fault=0x1A06856AD60），与「__declspec(thread)
    // 槽指针未初始化」的编译模式（先取槽指针再写槽内偏移）高度吻合。补上 ①②。
    // 注：SafeTlsMount（含 __try 的 SEH 辅助）定义在命名空间作用域（CI 37 教训：
    // __try 不能进类内成员函数，会触发 C2712）。
    static void InitTlsData(void* imageBase, const IMAGE_OPTIONAL_HEADER64& opt)
    {
        auto& dir = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
        if (!dir.VirtualAddress || !dir.Size) return;
        BYTE* base = reinterpret_cast<BYTE*>(imageBase);
        if (dir.VirtualAddress >= opt.SizeOfImage) return;
        auto* tls = reinterpret_cast<IMAGE_TLS_DIRECTORY64*>(base + dir.VirtualAddress);
        uintptr_t start = static_cast<uintptr_t>(tls->StartAddressOfRawData);
        uintptr_t end   = static_cast<uintptr_t>(tls->EndAddressOfRawData);
        uintptr_t idx   = static_cast<uintptr_t>(tls->AddressOfIndex);
        if (!start || !end || end <= start) {
            DebugLog("[loader] TLS 数据: 无模板数据，跳过");
            return;
        }
        uintptr_t pref  = opt.ImageBase;
        uintptr_t delta = reinterpret_cast<uintptr_t>(imageBase) - pref;
        // 链接时 VA（preferredBase 区间）→ +delta；已修正（imageBase 区间）直接用
        if (start >= pref && start < pref + opt.SizeOfImage) start += delta;
        if (end >= pref && end < pref + opt.SizeOfImage) end += delta;
        if (idx >= pref && idx < pref + opt.SizeOfImage) idx += delta;
        size_t tlsSize = static_cast<size_t>(end - start);
        if (tlsSize > 0x100000) {
            DebugLog("[loader] TLS 数据: size=0x%zX 异常过大，跳过", tlsSize);
            return;
        }
        void* tlsData = VirtualAlloc(nullptr, tlsSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!tlsData) { DebugLog("[loader] TLS 数据: VirtualAlloc 失败"); return; }
        DWORD tlsIndex = 0;
        bool ok = SafeTlsMount(idx, start, tlsData, tlsSize, &tlsIndex);
        if (!ok) {
            VirtualFree(tlsData, 0, MEM_RELEASE);
            DebugLog("[loader] TLS 数据: 挂载失败，放弃");
            return;
        }
        DebugLog("[loader] TLS 数据: size=0x%zX index=%u data=%p", tlsSize, tlsIndex, tlsData);
    }

    // ---------- .pdata 异常展开表注册 ----------
    // 真实 C++ 目标（Hanbot）抛 C++ 异常（0xE06D7363）时，系统展开器（RtlUnwindEx）需要
    // RtlLookupFunctionEntry 能查到【当前 RIP 所在函数】的展开数据。手动映射的 payload
    // 不在系统模块表，默认查不到 → 异常无法展开 → 未捕获崩溃。解法：把 payload 的
    // .pdata（RUNTIME_FUNCTION 数组，链接器生成、完整正确）用 RtlAddFunctionTable 注册。
    // 【CI 36 教训】此前 test_payload 的 .pdata 仅 2 条且不完整 → 注册后展开死循环 0xC0000005。
    // 本实现对每条做防御校验（Begin/End/UnwindData 实际 RVA 必须落在 SizeOfImage 内），
    // 任一条越界则整体不注册（保守，避免引入死循环）。
    static void RegisterPdata(void* imageBase, const IMAGE_OPTIONAL_HEADER64& opt)
    {
        auto& dir = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if (!dir.VirtualAddress || dir.Size < sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY)) {
            DebugLog("[loader] .pdata: 无异常目录，跳过");
            return;
        }
        DWORD count = dir.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);
        BYTE* base = reinterpret_cast<BYTE*>(imageBase);
        auto* rf = reinterpret_cast<IMAGE_RUNTIME_FUNCTION_ENTRY*>(base + dir.VirtualAddress);
        for (DWORD i = 0; i < count; i++) {
            // UnwindData 低 2 位是标志（chain 等），实际 RVA = UnwindData & ~3
            DWORD uwd = rf[i].UnwindData & ~3u;
            if (rf[i].BeginAddress >= opt.SizeOfImage ||
                rf[i].EndAddress   >  opt.SizeOfImage ||
                uwd >= opt.SizeOfImage) {
                DebugLog("[loader] .pdata: 条目 %u 越界(Begin=0x%X End=0x%X Unwind=0x%X)，整体跳过注册",
                         i, (unsigned)rf[i].BeginAddress, (unsigned)rf[i].EndAddress, (unsigned)uwd);
                return;
            }
        }
        BOOLEAN ok = SafeRtlAddFunctionTable(rf, count, reinterpret_cast<DWORD64>(imageBase));
        DebugLog("[loader] .pdata 注册: count=%u base=%p ok=%d", count, imageBase, (int)ok);
    }

    // ---------- TLS 回调 ----------
    static bool RunTlsCallbacks(void* imageBase, const IMAGE_OPTIONAL_HEADER64& opt)
    {
        auto& dir = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
        BYTE* base = reinterpret_cast<BYTE*>(imageBase);
        // 【CI 57 诊断】崩溃在「执行 TLS 回调」且首个 TLS 诊断未打出 → 读 TLS 目录结构时 AV。
        // 打印 TLS_RVA/SizeOfImage/tls 指针定位；并防御：TLS 目录地址无效则跳过（不崩）。
        DebugLog("[loader] TLS 回调 入口: TLS_RVA=0x%X SizeOfImage=0x%X imageBase=%p",
                 dir.VirtualAddress, opt.SizeOfImage, imageBase);
        MEMORY_BASIC_INFORMATION mbiTls = {};
        if (dir.VirtualAddress >= opt.SizeOfImage ||
            VirtualQuery(reinterpret_cast<LPCVOID>(base + dir.VirtualAddress), &mbiTls, sizeof(mbiTls)) == 0 ||
            mbiTls.State != MEM_COMMIT) {
            DebugLog("[loader] TLS 回调跳过: TLS_RVA=0x%X 超出/不可读", dir.VirtualAddress);
            return true;
        }
        auto* tls = reinterpret_cast<IMAGE_TLS_DIRECTORY64*>(base + dir.VirtualAddress);
        uintptr_t aoc = static_cast<uintptr_t>(tls->AddressOfCallBacks);
        DebugLog("[loader] TLS 回调 tls=%p AddressOfCallBacks=0x%llX",
                 (void*)tls, (unsigned long long)tls->AddressOfCallBacks);
        if (!aoc) return true;
        // 【CI 55/58 根因】AddressOfCallBacks 是【链接时 VA】（按 preferredBase 算），但
        // TLS 目录结构在 .rdata 节内 → ApplyRelocations 已把它修正到 imageBase 基址
        // （CI 58 实测值 0x234...=imageBase 形式）。不能无条件 +delta（会二次修正）。
        // 三段判断：已修正(imageBase 区间)直接用 / 未修正(preferredBase 区间)+delta / 都超则跳过。
        uintptr_t pref  = opt.ImageBase;
        uintptr_t delta = reinterpret_cast<uintptr_t>(imageBase) - pref;
        uintptr_t cbAddr = 0;
        if (aoc >= reinterpret_cast<uintptr_t>(imageBase) &&
            aoc < reinterpret_cast<uintptr_t>(imageBase) + opt.SizeOfImage)
            cbAddr = aoc;                                  // 已重定位修正
        else if (aoc >= pref && aoc < pref + opt.SizeOfImage)
            cbAddr = aoc + delta;                          // 仍是链接时 VA
        else {
            DebugLog("[loader] TLS 回调跳过: AddressOfCallBacks=0x%llX 超镜像范围", (unsigned long long)aoc);
            return true;
        }
        // 防御：回调数组必须 COMMIT 可读，否则跳过（CI 58：修正后 cb 指向镜像外 → 读崩）
        MEMORY_BASIC_INFORMATION mbiCb = {};
        if (VirtualQuery(reinterpret_cast<LPCVOID>(cbAddr), &mbiCb, sizeof(mbiCb)) == 0 ||
            mbiCb.State != MEM_COMMIT ||
            (mbiCb.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                              PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) == 0) {
            DebugLog("[loader] TLS 回调跳过: 回调数组不可读 cb=%p", (void*)cbAddr);
            return true;
        }
        // 【CI 56】回调执行前临时把镜像置为可执行：门控前代码页还是 RW，
        // 执行回调代码会被 DEP/NX 拦截 → 0xC0000005（崩溃地址落在 stub 模块附近）。
        // 执行完由门控循环重新设置各页保护。
        DWORD oldProt = 0;
        VirtualProtect(imageBase, opt.SizeOfImage, PAGE_EXECUTE_READWRITE, &oldProt);
        uint64_t* cb = reinterpret_cast<uint64_t*>(cbAddr);
        DebugLog("[loader] TLS 回调: cb=%p cb[0]=0x%llX", (void*)cb,
                 (unsigned long long)(cb ? *cb : 0));
        for (uint32_t i = 0; cb[i]; i++) {
            uintptr_t callAddr = static_cast<uintptr_t>(cb[i]);
            // 若回调地址仍是链接时 VA（preferredBase 区间）→ 手动 +delta 修正
            if (callAddr >= pref && callAddr < pref + opt.SizeOfImage)
                callAddr += delta;
            DebugLog("[loader] TLS 回调 #%u -> 0x%llX", i, (unsigned long long)callAddr);
            auto fn = reinterpret_cast<void(WINAPI*)(PVOID, DWORD, PVOID)>(callAddr);
            fn(imageBase, DLL_PROCESS_ATTACH, nullptr);
            DebugLog("[loader] TLS 回调 #%u 返回", i);
        }
        return true;
    }

    // ---------- 节保护 ----------
    static void ProtectSections(void* imageBase, const IMAGE_NT_HEADERS* nt)
    {
        BYTE* base = reinterpret_cast<BYTE*>(imageBase);
        DWORD sizeOfImage = nt->OptionalHeader.SizeOfImage;
        IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
            DWORD va  = sec[i].VirtualAddress;
            DWORD vsz = sec[i].Misc.VirtualSize;
            DWORD sz  = vsz ? vsz : sec[i].SizeOfRawData;
            if (va + sz > sizeOfImage) sz = sizeOfImage - va;
            DWORD prot = PAGE_READWRITE;
            if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
                prot = PAGE_EXECUTE_READ;
            } else if (sec[i].Characteristics & IMAGE_SCN_MEM_READ) {
                prot = PAGE_READONLY;
            }
            DWORD old = 0;
            VirtualProtect(base + va, sz, prot, &old);
        }
        (void)nt;
    }

    // ---------- 对抗自动脱壳（P2.4） ----------
    // 在加载修复完成后调用：覆写内存中 PE 头的关键字段，使 Scylla / ImpRec 等
    // 自动脱壳工具无法自动识别导入表 / 重定位 / 节结构。
    // 运行期此时已不再依赖 PE 头（导入/重定位/TLS 均已修复完毕），覆写安全。
    static void CorruptHeader(void* imageBase)
    {
        if (!imageBase) return;
        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(imageBase);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
        auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(
            reinterpret_cast<uintptr_t>(imageBase) + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return;

        // 1) 破坏 NT 签名（“PE\0\0” -> 0），让自动搜索的 MZ+PE 特征失效
        nt->Signature = 0;

        // 2) 节数量清零，破坏节表解析
        nt->FileHeader.NumberOfSections = 0;

        // 3) 清空全部数据目录（导入 / IAT / 重定位 / TLS / 异常 / 资源…）
        for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++) {
            nt->OptionalHeader.DataDirectory[i].VirtualAddress = 0;
            nt->OptionalHeader.DataDirectory[i].Size = 0;
        }

        // 4) 覆写首个节表项（节名/特征）为垃圾，进一步干扰节重建
        IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
        memset(sec, 0xCC, sizeof(IMAGE_SECTION_HEADER));
    }
};

} // namespace pearmor
