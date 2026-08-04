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
            return reinterpret_cast<void*>(moduleBase + fnRva);
        }
    }
    return nullptr;
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
    static void* ResolveSystemImport(uintptr_t hMod, const char* name, DWORD ordinal)
    {
        void* fn = nullptr;
        HMODULE hDll = reinterpret_cast<HMODULE>(hMod);
        if (ordinal) {
            char ordBuf[16];
            snprintf(ordBuf, sizeof(ordBuf), "#%u", ordinal);
            fn = resolveExportFromBase(hMod, ordBuf);
            if (!fn && hDll)
                fn = reinterpret_cast<void*>(GetProcAddress(hDll, MAKEINTRESOURCEA(ordinal)));
        } else {
            fn = resolveExportFromBase(hMod, name);
            if (!fn && hDll)
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
                    if (IMAGE_SNAP_BY_ORDINAL64(intn[i])) {
                        fn = ResolveSystemImport(hMod, nullptr, (DWORD)(intn[i] & 0xFFFF));
                    } else {
                        auto* imp = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(
                            base + static_cast<DWORD>(intn[i]));
                        fn = ResolveSystemImport(hMod,
                            reinterpret_cast<const char*>(imp->Name), 0);
                    }
                    iat[i] = reinterpret_cast<ULONGLONG>(fn);
                }
            }
        }
    }

    // ---------- TLS 回调 ----------
    static bool RunTlsCallbacks(void* imageBase, const IMAGE_OPTIONAL_HEADER64& opt)
    {
        auto& dir = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
        BYTE* base = reinterpret_cast<BYTE*>(imageBase);
        auto* tls = reinterpret_cast<IMAGE_TLS_DIRECTORY64*>(base + dir.VirtualAddress);
        if (!tls->AddressOfCallBacks) return true;
        // 【CI 55 根因】TLS 目录的 AddressOfCallBacks 是【链接时 VA】（按 preferredBase 算），
        // 重定位表不覆盖 PE 头里的 TLS 目录 → 手动加载后必须按 delta 修正到实际基址，
        // 否则指向 0x140000000 未映射区 → 崩溃地址超镜像（workBase+0x354BC0）。
        uintptr_t pref  = opt.ImageBase;
        uintptr_t delta = reinterpret_cast<uintptr_t>(imageBase) - pref;
        uint64_t* cb = reinterpret_cast<uint64_t*>(tls->AddressOfCallBacks + delta);
        DebugLog("[loader] TLS 回调: TLS_RVA=0x%X AddressOfCallBacks=0x%llX 修正后cb=%p cb[0]=0x%llX imageBase=%p",
                 dir.VirtualAddress, (unsigned long long)tls->AddressOfCallBacks,
                 (void*)cb, (unsigned long long)(cb ? *cb : 0), imageBase);
        for (uint32_t i = 0; cb[i]; i++) {
            uintptr_t callAddr = static_cast<uintptr_t>(cb[i]);
            // 若回调地址仍是链接时 VA（preferredBase 区间）→ 手动 +delta 修正
            if (callAddr >= pref && callAddr < pref + opt.SizeOfImage)
                callAddr += delta;
            auto fn = reinterpret_cast<void(WINAPI*)(PVOID, DWORD, PVOID)>(callAddr);
            fn(imageBase, DLL_PROCESS_ATTACH, nullptr);
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
