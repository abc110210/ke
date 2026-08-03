// ============================================================================
// page_crc.h — 轻量页面校验和（FNV-1a 32 位）
// 打包阶段对每页明文算一次，运行时解密后重算比对，被 Patch 直接退出。
// 同时被 packer（生成校验值）与 stub（运行时校验）共用。
// ============================================================================
#pragma once
#include <cstdint>
#include <cstring>

#ifndef PEARMOR_PAGE_SIZE
#define PEARMOR_PAGE_SIZE 0x1000
#endif

namespace pearmor {

// FNV-1a 32 位哈希：快速、够用，不需要密码学强度
inline uint32_t fnv1a32(const void* data, size_t len)
{
    const uint8_t* p = reinterpret_cast<const uint8_t*>(data);
    uint32_t h = 0x811C9DC5u;
    for (size_t i = 0; i < len; i++) {
        h ^= p[i];
        h *= 0x01000193u;
    }
    return h;
}

} // namespace pearmor
