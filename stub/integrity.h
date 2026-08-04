// ============================================================================
// integrity.h — 运行时代码自校验（完整性校验）
// 每个代码页在打包阶段就算好明文 CRC32（FNV-1a），运行时解密后重算比对。
// 一旦内存中的代码被补丁修改（Patch），CRC 不符 → 由调用方触发自毁。
// 也用于周期性重校验已解密的代码页。
// ============================================================================
#pragma once
#include <cstdint>

#include "../common/page_crc.h"

namespace pearmor {
namespace Integrity {

// 每页大小（与加壳器、paged_loader 的 PEARMOR_PAGE_SIZE 一致）
static constexpr uint32_t kPageSize = 0x1000;

// 校验某页明文是否与“运行期基准 CRC”一致。
// 注意：基准必须在重定位/导入修复之后建立（修复会改变代码页内容），
//       故不再比对打包期原始镜像的 CRC，避免误触发自毁。
inline bool VerifyPage(const void* plain, uint32_t expectedCrc)
{
    return fnv1a32(plain, kPageSize) == expectedCrc;
}

} // namespace Integrity
} // namespace pearmor
