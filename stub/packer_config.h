#pragma once
#include <cstdint>
// ============================================================================
// 由 pearmor-packer 生成的壳配置（占位版）
// 真实值由打包流程生成: packer <in.exe> packer_config.h，随后重新编译 stub。
//
// P2 字段变更：二进制里不再写死密钥，改为 PEARMOR_SEED（随机种子）；
// 运行时由 Stub 用 KDF 派生 innerKey / outerKey（分层密钥）。
//   - PEARMOR_ENC_INDEX：外层密钥加密后的块索引（每页是否代码页）
//   - PEARMOR_SEED     ：随机种子（二进制里唯一的密钥来源）
// 占位版给极小值，仅供“未打包先编译”通过；真实值由打包器生成。
// ============================================================================

#define PEARMOR_MAGIC 0x524F414D52414550ULL // "PEARMOR"
#define PEARMOR_PAGE_SIZE 0x1000
#define PEARMOR_PAGE_COUNT 1U
#define PEARMOR_PAYLOAD_LEN 4096ULL

static const unsigned char PEARMOR_PAYLOAD[4096] = { 0x00 };
static const uint32_t PEARMOR_PAGE_CRC[1] = { 0 };

static const unsigned char PEARMOR_SEED[32] = {
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
};

static const unsigned char PEARMOR_ENC_INDEX[16] = { 0x00 };
