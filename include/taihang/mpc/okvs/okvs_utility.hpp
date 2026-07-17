/****************************************************************************
 * @file      okvs_utility.hpp
 * @brief     Utility routines for Paxos/Baxos OKVS.
 *****************************************************************************/

#ifndef TAIHANG_MPC_OKVS_OKVS_UTILITY_HPP
#define TAIHANG_MPC_OKVS_OKVS_UTILITY_HPP

#include <taihang/crypto/block.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace taihang::mpc::okvs {

struct BlockArrayValue {
    Block var[9];

    BlockArrayValue();
    BlockArrayValue operator^(const BlockArrayValue& other) const;
    BlockArrayValue& operator^=(const BlockArrayValue& other);
    bool operator!=(const BlockArrayValue& other) const;
};

struct Divider {
    uint64_t magic;
    uint8_t more;
};

uint64_t divide_u64_do(uint64_t numer, const Divider* denom);
int32_t count_leading_zeros64(uint64_t val);
Divider gen_divider(uint64_t d);
__attribute__((target("avx2"))) void reduce_mod32(uint64_t* vals, Divider* div, const uint64_t& modVal);

template <typename T1, typename T2>
inline T1 gf128_mul(const T1, const T2) { return T1(); }

__attribute__((target("pclmul,sse2"))) Block gf128_mul(Block x, Block y);
BlockArrayValue gf128_mul(BlockArrayValue x, Block y);
Block gf128_inv(Block x);

bool prev_combination(std::vector<uint8_t>& comb, uint64_t n);
bool check_invert_gf128(std::vector<std::vector<Block>>& mat);
uint64_t col_to_dec(std::vector<uint64_t>& binary);
bool check_invert(std::vector<std::vector<uint8_t>>& mat);
uint64_t log2_floor(uint64_t x);
uint64_t log2_ceil(uint64_t x);
uint64_t hashtable_bin_size(uint64_t bin_num, uint64_t item_num, uint8_t lambda);

} // namespace taihang::mpc::okvs

#endif // TAIHANG_MPC_OKVS_OKVS_UTILITY_HPP
