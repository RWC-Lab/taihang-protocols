/****************************************************************************
 * @file      okvs.hpp
 * @brief     Oblivious Key-Value Store primitive.
 * @details   Implements the oblivious key-value store as described in
 *            "Blazing Fast PSI from Improved OKVS and Subfield VOLE":
 *            <https://eprint.iacr.org/2022/320>
 *            References the open-source implementation available at:
 *            <https://github.com/Visa-Research/volepsi.git>
 * @author    Yang Cao
 *****************************************************************************/

#ifndef TAIHANG_PROTOCOLS_OKVS_HPP
#define TAIHANG_PROTOCOLS_OKVS_HPP

#include <taihang/crypto/block.hpp>
#include <taihang/crypto/prg.hpp>

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

namespace taihang::mpc::okvs {

/**
 * @enum DenseType
 * @brief Dense-column arithmetic used by Paxos/Baxos OKVS.
 */
enum class DenseType {
    Binary,
    Gf128,
};

// BlockArrayValue supports variable value_type by changing the length of var[].
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

/**
 * @struct PublicParameters
 * @brief Parameters defining an OKVS encoding.
 */
struct PublicParameters {
    size_t item_num = 0;
    size_t bin_size = 0;
    size_t bin_num = 0;
    size_t item_num_per_bin = 0;

    uint8_t sparse_weight = 3;
    size_t statistical_security_parameter = 40;
    DenseType dense_type = DenseType::Gf128;

    size_t sparse_size = 0;
    size_t dense_size = 0;
    size_t total_size = 0;   // per-bin OKVS length
    size_t storage_size = 0; // full encoded vector length

    Block seed = kZeroBlock;

    std::string format() const;

    friend std::ostream& operator<<(std::ostream& os, const PublicParameters& pp);
    friend std::istream& operator>>(std::istream& is, PublicParameters& pp);
};

/**
 * @brief Constructs public parameters for the OKVS primitive.
 */
PublicParameters setup(size_t item_num,
                       size_t bin_size,
                       uint8_t sparse_weight = 3,
                       size_t statistical_security_parameter = 40,
                       DenseType dense_type = DenseType::Gf128,
                       const Block& seed = kZeroBlock);

/**
 * @brief Encodes key-value pairs into an OKVS storage vector.
 */
std::vector<Block> encode(const PublicParameters& pp,
                          const std::vector<Block>& keys,
                          const std::vector<Block>& values,
                          prg::Seed* prng = nullptr);

/**
 * @brief Decodes values associated with keys from an OKVS storage vector.
 */
std::vector<Block> decode(const PublicParameters& pp,
                          const std::vector<Block>& keys,
                          const std::vector<Block>& encoded);

} // namespace taihang::mpc::okvs

#endif // TAIHANG_PROTOCOLS_OKVS_HPP
