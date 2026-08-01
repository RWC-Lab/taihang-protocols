/****************************************************************************
 * @file      okvs.hpp
 * @brief     Oblivious Key-Value Store primitive.
 * @details   The underlying Paxos/Baxos OKVS code is modified from:
 *            <https://github.com/Visa-Research/volepsi.git>
 * @author    Yang Cao
 *****************************************************************************/

#ifndef TAIHANG_PROTOCOLS_OKVS_HPP
#define TAIHANG_PROTOCOLS_OKVS_HPP

#include <taihang/mpc/okvs/baxos.hpp>

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

namespace taihang::mpc::okvs {

/**
 * @struct PublicParameters
 * @brief Parameters defining an OKVS encoding domain.
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
