/****************************************************************************
 * @file      vole_oprf.hpp
 * @brief     VOLE-based oblivious PRF.
 * @details   VOLE OPRF = VOLE + OKVS.
 * @author    Yang Cao
 *****************************************************************************/

#ifndef TAIHANG_PROTOCOLS_VOLE_OPRF_HPP
#define TAIHANG_PROTOCOLS_VOLE_OPRF_HPP

#include <taihang/crypto/block.hpp>
#include <taihang/mpc/okvs/okvs.hpp>
#include <taihang/mpc/vole/vole.hpp>
#include <taihang/net/net_io.hpp>

#include <cstddef>
#include <iostream>
#include <string>
#include <vector>

namespace taihang::mpc::vole_oprf {

/**
 * @struct PublicParameters
 * @brief Parameters for the VOLE-based OPRF domain.
 */
struct PublicParameters {
    int base_ot_curve_id = 0;

    size_t input_num = 0;
    size_t log_input_num = 0;
    // The key size: sizeof(Block) * okvs_output_size.
    size_t key_size = 0;
    // The range size: sizeof(Block).
    size_t range_size = sizeof(Block);
    size_t statistical_security_parameter = 40;

    // The bin size in multi-threaded OKVS.
    size_t okvs_bin_size = 0;
    // The size of the output vector obtained in the OKVS encoding process.
    size_t okvs_output_size = 0;
    okvs::PublicParameters okvs_pp;
    vole::PublicParameters vole_pp;

    std::string format() const;

    friend std::ostream& operator<<(std::ostream& os, const PublicParameters& pp);
    friend std::istream& operator>>(std::istream& is, PublicParameters& pp);
};

/**
 * @struct SecretKey
 * @brief Sender-side OPRF key material.
 */
struct SecretKey {
    Block okvs_seed = kZeroBlock;
    // The data saved during interaction for local evaluation.
    std::vector<Block> encoded_key;
};

/**
 * @brief Constructs public parameters for VOLE-based OPRF.
 */
PublicParameters setup(int base_ot_curve_id,
                       size_t log_input_num,
                       size_t statistical_security_parameter = 40,
                       size_t okvs_bin_size = 0);

/**
 * @brief Sender runs the interactive protocol and returns the OPRF key.
 */
SecretKey sender(net::NetIO& io, const PublicParameters& pp);

/**
 * @brief Receiver runs the interactive protocol and obtains F_k(x_i).
 */
std::vector<Block> receiver(net::NetIO& io,
                            const PublicParameters& pp,
                            const std::vector<Block>& vec_x);

/**
 * @brief Locally evaluates the sender OPRF key on arbitrary inputs.
 */
std::vector<Block> evaluate(const PublicParameters& pp,
                            const SecretKey& oprf_key,
                            const std::vector<Block>& vec_y);

} // namespace taihang::mpc::vole_oprf

#endif // TAIHANG_PROTOCOLS_VOLE_OPRF_HPP
