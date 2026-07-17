/****************************************************************************
 * @file      vole_oprf.hpp
 * @brief     VOLE-based oblivious PRF.
 * @author    This file is part of Taihang, developed by Yu Chen.
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
    size_t key_size = 0;
    size_t range_size = sizeof(Block);
    size_t statistical_security_parameter = 40;

    size_t okvs_bin_size = 0;
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
