/****************************************************************************
 * @file      ote_oprf.hpp
 * @brief     OTE-based oblivious PRF.
 * @author    This file is part of Taihang, developed by Yu Chen.
 *****************************************************************************/

#ifndef TAIHANG_PROTOCOLS_OTE_OPRF_HPP
#define TAIHANG_PROTOCOLS_OTE_OPRF_HPP

#include <taihang/crypto/block.hpp>
#include <taihang/mpc/ot/naor_pinkas_ot.hpp>
#include <taihang/net/net_io.hpp>

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

namespace taihang::mpc::ote_oprf {

/**
 * @struct PublicParameters
 * @brief Parameters for the OTE-based OPRF domain.
 */
struct PublicParameters {
    int base_ot_curve_id = 0;

    size_t key_size = 0;
    size_t range_size = sizeof(Block);
    size_t statistical_security_parameter = 40;

    size_t input_num = 0;
    size_t matrix_height = 0;
    size_t log_matrix_height = 0;
    size_t matrix_width = 0;
    size_t batch_size = 0;

    Block common_seed = kZeroBlock;
    np_ot::PublicParameters npot_part;

    std::string format() const;

    friend std::ostream& operator<<(std::ostream& os, const PublicParameters& pp);
    friend std::istream& operator>>(std::istream& is, PublicParameters& pp);
};

/**
 * @brief Constructs public parameters for OTE-based OPRF.
 */
PublicParameters setup(int base_ot_curve_id,
                       size_t log_input_num,
                       size_t statistical_security_parameter = 40,
                       const Block& common_seed = kZeroBlock);

/**
 * @brief Sender runs the interactive protocol and returns the OPRF key.
 */
std::vector<uint8_t> sender(net::NetIO& io, const PublicParameters& pp);

/**
 * @brief Receiver runs the interactive protocol and obtains F_k(x_i).
 */
std::vector<std::vector<uint8_t>> receiver(net::NetIO& io,
                                           const PublicParameters& pp,
                                           const std::vector<Block>& vec_x);

/**
 * @brief Locally evaluates the sender OPRF key on arbitrary inputs.
 */
std::vector<std::vector<uint8_t>> evaluate(const PublicParameters& pp,
                                           const std::vector<uint8_t>& key,
                                           const std::vector<Block>& vec_y);

} // namespace taihang::mpc::ote_oprf

#endif // TAIHANG_PROTOCOLS_OTE_OPRF_HPP
