/****************************************************************************
 * @file      vole.hpp
 * @brief     Vector Oblivious Linear Evaluation over GF(2^128).
 * @author    This file is part of Taihang, developed by Yu Chen.
 *****************************************************************************/

#ifndef TAIHANG_PROTOCOLS_VOLE_HPP
#define TAIHANG_PROTOCOLS_VOLE_HPP

#include <taihang/crypto/block.hpp>
#include <taihang/mpc/ot/alsz_ote.hpp>
#include <taihang/net/net_io.hpp>

#include <cstddef>
#include <iostream>
#include <string>
#include <vector>

namespace taihang::mpc::vole {

constexpr size_t kDefaultPprfNum = 128;

/**
 * @struct PublicParameters
 * @brief Parameters for VOLE generation over GF(2^128).
 */
struct PublicParameters {
    size_t base_len = alsz_ote::kBaseLen;
    size_t pprf_num = kDefaultPprfNum;
    alsz_ote::PublicParameters ote_pp;

    std::string format() const;

    friend std::ostream& operator<<(std::ostream& os, const PublicParameters& pp);
    friend std::istream& operator>>(std::istream& is, PublicParameters& pp);
};

/**
 * @brief Constructs VOLE parameters using ALSZ OTE as the OT-extension backend.
 */
PublicParameters setup(int base_ot_curve_id,
                       size_t base_len = alsz_ote::kBaseLen,
                       size_t pprf_num = kDefaultPprfNum);

/**
 * @brief Party A obtains vectors a and c.
 *
 * Together with party_b(), the outputs satisfy b_i = c_i + a_i * delta over
 * GF(2^128). The returned vector is a; vec_c is filled in-place.
 */
std::vector<Block> party_a(net::NetIO& io,
                           const PublicParameters& pp,
                           size_t item_num,
                           std::vector<Block>& vec_c);

/**
 * @brief Party B obtains vector b using its correlation value delta.
 */
void party_b(net::NetIO& io,
             const PublicParameters& pp,
             size_t item_num,
             std::vector<Block>& vec_b,
             const Block& delta);

} // namespace taihang::mpc::vole

#endif // TAIHANG_PROTOCOLS_VOLE_HPP
