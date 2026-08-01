/****************************************************************************
 * @file      vole.hpp
 * @brief     Vector Oblivious Linear Evaluation over GF(2^128).
 * @details   This is an implementation of single-point-VOLE(spVOLE) and
 *            t-multi-points-VOLE(t_mpVOLE). Here we concatenate t spVOLE to
 *            get t_mpVOLE. In detail, we implement the protocol in Figure 7
 *            without consistency check.
 *
 *            References:
 *            [WYKW21]: "Wolverine: Fast, Scalable, and Communication-Efficient
 *            Zero-Knowledge Proofs for Boolean and Arithmetic Circuits",
 *            Chenkai Weng, Kang Yang, Jonathan Katz, and Xiao Wang,
 *            IEEE Symposium on Security and Privacy (Oakland), 2021.
 *            <https://eprint.iacr.org/2020/925>
 *
 *            This file also includes the baseVOLE part from Figure 15 with
 *            p = p^r = 2^128, and the Expand-Convolute Code:
 *            [RRT23]: "Expand-Convolute Codes for Pseudorandom Correlation
 *            Generators from LPN", Srinivasan Raghuraman, Peter Rindal and
 *            Titouan Tanguy, CRYPTO 2023.
 *            <https://eprint.iacr.org/2023/882>
 * @author    Yang Cao
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
 */
std::vector<Block> party_a(net::NetIO& io,
                           const PublicParameters& pp,
                           size_t item_num,
                           std::vector<Block>& vec_c);

/**
 * @brief Party B obtains vector b and holds delta.
 */
void party_b(net::NetIO& io,
             const PublicParameters& pp,
             size_t item_num,
             std::vector<Block>& vec_b,
             const Block& delta);

} // namespace taihang::mpc::vole

#endif // TAIHANG_PROTOCOLS_VOLE_HPP
