/****************************
 * @file      naor_pinkas_ot.hpp
 * @brief     Naor-Pinkas Oblivious Transfer (Base OT).
 * @details   Implementation of "Efficient Oblivious Transfer Protocols"
 * https://dl.acm.org/doi/10.5555/365411.365502
 * @author    This file is part of Taihang-Protocols, developed by Yu Chen.
 ****************************/

#ifndef TAIHANG_PROTOCOLS_MPC_NP_OT_HPP
#define TAIHANG_PROTOCOLS_MPC_NP_OT_HPP

#include <taihang/crypto/ec_group.hpp>
#include <taihang/crypto/zn.hpp>
#include <taihang/crypto/block.hpp>
#include <taihang/net/net_io.hpp>
#include <vector>
#include <iostream>
#include <memory>

using namespace taihang::net;

namespace taihang::mpc::np_ot {

/** @brief Public Parameters for Naor-Pinkas OT. */
struct PublicParameters {
    int curve_id;
    std::shared_ptr<ECGroup> group_ctx; // The ECC group context
    std::shared_ptr<Zn> field_ctx;      // The scalar field context
    ECPoint g;                                  // The generator point

    std::string format() const;
    // Serialization
    friend std::ostream& operator<<(std::ostream& os, const PublicParameters& pp);
    friend std::istream& operator>>(std::istream& is, PublicParameters& pp);
};

// --- Core API ---

/** @brief Initialize parameters using curve ID. */
PublicParameters setup(int curve_id);

/**
 * @brief Sender function for Naor-Pinkas OT.
 * @param io Reference to the network IO channel.
 * @param pp Public parameters context.
 * @param vec_m0 Vector of blocks corresponding to bit 0.
 * @param vec_m1 Vector of blocks corresponding to bit 1.
 * @param len Number of OT instances to execute.
 */
void send(NetIO& io, const PublicParameters& pp, const std::vector<Block>& vec_m0, const std::vector<Block>& vec_m1, size_t len);

/**
 * @brief Receiver function for Naor-Pinkas OT.
 * @param io Reference to the network IO channel.
 * @param pp Public parameters context.
 * @param vec_selection_bit Vector of selection bits (0 or 1).
 * @param len Number of OT instances to execute.
 * @return Vector of received blocks corresponding to the selection bits.
 */
std::vector<Block> receive(NetIO& io, const PublicParameters& pp, const std::vector<uint8_t>& vec_selection_bit, size_t len);

} // namespace taihang::mpc::np_ot

#endif // TAIHANG_PROTOCOLS_MPC_NP_OT_HPP