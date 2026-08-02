/****************************************************************************
 * @file      mqrpmt_private_id.hpp
 * @brief     Private-ID based on distributed VOLE-based OPRF and mqRPMT-based PSU.
 * @details   Implements Private-ID based on distributed OPRF and PSU.
 * @author    Yang Cao
 *****************************************************************************/

#ifndef TAIHANG_MPC_PSO_MQRPMT_PRIVATE_ID_HPP
#define TAIHANG_MPC_PSO_MQRPMT_PRIVATE_ID_HPP

#include <taihang/mpc/oprf/vole_oprf.hpp>
#include <taihang/mpc/pso/mqrpmt_pso.hpp>

#include <cstddef>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

namespace taihang::mpc::mqrpmt_private_id {

/**
 * @struct PublicParameters
 * @brief Shared parameters for distributed OPRF and mqRPMT-based PSU.
 */
struct PublicParameters {
    vole_oprf::PublicParameters oprf_pp;
    mqrpmt_pso::PublicParameters psu_pp;

    size_t log_sender_len = 0;
    size_t log_receiver_len = 0;
    size_t statistical_security_parameter = 40;
    cwprf_mqrpmt::MembershipMode membership_mode = cwprf_mqrpmt::MembershipMode::PlainSet;

    std::string format() const;

    friend std::ostream& operator<<(std::ostream& os, const PublicParameters& pp);
    friend std::istream& operator>>(std::istream& is, PublicParameters& pp);
};

/**
 * @struct SenderOutput
 * @brief Sender-side Private-ID output.
 */
struct SenderOutput {
    std::vector<Block> union_id;
    std::vector<Block> sender_id;
};

/**
 * @struct ReceiverOutput
 * @brief Receiver-side Private-ID output.
 */
struct ReceiverOutput {
    std::vector<Block> union_id;
    std::vector<Block> receiver_id;
};

/**
 * @brief Constructs parameters for Private-ID.
 */
PublicParameters setup(int base_ot_curve_id,
                       int mqrpmt_curve_id,
                       size_t log_sender_len,
                       size_t log_receiver_len,
                       cwprf_mqrpmt::MembershipMode membership_mode = cwprf_mqrpmt::MembershipMode::BloomFilter,
                       std::optional<size_t> statistical_security_parameter = std::nullopt,
                       size_t okvs_bin_size = 0);

/**
 * @brief Sender executes Private-ID and returns union_id and sender_id.
 */
SenderOutput sender(net::NetIO& io,
                    const PublicParameters& pp,
                    const std::vector<Block>& vec_x);

/**
 * @brief Receiver executes Private-ID and returns union_id and receiver_id.
 */
ReceiverOutput receiver(net::NetIO& io,
                        const PublicParameters& pp,
                        const std::vector<Block>& vec_y);

} // namespace taihang::mpc::mqrpmt_private_id

#endif // TAIHANG_MPC_PSO_MQRPMT_PRIVATE_ID_HPP
