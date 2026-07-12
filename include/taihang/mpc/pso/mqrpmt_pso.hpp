/****************************************************************************
 * @file      mqrpmt_pso.hpp
 * @brief     Unified multi-query reverse private membership test (mqRPMT) based 
 *            Private Set Operations (PSO) framework.
 * @details   Declarations for consolidated PSI, PSU, PSI-Card, and PSI-Card-Sum.
 * @author    This file is part of Taihang.
 *****************************************************************************/

#ifndef TAIHANG_MPC_PSO_MQRPMT_PSO_HPP
#define TAIHANG_MPC_PSO_MQRPMT_PSO_HPP

#include <taihang/mpc/rpmt/cwprf_mqrpmt.hpp>
#include <taihang/mpc/ot/alsz_ote.hpp>
#include <taihang/crypto/bigint.hpp>
#include <vector>
#include <optional>
#include <utility>
#include <iostream>

namespace taihang::mpc::mqrpmt_pso {

/**
 * @enum  PsoMode
 * @brief Identifies the target private set operation variant.
 */
enum class PsoMode {
    kIntersection,
    kUnion,
    kCard,
    kCardSum
};

/**
 * @struct PublicParameters
 * @brief Shared cryptographic parameters across all execution modes.
 */
struct PublicParameters {
    alsz_ote::PublicParameters ote_pp;
    cwprf_mqrpmt::PublicParameters mqrpmt_pp;

    size_t log_sender_len = 0;
    size_t log_receiver_len = 0;
    size_t log_sum_bound = 0;    // binary length of SUM_BOUND
    size_t log_value_bound = 0;  // binary length of VALUE_BOUND

    std::shared_ptr<Zn> field_ctx; 

    friend std::ostream& operator<<(std::ostream& os, const PublicParameters& pp);
    friend std::istream& operator>>(std::istream& is, PublicParameters& pp);
};

/**
 * @struct SenderOutput
 * @brief Compact structure containing metrics populated during specific modes (e.g., CardSum).
 */
struct SenderOutput {
    size_t cardinality = 0;
    ZnElement card_sum = ZnElement();
};

/**
 * @struct ReceiverOutput
 * @brief Unified container holding either plain items or calculated metric statistics.
 */
struct ReceiverOutput {
    std::vector<Block> set_result;
    size_t cardinality = 0;
};

// ===========================================================================
// Protocol Setup Interfaces
// ===========================================================================

PublicParameters setup(int base_ot_curve_id,
                       int mqrpmt_curve_id,
                       size_t log_sender_len,
                       size_t log_receiver_len,
                       size_t log_sum_bound = 0,
                       size_t log_value_bound = 0,
                       cwprf_mqrpmt::MembershipMode membership_mode = cwprf_mqrpmt::MembershipMode::BloomFilter,
                       std::optional<size_t> statistical_security_parameter = std::nullopt);

// ===========================================================================
// Unified Core Execution Pipeline
// ===========================================================================

/**
 * @brief Unified Sender entrypoint for all mqRPMT-based PSO variants.
 */
SenderOutput pso_sender(net::NetIO& io, 
                        const PublicParameters& pp, 
                        const std::vector<Block>& vec_x, 
                        PsoMode mode, 
                        const std::vector<ZnElement>& vec_v = {});

/**
 * @brief Unified Receiver entrypoint for all mqRPMT-based PSO variants.
 */
ReceiverOutput pso_receiver(net::NetIO& io, 
                            const PublicParameters& pp, 
                            const std::vector<Block>& vec_y, 
                            PsoMode mode);

} // namespace taihang::mpc::mqrpmt_pso

#endif // TAIHANG_MPC_PSO_MQRPMT_PSO_HPP