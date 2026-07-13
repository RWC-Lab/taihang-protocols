/****************************************************************************
 * @file      mqrpmt_pso.cpp
 * @brief     Implementation details for the unified mqRPMT PSO pipeline.
 * @author    This file is part of Taihang.
 *****************************************************************************/

#include <taihang/mpc/pso/mqrpmt_pso.hpp>
#include <taihang/common/check.hpp>
#include <taihang/common/logger.hpp>

namespace taihang::mpc::mqrpmt_pso {

const char* get_timer_name(PsoMode mode, bool is_sender)
{
    switch (mode) {
        case PsoMode::kIntersection:
            return is_sender ? "mqRPMT PSI Sender"
                             : "mqRPMT PSI Receiver";

        case PsoMode::kUnion:
            return is_sender ? "mqRPMT PSU Sender"
                             : "mqRPMT PSU Receiver";

        case PsoMode::kCard:
            return is_sender ? "mqRPMT PSI-card Sender"
                             : "mqRPMT PSI-card Receiver";

        case PsoMode::kCardSum:
            return is_sender ? "mqRPMT PSI-card-sum Sender"
                             : "mqRPMT PSI-card-sum Receiver";
    }

    TAIHANG_ASSERT(false, "Unknown PsoMode.");
}

std::ostream& operator<<(std::ostream& os, const PublicParameters& pp) {
    return os << pp.log_sender_len << " " << pp.log_receiver_len << " "
              << pp.log_sum_bound << " " << pp.log_value_bound << " "
              << pp.mqrpmt_pp << " " << pp.ote_pp;
}

std::istream& operator>>(std::istream& is, PublicParameters& pp) {
    return is >> pp.log_sender_len >> pp.log_receiver_len 
              >> pp.log_sum_bound >> pp.log_value_bound
              >> pp.mqrpmt_pp >> pp.ote_pp;
}

PublicParameters setup(int base_ot_curve_id,
                       int mqrpmt_curve_id,
                       size_t log_sender_len,
                       size_t log_receiver_len,
                       size_t log_sum_bound,
                       size_t log_value_bound,
                       cwprf_mqrpmt::MembershipMode membership_mode,
                       std::optional<size_t> statistical_security_parameter) {
    PublicParameters pp;

    // Only enforce bounds and initialize the field if Card-Sum parameters are provided
    if (log_sum_bound > 0 && log_value_bound > 0) {
        TAIHANG_ASSERT(log_sum_bound >= (log_sender_len + log_value_bound), 
                       "Parameters configuration fault: log_sum_bound must be larger than (log_sender_len + log_value_bound).");
        pp.ring_ctx = std::make_shared<Zn>(BigInt(1ULL << pp.log_sum_bound));
    } else {
        pp.ring_ctx = nullptr; 
    }

    pp.log_sender_len = log_sender_len;
    pp.log_receiver_len = log_receiver_len;
    pp.log_sum_bound = log_sum_bound;
    pp.log_value_bound = log_value_bound;
    
    pp.mqrpmt_pp = cwprf_mqrpmt::setup(mqrpmt_curve_id, log_receiver_len, log_sender_len, membership_mode, statistical_security_parameter);
    pp.ote_pp = alsz_ote::setup(base_ot_curve_id);
    return pp;
}

// P2: sender
SenderOutput pso_sender(net::NetIO& io, 
                        const PublicParameters& pp, 
                        const std::vector<Block>& vec_x, 
                        PsoMode mode, 
                        const std::vector<ZnElement>& vec_v) {

    [[maybe_unused]] const char* timer_name = nullptr;
    switch (mode) {
        case PsoMode::kIntersection:{
            timer_name = "mqRPMT PSI Sender";
            break;
        }
        case PsoMode::kUnion:{
            timer_name = "mqRPMT PSU Sender";
            break;
        }
        case PsoMode::kCard:{
            timer_name = "mqRPMT Cardinality Sender";
            break;
        }
        case PsoMode::kCardSum:{
            timer_name = "mqRPMT Cardinality-Sum Sender";
            break;
        }
    }

    TAIHANG_TIMER(timer_name, "Total pipeline execution time");
    const size_t sender_len = 1ULL << pp.log_sender_len;
    TAIHANG_ASSERT(sender_len == vec_x.size(), "Sender configuration fault: Input size mismatch.");

    // Shared execution phase 
    cwprf_mqrpmt::client(io, pp.mqrpmt_pp, vec_x);

    SenderOutput output;

    switch (mode) {
        case PsoMode::kIntersection: [[fallthrough]]; // execute the exact same instructions as the next case below it
        case PsoMode::kUnion: {
            alsz_ote::onesided_sender<alsz_ote::BlockPolicy>(io, pp.ote_pp, vec_x, sender_len);
            break;
        }
        case PsoMode::kCard: {
            break;
        }
        case PsoMode::kCardSum: {
            TAIHANG_ASSERT(pp.ring_ctx != nullptr, "Card-Sum failure: ring_ctx is null. Set log_sum_bound > 0 during setup().");
            TAIHANG_ASSERT(sender_len == vec_v.size(), "Card-Sum execution failure: Associated value size mismatch.");
            // BigInt sum_bound = BigInt::power_of_two(pp.log_sum_bound);
            // Zn field{sum_bound}; 
            std::vector<ZnElement> vec_r = gen_random_znelement_vector(pp.ring_ctx, sender_len);

            // compute the sum of mask
            ZnElement mask = pp.ring_ctx->get_zero();
            for (const auto& r_val : vec_r) {
                mask += r_val;
            }

            std::vector<std::vector<uint8_t>> vec_m0(sender_len);
            std::vector<std::vector<uint8_t>> vec_m1(sender_len);

            #pragma omp parallel for num_threads(config::thread_num)
            for (size_t i = 0; i < sender_len; ++i) {
                vec_m0[i] = vec_r[i].to_bytes();              // r_i
                vec_m1[i] = (vec_v[i] + vec_r[i]).to_bytes(); // r_i + v_i
            }

            alsz_ote::sender<alsz_ote::BytesPolicy>(io, pp.ote_pp, vec_m0, vec_m1, sender_len);

            io.recv(output.cardinality);
            ZnElement masked_sum(pp.ring_ctx); // initialize an Zn Element
            io.recv(masked_sum);
            // recover the actural sum
            output.card_sum = masked_sum - mask;
            break;
        }
    }
    return output;
}

ReceiverOutput pso_receiver(net::NetIO& io, 
                            const PublicParameters& pp, 
                            const std::vector<Block>& vec_y, 
                            PsoMode mode) {

        [[maybe_unused]] const char* timer_name = nullptr;
        switch (mode) {
            case PsoMode::kIntersection:{
                timer_name = "mqRPMT PSI Sender";
                break;
            }
            case PsoMode::kUnion:{
                timer_name = "mqRPMT PSU Sender";
                break;
            }
            case PsoMode::kCard:{
                timer_name = "mqRPMT Cardinality Sender";
                break;
            }
            case PsoMode::kCardSum:{
                timer_name = "mqRPMT Cardinality-Sum Sender";
                break;
            }
        }

    TAIHANG_TIMER(timer_name, "Total pipeline execution time");
    const size_t sender_len = 1ULL << pp.log_sender_len;
    TAIHANG_ASSERT((1ULL << pp.log_receiver_len) == vec_y.size(), "Receiver configuration fault: Input size mismatch.");

    // Shared execution phase
    std::vector<uint8_t> vec_indication_bit = cwprf_mqrpmt::server(io, pp.mqrpmt_pp, vec_y);
    TAIHANG_ASSERT(vec_indication_bit.size() == sender_len, "Internal protocol error: Vector size mutation.");

    ReceiverOutput receiver_output;

    switch (mode) {
        case PsoMode::kIntersection: {
            receiver_output.set_result = alsz_ote::onesided_receiver<alsz_ote::BlockPolicy>(io, pp.ote_pp, vec_indication_bit, sender_len);
            break;
        }
        case PsoMode::kUnion: {
            #pragma omp parallel for num_threads(config::thread_num)
            for (size_t i = 0; i < vec_indication_bit.size(); ++i) {
                vec_indication_bit[i] ^= 0x01;
            }
            std::vector<Block> vec_x_diff = alsz_ote::onesided_receiver<alsz_ote::BlockPolicy>(io, pp.ote_pp, vec_indication_bit, sender_len);
            receiver_output.set_result = vec_y;
            receiver_output.set_result.insert(receiver_output.set_result.end(), vec_x_diff.begin(), vec_x_diff.end());
            break;
        }
        case PsoMode::kCard: {
            for (size_t i = 0; i < vec_indication_bit.size(); ++i) {
                receiver_output.cardinality += vec_indication_bit[i];
            }
            break;
        }
        case PsoMode::kCardSum: {
            TAIHANG_ASSERT(pp.ring_ctx != nullptr, "Card-Sum failure: ring_ctx is null. Set log_sum_bound > 0 during setup().");
            std::vector<std::vector<uint8_t>> vec_result = alsz_ote::receiver<alsz_ote::BytesPolicy>(io, pp.ote_pp, vec_indication_bit, sender_len);

            for (size_t i = 0; i < vec_indication_bit.size(); ++i) {
                receiver_output.cardinality += vec_indication_bit[i];
            }

            ZnElement masked_sum = pp.ring_ctx->get_zero(); 
            for (size_t i = 0; i < vec_result.size(); ++i) {
                ZnElement val(pp.ring_ctx);
                val.from_bytes(vec_result[i]);
                masked_sum += val;
            }

            io.send(receiver_output.cardinality);
            io.send(masked_sum);
            break;
        }
    }
    return receiver_output;
}

} // namespace taihang::mpc::mqrpmt_pso