/****************************************************************************
 * @file      mqrpmt_private_id.cpp
 * @brief     Private-ID based on distributed VOLE-based OPRF and mqRPMT-based PSU.
 * @details   Implements Private-ID based on distributed OPRF and PSU.
 * @author    Yang Cao
 *****************************************************************************/

#include <taihang/mpc/pso/mqrpmt_private_id.hpp>
#include <taihang/common/check.hpp>
#include <taihang/common/logger.hpp>

#include <algorithm>
#include <format>
#include <optional>
#include <random>
#include <sstream>

namespace taihang::mpc::mqrpmt_private_id {

std::string PublicParameters::format() const {
    std::ostringstream oss;
    oss << "[mqRPMT Private-ID PublicParameters]\n";
    oss << "Sender log length              :" << log_sender_len << "\n";
    oss << "Receiver log length            :" << log_receiver_len << "\n";
    oss << "Statistical security parameter :" << statistical_security_parameter << "\n";
    oss << "Membership mode                :"
        << (membership_mode == cwprf_mqrpmt::MembershipMode::BloomFilter ? "BloomFilter" : "PlainSet")
        << "\n";
    oss << oprf_pp.format();
    oss << psu_pp.mqrpmt_pp.format();
    oss << psu_pp.ote_pp.format();
    return oss.str();
}

std::ostream& operator<<(std::ostream& os, const PublicParameters& pp) {
    os << pp.log_sender_len << " "
       << pp.log_receiver_len << " "
       << pp.statistical_security_parameter << " "
       << static_cast<int>(pp.membership_mode) << " "
       << pp.oprf_pp << " "
       << pp.psu_pp;
    return os;
}

std::istream& operator>>(std::istream& is, PublicParameters& pp) {
    int membership_mode = 0;
    is >> pp.log_sender_len
       >> pp.log_receiver_len
       >> pp.statistical_security_parameter
       >> membership_mode
       >> pp.oprf_pp
       >> pp.psu_pp;

    if (is) {
        pp.membership_mode = static_cast<cwprf_mqrpmt::MembershipMode>(membership_mode);
    }
    return is;
}

PublicParameters setup(int base_ot_curve_id,
                       int mqrpmt_curve_id,
                       size_t log_sender_len,
                       size_t log_receiver_len,
                       cwprf_mqrpmt::MembershipMode membership_mode,
                       std::optional<size_t> statistical_security_parameter,
                       size_t okvs_bin_size) {
    if (membership_mode == cwprf_mqrpmt::MembershipMode::BloomFilter) {
        TAIHANG_ASSERT(statistical_security_parameter.has_value(),
                       "BloomFilter mode requires statistical_security_parameter.");
    }

    PublicParameters pp;
    pp.log_sender_len = log_sender_len;
    pp.log_receiver_len = log_receiver_len;
    pp.statistical_security_parameter = statistical_security_parameter.value_or(40);
    pp.membership_mode = membership_mode;

    pp.oprf_pp = vole_oprf::setup(base_ot_curve_id,
                                  std::max(log_sender_len, log_receiver_len),
                                  pp.statistical_security_parameter,
                                  okvs_bin_size);

    pp.psu_pp = mqrpmt_pso::setup(
        base_ot_curve_id,
        mqrpmt_curve_id,
        log_sender_len,
        log_receiver_len,
        0,
        0,
        membership_mode,
        membership_mode == cwprf_mqrpmt::MembershipMode::BloomFilter ? statistical_security_parameter
                                                                      : std::nullopt);

    return pp;
}

SenderOutput sender(net::NetIO& io,
                    const PublicParameters& pp,
                    const std::vector<Block>& vec_x) {
    TAIHANG_TIMER("mqRPMT Private-ID Sender:", "Total pipeline execution time");

    const size_t sender_len = size_t{1} << pp.log_sender_len;
    TAIHANG_ASSERT(vec_x.size() == sender_len, "mqRPMT Private-ID sender input size mismatch.");

    // Phase 1: compute sender's ID using distributed OPRF (run OPRF twice).
    // First act as server: compute F_k1(X).
    vole_oprf::SecretKey first_key = vole_oprf::sender(io, pp.oprf_pp);
    std::vector<Block> first_id_part =
        vole_oprf::evaluate(pp.oprf_pp, first_key, vec_x);

    // Then act as client: compute F_k2(X).
    std::vector<Block> second_id_part =
        vole_oprf::receiver(io, pp.oprf_pp, vec_x);

    SenderOutput output;
    TAIHANG_ASSERT(first_id_part.size() == second_id_part.size(),
                   "mqRPMT Private-ID sender OPRF output size mismatch.");
    // Compute F_k(X) = F_k1(X) xor F_k2(X).
    output.sender_id = first_id_part ^ second_id_part;

    // Phase 2: PSU.
    mqrpmt_pso::pso_sender(io,
                           pp.psu_pp,
                           output.sender_id,
                           mqrpmt_pso::PsoMode::kUnion);
    size_t union_id_size = 0;
    io.recv(union_id_size);
    output.union_id.resize(union_id_size);
    io.recv(output.union_id);

    TAIHANG_LOG("mqRPMT Private-ID Sender:",
                std::format("Received union ID set [{} blocks]", output.union_id.size()));
    return output;
}

ReceiverOutput receiver(net::NetIO& io,
                        const PublicParameters& pp,
                        const std::vector<Block>& vec_y) {
    TAIHANG_TIMER("mqRPMT Private-ID Receiver:", "Total pipeline execution time");

    const size_t receiver_len = size_t{1} << pp.log_receiver_len;
    TAIHANG_ASSERT(vec_y.size() == receiver_len, "mqRPMT Private-ID receiver input size mismatch.");

    // Phase 1: compute receiver's ID using distributed OPRF (run OPRF twice).
    // First act as client: compute F_k1(Y).
    std::vector<Block> first_id_part = vole_oprf::receiver(io, pp.oprf_pp, vec_y);

    // Then act as server: compute F_k2(Y).
    vole_oprf::SecretKey second_key = vole_oprf::sender(io, pp.oprf_pp);
    std::vector<Block> second_id_part =
        vole_oprf::evaluate(pp.oprf_pp, second_key, vec_y);

    ReceiverOutput output;
    TAIHANG_ASSERT(first_id_part.size() == second_id_part.size(),
                   "mqRPMT Private-ID receiver OPRF output size mismatch.");
    // Compute F_k(Y) = F_k1(Y) xor F_k2(Y).
    output.receiver_id = first_id_part ^ second_id_part;

    // Phase 2: PSU.
    mqrpmt_pso::ReceiverOutput psu_output =
        mqrpmt_pso::pso_receiver(io,
                                 pp.psu_pp,
                                 output.receiver_id,
                                 mqrpmt_pso::PsoMode::kUnion);

    output.union_id = std::move(psu_output.set_result);
    // Phase 3: Receiver sends shuffled union_id to Sender.
    if (output.union_id.size() > 1) {
        thread_local std::mt19937_64 rng{std::random_device{}()};
        std::shuffle(output.union_id.begin(), output.union_id.end(), rng);
    }
    io.send(output.union_id.size());
    io.send(output.union_id);

    TAIHANG_LOG("mqRPMT Private-ID Receiver:",
                std::format("Receiver ===> shuffled union ID set ===> Sender [{} blocks]",
                            output.union_id.size()));
    return output;
}

} // namespace taihang::mpc::mqrpmt_private_id
