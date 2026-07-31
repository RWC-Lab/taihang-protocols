/****************************************************************************
 * @file      vole_oprf.cpp
 * @brief     VOLE-based oblivious PRF.
 * @author    This file is part of Taihang, developed by Yu Chen.
 *****************************************************************************/

#include <taihang/mpc/oprf/vole_oprf.hpp>
#include <taihang/common/check.hpp>
#include <taihang/common/logger.hpp>
#include <taihang/crypto/prg.hpp>
#include <taihang/mpc/okvs/okvs_utility.hpp>

#include <cmath>
#include <format>
#include <sstream>
#include <stdexcept>

namespace taihang::mpc::vole_oprf {

namespace {

okvs::PublicParameters okvs_parameters_with_seed(const PublicParameters& pp, const Block& seed) {
    auto okvs_pp = pp.okvs_pp;
    okvs_pp.seed = seed;
    return okvs_pp;
}

} // namespace

std::string PublicParameters::format() const {
    std::ostringstream oss;
    oss << "[VOLE-based OPRF PublicParameters]\n";
    oss << "Base OT curve ID               :" << base_ot_curve_id << "\n";
    oss << "Input number                   :" << input_num << "\n";
    oss << "log2(input number)             :" << log_input_num << "\n";
    oss << "Key size                       :" << key_size << "\n";
    oss << "Range size                     :" << range_size << "\n";
    oss << "Statistical security parameter :" << statistical_security_parameter << "\n";
    oss << "OKVS bin size                  :" << okvs_bin_size << "\n";
    oss << "OKVS output size               :" << okvs_output_size << "\n";
    oss << okvs_pp.format();
    oss << vole_pp.format();
    return oss.str();
}

std::ostream& operator<<(std::ostream& os, const PublicParameters& pp) {
    os << pp.base_ot_curve_id << " "
       << pp.log_input_num << " "
       << pp.statistical_security_parameter << " "
       << pp.okvs_bin_size;
    return os;
}

std::istream& operator>>(std::istream& is, PublicParameters& pp) {
    int base_ot_curve_id = 0;
    size_t log_input_num = 0;
    size_t statistical_security_parameter = 0;
    size_t okvs_bin_size = 0;

    is >> base_ot_curve_id
       >> log_input_num
       >> statistical_security_parameter
       >> okvs_bin_size;

    if (is) {
        pp = setup(base_ot_curve_id, log_input_num, statistical_security_parameter, okvs_bin_size);
    }
    return is;
}

PublicParameters setup(int base_ot_curve_id,
                       size_t log_input_num,
                       size_t statistical_security_parameter,
                       size_t okvs_bin_size) {
    TAIHANG_ASSERT(log_input_num >= 3, "VOLE-based OPRF requires at least 8 inputs.");

    PublicParameters pp;
    pp.base_ot_curve_id = base_ot_curve_id;
    pp.log_input_num = log_input_num;
    pp.input_num = 1ULL << log_input_num;
    pp.statistical_security_parameter = statistical_security_parameter;

    pp.okvs_bin_size = (okvs_bin_size == 0) ? (1ULL << 15) : okvs_bin_size;
    if ((pp.input_num >> 7) > (1ULL << 15) && okvs_bin_size == 0) {
        pp.okvs_bin_size = pp.input_num >> 7;
    }

    pp.okvs_pp = okvs::setup(pp.input_num,
                             pp.okvs_bin_size,
                             3,
                             pp.statistical_security_parameter,
                             okvs::DenseType::Gf128,
                             kZeroBlock);
    pp.okvs_output_size = pp.okvs_pp.storage_size;
    pp.key_size = sizeof(Block) * pp.okvs_output_size;
    pp.range_size = sizeof(Block);
    pp.vole_pp = vole::setup(base_ot_curve_id);

    return pp;
}

std::vector<Block> receiver(net::NetIO& io,
                            const PublicParameters& pp,
                            const std::vector<Block>& vec_x) {
    TAIHANG_TIMER("VOLE-based OPRF:", "Receiver total execution time");
    TAIHANG_ASSERT(vec_x.size() <= pp.input_num, "VOLE OPRF receiver input size exceeds parameter capacity.");

    auto okvs_seed = prg::set_seed(nullptr, 0);
    const Block okvs_seed_block = prg::gen_random_blocks(okvs_seed, 1)[0];
    auto round_okvs_pp = okvs_parameters_with_seed(pp, okvs_seed_block);

    std::vector<Block> zero_values(vec_x.size(), kZeroBlock);
    std::vector<Block> p = okvs::encode(round_okvs_pp, vec_x, zero_values, nullptr);

    std::vector<Block> vec_c;
    std::vector<Block> vec_a = vole::party_a(io, pp.vole_pp, pp.okvs_output_size, vec_c);

    io.send(okvs_seed_block);

    for (size_t i = 0; i < p.size(); ++i) {
        p[i] ^= vec_a[i];
    }

    io.send(p);

    TAIHANG_LOG("VOLE-based OPRF [step 1]:",
                std::format("Receiver ===> masked OKVS correction ===> Sender [{:.2f} MB]",
                            static_cast<double>(p.size() * sizeof(Block)) / (1024 * 1024)));

    return okvs::decode(round_okvs_pp, vec_x, vec_c);
}

SecretKey sender(net::NetIO& io, const PublicParameters& pp) {
    TAIHANG_TIMER("VOLE-based OPRF:", "Sender total execution time");

    auto delta_seed = prg::set_seed(nullptr, 0);
    const Block delta = prg::gen_random_blocks(delta_seed, 1)[0];

    std::vector<Block> key;
    vole::party_b(io, pp.vole_pp, pp.okvs_output_size, key, delta);

    Block okvs_seed_block;
    io.recv(okvs_seed_block);

    std::vector<Block> correction(pp.okvs_output_size);
    io.recv(correction);

    for (size_t i = 0; i < key.size(); ++i) {
        key[i] ^= okvs::gf128_mul(delta, correction[i]);
    }

    TAIHANG_LOG("VOLE-based OPRF [step 2]:",
                std::format("Sender derives OPRF key [{} blocks]", key.size()));

    SecretKey secret_key;
    secret_key.okvs_seed = okvs_seed_block;
    secret_key.encoded_key = std::move(key);
    return secret_key;
}

std::vector<Block> evaluate(const PublicParameters& pp,
                            const SecretKey& oprf_key,
                            const std::vector<Block>& vec_y) {
    TAIHANG_ASSERT(vec_y.size() <= pp.input_num, "VOLE OPRF evaluation input size exceeds parameter capacity.");
    if (oprf_key.encoded_key.size() != pp.okvs_output_size) {
        throw std::invalid_argument("VOLE OPRF key size mismatch.");
    }
    auto round_okvs_pp = okvs_parameters_with_seed(pp, oprf_key.okvs_seed);
    return okvs::decode(round_okvs_pp, vec_y, oprf_key.encoded_key);
}

} // namespace taihang::mpc::vole_oprf
