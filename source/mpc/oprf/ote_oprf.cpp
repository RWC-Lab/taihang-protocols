/****************************************************************************
 * @file      ote_oprf.cpp
 * @brief     OTE-based oblivious PRF.
 * @author    This file is part of Taihang, developed by Yu Chen.
 *****************************************************************************/

#include <taihang/mpc/oprf/ote_oprf.hpp>
#include <taihang/common/check.hpp>
#include <taihang/common/config.hpp>
#include <taihang/common/logger.hpp>
#include <taihang/crypto/aes.hpp>
#include <taihang/crypto/crypto_hash.hpp>
#include <taihang/crypto/prg.hpp>

#include <algorithm>
#include <array>
#include <cstring>
#include <format>
#include <sstream>
#include <stdexcept>

namespace taihang::mpc::ote_oprf {

namespace {

constexpr size_t kMinLogInputNum = 3;
constexpr size_t kMaxLogInputNum = 32;

size_t matrix_width_for_log_input_num(size_t log_input_num) {
    if (log_input_num <= 10) return 591;
    if (log_input_num <= 12) return 597;
    if (log_input_num <= 14) return 603;
    if (log_input_num <= 16) return 609;
    if (log_input_num <= 18) return 615;
    if (log_input_num <= 20) return 621;
    return 633;
}

std::array<uint64_t, 2> block_to_words(const Block& block) {
    std::array<uint64_t, 2> words{};
    const auto bytes = to_bytes(block);
    std::memcpy(words.data(), bytes.data(), bytes.size());
    return words;
}

Block words_to_block(uint64_t first, uint64_t second) {
    return make_block(second, first);
}

std::vector<Block> encode_inputs(const std::vector<Block>& vec_input, const Block& key) {
    const size_t input_num = vec_input.size();
    if (input_num == 0) {
        return {};
    }

    std::vector<std::vector<uint8_t>> vec_hash(input_num,
                                               std::vector<uint8_t>(cryptohash::kDigestOutputLen));
    std::vector<Block> vec_z0(input_num);
    std::vector<Block> vec_z1(input_num);

    #pragma omp parallel for num_threads(config::thread_num)
    for (size_t i = 0; i < input_num; ++i) {
        cryptohash::digest<taihang::kDefaultHash>(
            reinterpret_cast<const uint8_t*>(vec_input.data() + i),
            sizeof(Block),
            vec_hash[i].data());
        std::memcpy(&vec_z0[i], vec_hash[i].data(), sizeof(Block));
        std::memcpy(&vec_z1[i], vec_hash[i].data() + sizeof(Block), sizeof(Block));
    }

    aes::AESKey aes_enc_key = aes::set_encrypt_key(&key, 128);
    aes::encrypt_ecb(aes_enc_key, vec_z0.data(), vec_z0.data(), input_num);

    std::vector<Block> vec_encoded(input_num);
    #pragma omp parallel for num_threads(config::thread_num)
    for (size_t i = 0; i < input_num; ++i) {
        vec_encoded[i] = vec_z0[i] ^ vec_z1[i];
    }

    return vec_encoded;
}

std::vector<Block> derive_aes_salts(const PublicParameters& pp) {
    const size_t log_height_byte = (pp.log_matrix_height + 7) >> 3;
    const size_t split_bucket_size = sizeof(Block) / log_height_byte;
    const size_t aes_key_num = (pp.matrix_width / split_bucket_size) + 2;

    prg::Seed seed = prg::set_seed(&pp.common_seed, 0);
    return prg::gen_random_blocks(seed, aes_key_num);
}

std::vector<std::vector<uint8_t>> pack_outputs(const PublicParameters& pp,
                                               const std::vector<std::vector<uint8_t>>& matrix_mapping_values) {
    const size_t matrix_width_byte = (pp.matrix_width + 7) >> 3;
    std::vector<std::vector<uint8_t>> matrix_input(pp.matrix_height,
                                                   std::vector<uint8_t>(matrix_width_byte, 0));

    #pragma omp parallel for num_threads(config::thread_num)
    for (size_t low_index = 0; low_index < pp.matrix_height; low_index += pp.batch_size) {
        for (size_t i = 0; i < pp.matrix_width; ++i) {
            for (size_t j = low_index; j < low_index + pp.batch_size; ++j) {
                const uint8_t bit = static_cast<uint8_t>(
                    (matrix_mapping_values[i][j >> 3] >> (j & 7)) & 1U);
                matrix_input[j][i >> 3] |= static_cast<uint8_t>(bit << (i & 7));
            }
        }
    }

    std::vector<std::vector<uint8_t>> result;
    result.reserve(pp.matrix_height);

    for (size_t i = 0; i < pp.matrix_height; ++i) {
        std::array<uint8_t, cryptohash::kDigestOutputLen> digest{};
        cryptohash::digest<taihang::kDefaultHash>(matrix_input[i].data(), matrix_width_byte, digest.data());
        result.emplace_back(digest.begin(), digest.begin() + pp.range_size);
    }

    return result;
}

} // namespace

std::string PublicParameters::format() const {
    std::ostringstream oss;
    oss << "[OTE-based OPRF PublicParameters]\n";
    oss << "Base OT curve ID               :" << base_ot_curve_id << "\n";
    oss << "Key size                       :" << key_size << "\n";
    oss << "Range size                     :" << range_size << "\n";
    oss << "Statistical security parameter :" << statistical_security_parameter << "\n";
    oss << "Input number                   :" << input_num << "\n";
    oss << "Matrix height                  :" << matrix_height << "\n";
    oss << "Log matrix height              :" << log_matrix_height << "\n";
    oss << "Matrix width                   :" << matrix_width << "\n";
    oss << "Batch size                     :" << batch_size << "\n";
    oss << npot_part.format();
    return oss.str();
}

std::ostream& operator<<(std::ostream& os, const PublicParameters& pp) {
    const auto seed_words = block_to_words(pp.common_seed);
    os << pp.base_ot_curve_id << " "
       << pp.log_matrix_height << " "
       << pp.statistical_security_parameter << " "
       << seed_words[0] << " "
       << seed_words[1];
    return os;
}

std::istream& operator>>(std::istream& is, PublicParameters& pp) {
    int base_ot_curve_id = 0;
    size_t log_input_num = 0;
    size_t statistical_security_parameter = 0;
    uint64_t seed_first = 0;
    uint64_t seed_second = 0;

    is >> base_ot_curve_id
       >> log_input_num
       >> statistical_security_parameter
       >> seed_first
       >> seed_second;

    if (is) {
        pp = setup(base_ot_curve_id,
                   log_input_num,
                   statistical_security_parameter,
                   words_to_block(seed_first, seed_second));
    }
    return is;
}

PublicParameters setup(int base_ot_curve_id,
                       size_t log_input_num,
                       size_t statistical_security_parameter,
                       const Block& common_seed) {
    TAIHANG_ASSERT(log_input_num >= kMinLogInputNum,
                   "OTE OPRF requires at least 8 inputs.");
    TAIHANG_ASSERT(log_input_num <= kMaxLogInputNum,
                   "OTE OPRF uses 32-bit location encoding and requires log_input_num <= 32.");

    PublicParameters pp;
    pp.base_ot_curve_id = base_ot_curve_id;
    pp.log_matrix_height = log_input_num;
    pp.input_num = 1ULL << log_input_num;
    pp.matrix_height = pp.input_num;
    pp.statistical_security_parameter = statistical_security_parameter;
    pp.range_size = ((pp.statistical_security_parameter + 2 * pp.log_matrix_height) + 7) >> 3;
    pp.batch_size = (log_input_num < 10) ? (1ULL << (log_input_num / 2)) : 512;
    pp.matrix_width = matrix_width_for_log_input_num(log_input_num);
    pp.key_size = pp.matrix_width * (pp.matrix_height >> 3);
    pp.common_seed = common_seed;
    pp.npot_part = np_ot::setup(base_ot_curve_id);
    return pp;
}

std::vector<uint8_t> sender(net::NetIO& io, const PublicParameters& pp) {
    TAIHANG_TIMER("OTE-based OPRF:", "Sender total execution time");
    TAIHANG_ASSERT(pp.matrix_width > 0, "OTE OPRF setup error: matrix_width must be positive.");

    prg::Seed seed = prg::set_seed(&pp.common_seed, 0);
    std::vector<uint8_t> vec_selection_bit = prg::gen_random_bits(seed, pp.matrix_width);
    std::vector<Block> vec_k = np_ot::receiver(io, pp.npot_part, vec_selection_bit, pp.matrix_width);

    const size_t log_height_byte = (pp.log_matrix_height + 7) >> 3;
    const size_t matrix_height_byte = pp.matrix_height >> 3;
    const size_t split_bucket_size = sizeof(Block) / log_height_byte;

    std::vector<std::vector<uint8_t>> matrix_c(pp.matrix_width, std::vector<uint8_t>(matrix_height_byte));
    for (size_t left_index = 0; left_index < pp.matrix_width; left_index += split_bucket_size) {
        const size_t right_index = std::min(left_index + split_bucket_size, pp.matrix_width);
        const size_t bucket_size = right_index - left_index;

        std::vector<uint8_t> matrix_b(bucket_size * matrix_height_byte);
        io.recv(matrix_b);

        #pragma omp parallel for num_threads(config::thread_num)
        for (size_t i = 0; i < bucket_size; ++i) {
            prg::Seed col_seed = prg::set_seed(&vec_k[left_index + i], 0);
            matrix_c[left_index + i] = prg::gen_random_bytes(col_seed, matrix_height_byte);

            if (vec_selection_bit[left_index + i]) {
                for (size_t j = 0; j < matrix_height_byte; ++j) {
                    matrix_c[left_index + i][j] ^= matrix_b[i * matrix_height_byte + j];
                }
            }
        }
    }

    TAIHANG_LOG("OTE-based OPRF [step 1]:",
                std::format("Receiver ===> matrix_B ===> Sender [{:.2f} MB]",
                            static_cast<double>(pp.matrix_width * matrix_height_byte) / (1024 * 1024)));

    std::vector<uint8_t> key(pp.key_size);
    for (size_t i = 0; i < pp.matrix_width; ++i) {
        std::copy(matrix_c[i].begin(), matrix_c[i].end(), key.begin() + i * matrix_height_byte);
    }

    TAIHANG_LOG("OTE-based OPRF [step 2]:",
                std::format("Sender derives OPRF key [{} bytes]", key.size()));
    return key;
}

std::vector<std::vector<uint8_t>> receiver(net::NetIO& io,
                                           const PublicParameters& pp,
                                           const std::vector<Block>& vec_x) {
    TAIHANG_TIMER("OTE-based OPRF:", "Receiver total execution time");
    TAIHANG_ASSERT(vec_x.size() == pp.input_num, "OTE OPRF receiver input size mismatch.");

    prg::Seed seed = prg::set_seed(&pp.common_seed, 0);
    std::vector<Block> vec_k0 = prg::gen_random_blocks(seed, pp.matrix_width);
    std::vector<Block> vec_k1 = prg::gen_random_blocks(seed, pp.matrix_width);

    np_ot::sender(io, pp.npot_part, vec_k0, vec_k1, pp.matrix_width);

    const size_t log_height_byte = (pp.log_matrix_height + 7) >> 3;
    const size_t matrix_height_byte = pp.matrix_height >> 3;
    const size_t split_bucket_size = sizeof(Block) / log_height_byte;
    const size_t max_location = (1ULL << pp.log_matrix_height) - 1;

    std::vector<Block> vec_salt = derive_aes_salts(pp);
    std::vector<Block> vec_encode_x = encode_inputs(vec_x, vec_salt[0]);

    std::vector<std::vector<uint8_t>> matrix_a(split_bucket_size, std::vector<uint8_t>(matrix_height_byte));
    std::vector<std::vector<uint8_t>> matrix_d(split_bucket_size, std::vector<uint8_t>(matrix_height_byte));
    std::vector<std::vector<uint8_t>> matrix_location(
        split_bucket_size,
        std::vector<uint8_t>(vec_x.size() * log_height_byte + sizeof(uint32_t)));
    std::vector<std::vector<uint8_t>> matrix_mapping_values(pp.matrix_width,
                                                            std::vector<uint8_t>(matrix_height_byte, 0));

    for (size_t left_index = 0; left_index < pp.matrix_width; left_index += split_bucket_size) {
        const size_t right_index = std::min(left_index + split_bucket_size, pp.matrix_width);
        const size_t bucket_size = right_index - left_index;

        aes::AESKey aes_enc_key = aes::set_encrypt_key(&vec_salt[left_index / split_bucket_size + 1], 128);

        #pragma omp parallel for num_threads(config::thread_num)
        for (size_t low_index = 0; low_index < pp.input_num; low_index += pp.batch_size) {
            aes::encrypt_ecb(aes_enc_key,
                             vec_encode_x.data() + low_index,
                             vec_encode_x.data() + low_index,
                             pp.batch_size);

            for (size_t i = 0; i < bucket_size; ++i) {
                for (size_t j = low_index; j < low_index + pp.batch_size; ++j) {
                    std::memcpy(matrix_location[i].data() + j * log_height_byte,
                                reinterpret_cast<uint8_t*>(vec_encode_x.data() + j) + i * log_height_byte,
                                log_height_byte);
                }
            }
        }

        #pragma omp parallel for num_threads(config::thread_num)
        for (size_t i = 0; i < bucket_size; ++i) {
            std::memset(matrix_d[i].data(), 0xFF, matrix_height_byte);
        }

        #pragma omp parallel for num_threads(config::thread_num)
        for (size_t i = 0; i < bucket_size; ++i) {
            for (size_t j = 0; j < pp.input_num; ++j) {
                uint32_t location_in_d = 0;
                std::memcpy(&location_in_d, matrix_location[i].data() + j * log_height_byte, log_height_byte);
                location_in_d &= static_cast<uint32_t>(max_location);
                matrix_d[i][location_in_d >> 3] &= static_cast<uint8_t>(~(1u << (location_in_d & 7)));
            }
        }

        std::vector<std::vector<uint8_t>> matrix_b(bucket_size, std::vector<uint8_t>(matrix_height_byte));
        std::vector<uint8_t> send_matrix_b(bucket_size * matrix_height_byte);

        #pragma omp parallel for num_threads(config::thread_num)
        for (size_t i = 0; i < bucket_size; ++i) {
            prg::Seed col_seed0 = prg::set_seed(&vec_k0[left_index + i], 0);
            prg::Seed col_seed1 = prg::set_seed(&vec_k1[left_index + i], 0);
            matrix_a[i] = prg::gen_random_bytes(col_seed0, matrix_height_byte);
            matrix_b[i] = prg::gen_random_bytes(col_seed1, matrix_height_byte);

            for (size_t j = 0; j < matrix_height_byte; ++j) {
                matrix_b[i][j] ^= matrix_a[i][j] ^ matrix_d[i][j];
                send_matrix_b[i * matrix_height_byte + j] = matrix_b[i][j];
            }
        }

        io.send(send_matrix_b);

        #pragma omp parallel for num_threads(config::thread_num)
        for (size_t i = 0; i < bucket_size; ++i) {
            for (size_t j = 0; j < pp.input_num; ++j) {
                uint32_t location_in_a = 0;
                std::memcpy(&location_in_a, matrix_location[i].data() + j * log_height_byte, log_height_byte);
                location_in_a &= static_cast<uint32_t>(max_location);
                const uint8_t bit = static_cast<uint8_t>(
                    (matrix_a[i][location_in_a >> 3] >> (location_in_a & 7)) & 1U);
                matrix_mapping_values[left_index + i][j >> 3] |= static_cast<uint8_t>(bit << (j & 7));
            }
        }
    }

    TAIHANG_LOG("OTE-based OPRF [step 3]:",
                std::format("Receiver ===> matrix_B ===> Sender [{:.2f} MB]",
                            static_cast<double>(pp.matrix_width * matrix_height_byte) / (1024 * 1024)));

    return pack_outputs(pp, matrix_mapping_values);
}

std::vector<std::vector<uint8_t>> evaluate(const PublicParameters& pp,
                                           const std::vector<uint8_t>& key,
                                           const std::vector<Block>& vec_y) {
    TAIHANG_TIMER("OTE-based OPRF:", "Evaluate total execution time");
    TAIHANG_ASSERT(vec_y.size() == pp.input_num, "OTE OPRF evaluation input size mismatch.");
    if (key.size() != pp.key_size) {
        throw std::invalid_argument("OTE OPRF key size mismatch.");
    }

    const size_t log_height_byte = (pp.log_matrix_height + 7) >> 3;
    const size_t matrix_height_byte = pp.matrix_height >> 3;
    const size_t split_bucket_size = sizeof(Block) / log_height_byte;
    const size_t max_location = (1ULL << pp.log_matrix_height) - 1;

    std::vector<Block> vec_salt = derive_aes_salts(pp);
    std::vector<Block> vec_encode_y = encode_inputs(vec_y, vec_salt[0]);

    std::vector<std::vector<uint8_t>> matrix_c(pp.matrix_width, std::vector<uint8_t>(matrix_height_byte));
    for (size_t i = 0; i < pp.matrix_width; ++i) {
        std::copy(key.begin() + i * matrix_height_byte,
                  key.begin() + (i + 1) * matrix_height_byte,
                  matrix_c[i].begin());
    }

    std::vector<std::vector<uint8_t>> matrix_location(
        split_bucket_size,
        std::vector<uint8_t>(pp.input_num * log_height_byte + sizeof(uint32_t)));
    std::vector<std::vector<uint8_t>> matrix_mapping_values(pp.matrix_width,
                                                            std::vector<uint8_t>(matrix_height_byte, 0));

    for (size_t left_index = 0; left_index < pp.matrix_width; left_index += split_bucket_size) {
        const size_t right_index = std::min(left_index + split_bucket_size, pp.matrix_width);
        const size_t bucket_size = right_index - left_index;

        aes::AESKey aes_enc_key = aes::set_encrypt_key(&vec_salt[left_index / split_bucket_size + 1], 128);

        #pragma omp parallel for num_threads(config::thread_num)
        for (size_t low_index = 0; low_index < pp.input_num; low_index += pp.batch_size) {
            aes::encrypt_ecb(aes_enc_key,
                             vec_encode_y.data() + low_index,
                             vec_encode_y.data() + low_index,
                             pp.batch_size);

            for (size_t i = 0; i < bucket_size; ++i) {
                for (size_t j = low_index; j < low_index + pp.batch_size; ++j) {
                    std::memcpy(matrix_location[i].data() + j * log_height_byte,
                                reinterpret_cast<uint8_t*>(vec_encode_y.data() + j) + i * log_height_byte,
                                log_height_byte);
                }
            }
        }

        #pragma omp parallel for num_threads(config::thread_num)
        for (size_t i = 0; i < bucket_size; ++i) {
            for (size_t j = 0; j < pp.input_num; ++j) {
                uint32_t location = 0;
                std::memcpy(&location, matrix_location[i].data() + j * log_height_byte, log_height_byte);
                location &= static_cast<uint32_t>(max_location);
                const uint8_t bit = static_cast<uint8_t>(
                    (matrix_c[left_index + i][location >> 3] >> (location & 7)) & 1U);
                matrix_mapping_values[left_index + i][j >> 3] |= static_cast<uint8_t>(bit << (j & 7));
            }
        }
    }

    return pack_outputs(pp, matrix_mapping_values);
}

} // namespace taihang::mpc::ote_oprf
