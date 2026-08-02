/****************************************************************************
 * @file      ote_oprf.cpp
 * @brief     OTE-based oblivious PRF.
 * @details   This is an implementation of multi-point OPRF.
 *
 *            References:
 *            [CM-CRYPTO-2020]: Private Set Intersection in the Internet
 *            Setting From Lightweight, Melissa Chase, Peihan Miao,
 *            CRYPTO 2020.
 *            <https://eprint.iacr.org/2020/729>
 *
 *            Modified from:
 *            <https://github.com/peihanmiao/OPRF-PSI>
 *
 *            With modifications:
 *              Support multi-thread programming with OpenMP.
 * @author    Yang Cao
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

constexpr size_t kMinLogInputNum = 3;
constexpr size_t kMaxLogInputNum = 32;

size_t matrix_width_for_log_input_num(size_t log_input_num) {
    // Parameters of matrix width for input set size in page 16 table 1.
    if (log_input_num <= 10) return 591;
    if (log_input_num <= 12) return 597;
    if (log_input_num <= 14) return 603;
    if (log_input_num <= 16) return 609;
    if (log_input_num <= 18) return 615;
    if (log_input_num <= 20) return 621;
    return 633;
}

/*
 * Instantiate a small range PRF F: {0,1}^128 * {0,1}^* -> {0,1}^128 using AES.
 * H1: {0,1}^* -> {0,1}^256
 * H1(x) = (z_0 || z_1)
 * F_k(x) = ECBEnc(k, z_0) xor z_1
 */
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
        // H1(x) = (x_left || x_right).
        std::memcpy(&vec_z0[i], vec_hash[i].data(), sizeof(Block));
        std::memcpy(&vec_z1[i], vec_hash[i].data() + sizeof(Block), sizeof(Block));
    }

    aes::AESKey aes_enc_key = aes::set_encrypt_key(&key, 128);
    aes::encrypt_ecb(aes_enc_key, vec_z0.data(), vec_z0.data(), input_num);

    // Compute ECBEnc(k, x_0) xor x_1.
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
    // aes_key_num = t + 1 (t in page 17).
    const size_t aes_key_num = (pp.matrix_width / split_bucket_size) + 2;

    prg::Seed seed = prg::set_seed(&pp.common_seed, 0);
    return prg::gen_random_blocks(seed, aes_key_num);
}

// Hash each row in matrix_mapping_values to a OUTPUT_LEN string (H2:{0,1}^w -> {0,1}^{ell2}).
std::vector<std::vector<uint8_t>> pack_outputs(const PublicParameters& pp,
                                               const std::vector<std::vector<uint8_t>>& matrix_mapping_values) {
    const size_t matrix_width_byte = (pp.matrix_width + 7) >> 3;
    std::vector<std::vector<uint8_t>> matrix_input(pp.matrix_height,
                                                   std::vector<uint8_t>(matrix_width_byte, 0));

    // Convert matrix_mapping_values[matrix_width][matrix_height_byte] to
    // matrix_input[matrix_height][matrix_width_byte].
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
    uint64_t seed_words[2]{};
    const auto seed_bytes = to_bytes(pp.common_seed);
    std::memcpy(seed_words, seed_bytes.data(), seed_bytes.size());

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
                   make_block(seed_second, seed_first));
    }
    return is;
}

PublicParameters setup(int base_ot_curve_id,
                       size_t log_input_num,
                       size_t statistical_security_parameter,
                       const Block& common_seed) {
    TAIHANG_ASSERT(log_input_num >= kMinLogInputNum,
                   "OTE-based OPRF requires at least 8 inputs.");
    TAIHANG_ASSERT(log_input_num <= kMaxLogInputNum,
                   "OTE-based OPRF uses 32-bit location encoding and requires log_input_num <= 32.");

    PublicParameters pp;
    pp.base_ot_curve_id = base_ot_curve_id;
    pp.log_matrix_height = log_input_num;
    pp.input_num = 1ULL << log_input_num;
    pp.matrix_height = pp.input_num;
    pp.statistical_security_parameter = statistical_security_parameter;
    pp.range_size = ((pp.statistical_security_parameter + 2 * pp.log_matrix_height) + 7) >> 3;
    // Customize BATCH_SIZE w.r.t. LOG_LEN.
    pp.batch_size = (log_input_num < 10) ? (1ULL << (log_input_num / 2)) : 512;
    pp.matrix_width = matrix_width_for_log_input_num(log_input_num);
    pp.key_size = pp.matrix_width * (pp.matrix_height >> 3);
    pp.common_seed = common_seed;
    pp.npot_part = np_ot::setup(base_ot_curve_id);
    return pp;
}

std::vector<uint8_t> sender(net::NetIO& io, const PublicParameters& pp) {
    TAIHANG_TIMER("OTE-based OPRF:", "Sender total execution time");
    TAIHANG_ASSERT(pp.matrix_width > 0, "OTE-based OPRF setup error: matrix_width must be positive.");

    // The sender obtains a matrix with dimension m*w as the OPRF key.

    // Step 1: base OT (page 10 figure 4 item 1).
    prg::Seed seed = prg::set_seed(&pp.common_seed, 0);
    std::vector<uint8_t> vec_selection_bit = prg::gen_random_bits(seed, pp.matrix_width);
    std::vector<Block> vec_k = np_ot::receiver(io, pp.npot_part, vec_selection_bit, pp.matrix_width);

    // Step 2: compute matrix_C[matrix_width][matrix_height] (page 10 figure 4 item 3).
    const size_t log_height_byte = (pp.log_matrix_height + 7) >> 3;
    const size_t matrix_height_byte = pp.matrix_height >> 3;
    const size_t split_bucket_size = sizeof(Block) / log_height_byte;

    std::vector<std::vector<uint8_t>> matrix_c(pp.matrix_width, std::vector<uint8_t>(matrix_height_byte));
    for (size_t left_index = 0; left_index < pp.matrix_width; left_index += split_bucket_size) {
        const size_t right_index = std::min(left_index + split_bucket_size, pp.matrix_width);
        // bucket_size = split_bucket_size at most time, except for the last splited part.
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

    // Flatten 2D matrix_C to 1D key.
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
    TAIHANG_ASSERT(vec_x.size() == pp.input_num, "OTE-based OPRF receiver input size mismatch.");

    // The receiver obtains OPRF values with its input set.

    // Step 1: base OT (page 10 figure 4 item 1).
    prg::Seed seed = prg::set_seed(&pp.common_seed, 0);
    std::vector<Block> vec_k0 = prg::gen_random_blocks(seed, pp.matrix_width);
    std::vector<Block> vec_k1 = prg::gen_random_blocks(seed, pp.matrix_width);

    np_ot::sender(io, pp.npot_part, vec_k0, vec_k1, pp.matrix_width);

    const size_t log_height_byte = (pp.log_matrix_height + 7) >> 3;
    const size_t matrix_height_byte = pp.matrix_height >> 3;
    const size_t split_bucket_size = sizeof(Block) / log_height_byte;
    const size_t max_location = (1ULL << pp.log_matrix_height) - 1;

    std::vector<Block> vec_salt = derive_aes_salts(pp);
    // Step 2: compute F_k(x) (F: {0,1}^128 * {0,1}^* -> {0,1}^128).
    std::vector<Block> vec_encode_x = encode_inputs(vec_x, vec_salt[0]);

    /*
     * Step 3: compute matrix_location[w][m*logm] = {F_k(H(y_i))} and
     * matrix A, B, D in parallel (page 10 figure 4 item 2).
     * F: {0,1}^128 * {0,1}^128 -> {0,1}^{w*logm} is implemented by
     * applying AES ENC t times, t = ceil(w*logm/128).
     * F_k(y) = G_k1(G_k0(y0) xor y1) || ... || G_kt(G_k0(y0) xor y1),
     * PRG(k) -> k0 || k1 || ... || kt.
     * Matrix A, B, D, location are divided into t parts from the matrix_width side.
     */
    std::vector<std::vector<uint8_t>> matrix_a(split_bucket_size, std::vector<uint8_t>(matrix_height_byte));
    std::vector<std::vector<uint8_t>> matrix_d(split_bucket_size, std::vector<uint8_t>(matrix_height_byte));
    // The actual size is matrix_location[w][m*logm].
    std::vector<std::vector<uint8_t>> matrix_location(
        split_bucket_size,
        std::vector<uint8_t>(vec_x.size() * log_height_byte + sizeof(uint32_t)));
    std::vector<std::vector<uint8_t>> matrix_mapping_values(pp.matrix_width,
                                                            std::vector<uint8_t>(matrix_height_byte, 0));

    for (size_t left_index = 0; left_index < pp.matrix_width; left_index += split_bucket_size) {
        const size_t right_index = std::min(left_index + split_bucket_size, pp.matrix_width);
        const size_t bucket_size = right_index - left_index;

        aes::AESKey aes_enc_key = aes::set_encrypt_key(&vec_salt[left_index / split_bucket_size + 1], 128);

        // Step 3-1: compute matrix_location (page 9 figure 3 item 3-(c)).
        #pragma omp parallel for num_threads(config::thread_num)
        for (size_t low_index = 0; low_index < pp.input_num; low_index += pp.batch_size) {
            // Encrypt vec_Fk_Y t times, each time encrypt BATCH_SIZE blocks.
            aes::encrypt_ecb(aes_enc_key,
                             vec_encode_x.data() + low_index,
                             vec_encode_x.data() + low_index,
                             pp.batch_size);

            for (size_t i = 0; i < bucket_size; ++i) {
                for (size_t j = low_index; j < low_index + pp.batch_size; ++j) {
                    // i is the index of bucket_size (matrix_width).
                    // j is the index of input_num, but in the BATCH_SIZE way.
                    // When j = 0, the left log_height_byte columns of
                    // matrix_location is the result of F_k(H(y1)).
                    std::memcpy(matrix_location[i].data() + j * log_height_byte,
                                reinterpret_cast<uint8_t*>(vec_encode_x.data() + j) + i * log_height_byte,
                                log_height_byte);
                }
            }
        }

        #pragma omp parallel for num_threads(config::thread_num)
        for (size_t i = 0; i < bucket_size; ++i) {
            // Initialize an all one matrix_D.
            std::memset(matrix_d[i].data(), 0xFF, matrix_height_byte);
        }

        // Step 3-2: compute matrix_D (page 9 figure 3 item 1-(c)).
        #pragma omp parallel for num_threads(config::thread_num)
        for (size_t i = 0; i < bucket_size; ++i) {
            for (size_t j = 0; j < pp.input_num; ++j) {
                uint32_t location_in_d = 0;
                std::memcpy(&location_in_d, matrix_location[i].data() + j * log_height_byte, log_height_byte);
                location_in_d &= static_cast<uint32_t>(max_location);
                // Get a location from matrix_location, and set that location in matrix_D to 0.
                matrix_d[i][location_in_d >> 3] &= static_cast<uint8_t>(~(1u << (location_in_d & 7)));
            }
        }

        // Step 3-3: compute matrix_B and send to server (page 10 figure 4 item 2).
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

        // Step 3-4: compute mapping values from matrix A
        // (A1[v[1]] || ... || Aw[v[w]]) in page 9 figure 3 item 3-(c).
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

    // Step 4: compute Psi = H2(A1[v[1]] || ... || Aw[v[w]]).
    return pack_outputs(pp, matrix_mapping_values);
}

std::vector<std::vector<uint8_t>> evaluate(const PublicParameters& pp,
                                           const std::vector<uint8_t>& key,
                                           const std::vector<Block>& vec_y) {
    TAIHANG_TIMER("OTE-based OPRF:", "Evaluate total execution time");
    TAIHANG_ASSERT(vec_y.size() == pp.input_num, "OTE-based OPRF evaluation input size mismatch.");
    if (key.size() != pp.key_size) {
        throw std::invalid_argument("OTE-based OPRF key size mismatch.");
    }

    const size_t log_height_byte = (pp.log_matrix_height + 7) >> 3;
    const size_t matrix_height_byte = pp.matrix_height >> 3;
    const size_t split_bucket_size = sizeof(Block) / log_height_byte;
    const size_t max_location = (1ULL << pp.log_matrix_height) - 1;

    std::vector<Block> vec_salt = derive_aes_salts(pp);
    // Step 1: compute F_k(x) (F: {0,1}^128 * {0,1}^* -> {0,1}^128).
    std::vector<Block> vec_encode_y = encode_inputs(vec_y, vec_salt[0]);

    // Fold 1D key to 2D matrix_C.
    std::vector<std::vector<uint8_t>> matrix_c(pp.matrix_width, std::vector<uint8_t>(matrix_height_byte));
    for (size_t i = 0; i < pp.matrix_width; ++i) {
        std::copy(key.begin() + i * matrix_height_byte,
                  key.begin() + (i + 1) * matrix_height_byte,
                  matrix_c[i].begin());
    }

    // The actual size is matrix_location[w][m*logm].
    std::vector<std::vector<uint8_t>> matrix_location(
        split_bucket_size,
        std::vector<uint8_t>(pp.input_num * log_height_byte + sizeof(uint32_t)));
    std::vector<std::vector<uint8_t>> matrix_mapping_values(pp.matrix_width,
                                                            std::vector<uint8_t>(matrix_height_byte, 0));

    /*
     * Step 2: compute v = F_k(H1(x)) in page 9 figure 3 item 3-(b).
     * Extend the range of F from {0,1}^128 to {0,1}^{w*logm} by applying
     * AES Enc t times, t = matrix_width / split_bucket_size.
     */
    for (size_t left_index = 0; left_index < pp.matrix_width; left_index += split_bucket_size) {
        const size_t right_index = std::min(left_index + split_bucket_size, pp.matrix_width);
        const size_t bucket_size = right_index - left_index;

        aes::AESKey aes_enc_key = aes::set_encrypt_key(&vec_salt[left_index / split_bucket_size + 1], 128);

        // Divide matrix_location into t parts from the matrix_width side.
        #pragma omp parallel for num_threads(config::thread_num)
        for (size_t low_index = 0; low_index < pp.input_num; low_index += pp.batch_size) {
            // Encrypt vec_Fk_X t times, each time encrypt BATCH_SIZE blocks.
            aes::encrypt_ecb(aes_enc_key,
                             vec_encode_y.data() + low_index,
                             vec_encode_y.data() + low_index,
                             pp.batch_size);

            for (size_t i = 0; i < bucket_size; ++i) {
                for (size_t j = low_index; j < low_index + pp.batch_size; ++j) {
                    // i is the index of bucket_size (matrix_width).
                    // j is the index of input_num, but in the BATCH_SIZE way.
                    // When j = 0, the left log_height_byte columns of
                    // matrix_location is the result of F_k(H(x1)).
                    std::memcpy(matrix_location[i].data() + j * log_height_byte,
                                reinterpret_cast<uint8_t*>(vec_encode_y.data() + j) + i * log_height_byte,
                                log_height_byte);
                }
            }
        }

        // Compute mapping values from the OPRF key
        // (C1[v[1]] || ... || Cw[v[w]]) in page 9 figure 3 item 3-(b).
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

    // Step 3: compute Psi = H2(C1[v[1]] || ... || Cw[v[w]]).
    return pack_outputs(pp, matrix_mapping_values);
}

} // namespace taihang::mpc::ote_oprf
