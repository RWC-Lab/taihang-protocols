/****************************************************************************
 * @file      vole.cpp
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

#include <taihang/mpc/vole/vole.hpp>
#include <taihang/common/check.hpp>
#include <taihang/crypto/aes.hpp>
#include <taihang/crypto/prg.hpp>
#include <taihang/mpc/okvs/okvs.hpp>

#include <algorithm>
#include <cmath>
#include <cstring>
#include <sstream>

namespace taihang::mpc::vole {

constexpr size_t kBlockBitLen = sizeof(Block) * 8;
constexpr size_t kSmallVoleThreshold = 2 * kBlockBitLen;
constexpr size_t kMinPprfNum = kBlockBitLen;
/*
 * The range of t is [128,248]:
 * for t_max = max(128, -double(secParam) / d),
 * d = log2(1 - 2 * minDistRatio).
 * In EC Code, a = 24, w = 21, minDistRatio = 0.15, secParam = 128,
 * so t_max = 248.
 */
constexpr size_t kMaxPprfNum = 248;

std::vector<uint32_t> gen_random_mod(uint32_t modulus, uint32_t len, prg::Seed seed) {
    std::vector<uint32_t> values(len);
    if (len == 0) {
        return values;
    }

    const uint32_t block_len = len / 4 + 1;
    std::vector<Block> blocks = prg::gen_random_blocks(seed, block_len);
    std::memcpy(values.data(), blocks.data(), len * sizeof(uint32_t));

    for (auto& value : values) {
        value %= modulus;
    }
    return values;
}

std::vector<uint8_t> block_bits(const Block& block) {
    std::vector<uint8_t> bits(kBlockBitLen);
    const auto bytes = to_bytes(block);
    for (size_t i = 0; i < kBlockBitLen; ++i) {
        const auto byte = static_cast<uint8_t>(bytes[i / 8]);
        bits[i] = static_cast<uint8_t>((byte >> (i % 8)) & 1);
    }
    return bits;
}

void trans_to_bit_vec(uint64_t num, std::vector<uint8_t>& bits, uint8_t len) {
    // For instance: TransToBitVec(13, vec_bit, 6) gives {1,1,0,0,1,0,...}.
    for (uint8_t i = 0; i < len; ++i) {
        bits.insert(bits.begin(), static_cast<uint8_t>((num % 2 == 1) ? 0 : 1));
        num >>= 1;
    }
}

std::vector<Block> ggm_prg(const Block& input) {
    // Use as 1-to-2 PRG.
    auto key = aes::set_encrypt_key(&input, static_cast<int>(kBlockBitLen));
    std::vector<Block> out{make_block(0, 1), make_block(0, 2)};
    aes::encrypt_ecb(key, out.data(), out.data(), out.size());
    return out;
}

Block gadget_inner_product(const std::vector<Block>& vec_x) {
    TAIHANG_ASSERT(vec_x.size() == kBlockBitLen, "VOLE gadget inner product expects one block bit-width.");

    // <g, vec_x> = gf128_mul(2^0, vec_x[0]) + ... + gf128_mul(2^127, vec_x[127]).
    Block out = kZeroBlock;
    for (size_t i = 0; i < kBlockBitLen; ++i) {
        const Block weight = (i < 64) ? make_block(0, 1ULL << i)
                                      : make_block(1ULL << (i - 64), 0);
        out ^= okvs::gf128_mul(weight, vec_x[i]);
    }
    return out;
}

/*
 * Expand-Convolute Code.
 * G * x = B C * x
 * G:{0,1}k x n  B:{0,1}k x n  C:{0,1}n x n
 * dualEncode(vec_x) = expand(accumulate(vec_x))
 */
class ExConvCode {
public:
    void config(prg::Seed seed,
                uint32_t mR = 2,
                uint32_t mExpanderWeight = 21,
                uint32_t mAccumulatorSize = 24) {
        // We can set the value of R, R = codeSize / messageSize.
        ratio_ = mR;
        expander_weight_ = mExpanderWeight;
        accumulator_size_ = mAccumulatorSize;
        seed_ = seed;
    }

    void dual_encode(std::vector<Block>& e) {
        // e[0,1...,k-1] = G * e.
        // dualEncode(vec_x) = expand(accumulate(vec_x)).
        code_size_ = static_cast<uint32_t>(e.size());
        message_size_ = code_size_ / ratio_;

        // d[0,1,...,n-1] = accumulate(e[0,1,...,n-1]).
        std::vector<Block> d(e.begin(), e.end());
        accumulate(d);

        // e is just a volume for d to expand.
        e.resize(message_size_);
        // e[0,1...,k-1] is the final output.
        expand(d, e);
    }

    void dual_encode2(std::vector<Block>& e0, std::vector<Block>& e1) {
        TAIHANG_ASSERT(e0.size() == e1.size(), "VOLE ExConvCode: vector size mismatch.");
        code_size_ = static_cast<uint32_t>(e0.size());
        message_size_ = code_size_ / ratio_;

        // d[0,1,...,n-1] = accumulate(e[0,1,...,n-1]).
        std::vector<Block> d0(e0.begin(), e0.end());
        std::vector<Block> d1(e1.begin(), e1.end());
        accumulate2(d0, d1);

        // e is just a volume for d to expand.
        e0.resize(message_size_);
        e1.resize(message_size_);
        // e[0,1...,k-1] is the final output.
        expand2(d0, d1, e0, e1);
    }

private:
    void accumulate(std::vector<Block>& x) {
        // Accumulate x on itself.
        uint32_t i = 0;
        uint32_t j = 0;
        const uint32_t size = static_cast<uint32_t>(x.size());

        std::vector<uint8_t> rnd = prg::gen_random_bits(seed_, size * accumulator_size_);
        uint8_t* rrnd = rnd.data();
        const auto main = static_cast<uint32_t>(std::max<int64_t>(0, size - accumulator_size_));

        for (; i < main; ++i) {
            j = i + 1;
            for (uint32_t jj = 0; jj < accumulator_size_ - 1; ++jj, ++j, ++rrnd) {
                if (*rrnd == 1) {
                    x[j] ^= x[i];
                }
            }
            x[j] ^= x[i];
        }

        for (; i < size; ++i) {
            j = i + 1;
            const auto remaining = size - j;
            for (uint32_t jj = 0; jj < remaining; ++jj, ++j, ++rrnd) {
                if (*rrnd == 1) {
                    x[j] ^= x[i];
                }
            }
        }
    }

    void accumulate2(std::vector<Block>& x0, std::vector<Block>& x1) {
        uint32_t i = 0;
        uint32_t j = 0;
        const uint32_t size = static_cast<uint32_t>(x0.size());

        // Generate n alpha_i for convolution; alpha_i.size <= accumulatorSize.
        std::vector<uint8_t> rnd = prg::gen_random_bits(seed_, size * accumulator_size_);
        uint8_t* rrnd = rnd.data();
        const auto main = static_cast<uint32_t>(std::max<int64_t>(0, size - accumulator_size_));

        for (; i < main; ++i) {
            j = i + 1;
            for (uint32_t jj = 0; jj < accumulator_size_ - 1; ++jj, ++j, ++rrnd) {
                if (*rrnd == 1) {
                    x0[j] ^= x0[i];
                    x1[j] ^= x1[i];
                }
            }
            x0[j] ^= x0[i];
            x1[j] ^= x1[i];
        }

        for (; i < size; ++i) {
            j = i + 1;
            const auto remaining = size - j;
            for (uint32_t jj = 0; jj < remaining; ++jj, ++j, ++rrnd) {
                if (*rrnd == 1) {
                    x0[j] ^= x0[i];
                    x1[j] ^= x1[i];
                }
            }
        }
    }

    void expand(const std::vector<Block>& e, std::vector<Block>& w) {
        TAIHANG_ASSERT(e.size() == code_size_ && w.size() == message_size_,
                       "VOLE ExConvCode: invalid expand dimensions.");

        // Generate messageSize * expanderWeight random positions in e[0,1,...,codeSize-1].
        std::vector<uint32_t> rnd = gen_random_mod(code_size_, message_size_ * expander_weight_, seed_);
        uint32_t* rrnd = rnd.data();

        for (uint32_t i = 0; i < message_size_; ++i) {
            auto value = e[*rrnd];
            ++rrnd;
            for (uint32_t j = 1; j < expander_weight_; ++j, ++rrnd) {
                value ^= e[*rrnd];
            }
            w[i] = value;
        }
    }

    void expand2(const std::vector<Block>& e0,
                 const std::vector<Block>& e1,
                 std::vector<Block>& w0,
                 std::vector<Block>& w1) {
        TAIHANG_ASSERT(e0.size() == code_size_ && e1.size() == code_size_ &&
                       w0.size() == message_size_ && w1.size() == message_size_,
                       "VOLE ExConvCode: invalid expand2 dimensions.");

        // Generate messageSize * expanderWeight random positions in e[0,1,...,codeSize-1].
        std::vector<uint32_t> rnd = gen_random_mod(code_size_, message_size_ * expander_weight_, seed_);
        uint32_t* rrnd = rnd.data();

        for (uint32_t i = 0; i < message_size_; ++i) {
            auto value0 = e0[*rrnd];
            auto value1 = e1[*rrnd];
            ++rrnd;
            for (uint32_t j = 1; j < expander_weight_; ++j, ++rrnd) {
                value0 ^= e0[*rrnd];
                value1 ^= e1[*rrnd];
            }
            w0[i] = value0;
            w1[i] = value1;
        }
    }

    uint32_t message_size_ = 0;
    uint32_t code_size_ = 0;
    prg::Seed seed_;
    uint32_t ratio_ = 2;
    uint32_t expander_weight_ = 21;
    uint32_t accumulator_size_ = 24;
};

void base_vole_party_a(net::NetIO& io,
                       const PublicParameters& pp,
                       uint64_t len,
                       std::vector<Block>& vec_u,
                       std::vector<Block>& vec_w) {
    // Return [u, w = share_(u * delta)].
    const uint64_t extend_len = len * kBlockBitLen;
    vec_u.resize(len);
    vec_w.resize(len);

    auto common_seed = prg::set_seed(&kZeroBlock, 0);
    // Set a random seed to sample pairs of random K0, K1.
    auto seed_k = prg::set_seed(nullptr, 0);
    std::vector<Block> vec_k0 = prg::gen_random_blocks(seed_k, extend_len);
    std::vector<Block> vec_k1 = prg::gen_random_blocks(seed_k, extend_len);

    // Send vec_k0, vec_k1 to OT.
    alsz_ote::sender<alsz_ote::BlockPolicy>(io, pp.ote_pp, vec_k0, vec_k1, extend_len);

    std::vector<Block> vec_w0(extend_len);
    std::vector<Block> vec_w1(extend_len);
    aes::encrypt_ecb(common_seed.aes_key, vec_k0.data(), vec_w0.data(), extend_len);
    aes::encrypt_ecb(common_seed.aes_key, vec_k1.data(), vec_w1.data(), extend_len);

    // There is no given u.
    vec_u = prg::gen_random_blocks(seed_k, len);

    // Calculate vec_gamma.
    std::vector<Block> vec_gamma(extend_len);
    for (uint64_t j = 0; j < len; ++j) {
        for (uint64_t i = 0; i < kBlockBitLen; ++i) {
            const auto idx = j * kBlockBitLen + i;
            vec_gamma[idx] = vec_w0[idx] ^ vec_w1[idx] ^ vec_u[j];
        }
    }

    // Send vec_gamma to B.
    io.send(vec_gamma);

    // Calculate <g,w0>.
    for (uint64_t i = 0; i < len; ++i) {
        const auto begin = vec_w0.begin() + static_cast<std::ptrdiff_t>(i * kBlockBitLen);
        std::vector<Block> slice(begin, begin + kBlockBitLen);
        vec_w[i] = gadget_inner_product(slice);
    }
}

void base_vole_party_b(net::NetIO& io,
                       const PublicParameters& pp,
                       uint64_t len,
                       std::vector<Block>& vec_v,
                       const Block& delta) {
    // Return delta, [v = share_(u * delta)].
    const uint64_t extend_len = len * kBlockBitLen;
    vec_v.resize(len);

    // Decompose delta into delta_bits.
    const std::vector<uint8_t> delta_bits = block_bits(delta);
    // selection_bits = len * delta_bits.
    std::vector<uint8_t> selection_bits(extend_len);
    for (uint64_t j = 0; j < len; ++j) {
        std::copy(delta_bits.begin(), delta_bits.end(), selection_bits.begin() + j * kBlockBitLen);
    }

    // Use selection_bits to receive K from OT.
    std::vector<Block> vec_k = alsz_ote::receiver<alsz_ote::BlockPolicy>(io, pp.ote_pp, selection_bits, extend_len);

    auto common_seed = prg::set_seed(&kZeroBlock, 0);
    // Calculate vec_w = PRF(w).
    std::vector<Block> vec_w(extend_len);
    aes::encrypt_ecb(common_seed.aes_key, vec_k.data(), vec_w.data(), extend_len);

    // Receive vec_gamma from A.
    std::vector<Block> vec_gamma(extend_len);
    io.recv(vec_gamma);

    // Calculate vec_v = vec_w + delta_bits * vec_gamma.
    std::vector<Block> temp_v(kBlockBitLen);
    for (uint64_t j = 0; j < len; ++j) {
        const auto offset = j * kBlockBitLen;
        for (uint64_t i = 0; i < kBlockBitLen; ++i) {
            temp_v[i] = delta_bits[i] ? (vec_w[offset + i] ^ vec_gamma[offset + i])
                                      : vec_w[offset + i];
        }
        // Calculate <g,temp_v>.
        vec_v[j] = gadget_inner_product(temp_v);
    }
}

Block full_eval(uint8_t depth,
                const Block& root,
                std::vector<Block>& vec_leaf,
                std::vector<Block>& vec_m0,
                std::vector<Block>& vec_m1) {
    // spVOLE = FullEval + PuncEval.
    vec_leaf.clear();

    if (depth <= 1) {
        if (depth == 0) {
            return kZeroBlock;
        }

        std::vector<Block> temp = ggm_prg(root);
        vec_leaf.push_back(temp[0]);
        vec_leaf.push_back(temp[1]);
        vec_m0.push_back(vec_leaf[0]);
        vec_m1.push_back(vec_leaf[1]);
        return vec_leaf[0] ^ vec_leaf[1];
    }

    const uint64_t leaf_num = 1ULL << depth;
    const uint64_t inner_num = leaf_num - 2;
    std::vector<Block> vec_inner(inner_num);

    // Generate vec_inner.
    std::vector<Block> temp = ggm_prg(root);
    vec_inner[0] = temp[0];
    vec_inner[1] = temp[1];

    uint64_t parent_i = 0;
    for (uint64_t child_j = 2; child_j < inner_num; child_j += 2) {
        temp = ggm_prg(vec_inner[parent_i]);
        vec_inner[2 * parent_i + 2] = temp[0];
        vec_inner[2 * parent_i + 3] = temp[1];
        ++parent_i;
    }

    // Generate vec_leaf with vec_inner.
    for (; parent_i < inner_num; ++parent_i) {
        temp = ggm_prg(vec_inner[parent_i]);
        vec_leaf.push_back(temp[0]);
        vec_leaf.push_back(temp[1]);
    }

    // Generate vec_m0 and vec_m1.
    vec_m0.push_back(vec_inner[0]);
    vec_m1.push_back(vec_inner[1]);

    uint64_t left_index = 2;
    for (uint8_t i = 1; i < depth - 1; ++i) {
        const uint64_t level_node_num = 1ULL << i;
        Block temp_m0 = kZeroBlock;
        Block temp_m1 = kZeroBlock;
        for (uint64_t j = 0; j < level_node_num; ++j, left_index += 2) {
            temp_m0 ^= vec_inner[left_index];
            temp_m1 ^= vec_inner[left_index + 1];
        }
        vec_m0.push_back(temp_m0);
        vec_m1.push_back(temp_m1);
    }

    Block temp_m0 = vec_leaf[0];
    Block temp_m1 = vec_leaf[1];
    for (uint64_t i = 2; i < leaf_num; i += 2) {
        temp_m0 ^= vec_leaf[i];
        temp_m1 ^= vec_leaf[i + 1];
    }
    vec_m0.push_back(temp_m0);
    vec_m1.push_back(temp_m1);

    return temp_m0 ^ temp_m1;
}

struct PuncturedNode {
    Block node = kZeroBlock;
    // 1 if node is filled; else 0.
    bool filled = false;
};

std::vector<Block> punc_eval(uint8_t depth,
                             const Block& beta,
                             const Block* ptr_m,
                             const uint8_t* ptr_selection_bit) {
    if (depth <= 1) {
        if (depth == 0) {
            return {};
        }

        std::vector<Block> vec_leaf(2);
        if (*ptr_selection_bit == 0) {
            vec_leaf[0] = *ptr_m;
            vec_leaf[1] = *ptr_m ^ beta;
        } else {
            vec_leaf[1] = *ptr_m;
            vec_leaf[0] = *ptr_m ^ beta;
        }
        return vec_leaf;
    }

    const uint64_t leaf_num = 1ULL << depth;
    const uint64_t half_leaf_num = 1ULL << (depth - 1);
    std::vector<PuncturedNode> inner(leaf_num - 2);
    std::vector<Block> vec_leaf(leaf_num);

    // Generate the first level of inner nodes.
    if (*ptr_selection_bit == 0) {
        inner[0].node = *ptr_m;
        inner[0].filled = true;
    } else {
        inner[1].node = *ptr_m;
        inner[1].filled = true;
    }
    ++ptr_m;
    ++ptr_selection_bit;

    // parent_i indicates the parent node.
    uint64_t parent_i = 0;
    // alpha_i marks the index of the unfilled parent node.
    uint64_t alpha_i = 0;

    // Generate the remaining inner nodes by parent_i and alpha_i.
    for (uint8_t i = 1; i < depth - 1; ++i) {
        Block left_sum = kZeroBlock;
        Block right_sum = kZeroBlock;
        const uint64_t level_node_num = 1ULL << i;

        for (uint64_t j = 0; j < level_node_num; ++j, ++parent_i) {
            if (inner[parent_i].filled) {
                const auto temp = ggm_prg(inner[parent_i].node);
                inner[2 * parent_i + 2].node = temp[0];
                inner[2 * parent_i + 2].filled = true;
                inner[2 * parent_i + 3].node = temp[1];
                inner[2 * parent_i + 3].filled = true;
                // Calculate the sum of left nodes and right nodes.
                left_sum ^= temp[0];
                right_sum ^= temp[1];
            } else {
                alpha_i = parent_i;
            }
        }

        // Generate the brother node of chosen node.
        if (*ptr_selection_bit == 0) {
            inner[2 * alpha_i + 2].node = (*ptr_m) ^ left_sum;
            inner[2 * alpha_i + 2].filled = true;
        } else {
            inner[2 * alpha_i + 3].node = (*ptr_m) ^ right_sum;
            inner[2 * alpha_i + 3].filled = true;
        }
        ++ptr_m;
        ++ptr_selection_bit;
    }

    Block left_sum = kZeroBlock;
    Block right_sum = kZeroBlock;
    // Calculate vec_leaf besides punctured node.
    for (uint64_t i = 0; i < half_leaf_num; ++i, ++parent_i) {
        if (inner[parent_i].filled) {
            const auto temp = ggm_prg(inner[parent_i].node);
            vec_leaf[2 * i] = temp[0];
            vec_leaf[2 * i + 1] = temp[1];
            left_sum ^= temp[0];
            right_sum ^= temp[1];
        } else {
            alpha_i = i;
        }
    }

    // Correct the leaf of punctured node.
    if (*ptr_selection_bit == 0) {
        vec_leaf[2 * alpha_i] = (*ptr_m) ^ left_sum;
        vec_leaf[2 * alpha_i + 1] = (*ptr_m) ^ right_sum ^ beta;
    } else {
        vec_leaf[2 * alpha_i] = (*ptr_m) ^ left_sum ^ beta;
        vec_leaf[2 * alpha_i + 1] = (*ptr_m) ^ right_sum;
    }

    return vec_leaf;
}

void extend_vole_party_b(net::NetIO& io,
                         const PublicParameters& pp,
                         uint64_t item_num,
                         uint64_t t,
                         std::vector<Block> vec_v,
                         std::vector<Block>& vec_b) {
    // tmpVOLE = t * spVOLE + ExConvCode.
    vec_b.clear();
    item_num *= 2; // For EC Code mR = 2.

    const uint64_t sub_len = item_num / t;
    const uint64_t last_len = item_num % t + item_num / t;
    const uint8_t level = static_cast<uint8_t>(std::ceil(std::log2(sub_len)));
    const uint8_t level_last = static_cast<uint8_t>(std::ceil(std::log2(last_len)));
    const uint64_t selection_len = level * (t - 1) + level_last;
    const uint64_t extend_len = ((selection_len + kBlockBitLen - 1) / kBlockBitLen) * kBlockBitLen;

    auto seed_k = prg::set_seed(nullptr, 0);
    std::vector<Block> vec_k = prg::gen_random_blocks(seed_k, t);

    std::vector<Block> vec_m0;
    std::vector<Block> vec_m1;
    std::vector<Block> vec_send_to_a(t);

    // Generate t random blocks as roots for GGM.
    uint8_t temp_level = level;
    uint64_t temp_len = sub_len;
    // Call FullEval t times.
    for (uint64_t i = 0; i < t; ++i) {
        std::vector<Block> temp_leaf;
        if (i == t - 1) {
            temp_level = level_last;
            temp_len = last_len;
        }
        vec_send_to_a[i] = full_eval(temp_level, vec_k[i], temp_leaf, vec_m0, vec_m1);
        vec_send_to_a[i] ^= vec_v[i];
        temp_leaf.resize(temp_len);
        vec_b.insert(vec_b.end(), temp_leaf.begin(), temp_leaf.end());
    }

    // Send t blocks to A.
    io.send(vec_send_to_a);

    if (extend_len > selection_len) {
        vec_m0.resize(extend_len, kZeroBlock);
        vec_m1.resize(extend_len, kZeroBlock);
    }

    // Send vec_m0, vec_m1 to A by ALSZ OTE.
    alsz_ote::sender<alsz_ote::BlockPolicy>(io,
                                            pp.ote_pp,
                                            vec_m0,
                                            vec_m1,
                                            extend_len);

    // Set seed for ECCode.
    const Block ec_key = prg::gen_random_blocks(seed_k, 1)[0];
    io.send(ec_key);

    prg::Seed ec_seed;
    ec_seed.aes_key = aes::set_encrypt_key(&ec_key, static_cast<int>(kBlockBitLen));
    ec_seed.counter = 0;

    // Encode vec_b by ExConvCode.
    ExConvCode encoder;
    encoder.config(ec_seed);
    encoder.dual_encode(vec_b);
}

std::vector<Block> extend_vole_party_a(net::NetIO& io,
                                       const PublicParameters& pp,
                                       uint64_t item_num,
                                       uint64_t t,
                                       std::vector<Block>& vec_c,
                                       const std::vector<Block>& vec_u,
                                       const std::vector<Block>& vec_w) {
    // tmpVOLE = t * spVOLE + ExConvCode.
    vec_c.clear();
    item_num *= 2; // For EC Code mR = 2.

    // Generate and save the t random punctured positions in vec_index.
    const uint64_t sub_len = item_num / t;
    const uint64_t last_len = item_num % t + item_num / t;
    const uint8_t level = static_cast<uint8_t>(std::ceil(std::log2(sub_len)));
    const uint8_t level_last = static_cast<uint8_t>(std::ceil(std::log2(last_len)));
    const uint64_t select_len = level * (t - 1) + level_last;
    const uint64_t extend_len = ((select_len + kBlockBitLen - 1) / kBlockBitLen) * kBlockBitLen;

    std::vector<uint32_t> vec_index = gen_random_mod(static_cast<uint32_t>(sub_len),
                                                     static_cast<uint32_t>(t - 1),
                                                     prg::set_seed(nullptr, 0));
    const uint32_t index_last = gen_random_mod(static_cast<uint32_t>(last_len),
                                               1,
                                               prg::set_seed(nullptr, 0))[0];
    vec_index.push_back(index_last);

    // Concatenate the t unit vector into base_field_a:
    // base_field_a[vec_index[i]] = vec_u[i].
    std::vector<Block> base_field_a(item_num, kZeroBlock);
    for (uint64_t i = 0; i < t; ++i) {
        base_field_a[i * sub_len + vec_index[i]] = vec_u[i];
    }

    // Obtain the right selection bit vector by traveling vec_index reversely
    // and XORing 111...111.
    std::vector<uint8_t> selection_bits;
    trans_to_bit_vec(vec_index[t - 1], selection_bits, level_last);
    for (auto it = vec_index.rbegin() + 1; it != vec_index.rend(); ++it) {
        trans_to_bit_vec(*it, selection_bits, level);
    }
    selection_bits.resize(extend_len, 0);

    std::vector<Block> vec_from_b(t);
    io.recv(vec_from_b);

    // Receive vec_total_m by selection_bits.
    std::vector<Block> vec_total_m = alsz_ote::receiver<alsz_ote::BlockPolicy>(
        io,
        pp.ote_pp,
        selection_bits,
        extend_len);
    vec_total_m.resize(select_len);

    // Call PuncEval t times to get vec_c.
    for (uint64_t i = 0; i < t; ++i) {
        vec_from_b[i] ^= vec_w[i];
        std::vector<Block> temp_leaf;
        const Block* ptr_m = vec_total_m.data() + i * level;
        const uint8_t* ptr_selection_bit = selection_bits.data() + i * level;

        if (i == t - 1) {
            // Calculate the last PPRF.
            temp_leaf = punc_eval(level_last, vec_from_b[i], ptr_m, ptr_selection_bit);
            temp_leaf.resize(last_len);
            vec_c.insert(vec_c.end(), temp_leaf.begin(), temp_leaf.end());
            break;
        }

        // Calculate the first t - 1 PPRFs.
        temp_leaf = punc_eval(level, vec_from_b[i], ptr_m, ptr_selection_bit);
        temp_leaf.resize(sub_len);
        vec_c.insert(vec_c.end(), temp_leaf.begin(), temp_leaf.end());
    }

    Block ec_key;
    io.recv(ec_key);

    // Set seed for ECCode.
    prg::Seed ec_seed;
    ec_seed.aes_key = aes::set_encrypt_key(&ec_key, static_cast<int>(kBlockBitLen));
    ec_seed.counter = 0;

    // Encode vec_c and base_field_a by ExConvCode.
    ExConvCode encoder;
    encoder.config(ec_seed);
    encoder.dual_encode2(vec_c, base_field_a);

    return base_field_a;
}

std::string PublicParameters::format() const {
    std::ostringstream oss;
    oss << "[VOLE PublicParameters]\n"
        << "Base length :" << base_len << "\n"
        << "PPRF number :" << pprf_num << "\n"
        << ote_pp.format();
    return oss.str();
}

std::ostream& operator<<(std::ostream& os, const PublicParameters& pp) {
    os << pp.base_len << " " << pp.pprf_num << " " << pp.ote_pp;
    return os;
}

std::istream& operator>>(std::istream& is, PublicParameters& pp) {
    is >> pp.base_len >> pp.pprf_num >> pp.ote_pp;
    return is;
}

PublicParameters setup(int base_ot_curve_id, size_t base_len, size_t pprf_num) {
    TAIHANG_ASSERT(base_len > 0, "VOLE base_len must be positive.");
    TAIHANG_ASSERT((base_len % alsz_ote::kBaseLen) == 0, "VOLE base_len must be a multiple of ALSZ base length.");
    TAIHANG_ASSERT(pprf_num >= kMinPprfNum && pprf_num <= kMaxPprfNum, "VOLE pprf_num must be in [128, 248].");

    PublicParameters pp;
    pp.base_len = base_len;
    pp.pprf_num = pprf_num;
    pp.ote_pp = alsz_ote::setup(base_ot_curve_id, base_len);
    return pp;
}

std::vector<Block> party_a(net::NetIO& io,
                           const PublicParameters& pp,
                           size_t item_num,
                           std::vector<Block>& vec_c) {
    TAIHANG_ASSERT(item_num > 0, "VOLE item_num must be positive.");

    // VOLE = baseVOLE + tmpVOLE.
    // Party A obtains vec_A and vec_C.
    // vec_B = vec_C + vec_A * delta, and w + v = u * delta.
    std::vector<Block> vec_u;
    std::vector<Block> vec_w;

    if (item_num < kSmallVoleThreshold) {
        base_vole_party_a(io, pp, item_num, vec_u, vec_c);
        return vec_u;
    }

    // Call baseVOLE to get vec_u and vec_w.
    base_vole_party_a(io, pp, pp.pprf_num, vec_u, vec_w);
    return extend_vole_party_a(io, pp, item_num, pp.pprf_num, vec_c, vec_u, vec_w);
}

void party_b(net::NetIO& io,
             const PublicParameters& pp,
             size_t item_num,
             std::vector<Block>& vec_b,
             const Block& delta) {
    TAIHANG_ASSERT(item_num > 0, "VOLE item_num must be positive.");

    // VOLE = baseVOLE + tmpVOLE.
    // Party B obtains vec_B and delta, satisfying vec_B = vec_C + vec_A * delta.
    if (item_num < kSmallVoleThreshold) {
        base_vole_party_b(io, pp, item_num, vec_b, delta);
        return;
    }

    std::vector<Block> vec_v;
    base_vole_party_b(io, pp, pp.pprf_num, vec_v, delta);
    extend_vole_party_b(io, pp, item_num, pp.pprf_num, vec_v, vec_b);
}

} // namespace taihang::mpc::vole
