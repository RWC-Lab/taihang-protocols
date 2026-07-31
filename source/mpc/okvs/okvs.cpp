/****************************************************************************
 * @file      okvs.cpp
 * @brief     Oblivious Key-Value Store primitive.
 * @author    This file is part of Taihang, developed by Yu Chen.
 *****************************************************************************/

#include <taihang/mpc/okvs/okvs.hpp>
#include <taihang/common/config.hpp>
#include <taihang/crypto/prg.hpp>

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <set>
#include <sstream>
#include <stdexcept>

namespace taihang::mpc::okvs {

namespace {

const char* dense_type_name(DenseType dense_type) {
    switch (dense_type) {
    case DenseType::Binary:
        return "Binary";
    case DenseType::Gf128:
        return "Gf128";
    }
    return "Unknown";
}

uint8_t checked_byte(size_t value, const char* name) {
    if (value > std::numeric_limits<uint8_t>::max()) {
        throw std::invalid_argument(std::string("OKVS ") + name + " exceeds uint8_t.");
    }
    return static_cast<uint8_t>(value);
}

uint8_t thread_num() {
    const int configured = std::max(1, config::thread_num);
    return static_cast<uint8_t>(std::min(configured, static_cast<int>(std::numeric_limits<uint8_t>::max())));
}

struct BlockLess {
    bool operator()(const Block& lhs, const Block& rhs) const {
        return is_less_than(lhs, rhs);
    }
};

std::vector<Block> pad_keys(const PublicParameters& pp,
                            const std::vector<Block>& keys) {
    if (keys.size() == pp.item_num) {
        return keys;
    }

    std::vector<Block> padded = keys;
    padded.reserve(pp.item_num);

    std::set<Block, BlockLess> used(keys.begin(), keys.end());
    auto seed = prg::set_seed(&pp.seed, 1);
    while (padded.size() < pp.item_num) {
        const Block candidate = prg::gen_random_blocks(seed, 1)[0];
        if (used.insert(candidate).second) {
            padded.push_back(candidate);
        }
    }
    return padded;
}

std::vector<Block> pad_values(const std::vector<Block>& values, size_t target_size) {
    if (values.size() == target_size) {
        return values;
    }

    std::vector<Block> padded = values;
    padded.resize(target_size, kZeroBlock);
    return padded;
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

template <DenseType dense_type>
void fill_derived_parameters(PublicParameters& pp) {
    auto okvs_seed = prg::set_seed(&pp.seed, 0);
    Baxos<dense_type, Block> baxos(pp.item_num,
                                   pp.bin_size,
                                   pp.sparse_weight,
                                   checked_byte(pp.statistical_security_parameter, "statistical security parameter"),
                                   &okvs_seed);
    pp.bin_num = baxos.bin_num;
    pp.item_num_per_bin = baxos.item_num_per_bin;
    pp.sparse_size = baxos.sparse_size;
    pp.dense_size = baxos.dense_size;
    pp.total_size = baxos.total_size;
    pp.storage_size = baxos.bin_num * baxos.total_size;
}

void validate_public_parameters(const PublicParameters& pp) {
    if (pp.item_num == 0) {
        throw std::invalid_argument("OKVS item_num must be positive.");
    }
    if (pp.bin_size == 0) {
        throw std::invalid_argument("OKVS bin_size must be positive.");
    }
    if (pp.sparse_weight < 2) {
        throw std::invalid_argument("OKVS sparse_weight must be at least 2.");
    }
    checked_byte(pp.statistical_security_parameter, "statistical security parameter");
}

template <DenseType dense_type>
Baxos<dense_type, Block> make_baxos(const PublicParameters& pp) {
    auto okvs_seed = prg::set_seed(&pp.seed, 0);
    return Baxos<dense_type, Block>(pp.item_num,
                                    pp.bin_size,
                                    pp.sparse_weight,
                                    checked_byte(pp.statistical_security_parameter, "statistical security parameter"),
                                    &okvs_seed);
}

template <DenseType dense_type>
std::vector<Block> encode_impl(const PublicParameters& pp,
                               const std::vector<Block>& keys,
                               const std::vector<Block>& values,
                               prg::Seed* prng) {
    auto baxos = make_baxos<dense_type>(pp);
    std::vector<Block> encoded(pp.storage_size);
    auto padded_keys = pad_keys(pp, keys);
    auto padded_values = pad_values(values, padded_keys.size());
    baxos.solve(padded_keys, padded_values, encoded, prng, thread_num());
    return encoded;
}

template <DenseType dense_type>
std::vector<Block> decode_impl(const PublicParameters& pp,
                               const std::vector<Block>& keys,
                               const std::vector<Block>& encoded) {
    auto baxos = make_baxos<dense_type>(pp);
    std::vector<Block> values(keys.size());
    baxos.decode(keys, values, encoded, thread_num());
    return values;
}

} // namespace

std::string PublicParameters::format() const {
    std::ostringstream oss;
    oss << "[OKVS PublicParameters]\n";
    oss << "Item number                    :" << item_num << "\n";
    oss << "Requested bin size             :" << bin_size << "\n";
    oss << "Bin number                     :" << bin_num << "\n";
    oss << "Item number per bin            :" << item_num_per_bin << "\n";
    oss << "Sparse weight                  :" << static_cast<int>(sparse_weight) << "\n";
    oss << "Statistical security parameter :" << statistical_security_parameter << "\n";
    oss << "Dense type                     :" << dense_type_name(dense_type) << "\n";
    oss << "Sparse size per bin            :" << sparse_size << "\n";
    oss << "Dense size per bin             :" << dense_size << "\n";
    oss << "Total size per bin             :" << total_size << "\n";
    oss << "Encoded storage size           :" << storage_size << "\n";
    return oss.str();
}

std::ostream& operator<<(std::ostream& os, const PublicParameters& pp) {
    const auto seed_words = block_to_words(pp.seed);
    os << pp.item_num << " "
       << pp.bin_size << " "
       << static_cast<int>(pp.sparse_weight) << " "
       << pp.statistical_security_parameter << " "
       << static_cast<int>(pp.dense_type) << " "
       << seed_words[0] << " "
       << seed_words[1];
    return os;
}

std::istream& operator>>(std::istream& is, PublicParameters& pp) {
    int sparse_weight = 0;
    int dense_type = 0;
    uint64_t seed_first = 0;
    uint64_t seed_second = 0;

    size_t item_num = 0;
    size_t bin_size = 0;
    size_t statistical_security_parameter = 0;
    is >> item_num
       >> bin_size
       >> sparse_weight
       >> statistical_security_parameter
       >> dense_type
       >> seed_first
       >> seed_second;

    if (is) {
        pp = setup(item_num,
                   bin_size,
                   static_cast<uint8_t>(sparse_weight),
                   statistical_security_parameter,
                   static_cast<DenseType>(dense_type),
                   words_to_block(seed_first, seed_second));
    }
    return is;
}

PublicParameters setup(size_t item_num,
                       size_t bin_size,
                       uint8_t sparse_weight,
                       size_t statistical_security_parameter,
                       DenseType dense_type,
                       const Block& seed) {
    PublicParameters pp;
    pp.item_num = item_num;
    pp.bin_size = bin_size;
    pp.sparse_weight = sparse_weight;
    pp.statistical_security_parameter = statistical_security_parameter;
    pp.dense_type = dense_type;
    pp.seed = seed;

    validate_public_parameters(pp);

    switch (dense_type) {
    case DenseType::Binary:
        fill_derived_parameters<DenseType::Binary>(pp);
        break;
    case DenseType::Gf128:
        fill_derived_parameters<DenseType::Gf128>(pp);
        break;
    default:
        throw std::invalid_argument("Unknown OKVS dense type.");
    }

    return pp;
}

std::vector<Block> encode(const PublicParameters& pp,
                          const std::vector<Block>& keys,
                          const std::vector<Block>& values,
                          prg::Seed* prng) {
    validate_public_parameters(pp);
    if (keys.size() > pp.item_num || values.size() != keys.size()) {
        throw std::invalid_argument("OKVS encode input size mismatch.");
    }

    switch (pp.dense_type) {
    case DenseType::Binary:
        return encode_impl<DenseType::Binary>(pp, keys, values, prng);
    case DenseType::Gf128:
        return encode_impl<DenseType::Gf128>(pp, keys, values, prng);
    default:
        throw std::invalid_argument("Unknown OKVS dense type.");
    }
}

std::vector<Block> decode(const PublicParameters& pp,
                          const std::vector<Block>& keys,
                          const std::vector<Block>& encoded) {
    validate_public_parameters(pp);
    if (encoded.size() != pp.storage_size) {
        throw std::invalid_argument("OKVS encoded storage size mismatch.");
    }
    if (keys.empty()) {
        return {};
    }

    switch (pp.dense_type) {
    case DenseType::Binary:
        return decode_impl<DenseType::Binary>(pp, keys, encoded);
    case DenseType::Gf128:
        return decode_impl<DenseType::Gf128>(pp, keys, encoded);
    default:
        throw std::invalid_argument("Unknown OKVS dense type.");
    }
}

} // namespace taihang::mpc::okvs
