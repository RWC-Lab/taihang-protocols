/****************************************************************************
 * @file      test_mqrpmt_pso.cpp
 * @brief     Google Test suite for the unified mqRPMT-based PSO framework.
 * @author    This file is part of Taihang.
 *****************************************************************************/

#include <gtest/gtest.h>
#include <taihang/mpc/pso/mqrpmt_pso.hpp>
#include <openssl/obj_mac.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <future>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <vector>

using namespace taihang;
using namespace taihang::mpc;
namespace pso = taihang::mpc::mqrpmt_pso;

namespace {

struct BlockLess {
    bool operator()(const Block& lhs, const Block& rhs) const {
        return std::memcmp(&lhs, &rhs, sizeof(Block)) < 0;
    }
};

using BlockSet = std::set<Block, BlockLess>;

constexpr size_t kLogSenderLen = 8;
constexpr size_t kLogReceiverLen = 7;
constexpr size_t kLogSumBound = 32;
constexpr size_t kLogValueBound = 8;
constexpr size_t kStatisticalSecurityParameter = 40;
constexpr int kSecp256r1 = 415;

struct Dataset {
    std::vector<Block> vec_x;
    std::vector<Block> vec_y;
    BlockSet sender_values;
    BlockSet receiver_values;
    BlockSet intersection_values;
    BlockSet union_values;
    size_t intersection_size = 0;
    uint64_t intersection_sum = 0;
};

Dataset make_dataset(size_t sender_len,
                     size_t receiver_len,
                     size_t intersection_size) {
    EXPECT_LE(intersection_size, sender_len);
    EXPECT_LE(intersection_size, receiver_len);

    Dataset dataset;
    dataset.vec_x.resize(sender_len);
    dataset.vec_y.resize(receiver_len);
    dataset.intersection_size = intersection_size;

    // Domain-separated deterministic blocks make the expected sets exact.
    for (size_t i = 0; i < receiver_len; ++i) {
        dataset.vec_y[i] = make_block(0x5959595959595959ULL,
                                      static_cast<uint64_t>(i + 1));
        dataset.receiver_values.insert(dataset.vec_y[i]);
        dataset.union_values.insert(dataset.vec_y[i]);
    }

    for (size_t i = 0; i < sender_len; ++i) {
        if (i < intersection_size) {
            dataset.vec_x[i] = dataset.vec_y[i];
            dataset.intersection_values.insert(dataset.vec_x[i]);
            dataset.intersection_sum += static_cast<uint64_t>(i + 1);
        } else {
            dataset.vec_x[i] = make_block(0x5858585858585858ULL,
                                          static_cast<uint64_t>(i + 1));
        }

        dataset.sender_values.insert(dataset.vec_x[i]);
        dataset.union_values.insert(dataset.vec_x[i]);
    }

    return dataset;
}

std::vector<ZnElement> make_values(const pso::PublicParameters& pp,
                                   size_t sender_len) {
    EXPECT_NE(pp.ring_ctx, nullptr);
    if (pp.ring_ctx == nullptr) {
        return {};
    }

    std::vector<ZnElement> values;
    values.reserve(sender_len);
    for (size_t i = 0; i < sender_len; ++i) {
        values.emplace_back(pp.ring_ctx,
                            BigInt(static_cast<uint64_t>(i + 1)));
    }
    return values;
}

struct ProtocolResult {
    pso::SenderOutput sender;
    pso::ReceiverOutput receiver;
};

ProtocolResult run_protocol(const pso::PublicParameters& pp,
                            const Dataset& dataset,
                            pso::PsoMode mode,
                            uint16_t port) {
    const std::string address = "127.0.0.1";
    std::vector<ZnElement> values;
    if (mode == pso::PsoMode::kCardSum) {
        values = make_values(pp, dataset.vec_x.size());
    }

    auto sender_future = std::async(std::launch::async, [&] {
        net::NetIO io("server", address, port);
        return pso::pso_sender(io, pp, dataset.vec_x, mode, values);
    });

    auto receiver_future = std::async(std::launch::async, [&] {
        net::NetIO io("client", address, port);
        return pso::pso_receiver(io, pp, dataset.vec_y, mode);
    });

    ProtocolResult result;
    result.sender = sender_future.get();
    result.receiver = receiver_future.get();
    return result;
}

struct PsoConfig {
    pso::PsoMode operation;
    int mqrpmt_curve_id;
    cwprf_mqrpmt::MembershipMode membership_mode;
    uint16_t port;
    std::string name;
};

const std::vector<PsoConfig> kConfigs = [] {
    struct Operation {
        pso::PsoMode mode;
        const char* name;
    };
    struct Curve {
        int id;
        const char* name;
    };
    struct Membership {
        cwprf_mqrpmt::MembershipMode mode;
        const char* name;
    };

    constexpr std::array<Operation, 4> operations = {{
        {pso::PsoMode::kIntersection, "Intersection"},
        {pso::PsoMode::kUnion, "Union"},
        {pso::PsoMode::kCard, "Card"},
        {pso::PsoMode::kCardSum, "CardSum"},
    }};
    constexpr std::array<Curve, 2> curves = {{
        {kSecp256r1, "Secp256r1"},
        {NID_X25519, "X25519"},
    }};
    constexpr std::array<Membership, 2> memberships = {{
        {cwprf_mqrpmt::MembershipMode::BloomFilter, "BloomFilter"},
        {cwprf_mqrpmt::MembershipMode::PlainSet, "PlainSet"},
    }};

    std::vector<PsoConfig> configs;
    uint16_t port = 12400;
    for (const auto& operation : operations) {
        for (const auto& curve : curves) {
            for (const auto& membership : memberships) {
                configs.push_back({
                    operation.mode,
                    curve.id,
                    membership.mode,
                    port++,
                    std::string(operation.name) + "_" + curve.name + "_" +
                        membership.name,
                });
            }
        }
    }
    return configs;
}();

pso::PublicParameters make_public_parameters(const PsoConfig& config) {
    const std::optional<size_t> ssp =
        config.membership_mode == cwprf_mqrpmt::MembershipMode::BloomFilter
            ? std::optional<size_t>(kStatisticalSecurityParameter)
            : std::nullopt;

    return pso::setup(kSecp256r1,
                      config.mqrpmt_curve_id,
                      kLogSenderLen,
                      kLogReceiverLen,
                      kLogSumBound,
                      kLogValueBound,
                      config.membership_mode,
                      ssp);
}

void expect_all_present(const BlockSet& expected, const BlockSet& actual) {
    for (const Block& value : expected) {
        EXPECT_EQ(actual.count(value), 1U);
    }
}

void validate_set_result(const PsoConfig& config,
                         const Dataset& dataset,
                         const std::vector<Block>& result) {
    const BlockSet actual(result.begin(), result.end());
    const bool is_plain =
        config.membership_mode == cwprf_mqrpmt::MembershipMode::PlainSet;

    if (config.operation == pso::PsoMode::kIntersection) {
        expect_all_present(dataset.intersection_values, actual);
        for (const Block& value : actual) {
            EXPECT_EQ(dataset.sender_values.count(value), 1U);
        }

        if (is_plain) {
            EXPECT_EQ(actual.size(), dataset.intersection_values.size());
        } else {
            // Bloom filters may add false positives, but never false negatives.
            EXPECT_GE(actual.size(), dataset.intersection_values.size());
            EXPECT_LE(actual.size(), dataset.sender_values.size());
        }
        return;
    }

    ASSERT_EQ(config.operation, pso::PsoMode::kUnion);
    expect_all_present(dataset.receiver_values, actual);
    for (const Block& value : actual) {
        EXPECT_EQ(dataset.union_values.count(value), 1U);
    }

    if (is_plain) {
        expect_all_present(dataset.union_values, actual);
        EXPECT_EQ(actual.size(), dataset.union_values.size());
    } else {
        // A Bloom-filter false positive can omit a sender-only item from PSU.
        EXPECT_GE(actual.size(), dataset.receiver_values.size());
        EXPECT_LE(actual.size(), dataset.union_values.size());
    }
}

class MqRPMTPSOTest : public ::testing::TestWithParam<PsoConfig> {};

TEST_P(MqRPMTPSOTest, EndToEnd) {
    const PsoConfig& config = GetParam();
    const size_t sender_len = size_t{1} << kLogSenderLen;
    const size_t receiver_len = size_t{1} << kLogReceiverLen;
    const Dataset dataset =
        make_dataset(sender_len, receiver_len, receiver_len / 2);
    const pso::PublicParameters pp = make_public_parameters(config);

    const ProtocolResult result =
        run_protocol(pp, dataset, config.operation, config.port);
    const bool is_plain =
        config.membership_mode == cwprf_mqrpmt::MembershipMode::PlainSet;

    switch (config.operation) {
        case pso::PsoMode::kIntersection:
        case pso::PsoMode::kUnion:
            validate_set_result(config, dataset, result.receiver.set_result);
            break;

        case pso::PsoMode::kCard:
            if (is_plain) {
                EXPECT_EQ(result.receiver.cardinality,
                          dataset.intersection_size);
            } else {
                EXPECT_GE(result.receiver.cardinality,
                          dataset.intersection_size);
                EXPECT_LE(result.receiver.cardinality, sender_len);
            }
            break;

        case pso::PsoMode::kCardSum: {
            EXPECT_EQ(result.sender.cardinality,
                      result.receiver.cardinality);
            const uint64_t recovered_sum =
                result.sender.card_sum.value.to_uint64();

            if (is_plain) {
                EXPECT_EQ(result.receiver.cardinality,
                          dataset.intersection_size);
                EXPECT_EQ(recovered_sum, dataset.intersection_sum);
            } else {
                EXPECT_GE(result.receiver.cardinality,
                          dataset.intersection_size);
                EXPECT_LE(result.receiver.cardinality, sender_len);
                EXPECT_GE(recovered_sum, dataset.intersection_sum);
            }
            break;
        }
    }
}

INSTANTIATE_TEST_SUITE_P(
    AllOperations,
    MqRPMTPSOTest,
    ::testing::ValuesIn(kConfigs),
    [](const ::testing::TestParamInfo<PsoConfig>& info) {
        return info.param.name;
    });

TEST(MqRPMTPSOSetupTest, RoleCrossingAndCardSumRing) {
    const PsoConfig config = {
        pso::PsoMode::kCardSum,
        kSecp256r1,
        cwprf_mqrpmt::MembershipMode::PlainSet,
        0,
        "Setup",
    };
    const pso::PublicParameters pp = make_public_parameters(config);

    EXPECT_EQ(pp.mqrpmt_pp.log_server_len, kLogReceiverLen);
    EXPECT_EQ(pp.mqrpmt_pp.log_client_len, kLogSenderLen);
    ASSERT_NE(pp.ring_ctx, nullptr);
    EXPECT_EQ(pp.ring_ctx->modulus.to_uint64(),
              uint64_t{1} << kLogSumBound);
}

TEST(MqRPMTPSOSetupTest, PublicParametersSerialization) {
    const PsoConfig config = {
        pso::PsoMode::kCardSum,
        kSecp256r1,
        cwprf_mqrpmt::MembershipMode::PlainSet,
        0,
        "Serialization",
    };
    const pso::PublicParameters pp = make_public_parameters(config);

    std::ostringstream output;
    output << pp;

    pso::PublicParameters restored;
    std::istringstream input(output.str());
    input >> restored;

    ASSERT_TRUE(input);
    EXPECT_EQ(restored.log_sender_len, pp.log_sender_len);
    EXPECT_EQ(restored.log_receiver_len, pp.log_receiver_len);
    EXPECT_EQ(restored.log_sum_bound, pp.log_sum_bound);
    EXPECT_EQ(restored.log_value_bound, pp.log_value_bound);
    EXPECT_EQ(restored.mqrpmt_pp.log_server_len,
              pp.mqrpmt_pp.log_server_len);
    EXPECT_EQ(restored.mqrpmt_pp.log_client_len,
              pp.mqrpmt_pp.log_client_len);
    EXPECT_EQ(restored.mqrpmt_pp.membership_mode,
              pp.mqrpmt_pp.membership_mode);
    EXPECT_EQ(restored.ote_pp.base_len, pp.ote_pp.base_len);

    ASSERT_NE(restored.ring_ctx, nullptr)
        << "Deserializing Card-Sum parameters must reconstruct ring_ctx.";
    EXPECT_EQ(restored.ring_ctx->modulus.to_uint64(),
              uint64_t{1} << kLogSumBound);
}

TEST(MqRPMTPSOSetupTest, BloomFilterRequiresSecurityParameter) {
    EXPECT_DEATH(
        pso::setup(kSecp256r1,
                   kSecp256r1,
                   kLogSenderLen,
                   kLogReceiverLen,
                   0,
                   0,
                   cwprf_mqrpmt::MembershipMode::BloomFilter),
        ".*");
}

TEST(MqRPMTPSOSetupTest, CardSumRejectsInsufficientSumBound) {
    EXPECT_DEATH(
        pso::setup(kSecp256r1,
                   kSecp256r1,
                   kLogSenderLen,
                   kLogReceiverLen,
                   kLogSenderLen + kLogValueBound - 1,
                   kLogValueBound,
                   cwprf_mqrpmt::MembershipMode::PlainSet),
        ".*");
}

}  // namespace

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
