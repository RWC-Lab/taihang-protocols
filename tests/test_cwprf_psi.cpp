/****************************************************************************
 * @file      test_cwprf_psi.cpp
 * @brief     Google Test suite for cwPRF-based PSI.
 * @author    This file is part of Taihang.
 *****************************************************************************/

#include <gtest/gtest.h>

#include <taihang/mpc/pso/cwprf_psi.hpp>

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
namespace psi = taihang::mpc::cwprf_psi;

namespace {

struct BlockLess {
    bool operator()(const Block& lhs, const Block& rhs) const {
        return std::memcmp(&lhs, &rhs, sizeof(Block)) < 0;
    }
};

using BlockSet = std::set<Block, BlockLess>;

constexpr size_t kLogSenderLen = 6;
constexpr size_t kLogReceiverLen = 5;
constexpr size_t kStatisticalSecurityParameter = 40;
constexpr int kSecp256r1 = NID_X9_62_prime256v1;

struct Dataset {
    std::vector<Block> sender_set;
    std::vector<Block> receiver_set;
    BlockSet receiver_values;
    BlockSet intersection;
};

Dataset make_dataset(size_t sender_len,
                     size_t receiver_len,
                     size_t intersection_size) {
    EXPECT_LE(intersection_size, sender_len);
    EXPECT_LE(intersection_size, receiver_len);

    Dataset dataset;
    dataset.sender_set.reserve(sender_len);
    dataset.receiver_set.reserve(receiver_len);

    for (size_t i = 0; i < sender_len; ++i) {
        dataset.sender_set.push_back(
            make_block(0x5353535353535353ULL, static_cast<uint64_t>(i + 1)));
    }

    for (size_t i = 0; i < receiver_len; ++i) {
        Block value;
        if (i < intersection_size) {
            value = dataset.sender_set[i];
            dataset.intersection.insert(value);
        } else {
            value = make_block(0x5252525252525252ULL,
                               static_cast<uint64_t>(i + 1));
        }
        dataset.receiver_set.push_back(value);
        dataset.receiver_values.insert(value);
    }

    return dataset;
}

std::vector<Block> run_protocol(const psi::PublicParameters& pp,
                                const Dataset& dataset,
                                uint16_t port) {
    const std::string address = "127.0.0.1";

    auto sender_future = std::async(std::launch::async, [&] {
        net::NetIO io("server", address, port);
        psi::sender(io, pp, dataset.sender_set);
    });

    auto receiver_future = std::async(std::launch::async, [&] {
        net::NetIO io("client", address, port);
        return psi::receiver(io, pp, dataset.receiver_set);
    });

    sender_future.get();
    return receiver_future.get();
}

struct PsiConfig {
    int curve_id;
    psi::MembershipMode membership_mode;
    uint16_t port;
    std::string name;
};

const std::array<PsiConfig, 4> kConfigs = {{
    {kSecp256r1, psi::MembershipMode::Truncate, 12350, "Secp256r1_Truncate"},
    {kSecp256r1, psi::MembershipMode::PlainSet, 12351, "Secp256r1_PlainSet"},
    {NID_X25519, psi::MembershipMode::Truncate, 12352, "X25519_Truncate"},
    {NID_X25519, psi::MembershipMode::PlainSet, 12353, "X25519_PlainSet"},
}};

psi::PublicParameters make_public_parameters(const PsiConfig& config) {
    const std::optional<size_t> ssp =
        config.membership_mode == psi::MembershipMode::Truncate
            ? std::optional<size_t>(kStatisticalSecurityParameter)
            : std::nullopt;
    return psi::setup(config.curve_id,
                      kLogSenderLen,
                      kLogReceiverLen,
                      config.membership_mode,
                      ssp);
}

class CwPRFPsiTest : public ::testing::TestWithParam<PsiConfig> {};

TEST_P(CwPRFPsiTest, EndToEnd) {
    const PsiConfig& config = GetParam();
    const size_t sender_len = size_t{1} << kLogSenderLen;
    const size_t receiver_len = size_t{1} << kLogReceiverLen;
    const Dataset dataset =
        make_dataset(sender_len, receiver_len, receiver_len / 2);
    const psi::PublicParameters pp = make_public_parameters(config);

    const std::vector<Block> result = run_protocol(pp, dataset, config.port);
    const BlockSet actual(result.begin(), result.end());

    EXPECT_EQ(actual.size(), result.size())
        << "PSI output must not contain duplicate receiver elements.";
    for (const Block& value : actual) {
        EXPECT_EQ(dataset.receiver_values.count(value), 1U)
            << "PSI output must be a subset of the receiver input.";
    }
    for (const Block& value : dataset.intersection) {
        EXPECT_EQ(actual.count(value), 1U)
            << "PSI must not produce false negatives.";
    }

    if (config.membership_mode == psi::MembershipMode::PlainSet) {
        EXPECT_EQ(actual, dataset.intersection);
    } else {
        EXPECT_GE(actual.size(), dataset.intersection.size());
        EXPECT_LE(actual.size(), dataset.receiver_values.size());
    }
}

INSTANTIATE_TEST_SUITE_P(
    CurveAndMembershipModes,
    CwPRFPsiTest,
    ::testing::ValuesIn(kConfigs),
    [](const ::testing::TestParamInfo<PsiConfig>& info) {
        return info.param.name;
    });

TEST(CwPRFPsiSetupTest, TruncateComputesOutputLength) {
    const psi::PublicParameters pp =
        psi::setup(kSecp256r1,
                   kLogSenderLen,
                   kLogReceiverLen,
                   psi::MembershipMode::Truncate,
                   kStatisticalSecurityParameter);
    const size_t expected_byte_len =
        (kStatisticalSecurityParameter + kLogSenderLen + kLogReceiverLen + 7) / 8;

    EXPECT_EQ(pp.truncate_byte_len, expected_byte_len);
    EXPECT_EQ(pp.statistical_security_parameter,
              kStatisticalSecurityParameter);
    ASSERT_NE(pp.group_ctx, nullptr);
    ASSERT_NE(pp.ring_ctx, nullptr);
}

TEST(CwPRFPsiSetupTest, PlainSetDisablesTruncation) {
    const psi::PublicParameters pp =
        psi::setup(NID_X25519,
                   kLogSenderLen,
                   kLogReceiverLen,
                   psi::MembershipMode::PlainSet);

    EXPECT_EQ(pp.statistical_security_parameter, 0U);
    EXPECT_EQ(pp.truncate_byte_len, 0U);
    EXPECT_EQ(pp.group_ctx, nullptr);
    EXPECT_EQ(pp.ring_ctx, nullptr);
}

TEST(CwPRFPsiSetupTest, PublicParametersRoundTrip) {
    const psi::PublicParameters pp =
        psi::setup(kSecp256r1,
                   kLogSenderLen,
                   kLogReceiverLen,
                   psi::MembershipMode::Truncate,
                   kStatisticalSecurityParameter);
    std::stringstream stream;
    stream << pp;

    psi::PublicParameters restored;
    stream >> restored;

    ASSERT_TRUE(stream);
    EXPECT_EQ(restored.curve_id, pp.curve_id);
    EXPECT_EQ(restored.log_sender_len, pp.log_sender_len);
    EXPECT_EQ(restored.log_receiver_len, pp.log_receiver_len);
    EXPECT_EQ(restored.membership_mode, pp.membership_mode);
    EXPECT_EQ(restored.statistical_security_parameter,
              pp.statistical_security_parameter);
    EXPECT_EQ(restored.truncate_byte_len, pp.truncate_byte_len);
    ASSERT_NE(restored.group_ctx, nullptr);
    ASSERT_NE(restored.ring_ctx, nullptr);
    EXPECT_EQ(restored.ring_ctx->modulus, restored.group_ctx->order);
}

TEST(CwPRFPsiSetupTest, X25519PublicParametersRoundTrip) {
    const psi::PublicParameters pp =
        psi::setup(NID_X25519,
                   kLogSenderLen,
                   kLogReceiverLen,
                   psi::MembershipMode::PlainSet);
    std::stringstream stream;
    stream << pp;

    psi::PublicParameters restored;
    stream >> restored;

    ASSERT_TRUE(stream);
    EXPECT_EQ(restored.curve_id, NID_X25519);
    EXPECT_EQ(restored.membership_mode, psi::MembershipMode::PlainSet);
    EXPECT_EQ(restored.statistical_security_parameter, 0U);
    EXPECT_EQ(restored.truncate_byte_len, 0U);
    EXPECT_EQ(restored.group_ctx, nullptr);
    EXPECT_EQ(restored.ring_ctx, nullptr);
}

TEST(CwPRFPsiSetupTest, TruncateRequiresSecurityParameter) {
    EXPECT_DEATH(
        psi::setup(kSecp256r1,
                   kLogSenderLen,
                   kLogReceiverLen,
                   psi::MembershipMode::Truncate),
        ".*");
}

} // namespace
