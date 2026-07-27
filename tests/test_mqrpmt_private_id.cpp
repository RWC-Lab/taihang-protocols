/****************************************************************************
 * @file      test_mqrpmt_private_id.cpp
 * @brief     Google Test suite for mqRPMT-based Private-ID.
 * @author    This file is part of Taihang.
 *****************************************************************************/

#include <gtest/gtest.h>
#include <taihang/common/config.hpp>
#include <taihang/mpc/pso/mqrpmt_private_id.hpp>

#include <openssl/obj_mac.h>

#include <algorithm>
#include <cstring>
#include <future>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <vector>

using namespace taihang;
using namespace taihang::mpc;
namespace private_id = taihang::mpc::mqrpmt_private_id;

namespace {

struct BlockLess {
    bool operator()(const Block& lhs, const Block& rhs) const {
        return std::memcmp(&lhs, &rhs, sizeof(Block)) < 0;
    }
};

using BlockSet = std::set<Block, BlockLess>;
using BlockMap = std::map<Block, Block, BlockLess>;

constexpr int kBaseOtCurveId = NID_X9_62_prime256v1;
constexpr int kMqRPMTCurveId = NID_X9_62_prime256v1;
constexpr size_t kLogSenderLen = 8;
constexpr size_t kLogReceiverLen = 7;
constexpr size_t kSenderLen = size_t{1} << kLogSenderLen;
constexpr size_t kReceiverLen = size_t{1} << kLogReceiverLen;
constexpr size_t kStatisticalSecurityParameter = 40;

struct Dataset {
    std::vector<Block> vec_x;
    std::vector<Block> vec_y;
    BlockSet intersection_values;
    size_t intersection_size = 0;
};

Dataset make_dataset(size_t sender_len, size_t receiver_len) {
    Dataset dataset;
    dataset.vec_x.resize(sender_len);
    dataset.vec_y.resize(receiver_len);
    dataset.intersection_size = std::min(sender_len, receiver_len) / 2;

    for (size_t i = 0; i < receiver_len; ++i) {
        dataset.vec_y[i] = make_block(0x5959595959595959ULL,
                                      static_cast<uint64_t>(i + 1));
    }

    for (size_t i = 0; i < sender_len; ++i) {
        if (i < dataset.intersection_size) {
            dataset.vec_x[i] = dataset.vec_y[i];
            dataset.intersection_values.insert(dataset.vec_x[i]);
        } else {
            dataset.vec_x[i] = make_block(0x5858585858585858ULL,
                                          static_cast<uint64_t>(i + 1));
        }
    }

    if (!dataset.vec_y.empty()) {
        std::rotate(dataset.vec_y.begin(),
                    dataset.vec_y.begin() + static_cast<std::ptrdiff_t>(dataset.intersection_size),
                    dataset.vec_y.end());
    }
    return dataset;
}

private_id::PublicParameters make_public_parameters(
    cwprf_mqrpmt::MembershipMode membership_mode,
    std::optional<size_t> statistical_security_parameter = kStatisticalSecurityParameter) {
    return private_id::setup(kBaseOtCurveId,
                             kMqRPMTCurveId,
                             kLogSenderLen,
                             kLogReceiverLen,
                             membership_mode,
                             statistical_security_parameter);
}

struct ProtocolResult {
    private_id::SenderOutput sender;
    private_id::ReceiverOutput receiver;
};

ProtocolResult run_protocol(const private_id::PublicParameters& pp,
                            const Dataset& dataset,
                            uint16_t port) {
    const std::string address = "127.0.0.1";

    auto sender_future = std::async(std::launch::async, [&] {
        net::NetIO io("server", address, port);
        return private_id::sender(io, pp, dataset.vec_x);
    });

    auto receiver_future = std::async(std::launch::async, [&] {
        net::NetIO io("client", address, port);
        return private_id::receiver(io, pp, dataset.vec_y);
    });

    ProtocolResult result;
    result.sender = sender_future.get();
    result.receiver = receiver_future.get();
    return result;
}

BlockMap make_id_map(const std::vector<Block>& items,
                     const std::vector<Block>& ids) {
    BlockMap id_by_item;
    const size_t item_num = std::min(items.size(), ids.size());
    for (size_t i = 0; i < item_num; ++i) {
        id_by_item.emplace(items[i], ids[i]);
    }
    return id_by_item;
}

void expect_contains_all(const BlockSet& expected, const BlockSet& actual) {
    for (const Block& value : expected) {
        EXPECT_EQ(actual.count(value), 1U);
    }
}

void expect_shared_ids_match(const Dataset& dataset,
                             const ProtocolResult& result) {
    const BlockMap sender_id_by_item =
        make_id_map(dataset.vec_x, result.sender.sender_id);
    const BlockMap receiver_id_by_item =
        make_id_map(dataset.vec_y, result.receiver.receiver_id);

    for (const Block& value : dataset.intersection_values) {
        const auto sender_iter = sender_id_by_item.find(value);
        const auto receiver_iter = receiver_id_by_item.find(value);

        ASSERT_NE(sender_iter, sender_id_by_item.end());
        ASSERT_NE(receiver_iter, receiver_id_by_item.end());
        EXPECT_EQ(sender_iter->second, receiver_iter->second);
    }
}

void validate_union_id(const ProtocolResult& result,
                       bool expect_exact_union) {
    const BlockSet sender_ids(result.sender.sender_id.begin(), result.sender.sender_id.end());
    const BlockSet receiver_ids(result.receiver.receiver_id.begin(), result.receiver.receiver_id.end());
    const BlockSet sender_union(result.sender.union_id.begin(), result.sender.union_id.end());
    const BlockSet receiver_union(result.receiver.union_id.begin(), result.receiver.union_id.end());

    BlockSet expected_union = sender_ids;
    expected_union.insert(receiver_ids.begin(), receiver_ids.end());

    EXPECT_EQ(sender_union, receiver_union);
    expect_contains_all(receiver_ids, receiver_union);
    for (const Block& value : receiver_union) {
        EXPECT_EQ(expected_union.count(value), 1U);
    }

    if (expect_exact_union) {
        EXPECT_EQ(receiver_union.size(), expected_union.size());
        expect_contains_all(expected_union, receiver_union);
    } else {
        EXPECT_GE(receiver_union.size(), receiver_ids.size());
        EXPECT_LE(receiver_union.size(), expected_union.size());
    }
}

struct PrivateIdConfig {
    cwprf_mqrpmt::MembershipMode membership_mode;
    bool expect_exact_union;
    uint16_t port;
};

} // namespace

class MqRPMTPrivateIdTest : public ::testing::TestWithParam<PrivateIdConfig> {
protected:
    void SetUp() override {
        old_thread_num = config::thread_num;
        config::thread_num = 4;
    }

    void TearDown() override {
        config::thread_num = old_thread_num;
    }

    int old_thread_num = 0;
};

TEST(MqRPMTPrivateIdSetupTest, Setup_Parameter_Fields) {
    const auto pp = make_public_parameters(cwprf_mqrpmt::MembershipMode::PlainSet);

    EXPECT_EQ(pp.log_sender_len, kLogSenderLen);
    EXPECT_EQ(pp.log_receiver_len, kLogReceiverLen);
    EXPECT_EQ(pp.statistical_security_parameter, kStatisticalSecurityParameter);
    EXPECT_EQ(pp.membership_mode, cwprf_mqrpmt::MembershipMode::PlainSet);
    EXPECT_EQ(pp.oprf_pp.input_num, kSenderLen);
    EXPECT_EQ(pp.psu_pp.log_sender_len, kLogSenderLen);
    EXPECT_EQ(pp.psu_pp.log_receiver_len, kLogReceiverLen);
    EXPECT_EQ(pp.psu_pp.mqrpmt_pp.log_server_len, kLogReceiverLen);
    EXPECT_EQ(pp.psu_pp.mqrpmt_pp.log_client_len, kLogSenderLen);
}

TEST_P(MqRPMTPrivateIdTest, Execute_PrivateId_Roundtrip) {
    const PrivateIdConfig& config = GetParam();
    const auto pp = make_public_parameters(config.membership_mode);
    const Dataset dataset = make_dataset(kSenderLen, kReceiverLen);

    const ProtocolResult result = run_protocol(pp, dataset, config.port);

    ASSERT_EQ(result.sender.sender_id.size(), dataset.vec_x.size());
    ASSERT_EQ(result.receiver.receiver_id.size(), dataset.vec_y.size());
    ASSERT_EQ(result.sender.union_id.size(), result.receiver.union_id.size());

    expect_shared_ids_match(dataset, result);
    validate_union_id(result, config.expect_exact_union);
}

TEST(MqRPMTPrivateIdSetupTest, Serialization_PublicParameters_RoundTrip) {
    const auto pp = make_public_parameters(cwprf_mqrpmt::MembershipMode::PlainSet);

    std::ostringstream output;
    output << pp;

    private_id::PublicParameters restored;
    std::istringstream input(output.str());
    input >> restored;

    EXPECT_EQ(restored.log_sender_len, pp.log_sender_len);
    EXPECT_EQ(restored.log_receiver_len, pp.log_receiver_len);
    EXPECT_EQ(restored.statistical_security_parameter, pp.statistical_security_parameter);
    EXPECT_EQ(restored.membership_mode, pp.membership_mode);
    EXPECT_EQ(restored.oprf_pp.input_num, pp.oprf_pp.input_num);
    EXPECT_EQ(restored.oprf_pp.okvs_output_size, pp.oprf_pp.okvs_output_size);
    EXPECT_EQ(restored.psu_pp.log_sender_len, pp.psu_pp.log_sender_len);
    EXPECT_EQ(restored.psu_pp.log_receiver_len, pp.psu_pp.log_receiver_len);
    EXPECT_EQ(restored.psu_pp.mqrpmt_pp.membership_mode, pp.psu_pp.mqrpmt_pp.membership_mode);
}

TEST(MqRPMTPrivateIdSetupTest, BloomFilterRequiresSecurityParameter) {
    EXPECT_DEATH(
        private_id::setup(kBaseOtCurveId,
                          kMqRPMTCurveId,
                          kLogSenderLen,
                          kLogReceiverLen,
                          cwprf_mqrpmt::MembershipMode::BloomFilter),
        ".*");
}

INSTANTIATE_TEST_SUITE_P(
    MembershipModes,
    MqRPMTPrivateIdTest,
    ::testing::Values(
        PrivateIdConfig{cwprf_mqrpmt::MembershipMode::PlainSet, true, 12630},
        PrivateIdConfig{cwprf_mqrpmt::MembershipMode::BloomFilter, false, 12631}),
    [](const ::testing::TestParamInfo<PrivateIdConfig>& info) {
        return info.param.expect_exact_union ? "PlainSet" : "BloomFilter";
    });

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
