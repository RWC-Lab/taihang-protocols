/****************************************************************************
 * @file      test_okvs.cpp
 * @brief     GTest suite for the OKVS primitive.
 * @author    This file is part of Taihang, developed by Yu Chen.
 *****************************************************************************/

#include <gtest/gtest.h>
#include <taihang/common/config.hpp>
#include <taihang/crypto/prg.hpp>
#include <taihang/mpc/okvs/okvs.hpp>

#include <sstream>
#include <vector>

using namespace taihang;
namespace okvs = taihang::mpc::okvs;

// ============================================================
// OKVS Test Fixture
// ============================================================

class OkvsTest : public ::testing::Test {
protected:
    struct Testcase {
        size_t item_num;
        size_t bin_size;
        uint8_t thread_num;
        Block seed_block;
        std::vector<Block> vec_key;
        std::vector<Block> vec_value;
    };

    void SetUp() override {
        old_thread_num = config::thread_num;
        config::thread_num = kThreadNum;
    }

    void TearDown() override {
        config::thread_num = old_thread_num;
    }

    static constexpr size_t kLargeItemNum = 1ULL << 15;
    static constexpr size_t kLargeBinSize = 1ULL << 10;
    static constexpr size_t kSmallItemNum = 1ULL << 10;
    static constexpr size_t kSmallBinSize = 1ULL << 6;
    static constexpr size_t kSingleBinItemNum = 64;
    static constexpr size_t kSingleBinBinSize = 64;
    static constexpr uint8_t kSparseWeight = 3;
    static constexpr uint8_t kStatisticalSecurityParameter = 40;
    static constexpr uint8_t kThreadNum = 4;

    static Block testcase_seed() {
        return make_block(0x123456789abcdef0ULL, 0x0fedcba987654321ULL);
    }

    static Testcase make_testcase(size_t item_num, size_t bin_size, uint8_t thread_num) {
        Testcase testcase;
        testcase.item_num = item_num;
        testcase.bin_size = bin_size;
        testcase.thread_num = thread_num;
        testcase.seed_block = testcase_seed();

        auto seed = prg::set_seed(&testcase.seed_block, 0);
        testcase.vec_value = prg::gen_random_blocks(seed, testcase.item_num);
        testcase.vec_key = prg::gen_random_blocks(seed, testcase.item_num);
        return testcase;
    }

    static void expect_equal_blocks(const std::vector<Block>& actual,
                                    const std::vector<Block>& expected) {
        ASSERT_EQ(actual.size(), expected.size());
        for (size_t i = 0; i < expected.size(); ++i) {
            EXPECT_EQ(actual[i], expected[i]) << "Block mismatch at index: " << i;
        }
    }

    template <okvs::DenseType dense_type>
    static void expect_setup_matches_baxos(const okvs::PublicParameters& pp) {
        auto seed = prg::set_seed(&pp.seed, 0);
        okvs::Baxos<dense_type, Block> baxos(pp.item_num,
                                             pp.bin_size,
                                             pp.sparse_weight,
                                             static_cast<uint8_t>(pp.statistical_security_parameter),
                                             &seed);

        EXPECT_EQ(pp.bin_num, baxos.bin_num);
        EXPECT_EQ(pp.item_num_per_bin, baxos.item_num_per_bin);
        EXPECT_EQ(pp.sparse_size, baxos.sparse_size);
        EXPECT_EQ(pp.dense_size, baxos.dense_size);
        EXPECT_EQ(pp.total_size, baxos.total_size);
        EXPECT_EQ(pp.storage_size, baxos.bin_num * baxos.total_size);
    }

    int old_thread_num = 0;
};

// ============================================================
// 1. Parameterization & Structural Validity
// ============================================================

TEST_F(OkvsTest, Setup_Parameter_Fields_Gf128) {
    auto pp = okvs::setup(kLargeItemNum,
                          kLargeBinSize,
                          kSparseWeight,
                          kStatisticalSecurityParameter,
                          okvs::DenseType::Gf128,
                          testcase_seed());

    EXPECT_EQ(pp.item_num, kLargeItemNum);
    EXPECT_EQ(pp.bin_size, kLargeBinSize);
    EXPECT_EQ(pp.sparse_weight, kSparseWeight);
    EXPECT_EQ(pp.statistical_security_parameter, kStatisticalSecurityParameter);
    EXPECT_EQ(pp.dense_type, okvs::DenseType::Gf128);
    EXPECT_GT(pp.bin_num, 1u);
    EXPECT_GT(pp.storage_size, pp.item_num);

    expect_setup_matches_baxos<okvs::DenseType::Gf128>(pp);
}

TEST_F(OkvsTest, Setup_Parameter_Fields_Binary) {
    auto pp = okvs::setup(kSmallItemNum,
                          kSmallBinSize,
                          kSparseWeight,
                          kStatisticalSecurityParameter,
                          okvs::DenseType::Binary,
                          testcase_seed());

    EXPECT_EQ(pp.item_num, kSmallItemNum);
    EXPECT_EQ(pp.bin_size, kSmallBinSize);
    EXPECT_EQ(pp.sparse_weight, kSparseWeight);
    EXPECT_EQ(pp.statistical_security_parameter, kStatisticalSecurityParameter);
    EXPECT_EQ(pp.dense_type, okvs::DenseType::Binary);
    EXPECT_GT(pp.storage_size, pp.item_num);

    expect_setup_matches_baxos<okvs::DenseType::Binary>(pp);
}

// ============================================================
// 2. Baxos Execution Pipeline
// ============================================================

TEST_F(OkvsTest, Execute_Baxos_Gf128_Roundtrip) {
    auto testcase = make_testcase(kLargeItemNum, kLargeBinSize, kThreadNum);
    auto okvs_seed = prg::set_seed(&testcase.seed_block, 0);

    okvs::Baxos<okvs::DenseType::Gf128, Block> baxos(testcase.item_num,
                                                     testcase.bin_size,
                                                     kSparseWeight,
                                                     kStatisticalSecurityParameter,
                                                     &okvs_seed);

    std::vector<Block> encode_result(baxos.bin_num * baxos.total_size);
    std::vector<Block> decode_result(testcase.item_num);

    auto encode_randomness = prg::set_seed(&testcase.seed_block, 0);
    baxos.solve(testcase.vec_key,
                testcase.vec_value,
                encode_result,
                &encode_randomness,
                testcase.thread_num);

    baxos.decode(testcase.vec_key,
                 decode_result,
                 encode_result,
                 testcase.thread_num);

    expect_equal_blocks(decode_result, testcase.vec_value);
}

// ============================================================
// 3. Public OKVS Primitive API
// ============================================================

TEST_F(OkvsTest, Execute_PublicApi_Gf128_Roundtrip) {
    auto testcase = make_testcase(kLargeItemNum, kLargeBinSize, kThreadNum);
    auto pp = okvs::setup(testcase.item_num,
                          testcase.bin_size,
                          kSparseWeight,
                          kStatisticalSecurityParameter,
                          okvs::DenseType::Gf128,
                          testcase.seed_block);

    auto encode_randomness = prg::set_seed(&testcase.seed_block, 0);
    auto encoded = okvs::encode(pp, testcase.vec_key, testcase.vec_value, &encode_randomness);
    ASSERT_EQ(encoded.size(), pp.storage_size);

    auto decoded = okvs::decode(pp, testcase.vec_key, encoded);
    expect_equal_blocks(decoded, testcase.vec_value);
}

TEST_F(OkvsTest, Execute_PublicApi_Binary_Roundtrip) {
    auto testcase = make_testcase(kSmallItemNum, kSmallBinSize, kThreadNum);
    auto pp = okvs::setup(testcase.item_num,
                          testcase.bin_size,
                          kSparseWeight,
                          kStatisticalSecurityParameter,
                          okvs::DenseType::Binary,
                          testcase.seed_block);

    auto encode_randomness = prg::set_seed(&testcase.seed_block, 0);
    auto encoded = okvs::encode(pp, testcase.vec_key, testcase.vec_value, &encode_randomness);
    ASSERT_EQ(encoded.size(), pp.storage_size);

    auto decoded = okvs::decode(pp, testcase.vec_key, encoded);
    expect_equal_blocks(decoded, testcase.vec_value);
}

TEST_F(OkvsTest, Execute_PublicApi_SubsetDecode) {
    auto testcase = make_testcase(kSmallItemNum, kSmallBinSize, kThreadNum);
    auto pp = okvs::setup(testcase.item_num,
                          testcase.bin_size,
                          kSparseWeight,
                          kStatisticalSecurityParameter,
                          okvs::DenseType::Gf128,
                          testcase.seed_block);

    auto encode_randomness = prg::set_seed(&testcase.seed_block, 0);
    auto encoded = okvs::encode(pp, testcase.vec_key, testcase.vec_value, &encode_randomness);

    constexpr size_t kQueryLen = 128;
    std::vector<Block> query_keys(testcase.vec_key.begin(), testcase.vec_key.begin() + kQueryLen);
    std::vector<Block> expected_values(testcase.vec_value.begin(), testcase.vec_value.begin() + kQueryLen);

    auto decoded = okvs::decode(pp, query_keys, encoded);
    expect_equal_blocks(decoded, expected_values);
}

TEST_F(OkvsTest, Execute_PublicApi_UnderfilledEncode) {
    auto testcase = make_testcase(kSmallItemNum, kSmallBinSize, kThreadNum);
    auto pp = okvs::setup(testcase.item_num,
                          testcase.bin_size,
                          kSparseWeight,
                          kStatisticalSecurityParameter,
                          okvs::DenseType::Gf128,
                          testcase.seed_block);

    constexpr size_t kActualItemNum = 128;
    std::vector<Block> keys(testcase.vec_key.begin(),
                            testcase.vec_key.begin() + kActualItemNum);
    std::vector<Block> values(testcase.vec_value.begin(),
                              testcase.vec_value.begin() + kActualItemNum);

    auto encode_randomness = prg::set_seed(&testcase.seed_block, 0);
    auto encoded = okvs::encode(pp, keys, values, &encode_randomness);
    ASSERT_EQ(encoded.size(), pp.storage_size);

    auto decoded = okvs::decode(pp, keys, encoded);
    expect_equal_blocks(decoded, values);
}

// ============================================================
// 4. Failure Modes & Serialization
// ============================================================

TEST_F(OkvsTest, Rejects_DuplicateKeys) {
    auto testcase = make_testcase(kSingleBinItemNum, kSingleBinBinSize, 1);
    testcase.vec_key[1] = testcase.vec_key[0];

    auto pp = okvs::setup(testcase.item_num,
                          testcase.bin_size,
                          kSparseWeight,
                          kStatisticalSecurityParameter,
                          okvs::DenseType::Gf128,
                          testcase.seed_block);

    auto encode_randomness = prg::set_seed(&testcase.seed_block, 0);
    EXPECT_THROW(okvs::encode(pp, testcase.vec_key, testcase.vec_value, &encode_randomness),
                 std::invalid_argument);
}

TEST_F(OkvsTest, Serialization_PublicParameters_RoundTrip) {
    auto pp = okvs::setup(kSmallItemNum,
                          kSmallBinSize,
                          kSparseWeight,
                          kStatisticalSecurityParameter,
                          okvs::DenseType::Gf128,
                          testcase_seed());

    std::ostringstream oss;
    oss << pp;

    okvs::PublicParameters pp_reconstructed;
    std::istringstream iss(oss.str());
    iss >> pp_reconstructed;

    EXPECT_EQ(pp_reconstructed.item_num, pp.item_num);
    EXPECT_EQ(pp_reconstructed.bin_size, pp.bin_size);
    EXPECT_EQ(pp_reconstructed.bin_num, pp.bin_num);
    EXPECT_EQ(pp_reconstructed.item_num_per_bin, pp.item_num_per_bin);
    EXPECT_EQ(pp_reconstructed.sparse_weight, pp.sparse_weight);
    EXPECT_EQ(pp_reconstructed.statistical_security_parameter, pp.statistical_security_parameter);
    EXPECT_EQ(pp_reconstructed.dense_type, pp.dense_type);
    EXPECT_EQ(pp_reconstructed.sparse_size, pp.sparse_size);
    EXPECT_EQ(pp_reconstructed.dense_size, pp.dense_size);
    EXPECT_EQ(pp_reconstructed.total_size, pp.total_size);
    EXPECT_EQ(pp_reconstructed.storage_size, pp.storage_size);
    EXPECT_EQ(pp_reconstructed.seed, pp.seed);
}
