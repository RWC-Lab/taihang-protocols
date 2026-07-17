/****************************************************************************
 * @file      test_ote_oprf.cpp
 * @brief     GTest suite for the OTE-based OPRF primitive.
 * @author    This file is part of Taihang, developed by Yu Chen.
 *****************************************************************************/

#include <gtest/gtest.h>
#include <taihang/common/config.hpp>
#include <taihang/crypto/prg.hpp>
#include <taihang/mpc/oprf/ote_oprf.hpp>

#include <openssl/obj_mac.h>
#include <future>
#include <sstream>
#include <stdexcept>
#include <vector>

using namespace taihang;
namespace oprf = taihang::mpc::ote_oprf;

class OteOprfTest : public ::testing::Test {
protected:
    void SetUp() override {
        old_thread_num = config::thread_num;
        config::thread_num = 4;
    }

    void TearDown() override {
        config::thread_num = old_thread_num;
    }

    static constexpr int kCurveId = NID_X9_62_prime256v1;
    static constexpr size_t kLogInputNum = 8;
    static constexpr size_t kInputNum = 1ULL << kLogInputNum;
    static constexpr uint16_t kPort = 12490;

    static std::vector<Block> gen_input() {
        Block seed_block = make_block(0x123456789abcdef0ULL, 0x0fedcba987654321ULL);
        auto seed = prg::set_seed(&seed_block, 0);
        return prg::gen_random_blocks(seed, kInputNum);
    }

    static void expect_equal_outputs(const std::vector<std::vector<uint8_t>>& lhs,
                                     const std::vector<std::vector<uint8_t>>& rhs) {
        ASSERT_EQ(lhs.size(), rhs.size());
        for (size_t i = 0; i < lhs.size(); ++i) {
            ASSERT_EQ(lhs[i].size(), rhs[i].size()) << "Row size mismatch at index: " << i;
            EXPECT_EQ(lhs[i], rhs[i]) << "Row mismatch at index: " << i;
        }
    }

    int old_thread_num = 0;
};

TEST_F(OteOprfTest, Setup_Parameter_Fields) {
    auto pp = oprf::setup(kCurveId, kLogInputNum);

    EXPECT_EQ(pp.base_ot_curve_id, kCurveId);
    EXPECT_EQ(pp.input_num, kInputNum);
    EXPECT_EQ(pp.matrix_height, kInputNum);
    EXPECT_EQ(pp.log_matrix_height, kLogInputNum);
    EXPECT_GT(pp.matrix_width, 0u);
    EXPECT_EQ(pp.key_size, pp.matrix_width * (pp.matrix_height >> 3));
    EXPECT_GT(pp.range_size, 0u);
    EXPECT_EQ(pp.npot_part.curve_id, kCurveId);
    EXPECT_NE(pp.npot_part.group_ctx, nullptr);
}

TEST_F(OteOprfTest, Execute_OteOprf_Roundtrip) {
    auto pp = oprf::setup(kCurveId, kLogInputNum);
    auto vec_x = gen_input();
    auto vec_y = vec_x;

    std::vector<std::vector<uint8_t>> client_result;
    std::vector<std::vector<uint8_t>> server_result;

    auto server_task = std::async(std::launch::async, [&]() {
        net::NetIO io("server", "127.0.0.1", kPort);
        auto key = oprf::sender(io, pp);
        EXPECT_EQ(key.size(), pp.key_size);
        server_result = oprf::evaluate(pp, key, vec_x);
    });

    auto client_task = std::async(std::launch::async, [&]() {
        net::NetIO io("client", "127.0.0.1", kPort);
        client_result = oprf::receiver(io, pp, vec_y);
    });

    client_task.get();
    server_task.get();

    expect_equal_outputs(client_result, server_result);
}

TEST_F(OteOprfTest, Serialization_PublicParameters_RoundTrip) {
    auto pp = oprf::setup(kCurveId, kLogInputNum);

    std::ostringstream oss;
    oss << pp;

    oprf::PublicParameters pp_reconstructed;
    std::istringstream iss(oss.str());
    iss >> pp_reconstructed;

    EXPECT_EQ(pp_reconstructed.base_ot_curve_id, pp.base_ot_curve_id);
    EXPECT_EQ(pp_reconstructed.key_size, pp.key_size);
    EXPECT_EQ(pp_reconstructed.range_size, pp.range_size);
    EXPECT_EQ(pp_reconstructed.statistical_security_parameter, pp.statistical_security_parameter);
    EXPECT_EQ(pp_reconstructed.input_num, pp.input_num);
    EXPECT_EQ(pp_reconstructed.matrix_height, pp.matrix_height);
    EXPECT_EQ(pp_reconstructed.log_matrix_height, pp.log_matrix_height);
    EXPECT_EQ(pp_reconstructed.matrix_width, pp.matrix_width);
    EXPECT_EQ(pp_reconstructed.batch_size, pp.batch_size);
    EXPECT_EQ(pp_reconstructed.common_seed, pp.common_seed);
    EXPECT_EQ(pp_reconstructed.npot_part.curve_id, pp.npot_part.curve_id);
    EXPECT_EQ(pp_reconstructed.npot_part.g, pp.npot_part.g);
}

TEST_F(OteOprfTest, Rejects_InvalidEvaluateKeySize) {
    auto pp = oprf::setup(kCurveId, kLogInputNum);
    auto vec_x = gen_input();

    std::vector<uint8_t> bad_key(pp.key_size - 1);
    EXPECT_THROW(oprf::evaluate(pp, bad_key, vec_x), std::invalid_argument);
}
