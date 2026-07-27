/****************************************************************************
 * @file      test_vole_oprf.cpp
 * @brief     GTest suite for the VOLE-based OPRF primitive.
 * @author    This file is part of Taihang, developed by Yu Chen.
 *****************************************************************************/

#include <gtest/gtest.h>
#include <taihang/common/config.hpp>
#include <taihang/crypto/prg.hpp>
#include <taihang/mpc/oprf/vole_oprf.hpp>

#include <openssl/obj_mac.h>
#include <future>
#include <sstream>
#include <stdexcept>
#include <vector>

using namespace taihang;
namespace oprf = taihang::mpc::vole_oprf;

class VoleOprfTest : public ::testing::Test {
protected:
    void SetUp() override {
        old_thread_num = config::thread_num;
        config::thread_num = 4;
    }

    void TearDown() override {
        config::thread_num = old_thread_num;
    }

    static constexpr size_t kLogInputNum = 8;
    static constexpr size_t kInputNum = 1ULL << kLogInputNum;
    static constexpr uint16_t kPort = 12480;
    static constexpr uint16_t kUnderfilledPort = 12484;
    static constexpr int kCurveId = NID_X9_62_prime256v1;

    static std::vector<Block> gen_input(size_t input_num = kInputNum) {
        Block seed_block = make_block(0x123456789abcdef0ULL, 0x0fedcba987654321ULL);
        auto seed = prg::set_seed(&seed_block, 0);
        return prg::gen_random_blocks(seed, input_num);
    }

    static void expect_equal_blocks(const std::vector<Block>& lhs, const std::vector<Block>& rhs) {
        ASSERT_EQ(lhs.size(), rhs.size());
        for (size_t i = 0; i < lhs.size(); ++i) {
            EXPECT_EQ(lhs[i], rhs[i]) << "Mismatch at index: " << i;
        }
    }

    int old_thread_num = 0;
};

TEST_F(VoleOprfTest, Setup_Parameter_Fields) {
    auto pp = oprf::setup(kCurveId, kLogInputNum);

    EXPECT_EQ(pp.base_ot_curve_id, kCurveId);
    EXPECT_EQ(pp.input_num, kInputNum);
    EXPECT_EQ(pp.log_input_num, kLogInputNum);
    EXPECT_EQ(pp.range_size, sizeof(Block));
    EXPECT_GT(pp.okvs_output_size, 0u);
    EXPECT_EQ(pp.okvs_pp.item_num, pp.input_num);
}

TEST_F(VoleOprfTest, Execute_VoleOprf_Roundtrip) {
    auto pp = oprf::setup(kCurveId, kLogInputNum);
    auto vec_x = gen_input();
    auto vec_y = vec_x;

    std::vector<Block> client_result;
    std::vector<Block> server_result;

    auto server_task = std::async(std::launch::async, [&]() {
        net::NetIO io("server", "127.0.0.1", kPort);
        auto secret_key = oprf::sender(io, pp);
        server_result = oprf::evaluate(pp, secret_key, vec_y);
        io.send(server_result);
    });

    auto client_task = std::async(std::launch::async, [&]() {
        net::NetIO io("client", "127.0.0.1", kPort);
        client_result = oprf::receiver(io, pp, vec_x);
        std::vector<Block> echoed(client_result.size());
        io.recv(echoed);
        expect_equal_blocks(client_result, echoed);
    });

    client_task.get();
    server_task.get();

    expect_equal_blocks(client_result, server_result);
}

TEST_F(VoleOprfTest, Receiver_AllowsShorterInputCount) {
    auto pp = oprf::setup(kCurveId, kLogInputNum);
    auto vec_x = gen_input(kInputNum / 2);

    std::vector<Block> client_result;
    std::vector<Block> server_result;

    auto server_task = std::async(std::launch::async, [&]() {
        net::NetIO io("server", "127.0.0.1", kUnderfilledPort);
        auto secret_key = oprf::sender(io, pp);
        server_result = oprf::evaluate(pp, secret_key, vec_x);
    });

    auto client_task = std::async(std::launch::async, [&]() {
        net::NetIO io("client", "127.0.0.1", kUnderfilledPort);
        client_result = oprf::receiver(io, pp, vec_x);
    });

    client_task.get();
    server_task.get();

    expect_equal_blocks(client_result, server_result);
}

TEST_F(VoleOprfTest, Rejects_QueryCountAboveCapacity) {
    auto pp = oprf::setup(kCurveId, kLogInputNum);
    auto vec_y = gen_input(kInputNum * 2);

    oprf::SecretKey secret_key;
    secret_key.encoded_key.resize(pp.okvs_output_size);

    EXPECT_DEATH(oprf::evaluate(pp, secret_key, vec_y), ".*");
}

TEST_F(VoleOprfTest, Serialization_PublicParameters_RoundTrip) {
    auto pp = oprf::setup(kCurveId, kLogInputNum);

    std::ostringstream oss;
    oss << pp;

    oprf::PublicParameters pp_reconstructed;
    std::istringstream iss(oss.str());
    iss >> pp_reconstructed;

    EXPECT_EQ(pp_reconstructed.base_ot_curve_id, pp.base_ot_curve_id);
    EXPECT_EQ(pp_reconstructed.input_num, pp.input_num);
    EXPECT_EQ(pp_reconstructed.log_input_num, pp.log_input_num);
    EXPECT_EQ(pp_reconstructed.key_size, pp.key_size);
    EXPECT_EQ(pp_reconstructed.range_size, pp.range_size);
    EXPECT_EQ(pp_reconstructed.statistical_security_parameter, pp.statistical_security_parameter);
    EXPECT_EQ(pp_reconstructed.okvs_bin_size, pp.okvs_bin_size);
    EXPECT_EQ(pp_reconstructed.okvs_output_size, pp.okvs_output_size);
    EXPECT_EQ(pp_reconstructed.okvs_pp.storage_size, pp.okvs_pp.storage_size);
    EXPECT_EQ(pp_reconstructed.vole_pp.base_len, pp.vole_pp.base_len);
}

TEST_F(VoleOprfTest, Rejects_InvalidKeySize) {
    auto pp = oprf::setup(kCurveId, kLogInputNum);
    auto vec_y = gen_input();

    oprf::SecretKey invalid_key;
    invalid_key.encoded_key.resize(pp.okvs_output_size - 1);

    EXPECT_THROW(oprf::evaluate(pp, invalid_key, vec_y), std::invalid_argument);
}
