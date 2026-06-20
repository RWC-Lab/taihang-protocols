/****************************************************************************
 * @file      test_naor_pinkas_ot.cpp
 * @brief     GTest suite for Naor-Pinkas Oblivious Transfer (Base OT).
 * @author    Yu Chen
 *****************************************************************************/

#include <gtest/gtest.h>
#include <taihang/mpc/ot/naor_pinkas_ot.hpp>
#include <taihang/crypto/prg.hpp>
#include <openssl/obj_mac.h>
#include <thread>
#include <vector>

using namespace taihang;
using namespace taihang::mpc::np_ot;

// ============================================================
// Protocol Test Fixture
// ============================================================

class NaorPinkasOTTest : public ::testing::Test {
protected:
    void SetUp() override {
        kCurveId = NID_X9_62_prime256v1; 
        kOtLen   = 128; 
        kPort    = 12345;
        kAddress = "127.0.0.1";

        pp = setup(kCurveId);

        // Pre-generate shared structural context parameters 
        prg::Seed seed = prg::set_seed(nullptr, 0);
        vec_m0 = prg::gen_random_blocks(seed, kOtLen);
        vec_m1 = prg::gen_random_blocks(seed, kOtLen);
        
        vec_selection_bit.resize(kOtLen);
        for (size_t i = 0; i < kOtLen; ++i) {
            vec_selection_bit[i] = static_cast<uint8_t>(i % 2);
        }
    }

    int kCurveId;
    size_t kOtLen;
    uint16_t kPort;
    std::string kAddress;

    PublicParameters pp;
    std::vector<Block> vec_m0;
    std::vector<Block> vec_m1;
    std::vector<uint8_t> vec_selection_bit;
};

// ============================================================
// 1. Parameter Parameterization & Structural Validity
// ============================================================

TEST_F(NaorPinkasOTTest, Setup_Parameter_Fields) {
    EXPECT_EQ(pp.curve_id, kCurveId);
    EXPECT_NE(pp.group_ctx, nullptr);
    EXPECT_NE(pp.field_ctx, nullptr);
    EXPECT_TRUE(pp.g.is_on_curve());
}

// ============================================================
// 2. Core Protocol Execution Pipeline
// ============================================================

TEST_F(NaorPinkasOTTest, Execute_Standard_Protocol_Roundtrip) {
    std::vector<Block> vec_result;

    // Run Sender instance inside an isolated worker background context ("server")
    std::thread sender_worker([&]() {
        net::NetIO io_sender("server", kAddress, kPort);
        send(io_sender, pp, vec_m0, vec_m1, kOtLen);
    });

    // Run Receiver instance on the execution primary loop context ("client")
    std::thread receiver_worker([&]() {
        net::NetIO io_receiver("client", kAddress, kPort);
        vec_result = receive(io_receiver, pp, vec_selection_bit, kOtLen);
    });

    sender_worker.join();
    receiver_worker.join();

    // Verify consistency criteria across all selected elements
    ASSERT_EQ(vec_result.size(), kOtLen);
    for (size_t i = 0; i < kOtLen; ++i) {
        if (vec_selection_bit[i] == 0) {
            EXPECT_EQ(vec_result[i], vec_m0[i]) << "Mismatch at index: " << i << " for bit 0";
        } else {
            EXPECT_EQ(vec_result[i], vec_m1[i]) << "Mismatch at index: " << i << " for bit 1";
        }
    }
}

// ============================================================
// 3. Serialization Validation
// ============================================================

TEST_F(NaorPinkasOTTest, Serialization_PublicParameters_RoundTrip) {
    std::ostringstream oss;
    oss << pp;

    PublicParameters pp_reconstructed;
    std::istringstream iss(oss.str());
    iss >> pp_reconstructed;

    EXPECT_EQ(pp.curve_id, pp_reconstructed.curve_id);
    EXPECT_EQ(pp.g, pp_reconstructed.g);
}