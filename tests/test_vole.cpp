/****************************************************************************
 * @file      test_vole.cpp
 * @brief     GTest suite for the VOLE primitive.
 * @author    Yang Cao
 *****************************************************************************/

#include <gtest/gtest.h>
#include <taihang/common/config.hpp>
#include <taihang/crypto/prg.hpp>
#include <taihang/mpc/okvs/okvs.hpp>
#include <taihang/mpc/vole/vole.hpp>

#include <openssl/obj_mac.h>
#include <future>
#include <sstream>
#include <vector>

using namespace taihang;
namespace okvs = taihang::mpc::okvs;
namespace alsz_ote = taihang::mpc::alsz_ote;
namespace vole = taihang::mpc::vole;

class VoleTest : public ::testing::Test {
protected:
    void SetUp() override {
        old_thread_num = config::thread_num;
        config::thread_num = 4;
    }

    void TearDown() override {
        config::thread_num = old_thread_num;
    }

    static constexpr int kCurveId = NID_X9_62_prime256v1;
    static constexpr size_t kBaseLen = alsz_ote::kBaseLen;
    static constexpr size_t kPprfNum = vole::kDefaultPprfNum;
    static constexpr size_t kSmallItemNum = sizeof(Block) * 8;
    static constexpr size_t kExpandedItemNum = 300;
    static constexpr uint16_t kSmallPort = 12470;
    static constexpr uint16_t kExpandedPort = 12471;

    struct Transcript {
        // Party A obtains vec_a and vec_c; Party B obtains vec_b and delta.
        std::vector<Block> vec_a;
        std::vector<Block> vec_b;
        std::vector<Block> vec_c;
    };

    static Block fixed_delta() {
        return make_block(0x2c9e2e7639500ed4ULL, 0x97f40bbf3a16f778ULL);
    }

    static void expect_vole_relation(const Transcript& transcript, const Block& delta, size_t item_num) {
        ASSERT_EQ(transcript.vec_a.size(), item_num);
        ASSERT_EQ(transcript.vec_b.size(), item_num);
        ASSERT_EQ(transcript.vec_c.size(), item_num);

        // Test if vec_b == vec_c + vec_a * delta.
        for (size_t i = 0; i < item_num; ++i) {
            const Block expected = transcript.vec_c[i] ^ okvs::gf128_mul(transcript.vec_a[i], delta);
            EXPECT_EQ(transcript.vec_b[i], expected) << "VOLE correlation mismatch at index: " << i;
        }
    }

    static Transcript execute_roundtrip(const vole::PublicParameters& pp,
                                        size_t item_num,
                                        const Block& delta,
                                        uint16_t port) {
        Transcript transcript;

        auto party_b_task = std::async(std::launch::async, [&]() {
            net::NetIO io("server", "127.0.0.1", port);
            // Generate delta and vec_b.
            vole::party_b(io, pp, item_num, transcript.vec_b, delta);
        });

        auto party_a_task = std::async(std::launch::async, [&]() {
            net::NetIO io("client", "127.0.0.1", port);
            // Generate vec_a and vec_c.
            transcript.vec_a = vole::party_a(io, pp, item_num, transcript.vec_c);
        });

        party_a_task.get();
        party_b_task.get();

        return transcript;
    }

    int old_thread_num = 0;
};

TEST_F(VoleTest, Setup_Parameter_Fields) {
    auto pp = vole::setup(kCurveId, kBaseLen, kPprfNum);

    EXPECT_EQ(pp.base_len, kBaseLen);
    EXPECT_EQ(pp.pprf_num, kPprfNum);
    EXPECT_EQ(pp.ote_pp.base_len, kBaseLen);
    EXPECT_EQ(pp.ote_pp.base_ot_pp.curve_id, kCurveId);
}

TEST_F(VoleTest, Execute_BaseVole_Roundtrip) {
    auto pp = vole::setup(kCurveId, kBaseLen, kPprfNum);
    const Block delta = fixed_delta();

    auto transcript = execute_roundtrip(pp, kSmallItemNum, delta, kSmallPort);
    expect_vole_relation(transcript, delta, kSmallItemNum);
}

TEST_F(VoleTest, Execute_ExpandedVole_Roundtrip) {
    auto pp = vole::setup(kCurveId, kBaseLen, kPprfNum);
    const Block delta = fixed_delta();

    auto transcript = execute_roundtrip(pp, kExpandedItemNum, delta, kExpandedPort);
    expect_vole_relation(transcript, delta, kExpandedItemNum);
}

TEST_F(VoleTest, Serialization_PublicParameters_RoundTrip) {
    auto pp = vole::setup(kCurveId, kBaseLen, kPprfNum);

    std::ostringstream oss;
    oss << pp;

    vole::PublicParameters pp_reconstructed;
    std::istringstream iss(oss.str());
    iss >> pp_reconstructed;

    EXPECT_EQ(pp_reconstructed.base_len, pp.base_len);
    EXPECT_EQ(pp_reconstructed.pprf_num, pp.pprf_num);
    EXPECT_EQ(pp_reconstructed.ote_pp.base_len, pp.ote_pp.base_len);
    EXPECT_EQ(pp_reconstructed.ote_pp.base_ot_pp.curve_id, pp.ote_pp.base_ot_pp.curve_id);
}
