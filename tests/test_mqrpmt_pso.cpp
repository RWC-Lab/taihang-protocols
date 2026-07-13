/****************************************************************************
 * @file      test_mqrpmt_pso.cpp
 * @brief     Google Test suite for unified mqRPMT-based PSO framework.
 * @author    This file is part of Taihang, developed by Yu Chen.
 *****************************************************************************/

#include <gtest/gtest.h>
#include <taihang/mpc/pso/mqrpmt_pso.hpp>
#include <taihang/common/logger.hpp>
#include <taihang/crypto/prg.hpp>
#include <taihang/crypto/zn.hpp>
#include <openssl/obj_mac.h>
#include <future>
#include <set>
#include <cstring>
#include <sstream>

using namespace taihang;
using namespace taihang::mpc;        
namespace pso = taihang::mpc::mqrpmt_pso;

// ── Block comparator ──────────────────────────────────────────────────────────

struct BlockLess {
    bool operator()(const Block& a, const Block& b) const {
        return std::memcmp(&a, &b, sizeof(Block)) < 0;
    }
};

// ── Test fixture ──────────────────────────────────────────────────────────────

class MqRPMTPSOTest : public ::testing::Test {
protected:
    static constexpr size_t kLogSenderLen   = 8;   // 2^8=256 >= 128 (OTE base_len)
    static constexpr size_t kLogReceiverLen = 7;   // 2^7=128
    static constexpr size_t kLogSumBound    = 62;
    static constexpr size_t kLogValueBound  = 32;
    static constexpr size_t kSSP            = 40;
    static constexpr int    kNormalCurveId  = 415;

    static constexpr uint16_t kPortIntersectionBloom = 12370;
    static constexpr uint16_t kPortUnionPlain        = 12371;
    static constexpr uint16_t kPortCardBloom         = 12372;
    static constexpr uint16_t kPortCardSumPlain      = 12373;
    static constexpr uint16_t kPortEmptyIntersect    = 12374;
    static constexpr uint16_t kPortFullIntersect     = 12375;
    static constexpr uint16_t kPortAsymmetric        = 12376;

    // ── Dataset ───────────────────────────────────────────────────────────

    struct Dataset {
        std::vector<Block>         vec_x;
        std::vector<Block>         vec_y;
        std::vector<ZnElement>     vec_v;
        size_t                     expected_intersection_size;
        ZnElement                  expected_card_sum;
        std::set<Block, BlockLess> ground_truth_intersection;
        std::set<Block, BlockLess> ground_truth_union;
    };

    static Dataset make_dataset(size_t sender_len,
                                size_t receiver_len,
                                size_t intersection_count,
                                std::shared_ptr<Zn> ring_ctx) {
        Block     seed_block = make_block(0xABCDEF0123456789ULL, 0xFEDCBA9876543210ULL);
        prg::Seed seed       = prg::set_seed(&seed_block, 0);

        std::vector<Block> pool(receiver_len + sender_len);
        prg::gen_random_blocks(seed, pool.data(), pool.size());

        Dataset ds;
        ds.vec_y.resize(receiver_len);
        ds.vec_x.resize(sender_len);
        ds.expected_intersection_size = intersection_count;
        
        if (ring_ctx) {
            ds.vec_v = gen_random_znelement_vector(ring_ctx, sender_len);
            ds.expected_card_sum = ring_ctx->get_zero();
        }

        for (size_t j = 0; j < receiver_len; ++j) {
            ds.vec_y[j] = pool[j];
            ds.ground_truth_union.insert(pool[j]);
        }

        for (size_t i = 0; i < sender_len; ++i) {
            if (i < intersection_count) {
                ds.vec_x[i] = pool[i];           // same value as vec_y[i]
                ds.ground_truth_intersection.insert(pool[i]);
                if (ring_ctx) {
                    ds.expected_card_sum += ds.vec_v[i];
                }
            } else {
                ds.vec_x[i] = pool[receiver_len + i]; // disjoint
            }
            ds.ground_truth_union.insert(ds.vec_x[i]);
        }
        return ds;
    }

    // ── Protocol runner ───────────────────────────────────────────────────

    struct ProtocolOutput {
        pso::SenderOutput   sender_out;
        pso::ReceiverOutput receiver_out;
    };

    static ProtocolOutput run_protocol(const pso::PublicParameters& pp,
                                       const Dataset&               ds,
                                       pso::PsoMode                 mode,
                                       uint16_t                     port) {
        const std::string addr = "127.0.0.1";

        auto sender_task = std::async(std::launch::async, [&]() {
            net::NetIO io("server", addr, port);
            return pso::pso_sender(io, pp, ds.vec_x, mode, ds.vec_v);
        });

        auto receiver_task = std::async(std::launch::async, [&]() {
            net::NetIO io("client", addr, port);
            return pso::pso_receiver(io, pp, ds.vec_y, mode);
        });

        return {sender_task.get(), receiver_task.get()};
    }

    // ── Correctness validator ─────────────────────────────────────────────

    static void validate_set(const std::vector<Block>&        result,
                             const std::set<Block, BlockLess>& ground_truth,
                             cwprf_mqrpmt::MembershipMode     mode,
                             const std::string&               label) {
        std::set<Block, BlockLess> result_set(result.begin(), result.end());

        size_t tp = 0, fp = 0, fn = 0;
        for (const auto& expected : ground_truth) {
            if (result_set.count(expected)) ++tp; else ++fn;
        }
        for (const auto& got : result_set) {
            if (!ground_truth.count(got)) ++fp;
        }

        std::cout << "[" << label << "] expected=" << ground_truth.size()
                  << "  TP=" << tp << "  FP=" << fp << "  FN=" << fn << "\n";

        EXPECT_EQ(fn, 0u) << label << ": false negatives detected.";
        if (mode == cwprf_mqrpmt::MembershipMode::PlainSet) {
            EXPECT_EQ(fp, 0u) << label << ": false positives in PlainSet mode.";
        }
        EXPECT_EQ(tp, ground_truth.size()) << label << ": TP count validation failure.";
    }
};

// ===========================================================================
// End-to-end tests for all PSO Modes
// ===========================================================================

TEST_F(MqRPMTPSOTest, Intersection_BloomFilter) {
    const size_t sender_len   = 1u << kLogSenderLen;
    const size_t receiver_len = 1u << kLogReceiverLen;

    auto pp = pso::setup(kNormalCurveId, kNormalCurveId, kLogSenderLen, kLogReceiverLen, 0, 0, 
                         cwprf_mqrpmt::MembershipMode::BloomFilter, kSSP);
    auto ds  = make_dataset(sender_len, receiver_len, receiver_len / 2, pp.ring_ctx);
    auto res = run_protocol(pp, ds, pso::PsoMode::kIntersection, kPortIntersectionBloom);
    
    validate_set(res.receiver_out.set_result, ds.ground_truth_intersection, 
                 cwprf_mqrpmt::MembershipMode::BloomFilter, "Intersection/BloomFilter");
}

TEST_F(MqRPMTPSOTest, Union_PlainSet) {
    const size_t sender_len   = 1u << kLogSenderLen;
    const size_t receiver_len = 1u << kLogReceiverLen;

    auto pp = pso::setup(kNormalCurveId, kNormalCurveId, kLogSenderLen, kLogReceiverLen, 0, 0, 
                         cwprf_mqrpmt::MembershipMode::PlainSet);
    auto ds  = make_dataset(sender_len, receiver_len, receiver_len / 2, pp.ring_ctx);
    auto res = run_protocol(pp, ds, pso::PsoMode::kUnion, kPortUnionPlain);
    
    validate_set(res.receiver_out.set_result, ds.ground_truth_union, 
                 cwprf_mqrpmt::MembershipMode::PlainSet, "Union/PlainSet");
}

TEST_F(MqRPMTPSOTest, Cardinality_BloomFilter) {
    const size_t sender_len   = 1u << kLogSenderLen;
    const size_t receiver_len = 1u << kLogReceiverLen;

    auto pp = pso::setup(kNormalCurveId, NID_X25519, kLogSenderLen, kLogReceiverLen, 0, 0, 
                         cwprf_mqrpmt::MembershipMode::BloomFilter, kSSP);
    auto ds  = make_dataset(sender_len, receiver_len, receiver_len / 2, pp.ring_ctx);
    auto res = run_protocol(pp, ds, pso::PsoMode::kCard, kPortCardBloom);
    
    EXPECT_EQ(res.receiver_out.cardinality, ds.expected_intersection_size);
}

TEST_F(MqRPMTPSOTest, CardSum_PlainSet) {
    const size_t sender_len   = 1u << kLogSenderLen;
    const size_t receiver_len = 1u << kLogReceiverLen;

    // CardSum requires explicit initialization bounds for scalar algebraic setup
    auto pp = pso::setup(kNormalCurveId, NID_X25519, kLogSenderLen, kLogReceiverLen, kLogSumBound, kLogValueBound, 
                         cwprf_mqrpmt::MembershipMode::PlainSet);
    auto ds  = make_dataset(sender_len, receiver_len, receiver_len / 2, pp.ring_ctx);
    auto res = run_protocol(pp, ds, pso::PsoMode::kCardSum, kPortCardSumPlain);
    
    EXPECT_EQ(res.receiver_out.cardinality, ds.expected_intersection_size);
    EXPECT_EQ(res.sender_out.cardinality, ds.expected_intersection_size);
    EXPECT_TRUE(res.sender_out.card_sum == ds.expected_card_sum);
}

// ── Serialization round-trip ──────────────────────────────────────────────────

TEST_F(MqRPMTPSOTest, PublicParameters_Serialization) {
    auto pp = pso::setup(kNormalCurveId, kNormalCurveId, kLogSenderLen, kLogReceiverLen, kLogSumBound, kLogValueBound,
                         cwprf_mqrpmt::MembershipMode::BloomFilter, kSSP);

    std::ostringstream oss;
    oss << pp;

    pso::PublicParameters pp2;
    std::istringstream iss(oss.str());
    iss >> pp2;

    EXPECT_EQ(pp.log_sender_len,   pp2.log_sender_len);
    EXPECT_EQ(pp.log_receiver_len, pp2.log_receiver_len);
    EXPECT_EQ(pp.log_sum_bound,    pp2.log_sum_bound);
    EXPECT_EQ(pp.log_value_bound,  pp2.log_value_bound);

    EXPECT_EQ(pp2.mqrpmt_pp.log_server_len, kLogReceiverLen);
    EXPECT_EQ(pp2.mqrpmt_pp.log_client_len, kLogSenderLen);
}

// ── Setup guard tests ─────────────────────────────────────────────────────────

TEST_F(MqRPMTPSOTest, Setup_BloomFilter_MissingSSP_Asserts) {
    EXPECT_DEATH(
        pso::setup(kNormalCurveId, kNormalCurveId, kLogSenderLen, kLogReceiverLen, 0, 0,
                   cwprf_mqrpmt::MembershipMode::BloomFilter),
        ".*");
}

TEST_F(MqRPMTPSOTest, Setup_InvalidBounds_Asserts) {
    // Assert triggered when log_sum_bound < log_sender_len + log_value_bound
    EXPECT_DEATH(
        pso::setup(kNormalCurveId, kNormalCurveId, 10, 10, 12, 5, cwprf_mqrpmt::MembershipMode::PlainSet),
        ".*Parameters configuration fault.*");
}

// ── Edge-case intersection sizes ──────────────────────────────────────────────

TEST_F(MqRPMTPSOTest, EmptyIntersection) {
    const size_t sender_len   = 1u << kLogSenderLen;
    const size_t receiver_len = 1u << kLogReceiverLen;

    auto pp = pso::setup(kNormalCurveId, kNormalCurveId, kLogSenderLen, kLogReceiverLen, 0, 0,
                         cwprf_mqrpmt::MembershipMode::PlainSet);
    auto ds  = make_dataset(sender_len, receiver_len, 0, pp.ring_ctx);
    auto res = run_protocol(pp, ds, pso::PsoMode::kIntersection, kPortEmptyIntersect);

    EXPECT_TRUE(res.receiver_out.set_result.empty());
}

TEST_F(MqRPMTPSOTest, FullIntersection) {
    constexpr size_t kLogSmallSender = 7; 
    const size_t sender_len   = 1u << kLogSmallSender;
    const size_t receiver_len = 1u << kLogReceiverLen;
    ASSERT_LE(sender_len, receiver_len);

    auto pp = pso::setup(kNormalCurveId, kNormalCurveId, kLogSmallSender, kLogReceiverLen, kLogSumBound, kLogValueBound,
                         cwprf_mqrpmt::MembershipMode::PlainSet);
    auto ds  = make_dataset(sender_len, receiver_len, sender_len, pp.ring_ctx);
    auto res = run_protocol(pp, ds, pso::PsoMode::kCardSum, kPortFullIntersect);

    EXPECT_EQ(res.receiver_out.cardinality, sender_len);
    EXPECT_TRUE(res.sender_out.card_sum == ds.expected_card_sum);
}

TEST_F(MqRPMTPSOTest, AsymmetricSizes_PlainSet) {
    const size_t sender_len   = 1u << kLogSenderLen;
    const size_t receiver_len = 1u << kLogReceiverLen;

    auto pp = pso::setup(kNormalCurveId, kNormalCurveId, kLogSenderLen, kLogReceiverLen, 0, 0,
                         cwprf_mqrpmt::MembershipMode::PlainSet);
    auto ds  = make_dataset(sender_len, receiver_len, receiver_len / 2, pp.ring_ctx);
    auto res = run_protocol(pp, ds, pso::PsoMode::kIntersection, kPortAsymmetric);

    validate_set(res.receiver_out.set_result, ds.ground_truth_intersection, 
                 cwprf_mqrpmt::MembershipMode::PlainSet, "Asymmetric/PlainSet");
}

// ── Role-crossing structural invariant ───────────────────────────────────────

TEST_F(MqRPMTPSOTest, RoleCrossing_Invariant) {
    auto pp = pso::setup(kNormalCurveId, kNormalCurveId, kLogSenderLen, kLogReceiverLen, 0, 0,
                         cwprf_mqrpmt::MembershipMode::PlainSet);

    EXPECT_EQ(pp.mqrpmt_pp.log_server_len, pp.log_receiver_len);
    EXPECT_EQ(pp.mqrpmt_pp.log_client_len, pp.log_sender_len);
}

// ── main ──────────────────────────────────────────────────────────────────────

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}