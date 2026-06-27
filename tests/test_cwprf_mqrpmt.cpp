/****************************************************************************
 * @file      test_cwprf_mqrpmt.cpp
 * @brief     Google Test suite for cwPRF-based mqRPMT protocol.
 * @details   Covers all four combinations of:
 *              curve  : NormalCurve (Secp256r1)  |  X25519 (NID_X25519)
 *              filter : BloomFilter              |  PlainSet
 *            Each test spawns a loopback server + client via std::async,
 *            builds a synthetic dataset with a known intersection, runs the
 *            protocol, and validates the indication-bit output.
 * @author    This file is part of Taihang, developed by Yu Chen.
 *****************************************************************************/

#include <gtest/gtest.h>
#include <taihang/mpc/rpmt/cwprf_mqrpmt.hpp>
#include <taihang/common/logger.hpp>
#include <taihang/crypto/prg.hpp>
#include <openssl/obj_mac.h>   // NID_X25519
#include <future>
#include <set>
#include <cstring>
#include <cmath>

using namespace taihang;
using namespace taihang::mpc::cwprf_mqrpmt;

// ── Test fixture ──────────────────────────────────────────────────────────────

class CwPRFMqRPMTTest : public ::testing::Test {
protected:
    // Protocol dimensions (kept small for unit-test speed)
    static constexpr size_t kLogServerLen = 6;   // 2^6 = 64
    static constexpr size_t kLogClientLen = 5;   // 2^5 = 32
    static constexpr size_t kSSP          = 40;  // BloomFilter FPR ~ 2^-40

    // Each test case uses a distinct port to avoid bind() conflicts when
    // tests run in parallel or in rapid succession.
    static constexpr uint16_t kPortNormalBloom   = 12340;
    static constexpr uint16_t kPortNormalPlain   = 12341;
    static constexpr uint16_t kPortX25519Bloom   = 12342;
    static constexpr uint16_t kPortX25519Plain   = 12343;

    // ── Dataset helpers ───────────────────────────────────────────────────

    struct Dataset {
        std::vector<Block> vec_y;                    // server set
        std::vector<Block> vec_x;                    // client set
        size_t             expected_intersection;    // ground-truth count
        // ground_truth[i] == true  iff  vec_x[i] ∈ vec_y
        std::vector<bool>  ground_truth;
    };

    static Dataset make_dataset(size_t server_len, size_t client_len) {
        // Reproducible random pool
        Block seed_block = make_block(0x123456789ABCDEF0ULL, 0x0FEDCBA987654321ULL);
        prg::Seed seed   = prg::set_seed(&seed_block, 0);

        std::vector<Block> pool(server_len + client_len);
        prg::gen_random_blocks(seed, pool.data(), pool.size());

        Dataset ds;
        ds.vec_y.resize(server_len);
        ds.vec_x.resize(client_len);
        ds.ground_truth.resize(client_len, false);

        for (size_t i = 0; i < server_len; ++i) {
            ds.vec_y[i] = pool[i];
        }

        // First half of client set overlaps with server set → known intersection
        ds.expected_intersection = client_len / 2;
        for (size_t i = 0; i < client_len; ++i) {
            if (i < ds.expected_intersection) {
                ds.vec_x[i]       = pool[i];   // in vec_y
                ds.ground_truth[i] = true;
            } else {
                ds.vec_x[i]       = pool[server_len + i]; // disjoint
                ds.ground_truth[i] = false;
            }
        }
        return ds;
    }

    // ── Protocol runner ───────────────────────────────────────────────────

    // Spawns server + client on loopback, returns indication bit vector.
    static std::vector<uint8_t> run_protocol(const PublicParameters& pp,
                                              const Dataset&          ds,
                                              uint16_t                port)
    {
        const std::string addr = "127.0.0.1";

        auto server_task = std::async(std::launch::async, [&]() {
            net::NetIO io("server", addr, port);
            return server(io, pp, ds.vec_y);
        });

        auto client_task = std::async(std::launch::async, [&]() {
            net::NetIO io("client", addr, port);
            client(io, pp, ds.vec_x);
        });

        client_task.get();
        return server_task.get();
    }

    // ── Correctness validator ─────────────────────────────────────────────

    // For BloomFilter mode: no false negatives allowed; false positives OK.
    // For PlainSet mode:    exact match required (no false positives either).
    static void validate(const std::vector<uint8_t>& bits,
                         const Dataset&               ds,
                         FilterMode                   mode,
                         const std::string&           label)
    {
        const size_t n = ds.vec_x.size();
        ASSERT_EQ(bits.size(), n) << label << ": indication vector size mismatch.";

        size_t tp = 0, fp = 0, fn = 0;
        for (size_t i = 0; i < n; ++i) {
            bool indicated = (bits[i] == 1);
            bool expected  = ds.ground_truth[i];

            if (indicated && expected)  ++tp;
            if (indicated && !expected) ++fp;
            if (!indicated && expected) ++fn;
        }

        std::cout << "[" << label << "] "
                  << "TP=" << tp << "  FP=" << fp << "  FN=" << fn
                  << "  (expected intersection=" << ds.expected_intersection << ")\n";

        // False negatives are always a hard failure in both modes
        EXPECT_EQ(fn, 0u) << label << ": false negatives detected.";

        if (mode == FilterMode::PlainSet) {
            // PlainSet is exact — false positives are also forbidden
            EXPECT_EQ(fp, 0u) << label << ": false positives in PlainSet mode.";
        }

        EXPECT_EQ(tp, ds.expected_intersection)
            << label << ": true-positive count does not match expected intersection.";
    }
};

// ── Test cases ────────────────────────────────────────────────────────────────

// 1. Normal curve + BloomFilter
TEST_F(CwPRFMqRPMTTest, NormalCurve_BloomFilter) {
    constexpr int curve_id = 415; // Secp256r1

    auto pp = setup(curve_id, kLogServerLen, kLogClientLen,
                    FilterMode::BloomFilter, kSSP);
    auto ds = make_dataset(static_cast<size_t>(std::pow(2, kLogServerLen)),
                           static_cast<size_t>(std::pow(2, kLogClientLen)));

    auto bits = run_protocol(pp, ds, kPortNormalBloom);
    validate(bits, ds, FilterMode::BloomFilter, "NormalCurve/BloomFilter");
}

// 2. Normal curve + PlainSet
TEST_F(CwPRFMqRPMTTest, NormalCurve_PlainSet) {
    constexpr int curve_id = 415;

    auto pp = setup(curve_id, kLogServerLen, kLogClientLen,
                    FilterMode::PlainSet);
    auto ds = make_dataset(static_cast<size_t>(std::pow(2, kLogServerLen)),
                           static_cast<size_t>(std::pow(2, kLogClientLen)));

    auto bits = run_protocol(pp, ds, kPortNormalPlain);
    validate(bits, ds, FilterMode::PlainSet, "NormalCurve/PlainSet");
}

// 3. X25519 + BloomFilter
TEST_F(CwPRFMqRPMTTest, X25519_BloomFilter) {
    auto pp = setup(NID_X25519, kLogServerLen, kLogClientLen,
                    FilterMode::BloomFilter, kSSP);
    auto ds = make_dataset(static_cast<size_t>(std::pow(2, kLogServerLen)),
                           static_cast<size_t>(std::pow(2, kLogClientLen)));

    auto bits = run_protocol(pp, ds, kPortX25519Bloom);
    validate(bits, ds, FilterMode::BloomFilter, "X25519/BloomFilter");
}

// 4. X25519 + PlainSet
TEST_F(CwPRFMqRPMTTest, X25519_PlainSet) {
    auto pp = setup(NID_X25519, kLogServerLen, kLogClientLen,
                    FilterMode::PlainSet);
    auto ds = make_dataset(static_cast<size_t>(std::pow(2, kLogServerLen)),
                           static_cast<size_t>(std::pow(2, kLogClientLen)));

    auto bits = run_protocol(pp, ds, kPortX25519Plain);
    validate(bits, ds, FilterMode::PlainSet, "X25519/PlainSet");
}

// ── PublicParameters serialisation round-trip ─────────────────────────────────

TEST_F(CwPRFMqRPMTTest, PublicParameters_Serialization_NormalCurve) {
    auto pp = setup(415, kLogServerLen, kLogClientLen,
                    FilterMode::BloomFilter, kSSP);

    std::ostringstream oss;
    oss << pp;

    PublicParameters pp2;
    std::istringstream iss(oss.str());
    iss >> pp2;

    EXPECT_EQ(pp.curve_id,                       pp2.curve_id);
    EXPECT_EQ(pp.log_server_len,                  pp2.log_server_len);
    EXPECT_EQ(pp.log_client_len,                  pp2.log_client_len);
    EXPECT_EQ(pp.filter_mode,                     pp2.filter_mode);
    EXPECT_EQ(pp.statistical_security_parameter,  pp2.statistical_security_parameter);
    EXPECT_NE(pp2.group_ctx, nullptr);
    EXPECT_NE(pp2.field_ctx, nullptr);
}

TEST_F(CwPRFMqRPMTTest, PublicParameters_Serialization_X25519) {
    auto pp = setup(NID_X25519, kLogServerLen, kLogClientLen,
                    FilterMode::PlainSet);

    std::ostringstream oss;
    oss << pp;

    PublicParameters pp2;
    std::istringstream iss(oss.str());
    iss >> pp2;

    EXPECT_EQ(pp.curve_id,      pp2.curve_id);
    EXPECT_EQ(pp.log_server_len, pp2.log_server_len);
    EXPECT_EQ(pp.log_client_len, pp2.log_client_len);
    EXPECT_EQ(pp.filter_mode,    pp2.filter_mode);
    // X25519 mode: contexts must remain null after deserialisation
    EXPECT_EQ(pp2.group_ctx, nullptr);
    EXPECT_EQ(pp2.field_ctx, nullptr);
}

// ── setup() guard: BloomFilter without ssp must assert ───────────────────────

TEST_F(CwPRFMqRPMTTest, Setup_BloomFilter_MissingSSP_Asserts) {
    // TAIHANG_ASSERT terminates on failure; use EXPECT_DEATH to catch it.
    EXPECT_DEATH(
        setup(415, kLogServerLen, kLogClientLen, FilterMode::BloomFilter),
        ".*"   // any termination message
    );
}

// ─────────────────────────────────────────────────────────────────────────────

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
