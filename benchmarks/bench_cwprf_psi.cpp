/****************************************************************************
 * @file      bench_cwprf_psi.cpp
 * @brief     Performance benchmark suite for cwPRF-based two-party PSI.
 *
 * @details
 *   Benchmarked configurations (6 total):
 *
 *     Secp256r1 (compressed,   33 bytes/point) + MembershipMode::Truncate
 *     Secp256r1 (compressed,   33 bytes/point) + MembershipMode::PlainSet
 *     Secp256r1 (uncompressed, 65 bytes/point) + MembershipMode::Truncate
 *     Secp256r1 (uncompressed, 65 bytes/point) + MembershipMode::PlainSet
 *     X25519    (always 32 bytes/point)        + MembershipMode::Truncate
 *     X25519    (always 32 bytes/point)        + MembershipMode::PlainSet
 *
 *   Dataset
 *     Sender   : 2^20 elements
 *     Receiver : 2^20 elements
 *     Intersection : 50% (first half of receiver set overlaps with sender)
 *
 *   Threading note
 *     Sender and receiver run concurrently on THIS machine via std::async,
 *     each spawning its own OMP thread pool of size config::thread_num.
 *     Total concurrent OMP threads = 2 × config::thread_num, competing for
 *     the same physical cores. This differs from a real two-party deployment
 *     where each party runs on a dedicated machine.
 *
 * @author    This file is part of Taihang, developed by Yu Chen.
 *****************************************************************************/

#include <taihang/mpc/pso/cwprf_psi.hpp>
#include <taihang/common/config.hpp>
#include <taihang/common/logger.hpp>
#include <taihang/common/bench_setting.hpp>
#include <taihang/crypto/prg.hpp>

#include <openssl/obj_mac.h>   // NID_X25519


#include <chrono>
#include <future>
#include <iomanip>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

using namespace taihang;
using namespace taihang::mpc::cwprf_psi;

using Clock = std::chrono::high_resolution_clock;
using Ms    = std::chrono::duration<double, std::milli>;

// ===========================================================================
// Dataset (generated once, shared across all benchmark runs)
// ===========================================================================

struct Dataset {
    std::vector<Block> vec_y;          // Sender's set
    std::vector<Block> vec_x;          // Receiver's set
    size_t             intersection_len;
};

static Dataset make_dataset(size_t sender_len, size_t receiver_len) {
    Block     seed_block = make_block(0x123456789ABCDEF0ULL, 0x0FEDCBA987654321ULL);
    prg::Seed seed       = prg::set_seed(&seed_block, 0);

    Dataset ds;
    ds.vec_y.resize(sender_len);
    ds.vec_x.resize(receiver_len);
    ds.intersection_len = receiver_len / 2;

    prg::gen_random_blocks(seed, ds.vec_y.data(), sender_len);

    for (size_t i = 0; i < receiver_len; ++i) {
        if (i < ds.intersection_len)
            ds.vec_x[i] = ds.vec_y[i];                       // intersecting
        else
            ds.vec_x[i] = make_block(i, 0xDEADBEEFADDEULL); // disjoint
    }
    return ds;
}

// ===========================================================================
// Single benchmark run
// ===========================================================================

struct BenchResult {
    double sender_ms;
    double receiver_ms;
    double wall_ms;
    size_t intersection_found;
};

static BenchResult run_once(const PublicParameters& pp,
                             const Dataset&          ds,
                             uint16_t                port)
{
    const std::string addr = "127.0.0.1";
    auto wall_begin = Clock::now();

    auto sender_future = std::async(std::launch::async, [&]() {
        net::NetIO io("server", addr, port);
        auto t0 = Clock::now();
        sender(io, pp, ds.vec_y);
        return Ms(Clock::now() - t0).count();
    });

    auto receiver_future = std::async(std::launch::async, [&]() {
        net::NetIO io("client", addr, port);
        auto t0          = Clock::now();
        auto intersection = receiver(io, pp, ds.vec_x);
        double ms        = Ms(Clock::now() - t0).count();
        return std::make_pair(std::move(intersection), ms);
    });

    double sender_ms = sender_future.get();
    auto [intersection, receiver_ms] = receiver_future.get();
    double wall_ms = Ms(Clock::now() - wall_begin).count();

    return { sender_ms, receiver_ms, wall_ms, intersection.size() };
}

// ===========================================================================
// Printing helpers
// ===========================================================================

static double kelem_per_sec(size_t n, double ms) {
    return static_cast<double>(n) / (ms / 1000.0) / 1000.0;
}


static void print_header(const std::string& label,
                          size_t sender_len, size_t receiver_len,
                          size_t log_sender,  size_t log_receiver)
{
    std::cout
        << "\n"
        << "================================================================================\n"
        << label << "\n"
        << "--------------------------------------------------------------------------------\n"
        << "Sender Set   : 2^" << log_sender   << " = " << sender_len   << "\n"
        << "Receiver Set : 2^" << log_receiver  << " = " << receiver_len  << "\n"
        << "Intersection : 50%\n"
        << "================================================================================\n";
}

static void print_result(const BenchResult& r,
                          size_t sender_len,
                          size_t expected_intersection)
{
    double sender_tp   = kelem_per_sec(sender_len, r.sender_ms);
    double receiver_tp = kelem_per_sec(sender_len, r.receiver_ms);

    std::cout << std::fixed << std::setprecision(2)
        << "Wall time          : " << r.wall_ms     / 1000.0 << " s\n"
        << "Sender time        : " << r.sender_ms   / 1000.0 << " s    ("
                                   << sender_tp               << " Kelem/s)\n"
        << "Receiver time      : " << r.receiver_ms / 1000.0 << " s    ("
                                   << receiver_tp              << " Kelem/s)\n"
        << "Intersection found : " << r.intersection_found
        << " / " << expected_intersection
        << (r.intersection_found >= expected_intersection ? "  [PASS]" : "  [FAIL]") << "\n";
}

static void print_summary(
        const std::vector<std::pair<std::string, BenchResult>>& results,
        size_t sender_len, size_t receiver_len,
        size_t log_sender,  size_t log_receiver)
{
    constexpr int LW = 40;   // label column width

    std::cout
        << "\n\n"
        << "========================================================================================================\n"
        << "                           Taihang cwPRF-PSI Benchmark Summary\n"
        << "========================================================================================================\n"
        << "Sender   : 2^" << log_sender   << " (" << sender_len   << ") elements\n"
        << "Receiver : 2^" << log_receiver  << " (" << receiver_len  << ") elements    50% intersection\n"
        << "--------------------------------------------------------------------------------------------------------\n"
        << std::left  << std::setw(LW) << "Configuration"
        << std::right << std::setw(12) << "Sender(s)"
                      << std::setw(13) << "Receiver(s)"
                      << std::setw(11) << "Wall(s)"
                      << std::setw(14) << "Kelem/s"
        << "\n"
        << "--------------------------------------------------------------------------------------------------------\n";

    for (const auto& [label, r] : results) {
        std::cout
            << std::left  << std::setw(LW) << label
            << std::right << std::fixed << std::setprecision(2)
            << std::setw(12) << r.sender_ms   / 1000.0
            << std::setw(13) << r.receiver_ms / 1000.0
            << std::setw(11) << r.wall_ms     / 1000.0
            << std::setw(14) << kelem_per_sec(sender_len, r.sender_ms)
            << "\n";
    }

    // ── Compression speedup (compressed vs uncompressed, Secp256r1 rows 0–3) ──
    if (results.size() >= 4) {
        double cmp_trunc_s   = results[0].second.sender_ms;
        double cmp_plain_s   = results[1].second.sender_ms;
        double ucmp_trunc_s  = results[2].second.sender_ms;
        double ucmp_plain_s  = results[3].second.sender_ms;

        std::cout
            << "--------------------------------------------------------------------------------------------------------\n"
            << "Secp256r1 compression speedup (compressed vs uncompressed, sender side)\n"
            << "  Truncate : " << std::fixed << std::setprecision(2)
            << ucmp_trunc_s / cmp_trunc_s << "x\n"
            << "  PlainSet : "
            << ucmp_plain_s / cmp_plain_s << "x\n";
    }

    // ── Truncate vs PlainSet speedup ──────────────────────────────────────────
    if (results.size() >= 6) {
        auto speedup = [](double plain_ms, double truncate_ms) {
            return plain_ms / truncate_ms;
        };

        std::cout
            << "--------------------------------------------------------------------------------------------------------\n"
            << "PlainSet slowdown vs Truncate (sender side — PlainSet sends full-length points)\n"
            << "  Secp256r1 compressed   : "
            << speedup(results[1].second.sender_ms, results[0].second.sender_ms) << "x\n"
            << "  Secp256r1 uncompressed : "
            << speedup(results[3].second.sender_ms, results[2].second.sender_ms) << "x\n"
            << "  X25519                 : "
            << speedup(results[5].second.sender_ms, results[4].second.sender_ms) << "x\n";
    }

    std::cout
        << "========================================================================================================\n";
}

// ===========================================================================
// main
// ===========================================================================

int main() {
    constexpr size_t kLogSenderLen   = 20;
    constexpr size_t kLogReceiverLen = 20;
    constexpr size_t kSSP            = 40;

    // Six configurations — each needs a distinct port.
    constexpr uint16_t kPortSecpCompTrunc   = 12360;
    constexpr uint16_t kPortSecpCompPlain   = 12361;
    constexpr uint16_t kPortSecpUncompTrunc = 12362;
    constexpr uint16_t kPortSecpUncompPlain = 12363;
    constexpr uint16_t kPortX25519Trunc     = 12364;
    constexpr uint16_t kPortX25519Plain     = 12365;

    const size_t sender_len   = 1ULL << kLogSenderLen;
    const size_t receiver_len = 1ULL << kLogReceiverLen;

    //==============================================================================
    // Thread configuration
    //==============================================================================

    constexpr BenchmarkMode kBenchmarkMode = BenchmarkMode::SingleMachine; 
    thread_configuration(kBenchmarkMode); 

    // ── Dataset generation (done once) ───────────────────────────────────
    std::cout << "\nGenerating benchmark dataset...\n";
    auto t0 = Clock::now();
    Dataset ds = make_dataset(sender_len, receiver_len);
    std::cout << "Dataset ready in "
              << std::fixed << std::setprecision(2)
              << Ms(Clock::now() - t0).count() << " ms\n";

    std::vector<std::pair<std::string, BenchResult>> summary;

    // =====================================================================
    // Secp256r1 + Compressed (33 bytes/point) + Truncate
    // =====================================================================
    {
        config::use_point_compression = true;
        print_header("Secp256r1 [compressed, 33 bytes/point] + Truncate",
                     sender_len, receiver_len, kLogSenderLen, kLogReceiverLen);

        auto pp = setup(415, kLogSenderLen, kLogReceiverLen,
                        MembershipMode::Truncate, kSSP);
        auto r  = run_once(pp, ds, kPortSecpCompTrunc);
        print_result(r, sender_len, ds.intersection_len);
        summary.emplace_back("Secp256r1 [comp]   + Truncate", r);
    }

    // =====================================================================
    // Secp256r1 + Compressed (33 bytes/point) + PlainSet
    // =====================================================================
    {
        config::use_point_compression = true;
        print_header("Secp256r1 [compressed, 33 bytes/point] + PlainSet",
                     sender_len, receiver_len, kLogSenderLen, kLogReceiverLen);

        auto pp = setup(415, kLogSenderLen, kLogReceiverLen,
                        MembershipMode::PlainSet);
        auto r  = run_once(pp, ds, kPortSecpCompPlain);
        print_result(r, sender_len, ds.intersection_len);
        summary.emplace_back("Secp256r1 [comp]   + PlainSet ", r);
    }

    // =====================================================================
    // Secp256r1 + Uncompressed (65 bytes/point) + Truncate
    // =====================================================================
    {
        config::use_point_compression = false;
        print_header("Secp256r1 [uncompressed, 65 bytes/point] + Truncate",
                     sender_len, receiver_len, kLogSenderLen, kLogReceiverLen);

        auto pp = setup(415, kLogSenderLen, kLogReceiverLen,
                        MembershipMode::Truncate, kSSP);
        auto r  = run_once(pp, ds, kPortSecpUncompTrunc);
        print_result(r, sender_len, ds.intersection_len);
        summary.emplace_back("Secp256r1 [uncomp] + Truncate", r);
    }

    // =====================================================================
    // Secp256r1 + Uncompressed (65 bytes/point) + PlainSet
    // =====================================================================
    {
        config::use_point_compression = false;
        print_header("Secp256r1 [uncompressed, 65 bytes/point] + PlainSet",
                     sender_len, receiver_len, kLogSenderLen, kLogReceiverLen);

        auto pp = setup(415, kLogSenderLen, kLogReceiverLen,
                        MembershipMode::PlainSet);
        auto r  = run_once(pp, ds, kPortSecpUncompPlain);
        print_result(r, sender_len, ds.intersection_len);
        summary.emplace_back("Secp256r1 [uncomp] + PlainSet ", r);
    }

    // Restore default for X25519 runs (irrelevant but tidy).
    config::use_point_compression = true;

    // =====================================================================
    // X25519 + Truncate  (always 32 bytes/point)
    // =====================================================================
    {
        print_header("X25519 [32 bytes/point] + Truncate",
                     sender_len, receiver_len, kLogSenderLen, kLogReceiverLen);

        auto pp = setup(NID_X25519, kLogSenderLen, kLogReceiverLen,
                        MembershipMode::Truncate, kSSP);
        auto r  = run_once(pp, ds, kPortX25519Trunc);
        print_result(r, sender_len, ds.intersection_len);
        summary.emplace_back("X25519             + Truncate", r);
    }

    // =====================================================================
    // X25519 + PlainSet
    // =====================================================================
    {
        print_header("X25519 [32 bytes/point] + PlainSet",
                     sender_len, receiver_len, kLogSenderLen, kLogReceiverLen);

        auto pp = setup(NID_X25519, kLogSenderLen, kLogReceiverLen,
                        MembershipMode::PlainSet);
        auto r  = run_once(pp, ds, kPortX25519Plain);
        print_result(r, sender_len, ds.intersection_len);
        summary.emplace_back("X25519             + PlainSet ", r);
    }

    // ── Final summary table ───────────────────────────────────────────────
    print_summary(summary, sender_len, receiver_len, kLogSenderLen, kLogReceiverLen);

    return 0;
}
