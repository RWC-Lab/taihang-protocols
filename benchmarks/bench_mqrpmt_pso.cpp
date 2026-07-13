/****************************************************************************
 * @file      bench_mqrpmt_pso.cpp
 * @brief     Performance benchmark suite for the unified mqRPMT-based 
 *            Private Set Operations (PSO) framework.
 *
 * @details
 *   Benchmarked configurations (table-driven — see `kConfigs`):
 *     Evaluates Intersection, Union, Cardinality, and Card-Sum operations
 *     across different curve definitions and membership structures.
 *
 *   Dataset
 *     Sender   : 2^20 elements  (|X|)
 *     Receiver : 2^20 elements  (|Y|)
 *     Intersection : 50%  (first half of X copied from Y)
 *
 *   Threading note
 *     Sender and receiver run concurrently on THIS machine via std::async.
 *     Total OMP threads = 2 × config::thread_num, competing for the same
 *     physical cores. See threading diagnostics printed at startup.
 *
 * @author    This file is part of Taihang, developed by Yu Chen.
 *****************************************************************************/

#include <taihang/mpc/pso/mqrpmt_pso.hpp>
#include <taihang/common/config.hpp>
#include <taihang/common/logger.hpp>
#include <taihang/common/bench_setting.hpp>
#include <taihang/crypto/prg.hpp>
#include <taihang/crypto/zn.hpp>
#include <openssl/obj_mac.h>   // NID_X25519
#include <chrono>
#include <future>
#include <iomanip>
#include <iostream>
#include <optional>
#include <string>
#include <tuple>
#include <vector>

using namespace taihang;
using namespace taihang::mpc;
namespace pso = taihang::mpc::mqrpmt_pso;

using Clock = std::chrono::high_resolution_clock;
using Ms    = std::chrono::duration<double, std::milli>;

namespace {

// ===========================================================================
// Fixed benchmark parameters
// ===========================================================================

constexpr size_t kLogSenderLen   = 20;
constexpr size_t kLogReceiverLen = 20;
constexpr size_t kLogSumBound    = 62;
constexpr size_t kLogValueBound  = 32;
constexpr size_t kSSP            = 40;
constexpr int    kSecp256r1      = 415;

// ===========================================================================
// Dataset
// ===========================================================================

struct Dataset {
    std::vector<Block>     vec_x;          // Sender's set
    std::vector<Block>     vec_y;          // Receiver's set
    std::vector<ZnElement> vec_v;          // Associated values for Card-Sum
    size_t                 intersection_len;
};

Dataset make_dataset(size_t sender_len, size_t receiver_len, const Zn& field) {
    Block     seed_block = make_block(0x123456789ABCDEF0ULL, 0x0FEDCBA987654321ULL);
    prg::Seed seed       = prg::set_seed(&seed_block, 0);

    Dataset ds;
    ds.vec_x.resize(sender_len);
    ds.vec_y.resize(receiver_len);
    ds.intersection_len = sender_len / 2;

    prg::gen_random_blocks(seed, ds.vec_y.data(), receiver_len);

    for (size_t i = 0; i < sender_len; ++i) {
        ds.vec_x[i] = (i < ds.intersection_len)
                          ? ds.vec_y[i]                        // intersecting
                          : make_block(i, 0xDEADBEEFADDEULL);  // disjoint
    }

    // Populate random associated values for the Card-Sum pipeline evaluations
    ds.vec_v = gen_random_znelement_vector(&field, sender_len);
    return ds;
}

// ===========================================================================
// Configuration table — the single source of truth for what gets benchmarked
// ===========================================================================

struct Config {
    std::string                  label;
    pso::PsoMode                 pso_mode;
    int                          curve_id;
    cwprf_mqrpmt::MembershipMode mem_mode;
    uint16_t                     port;
};

const std::vector<Config> kConfigs = {
    {"PSI (Secp256r1 + BloomFilter)", pso::PsoMode::kIntersection, kSecp256r1,  cwprf_mqrpmt::MembershipMode::BloomFilter, 12380},
    {"PSU (Secp256r1 + PlainSet)",    pso::PsoMode::kUnion,        kSecp256r1,  cwprf_mqrpmt::MembershipMode::PlainSet,    12381},
    {"PSI-Card (X25519 + BloomFilter)",pso::PsoMode::kCard,         NID_X25519, cwprf_mqrpmt::MembershipMode::BloomFilter, 12382},
    {"Card-Sum (X25519 + PlainSet)",   pso::PsoMode::kCardSum,      NID_X25519, cwprf_mqrpmt::MembershipMode::PlainSet,    12383},
};

pso::PublicParameters make_pp(const Config& cfg) {
    // BloomFilter mode requires an explicit statistical security parameter;
    // PlainSet mode asserts if one is given, so the two modes must be
    // constructed through different setup parameters.
    return (cfg.mem_mode == cwprf_mqrpmt::MembershipMode::BloomFilter)
               ? pso::setup(cfg.curve_id, cfg.curve_id, kLogSenderLen, kLogReceiverLen, kLogSumBound, kLogValueBound, cfg.mem_mode, kSSP)
               : pso::setup(cfg.curve_id, cfg.curve_id, kLogSenderLen, kLogReceiverLen, kLogSumBound, kLogValueBound, cfg.mem_mode);
}

// ===========================================================================
// Benchmark result
// ===========================================================================

struct BenchResult {
    double sender_ms    = 0.0;
    double receiver_ms  = 0.0;
    double wall_ms      = 0.0;
    size_t cardinality  = 0;
};

double kelem_per_sec(size_t n, double ms) {
    return static_cast<double>(n) / (ms / 1000.0) / 1000.0;
}

BenchResult run_once(const pso::PublicParameters& pp,
                     const Config&                cfg,
                     const Dataset&               ds) {
    const std::string addr = "127.0.0.1";
    auto wall_begin = Clock::now();

    auto sender_future = std::async(std::launch::async, [&] {
        net::NetIO io("server", addr, cfg.port);
        auto t0 = Clock::now();
        pso::pso_sender(io, pp, ds.vec_x, cfg.pso_mode, ds.vec_v);
        return Ms(Clock::now() - t0).count();
    });

    auto receiver_future = std::async(std::launch::async, [&] {
        net::NetIO io("client", addr, cfg.port);
        auto t0     = Clock::now();
        auto output = pso::pso_receiver(io, pp, ds.vec_y, cfg.pso_mode);
        double duration = Ms(Clock::now() - t0).count();
        return std::make_pair(output.cardinality, duration);
    });

    BenchResult r;
    r.sender_ms = sender_future.get();
    std::tie(r.cardinality, r.receiver_ms) = receiver_future.get();
    r.wall_ms = Ms(Clock::now() - wall_begin).count();
    return r;
}

// ===========================================================================
// Printing helpers
// ===========================================================================

void print_header(const Config& cfg, size_t sender_len, size_t receiver_len) {
    std::cout
        << "\n"
        << "================================================================================\n"
        << cfg.label << "\n"
        << "--------------------------------------------------------------------------------\n"
        << "Sender Set   (X) : 2^" << kLogSenderLen   << " = " << sender_len   << "\n"
        << "Receiver Set (Y) : 2^" << kLogReceiverLen << " = " << receiver_len << "\n"
        << "Intersection     : 50% of X\n"
        << "================================================================================\n";
}

void print_result(const BenchResult& r, size_t sender_len, size_t expected_intersection, pso::PsoMode mode) {
    std::cout << std::fixed << std::setprecision(2)
        << "Wall time          : " << r.wall_ms     / 1000.0 << " s\n"
        << "Sender time        : " << r.sender_ms   / 1000.0 << " s"
        << "    (" << kelem_per_sec(sender_len, r.sender_ms)   << " Kelem/s)\n"
        << "Receiver time      : " << r.receiver_ms / 1000.0 << " s"
        << "    (" << kelem_per_sec(sender_len, r.receiver_ms) << " Kelem/s)\n";

    if (mode == pso::PsoMode::kCard || mode == pso::PsoMode::kCardSum) {
        std::cout << "Cardinality found  : " << r.cardinality
                  << " / " << expected_intersection
                  << (r.cardinality == expected_intersection ? "  [PASS]" : "  [FAIL]") << "\n";
    }
}

void print_summary(const std::vector<std::pair<Config, BenchResult>>& results,
                    size_t sender_len, size_t receiver_len) {
    constexpr int LW = 42;

    std::cout
        << "\n\n"
        << "========================================================================================================\n"
        << "                         Taihang Unified mqRPMT-PSO Framework Summary\n"
        << "========================================================================================================\n"
        << "Sender   (X) : 2^" << kLogSenderLen   << " (" << sender_len   << ") elements\n"
        << "Receiver (Y) : 2^" << kLogReceiverLen << " (" << receiver_len << ") elements   "
        << "50% intersection\n"
        << "Threads      : " << config::thread_num << " per party  ("
        << config::thread_num * 2 << " concurrent total, single-machine loopback)\n"
        << "--------------------------------------------------------------------------------------------------------\n"
        << std::left  << std::setw(LW) << "Configuration"
        << std::right << std::setw(12) << "Sender(s)"
                      << std::setw(13) << "Receiver(s)"
                      << std::setw(11) << "Wall(s)"
                      << std::setw(14) << "Kelem/s"
        << "\n"
        << "--------------------------------------------------------------------------------------------------------\n";

    for (const auto& [cfg, r] : results) {
        std::cout
            << std::left  << std::setw(LW) << cfg.label
            << std::right << std::fixed << std::setprecision(2)
            << std::setw(12) << r.sender_ms   / 1000.0
            << std::setw(13) << r.receiver_ms / 1000.0
            << std::setw(11) << r.wall_ms     / 1000.0
            << std::setw(14) << kelem_per_sec(sender_len, r.sender_ms)
            << "\n";
    }
    std::cout << "========================================================================================================\n";
}

} // namespace

// ===========================================================================
// main
// ===========================================================================

int main() {
    const size_t sender_len   = 1ULL << kLogSenderLen;
    const size_t receiver_len = 1ULL << kLogReceiverLen;

    thread_configuration(BenchmarkMode::SingleMachine);

    std::cout << "\nGenerating benchmark dataset...\n";
    auto t0 = Clock::now();
    
    // Explicit scalar field initialization to seed the associated evaluation values
    Zn local_field(BigInt(1ULL << kLogSumBound));
    Dataset ds = make_dataset(sender_len, receiver_len, local_field);
    
    std::cout << "Dataset ready in "
              << std::fixed << std::setprecision(2)
              << Ms(Clock::now() - t0).count() << " ms\n";

    std::vector<std::pair<Config, BenchResult>> summary;
    summary.reserve(kConfigs.size());

    for (const auto& cfg : kConfigs) {
        print_header(cfg, sender_len, receiver_len);

        auto pp = make_pp(cfg);
        auto r  = run_once(pp, cfg, ds);

        print_result(r, sender_len, ds.intersection_len, cfg.pso_mode);
        summary.emplace_back(cfg, r);
    }

    print_summary(summary, sender_len, receiver_len);
    return 0;
}