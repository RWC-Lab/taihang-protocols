/****************************************************************************
 * @file      bench_bullet_proof.cpp
 * @brief     Benchmark suite for aggregated Bulletproof range proofs.
 *
 * Public-parameter setup, witness generation, and statement construction are
 * outside the timed region. Each operation is warmed up before measurement.
 *****************************************************************************/

#include <openssl/obj_mac.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <taihang/common/config.hpp>
#include <taihang/system/cpu.hpp>
#include <taihang/zkp/range_proofs/bullet_proof.hpp>

namespace {

using namespace taihang;
namespace bulletproof = taihang::zkp::range_proofs::bulletproof;

using Clock = std::chrono::steady_clock;
using Milliseconds = std::chrono::duration<double, std::milli>;

constexpr int kCurveId = NID_X9_62_prime256v1;
constexpr std::size_t kRangeBits = 32;
constexpr std::size_t kMaxAggregation = 4;
constexpr std::size_t kDefaultIterations = 10;
constexpr std::size_t kDefaultWarmups = 1;
constexpr std::string_view kContext = "bulletproof-benchmark";

constexpr std::array<std::size_t, 3> kAggregations = {1, 2, 4};
constexpr std::array<int, 4> kThreadCounts = {1, 2, 4, 8};

struct Workload {
    std::size_t aggregation;
    bulletproof::Witness witness;
    bulletproof::Statement statement;
};

struct BenchResult {
    std::size_t aggregation = 0;
    int thread_count = 0;
    double prove_ms = 0.0;
    double verify_ms = 0.0;
    bool passed = false;
};

template <typename Function>
double average_ms(std::size_t warmups,
                  std::size_t iterations,
                  Function&& function) {
    for (std::size_t i = 0; i < warmups; ++i) {
        function();
    }

    const auto begin = Clock::now();
    for (std::size_t i = 0; i < iterations; ++i) {
        function();
    }
    return Milliseconds(Clock::now() - begin).count() /
           static_cast<double>(iterations);
}

Workload make_workload(const bulletproof::PublicParameters& pp,
                       std::size_t aggregation) {
    bulletproof::Witness witness{
        std::vector<ZnElement>(aggregation, ZnElement(pp.ring_ctx)),
        std::vector<ZnElement>(aggregation, ZnElement(pp.ring_ctx))};
    bulletproof::Statement statement{
        std::vector<ECPoint>(aggregation, ECPoint(pp.group_ctx))};

    const BigInt bound(uint64_t{1} << kRangeBits);
    for (std::size_t i = 0; i < aggregation; ++i) {
        witness.randomness[i] = pp.ring_ctx->gen_random();
        witness.values[i] = ZnElement(
            pp.ring_ctx, gen_random_bigint_less_than(bound));
        statement.commitments[i] =
            pp.g * witness.randomness[i] + pp.h * witness.values[i];
    }

    return {aggregation, std::move(witness), std::move(statement)};
}

BenchResult run_once(const bulletproof::PublicParameters& pp,
                     const Workload& workload,
                     int thread_count,
                     std::size_t warmups,
                     std::size_t iterations) {
    config::thread_num = thread_count;

    bulletproof::Proof proof;
    const double prove_ms = average_ms(warmups, iterations, [&] {
        proof = bulletproof::prove(
            pp, workload.statement, workload.witness, kContext);
    });

    bool passed = bulletproof::verify(
        pp, workload.statement, proof, kContext);
    const double verify_ms = average_ms(warmups, iterations, [&] {
        passed = bulletproof::verify(
                     pp, workload.statement, proof, kContext) &&
                 passed;
    });

    return {
        workload.aggregation,
        thread_count,
        prove_ms,
        verify_ms,
        passed,
    };
}

void print_benchmark_header(std::size_t physical_cores,
                            std::size_t warmups,
                            std::size_t iterations) {
    std::cout
        << "\n"
        << "===================================================="
           "====================================================\n"
        << "                              Taihang Bulletproof Benchmark\n"
        << "===================================================="
           "====================================================\n"
        << "Curve               : Secp256r1\n"
        << "Range bits          : " << kRangeBits << "\n"
        << "Aggregation sizes   : 1, 2, 4\n"
        << "OpenMP thread counts: 1, 2, 4, 8\n"
        << "Physical CPU cores  : " << physical_cores << "\n"
        << "Warmup calls        : " << warmups << " per operation\n"
        << "Measured calls      : " << iterations << " per operation\n"
        << "===================================================="
           "====================================================\n";
}

void print_workload_header(std::size_t aggregation) {
    std::cout << "\n"
              << "========================================"
                 "========================================\n"
              << "Bulletproof / Secp256r1 / " << kRangeBits
              << "-bit x " << aggregation << "\n"
              << "----------------------------------------"
                 "----------------------------------------\n"
              << std::left << std::setw(12) << "Threads"
              << std::right << std::setw(16) << "Prove(ms)"
              << std::setw(16) << "Verify(ms)"
              << std::setw(12) << "Status" << "\n"
              << "----------------------------------------"
                 "----------------------------------------\n";
}

void print_workload_result(const BenchResult& result) {
    std::cout << std::left << std::setw(12) << result.thread_count
              << std::right << std::fixed << std::setprecision(3)
              << std::setw(16) << result.prove_ms
              << std::setw(16) << result.verify_ms
              << std::setw(12) << (result.passed ? "PASS" : "FAIL")
              << "\n";
}

void print_summary(const std::vector<BenchResult>& results) {
    constexpr int kConfigurationWidth = 20;

    std::cout
        << "\n\n"
        << "===================================================="
           "====================================================\n"
        << "                              Bulletproof Benchmark Summary\n"
        << "===================================================="
           "====================================================\n"
        << std::left << std::setw(kConfigurationWidth) << "Configuration"
        << std::right << std::setw(10) << "Threads"
        << std::setw(14) << "Prove(ms)"
        << std::setw(13) << "Prove(x)"
        << std::setw(14) << "Verify(ms)"
        << std::setw(14) << "Verify(x)"
        << std::setw(10) << "Status" << "\n"
        << "----------------------------------------------------"
           "----------------------------------------------------\n";

    for (std::size_t aggregation : kAggregations) {
        const BenchResult* baseline = nullptr;
        for (const BenchResult& result : results) {
            if (result.aggregation == aggregation &&
                result.thread_count == 1) {
                baseline = &result;
                break;
            }
        }

        for (const BenchResult& result : results) {
            if (result.aggregation != aggregation) {
                continue;
            }

            const std::string label = std::to_string(kRangeBits) +
                                      "-bit x " +
                                      std::to_string(aggregation);
            const double prove_speedup =
                baseline->prove_ms / result.prove_ms;
            const double verify_speedup =
                baseline->verify_ms / result.verify_ms;

            std::cout << std::left << std::setw(kConfigurationWidth) << label
                      << std::right << std::setw(10) << result.thread_count
                      << std::fixed << std::setprecision(3)
                      << std::setw(14) << result.prove_ms
                      << std::setw(13) << prove_speedup
                      << std::setw(14) << result.verify_ms
                      << std::setw(14) << verify_speedup
                      << std::setw(10)
                      << (result.passed ? "PASS" : "FAIL") << "\n";
        }
    }

    std::cout
        << "===================================================="
           "====================================================\n";
}

std::size_t parse_positive(const char* value, const char* name) {
    char* end = nullptr;
    const unsigned long long parsed = std::strtoull(value, &end, 10);
    if (*value == '\0' || *end != '\0' || parsed == 0) {
        std::cerr << name << " must be a positive integer\n";
        std::exit(EXIT_FAILURE);
    }
    return static_cast<std::size_t>(parsed);
}

}  // namespace

int main(int argc, char** argv) {
    if (argc > 3) {
        std::cerr << "Usage: " << argv[0] << " [iterations] [warmups]\n";
        return EXIT_FAILURE;
    }

    const std::size_t iterations =
        argc > 1 ? parse_positive(argv[1], "iterations")
                 : kDefaultIterations;
    const std::size_t warmups =
        argc > 2 ? parse_positive(argv[2], "warmups") : kDefaultWarmups;

    const std::size_t physical_cores = system::get_physical_core_count();
    print_benchmark_header(physical_cores, warmups, iterations);

    // One setup supports all three power-of-two aggregation sizes.
    config::thread_num = 1;
    const bulletproof::PublicParameters pp = bulletproof::setup(
        kCurveId, kRangeBits, kMaxAggregation);

    std::vector<Workload> workloads;
    workloads.reserve(kAggregations.size());
    for (std::size_t aggregation : kAggregations) {
        workloads.emplace_back(make_workload(pp, aggregation));
    }

    std::vector<BenchResult> summary;
    summary.reserve(kAggregations.size() * kThreadCounts.size());
    for (const Workload& workload : workloads) {
        print_workload_header(workload.aggregation);
        for (int thread_count : kThreadCounts) {
            const BenchResult result = run_once(
                pp, workload, thread_count, warmups, iterations);
            print_workload_result(result);
            summary.emplace_back(result);
        }
    }

    print_summary(summary);
    return 0;
}
