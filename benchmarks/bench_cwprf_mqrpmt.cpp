/****************************************************************************
 * @file      bench_cwprf_mqrpmt.cpp
 * @brief     Performance benchmark suite for cwPRF-based mqRPMT protocol.
 *
 * Benchmarked configurations
 *   - Secp256r1 + BloomFilter
 *   - Secp256r1 + PlainSet
 *   - X25519    + BloomFilter
 *   - X25519    + PlainSet
 *
 * Dataset
 *   Server : 2^20 elements
 *   Client : 2^20 elements
 *   Intersection : 50%
 *
 * Author: Yu Chen
 ****************************************************************************/

#include <taihang/mpc/rpmt/cwprf_mqrpmt.hpp>
#include <taihang/common/logger.hpp>
#include <taihang/crypto/prg.hpp>

#include <openssl/obj_mac.h>

#include <chrono>
#include <future>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

using namespace taihang;
using namespace taihang::mpc::cwprf_mqrpmt;

using Clock = std::chrono::high_resolution_clock;
using Ms    = std::chrono::duration<double, std::milli>;


//==============================================================================
// Dataset
//==============================================================================

struct Dataset
{
    std::vector<Block> vec_y;
    std::vector<Block> vec_x;
    size_t intersection_len;
};

static Dataset make_dataset(size_t server_len,
                            size_t client_len)
{
    Block seed_block =
        make_block(0x123456789ABCDEF0ULL,
                   0x0FEDCBA987654321ULL);

    prg::Seed seed = prg::set_seed(&seed_block, 0);

    Dataset ds;

    ds.vec_y.resize(server_len);
    ds.vec_x.resize(client_len);

    ds.intersection_len = client_len / 2;

    //----------------------------------------------------------------------
    // Generate server set
    //----------------------------------------------------------------------

    prg::gen_random_blocks(seed,
                           ds.vec_y.data(),
                           server_len);

    //----------------------------------------------------------------------
    // Client set:
    //   first half  -> intersection
    //   second half -> disjoint
    //----------------------------------------------------------------------

    for (size_t i = 0; i < client_len; ++i)
    {
        if (i < ds.intersection_len)
        {
            ds.vec_x[i] = ds.vec_y[i];
        }
        else
        {
            ds.vec_x[i] =
                make_block(i,
                           0xDEADBEEFADDEULL);
        }
    }

    return ds;
}


//==============================================================================
// Benchmark Result
//==============================================================================

struct BenchResult
{
    double server_ms;
    double client_ms;
    double wall_ms;

    size_t matches;
};


//==============================================================================
// Run one benchmark
//==============================================================================

static BenchResult run_once(const PublicParameters& pp,
                            const Dataset& ds,
                            uint16_t port)
{
    const std::string address = "127.0.0.1";

    auto wall_begin = Clock::now();

    //----------------------------------------------------------------------
    // Server
    //----------------------------------------------------------------------

    auto server_future =
        std::async(std::launch::async,
                   [&]()
                   {
                       net::NetIO io("server",
                                     address,
                                     port);

                       auto t0 = Clock::now();

                       auto bits =
                           server(io,
                                  pp,
                                  ds.vec_y);

                       double elapsed =
                           Ms(Clock::now() - t0).count();

                       return std::make_pair(std::move(bits),
                                             elapsed);
                   });

    //----------------------------------------------------------------------
    // Client
    //----------------------------------------------------------------------

    auto client_future =
        std::async(std::launch::async,
                   [&]()
                   {
                       net::NetIO io("client",
                                     address,
                                     port);

                       auto t0 = Clock::now();

                       client(io,
                              pp,
                              ds.vec_x);

                       return Ms(Clock::now() - t0).count();
                   });

    //----------------------------------------------------------------------
    // Wait
    //----------------------------------------------------------------------

    double client_ms = client_future.get();

    auto [bits, server_ms] =
        server_future.get();

    double wall_ms =
        Ms(Clock::now() - wall_begin).count();

    //----------------------------------------------------------------------
    // Count intersection
    //----------------------------------------------------------------------

    size_t matches = 0;

    for (auto b : bits)
        matches += b;

    return {
        server_ms,
        client_ms,
        wall_ms,
        matches
    };
}

//==============================================================================
// Pretty Printing
//==============================================================================

// static std::string format_time_sec(double ms)
// {
//     std::ostringstream oss;

//     oss << std::fixed
//         << std::setprecision(2)
//         << (ms / 1000.0);

//     return oss.str();
// }


static double throughput_kelem_per_sec(size_t num_elements,
                                       double elapsed_ms)
{
    return num_elements / (elapsed_ms / 1000.0) / 1000.0;
}


//==============================================================================
// Experiment Header
//==============================================================================

static void print_header(const std::string& label,
                         size_t server_len,
                         size_t client_len,
                         size_t log_server,
                         size_t log_client)
{
    std::cout << "\n";

    std::cout
        << "================================================================================\n";

    std::cout
        << label
        << "\n";

    std::cout
        << "--------------------------------------------------------------------------------\n";

    std::cout
        << "Server Set : 2^"
        << log_server
        << " = "
        << server_len
        << "\n";

    std::cout
        << "Client Set : 2^"
        << log_client
        << " = "
        << client_len
        << "\n";

    std::cout
        << "Intersection Ratio : 50%\n";

    std::cout
        << "================================================================================\n";
}


//==============================================================================
// Per-run Result
//==============================================================================

static void print_result(const BenchResult& r,
                         size_t server_len,
                         size_t client_len,
                         size_t expected_intersection)
{
    double server_tp =
        throughput_kelem_per_sec(server_len,
                                 r.server_ms);

    double client_tp =
        throughput_kelem_per_sec(client_len,
                                 r.client_ms);

    std::cout
        << std::fixed
        << std::setprecision(2);

    std::cout
        << "Wall Time      : "
        << r.wall_ms / 1000.0
        << " s\n";

    std::cout
        << "Server Time    : "
        << r.server_ms / 1000.0
        << " s"
        << "    ("
        << server_tp
        << " Kelem/s)\n";

    std::cout
        << "Client Time    : "
        << r.client_ms / 1000.0
        << " s"
        << "    ("
        << client_tp
        << " Kelem/s)\n";

    std::cout
        << "Intersection   : "
        << r.matches
        << " / "
        << expected_intersection;

    if (r.matches >= expected_intersection)
    {
        std::cout << "  [PASS]";
    }
    else
    {
        std::cout << "  [FAIL]";
    }

    std::cout << "\n";
}


//==============================================================================
// Benchmark Summary
//==============================================================================

static void print_summary(
    const std::vector<std::pair<std::string, BenchResult>>& results,
    size_t server_len,
    size_t client_len,
    size_t log_server,
    size_t log_client)
{
    constexpr int LABEL_W = 32;

    std::cout << "\n\n";

    std::cout
        << "========================================================================================================\n";

    std::cout
        << "                                  Taihang cwPRF-mqRPMT Benchmark\n";

    std::cout
        << "========================================================================================================\n";

    std::cout
        << "Dataset : "
        << "2^" << log_server
        << " (" << server_len << ") server elements"
        << "    "
        << "2^" << log_client
        << " (" << client_len << ") client elements"
        << "    "
        << "50% intersection\n";

    std::cout
        << "--------------------------------------------------------------------------------------------------------\n";

    //----------------------------------------------------------------------
    // Table Header
    //----------------------------------------------------------------------

    std::cout
        << std::left
        << std::setw(LABEL_W)
        << "Configuration"

        << std::right
        << std::setw(12)
        << "Server(s)"

        << std::setw(12)
        << "Client(s)"

        << std::setw(12)
        << "Wall(s)"

        << std::setw(16)
        << "Kelem/s"

        << "\n";

    std::cout
        << "--------------------------------------------------------------------------------------------------------\n";

    //----------------------------------------------------------------------
    // Table Rows
    //----------------------------------------------------------------------

    for (const auto& [label, r] : results)
    {
        double tp =
            throughput_kelem_per_sec(server_len,
                                     r.server_ms);

        std::cout
            << std::left
            << std::setw(LABEL_W)
            << label

            << std::right
            << std::fixed
            << std::setprecision(2)

            << std::setw(12)
            << r.server_ms / 1000.0

            << std::setw(12)
            << r.client_ms / 1000.0

            << std::setw(12)
            << r.wall_ms / 1000.0

            << std::setw(16)
            << tp

            << "\n";
    }

    //----------------------------------------------------------------------
    // Speedup Analysis
    //----------------------------------------------------------------------

    if (results.size() == 4)
    {
        double secp_speedup =
            results[1].second.server_ms /
            results[0].second.server_ms;

        double x25519_speedup =
            results[3].second.server_ms /
            results[2].second.server_ms;

        std::cout
            << "--------------------------------------------------------------------------------------------------------\n";

        std::cout
            << std::fixed
            << std::setprecision(2);

        std::cout
            << "BloomFilter Speedup over PlainSet\n";

        std::cout
            << "  Secp256r1 : "
            << secp_speedup
            << "x\n";

        std::cout
            << "  X25519    : "
            << x25519_speedup
            << "x\n";
    }

    std::cout
        << "========================================================================================================\n";
}


//==============================================================================
// Main
//==============================================================================

int main()
{
    constexpr size_t kLogServerLen = 20;
    constexpr size_t kLogClientLen = 20;

    constexpr uint16_t kPortSecpBloom = 12350;
    constexpr uint16_t kPortSecpPlain = 12351;
    constexpr uint16_t kPortX25519Bloom = 12352;
    constexpr uint16_t kPortX25519Plain = 12353;

    const size_t server_len = 1ULL << kLogServerLen;
    const size_t client_len = 1ULL << kLogClientLen;

    //----------------------------------------------------------------------
    // Generate dataset
    //----------------------------------------------------------------------

    std::cout
        << "Generating benchmark dataset ...\n";

    auto dataset_begin = Clock::now();

    Dataset ds = make_dataset(server_len,
                              client_len);

    double dataset_ms =
        Ms(Clock::now() - dataset_begin).count();

    std::cout
        << "Dataset generation completed in "
        << std::fixed
        << std::setprecision(2)
        << dataset_ms
        << " ms\n";

    //----------------------------------------------------------------------
    // Benchmark summary
    //----------------------------------------------------------------------

    std::vector<std::pair<std::string, BenchResult>> summary;

    //======================================================================
    // Secp256r1 + BloomFilter
    //======================================================================

    {
        print_header(
            "Benchmark: Secp256r1 + BloomFilter",
            server_len,
            client_len,
            kLogServerLen,
            kLogClientLen);

        auto pp =
            setup(415,
                  kLogServerLen,
                  kLogClientLen,
                  FilterMode::BloomFilter,
                  40);

        auto result =
            run_once(pp,
                     ds,
                     kPortSecpBloom);

        print_result(result,
                     server_len,
                     client_len,
                     ds.intersection_len);

        summary.emplace_back(
            "Secp256r1 + BloomFilter",
            result);
    }

    //======================================================================
    // Secp256r1 + PlainSet
    //======================================================================

    {
        print_header(
            "Benchmark: Secp256r1 + PlainSet",
            server_len,
            client_len,
            kLogServerLen,
            kLogClientLen);

        auto pp =
            setup(415,
                  kLogServerLen,
                  kLogClientLen,
                  FilterMode::PlainSet);

        auto result =
            run_once(pp,
                     ds,
                     kPortSecpPlain);

        print_result(result,
                     server_len,
                     client_len,
                     ds.intersection_len);

        summary.emplace_back(
            "Secp256r1 + PlainSet",
            result);
    }

    //======================================================================
    // X25519 + BloomFilter
    //======================================================================

    {
        print_header(
            "Benchmark: X25519 + BloomFilter",
            server_len,
            client_len,
            kLogServerLen,
            kLogClientLen);

        auto pp =
            setup(NID_X25519,
                  kLogServerLen,
                  kLogClientLen,
                  FilterMode::BloomFilter,
                  40);

        auto result =
            run_once(pp,
                     ds,
                     kPortX25519Bloom);

        print_result(result,
                     server_len,
                     client_len,
                     ds.intersection_len);

        summary.emplace_back(
            "X25519 + BloomFilter",
            result);
    }

    //======================================================================
    // X25519 + PlainSet
    //======================================================================

    {
        print_header(
            "Benchmark: X25519 + PlainSet",
            server_len,
            client_len,
            kLogServerLen,
            kLogClientLen);

        auto pp =
            setup(NID_X25519,
                  kLogServerLen,
                  kLogClientLen,
                  FilterMode::PlainSet);

        auto result =
            run_once(pp,
                     ds,
                     kPortX25519Plain);

        print_result(result,
                     server_len,
                     client_len,
                     ds.intersection_len);

        summary.emplace_back(
            "X25519 + PlainSet",
            result);
    }

    //----------------------------------------------------------------------
    // Final summary
    //----------------------------------------------------------------------

    print_summary(summary,
                  server_len,
                  client_len,
                  kLogServerLen,
                  kLogClientLen);

    return 0;
}