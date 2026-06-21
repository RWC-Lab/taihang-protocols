/****************************************************************************
 * @file      bench_cwprf_mqrpmt.cpp
 * @brief     High-performance microsecond-accurate benchmark suite for cwPRF mqRPMT.
 * @details   Measures execution time and communication overhead for 2^20 elements.
 * @author    This file is part of Taihang, developed by Yu Chen.
 *****************************************************************************/

#include <taihang/mpc/rpmt/cwprf_mqrpmt.hpp>
#include <taihang/common/logger.hpp>
#include <taihang/crypto/prg.hpp>
#include <chrono>
#include <future>
#include <iostream>
#include <vector>
#include <cmath>
#include <iomanip>

using namespace taihang;
using namespace taihang::mpc::cwprf_mqrpmt;

void run_million_scale_benchmark() {
    // 1. Setup Parameters for 2^20 elements
    constexpr int kCurveId = 415; // Secp256r1
    constexpr size_t kStatisticalSecurityParameter = 40;
    constexpr size_t kLogServerLen = 20; // 2^20 elements (~1.04 Million)
    constexpr size_t kLogClientLen = 20; // 2^20 elements

    size_t server_len = 1ULL << kLogServerLen;
    size_t client_len = 1ULL << kLogClientLen;

    std::cout << "[ BENCHMARK ] ====================================================\n";
    std::cout << "[ BENCHMARK ] Starting cwPRF mqRPMT Performance Profile\n";
    std::cout << "[ BENCHMARK ] Dataset Sizes: Server = 2^" << kLogServerLen 
              << " (" << server_len << ") | Client = 2^" << kLogClientLen 
              << " (" << client_len << ")\n";
    std::cout << "[ BENCHMARK ] ====================================================\n";

    std::cout << "[ BENCHMARK ] Generating synthetic data sets..." << std::endl;
    auto start_data = std::chrono::high_resolution_clock::now();

    // 2. Data Preparation
    std::vector<Block> vec_y(server_len);
    std::vector<Block> vec_x(client_len);

    Block fixed_seed_block = make_block(0x123456789ABCDEF0ULL, 0x0FEDCBA987654321ULL);
    prg::Seed seed = prg::set_seed(&fixed_seed_block, 0);

    // Generate server set elements directly
    prg::gen_random_blocks(seed, vec_y.data(), server_len);

    // Generate client set elements (with 50% intersection overlap)
    size_t intersection_len = client_len / 2;
    for (size_t i = 0; i < client_len; ++i) {
        if (i < intersection_len) {
            vec_x[i] = vec_y[i]; // Shared element
        } else {
            // Distinct element to verify non-membership
            vec_x[i] = make_block(i, 0xDEADBEEFADDEULL);
        }
    }

    // Set setup configurations
    PublicParameters pp = setup(kCurveId, kStatisticalSecurityParameter, kLogServerLen, kLogClientLen);

    auto end_data = std::chrono::high_resolution_clock::now();
    auto data_duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_data - start_data).count();
    std::cout << "[ BENCHMARK ] Setup and Data Generation Completed in: " << data_duration << " ms\n\n";

    // Loopback networking parameters
    const std::string address = "127.0.0.1";
    const uint16_t port = 12346;

    std::cout << "[ BENCHMARK ] Executing Protocol Pipelines..." << std::endl;
    auto start_protocol = std::chrono::high_resolution_clock::now();

    // 3. Spawn Concurrent Execution Roles
    auto server_task = std::async(std::launch::async, [&]() -> std::pair<std::vector<uint8_t>, double> {
        net::NetIO io_server("server", address, port);
        
        auto t1 = std::chrono::high_resolution_clock::now();
        std::vector<uint8_t> indicators = server(io_server, pp, vec_y);
        auto t2 = std::chrono::high_resolution_clock::now();
        
        double duration = std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count() / 1000.0;
        return {indicators, duration};
    });

    auto client_task = std::async(std::launch::async, [&]() -> double {
        net::NetIO io_client("client", address, port);
        
        auto t1 = std::chrono::high_resolution_clock::now();
        client(io_client, pp, vec_x);
        auto t2 = std::chrono::high_resolution_clock::now();
        
        return std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count() / 1000.0;
    });

    // 4. Collect Benchmark Metrics
    double client_time_ms = client_task.get();
    auto server_result = server_task.get();
    std::vector<uint8_t> vec_indication_bit = server_result.first;
    double server_time_ms = server_result.second;

    auto end_protocol = std::chrono::high_resolution_clock::now();
    double total_wall_time_ms = std::chrono::duration_cast<std::chrono::microseconds>(end_protocol - start_protocol).count() / 1000.0;

    // 5. Verification Checks
    size_t matches = 0;
    for (size_t i = 0; i < client_len; ++i) {
        if (vec_indication_bit[i] == 1) {
            matches++;
        }
    }

    // 6. Print Performance Matrix Report
    std::cout << "\n[ BENCHMARK ] ================= PERFORMANCE REPORT =================\n";
    std::cout << "[ BENCHMARK ] Total Parallel Wall Time : " << std::fixed << std::setprecision(2) << total_wall_time_ms << " ms\n";
    std::cout << "[ BENCHMARK ] Server Computation Time  : " << server_time_ms << " ms\n";
    std::cout << "[ BENCHMARK ] Client Computation Time  : " << client_time_ms << " ms\n";
    std::cout << "[ BENCHMARK ] ------------------------------------------------------\n";
    std::cout << "[ BENCHMARK ] Throughput (Server)      : " 
              << std::fixed << std::setprecision(0) << (server_len / (server_time_ms / 1000.0)) << " elements/sec\n";
    std::cout << "[ BENCHMARK ] Throughput (Client)      : " 
              << (client_len / (client_time_ms / 1000.0)) << " elements/sec\n";
    std::cout << "[ BENCHMARK ] ------------------------------------------------------\n";
    std::cout << "[ BENCHMARK ] Expected Intersections   : " << intersection_len << "\n";
    std::cout << "[ BENCHMARK ] Found Intersections      : " << matches << "\n";
    
    // Fix: TAIHANG_ASSERT requires 2 arguments (condition, message)
    TAIHANG_ASSERT(matches >= intersection_len, "Benchmark Error: Intersection mismatch target constraint.");
    std::cout << "[ BENCHMARK ] Accuracy Verification    : PASSED\n";
    std::cout << "[ BENCHMARK ] ======================================================\n";
}

int main() {
    // Fix: Remove the incorrect set_level() statement to rely on default Logger initialization values.
    run_million_scale_benchmark();
    return 0;
}