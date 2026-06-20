/****************************************************************************
 * @file      bench_alsz_ote.cpp
 * @brief     Performance Benchmarks for Taihang ALSZ OT Extension.
 * @details   Benchmarks multi-threaded interactive OT Extension routing.
 * @author    Yu Chen
 *****************************************************************************/

#include <taihang/mpc/ot/alsz_ote.hpp>
#include <taihang/crypto/prg.hpp>
#include <iostream>
#include <chrono>
#include <vector>
#include <iomanip>
#include <thread>
#include <openssl/obj_mac.h>

using namespace taihang;
using namespace taihang::mpc::alsz_ote;

int main() {
    // Configuration parameters
    const size_t BENCH_OT_LEN = 1048576;          // Extension batch footprint size (2^20)
    const size_t BASE_OT_LEN = 128;              // Security Parameter (\kappa)
    const int CURVE_NID = NID_X9_62_prime256v1;  // NIST P-256 for internal base OTs
    const uint16_t PORT = 12347;
    const std::string ADDRESS = "127.0.0.1";

    std::cout << "============================================================\n";
    std::cout << "   Taihang Cryptography Toolkit: ALSZ OT Extension Benchmark\n";
    std::cout << "   Batch Size (Length): " << BENCH_OT_LEN << " | Base OTs: " << BASE_OT_LEN << "\n";
    std::cout << "============================================================\n" << std::endl;

    // 1. Global Setup Context
    PublicParameters pp = setup(CURVE_NID, BASE_OT_LEN);

    // 2. Pre-allocate structural data matrices
    prg::Seed seed = prg::set_seed(nullptr, 0);
    std::vector<Block> vec_m0 = prg::gen_random_blocks(seed, BENCH_OT_LEN);
    std::vector<Block> vec_m1 = prg::gen_random_blocks(seed, BENCH_OT_LEN);
    
    std::vector<uint8_t> vec_selection_bit = prg::gen_random_bits(seed, BENCH_OT_LEN);

    // Storage containers for timing outputs
    double duration_sender_ms = 0.0;
    double duration_receiver_ms = 0.0;
    std::vector<Block> vec_result;

    // 3. Execution Pipeline (Synchronous thread-joined tracking via Socket NetIO)
    auto start_total = std::chrono::high_resolution_clock::now();

    std::thread sender_worker([&]() {
        net::NetIO io_sender("server", ADDRESS, PORT);
        
        auto start = std::chrono::high_resolution_clock::now();
        send<BlockPolicy>(io_sender, pp, vec_m0, vec_m1, BENCH_OT_LEN);
        auto end = std::chrono::high_resolution_clock::now();
        
        duration_sender_ms = std::chrono::duration<double, std::milli>(end - start).count();
    });

    std::thread receiver_worker([&]() {
        net::NetIO io_receiver("client", ADDRESS, PORT);
        
        auto start = std::chrono::high_resolution_clock::now();
        vec_result = recv<BlockPolicy>(io_receiver, pp, vec_selection_bit, BENCH_OT_LEN);
        auto end = std::chrono::high_resolution_clock::now();
        
        duration_receiver_ms = std::chrono::duration<double, std::milli>(end - start).count();
    });

    sender_worker.join();
    receiver_worker.join();

    auto end_total = std::chrono::high_resolution_clock::now();
    double duration_total_ms = std::chrono::duration<double, std::milli>(end_total - start_total).count();

    // Standard cryptographic engineering metrics conversion
    double total_seconds = duration_total_ms / 1000.0;
    double ots_per_sec = static_cast<double>(BENCH_OT_LEN) / total_seconds;
    double million_ots_per_sec = ots_per_sec / 1000000.0;
    double amortized_ns_per_ot = (duration_total_ms / static_cast<double>(BENCH_OT_LEN)) * 1000000.0;

    // 4. Output Benchmark Metric Matrix
    std::cout << "------------------------------------------------------------\n";
    std::cout << "   Execution Timing Performance Metrics\n";
    std::cout << "------------------------------------------------------------\n";
    std::cout << std::left << std::setw(35) << "Sender Thread Processing:" 
              << std::fixed << std::setprecision(4) << duration_sender_ms << " ms\n";
    std::cout << std::left << std::setw(35) << "Receiver Thread Processing:" 
              << duration_receiver_ms << " ms\n";
    std::cout << std::left << std::setw(35) << "Total Round-trip Execution:" 
              << duration_total_ms << " ms\n";
    std::cout << "------------------------------------------------------------\n";
    std::cout << std::left << std::setw(35) << "Throughput:" 
              << std::fixed << std::setprecision(2) << million_ots_per_sec << " M OT/s\n";
    std::cout << std::left << std::setw(35) << "Amortized Cost:" 
              << std::fixed << std::setprecision(1) << amortized_ns_per_ot << " ns/OT\n";
    std::cout << "------------------------------------------------------------\n";

    // 5. Sanity Check Verification Rule
    if (vec_result.size() != BENCH_OT_LEN) {
        std::cerr << "[Benchmark Error] Output vector dimension mismatch." << std::endl;
        return 1;
    }
    for (size_t i = 0; i < BENCH_OT_LEN; ++i) {
        Block expected = (vec_selection_bit[i] == 0) ? vec_m0[i] : vec_m1[i];
        if (vec_result[i] != expected) {
            std::cerr << "[Benchmark Error] Protocol correctness verification failed at entry: " << i << std::endl;
            return 1;
        }
    }
    std::cout << " Verification Status: SUCCESSFUL\n";
    std::cout << "============================================================\n";

    return 0;
}