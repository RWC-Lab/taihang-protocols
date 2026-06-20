/****************************************************************************
 * @file      bench_naor_pinkas_ot.cpp
 * @brief     Performance Benchmarks for Taihang Naor-Pinkas OT.
 * @details   Benchmarks interactive Base OT computation and communication.
 * @author    Yu Chen
 *****************************************************************************/

#include <taihang/mpc/ot/naor_pinkas_ot.hpp>
#include <taihang/crypto/prg.hpp>
#include <iostream>
#include <chrono>
#include <vector>
#include <iomanip>
#include <thread>
#include <openssl/obj_mac.h>

using namespace taihang;
using namespace taihang::mpc::np_ot;

int main() {
    // Configuration parameters
    const size_t BENCH_OT_LEN = 128;             // Base OT batch constraint size
    const int CURVE_NID = NID_X9_62_prime256v1;  // NIST P-256 curve configuration
    const uint16_t PORT = 12346;
    const std::string ADDRESS = "127.0.0.1";

    std::cout << "============================================================\n";
    std::cout << "   Taihang Cryptography Toolkit: Naor-Pinkas OT Benchmark\n";
    std::cout << "   Batch Size (Length): " << BENCH_OT_LEN << " | Curve: NIST P-256\n";
    std::cout << "============================================================\n" << std::endl;

    // 1. Global Setup Context
    PublicParameters pp = setup(CURVE_NID);

    // 2. Pre-allocate structural data matrices
    prg::Seed seed = prg::set_seed(nullptr, 0);
    std::vector<Block> vec_m0 = prg::gen_random_blocks(seed, BENCH_OT_LEN);
    std::vector<Block> vec_m1 = prg::gen_random_blocks(seed, BENCH_OT_LEN);
    
    std::vector<uint8_t> vec_selection_bit(BENCH_OT_LEN);
    for (size_t i = 0; i < BENCH_OT_LEN; ++i) {
        vec_selection_bit[i] = static_cast<uint8_t>(i % 2); // Alternating paths
    }

    // Storage containers for timing outputs
    double duration_sender_ms = 0.0;
    double duration_receiver_ms = 0.0;
    std::vector<Block> vec_result;

    // 3. Execution Pipeline (Synchronous thread-joined tracking)
    auto start_total = std::chrono::high_resolution_clock::now();

    std::thread sender_worker([&]() {
        net::NetIO io_sender("server", ADDRESS, PORT);
        
        auto start = std::chrono::high_resolution_clock::now();
        send(io_sender, pp, vec_m0, vec_m1, BENCH_OT_LEN);
        auto end = std::chrono::high_resolution_clock::now();
        
        duration_sender_ms = std::chrono::duration<double, std::milli>(end - start).count();
    });

    std::thread receiver_worker([&]() {
        net::NetIO io_receiver("client", ADDRESS, PORT);
        
        auto start = std::chrono::high_resolution_clock::now();
        vec_result = receive(io_receiver, pp, vec_selection_bit, BENCH_OT_LEN);
        auto end = std::chrono::high_resolution_clock::now();
        
        duration_receiver_ms = std::chrono::duration<double, std::milli>(end - start).count();
    });

    sender_worker.join();
    receiver_worker.join();

    auto end_total = std::chrono::high_resolution_clock::now();
    double duration_total_ms = std::chrono::duration<double, std::milli>(end_total - start_total).count();

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
    std::cout << std::left << std::setw(35) << "Amortized Cost per OT Instance:" 
              << (duration_total_ms / BENCH_OT_LEN) << " ms/op\n";

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