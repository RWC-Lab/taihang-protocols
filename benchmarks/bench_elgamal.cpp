/****************************************************************************
 * @file      bench_elgamal.cpp
 * @brief     Performance Benchmarks for Taihang ElGamal PKE.
 * @details   Benchmarks KeyGen, Encrypt, Decrypt, and Homomorphic operations.
 * Includes realistic BSGS DLog performance testing.
 * @author    Yu Chen
 *****************************************************************************/

#include <taihang/pke/elgamal.hpp>
#include <taihang/algorithm/bsgs_dlog.hpp>
#include <taihang/crypto/ec_group.hpp>
#include <taihang/crypto/zn.hpp>
#include <iostream>
#include <chrono>
#include <vector>
#include <iomanip>
#include <openssl/obj_mac.h>

using namespace taihang;
using namespace taihang::pke::elgamal;
using namespace taihang::dlog;

/**
 * @brief Helper to measure average execution time.
 */
template<typename Func>
double measure_ms(Func&& func, size_t iterations) {
    if (iterations == 0) return 0.0;
    auto start = std::chrono::high_resolution_clock::now();
    for (size_t i = 0; i < iterations; ++i) {
        func(i);
    }
    auto end = std::chrono::high_resolution_clock::now();
    return std::chrono::duration<double, std::milli>(end - start).count() / iterations;
}

int main() {
    // Configuration
    const size_t TEST_NUM = 1000;
    const int CURVE_NID = NID_X9_62_prime256v1; // NIST P-256
    const size_t BSGS_RANGE_BITS = 32;          // Search space 2^20

    std::cout << "============================================================\n";
    std::cout << "   Taihang Cryptography Toolkit: ElGamal PKE Benchmark\n";
    std::cout << "   Iterations: " << TEST_NUM << " | Curve: NIST P-256\n";
    std::cout << "============================================================\n" << std::endl;

    // 1. Global Setup
    PublicParameters pp = setup(CURVE_NID);
    
    // 2. Pre-allocate Data
    std::vector<PublicKey> pks(TEST_NUM);
    std::vector<SecretKey> sks(TEST_NUM);
    std::vector<ECPoint> msgs_pt(TEST_NUM);
    std::vector<Ciphertext> cts_std(TEST_NUM);
    std::vector<ZnElement> scalars(TEST_NUM);

    // --- Benchmark: KeyGen ---
    double time_keygen = measure_ms([&](size_t i) {
        auto pair = keygen(pp);
        pks[i] = std::move(pair.first);
        sks[i] = std::move(pair.second);
    }, TEST_NUM);
    std::cout << std::left << std::setw(30) << "Key Generation:" 
              << std::fixed << std::setprecision(4) << time_keygen << " ms/op\n";

    // Prepare Standard Messages (Random Points)
    for(size_t i = 0; i < TEST_NUM; ++i) {
        msgs_pt[i] = pp.group_ctx->gen_random();
        scalars[i] = pp.field_ctx->gen_random();
    }

    // --- Benchmark: Encryption (Standard) ---
    double time_enc = measure_ms([&](size_t i) {
        cts_std[i] = encrypt(pp, pks[i], msgs_pt[i]);
    }, TEST_NUM);
    std::cout << std::left << std::setw(30) << "Encryption (Point):" 
              << time_enc << " ms/op\n";

    // --- Benchmark: Decryption (Standard) ---
    double time_dec = measure_ms([&](size_t i) {
        decrypt(sks[i], cts_std[i]);
    }, TEST_NUM);
    std::cout << std::left << std::setw(30) << "Decryption (Point):" 
              << time_dec << " ms/op\n";

    // --- Benchmark: Re-Randomization ---
    double time_rerand = measure_ms([&](size_t i) {
        re_rand(pp, pks[i], cts_std[i]);
    }, TEST_NUM);
    std::cout << std::left << std::setw(30) << "Ciphertext Re-Rand:" 
              << time_rerand << " ms/op\n";

    // --- Benchmark: Homomorphic Add ---
    double time_add = measure_ms([&](size_t i) {
        auto res = cts_std[i] + cts_std[0];
    }, TEST_NUM);
    std::cout << std::left << std::setw(30) << "Homomorphic Addition:" 
              << time_add << " ms/op\n";

    // --- Benchmark: Homomorphic Scalar Mul ---
    double time_mul = measure_ms([&](size_t i) {
        auto res = cts_std[i] * scalars[i];
    }, TEST_NUM);
    std::cout << std::left << std::setw(30) << "Scalar Multiplication:" 
              << time_mul << " ms/op\n";

    std::cout << "\n------------------------------------------------------------\n";
    std::cout << " Exponential ElGamal Performance (Search Space: 2^" << BSGS_RANGE_BITS << ")\n";
    std::cout << "------------------------------------------------------------\n";

    // --- Setup BSGS Solver ---
    // BSGS table size is sqrt(2^bits). For 2^20, this is 1024 baby steps.
    BSGSConfig config = {BSGS_RANGE_BITS, 7, 8}; 
    BSGSSolver solver(*pp.group_ctx, pp.g, config);

    auto t_1 = std::chrono::high_resolution_clock::now();
    solver.build_and_save_table();
    auto t_2 = std::chrono::high_resolution_clock::now();
    solver.construct_hashmap_from_table(solver.get_table_filename());
    auto t_3 = std::chrono::high_resolution_clock::now();
    
    double build_time = std::chrono::duration<double>(t_2 - t_1).count();
    std::cout << "BSGS Table Build Time:         " << build_time << " s\n";
    
    double construct_time = std::chrono::duration<double>(t_3 - t_2).count();
    std::cout << "Hashmap Construct Time:         " << construct_time << " s\n";

    // Prepare Exponential Data: REALISTIC RANDOM MESSAGES
    std::vector<Ciphertext> cts_exp(TEST_NUM);
    std::vector<BigInt> msgs_raw(TEST_NUM);
    BigInt max_m = BigInt(1ULL << BSGS_RANGE_BITS); 

    for(size_t i = 0; i < TEST_NUM; ++i) {
        // Pick a message randomly from the supported range [0, 2^BSGS_RANGE_BITS)
        msgs_raw[i] = gen_random_bigint_less_than(max_m);
        cts_exp[i] = encrypt(pp, pks[i], ZnElement(pp.field_ctx, msgs_raw[i]));
    }

    // --- Benchmark: Decryption (Exponential) ---
    // This now tests the solver's ability to handle "Giant Steps" correctly.
    double time_dec_exp = measure_ms([&](size_t i) {
        ZnElement res = decrypt_exp(pp, sks[i], cts_exp[i], solver);
        
        // Optional sanity check to ensure randomness hasn't broken logic
        // if (res != msgs_raw[i]) { throw std::runtime_error("DLog Mismatch!"); }
    }, TEST_NUM);
    
    std::cout << std::left << std::setw(30) << "Decryption (Exp/BSGS):" 
              << time_dec_exp << " ms/op\n";
    std::cout << "============================================================\n";

    return 0;
}