/****************************************************************************
 * @file      bench_cwprf_mqrpmt_optimized.cpp
 * @brief     Standalone benchmark for experimental cwPRF optimization kernels.
 *
 * Build manually; this file is intentionally not included by CMake:
 *   c++ ... experimental/cwprf_mqrpmt_optimized.cpp \
 *       experimental/bench_cwprf_mqrpmt_optimized.cpp ...
 ****************************************************************************/

#include "cwprf_mqrpmt_optimized.hpp"

#include <taihang/crypto/prg.hpp>
#include <algorithm>
#include <array>
#include <iomanip>
#include <iostream>
#include <string>

using namespace taihang;
using namespace taihang::experimental::cwprf_mqrpmt;

int main(int argc, char** argv) {
    const std::size_t log_size = argc > 1 ? std::stoul(argv[1]) : 16;
    const std::size_t threads = argc > 2 ? std::stoul(argv[2]) : 1;
    const std::size_t size = std::size_t{1} << log_size;

    Block seed_block = make_block(0x123456789ABCDEF0ULL, 0x0FEDCBA987654321ULL);
    auto seed = prg::set_seed(&seed_block, 0);
    std::vector<Block> server(size), client(size);
    prg::gen_random_blocks(seed, server.data(), size);
    for (std::size_t i = 0; i < size; ++i) client[i] = i < size / 2 ? server[i] : make_block(i, 0xDEADBEEFADDEULL);
    std::vector<std::uint8_t> server_scalar(32, 7), client_scalar(32, 11);

    std::cout << "X25519 cwPRF optimization experiment\n"
              << "set size: 2^" << log_size << " x 2^" << log_size
              << ", threads: " << threads << "\n\n";
    for (Kernel kernel : {Kernel::Baseline, Kernel::CurrentParallel, Kernel::FusedDirect,
                          Kernel::PersistentOpenMP, Kernel::ChunkedPipeline}) {
        Options options;
        options.kernel = kernel;
        options.threads = threads;
        options.chunk_size = 4096;
        auto result = run(server, client, server_scalar, client_scalar, options);
        std::cout << std::left << std::setw(20) << kernel_name(kernel)
                  << std::right << std::fixed << std::setprecision(2)
                  << " first-layers=" << std::setw(9) << result.first_layers_ms << " ms"
                  << " composite=" << std::setw(9) << result.composite_layers_ms << " ms"
                  << " membership=" << std::setw(9) << result.membership_ms << " ms"
                  << " total=" << std::setw(9) << result.total_ms << " ms"
                  << " matches=" << result.matches << '\n';
    }
}
