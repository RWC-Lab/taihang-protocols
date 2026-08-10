/****************************************************************************
 * @file      cwprf_mqrpmt_optimized.hpp
 * @brief     Isolated experiments for optimizing X25519 cwPRF mqRPMT.
 *
 * This module is deliberately not part of the production protocol.  It is a
 * measurement harness for comparing allocation-free, fused, persistent-OMP,
 * and chunked-pipeline kernels before selecting any production changes.
 ****************************************************************************/

#ifndef TAIHANG_EXPERIMENTAL_CWPRF_MQRPMT_OPTIMIZED_HPP
#define TAIHANG_EXPERIMENTAL_CWPRF_MQRPMT_OPTIMIZED_HPP

#include <taihang/crypto/block.hpp>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

namespace taihang::experimental::cwprf_mqrpmt {

enum class Kernel {
    Baseline,
    CurrentParallel,
    FusedDirect,
    PersistentOpenMP,
    ChunkedPipeline,
};

struct Timings {
    double first_layers_ms = 0.0;
    double composite_layers_ms = 0.0;
    double membership_ms = 0.0;
    double total_ms = 0.0;
    std::size_t matches = 0;
};

struct Options {
    Kernel kernel = Kernel::FusedDirect;
    std::size_t threads = 1;
    std::size_t chunk_size = 4096;
    std::size_t bloom_security_parameter = 40;
};

std::string_view kernel_name(Kernel kernel) noexcept;

Timings run(const std::vector<Block>& server_input,
            const std::vector<Block>& client_input,
            const std::vector<std::uint8_t>& server_scalar,
            const std::vector<std::uint8_t>& client_scalar,
            const Options& options);

} // namespace taihang::experimental::cwprf_mqrpmt

#endif
