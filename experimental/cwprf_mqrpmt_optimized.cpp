/****************************************************************************
 * @file      cwprf_mqrpmt_optimized.cpp
 * @brief     Experimental allocation-free and pipelined X25519 kernels.
 ****************************************************************************/

#include "cwprf_mqrpmt_optimized.hpp"

#include <taihang/crypto/aes.hpp>
#include <taihang/crypto/ec25519_point.hpp>
#include <taihang/structure/plain_hash.hpp>
#include <algorithm>
#include <array>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <future>
#include <mutex>
#include <omp.h>
#include <thread>

namespace taihang::experimental::cwprf_mqrpmt {
namespace {

using Clock = std::chrono::steady_clock;
using PointBytes = std::array<std::uint8_t, EC25519Point::POINT_BYTE_LEN>;

double elapsed_ms(Clock::time_point begin, Clock::time_point end) {
    return std::chrono::duration<double, std::milli>(end - begin).count();
}

void hash_block_to_bytes(const Block& input, std::uint8_t output[32]) {
    Block expanded[2];
#if defined(TAIHANG_ARCH_X64)
    expanded[0].mm = _mm_xor_si128(input.mm, _mm_set_epi64x(0, 1));
    expanded[1].mm = _mm_xor_si128(input.mm, _mm_set_epi64x(0, 2));
#else
    expanded[0] = input;
    expanded[1] = input;
#endif
    aes::encrypt_two_blocks(aes::get_fixed_key(), expanded);
    std::memcpy(output, expanded, 32);
}

void fused_direct_range(const std::vector<Block>& input,
                        const std::uint8_t scalar[32],
                        std::vector<PointBytes>& output,
                        std::size_t begin,
                        std::size_t end) {
    for (std::size_t i = begin; i < end; ++i) {
        PointBytes hashed{};
        hash_block_to_bytes(input[i], hashed.data());
        x25519_scalar_mulx(output[i].data(), scalar, hashed.data());
    }
}

void baseline_range(const std::vector<Block>& input,
                    const std::uint8_t scalar[32],
                    std::vector<PointBytes>& output,
                    std::size_t begin,
                    std::size_t end) {
    for (std::size_t i = begin; i < end; ++i) {
        const EC25519Point point = hash_to_curve25519(input[i]);
        x25519_scalar_mulx(output[i].data(), scalar, point.px);
    }
}

void current_parallel_range(const std::vector<Block>& input,
                            const std::uint8_t scalar[32],
                            std::vector<PointBytes>& output,
                            std::size_t threads) {
    std::vector<EC25519Point> points(input.size());
#pragma omp parallel for num_threads(threads)
    for (std::int64_t i = 0; i < static_cast<std::int64_t>(input.size()); ++i) {
        const std::size_t index = static_cast<std::size_t>(i);
        points[index] = hash_to_curve25519(input[index]) * scalar;
        std::memcpy(output[index].data(), points[index].px, 32);
    }
}

void current_parallel_point_range(const std::vector<PointBytes>& input,
                                  const std::uint8_t scalar[32],
                                  std::vector<PointBytes>& output,
                                  std::size_t threads) {
#pragma omp parallel for num_threads(threads)
    for (std::int64_t i = 0; i < static_cast<std::int64_t>(input.size()); ++i) {
        const std::size_t index = static_cast<std::size_t>(i);
        EC25519Point point(input[index].data());
        point = point * scalar;
        std::memcpy(output[index].data(), point.px, 32);
    }
}

void persistent_range(const std::vector<Block>& input,
                      const std::uint8_t scalar[32],
                      std::vector<PointBytes>& output,
                      std::size_t threads) {
#pragma omp parallel num_threads(threads)
    {
#pragma omp for schedule(static)
        for (std::int64_t i = 0; i < static_cast<std::int64_t>(input.size()); ++i) {
            PointBytes hashed{};
            hash_block_to_bytes(input[static_cast<std::size_t>(i)], hashed.data());
            x25519_scalar_mulx(output[static_cast<std::size_t>(i)].data(), scalar, hashed.data());
        }
    }
}

void direct_point_range(const std::vector<PointBytes>& input,
                        const std::uint8_t scalar[32],
                        std::vector<PointBytes>& output,
                        std::size_t begin,
                        std::size_t end) {
    for (std::size_t i = begin; i < end; ++i)
        x25519_scalar_mulx(output[i].data(), scalar, input[i].data());
}

void persistent_point_range(const std::vector<PointBytes>& input,
                            const std::uint8_t scalar[32],
                            std::vector<PointBytes>& output,
                            std::size_t threads) {
#pragma omp parallel num_threads(threads)
    {
#pragma omp for schedule(static)
        for (std::int64_t i = 0; i < static_cast<std::int64_t>(input.size()); ++i)
            x25519_scalar_mulx(output[static_cast<std::size_t>(i)].data(), scalar,
                               input[static_cast<std::size_t>(i)].data());
    }
}

class ByteBloomFilter {
public:
    ByteBloomFilter(std::size_t elements, std::size_t security)
        : hashes_(static_cast<std::uint32_t>(security)),
          bits_((static_cast<std::uint64_t>(elements) * security * 1442695ULL / 1000000ULL + 63) & ~63ULL),
          table_(bits_ / 8, 0) {}

    void insert(const PointBytes& value) {
        auto [h1, h2] = plainhash::murmur3_128x2(value.data(), value.size(), seed_);
        h2 |= 1ULL;
        for (std::uint32_t i = 0; i < hashes_; ++i) {
            const std::uint64_t bit = (h1 + static_cast<std::uint64_t>(i) * h2) % bits_;
            table_[bit >> 3] |= static_cast<std::uint8_t>(1U << (bit & 7));
        }
    }

    bool contains(const PointBytes& value) const {
        auto [h1, h2] = plainhash::murmur3_128x2(value.data(), value.size(), seed_);
        h2 |= 1ULL;
        for (std::uint32_t i = 0; i < hashes_; ++i) {
            const std::uint64_t bit = (h1 + static_cast<std::uint64_t>(i) * h2) % bits_;
            if ((table_[bit >> 3] & static_cast<std::uint8_t>(1U << (bit & 7))) == 0) return false;
        }
        return true;
    }

private:
    static constexpr std::uint32_t seed_ = 0xA5A5A5A5U;
    std::uint32_t hashes_;
    std::uint64_t bits_;
    std::vector<std::uint8_t> table_;
};

struct Chunk {
    std::size_t begin = 0;
    std::size_t end = 0;
};

class ChunkQueue {
public:
    explicit ChunkQueue(std::size_t capacity) : capacity_(capacity) {}

    void push(Chunk chunk) {
        std::unique_lock lock(mutex_);
        not_full_.wait(lock, [&] { return queue_.size() < capacity_ || closed_; });
        if (closed_) return;
        queue_.push_back(chunk);
        not_empty_.notify_one();
    }

    bool pop(Chunk& chunk) {
        std::unique_lock lock(mutex_);
        not_empty_.wait(lock, [&] { return !queue_.empty() || closed_; });
        if (queue_.empty()) return false;
        chunk = queue_.front();
        queue_.pop_front();
        not_full_.notify_one();
        return true;
    }

    void close() {
        std::lock_guard lock(mutex_);
        closed_ = true;
        not_empty_.notify_all();
        not_full_.notify_all();
    }

private:
    std::size_t capacity_;
    std::deque<Chunk> queue_;
    std::mutex mutex_;
    std::condition_variable not_empty_;
    std::condition_variable not_full_;
    bool closed_ = false;
};

struct HashedChunk {
    std::size_t begin = 0;
    std::vector<PointBytes> values;
};

class HashedChunkQueue {
public:
    explicit HashedChunkQueue(std::size_t capacity) : capacity_(capacity) {}

    void push(HashedChunk chunk) {
        std::unique_lock lock(mutex_);
        not_full_.wait(lock, [&] { return queue_.size() < capacity_ || closed_; });
        if (closed_) return;
        queue_.push_back(std::move(chunk));
        not_empty_.notify_one();
    }

    bool pop(HashedChunk& chunk) {
        std::unique_lock lock(mutex_);
        not_empty_.wait(lock, [&] { return !queue_.empty() || closed_; });
        if (queue_.empty()) return false;
        chunk = std::move(queue_.front());
        queue_.pop_front();
        not_full_.notify_one();
        return true;
    }

    void close() {
        std::lock_guard lock(mutex_);
        closed_ = true;
        not_empty_.notify_all();
        not_full_.notify_all();
    }

private:
    std::size_t capacity_;
    std::deque<HashedChunk> queue_;
    std::mutex mutex_;
    std::condition_variable not_empty_;
    std::condition_variable not_full_;
    bool closed_ = false;
};

void pipeline_range(const std::vector<Block>& input,
                    const std::uint8_t scalar[32],
                    std::vector<PointBytes>& output,
                    std::size_t chunk_size) {
    HashedChunkQueue queue(2);
    std::thread producer([&] {
        for (std::size_t begin = 0; begin < input.size(); begin += chunk_size) {
            const std::size_t end = std::min(begin + chunk_size, input.size());
            HashedChunk chunk;
            chunk.begin = begin;
            chunk.values.resize(end - begin);
            for (std::size_t i = begin; i < end; ++i)
                hash_block_to_bytes(input[i], chunk.values[i - begin].data());
            queue.push(std::move(chunk));
        }
        queue.close();
    });
    HashedChunk chunk;
    while (queue.pop(chunk)) {
        for (std::size_t i = 0; i < chunk.values.size(); ++i)
            x25519_scalar_mulx(output[chunk.begin + i].data(), scalar, chunk.values[i].data());
    }
    producer.join();
}

void pipeline_point_range(const std::vector<PointBytes>& input,
                          const std::uint8_t scalar[32],
                          std::vector<PointBytes>& output,
                          std::size_t chunk_size) {
    ChunkQueue queue(2);
    std::thread producer([&] {
        for (std::size_t begin = 0; begin < input.size(); begin += chunk_size)
            queue.push({begin, std::min(begin + chunk_size, input.size())});
        queue.close();
    });
    Chunk chunk;
    while (queue.pop(chunk)) direct_point_range(input, scalar, output, chunk.begin, chunk.end);
    producer.join();
}

void compute(const std::vector<Block>& input,
             const std::vector<std::uint8_t>& scalar,
             std::vector<PointBytes>& output,
             const Options& options) {
    const auto* scalar_bytes = scalar.data();
    switch (options.kernel) {
    case Kernel::Baseline:
        baseline_range(input, scalar_bytes, output, 0, input.size());
        break;
    case Kernel::CurrentParallel:
        current_parallel_range(input, scalar_bytes, output,
                               std::max<std::size_t>(1, options.threads));
        break;
    case Kernel::FusedDirect:
        fused_direct_range(input, scalar_bytes, output, 0, input.size());
        break;
    case Kernel::PersistentOpenMP:
        persistent_range(input, scalar_bytes, output, std::max<std::size_t>(1, options.threads));
        break;
    case Kernel::ChunkedPipeline:
        pipeline_range(input, scalar_bytes, output, std::max<std::size_t>(1, options.chunk_size));
        break;
    }
}

void compute_points(const std::vector<PointBytes>& input,
                    const std::vector<std::uint8_t>& scalar,
                    std::vector<PointBytes>& output,
                    const Options& options) {
    const auto* scalar_bytes = scalar.data();
    switch (options.kernel) {
    case Kernel::Baseline:
        direct_point_range(input, scalar_bytes, output, 0, input.size());
        break;
    case Kernel::CurrentParallel:
        current_parallel_point_range(input, scalar_bytes, output,
                                     std::max<std::size_t>(1, options.threads));
        break;
    case Kernel::FusedDirect:
        direct_point_range(input, scalar_bytes, output, 0, input.size());
        break;
    case Kernel::PersistentOpenMP:
        persistent_point_range(input, scalar_bytes, output,
                               std::max<std::size_t>(1, options.threads));
        break;
    case Kernel::ChunkedPipeline:
        pipeline_point_range(input, scalar_bytes, output,
                             std::max<std::size_t>(1, options.chunk_size));
        break;
    }
}

} // namespace

std::string_view kernel_name(Kernel kernel) noexcept {
    switch (kernel) {
    case Kernel::Baseline: return "baseline";
    case Kernel::CurrentParallel: return "current-parallel";
    case Kernel::FusedDirect: return "fused-direct";
    case Kernel::PersistentOpenMP: return "persistent-openmp";
    case Kernel::ChunkedPipeline: return "chunked-pipeline";
    }
    return "unknown";
}

Timings run(const std::vector<Block>& server_input,
            const std::vector<Block>& client_input,
            const std::vector<std::uint8_t>& server_scalar,
            const std::vector<std::uint8_t>& client_scalar,
            const Options& options) {
    Timings timings;
    std::vector<PointBytes> server_layer(server_input.size());
    std::vector<PointBytes> client_layer(client_input.size());
    std::vector<PointBytes> server_composite(client_input.size());
    std::vector<PointBytes> client_composite(server_input.size());
    const auto total_begin = Clock::now();

    auto first_begin = Clock::now();
    auto server_first = std::async(std::launch::async, [&] {
        compute(server_input, server_scalar, server_layer, options);
    });
    auto client_first = std::async(std::launch::async, [&] {
        compute(client_input, client_scalar, client_layer, options);
    });
    server_first.get();
    client_first.get();
    timings.first_layers_ms = elapsed_ms(first_begin, Clock::now());

    auto composite_begin = Clock::now();
    auto server_composite_task = std::async(std::launch::async, [&] {
        compute_points(client_layer, server_scalar, server_composite, options);
    });
    auto client_composite_task = std::async(std::launch::async, [&] {
        compute_points(server_layer, client_scalar, client_composite, options);
    });
    server_composite_task.get();
    client_composite_task.get();
    timings.composite_layers_ms = elapsed_ms(composite_begin, Clock::now());

    auto membership_begin = Clock::now();
    ByteBloomFilter filter(client_composite.size(), options.bloom_security_parameter);
    for (const auto& value : client_composite) filter.insert(value);
    for (const auto& value : server_composite) timings.matches += filter.contains(value) ? 1 : 0;
    timings.membership_ms = elapsed_ms(membership_begin, Clock::now());
    timings.total_ms = elapsed_ms(total_begin, Clock::now());
    return timings;
}

} // namespace taihang::experimental::cwprf_mqrpmt
