/****************************
 * @file      baxos.hpp
 * @brief     Batched Paxos OKVS engine.
 ****************************/

#ifndef TAIHANG_MPC_OKVS_BAXOS_HPP
#define TAIHANG_MPC_OKVS_BAXOS_HPP

#include <taihang/mpc/okvs/paxos.hpp>

#include <array>
#include <cstring>
#include <future>
#include <memory>
#include <omp.h>

namespace taihang::mpc::okvs {

template <DenseType dense_type = DenseType::Binary, typename value_type = Block>
class Baxos
{
public:
    uint64_t item_num = 0;
    uint64_t bin_num = 0;
    uint64_t item_num_per_bin = 0;
    uint8_t sparse_weight = 0;
    uint8_t statistical_security_parameter = 40;
    bool is_decoding = false;

    uint64_t sparse_size;
    uint64_t dense_size;
    uint64_t total_size;
    uint8_t g_limit;

    prg::Seed seed;

    Baxos() = default;
    Baxos(const uint64_t item_num, const uint64_t bin_size, const uint8_t sparse_weight = 3, const uint8_t statistical_security_parameter = 40, const prg::Seed *seed = nullptr);
    template <typename idx_type>
    void impl_solve(const std::vector<Block> &keys, const std::vector<value_type> &values, std::vector<value_type> &output, prg::Seed *prng, uint8_t thread_num);
    template <typename idx_type>
    void impl_decode(const std::vector<Block> &keys, std::vector<value_type> &values, const std::vector<value_type> &output, uint8_t thread_num);
    template <typename idx_type>
    void impl_decode_batch(Block *keys, value_type *values, uint64_t batch_len, value_type *output);
    void solve(const std::vector<Block> &keys, const std::vector<value_type> &values, std::vector<value_type> &output, prg::Seed *prng = nullptr, uint8_t thread_num = 1);
    void decode(const std::vector<Block> &keys, std::vector<value_type> &values, const std::vector<value_type> &output, uint8_t thread_num = 1);
};

extern template class Baxos<DenseType::Binary, Block>;
extern template class Baxos<DenseType::Gf128, Block>;

} // namespace taihang::mpc::okvs

#endif // TAIHANG_MPC_OKVS_BAXOS_HPP
