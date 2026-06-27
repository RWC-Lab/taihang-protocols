/****************************************************************************
 * @file      cwprf_mqrpmt.hpp
 * @brief     Multi-query RPMT based on weak commutative PRF
 * @author    This file is part of Taihang, developed by Yu Chen.
 *****************************************************************************/

#ifndef TAIHANG_PROTOCOLS_CWPRF_MQRPMT_HPP
#define TAIHANG_PROTOCOLS_CWPRF_MQRPMT_HPP

#include <taihang/common/config.hpp>
#include <taihang/common/check.hpp>
#include <taihang/crypto/block.hpp>
#include <taihang/crypto/ec_group.hpp>
#include <taihang/crypto/ec25519_point.hpp>
#include <taihang/net/net_io.hpp>
#include <taihang/structure/bloom_filter.hpp>
#include <vector>
#include <string>
#include <iostream>
#include <optional>

namespace taihang::mpc::cwprf_mqrpmt {

/**
 * @enum FilterMode
 * @brief Selects the membership-test structure used in the final round.
 *
 *  BloomFilter – Client sends a compact probabilistic filter (FPR ~ 2^-ssp).
 *                Communication is O(n) bits; a small false-positive rate is
 *                accepted in exchange for reduced bandwidth.
 *
 *  PlainSet    – Client sends the full, randomly-permuted set of PRF values.
 *                No false positives; communication is O(n * point_byte_len).
 *                statistical_security_parameter is ignored in this mode.
 */
enum class FilterMode {
    BloomFilter,
    PlainSet
};

/**
 * @struct PublicParameters
 * @brief Parameters defining the server and client configuration domains.
 */
struct PublicParameters {
    int curve_id; 
    std::shared_ptr<ECGroup> group_ctx;            // The ECC group context
    std::shared_ptr<Zn> field_ctx;                 // the SK space

    size_t log_server_len = 0;
    size_t log_client_len = 0;

    FilterMode filter_mode = FilterMode::BloomFilter; // membership-test backend
    size_t statistical_security_parameter = 40;    // default k = 40 → FPR ~ 2^-40 (BloomFilter mode only)

    std::string format() const;

    // Stream serialization operators matching Taihang's style
    friend std::ostream& operator<<(std::ostream& os, const PublicParameters& pp);
    friend std::istream& operator>>(std::istream& is,       PublicParameters& pp);
};

/**
 * @brief Constructs a fully-initialised PublicParameters object.
 *
 * @param curve_id                  OpenSSL NID identifying the elliptic curve.
 * @param log_server_len            log2 of the server set size.
 * @param log_client_len            log2 of the client set size.
 * @param mode                      FilterMode::BloomFilter (default) or FilterMode::PlainSet.
 * @param statistical_security_param  Bits of statistical security for the Bloom Filter (ignored when mode == PlainSet).
 */
PublicParameters setup(int    curve_id,
                       size_t log_server_len,
                       size_t log_client_len,
                       FilterMode mode = FilterMode::BloomFilter,
                       std::optional<size_t> statistical_security_parameter = std::nullopt);

/**
 * @brief Executes the Server-side context of the mqRPMT protocol.
 * @param io Reference to the network transmission pipeline.
 * @param pp Protocol operational dimension constraints.
 * @param vec_y Server dataset of elements packed as Blocks.
 * @return std::vector<uint8_t> An indication vector aligned with Client's input vector entries.
 */
std::vector<uint8_t> server(net::NetIO& io, const PublicParameters& pp, const std::vector<Block>& vec_y);

/**
 * @brief Executes the Client-side context of the mqRPMT protocol.
 * @param io Reference to the network transmission pipeline.
 * @param pp Protocol operational dimension constraints.
 * @param vec_x Client query dataset of elements packed as Blocks.
 */
void client(net::NetIO& io, const PublicParameters& pp, const std::vector<Block>& vec_x);

} // namespace taihang::mpc::cwprf_mqrpmt

#endif // TAIHANG_PROTOCOLS_CWPRF_MQRPMT_HPP