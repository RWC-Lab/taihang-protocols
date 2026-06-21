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
#include <taihang/net/net_io.hpp>
#include <taihang/structure/bloom_filter.hpp>
#include <vector>
#include <string>
#include <iostream>

namespace taihang::mpc::cwprf_mqrpmt {

/**
 * @struct PublicParameters
 * @brief Parameters defining the server and client configuration domains.
 */
struct PublicParameters {
    int curve_id; 
    std::shared_ptr<ECGroup> group_ctx;            // The ECC group context
    std::shared_ptr<Zn> field_ctx;                 // the SK space

    size_t statistical_security_parameter = 40;    // Default k = 40 (FPR ~ 2^-40)
    size_t log_server_len = 0;
    size_t log_client_len = 0;

    std::string format() const;

    // Stream serialization operators matching Taihang's style
    friend std::ostream& operator<<(std::ostream& os, const PublicParameters& pp);
    friend std::istream& operator>>(std::istream& is, PublicParameters& pp);
};

/**
 * @brief Global parameter configuration setup utility.
 */
PublicParameters setup(int curve_id, size_t statistical_security_param, size_t log_server_len, size_t log_client_len);

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