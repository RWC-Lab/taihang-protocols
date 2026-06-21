/****************************************************************************
 * @file      cwprf_mqrpmt.cpp
 * @brief     Implementation of weak commutative PRF multi-query RPMT.
 * @author    This file is part of Taihang, developed by Yu Chen.
 *****************************************************************************/

#include <taihang/mpc/rpmt/cwprf_mqrpmt.hpp>
#include <taihang/common/logger.hpp>
#include <format>
#include <chrono>
#include <cmath>
#include <omp.h>

namespace taihang::mpc::cwprf_mqrpmt {

std::string PublicParameters::format() const {
    std::ostringstream oss; 
    oss << "[cwPRF-based mqRPMT PublicParameters] \n";
    oss << "Curve ID: " << curve_id << "\n";
    oss << "Statistical parameter = " << statistical_security_parameter << "\n"; 
    oss << "Server set size = " << log_server_len << "\n"; 
    oss << "Client set size = " << log_client_len << "\n"; 
    return oss.str(); 
}

std::ostream& operator<<(std::ostream& os, const PublicParameters& pp) {
    os << pp.curve_id << " "  << pp.statistical_security_parameter << " "
       << pp.log_server_len << " " << pp.log_client_len;
    return os;
}

std::istream& operator>>(std::istream& is, PublicParameters& pp) {
    is >> pp.curve_id >> pp.statistical_security_parameter 
       >> pp.log_server_len >> pp.log_client_len;

    // Allocate contexts with stable addresses
    pp.group_ctx = std::make_shared<ECGroup>(pp.curve_id);
    pp.field_ctx = std::make_shared<Zn>(pp.group_ctx->order); 
    
    return is;
}

PublicParameters setup(int curve_id, size_t statistical_security_param, size_t log_server_len, size_t log_client_len) {
    PublicParameters pp;
    pp.curve_id = curve_id;
    // Allocate contexts with stable addresses
    pp.group_ctx = std::make_shared<ECGroup>(pp.curve_id);
    pp.field_ctx = std::make_shared<Zn>(pp.group_ctx->order); 

    pp.statistical_security_parameter = statistical_security_param;
    pp.log_server_len = log_server_len;
    pp.log_client_len = log_client_len;

    return pp;
}

std::vector<uint8_t> server(net::NetIO& io, const PublicParameters& pp, const std::vector<Block>& vec_y) {
    TAIHANG_TIMER("cwPRF mqRPMT:", "Server total execution time");
    TAIHANG_LOG("cwPRF mqRPMT:", "Server protocol context initiated >>>");

    size_t server_len = static_cast<size_t>(std::pow(2, pp.log_server_len));
    size_t client_len = static_cast<size_t>(std::pow(2, pp.log_client_len));

    TAIHANG_ASSERT(server_len == vec_y.size(), "cwPRF mqRPMT: Server input size mismatch.");

    [[maybe_unused]] size_t point_byte_len = pp.group_ctx->get_point_byte_len();
    
    // Pick a secret random exponent key k1 from the Zn scalar field
    ZnElement k1 = pp.field_ctx->gen_random();
    
    // Step 1: Compute F_k1(H(y_i)) = H(y_i)^k1
    std::vector<ECPoint> vec_fk1_y(server_len, pp.group_ctx);
    #pragma omp parallel for num_threads(config::thread_num)
    for (size_t i = 0; i < server_len; ++i) {
        vec_fk1_y[i] = hash_to_curve_fast(vec_y[i], *pp.group_ctx) * k1;
    }

    TAIHANG_LOG("cwPRF mqRPMT [step 1]:", std::format("Server ===> F_k1(H(y_i)) ===> Client [{:.2f} MB]", 
                                                  static_cast<double>(pp.server_len * point_byte_len) / (1024 * 1024)));
    // Send F_k1(y_i) elements immediately to client
    io.send(vec_fk1_y);

    TAIHANG_LOG("cwPRF mqRPMT [step 2]:", "Server receives F_k2(H(x_i)) from Client...");
    // Receive F_k2(x_i) from client
    std::vector<ECPoint> vec_fk2_x(client_len, pp.group_ctx);
    io.recv(vec_fk2_x);

    // Step 2: Compute commutative composite layer F_k1k2(x_i) = (F_k2(x_i))^k1
    std::vector<ECPoint> vec_fk1k2_x(client_len, pp.group_ctx);
    #pragma omp parallel for num_threads(config::thread_num)
    for (size_t i = 0; i < client_len; ++i) {
        vec_fk1k2_x[i] = vec_fk2_x[i] * k1;
    }

    TAIHANG_LOG("cwPRF mqRPMT [step 2]:", "Server receives bloom filter from Client...");
    // Step 3: Receive Bloom Filter payload metadata and mapping from client
    size_t filter_size = 0;
    io.recv(filter_size);

    std::vector<char> buffer(filter_size);
    io.recv(buffer.data(), filter_size);

    TAIHANG_LOG("cwPRF mqRPMT [step 3]:", std::format("Server reconstructing Bloom Filter structure [{:.2f} MB]", 
                                                  static_cast<double>(filter_size) / (1024 * 1024)));
    // Reconstruct Bloom Filter representation object
    BloomFilter filter;
    bool deserialize_success = filter.deserialize(buffer.data());
    TAIHANG_ASSERT(deserialize_success, "cwPRF mqRPMT: Bloom Filter parsing failed.");

    TAIHANG_LOG("cwPRF mqRPMT [step 4]:", "Server running batched membership lookup over intersection domain");
    // Determine intersection membership representation
    std::vector<uint8_t> vec_indication_bit(client_len);
    #pragma omp parallel for num_threads(config::thread_num)
    for (size_t i = 0; i < client_len; ++i) {
        auto bytes = vec_fk1k2_x[i].to_bytes();
        vec_indication_bit[i] = filter.contains(bytes.data(), bytes.size()) ? 1 : 0;
    }

    TAIHANG_LOG("cwPRF mqRPMT:", "Server protocol context successfully completed <<<");
    return vec_indication_bit;
}

void client(net::NetIO& io, const PublicParameters& pp, const std::vector<Block>& vec_x) {
    TAIHANG_TIMER("cwPRF mqRPMT:", "Client total execution time");
    TAIHANG_LOG("cwPRF mqRPMT:", "Client protocol context initiated >>>");

    size_t server_len = static_cast<size_t>(std::pow(2, pp.log_server_len));
    size_t client_len = static_cast<size_t>(std::pow(2, pp.log_client_len));

    TAIHANG_ASSERT(client_len == vec_x.size(), "cwPRF mqRPMT: Client input size mismatch.");

    [[maybe_unused]] size_t point_byte_len = pp.group_ctx -> get_point_byte_len();

    // Pick a secret random exponent key k2 from the Zn scalar field
    ZnElement k2 = pp.field_ctx -> gen_random();


    // Step 1: Compute F_k2(H(x_i)) = H(x_i)^k2
    std::vector<ECPoint> vec_fk2_x(client_len, pp.group_ctx);
    #pragma omp parallel for num_threads(config::thread_num)
    for (size_t i = 0; i < client_len; ++i) {
        vec_fk2_x[i] = hash_to_curve_fast(vec_x[i], *pp.group_ctx) * k2;
    }

    TAIHANG_LOG("cwPRF mqRPMT [step 1]:", "Client receives F_k1(H(y_i)) from Server...");
    // Receive incoming server layers F_k1(y_i)
    std::vector<ECPoint> vec_fk1_y(server_len, pp.group_ctx);
    io.recv(vec_fk1_y);

    TAIHANG_LOG("cwPRF mqRPMT [step 2]:", std::format("Client ===> F_k2(H(x_i)) ===> Server [{:.2f} MB]", 
                                                  static_cast<double>(pp.client_len * point_byte_len) / (1024 * 1024)));
    // Send blindings out immediately
    io.send(vec_fk2_x);

    // Step 2: Compute commutative PRF values F_k2k1(y_i) = (F_k1(y_i))^k2
    std::vector<ECPoint> vec_fk2k1_y(server_len, pp.group_ctx);
    #pragma omp parallel for num_threads(config::thread_num)
    for (size_t i = 0; i < server_len; ++i) {
        vec_fk2k1_y[i] = vec_fk1_y[i] * k2;
    }

    TAIHANG_LOG("cwPRF mqRPMT [step 3]:", "Client initializing and populating probabilistic Bloom Filter structure");
    // Step 3: Initialize and populate Bloom Filter structure with F_k2k1(y_i)
    BloomFilter filter(vec_fk2k1_y.size(), pp.statistical_security_parameter);

    #pragma omp parallel for num_threads(config::thread_num)
    for (size_t i = 0; i < server_len; ++i) {
        auto bytes = vec_fk2k1_y[i].to_bytes();
        filter.insert(bytes.data(), bytes.size());
    }

    // Serialize and ship the Bloom Filter structure across the wire
    size_t filter_size = filter.get_serialized_size();
    io.send(filter_size);

    std::vector<char> buffer(filter_size);
    bool serialize_success = filter.serialize(buffer.data());
    TAIHANG_ASSERT(serialize_success, "cwPRF mqRPMT: Bloom Filter serialization failed.");
    
    TAIHANG_LOG("cwPRF mqRPMT [step 3]:", std::format("Client ===> BloomFilter(F_k2k1(y_i)) ===> Server [{:.2f} MB]", 
                                                  static_cast<double>(filter_size) / (1024 * 1024)));
    io.send(buffer.data(), filter_size);

    TAIHANG_LOG("cwPRF mqRPMT:", "Client protocol context successfully completed <<<");
}

} // namespace taihang::mpc::cwprf_mqrpmt