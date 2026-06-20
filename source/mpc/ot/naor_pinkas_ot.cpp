/****************************
 * @file      naor_pinkas_ot.cpp
 * @brief     Implementation of Naor-Pinkas Oblivious Transfer.
 * @author    This file is part of Taihang-Protocols, developed by Yu Chen.
 ****************************/

#include <taihang/common/check.hpp>
#include <taihang/common/logger.hpp>
#include <taihang/crypto/stream_cipher.hpp>
#include <taihang/mpc/ot/naor_pinkas_ot.hpp>
#include <format>
#include <omp.h>

namespace taihang::mpc::np_ot {

// --- PublicParameters ---

std::string PublicParameters::format() const {
    std::ostringstream oss;
    oss << "[PublicParameters] \n"
        << "Curve ID: " << curve_id << "\n"
        << "Base point g = " << g.to_string() << "\n";
    return oss.str();
};

std::ostream& operator<<(std::ostream& os, const PublicParameters& pp) {
    os << pp.curve_id << pp.g;
    return os;
}

std::istream& operator>>(std::istream& is, PublicParameters& pp) {
    if (!(is >> pp.curve_id)) return is;
    
    // Reconstruct contexts based on the received curve ID
    pp.group_ctx = std::make_shared<ECGroup>(pp.curve_id);
    pp.field_ctx = std::make_shared<Zn>(pp.group_ctx->order);
    
    pp.g = ECPoint(pp.group_ctx);
    is >> pp.g;

    return is;
}

// --- Algorithms ---

PublicParameters setup(int curve_id) {
    PublicParameters pp;
    pp.curve_id = curve_id;
    
    // Allocate contexts with stable addresses
    pp.group_ctx = std::make_shared<ECGroup>(pp.curve_id);
    pp.field_ctx = std::make_shared<Zn>(pp.group_ctx->order); 
    pp.g = pp.group_ctx->get_generator();
    
    return pp;
}

void send(net::NetIO& io, const PublicParameters& pp, const std::vector<Block>& vec_m0, const std::vector<Block>& vec_m1, size_t len) {
    
    TAIHANG_ASSERT(vec_m0.size() == len && vec_m1.size() == len, "Message vectors size mismatch");
    
    [[maybe_unused]] size_t fixed_point_len = pp.group_ctx->get_point_byte_len(); 
 
    TAIHANG_TIMER("Naor-Pinkas OT:", "Sender total time");
    TAIHANG_LOG("Naor-Pinkas OT:", "Sender execution started >>>");

    std::vector<ZnElement> vec_r(len); // randomness used for encryption
    std::vector<ECPoint> vec_pk0(len, ECPoint(pp.group_ctx)); 
    std::vector<ECPoint> vec_x(len, ECPoint(pp.group_ctx));   // the left component of ciphertext
    std::vector<ECPoint> vec_z(len, ECPoint(pp.group_ctx));   // the initial form of right component of ciphertext

    TAIHANG_LOG("Naor-Pinkas OT [step 1]:", "Sender computes public commitments (offline)");
    // Offline phase: generate a random scalar for the sender's secret d
    ZnElement d = pp.field_ctx->gen_random();
    ECPoint c = pp.g * d; // C = g^d

    // Compute g^r[i] and C^r[i] in parallel
    #pragma omp parallel for num_threads(config::thread_num)
    for (size_t i = 0; i < len; ++i) {
        vec_r[i] = pp.field_ctx->gen_random();
        vec_x[i] = pp.g * vec_r[i];
        vec_z[i] = c * vec_r[i];
    }

    TAIHANG_LOG("Naor-Pinkas OT [step 1]:", "Sender ===> (x, vec_x) ===> Receiver ..."); 
    TAIHANG_LOG("Naor-Pinkas OT [step 1]:", std::format("communication cost = {:.2f} MB", 
                                                  static_cast<double>(fixed_point_len) * (len+1) / (1024 * 1024))); 

    // Send C and vector X to the receiver
    io.send(c);
    io.send(vec_x);

    TAIHANG_LOG("Naor-Pinkas OT [step 2]:", "Sender awaits target public keys from Receiver ...");
    // Receive vector pk0 from the receiver
    io.recv(vec_pk0);

    TAIHANG_LOG("Naor-Pinkas OT [step 2]:", "Sender builds encrypted matrices (vec_y0, vec_y1) ...");
    std::vector<ECPoint> vec_k0(len, ECPoint(pp.group_ctx));
    std::vector<ECPoint> vec_k1(len, ECPoint(pp.group_ctx));
    std::vector<Block> vec_y0(len);
    std::vector<Block> vec_y1(len);

    // Compute session keys and encrypt the messages
    #pragma omp parallel for num_threads(config::thread_num)
    for (size_t i = 0; i < len; ++i) {
        vec_k0[i] = vec_pk0[i] * vec_r[i];
        vec_k1[i] = vec_z[i] - vec_k0[i];
        
        vec_y0[i] = vec_k0[i].hash_to_block() ^ vec_m0[i];
        vec_y1[i] = vec_k1[i].hash_to_block() ^ vec_m1[i];
    }

    TAIHANG_LOG("Naor-Pinkas OT [step 3]:", "Sender ===> (vec_y0, vec_y1) ===> Receiver");
    TAIHANG_LOG("Naor-Pinkas OT [step 3]:", std::format("communication cost = {:.2f} MB", 
                                            static_cast<double>(fixed_point_len) * len * 2 / (1024 * 1024)));

    // Send the encrypted messages
    io.send(vec_y0);
    io.send(vec_y1);

    TAIHANG_LOG("Naor-Pinkas OT:", "Sender execution completed >>>");
}

std::vector<Block> receive(net::NetIO& io, const PublicParameters& pp, const std::vector<uint8_t>& vec_selection_bit, size_t len) {
    
    TAIHANG_ASSERT(vec_selection_bit.size() == len, "Selection bit vector size mismatch");
    [[maybe_unused]] size_t fixed_point_len = pp.group_ctx->get_point_byte_len(); 

    TAIHANG_TIMER("Naor-Pinkas OT:", "Receiver total time");
    TAIHANG_LOG("Naor-Pinkas OT:", "Receiver execution started >>>");

    std::vector<Block> vec_result(len);
    std::vector<ZnElement> vec_sk(len);
    std::vector<ECPoint> vec_x(len, ECPoint(pp.group_ctx));
    std::vector<ECPoint> vec_pk0(len, ECPoint(pp.group_ctx));

    ECPoint c = ECPoint(pp.group_ctx);
    
    TAIHANG_LOG("Naor-Pinkas OT [step 1]:", "Receiver <=== (c, vec_x) <=== Sender");
    // Receive C and vector X from the sender
    io.recv(c);
    io.recv(vec_x);

    TAIHANG_LOG("Naor-Pinkas OT [step 2]:", "Receiver prepares vec_pk[0] ...");
    // Generate public keys based on selection bits
    #pragma omp parallel for num_threads(config::thread_num)
    for (size_t i = 0; i < len; ++i) {
        vec_sk[i] = pp.field_ctx->gen_random();
        vec_pk0[i] = pp.g * vec_sk[i];
        
        if (vec_selection_bit[i] == 1) {
            vec_pk0[i] = c - vec_pk0[i];
        }
    }

    TAIHANG_LOG("Naor-Pinkas OT [step 2]:", "Receiver ===> vec_pk[0] ===> Sender");
    TAIHANG_LOG("Naor-Pinkas OT [step 2]:", std::format("communication cost = {:.2f} MB", 
                                            static_cast<double>(fixed_point_len) * len / (1024 * 1024)));
    // Send pk0 array to sender
    io.send(vec_pk0);

    std::vector<ECPoint> vec_k(len, ECPoint(pp.group_ctx));
    std::vector<Block> vec_y0(len);
    std::vector<Block> vec_y1(len);

    TAIHANG_LOG("Naor-Pinkas OT [step 3]:", "Receiver <=== (vec_y0, vec_y1) <=== Sender");
    // Receive the encrypted messages
    io.recv(vec_y0);
    io.recv(vec_y1);

    TAIHANG_LOG("Naor-Pinkas OT [step 4]:", "Receiver computes vec_result");
    // Decrypt the selected messages
    #pragma omp parallel for num_threads(config::thread_num)
    for (size_t i = 0; i < len; ++i) {
        vec_k[i] = vec_x[i] * vec_sk[i];
        
        if (vec_selection_bit[i] == 0) {
            vec_result[i] = vec_y0[i] ^ vec_k[i].hash_to_block();
        } 
        else {
            vec_result[i] = vec_y1[i] ^ vec_k[i].hash_to_block();
        }
    }

    TAIHANG_LOG("Naor-Pinkas OT", "Receiver execution completed <<<");

    return vec_result;
}

} // namespace taihang::mpc::np_ot