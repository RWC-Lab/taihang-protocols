/****************************
 * @file      alsz_ote.hpp
 * @brief     ALSZ OT Extension.
 * @details   With optimization of "More Efficient Oblivious Transfer and Extensions for Faster Secure Computation"
 * https://eprint.iacr.org/2013/552.pdf
 ****************************/

#ifndef TAIHANG_MPC_ALSZ_OTE_HPP_
#define TAIHANG_MPC_ALSZ_OTE_HPP_

#include <taihang/mpc/ot/naor_pinkas_ot.hpp>
#include <taihang/crypto/block.hpp>
#include <taihang/crypto/stream_cipher.hpp>
#include <vector>
#include <iostream>
#include <fstream>
#include <string>

using namespace taihang::net;

namespace taihang::mpc::alsz_ote {

// Policy for Block messages: "encryption" is just XOR
struct BlockPolicy {
    using Message = Block;
    using Ciphertext = Block;

    static Ciphertext encrypt(const Block& key, const Block& msg) { return msg ^ key; }
    static Message    decrypt(const Block& key, const Ciphertext& ct) { return ct ^ key; }
};

// Policy for variable-length byte messages: stream cipher
struct BytesPolicy {
    using Message    = std::vector<uint8_t>;
    using Ciphertext = std::vector<uint8_t>;

    static Ciphertext encrypt(const Block& key, const Message& msg) {
        return streamcipher::encrypt(key, msg);
    }
    static Message decrypt(const Block& key, const Ciphertext& ct) {
        return streamcipher::decrypt(key, ct);
    }
};

// 1. Define the trait template
template <typename T>
struct CiphertextTraits;

// 2. Specialize for Block (Fixed size)
template <>
struct CiphertextTraits<Block> {
    static constexpr size_t get_size(const Block&) { return 16; }
};

// 3. Specialize for vector<uint8_t> (Dynamic size)
template <>
struct CiphertextTraits<std::vector<uint8_t>> {
    static size_t get_size(const std::vector<uint8_t>& vec) { return vec.size(); }
};

constexpr size_t kBaseLen = 128; // the default length of base OT

/** @brief Public Parameters for ALSZ OTE. */
struct PublicParameters {
    bool malicious = false; 
    taihang::mpc::np_ot::PublicParameters base_ot_pp;  
    size_t base_len = kBaseLen;  

    std::string format() const;

    // Serialization
    friend std::ostream& operator<<(std::ostream& os, const PublicParameters& pp);
    friend std::istream& operator>>(std::istream& is, PublicParameters& pp);
};

// --- Core API ---

/** @brief Initialize parameters using base length. */
PublicParameters setup(int curve_id, size_t base_len = kBaseLen);

// --- OT Extension Routines ---

std::pair<std::vector<Block>, std::vector<Block>> random_send(net::NetIO& io, 
                                                              const PublicParameters& pp, 
                                                              size_t extend_len);

std::vector<Block> random_recv(net::NetIO& io, 
                               const PublicParameters& pp, 
                               std::vector<uint8_t>& vec_receiver_selection_bit, 
                               size_t extend_len);

template <typename Policy>
void send(net::NetIO& io, 
          const PublicParameters& pp, 
          const std::vector<typename Policy::Message>& vec_m0, 
          const std::vector<typename Policy::Message>& vec_m1, 
          size_t extend_len);

template <typename Policy>
std::vector<typename Policy::Message> recv(net::NetIO& io, 
                                           const PublicParameters& pp, 
                                           const std::vector<uint8_t>& vec_receiver_selection_bit, 
                                           size_t extend_len);

template <typename Policy>                                       
void onesided_send(net::NetIO& io, 
                   const PublicParameters& pp, 
                   const std::vector<typename Policy::Message>& vec_m, 
                   size_t extend_len);

template <typename Policy>  
std::vector<typename Policy::Message> onesided_recv(net::NetIO& io, 
                                                    const PublicParameters& pp, 
                                                    const std::vector<uint8_t>& vec_receiver_selection_bit, 
                                                    size_t extend_len);


} // namespace kunlun::mpc::alsz_ote

#endif // KUNLUN_MPC_ALSZ_OTE_HPP_