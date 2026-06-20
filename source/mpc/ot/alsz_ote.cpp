/****************************
 * @file      alsz_ote.cpp
 * @brief     Implementation of ALSZ OT Extension.
 ****************************/

#include <taihang/mpc/ot/alsz_ote.hpp>
#include <taihang/common/check.hpp>
#include <taihang/common/logger.hpp>
#include <taihang/crypto/prg.hpp>
#include <taihang/crypto/stream_cipher.hpp>
#include <format>
#include <omp.h>
#include <cstring>

namespace taihang::mpc::alsz_ote {

// --- PublicParameters ---

std::string PublicParameters::format() const {
    std::ostringstream oss;
    oss << "[ALSZ OTE PublicParameters] \n"
        << "Malicious: " << (malicious ? "true" : "false") << "\n"
        << "Base Length: " << base_len << "\n"
        << base_ot_pp.format();
    return oss.str();
}

std::ostream& operator<<(std::ostream& os, const PublicParameters& pp) {
    os << pp.base_ot_pp << " " << pp.malicious << " " << pp.base_len;
    return os;
}

std::istream& operator>>(std::istream& is, PublicParameters& pp) {
    is >> pp.base_ot_pp >> pp.malicious >> pp.base_len;
    return is;
}

// --- Algorithms ---

PublicParameters setup(int curve_id, size_t base_len) {
    PublicParameters pp; 
    pp.malicious = false; 
    pp.base_ot_pp = taihang::mpc::np_ot::setup(curve_id); // Assuming standard integration
    pp.base_len = base_len;
    return pp;
}


// sender obtains extend_len number of key pairs
inline std::pair<std::vector<Block>, std::vector<Block>> random_send(net::NetIO& io, 
                                                                     const PublicParameters& pp, 
                                                                     size_t extend_len) 
{
    /* 
    ** Phase 1: sender obtains a random blended matrix Q of matrix T and U from receiver
    ** T and U are tall and skinny matrix, to use base OT oblivious transfer T and U, 
    ** the sender first oblivous get 1-out-of-2 keys per column from receiver via base OT 
    ** receiver then send encryptions of the original column and shared column under k0 and k1 respectively
    */

    // prepare to receive a secret shared matrix Q from receiver
    size_t row_num = extend_len;      // set row num as the length of ot extension
    size_t column_num = pp.base_len;  // set column num as the number of base ot

    TAIHANG_ASSERT(row_num % 128 == 0 && column_num % 128 == 0, "Row or column parameters are wrong");

    // initial OT phase (base OTs)
    // generate phase 1 selection bit vector (sparse form)
    prg::Seed seed = prg::set_seed(nullptr, 0); 
    std::vector<uint8_t> vec_sender_selection_bit = prg::gen_random_bits(seed, column_num); 

    // first receive 1-out-2 keys (acturally seeds) from the receiver 
    auto vec_q_seed = taihang::mpc::np_ot::receive(io, pp.base_ot_pp, vec_sender_selection_bit, column_num);

    TAIHANG_LOG("ALSZ OTE [step 1]:", std::format("Sender obliviously gets {} keys from Receiver via base OT", pp.base_len));

    // after receiving keys, begin to receive ciphertexts
    std::vector<Block> matrix_q((row_num / 128) * column_num); // size = ROW_NUM/128 * COLUMN_NUM 
    std::vector<Block> q_column; // size = ROW_NUM/128

    for(size_t j = 0; j < column_num; j++) {
        prg::reset_seed(seed, &vec_q_seed[j], 0); 
        q_column = prg::gen_random_blocks(seed, row_num / 128);
        std::memcpy(matrix_q.data() + (row_num / 128) * j, q_column.data(), row_num / 8);   
    } 
    
    // OT extension phase: receive u^i from receiver for every 1 \leq i \leq \kappa
    std::vector<Block> matrix_p((row_num / 128) * column_num); 
    io.recv(matrix_p); 

    // for every 1 \leq j \leq \kappa, define q^j = (s_j \cdot u^j) \oplus G(k_j^s_j)
    for(size_t j = 0; j < column_num; j++) {
        for(size_t i = 0; i < row_num / 128; i++) {
            if(vec_sender_selection_bit[j] == 1) {
                matrix_q[j * (row_num / 128) + i] ^= matrix_p[j * (row_num / 128) + i]; 
            }
        }
    }

    // transpose matrix Q
    std::vector<Block> matrix_q_transpose((row_num / 128) * column_num);  
    bit_matrix_transpose(reinterpret_cast<uint8_t*>(matrix_q.data()), column_num, row_num, reinterpret_cast<uint8_t*>(matrix_q_transpose.data()));  

    // crush selection bit vector in sparse form to dense form
    std::vector<Block> vec_sender_selection_block(column_num / 128); 
    pack_bits_to_blocks(vec_sender_selection_bit.data(), column_num, vec_sender_selection_block.data(), column_num / 128); 
    

    // Generate return vectors
    std::vector<Block> vec_k0(row_num);
    std::vector<Block> vec_k1(row_num);

    // prepare k_0 and k_1 for every row 1 \leq j \leq m
    #pragma omp parallel for num_threads(config::thread_num)
    for(size_t j = 0; j < row_num; j++) {
        std::vector<Block> q_row(column_num / 128);
        std::memcpy(q_row.data(), matrix_q_transpose.data() + j * (column_num / 128), column_num / 8); 
        vec_k0[j] = aes::hash_blocks_to_block(q_row); 
        vec_k1[j] = aes::hash_blocks_to_block(q_row ^ vec_sender_selection_block);
    }

    return {std::move(vec_k0), std::move(vec_k1)};
}


// implement random receive: note this random ot is slightly different from Beaver's ROT
// cause receiver can choose selection bit itself
// receiver only obtains extend_len number of 1-out-of-2 keys
std::vector<Block> random_recv(net::NetIO& io, 
                               const PublicParameters& pp, 
                               const std::vector<uint8_t>& vec_receiver_selection_bit, 
                               size_t extend_len) 
{
    // prepare random sharing of repetition of r 
    size_t row_num = extend_len; 
    size_t column_num = pp.base_len; 
    TAIHANG_ASSERT(row_num % 128 == 0 && column_num % 128 == 0, "Row or column parameters are wrong");

    prg::Seed seed = prg::set_seed(nullptr, 0); 

    std::vector<Block> vec_t_seed = prg::gen_random_blocks(seed, column_num);
    std::vector<Block> vec_u_seed = prg::gen_random_blocks(seed, column_num);

    taihang::mpc::np_ot::send(io, pp.base_ot_pp, vec_t_seed, vec_u_seed, column_num); 

    TAIHANG_LOG("ALSZ OTE [step 1]:", std::format("Receiver transmits {} seeds to Sender via base OT", column_num));
    
    // crush sparse bytes to dense bytes
    std::vector<Block> vec_receiver_selection_block(row_num / 128); 
    pack_bits_to_blocks(vec_receiver_selection_bit.data(), row_num, vec_receiver_selection_block.data(), row_num / 128); 
    
    // derive matrix T, U, and P: size = ROW_NUM/128*COLUMN_NUM
    std::vector<Block> matrix_t((row_num / 128) * column_num);
    std::vector<Block> matrix_p((row_num / 128) * column_num);
    
    for(size_t j = 0; j < column_num; j++) {
        // generate two random matrixs from seeds
        prg::reset_seed(seed, &vec_t_seed[j], 0); 
        auto t_column = prg::gen_random_blocks(seed, row_num / 128); // t = G(t_seed)
        std::memcpy(matrix_t.data() + (row_num / 128) * j, t_column.data(), row_num / 8); // form matrix T

        prg::reset_seed(seed, &vec_u_seed[j], 0);  
        auto u_column = prg::gen_random_blocks(seed, row_num / 128); // u = G(u_seed)
        
        // compute adjust matrix
        auto p_column = t_column ^ u_column; 
        p_column = p_column ^ vec_receiver_selection_block; // p = t xor u xor r 
        std::memcpy(matrix_p.data() + (row_num / 128) * j, p_column.data(), row_num / 8);  // form matrix P
    } 

    // transmit adjust bit matrix 
    io.send(matrix_p); 
    
    TAIHANG_LOG("ALSZ OTE [step 2]:", std::format("Receiver ===> {}*{} adjust bit matrix ===> Sender [{:.2f} MB]", 
                                                  row_num, column_num, 
                                                  static_cast<double>(row_num / 128 * column_num * 16) / (1024 * 1024)));

    // transpose matrix T                                              
    std::vector<Block> matrix_t_transpose((row_num / 128) * column_num); 
    bit_matrix_transpose(reinterpret_cast<uint8_t*>(matrix_t.data()), column_num, row_num, reinterpret_cast<uint8_t*>(matrix_t_transpose.data()));

    std::vector<Block> vec_k(row_num);
    #pragma omp parallel for num_threads(config::thread_num)
    for(size_t i = 0; i < row_num; i++) {
        std::vector<Block> t_row(column_num / 128);  
        std::memcpy(t_row.data(), matrix_t_transpose.data() + i * (column_num / 128), column_num / 8); 
        vec_k[i] = aes::hash_blocks_to_block(t_row); 
    } 
    return vec_k; 
}

template <typename Policy>
void send(net::NetIO& io, 
          const PublicParameters& pp, 
          const std::vector<typename Policy::Message>& vec_m0, 
          const std::vector<typename Policy::Message>& vec_m1, 
          size_t extend_len) 
{
    TAIHANG_TIMER("ALSZ OTE:", "Sender total time");
    
    // obtain two vector<Block> of length extend_len
    std::vector<Block> vec_k0, vec_k1;
    std::tie(vec_k0, vec_k1) = random_send(io, pp, extend_len);  

    std::vector<typename Policy::Ciphertext> vec_outer_c0(extend_len), vec_outer_c1(extend_len); 

    #pragma omp parallel for num_threads(config::thread_num) 
    for(size_t i = 0; i < extend_len; i++) {       
        vec_outer_c0[i] = Policy::encrypt(vec_k0[i], vec_m0[i]); 
        vec_outer_c1[i] = Policy::encrypt(vec_k1[i], vec_m1[i]);
    }

    io.send(vec_outer_c0); 
    io.send(vec_outer_c1);

    [[maybe_unused]] size_t item_size = CiphertextTraits<typename Policy::Ciphertext>::get_size(vec_outer_c0[0]);
    
    TAIHANG_LOG("ALSZ OTE [step 3]:", std::format("Sender ===> (vec_c0, vec_c1) ===> Receiver [{:.2f} MB]", 
                                                  static_cast<double>(extend_len * item_size * 2) / (1024 * 1024))); 
}

template <typename Policy>
std::vector<typename Policy::Message> recv(net::NetIO& io, 
                                           const PublicParameters& pp, 
                                           const std::vector<uint8_t>& vec_receiver_selection_bit, 
                                           size_t extend_len) 
{
    TAIHANG_TIMER("ALSZ OTE:", "Receiver total time");

    // receive extend_len number of key
    std::vector<Block> vec_k = random_recv(io, pp, vec_receiver_selection_bit, extend_len); 

    std::vector<typename Policy::Ciphertext> vec_outer_c0(extend_len), vec_outer_c1(extend_len); 

    io.recv(vec_outer_c0);
    io.recv(vec_outer_c1);

    std::vector<typename Policy::Message> vec_result(extend_len);

    #pragma omp parallel for num_threads(config::thread_num) 
    for(size_t i = 0; i < extend_len; i++) {
        if(vec_receiver_selection_bit[i] == 0) {
            vec_result[i] = Policy::decrypt(vec_k[i], vec_outer_c0[i]); 
        } else {
            vec_result[i] = Policy::decrypt(vec_k[i], vec_outer_c1[i]); 
        }
    }   

    TAIHANG_LOG("ALSZ OTE [step 4]:", "Receiver obtains vec_m"); 
    return std::move(vec_result); 
}

// one message is dummy
template <typename Policy>
void onesided_send(net::NetIO& io, 
                   const PublicParameters& pp, 
                   const std::vector<typename Policy::Message>& vec_m, 
                   size_t extend_len) 
{
    TAIHANG_TIMER("ALSZ OTE:", "Sender total time");
 
    // obtain extend_len number of two keys 
    std::vector<Block> vec_k0, vec_k1;
    std::tie(vec_k0, vec_k1) = random_send(io, pp, extend_len);   

    std::vector<typename Policy::Ciphertext> vec_outer_c(extend_len);

    #pragma omp parallel for num_threads(config::thread_num) shared(vec_k1)
    for(size_t i = 0; i < extend_len; i++) {
        vec_outer_c[i] = Policy::encrypt(vec_k1[i], vec_m[i]);
    }
    io.send(vec_outer_c); 

    [[maybe_unused]] size_t item_size = CiphertextTraits<typename Policy::Ciphertext>::get_size(vec_outer_c[0]);

    TAIHANG_LOG("ALSZ OTE [step 3]:", std::format("Sender ===> vec_c ===> Receiver [{:.2f} MB]", 
                                                  static_cast<double>(extend_len * item_size) / (1024 * 1024)));
}

template <typename Policy>
std::vector<typename Policy::Message> onesided_recv(net::NetIO& io, 
                                                    const PublicParameters& pp, 
                                                    const std::vector<uint8_t>& vec_receiver_selection_bit, 
                                                    size_t extend_len) 
{
    TAIHANG_TIMER("ALSZ OTE:", "Receiver total time");
 
    // obtain extend_len number of keys
    std::vector<Block> vec_k = random_recv(io, pp, vec_receiver_selection_bit, extend_len);

    std::vector<typename Policy::Ciphertext> vec_outer_c(extend_len); 
    io.recv(vec_outer_c);

    std::vector<typename Policy::Message> vec_result;
    vec_result.reserve(extend_len);

    for(size_t i = 0; i < extend_len; i++) {       
        if(vec_receiver_selection_bit[i] == 1) {
            vec_result.emplace_back(Policy::decrypt(vec_k[i], vec_outer_c[i]));
        }
    }   

    TAIHANG_LOG("ALSZ OTE [step 4]:", "Receiver obtains vec_m"); 
    return std::move(vec_result); 
}

}

// Add this to the bottom of alsz_ote.cpp

namespace taihang::mpc::alsz_ote {

// Explicit instantiations for BlockPolicy
template void send<BlockPolicy>(
    net::NetIO& io, 
    const PublicParameters& pp, 
    const std::vector<typename BlockPolicy::Message>& vec_m0, 
    const std::vector<typename BlockPolicy::Message>& vec_m1, 
    size_t extend_len);

template std::vector<typename BlockPolicy::Message> recv<BlockPolicy>(
    net::NetIO& io, 
    const PublicParameters& pp, 
    const std::vector<uint8_t>& vec_receiver_selection_bit, 
    size_t extend_len);

// Explicit instantiations for BytesPolicy (To prevent similar issues later)
template void send<BytesPolicy>(
    net::NetIO& io, 
    const PublicParameters& pp, 
    const std::vector<typename BytesPolicy::Message>& vec_m0, 
    const std::vector<typename BytesPolicy::Message>& vec_m1, 
    size_t extend_len);

template std::vector<typename BytesPolicy::Message> recv<BytesPolicy>(
    net::NetIO& io, 
    const PublicParameters& pp, 
    const std::vector<uint8_t>& vec_receiver_selection_bit, 
    size_t extend_len);

} // namespace taihang::mpc::alsz_ote