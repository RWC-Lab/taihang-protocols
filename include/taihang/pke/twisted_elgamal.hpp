/****************************
 * @file      elgamal.hpp
 * @brief     Twisted ElGamal Public Key Encryption (Standard and Exponential).
 * @details   Implementation of ECC-based ElGamal PKE. 
 * - Standard twisted ElGamal: msg_len_bits = 0
 * - Exponential twisted ElGamal: msg_len_bits > 0
 * @author    This file is part of Taihang-Protocols, developed by Yu Chen.
 ****************************/

#ifndef TAIHANG_PROTOCOLS_PKE_TWISTED_ELGAMAL_HPP
#define TAIHANG_PROTOCOLS_PKE_TWISTED_ELGAMAL_HPP

#include <taihang/crypto/ec_group.hpp>
#include <taihang/crypto/zn.hpp>
#include <taihang/algorithm/bsgs_dlog.hpp>
#include <functional>
#include <optional>
#include <vector>
#include <iostream>

namespace taihang::pke::twisted_elgamal {

/** @brief Public Parameters for ElGamal PKE. */
struct PublicParameters {
    int curve_id; 
    std::shared_ptr<ECGroup> group_ctx;            // The ECC group context
    ECPoint g;                // The generator point
    ECPoint h; 

    std::shared_ptr<Zn> field_ctx;                 // the SK space
    
    size_t msg_len_bits{0};   // 0 for Standard, >0 for Exponential
    BigInt msg_size{0ULL};    // 2^msg_len_bits

    // // 3. SYNTACTIC SUGAR: Makes algorithm code read naturally!
    // inline const ECGroup& get_group() const { return *group_ptr; }
    // inline const Zn& get_field() const { return *field_ptr; }

    // explicit PublicParameters(const int input_curve_id);

    // Since PublicParameters owns a unique_ptr, it is non-copyable.
    // We must explicitly allow moving.
    // PublicParameters(PublicParameters&&) noexcept = default;
    // PublicParameters& operator=(PublicParameters&&) noexcept = default;

    void print(std::string_view label = "", std::ostream& os = std::cout) const;

    // Serialization
    friend std::ostream& operator<<(std::ostream& os, const PublicParameters& pp);
    friend std::istream& operator>>(std::istream& is, PublicParameters& pp);
};

struct SecretKey {
    ZnElement x;
};

struct PublicKey {
    ECPoint y; // g^x
};

/** @brief Standard Ciphertext (X, Y) = (g^r, pk^r * M) */
struct Ciphertext {
    ECPoint c1;
    ECPoint c2;

    Ciphertext homo_add(const Ciphertext& other) const;
    Ciphertext homo_sub(const Ciphertext& other) const;
    Ciphertext homo_mul(const ZnElement& k) const;

    Ciphertext operator+(const Ciphertext& other) const;
    Ciphertext operator-(const Ciphertext& other) const;
    Ciphertext operator*(const ZnElement& k) const;

    bool operator==(const Ciphertext& other) const;
    bool operator!=(const Ciphertext& other) const { return !(*this == other); }

    friend std::ostream& operator<<(std::ostream& os, const Ciphertext& ct);
    friend std::istream& operator>>(std::istream& is, Ciphertext& ct);

    void print(std::string_view label = "", std::ostream& os = std::cout) const;

};

/** 
 * @brief Multi-Recipient Ciphertext 
 * @details Shares the same randomness 'r' (c1_vec) across multiple recipients (c2).
 *          c1[i] = pk[i]^r
 *          c2    = h^r * m
 */
struct MrCiphertext {
    std::vector<ECPoint> vec_c1;
    ECPoint c2;

    friend std::ostream& operator<<(std::ostream& os, const MrCiphertext& ct);
    friend std::istream& operator>>(std::istream& is, MrCiphertext& ct);

    bool operator==(const MrCiphertext& other) const;
    bool operator!=(const MrCiphertext& other) const { return !(*this == other); }

    void print(std::string_view label = "", std::ostream& os = std::cout) const;
};

// --- Core API ---

/** @brief Initialize parameters using curve ID. Set bits > 0 for Exponential ElGamal. */
PublicParameters setup(int curve_id, size_t msg_len_bits = 0ULL);

/** @brief Generate (pk, sk) where pk = g^sk. */
std::pair<PublicKey, SecretKey> keygen(const PublicParameters& pp);

// Single Recipient Encryption
// Encryption (Overloaded for ECPoint/Standard and Zn/Exponential)
Ciphertext encrypt(const PublicParameters& pp, const PublicKey& pk, const ECPoint& m, 
                   const std::optional<ZnElement>& r = std::nullopt);
Ciphertext encrypt(const PublicParameters& pp, const PublicKey& pk, const ZnElement& m, 
                   const std::optional<ZnElement>& r = std::nullopt);

// Multi-Recipient Encryption
MrCiphertext encrypt(const PublicParameters& pp, const std::vector<PublicKey>& vec_pk, 
                     const ZnElement& m, const std::optional<ZnElement>& r = std::nullopt);
ECPoint decrypt(const SecretKey& sk, const MrCiphertext& ct, size_t index);

// Decryption
ECPoint decrypt_raw(const SecretKey& sk, const Ciphertext& ct);
inline ECPoint decrypt(const SecretKey& sk, const Ciphertext& ct) { return decrypt_raw(sk, ct); }
ZnElement decrypt_exp(const PublicParameters& pp, const SecretKey& sk, const Ciphertext& ct, const dlog::BSGSSolver& solver);

// Decrypt specific index from MR-Ciphertext
ECPoint decrypt(const SecretKey& sk, const MrCiphertext& ct, size_t index);

// Transformation & Homomorphic Ops
Ciphertext re_enc(const PublicParameters& pp, const PublicKey& pk, const SecretKey& sk, 
                  const Ciphertext& ct, const ZnElement& r);
Ciphertext re_rand(const PublicParameters& pp, const PublicKey& pk, const Ciphertext& ct);


} // namespace taihang::pke::elgamal

#endif