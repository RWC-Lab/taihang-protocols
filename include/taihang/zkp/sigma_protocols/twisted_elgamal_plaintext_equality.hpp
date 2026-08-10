/****************************************************************************
 * @file      twisted_elgamal_plaintext_equality.hpp
 * @brief     NIZK proof that multi-recipient twisted-ElGamal ciphertexts share a plaintext and randomness.
 *****************************************************************************/

#ifndef TAIHANG_PROTOCOLS_ZKP_SIGMA_TWISTED_ELGAMAL_PLAINTEXT_EQUALITY_HPP
#define TAIHANG_PROTOCOLS_ZKP_SIGMA_TWISTED_ELGAMAL_PLAINTEXT_EQUALITY_HPP

#include <iosfwd>
#include <memory>
#include <string_view>
#include <vector>

#include <taihang/crypto/ec_group.hpp>
#include <taihang/crypto/zn.hpp>
#include <taihang/pke/twisted_elgamal.hpp>

namespace taihang::zkp::nizk::twisted_elgamal_plaintext_equality {

/**
 * @brief Public parameters for the multi-recipient plaintext-equality relation.
 *
 * The parameters are inherited from twisted ElGamal and share its group and
 * scalar-ring contexts.
 */
struct PublicParameters {
    int curve_id;
    std::shared_ptr<ECGroup> group_ctx;
    std::shared_ptr<Zn> ring_ctx;
    ECPoint g;
    ECPoint h;
};

/**
 * @brief Public statement for multi-recipient ciphertexts with reused
 * randomness.
 *
 * For every recipient i, the relation is
 * `ct.vec_c1[i] = vec_pk[i] * r`, while the common component satisfies
 * `ct.c2 = g * r + h * v`.
 */
struct Statement {
    std::vector<ECPoint> vec_pk;
    pke::twisted_elgamal::MrCiphertext ct;
};

/** @brief Common plaintext v and common encryption randomness r. */
struct Witness {
    ZnElement v;
    ZnElement r;
};

/**
 * @brief Fiat-Shamir proof that all recipient ciphertexts use the same (v, r).
 *
 * Each `vec_c1[i]` is the first-round commitment `vec_pk[i] * a`; `c2` is
 * `g * a + h * b`.  The responses are `z = a + e * r` and
 * `t = b + e * v`.
 */
struct Proof {
    std::vector<ECPoint> vec_c1; ///< Per-recipient first-round commitments.
    ECPoint c2;                  ///< Commitment for the common component.
    ZnElement z;                 ///< Response associated with r.
    ZnElement t;                 ///< Response associated with v.

    bool operator==(const Proof& other) const;
    bool operator!=(const Proof& other) const { return !(*this == other); }

    friend std::ostream& operator<<(std::ostream& os, const Proof& proof);
    /** @note The caller must initialize point and scalar contexts before deserialization. */
    friend std::istream& operator>>(std::istream& is, Proof& proof);
};

/**
 * @brief Set up proof parameters from an existing twisted-ElGamal setup.
 *
 * Sharing contexts ensures that public keys, ciphertexts, and proof bases
 * belong to the same elliptic-curve group and scalar ring.
 */
PublicParameters setup(const pke::twisted_elgamal::PublicParameters& encryption_pp);

/**
 * @brief Generate a proof that all recipient ciphertexts encrypt one (v, r).
 *
 * The prover samples a,b, creates one commitment per recipient plus the
 * common commitment, hashes the statement and commitments to obtain e, and
 * returns the two responses.
 *
 * @param context Optional associated data bound to the proof.
 */
Proof prove(const PublicParameters& pp,
            const Statement& statement,
            const Witness& witness,
            std::string_view context = {});

/**
 * @brief Verify a multi-recipient plaintext-equality proof.
 *
 * Verification checks every recipient equation
 * `vec_pk[i] * z = vec_c1[i] + ct.vec_c1[i] * e` and the common equation
 * `g * z + h * t = c2 + ct.c2 * e`.
 */
bool verify(const PublicParameters& pp,
            const Statement& statement,
            const Proof& proof,
            std::string_view context = {});

} // namespace taihang::zkp::nizk::twisted_elgamal_plaintext_equality

#endif // TAIHANG_PROTOCOLS_ZKP_SIGMA_TWISTED_ELGAMAL_PLAINTEXT_EQUALITY_HPP
