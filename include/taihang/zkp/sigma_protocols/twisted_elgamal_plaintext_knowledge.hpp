/****************************************************************************
 * @file      twisted_elgamal_plaintext_knowledge.hpp
 * @brief     NIZK proof of knowledge of a twisted-ElGamal plaintext/randomness pair.
 *****************************************************************************/

#ifndef TAIHANG_PROTOCOLS_ZKP_SIGMA_TWISTED_ELGAMAL_PLAINTEXT_KNOWLEDGE_HPP
#define TAIHANG_PROTOCOLS_ZKP_SIGMA_TWISTED_ELGAMAL_PLAINTEXT_KNOWLEDGE_HPP

#include <iosfwd>
#include <memory>
#include <string_view>

#include <taihang/crypto/ec_group.hpp>
#include <taihang/crypto/zn.hpp>
#include <taihang/pke/twisted_elgamal.hpp>

namespace taihang::zkp::nizk::twisted_elgamal_plaintext_knowledge {

/**
 * @brief Public parameters for the plaintext-knowledge relation.
 *
 * The parameters are inherited from twisted ElGamal.  In particular, `g`
 * and `h` are the bases used by the exponential ciphertext equation, while
 * `group_ctx` and `ring_ctx` provide the corresponding arithmetic contexts.
 */
struct PublicParameters {
    int curve_id;
    std::shared_ptr<ECGroup> group_ctx;
    std::shared_ptr<Zn> ring_ctx;
    ECPoint g;
    ECPoint h;
};

/**
 * @brief Public statement for a ciphertext C = Enc(pk, v; r).
 *
 * For exponential twisted ElGamal, the relation proved by this module is
 *
 *   ct.c1 = pk * r,
 *   ct.c2 = g * r + h * v.
 */
struct Statement {
    ECPoint pk;
    pke::twisted_elgamal::Ciphertext ct;
};

/** @brief Witness consisting of the plaintext v and encryption randomness r. */
struct Witness {
    ZnElement v;
    ZnElement r;
};

/**
 * @brief Fiat-Shamir proof of knowledge of (v, r).
 *
 * The commitments are `c1 = pk * a` and `c2 = g * a + h * b`; the responses
 * are `z1 = a + e * r` and `z2 = b + e * v`, where e is the Fiat-Shamir
 * challenge.
 */
struct Proof {
    ECPoint c1;  ///< First-round commitment for mask of the encryption randomness.
    ECPoint c2;  ///< First-round commitment for mask of the randomness/plaintext pair.
    ZnElement z1; ///< Response associated with r.
    ZnElement z2; ///< Response associated with v.

    bool operator==(const Proof& other) const;
    bool operator!=(const Proof& other) const { return !(*this == other); }

    friend std::ostream& operator<<(std::ostream& os, const Proof& proof);
    /** @note The caller must initialize point and scalar contexts before deserialization. */
    friend std::istream& operator>>(std::istream& is, Proof& proof);
};

/**
 * @brief Set up the proof parameters from an existing twisted-ElGamal setup.
 *
 * The returned object shares the group and scalar-ring contexts with
 * @p encryption_pp, so statements and ciphertexts created from that setup
 * can be used directly.
 */
PublicParameters setup(const pke::twisted_elgamal::PublicParameters& encryption_pp);

/**
 * @brief Generate a non-interactive proof of plaintext/randomness knowledge.
 *
 * The prover samples fresh a,b in the scalar ring, constructs the two
 * commitments, hashes the statement and commitments to obtain e, and returns
 * the Schnorr responses.
 *
 * @param context Optional associated data bound to the proof.
 */
Proof prove(const PublicParameters& pp,
            const Statement& statement,
            const Witness& witness,
            std::string_view context = {});

/**
 * @brief Verify a plaintext/randomness-knowledge proof.
 *
 * Verification recomputes e and checks
 * `pk * z1 = c1 + ct.c1 * e` and
 * `g * z1 + h * z2 = c2 + ct.c2 * e`.
 */
bool verify(const PublicParameters& pp,
            const Statement& statement,
            const Proof& proof,
            std::string_view context = {});

} // namespace taihang::zkp::nizk::twisted_elgamal_plaintext_knowledge

#endif // TAIHANG_PROTOCOLS_ZKP_SIGMA_TWISTED_ELGAMAL_PLAINTEXT_KNOWLEDGE_HPP
