/****************************************************************************
 * @file      twisted_elgamal_range_proof.hpp
 * @brief     Range proofs for plaintexts inside twisted-ElGamal ciphertexts.
 *
 * The module proves that the plaintext m encrypted by a ciphertext belongs to
 * a public half-open interval [lower, upper). It supports two witness models:
 *
 *  - the encryptor proves with the plaintext m and encryption randomness r;
 *  - the key holder proves with the secret key by refreshing the ciphertext.
 *
 * Both constructions reduce the interval relation to one aggregated
 * Bulletproof over two shifted commitments.
 *****************************************************************************/

#ifndef TAIHANG_PROTOCOLS_ZKP_RANGE_PROOFS_TWISTED_ELGAMAL_RANGE_PROOF_HPP
#define TAIHANG_PROTOCOLS_ZKP_RANGE_PROOFS_TWISTED_ELGAMAL_RANGE_PROOF_HPP

#include <iosfwd>
#include <string_view>

#include <taihang/algorithm/bsgs_dlog.hpp>
#include <taihang/pke/twisted_elgamal.hpp>
#include <taihang/zkp/range_proofs/bullet_proof.hpp>
#include <taihang/zkp/sigma_protocols/dlog_equality.hpp>
#include <taihang/zkp/sigma_protocols/twisted_elgamal_plaintext_knowledge.hpp>

namespace taihang::zkp::range_proofs::twisted_elgamal_range_proof {

/**
 * @brief Public parameters shared by encryption and the range proof.
 *
 * The Bulletproof commitment bases are exactly the twisted-ElGamal bases:
 *
 *   ciphertext.c2 = g * randomness + h * plaintext.
 *
 * Reusing these bases is essential: it lets the ciphertext component serve
 * directly as the Pedersen commitment checked by Bulletproof.
 */
struct PublicParameters {
    pke::twisted_elgamal::PublicParameters encryption;
    bulletproof::PublicParameters range;
};

/** @brief Public half-open interval [lower, upper). */
struct Interval {
    BigInt lower;
    BigInt upper;
};

/** @brief Public key, ciphertext, and interval whose relation is proved. */
struct Statement {
    pke::twisted_elgamal::PublicKey public_key;
    pke::twisted_elgamal::Ciphertext ciphertext;
    Interval interval;
};

/**
 * @brief Witness for a prover that knows how the ciphertext was encrypted.
 *
 * For ciphertext (c1, c2), the witness satisfies
 *
 *   c1 = public_key * randomness,
 *   c2 = g * randomness + h * plaintext.
 */
struct PlaintextKnowledgeWitness {
    ZnElement plaintext;
    ZnElement randomness;
};

/**
 * @brief Range proof generated from knowledge of plaintext and randomness.
 *
 * `plaintext_knowledge` binds the plaintext and randomness to the complete
 * ciphertext. `range` proves that the same committed plaintext lies in the
 * public interval.
 */
struct PlaintextKnowledgeProof {
    nizk::twisted_elgamal_plaintext_knowledge::Proof plaintext_knowledge;
    bulletproof::Proof range;

    bool operator==(const PlaintextKnowledgeProof& other) const;
    bool operator!=(const PlaintextKnowledgeProof& other) const {
        return !(*this == other);
    }

    friend std::ostream& operator<<(std::ostream& os,
                                    const PlaintextKnowledgeProof& proof);
    /** @note Nested point and scalar contexts must be initialized first. */
    friend std::istream& operator>>(std::istream& is,
                                    PlaintextKnowledgeProof& proof);
};

/**
 * @brief Witness for a prover that knows the ciphertext's decryption key.
 *
 * The secret key is used to recover the plaintext and to prove that a freshly
 * encrypted ciphertext contains the same plaintext as the public ciphertext.
 */
struct SecretKeyKnowledgeWitness {
    pke::twisted_elgamal::SecretKey secret_key;
};

/**
 * @brief Range proof generated from knowledge of the decryption key.
 *
 * The prover refreshes the ciphertext with known randomness. The
 * `rerandomization` proof establishes plaintext equality with the original
 * ciphertext, `plaintext_knowledge` proves knowledge of the refreshed
 * ciphertext's plaintext and randomness, and `range` proves the interval.
 */
struct SecretKeyKnowledgeProof {
    pke::twisted_elgamal::Ciphertext refreshed_ciphertext;
    nizk::dlog_equality::Proof rerandomization;
    nizk::twisted_elgamal_plaintext_knowledge::Proof plaintext_knowledge;
    bulletproof::Proof range;

    bool operator==(const SecretKeyKnowledgeProof& other) const;
    bool operator!=(const SecretKeyKnowledgeProof& other) const {
        return !(*this == other);
    }

    friend std::ostream& operator<<(std::ostream& os,
                                    const SecretKeyKnowledgeProof& proof);
    /** @note Nested point and scalar contexts must be initialized first. */
    friend std::istream& operator>>(std::istream& is,
                                    SecretKeyKnowledgeProof& proof);
};

/**
 * @brief Create range-proof parameters from exponential twisted ElGamal.
 *
 * The encryption message width becomes the Bulletproof range width. The
 * Bulletproof setup reserves aggregation two because an arbitrary interval
 * requires one lower-bound and one upper-bound commitment.
 */
PublicParameters setup(
    const pke::twisted_elgamal::PublicParameters& encryption_pp);

/**
 * @brief Prove the range relation using the plaintext and randomness.
 * @param context Optional public data bound to every component proof.
 */
PlaintextKnowledgeProof prove(
    const PublicParameters& pp,
    const Statement& statement,
    const PlaintextKnowledgeWitness& witness,
    std::string_view context = {});

/**
 * @brief Publicly verify a plaintext-knowledge range proof.
 * @param context Public data supplied to prove().
 */
bool verify(const PublicParameters& pp,
            const Statement& statement,
            const PlaintextKnowledgeProof& proof,
            std::string_view context = {});

/**
 * @brief Prove the ciphertext interval relation from the decryption key.
 *
 * The prepared BSGS solver recovers the scalar plaintext from h*plaintext.
 * Its base and search range must match the encryption parameters.
 * @param context Optional public data bound to every component proof.
 */
SecretKeyKnowledgeProof prove(
    const PublicParameters& pp,
    const Statement& statement,
    const SecretKeyKnowledgeWitness& witness,
    const dlog::BSGSSolver& solver,
    std::string_view context = {});

/**
 * @brief Publicly verify a secret-key-knowledge range proof.
 * @param context Public data supplied to prove().
 */
bool verify(const PublicParameters& pp,
            const Statement& statement,
            const SecretKeyKnowledgeProof& proof,
            std::string_view context = {});

} // namespace taihang::zkp::range_proofs::twisted_elgamal_range_proof

#endif // TAIHANG_PROTOCOLS_ZKP_RANGE_PROOFS_TWISTED_ELGAMAL_RANGE_PROOF_HPP
