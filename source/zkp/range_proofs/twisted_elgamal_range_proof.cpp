/****************************************************************************
 * @file      twisted_elgamal_range_proof.cpp
 * @brief     Range proofs for plaintexts inside twisted-ElGamal ciphertexts.
 *****************************************************************************/

#include <taihang/zkp/range_proofs/twisted_elgamal_range_proof.hpp>

#include <openssl/obj_mac.h>

#include <istream>
#include <ostream>
#include <string>
#include <utility>
#include <vector>

#include <taihang/common/check.hpp>
#include <taihang/utility/arithmetic.hpp>

namespace taihang::zkp::range_proofs::twisted_elgamal_range_proof {
namespace {

constexpr std::size_t kIntervalAggregation = 2;

/** Derive a deterministic Bulletproof generator in the configured group. */
ECPoint derive_bulletproof_generator(const std::string& label,
                                     const ECGroup& group) {
    static const std::string kP256Dst =
        "TAIHANG-PROTOCOLS-V01-P256_XMD:SHA-256_SSWU_RO_";

    if (group.curve_id == NID_X9_62_prime256v1) {
        return hash_to_curve_standard(label, kP256Dst, group);
    }
    return hash_to_curve_fast(label, group);
}

/**
 * Derive the Bulletproof parameters used only by this composition.
 *
 * Bulletproof remains an independent system with its own setup algorithm.
 * Here the parameters are assembled ad hoc because ciphertext.c2 already has
 * the Pedersen form g*randomness + h*plaintext. Reusing the encryption bases
 * avoids creating a second commitment and an additional equality proof.
 */
bulletproof::PublicParameters derive_bulletproof_parameters(
    const pke::twisted_elgamal::PublicParameters& encryption_pp) {
    bulletproof::PublicParameters range_pp;
    range_pp.curve_id = encryption_pp.curve_id;
    range_pp.range_bits = encryption_pp.msg_len_bits;
    range_pp.max_aggregation = kIntervalAggregation;
    range_pp.vector_length =
        range_pp.range_bits * range_pp.max_aggregation;
    range_pp.group_ctx = encryption_pp.group_ctx;
    range_pp.ring_ctx = encryption_pp.ring_ctx;
    range_pp.g = encryption_pp.g;
    range_pp.h = encryption_pp.h;
    range_pp.u = derive_bulletproof_generator("taihang/bulletproof/base-u", *range_pp.group_ctx);
    range_pp.vector_g.assign(range_pp.vector_length, ECPoint(range_pp.group_ctx));
    range_pp.vector_h.assign(range_pp.vector_length, ECPoint(range_pp.group_ctx));

    // The inner-product basis must contain independent generators. The same
    // labels as standalone Bulletproof setup preserve deterministic parameters.
    for (std::size_t i = 0; i < range_pp.vector_length; ++i) {
        range_pp.vector_g[i] = derive_bulletproof_generator(
            "taihang/bulletproof/vector-g/" + std::to_string(i),
            *range_pp.group_ctx);
        range_pp.vector_h[i] = derive_bulletproof_generator(
            "taihang/bulletproof/vector-h/" + std::to_string(i),
            *range_pp.group_ctx);
    }
    return range_pp;
}

void validate_interval(const PublicParameters& pp, const Interval& interval) {
    TAIHANG_ASSERT(interval.lower.is_non_negative() &&
                       interval.lower < interval.upper &&
                       interval.upper <= pp.encryption.msg_size,
                   "twisted-ElGamal range proof: invalid interval");
}

/**
 * Reduce m in [lower, upper) to two standard range statements:
 *
 *   m - lower                 in [0, 2^n),
 *   m + (2^n - upper)        in [0, 2^n).
 *
 * Both shifted commitments retain the original encryption randomness. This
 * permits one aggregated Bulletproof with two values and two equal blindings.
 */
bulletproof::Statement derive_shifted_commitments(
    const PublicParameters& pp,
    const pke::twisted_elgamal::Ciphertext& ciphertext,
    const Interval& interval) {
    const ZnElement lower(pp.encryption.ring_ctx, interval.lower);
    const ZnElement upper_offset(pp.encryption.ring_ctx, pp.encryption.msg_size - interval.upper);

    return {{
        ciphertext.c2 - pp.range.h * lower,
        ciphertext.c2 + pp.range.h * upper_offset,
    }};
}

/** Apply the same interval shifts to the private Bulletproof values. */
bulletproof::Witness derive_shifted_witness(
    const PublicParameters& pp,
    const Interval& interval,
    const ZnElement& plaintext,
    const ZnElement& randomness) {
    const ZnElement lower(pp.encryption.ring_ctx, interval.lower);
    const ZnElement upper_offset(pp.encryption.ring_ctx, pp.encryption.msg_size - interval.upper);

    return {
        {randomness, randomness},
        {plaintext - lower, plaintext + upper_offset},
    };
}

/** Bind the public key to the selected ciphertext knowledge statement. */
nizk::twisted_elgamal_plaintext_knowledge::Statement
derive_plaintext_knowledge_statement(
    const Statement& statement,
    const pke::twisted_elgamal::Ciphertext& ciphertext) {
    return {statement.public_key.y, ciphertext};
}

/** Reuse the encryption arithmetic contexts in the Chaum-Pedersen proof. */
nizk::dlog_equality::PublicParameters derive_dlog_equality_parameters(
    const PublicParameters& pp) {
    return {
        pp.encryption.curve_id,
        pp.encryption.group_ctx,
        pp.encryption.ring_ctx,
    };
}

nizk::dlog_equality::Statement derive_ciphertext_link_statement(
    const PublicParameters& pp,
    const Statement& statement,
    const pke::twisted_elgamal::Ciphertext& refreshed_ciphertext) {
    // Let delta denote the refreshed ciphertext minus the original one.
    // Proving log_g(pk) = log_delta.c2(delta.c1) shows
    //
    //   pk = g*sk  and  delta.c1 = delta.c2*sk.
    //
    // Therefore both ciphertexts contain the same plaintext, while their
    // encryption randomness may differ.
    return {
        pp.encryption.g,
        statement.public_key.y,
        refreshed_ciphertext.c2 - statement.ciphertext.c2,
        refreshed_ciphertext.c1 - statement.ciphertext.c1,
    };
}

} // namespace

PublicParameters setup(
    const pke::twisted_elgamal::PublicParameters& encryption_pp) {
    TAIHANG_ASSERT(encryption_pp.msg_len_bits > 0 &&
                       !encryption_pp.msg_size.is_zero() &&
                       arithmetic::is_pow2(encryption_pp.msg_len_bits),
                   "twisted-ElGamal range proof requires a positive, "
                   "power-of-two message width");

    return {
        encryption_pp,
        derive_bulletproof_parameters(encryption_pp),
    };
}

bool PlaintextKnowledgeProof::operator==(
    const PlaintextKnowledgeProof& other) const {
    return plaintext_knowledge == other.plaintext_knowledge &&
           range == other.range;
}

std::ostream& operator<<(std::ostream& os,
                         const PlaintextKnowledgeProof& proof) {
    return os << proof.plaintext_knowledge << proof.range;
}

std::istream& operator>>(std::istream& is,
                         PlaintextKnowledgeProof& proof) {
    return is >> proof.plaintext_knowledge >> proof.range;
}

bool SecretKeyKnowledgeProof::operator==(
    const SecretKeyKnowledgeProof& other) const {
    return refreshed_ciphertext == other.refreshed_ciphertext &&
           rerandomization == other.rerandomization &&
           plaintext_knowledge == other.plaintext_knowledge &&
           range == other.range;
}

std::ostream& operator<<(std::ostream& os,
                         const SecretKeyKnowledgeProof& proof) {
    return os << proof.refreshed_ciphertext
              << proof.rerandomization
              << proof.plaintext_knowledge
              << proof.range;
}

std::istream& operator>>(std::istream& is,
                         SecretKeyKnowledgeProof& proof) {
    return is >> proof.refreshed_ciphertext
              >> proof.rerandomization
              >> proof.plaintext_knowledge
              >> proof.range;
}

PlaintextKnowledgeProof prove(
    const PublicParameters& pp,
    const Statement& statement,
    const PlaintextKnowledgeWitness& witness,
    std::string_view context) {
    validate_interval(pp, statement.interval);

    const auto knowledge_pp =
        nizk::twisted_elgamal_plaintext_knowledge::setup(pp.encryption);
    const nizk::twisted_elgamal_plaintext_knowledge::Statement
        knowledge_statement =
            derive_plaintext_knowledge_statement(statement, statement.ciphertext);
    const nizk::twisted_elgamal_plaintext_knowledge::Witness
        knowledge_witness{
            witness.plaintext,
            witness.randomness,
        };

    PlaintextKnowledgeProof proof;
    proof.plaintext_knowledge =
        nizk::twisted_elgamal_plaintext_knowledge::prove(
            knowledge_pp, knowledge_statement, knowledge_witness, context);
    proof.range = bulletproof::prove(
        pp.range,
        derive_shifted_commitments(pp, statement.ciphertext, statement.interval),
        derive_shifted_witness(pp, statement.interval, witness.plaintext, witness.randomness),
        context);
    return proof;
}

bool verify(const PublicParameters& pp,
            const Statement& statement,
            const PlaintextKnowledgeProof& proof,
            std::string_view context) {
    validate_interval(pp, statement.interval);

    const auto knowledge_pp =
        nizk::twisted_elgamal_plaintext_knowledge::setup(pp.encryption);
    const bool plaintext_knowledge_valid =
        nizk::twisted_elgamal_plaintext_knowledge::verify(
            knowledge_pp,
            derive_plaintext_knowledge_statement(statement, statement.ciphertext),
            proof.plaintext_knowledge,
            context);
    const bool range_valid = bulletproof::verify(
        pp.range,
        derive_shifted_commitments(pp, statement.ciphertext, statement.interval),
        proof.range,
        context);
    return plaintext_knowledge_valid && range_valid;
}

SecretKeyKnowledgeProof prove(
    const PublicParameters& pp,
    const Statement& statement,
    const SecretKeyKnowledgeWitness& witness,
    const dlog::BSGSSolver& solver,
    std::string_view context) {
    validate_interval(pp, statement.interval);

    const ZnElement plaintext = pke::twisted_elgamal::decrypt_exp(
        pp.encryption,
        witness.secret_key,
        statement.ciphertext,
        solver);
    const ZnElement randomness = pp.encryption.ring_ctx->gen_random();
    pke::twisted_elgamal::Ciphertext refreshed_ciphertext =
        pke::twisted_elgamal::encrypt(pp.encryption,
                                      statement.public_key,
                                      plaintext,
                                      randomness);

    const nizk::dlog_equality::PublicParameters equality_pp =
        derive_dlog_equality_parameters(pp);
    const nizk::dlog_equality::Statement equality_statement =
        derive_ciphertext_link_statement(pp, statement, refreshed_ciphertext);
    const auto knowledge_pp =
        nizk::twisted_elgamal_plaintext_knowledge::setup(pp.encryption);
    const nizk::twisted_elgamal_plaintext_knowledge::Statement
        knowledge_statement =
            derive_plaintext_knowledge_statement(statement, refreshed_ciphertext);

    SecretKeyKnowledgeProof proof;
    proof.refreshed_ciphertext = std::move(refreshed_ciphertext);
    proof.rerandomization = nizk::dlog_equality::prove(
        equality_pp,
        equality_statement,
        {witness.secret_key.x},
        context);
    proof.plaintext_knowledge =
        nizk::twisted_elgamal_plaintext_knowledge::prove(
            knowledge_pp,
            knowledge_statement,
            {plaintext, randomness},
            context);
    proof.range = bulletproof::prove(
        pp.range,
        derive_shifted_commitments(pp, proof.refreshed_ciphertext, statement.interval),
        derive_shifted_witness(pp, statement.interval, plaintext, randomness),
        context);
    return proof;
}

bool verify(const PublicParameters& pp,
            const Statement& statement,
            const SecretKeyKnowledgeProof& proof,
            std::string_view context) {
    validate_interval(pp, statement.interval);

    const nizk::dlog_equality::PublicParameters equality_pp =
        derive_dlog_equality_parameters(pp);
    const bool ciphertext_link_valid = nizk::dlog_equality::verify(
        equality_pp,
        derive_ciphertext_link_statement(pp, statement, proof.refreshed_ciphertext),
        proof.rerandomization,
        context);

    const auto knowledge_pp =
        nizk::twisted_elgamal_plaintext_knowledge::setup(pp.encryption);
    const bool plaintext_knowledge_valid =
        nizk::twisted_elgamal_plaintext_knowledge::verify(
            knowledge_pp,
            derive_plaintext_knowledge_statement(statement, proof.refreshed_ciphertext),
            proof.plaintext_knowledge,
            context);

    const bool range_valid = bulletproof::verify(
        pp.range,
        derive_shifted_commitments(pp, proof.refreshed_ciphertext, statement.interval),
        proof.range,
        context);
    return ciphertext_link_valid &&
           plaintext_knowledge_valid &&
           range_valid;
}

} // namespace taihang::zkp::range_proofs::twisted_elgamal_range_proof
