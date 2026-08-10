/****************************************************************************
 * @file      twisted_elgamal_plaintext_knowledge.cpp
 * @brief     NIZK proof of twisted-ElGamal plaintext/randomness knowledge.
 *****************************************************************************/

#include <taihang/zkp/sigma_protocols/twisted_elgamal_plaintext_knowledge.hpp>

#include <istream>
#include <ios>
#include <ostream>
#include <sstream>
#include <utility>

namespace taihang::zkp::nizk::twisted_elgamal_plaintext_knowledge {

PublicParameters setup(const pke::twisted_elgamal::PublicParameters& encryption_pp) {
    // The proof relation uses the same bases and contexts as exponential
    // twisted ElGamal; retaining the shared pointers also keeps point
    // arithmetic context-compatible with the supplied ciphertext.
    return {encryption_pp.curve_id,
            encryption_pp.group_ctx,
            encryption_pp.ring_ctx,
            encryption_pp.g,
            encryption_pp.h};
}

bool Proof::operator==(const Proof& other) const {
    return c1 == other.c1 && c2 == other.c2 && z1 == other.z1 && z2 == other.z2;
}

std::ostream& operator<<(std::ostream& os, const Proof& proof) {
    // ECPoint and ZnElement already use fixed-width binary encodings.
    return os << proof.c1 << proof.c2 << proof.z1 << proof.z2;
}

std::istream& operator>>(std::istream& is, Proof& proof) {
    is >> proof.c1 >> proof.c2 >> proof.z1 >> proof.z2;
    return is;
}

Proof prove(const PublicParameters& pp,
            const Statement& statement,
            const Witness& witness,
            std::string_view context) {
    // First Sigma-protocol round: hide the witness with fresh a,b.
    const ZnElement a = pp.ring_ctx->gen_random();
    const ZnElement b = pp.ring_ctx->gen_random();
    ECPoint c1 = statement.pk * a;                         // c1 = pk * a
    ECPoint c2 = ec_point_msm({pp.g, pp.h}, {a, b});       // c2 = g * a + h * b

    // Fiat-Shamir transform: the statement and first-round commitments are
    // hashed together, with optional associated data supplied by the caller.
    std::ostringstream transcript;
    transcript.write(context.data(), static_cast<std::streamsize>(context.size()));
    transcript << statement.pk << statement.ct.c1 << statement.ct.c2 << c1 << c2;
    const ZnElement e = hash_to_zn(transcript.str(), *pp.ring_ctx);

    // Responses reconstruct the commitments when the verifier combines them
    // with the public ciphertext and the challenge.
    return {std::move(c1), std::move(c2), a + e * witness.r, b + e * witness.v};
}

bool verify(const PublicParameters& pp,
            const Statement& statement,
            const Proof& proof,
            std::string_view context) {
    // Recompute exactly the challenge used by the prover from the public
    // statement and the proof commitments.
    std::ostringstream transcript;
    transcript.write(context.data(), static_cast<std::streamsize>(context.size()));
    transcript << statement.pk << statement.ct.c1 << statement.ct.c2 << proof.c1 << proof.c2;
    const ZnElement e = hash_to_zn(transcript.str(), *pp.ring_ctx);

    // The first equation checks knowledge of the encryption randomness r.
    const bool first = statement.pk * proof.z1 == proof.c1 + statement.ct.c1 * e;

    // The second equation checks the linked pair (r, v) in the common
    // exponential-ElGamal component.
    const ECPoint left = ec_point_msm({pp.g, pp.h}, {proof.z1, proof.z2});
    const ECPoint right = proof.c2 + statement.ct.c2 * e;
    return first && left == right;
}

} // namespace taihang::zkp::nizk::twisted_elgamal_plaintext_knowledge
