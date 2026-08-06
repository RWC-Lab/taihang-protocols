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

struct PublicParameters {
    int curve_id;
    std::shared_ptr<ECGroup> group_ctx;
    std::shared_ptr<Zn> ring_ctx;
    ECPoint g;
    ECPoint h;
};

struct Statement {
    ECPoint pk;
    pke::twisted_elgamal::Ciphertext ct;
};

struct Witness {
    ZnElement v;
    ZnElement r;
};

struct Proof {
    ECPoint c1;
    ECPoint c2;
    ZnElement z1;
    ZnElement z2;

    bool operator==(const Proof& other) const;
    bool operator!=(const Proof& other) const { return !(*this == other); }

    friend std::ostream& operator<<(std::ostream& os, const Proof& proof);
    /** @note The caller must initialize point and scalar contexts before deserialization. */
    friend std::istream& operator>>(std::istream& is, Proof& proof);
};

/** @brief Derive proof parameters from an existing twisted-ElGamal setup. */
PublicParameters setup(const pke::twisted_elgamal::PublicParameters& encryption_pp);

Proof prove(const PublicParameters& pp,
            const Statement& statement,
            const Witness& witness,
            std::string_view context = {});

bool verify(const PublicParameters& pp,
            const Statement& statement,
            const Proof& proof,
            std::string_view context = {});

} // namespace taihang::zkp::nizk::twisted_elgamal_plaintext_knowledge

#endif // TAIHANG_PROTOCOLS_ZKP_SIGMA_TWISTED_ELGAMAL_PLAINTEXT_KNOWLEDGE_HPP
