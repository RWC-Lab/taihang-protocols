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

struct PublicParameters {
    int curve_id;
    std::shared_ptr<ECGroup> group_ctx;
    std::shared_ptr<Zn> ring_ctx;
    ECPoint g;
    ECPoint h;
};

struct Statement {
    std::vector<ECPoint> vec_pk;
    pke::twisted_elgamal::MrCiphertext ct;
};

struct Witness {
    ZnElement v;
    ZnElement r;
};

struct Proof {
    std::vector<ECPoint> vec_c1;
    ECPoint c2;
    ZnElement z;
    ZnElement t;

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

} // namespace taihang::zkp::nizk::twisted_elgamal_plaintext_equality

#endif // TAIHANG_PROTOCOLS_ZKP_SIGMA_TWISTED_ELGAMAL_PLAINTEXT_EQUALITY_HPP
