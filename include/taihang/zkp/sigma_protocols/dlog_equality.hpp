/****************************************************************************
 * @file      dlog_equality.hpp
 * @brief     Non-interactive Chaum-Pedersen proof of discrete-log equality.
 * @author    This file is part of Taihang-Protocols, developed by Yu Chen.
 *****************************************************************************/

#ifndef TAIHANG_PROTOCOLS_ZKP_SIGMA_DLOG_EQUALITY_HPP
#define TAIHANG_PROTOCOLS_ZKP_SIGMA_DLOG_EQUALITY_HPP

#include <iosfwd>
#include <memory>
#include <string_view>

#include <taihang/crypto/ec_group.hpp>
#include <taihang/crypto/zn.hpp>

namespace taihang::zkp::nizk::dlog_equality {

/** @brief Public parameters describing the group and its scalar ring. */
struct PublicParameters {
    int curve_id;
    std::shared_ptr<ECGroup> group_ctx;
    std::shared_ptr<Zn> ring_ctx;
};

/** @brief Public relation: h1 = g1^exponent and h2 = g2^exponent. */
struct Statement {
    ECPoint g1;
    ECPoint h1;
    ECPoint g2;
    ECPoint h2;
};

struct Witness {
    ZnElement w; // exponent
};

struct Proof {
    ECPoint c1;  // first commitment
    ECPoint c2;  // second commitment
    ZnElement z; // response;

    bool operator==(const Proof& other) const;
    bool operator!=(const Proof& other) const { return !(*this == other); }

    /**
     * @brief Serialize a proof using fixed-width point and scalar encodings.
     * @note The caller must initialize the point and scalar contexts before deserialization.
     */
    friend std::ostream& operator<<(std::ostream& os, const Proof& proof);
    friend std::istream& operator>>(std::istream& is, Proof& proof);
};

/** @brief Initialize the group and scalar ring. */
PublicParameters setup(int curve_id);

/**
 * @brief Prove knowledge of the common exponent in @p statement.
 * @param context Optional associated data that must also be supplied to verify().
 * @note The caller must provide compatible parameter, statement, and witness contexts.
 */
Proof prove(const PublicParameters& pp,
            const Statement& statement,
            const Witness& witness,
            std::string_view context = {});

/**
 * @brief Verify a proof, returning false when either verification equation fails.
 * @param context Associated data used by the prover.
 * @note The caller must provide compatible parameter, statement, and proof contexts.
 */
bool verify(const PublicParameters& pp,
            const Statement& statement,
            const Proof& proof,
            std::string_view context = {});

} // namespace taihang::zkp::nizk::dlog_equality

#endif // TAIHANG_PROTOCOLS_ZKP_SIGMA_DLOG_EQUALITY_HPP
