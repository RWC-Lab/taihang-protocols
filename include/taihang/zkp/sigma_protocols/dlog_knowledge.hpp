/****************************************************************************
 * @file      dlog_knowledge.hpp
 * @brief     Non-interactive Schnorr proof of discrete-log knowledge.
 * @author    This file is part of Taihang-Protocols, developed by Yu Chen.
 *****************************************************************************/

#ifndef TAIHANG_PROTOCOLS_ZKP_SIGMA_DLOG_KNOWLEDGE_HPP
#define TAIHANG_PROTOCOLS_ZKP_SIGMA_DLOG_KNOWLEDGE_HPP

#include <iosfwd>
#include <memory>
#include <string_view>

#include <taihang/crypto/ec_group.hpp>
#include <taihang/crypto/zn.hpp>

namespace taihang::zkp::nizk::dlog_knowledge {

/** @brief Public parameters describing the group and its scalar ring. */
struct PublicParameters {
    int curve_id;
    std::shared_ptr<ECGroup> group_ctx;
    std::shared_ptr<Zn> ring_ctx;
};

/** @brief Public relation: h = g^w. */
struct Statement {
    ECPoint g;
    ECPoint h;
};

struct Witness {
    ZnElement w; // discrete logarithm
};

struct Proof {
    ECPoint c;   // commitment
    ZnElement z; // response

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
 * @brief Prove knowledge of the discrete logarithm in @p statement.
 * @param context Optional associated data that must also be supplied to verify().
 * @note The caller must provide compatible parameter, statement, and witness contexts.
 */
Proof prove(const PublicParameters& pp,
            const Statement& statement,
            const Witness& witness,
            std::string_view context = {});

/**
 * @brief Verify a discrete-log knowledge proof.
 * @param context Associated data used by the prover.
 * @note The caller must provide compatible parameter, statement, and proof contexts.
 */
bool verify(const PublicParameters& pp,
            const Statement& statement,
            const Proof& proof,
            std::string_view context = {});

} // namespace taihang::zkp::nizk::dlog_knowledge

#endif // TAIHANG_PROTOCOLS_ZKP_SIGMA_DLOG_KNOWLEDGE_HPP
