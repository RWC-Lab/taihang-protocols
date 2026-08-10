/****************************************************************************
 * @file      bullet_proof.hpp
 * @brief     Aggregated logarithmic-size Bulletproof range argument.
 *
 * This is the aggregated logarithmic-size range argument from the
 * Bulletproofs paper. For commitments
 *
 *   C_i = g*r_i + h*v_i,
 *
 * the proof establishes v_i in [0, 2^range_bits) for every i while using one
 * shared inner-product argument. Values are encoded little-endian, so the
 * Boolean constraint is expressed by aR = aL - 1^n. The polynomial identity
 * t(X) = <l(X), r(X)> then reduces all bit constraints to the two points T1,
 * T2 and one scalar evaluation t = t(x).
 *
 * The protocol proceeds in five stages:
 *
 *  1. A commits to the bit vectors aL and aR.
 *  2. S commits to independent masking vectors sL and sR.
 *  3. Fiat-Shamir challenges y and z define l(X), r(X), and t(X).
 *  4. T1 and T2 commit to the nonconstant coefficients of t(X), after which
 *     challenge x fixes the evaluation t = t(x).
 *  5. A logarithmic inner-product argument proves the opening of l(x), r(x).
 *
 * Verification batches the polynomial identity and final inner-product
 * identity into one MSM after all Fiat-Shamir messages have been fixed.
 *****************************************************************************/

#ifndef TAIHANG_PROTOCOLS_ZKP_RANGE_PROOFS_BULLET_PROOF_HPP
#define TAIHANG_PROTOCOLS_ZKP_RANGE_PROOFS_BULLET_PROOF_HPP

#include <iosfwd>
#include <memory>
#include <string_view>
#include <vector>

#include <taihang/crypto/ec_group.hpp>
#include <taihang/crypto/zn.hpp>
#include <taihang/zkp/range_proofs/inner_product_proof.hpp>

namespace taihang::zkp::range_proofs::bulletproof {

/**
 * @brief Generator basis and contexts for aggregated range proofs.
 *
 * `max_aggregation` and `range_bits` are powers of two, which guarantees that
 * every supported aggregation has a power-of-two inner-product length. The
 * vector generators are deterministic and curve-bound; no mutable global
 * setup state is required. P-256 generator derivation uses RFC 9380 SSWU.
 */
struct PublicParameters {
    /// OpenSSL curve identifier.
    int curve_id;

    /// Each value is proved to lie in [0, 2^range_bits).
    std::size_t range_bits;

    /// Maximum number of values supported by this generator basis.
    std::size_t max_aggregation;

    /// Total generator capacity: range_bits * max_aggregation.
    std::size_t vector_length;

    /// Shared elliptic-curve context.
    std::shared_ptr<ECGroup> group_ctx;

    /// Scalar field modulo the group order.
    std::shared_ptr<Zn> ring_ctx;

    /// Blinding base in C_i = g*r_i + h*v_i.
    ECPoint g;

    /// Value base in the commitment equation.
    ECPoint h;

    /// Base used by the embedded inner-product argument.
    ECPoint u;

    /// Generator basis for aL and l(x).
    std::vector<ECPoint> vector_g;

    /// Generator basis for aR and r(x).
    std::vector<ECPoint> vector_h;
};

/**
 * @brief Commitment statement C_i = g*r_i + h*v_i.
 *
 * The caller is responsible for constructing commitments with the same g, h,
 * group context, and scalar ring carried by PublicParameters.
 */
struct Statement {
    std::vector<ECPoint> commitments;
};

/**
 * @brief Values and blinding factors opening the commitment statement.
 *
 * `randomness` and `values` have one entry per commitment. The prover checks
 * only the vector lengths needed to execute the protocol; semantic validity
 * of the caller's contexts remains the caller's responsibility, consistent
 * with the rest of Taihang-Protocols.
 */
struct Witness {
    std::vector<ZnElement> randomness;
    std::vector<ZnElement> values;
};

/**
 * @brief Aggregated Bulletproof proof.
 *
 * A and S commit to the left/right bit vectors and their masks. T1 and T2
 * commit to the nonconstant polynomial coefficients. `taux`, `mu`, and `t`
 * are the scalar responses, and `inner_product` proves the final vector
 * opening with logarithmic communication.
 */
struct Proof {
    /// Commitment A to the bit vectors.
    ECPoint a;

    /// Commitment S to the masking vectors.
    ECPoint s;

    /// Commitment T1 to t(X)'s linear coefficient.
    ECPoint t1;

    /// Commitment T2 to t(X)'s quadratic coefficient.
    ECPoint t2;

    /// Blinding response for the original value commitments.
    ZnElement taux;

    /// Combined blinding response for A and S.
    ZnElement mu;

    /// Evaluation t(x) = <l(x), r(x)>.
    ZnElement t;

    /// Logarithmic proof opening l(x) and r(x).
    inner_product::Proof inner_product;

    bool operator==(const Proof& other) const;
    bool operator!=(const Proof& other) const { return !(*this == other); }

    friend std::ostream& operator<<(std::ostream& os, const Proof& proof);
    /** @note The caller must initialize all point and scalar contexts first. */
    friend std::istream& operator>>(std::istream& is, Proof& proof);
};

/**
 * @brief Create deterministic, curve-bound Bulletproof generators.
 * @param curve_id OpenSSL curve identifier.
 * @param range_bits Number of bits in each committed range.
 * @param max_aggregation Maximum number of values supported by the setup.
 */
PublicParameters setup(int curve_id,
                       std::size_t range_bits,
                       std::size_t max_aggregation);

/**
 * @brief Prove that all committed values are in the configured range.
 *
 * The bit vectors are committed first (A and S), then the polynomial
 * coefficients are committed (T1 and T2). The final vector opening is reduced
 * to the inner-product proof included in Proof::inner_product.
 */
Proof prove(const PublicParameters& pp,
            const Statement& statement,
            const Witness& witness,
            std::string_view context = {});

/**
 * @brief Verify an aggregated Bulletproof range argument.
 *
 * Verification reconstructs y, z, x, and e from the statement and proof,
 * checks the outer polynomial relation, and checks the folded inner-product
 * relation. The two equations are combined with a nonzero Fiat-Shamir-derived
 * batching scalar and evaluated by one MSM. The caller supplies the same
 * optional associated context used during proving.
 */
bool verify(const PublicParameters& pp,
            const Statement& statement,
            const Proof& proof,
            std::string_view context = {});

} // namespace taihang::zkp::range_proofs::bulletproof

#endif // TAIHANG_PROTOCOLS_ZKP_RANGE_PROOFS_BULLET_PROOF_HPP
