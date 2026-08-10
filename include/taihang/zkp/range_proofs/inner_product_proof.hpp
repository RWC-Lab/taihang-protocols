/****************************************************************************
 * @file      inner_product_proof.hpp
 * @brief     Logarithmic-size Bulletproof inner-product argument.
 *
 * This is Protocol 2 from the Bulletproofs paper. The relation proved is
 *
 *   P = sum_i (g_i * a_i + h_i * b_i) + u * <a, b>,
 *
 * where the vectors have power-of-two length. The prover repeatedly folds
 * both witness and generator vectors in half. Each round publishes two cross
 * commitments L and R, so a length-n witness is reduced to two final scalars
 * with only 2*log2(n) group elements in the proof.
 *
 * At round j, the prover computes
 *
 *   L_j = sum_i (g_R,i * a_L,i + h_L,i * b_R,i)
 *         + u * <a_L, b_R>,
 *   R_j = sum_i (g_L,i * a_R,i + h_R,i * b_L,i)
 *         + u * <a_R, b_L>.
 *
 * The Fiat-Shamir challenge x_j folds each pair of halves. The verifier does
 * not replay those folds. It reconstructs all challenges, derives the paper's
 * s-vector in linear time, and checks the final relation with two MSMs.
 *****************************************************************************/

#ifndef TAIHANG_PROTOCOLS_ZKP_RANGE_PROOFS_INNER_PRODUCT_PROOF_HPP
#define TAIHANG_PROTOCOLS_ZKP_RANGE_PROOFS_INNER_PRODUCT_PROOF_HPP

#include <iosfwd>
#include <memory>
#include <string_view>
#include <vector>

#include <taihang/crypto/ec_group.hpp>
#include <taihang/crypto/zn.hpp>

namespace taihang::zkp::range_proofs::inner_product {

/**
 * @brief Generator basis and arithmetic contexts for the relation.
 *
 * Unlike Kunlun's process-global curve/order state, each parameter object owns
 * the contexts required by its points and scalars. Generator vectors are
 * derived deterministically during setup and may therefore be reproduced by
 * independent parties from the same curve and vector length.
 */
struct PublicParameters {
    /// OpenSSL curve identifier.
    int curve_id;

    /// Number of entries in a and b; always a power of two.
    std::size_t vector_length;

    /// Number of L/R folding rounds, equal to log2(vector_length).
    std::size_t rounds;

    /// Shared elliptic-curve context.
    std::shared_ptr<ECGroup> group_ctx;

    /// Scalar field modulo the group order.
    std::shared_ptr<Zn> ring_ctx;

    /// Generator basis for witness vector a.
    std::vector<ECPoint> g;

    /// Generator basis for witness vector b.
    std::vector<ECPoint> h;

    /// Generator carrying the scalar inner product <a,b>.
    ECPoint u;
};

/**
 * @brief Public relation P = sum(g_i*a_i + h_i*b_i) + u*<a,b>.
 *
 * The point P is also included in the Fiat-Shamir input before the first
 * folding round, so a proof cannot be replayed for another statement.
 */
struct Statement {
    ECPoint p; ///< Public group element in the inner-product relation.
};

/**
 * @brief Secret vectors a and b.
 *
 * Both vectors contain exactly PublicParameters::vector_length scalars. Their
 * modular inner product is committed under PublicParameters::u.
 */
struct Witness {
    std::vector<ZnElement> a;
    std::vector<ZnElement> b;
};

/**
 * @brief Logarithmic inner-product proof.
 *
 * For a vector of length n, left and right each contain log2(n) points. The
 * final a and b are the two scalars remaining after all recursive folds.
 */
struct Proof {
    /// L commitments, one for each folding round.
    std::vector<ECPoint> left;

    /// R commitments, one for each folding round.
    std::vector<ECPoint> right;

    /// Final folded scalar a.
    ZnElement a;

    /// Final folded scalar b.
    ZnElement b;

    bool operator==(const Proof& other) const;
    bool operator!=(const Proof& other) const { return !(*this == other); }

    friend std::ostream& operator<<(std::ostream& os, const Proof& proof);
    /** @note The caller must initialize a, b, and the point contexts first. */
    friend std::istream& operator>>(std::istream& is, Proof& proof);
};

/**
 * @brief Create deterministic, curve-bound generators for a vector length.
 *
 * The original Kunlun setup sampled generator vectors globally. Taihang binds
 * them to the selected curve and fixed labels so independent processes derive
 * the same public parameters without sharing mutable global state. P-256 uses
 * the RFC 9380 SSWU suite; other curves retain Taihang's deterministic fallback
 * until their RFC suites are available.
 */
PublicParameters setup(int curve_id, std::size_t vector_length);

/**
 * @brief Prove the logarithmic inner-product relation.
 *
 * Every round splits the vectors into left/right halves and computes
 *
 *   L = g_R*a_L + h_L*b_R + u*<a_L,b_R>,
 *   R = g_L*a_R + h_R*b_L + u*<a_R,b_L>.
 *
 * Hashing L and R gives x. The vectors are then folded with x and x^-1 while
 * preserving the public relation. The optional context binds application data
 * or a parent protocol transcript without exposing a transcript abstraction.
 */
Proof prove(const PublicParameters& pp,
            const Statement& statement,
            const Witness& witness,
            std::string_view context = {});

/**
 * @brief Verify the logarithmic inner-product relation.
 *
 * The verifier reconstructs every x challenge, computes the paper's s-vector
 * in O(n) time, and checks the final group equation using optimized MSM. This
 * is the fast verifier from pages 15-17 rather than replaying every fold.
 */
bool verify(const PublicParameters& pp,
            const Statement& statement,
            const Proof& proof,
            std::string_view context = {});

namespace detail {

/**
 * @brief Prove an inner-product relation embedded in a parent protocol.
 *
 * The parent context must bind every public value that determines the derived
 * inner-product statement. Unlike the standalone API, this composition hook
 * does not append a separately materialized Statement::p. It allows a parent
 * verifier to fuse the derived statement into its final MSM.
 *
 * `h_factors[i]` represents the factor in H'_i = H_i*h_factors[i]. The
 * factors are absorbed into the first folding MSM rather than applied by
 * constructing a second generator vector. `u_factor` similarly represents
 * the factor in u' = u*u_factor and is absorbed into every cross-term scalar.
 *
 * This function is an implementation detail for composed proof systems. Use
 * the standalone prove() API when the inner-product statement is independent.
 */
Proof prove_embedded(const PublicParameters& pp,
                     const Witness& witness,
                     const std::vector<ZnElement>& h_factors,
                     const ZnElement& u_factor,
                     std::string_view parent_context);

} // namespace detail

} // namespace taihang::zkp::range_proofs::inner_product

#endif // TAIHANG_PROTOCOLS_ZKP_RANGE_PROOFS_INNER_PRODUCT_PROOF_HPP
