/****************************************************************************
 * @file      cwprf_psi.hpp
 * @brief     Two-party Private Set Intersection (PSI) based on a weakly
 *            commutative PRF (cwPRF), built on Diffie-Hellman style
 *            "double masking" of the same group element by both parties.
 *
 * @details
 *   Protocol intuition
 *   -------------------
 *   Let F_k(m) = H(m)^k for a hash-to-curve function H and a secret scalar
 *   key k. F is a *weakly commutative* PRF in the sense that, for a fixed
 *   group element g = H(m):
 *
 *       F_k2(F_k1(g)) == F_k1(F_k2(g)) == g^{k1 * k2}
 *
 *   i.e. it does not matter in which order the two parties apply their
 *   private exponent — the final value is the same. This is exactly the
 *   classical two-round Diffie-Hellman PSI construction:
 *
 *       Sender (holds Y): F_k1(H(y_i))      for every y_i in Y
 *       Receiver (holds X): F_k2(H(x_i))      for every x_i in X
 *
 *   After one round of exchange, each party can locally finish the
 *   "double-masking" of the *other* party's elements:
 *
 *       Sender computes F_k1(F_k2(x_i)) = H(x_i)^{k1*k2}   for all x_i in X
 *       Receiver computes F_k2(F_k1(y_i)) = H(y_i)^{k1*k2}   for all y_i in Y
 *
 *   Because exponentiation is commutative, H(x_i)^{k1*k2} ==
 *   H(y_i)^{k1*k2} whenever x_i == y_i. The Receiver — who now holds both
 *   the doubly-masked X values (computed locally) and the doubly-masked Y
 *   values (received from the Sender) — can therefore recover the
 *   intersection by straightforward membership testing, **without ever
 *   learning anything about elements of Y \ X**, and without the Sender
 *   learning anything about X at all (semi-honest model).
 *
 *   Important asymmetry versus cwprf_mqrpmt
 *   ----------------------------------------
 *   Unlike taihang::mpc::cwprf_mqrpmt — which outputs an indication bit
 *   vector aligned with the *Receiver's* query set — this PSI protocol
 *   outputs the actual recovered intersection elements (as Blocks), and it
 *   is the **Receiver** that learns the result, mirroring Kunlun's original
 *   cwPRF_PSI design (Receiver computes the intersection; Sender learns
 *   nothing about the output).
 *
 *   Why Bloom Filters cannot be used here (unlike cwprf_mqrpmt)
 *   -------------------------------------------------------------
 *   cwprf_mqrpmt's final output is an opaque indication BIT per query
 *   element — a pure "is x_i a member of Y?" test, which a Bloom Filter
 *   answers perfectly, because the protocol never needs to recover *which*
 *   y_j caused a match.
 *
 *   PSI's final output, in contrast, is the actual intersecting ELEMENTS.
 *   To attribute a positive match back to a specific x_i, the Receiver must
 *   be able to test "is the i-th wire value a member of my local lookup
 *   set?" for each index i in turn — i.e. the transmitted structure must
 *   preserve per-index alignment with the Receiver's own set.
 *
 *   A Bloom Filter discards index information by construction (that is
 *   precisely the source of its O(n) space efficiency): it can answer
 *   "is this byte-string a member?" but never "which index inserted it?".
 *   Once Sender-side values are folded into a filter, the Receiver has no
 *   way to recover which of its own x_i produced a match. This is a
 *   structural limitation, not an implementation gap — it is the reason
 *   Kunlun's original cwPRF_PSI never offered a Bloom-Filter-backed mode,
 *   and why this Taihang port does not either.
 *
 *   Membership-test backends (MembershipMode)
 *   -------------------------------------------
 *   Two interchangeable, index-preserving strategies are provided for the
 *   final round, in which the Sender ships its doubly-masked X-side values
 *   F_k1k2(x_i) to the Receiver in an array indexed identically to vec_x:
 *
 *     Truncate    – Classical cwPRF-PSI optimization (see references
 *                   below). Only the first `truncate_byte_len` bytes of
 *                   each PRF output are exchanged and compared. This is
 *                   the bandwidth-optimal index-preserving choice and
 *                   matches Kunlun's original behaviour exactly: it
 *                   achieves a Bloom-Filter-like compression ratio while
 *                   still preserving the array ordering PSI requires for
 *                   element attribution.
 *     PlainSet    – Sends the full-length, UN-truncated set of doubly-
 *                   masked values, still index-aligned with vec_x. No
 *                   false positives at all (exact result). Highest
 *                   bandwidth cost; useful as a correctness baseline.
 *
 *   Curve backend (selected via PublicParameters::curve_id)
 *   -----------------------------------------------------------
 *   - curve_id == NID_X25519  → uses EC25519Point (Montgomery curve,
 *     OpenSSL EVP_PKEY X25519 backend). Fixed 32-byte point representation.
 *   - any other curve_id      → uses the general-purpose ECPoint /
 *     ECGroup machinery (e.g. Secp256r1), supporting both compressed and
 *     uncompressed point serialization via config::use_point_compression.
 *
 *   Security notes (carried over from Kunlun's original implementation)
 *   ----------------------------------------------------------------------
 *   For correctness, it suffices to truncate F's output length to
 *   lambda + log(n1) + log(n2) bits, where lambda is the statistical
 *   security parameter and n1, n2 are the two parties' set sizes
 *   (see [CRYPTO 2019 - Pinkas, Rosulek, Trieu, Yanai - SpOT: Lightweight
 *   PSI from Sparse OT Extension], the section on output truncation).
 *
 *   This truncation argument relies on F's output being (computationally)
 *   close to uniform over {0,1}^l. Raw group elements of a *sparse*
 *   encoding would *not* satisfy this directly; however, for curves such
 *   as Curve25519 the compressed coordinate (the raw 32-byte u-coordinate,
 *   or correspondingly the x-coordinate for short Weierstrass curves) is
 *   computationally indistinguishable from a uniform bit-string, by the
 *   randomness-extraction properties of Diffie-Hellman elements
 *   (see [EUROCRYPT 2009 - Optimal Randomness Extraction from a
 *   Diffie-Hellman Element]). Hence truncating the serialized point
 *   directly — rather than first hashing it through a CRHF — is sound for
 *   both curve backends supported here.
 *
 * @author    This file is part of Taihang, developed by Yu Chen.
 *****************************************************************************/

#ifndef TAIHANG_PROTOCOLS_CWPRF_PSI_HPP
#define TAIHANG_PROTOCOLS_CWPRF_PSI_HPP

#include <taihang/common/config.hpp>
#include <taihang/common/check.hpp>
#include <taihang/crypto/block.hpp>
#include <taihang/crypto/ec_group.hpp>
#include <taihang/crypto/ec25519_point.hpp>
#include <taihang/net/net_io.hpp>
#include <vector>
#include <string>
#include <iostream>
#include <optional>

namespace taihang::mpc::cwprf_psi {

/**
 * @enum MembershipMode
 * @brief Selects the index-preserving transmission strategy used in the
 *        final round, where the Sender ships its doubly-masked X-side
 *        values F_k1k2(x_i) — indexed identically to the Receiver's own
 *        vec_x — so the Receiver can both test membership AND attribute a
 *        match back to a specific x_i.
 *
 *        Note: unlike taihang::mpc::cwprf_mqrpmt, PSI does NOT offer a
 *        Bloom Filter mode. See the "Why Bloom Filters cannot be used
 *        here" section in this file's header comment for the structural
 *        reason: a Bloom Filter discards index information, which PSI's
 *        element-attribution requirement cannot tolerate.
 *
 *  Truncate – Only the first `truncate_byte_len` bytes of each doubly-
 *             masked value are sent and compared (Kunlun-style
 *             optimization). Bandwidth-optimal among the index-preserving
 *             options; small, tunable false-positive rate governed by
 *             statistical_security_parameter and the two set sizes (see
 *             file-level documentation above).
 *
 *  PlainSet – The full-length set of doubly-masked values is sent, still
 *             index-aligned with vec_x. No false positives.
 *             statistical_security_parameter is ignored in this mode.
 */
enum class MembershipMode {
    Truncate,
    PlainSet
};

/**
 * @struct PublicParameters
 * @brief Parameters shared by both Sender and Receiver.
 *
 * @note  When curve_id == NID_X25519, group_ctx and field_ctx are left as
 *        nullptr: EC25519Point arithmetic does not require an ECGroup
 *        context, and its scalars are raw 32-byte CSPRNG outputs rather
 *        than Zn field elements. Code paths must check pp.curve_id before
 *        dereferencing group_ctx / field_ctx, mirroring the convention
 *        already established in taihang::mpc::cwprf_mqrpmt.
 */
struct PublicParameters {
    int curve_id;
    std::shared_ptr<ECGroup> group_ctx;   // nullptr when curve_id == NID_X25519
    std::shared_ptr<Zn>      field_ctx;   // nullptr when curve_id == NID_X25519

    size_t log_sender_len = 0;            // log2(|Y|), Sender's set size
    size_t log_receiver_len = 0;            // log2(|X|), Receiver's set size

    MembershipMode membership_mode = MembershipMode::Truncate;

    // Meaningful only when membership_mode == Truncate.
    size_t statistical_security_parameter = 40;   // default lambda = 40

    // Meaningful only when membership_mode == Truncate.
    // Computed by setup() as ceil((ssp + log_sender_len + log_receiver_len) / 8),
    // following [CRYPTO 2019 SpOT] Section 4.2's truncation argument.
    size_t truncate_byte_len = 0;

    std::string format() const;

    // Stream serialization operators matching Taihang's style.
    friend std::ostream& operator<<(std::ostream& os, const PublicParameters& pp);
    friend std::istream& operator>>(std::istream& is,       PublicParameters& pp);
};

/**
 * @brief Constructs a fully-initialised PublicParameters object.
 *
 * @param curve_id          OpenSSL NID identifying the elliptic curve.
 *                           Pass NID_X25519 to select the X25519 backend.
 * @param log_sender_len     log2 of the Sender's set size |Y|.
 * @param log_receiver_len     log2 of the Receiver's set size |X|.
 * @param mode               MembershipMode::Truncate (default) or
 *                           MembershipMode::PlainSet.
 * @param statistical_security_param  Statistical security parameter,
 *                           lambda. Used as the truncation-length input
 *                           in Truncate mode. Required when mode is
 *                           Truncate; ignored for PlainSet.
 */
PublicParameters setup(int    curve_id,
                       size_t log_sender_len,
                       size_t log_receiver_len,
                       MembershipMode mode = MembershipMode::Truncate,
                       std::optional<size_t> statistical_security_param = std::nullopt);

/**
 * @brief Sender execution of the cwPRF-based PSI protocol.
 *
 * @details The Sender contributes its set Y, applies its private key k1 to
 *          obtain F_k1(H(y_i)), and ships those values to the Receiver. After
 *          receiving the Receiver's blinded set F_k2(H(x_i)), it applies k1
 *          again to obtain the doubly-masked values F_k1(F_k2(x_i)), and
 *          transmits them — index-aligned with the Receiver's own vec_x, via
 *          the selected MembershipMode — so the Receiver can locally compute
 *          the intersection.
 *
 *          The Sender learns nothing about the Receiver's input set X, and
 *          the protocol's output (the intersection) is delivered only to
 *          the Receiver — the Sender's call returns void.
 *
 * @param io    Reference to the network transmission pipeline.
 * @param pp    Protocol public parameters (must match the Receiver's pp).
 * @param vec_y Sender's dataset, packed as 128-bit Blocks. Must have
 *              exactly 2^pp.log_sender_len elements.
 */
void sender(net::NetIO& io, const PublicParameters& pp, const std::vector<Block>& vec_y);

/**
 * @brief Receiver-side execution of the cwPRF-based PSI protocol.
 *
 * @details The Receiver contributes its set X, applies its private key k2 to
 *          obtain F_k2(H(x_i)), exchanges blinded values with the Sender,
 *          and finally locally computes F_k2(F_k1(y_i)) for every y_i,
 *          forming the lookup set against which the Sender's index-aligned
 *          doubly-masked X values are tested. Elements of X whose doubly-
 *          masked image is found in that lookup set are output as the
 *          recovered intersection.
 *
 * @param io    Reference to the network transmission pipeline.
 * @param pp    Protocol public parameters (must match the Sender's pp).
 * @param vec_x Receiver's dataset, packed as 128-bit Blocks. Must have
 *              exactly 2^pp.log_receiver_len elements.
 * @return      The recovered intersection X ∩ Y, as a subset of vec_x
 *              (original Block values, not PRF images). In Truncate mode
 *              the false-positive probability is bounded by the
 *              truncation-length argument described in the file-level
 *              documentation; in PlainSet mode the result is exact.
 */
std::vector<Block> receiver(net::NetIO& io, const PublicParameters& pp, const std::vector<Block>& vec_x);

} // namespace taihang::mpc::cwprf_psi

#endif // TAIHANG_PROTOCOLS_CWPRF_PSI_HPP
