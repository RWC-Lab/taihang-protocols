/****************************************************************************
 * @file      bullet_proof.cpp
 * @brief     Aggregated logarithmic-size Bulletproof range argument.
 *****************************************************************************/

#include <taihang/zkp/range_proofs/bullet_proof.hpp>

#include <openssl/bn.h>
#include <openssl/obj_mac.h>

#include <algorithm>
#include <bit>
#include <istream>
#include <ostream>
#include <sstream>
#include <utility>

#include <taihang/common/check.hpp>
#include <taihang/utility/arithmetic.hpp>

namespace taihang::zkp::range_proofs::bulletproof {
namespace {

using taihang::arithmetic::is_pow2;
using ScalarVector = std::vector<ZnElement>;

ECPoint derive_generator(const std::string& label, const ECGroup& group) {
    static const std::string kP256Dst =
        "TAIHANG-PROTOCOLS-V01-P256_XMD:SHA-256_SSWU_RO_";

    if (group.curve_id == NID_X9_62_prime256v1) {
        return hash_to_curve_standard(label, kP256Dst, group);
    }
    return hash_to_curve_fast(label, group);
}

/** Generate (1, base, base^2, ..., base^(length-1)). */
ScalarVector powers(std::size_t length, const ZnElement& base) {
    ScalarVector result(length, base.ring_ctx->get_one());
    for (std::size_t i = 1; i < length; ++i) {
        result[i] = result[i - 1] * base;
    }
    return result;
}

ScalarVector add_vectors(const ScalarVector& a, const ScalarVector& b) {
    TAIHANG_ASSERT(a.size() == b.size(),
                   "range-proof vector size mismatch");

    ScalarVector result(a.size(), a.front().ring_ctx->get_zero());
    for (std::size_t i = 0; i < a.size(); ++i) {
        result[i] = a[i] + b[i];
    }
    return result;
}

ScalarVector scalar_vector(const ScalarVector& input,
                           const ZnElement& scalar) {
    ScalarVector result(input.size(), scalar.ring_ctx->get_zero());
    for (std::size_t i = 0; i < input.size(); ++i) {
        result[i] = input[i] * scalar;
    }
    return result;
}

ZnElement inner_product(const ScalarVector& a, const ScalarVector& b) {
    TAIHANG_ASSERT(a.size() == b.size(),
                   "range-proof inner-product size mismatch");
    TAIHANG_ASSERT(!a.empty(), "range-proof vector cannot be empty");

    ZnElement result = a.front().ring_ctx->get_zero();
    for (std::size_t i = 0; i < a.size(); ++i) {
        result += a[i] * b[i];
    }
    return result;
}

/** Encode a scalar as a little-endian vector of zero/one field elements. */
ScalarVector bit_vector(const ZnElement& value, std::size_t bit_count) {
    const Zn* ring = value.ring_ctx;
    const ZnElement zero = ring->get_zero();
    const ZnElement one = ring->get_one();
    ScalarVector result(bit_count, zero);

    for (std::size_t bit = 0; bit < bit_count; ++bit) {
        result[bit] = BN_is_bit_set(value.value.bn_ptr,
                                    static_cast<int>(bit))
                          ? one
                          : zero;
    }
    return result;
}

/** Number of folding rounds for a power-of-two vector length. */
std::size_t folding_rounds(std::size_t vector_length) {
    std::size_t rounds = 0;
    for (std::size_t n = vector_length; n > 1; n /= 2) {
        ++rounds;
    }
    return rounds;
}

/**
 * Compute the inner-product verifier's s-vector in O(n).
 *
 * This is the optimized recurrence from page 15. Starting with
 * s_0 = product_j x_j^-1, each subsequent binary index differs from an
 * already-computed predecessor by one x_j^2 factor.
 */
ScalarVector compute_s(const ScalarVector& x_square,
                       const ScalarVector& x_inverse,
                       const Zn* ring,
                       std::size_t vector_length) {
    ScalarVector s(vector_length, ring->get_one());

    for (const ZnElement& inverse : x_inverse) {
        s[0] *= inverse;
    }

    for (std::size_t i = 1; i < vector_length; ++i) {
        const std::size_t highest_bit = std::bit_width(i) - 1;

        const std::size_t predecessor =
            i - (std::size_t{1} << highest_bit);
        const std::size_t challenge_index =
            x_square.size() - 1 - highest_bit;
        s[i] = s[predecessor] * x_square[challenge_index];
    }

    return s;
}

/** Invert nonzero scalars with one field inversion. */
ScalarVector batch_invert(const ScalarVector& input, const Zn* ring) {
    if (input.empty()) {
        return {};
    }

    ScalarVector prefix(input.size(), ring->get_one());
    ZnElement product = ring->get_one();
    for (std::size_t i = 0; i < input.size(); ++i) {
        prefix[i] = product;
        product *= input[i];
    }

    ZnElement product_inverse = product.inv();
    ScalarVector result(input.size(), ring->get_zero());
    for (std::size_t i = input.size(); i-- > 0;) {
        result[i] = product_inverse * prefix[i];
        product_inverse *= input[i];
    }
    return result;
}

/** Build the generator basis used by the embedded inner-product argument. */
inner_product::PublicParameters make_inner_product_parameters(
    const PublicParameters& pp,
    std::size_t vector_length) {
    inner_product::PublicParameters ip_pp;
    ip_pp.curve_id = pp.curve_id;
    ip_pp.vector_length = vector_length;
    ip_pp.rounds = folding_rounds(vector_length);
    ip_pp.group_ctx = pp.group_ctx;
    ip_pp.ring_ctx = pp.ring_ctx;
    ip_pp.g.assign(pp.vector_g.begin(),
                   pp.vector_g.begin() + vector_length);
    ip_pp.h.assign(pp.vector_h.begin(),
                   pp.vector_h.begin() + vector_length);

    // The embedded prover receives the y^-i and e factors separately. It
    // absorbs them into MSM scalars instead of materializing h'_i and u'.
    ip_pp.u = pp.u;
    return ip_pp;
}

} // namespace

PublicParameters setup(int curve_id,
                       std::size_t range_bits,
                       std::size_t max_aggregation) {
    TAIHANG_ASSERT(range_bits > 0 && is_pow2(range_bits),
                   "range bit length must be a positive power of two");
    TAIHANG_ASSERT(max_aggregation > 0 && is_pow2(max_aggregation),
                   "maximum aggregation must be a positive power of two");

    PublicParameters pp;
    pp.curve_id = curve_id;
    pp.range_bits = range_bits;
    pp.max_aggregation = max_aggregation;
    pp.vector_length = range_bits * max_aggregation;
    pp.group_ctx = std::make_shared<ECGroup>(curve_id);
    pp.ring_ctx = std::make_shared<Zn>(pp.group_ctx->order);
    pp.g = pp.group_ctx->get_generator();
    pp.h = derive_generator("taihang/bulletproof/base-h", *pp.group_ctx);
    pp.u = derive_generator("taihang/bulletproof/base-u", *pp.group_ctx);
    pp.vector_g =
        std::vector<ECPoint>(pp.vector_length, ECPoint(pp.group_ctx));
    pp.vector_h =
        std::vector<ECPoint>(pp.vector_length, ECPoint(pp.group_ctx));

    // The generator basis is deterministically reproducible. Distinct labels
    // prevent a known discrete-log relation between any two basis points.
    for (std::size_t i = 0; i < pp.vector_length; ++i) {
        pp.vector_g[i] = derive_generator(
            "taihang/bulletproof/vector-g/" + std::to_string(i),
            *pp.group_ctx);
        pp.vector_h[i] = derive_generator(
            "taihang/bulletproof/vector-h/" + std::to_string(i),
            *pp.group_ctx);
    }

    return pp;
}

bool Proof::operator==(const Proof& other) const {
    return a == other.a && s == other.s &&
           t1 == other.t1 && t2 == other.t2 &&
           taux == other.taux && mu == other.mu && t == other.t &&
           inner_product == other.inner_product;
}

std::ostream& operator<<(std::ostream& os, const Proof& proof) {
    return os << proof.a << proof.s << proof.t1 << proof.t2
              << proof.taux << proof.mu << proof.t
              << proof.inner_product;
}

std::istream& operator>>(std::istream& is, Proof& proof) {
    is >> proof.a >> proof.s >> proof.t1 >> proof.t2
       >> proof.taux >> proof.mu >> proof.t
       >> proof.inner_product;
    return is;
}

Proof prove(const PublicParameters& pp,
            const Statement& statement,
            const Witness& witness,
            std::string_view context) {
    const std::size_t aggregation = statement.commitments.size();
    TAIHANG_ASSERT(aggregation > 0 && aggregation <= pp.max_aggregation,
                   "invalid Bulletproof aggregation size");
    TAIHANG_ASSERT(is_pow2(aggregation),
                   "aggregation size must be a power of two");
    TAIHANG_ASSERT(witness.randomness.size() == aggregation &&
                       witness.values.size() == aggregation,
                   "Bulletproof witness size mismatch");

    const std::size_t length = pp.range_bits * aggregation;
    const ZnElement zero = pp.ring_ctx->get_zero();
    const ZnElement one = pp.ring_ctx->get_one();

    Proof proof{
        ECPoint(pp.group_ctx),
        ECPoint(pp.group_ctx),
        ECPoint(pp.group_ctx),
        ECPoint(pp.group_ctx),
        ZnElement(pp.ring_ctx),
        ZnElement(pp.ring_ctx),
        ZnElement(pp.ring_ctx),
        {}
    };

    // Encode every value in little-endian binary. Equation (42) defines
    // a_R = a_L - 1^nm. Consequently a_L o a_R = 0 exactly when every entry
    // of a_L is a bit, while <a_L, 2^n> reconstructs each committed value.
    ScalarVector a_left(length, zero);
    for (std::size_t block = 0; block < aggregation; ++block) {
        const ScalarVector bits =
            bit_vector(witness.values[block], pp.range_bits);
        std::copy(bits.begin(), bits.end(),
                  a_left.begin() + block * pp.range_bits);
    }

    ScalarVector a_right(length, zero);
    for (std::size_t i = 0; i < length; ++i) {
        a_right[i] = a_left[i] - one;
    }

    // Equation (44): A commits to the two bit vectors with fresh blinding
    // alpha. The same fixed generator list is reused for S below.
    std::vector<ECPoint> commitment_points(2 * length + 1,
                                           ECPoint(pp.group_ctx));
    ScalarVector commitment_scalars(2 * length + 1, zero);
    std::copy_n(pp.vector_g.begin(), length, commitment_points.begin());
    std::copy_n(pp.vector_h.begin(), length,
                commitment_points.begin() + length);
    commitment_points[2 * length] = pp.h;

    std::copy(a_left.begin(), a_left.end(), commitment_scalars.begin());
    std::copy(a_right.begin(), a_right.end(),
              commitment_scalars.begin() + length);
    const ZnElement alpha = pp.ring_ctx->gen_random();
    commitment_scalars[2 * length] = alpha;
    proof.a = ec_point_msm(commitment_points, commitment_scalars);

    // Equations (46) and (47): S commits to independent masks s_L and s_R.
    // These masks hide the bit vectors after evaluation at challenge x.
    const ScalarVector s_left =
        gen_random_znelement_vector(pp.ring_ctx, length);
    const ScalarVector s_right =
        gen_random_znelement_vector(pp.ring_ctx, length);
    const ZnElement rho = pp.ring_ctx->gen_random();

    std::copy(s_left.begin(), s_left.end(), commitment_scalars.begin());
    std::copy(s_right.begin(), s_right.end(),
              commitment_scalars.begin() + length);
    commitment_scalars[2 * length] = rho;
    proof.s = ec_point_msm(commitment_points, commitment_scalars);

    // Fiat-Shamir equations (49) and (50). The complete public statement is
    // included before A, and S is added before deriving z.
    std::ostringstream transcript;
    transcript.write(context.data(),
                     static_cast<std::streamsize>(context.size()));
    for (const ECPoint& commitment : statement.commitments) {
        transcript << commitment;
    }
    transcript << proof.a;

    ZnElement y = hash_to_zn(transcript.str(), *pp.ring_ctx);
    if (y.value.is_zero()) {
        y = one;
    }
    const ZnElement y_inverse = y.inv();
    const ScalarVector y_power = powers(length, y);
    const ScalarVector y_inverse_power = powers(length, y_inverse);

    transcript << proof.s;
    ZnElement z = hash_to_zn(transcript.str(), *pp.ring_ctx);
    if (z.value.is_zero()) {
        z = one;
    }
    const ZnElement z_square = z * z;

    const ZnElement two(pp.ring_ctx, BigInt(uint64_t{2}));
    const ScalarVector two_power = powers(pp.range_bits, two);
    ScalarVector z_power(aggregation + 1, zero);
    z_power[0] = z;
    for (std::size_t i = 1; i <= aggregation; ++i) {
        z_power[i] = z_power[i - 1] * z;
    }

    // Equations (70) and (71): construct the vector polynomials
    //
    //   l(X) = (a_L - z*1^nm) + s_L*X,
    //   r(X) = y^nm o (a_R + z*1^nm) + z powers o 2^n
    //          + (y^nm o s_R)*X.
    //
    // z_power[block + 1] is z^(block+2), matching the aggregation term in
    // the paper while z_power[0] remains z.
    ScalarVector l0(length, zero);
    ScalarVector r0(length, zero);
    ScalarVector r1(length, zero);
    for (std::size_t i = 0; i < length; ++i) {
        l0[i] = a_left[i] - z;
        r0[i] = y_power[i] * (a_right[i] + z);
        r1[i] = y_power[i] * s_right[i];
    }
    for (std::size_t block = 0; block < aggregation; ++block) {
        for (std::size_t bit = 0; bit < pp.range_bits; ++bit) {
            const std::size_t index = block * pp.range_bits + bit;
            r0[index] += z_power[block + 1] * two_power[bit];
        }
    }

    // t(X) = <l(X), r(X)> is quadratic. Its constant coefficient is fixed by
    // the public bit constraints, so only t_1 and t_2 require commitments.
    // This is the transition from equations (52) to (53).
    const ZnElement t1 = inner_product(s_left, r0) +
                         inner_product(l0, r1);
    const ZnElement t2 = inner_product(s_left, r1);
    const ZnElement tau1 = pp.ring_ctx->gen_random();
    const ZnElement tau2 = pp.ring_ctx->gen_random();
    const std::vector<ECPoint> polynomial_points{pp.g, pp.h};
    ScalarVector polynomial_scalars(2, zero);

    polynomial_scalars[0] = tau1;
    polynomial_scalars[1] = t1;
    proof.t1 = ec_point_msm(polynomial_points, polynomial_scalars);
    polynomial_scalars[0] = tau2;
    polynomial_scalars[1] = t2;
    proof.t2 = ec_point_msm(polynomial_points, polynomial_scalars);

    // Equation (56): x fixes the polynomial evaluation point after T1 and T2
    // are committed. Evaluate l(x), r(x), and t(x) = <l(x), r(x)>.
    transcript << proof.t1 << proof.t2;
    ZnElement x = hash_to_zn(transcript.str(), *pp.ring_ctx);
    if (x.value.is_zero()) {
        x = one;
    }
    const ZnElement x_square = x * x;
    const ScalarVector l_x = add_vectors(l0, scalar_vector(s_left, x));
    const ScalarVector r_x = add_vectors(r0, scalar_vector(r1, x));
    const ZnElement tx = inner_product(l_x, r_x);

    // Equations (61) and (62): combine the polynomial blindings with the
    // original commitment openings, and combine the A/S blindings.
    ZnElement taux = tau1 * x + tau2 * x_square;
    for (std::size_t i = 1; i <= aggregation; ++i) {
        taux += z_power[i] * witness.randomness[i - 1];
    }
    const ZnElement mu = alpha + rho * x;

    // Equation (65): e randomizes the inner-product base u. Serializing x as
    // a ZnElement gives a canonical fixed-width scalar encoding.
    transcript << x;
    ZnElement e = hash_to_zn(transcript.str(), *pp.ring_ctx);
    if (e.value.is_zero()) {
        e = one;
    }

    proof.taux = taux;
    proof.mu = mu;
    proof.t = tx;

    // These responses, together with the preceding outer transcript, uniquely
    // determine the derived inner-product statement. Binding the components
    // directly lets the verifier fuse that statement into its final MSM
    // instead of first materializing P with another large MSM.
    transcript << proof.taux << proof.mu << proof.t;

    inner_product::PublicParameters ip_pp =
        make_inner_product_parameters(pp, length);

    // Equations (66)-(68) define P from l(x), r(x), and t(x). The embedded
    // prover only needs the witness and generator basis; P is already bound by
    // its serialized components and is checked inside the final fused MSM.
    const inner_product::Witness ip_witness{l_x, r_x};
    proof.inner_product = inner_product::detail::prove_embedded(
        ip_pp, ip_witness, y_inverse_power, e, transcript.str());
    return proof;
}

bool verify(const PublicParameters& pp,
            const Statement& statement,
            const Proof& proof,
            std::string_view context) {
    const std::size_t aggregation = statement.commitments.size();
    if (aggregation == 0 ||
        aggregation > pp.max_aggregation ||
        !is_pow2(aggregation)) {
        return false;
    }

    const std::size_t length = pp.range_bits * aggregation;
    const std::size_t expected_rounds = folding_rounds(length);
    if (proof.inner_product.left.size() != expected_rounds ||
        proof.inner_product.right.size() != expected_rounds) {
        return false;
    }

    const ZnElement zero = pp.ring_ctx->get_zero();
    const ZnElement one = pp.ring_ctx->get_one();

    // Reconstruct y and z from exactly the same public statement and first
    // messages used by the prover (equations (49) and (50)).
    std::ostringstream transcript;
    transcript.write(context.data(),
                     static_cast<std::streamsize>(context.size()));
    for (const ECPoint& commitment : statement.commitments) {
        transcript << commitment;
    }
    transcript << proof.a;

    ZnElement y = hash_to_zn(transcript.str(), *pp.ring_ctx);
    if (y.value.is_zero()) {
        y = one;
    }
    const ZnElement y_inverse = y.inv();

    transcript << proof.s;
    ZnElement z = hash_to_zn(transcript.str(), *pp.ring_ctx);
    if (z.value.is_zero()) {
        z = one;
    }
    const ZnElement z_square = z * z;

    const ScalarVector y_power = powers(length, y);
    const ScalarVector y_inverse_power = powers(length, y_inverse);
    const ZnElement two(pp.ring_ctx, BigInt(uint64_t{2}));
    const ScalarVector two_power = powers(pp.range_bits, two);

    ScalarVector z_power(aggregation + 1, zero);
    z_power[0] = z;
    for (std::size_t i = 1; i <= aggregation; ++i) {
        z_power[i] = z_power[i - 1] * z;
    }

    // Equation (39), also used in equation (72):
    //   delta(y,z) = (z-z^2)<1^nm,y^nm>
    //                - sum_j z^(j+2)<1^n,2^n>.
    ZnElement sum_y = zero;
    for (const ZnElement& value : y_power) {
        sum_y += value;
    }
    ZnElement sum_two = zero;
    for (const ZnElement& value : two_power) {
        sum_two += value;
    }
    ZnElement sum_z = zero;
    for (std::size_t i = 1; i <= aggregation; ++i) {
        sum_z += z_power[i];
    }
    sum_z *= z;
    const ZnElement delta = (z - z_square) * sum_y - sum_z * sum_two;

    transcript << proof.t1 << proof.t2;
    ZnElement x = hash_to_zn(transcript.str(), *pp.ring_ctx);
    if (x.value.is_zero()) {
        x = one;
    }
    const ZnElement x_square = x * x;

    transcript << x;
    ZnElement e = hash_to_zn(transcript.str(), *pp.ring_ctx);
    if (e.value.is_zero()) {
        e = one;
    }

    // Bind the response scalars that determine the embedded inner-product
    // statement before processing its L/R messages.
    transcript << proof.taux << proof.mu << proof.t;

    // Public h coefficients in equations (66)-(68) and (104). The verifier
    // keeps the original h generators and absorbs y^-i into their final MSM
    // scalars instead of materializing h'_i = h_i*y^-i as separate points.
    ScalarVector rr = scalar_vector(y_power, z);
    for (std::size_t block = 0; block < aggregation; ++block) {
        for (std::size_t bit = 0; bit < pp.range_bits; ++bit) {
            const std::size_t index = block * pp.range_bits + bit;
            rr[index] += z_power[block + 1] * two_power[bit];
        }
    }

    // Recover the inner-product folding challenges. The outer transcript now
    // binds every component of the derived statement, so no preliminary MSM
    // is needed merely to serialize P.
    const std::string outer_transcript = transcript.str();
    std::ostringstream inner_transcript;
    inner_transcript.write(
        outer_transcript.data(),
        static_cast<std::streamsize>(outer_transcript.size()));

    ScalarVector ip_x(expected_rounds, zero);
    ScalarVector ip_x_square(expected_rounds, zero);
    for (std::size_t round = 0; round < expected_rounds; ++round) {
        inner_transcript << proof.inner_product.left[round]
                         << proof.inner_product.right[round];
        ip_x[round] =
            hash_to_zn(inner_transcript.str(), *pp.ring_ctx);
        if (ip_x[round].value.is_zero()) {
            ip_x[round] = one;
        }
        ip_x_square[round] = ip_x[round] * ip_x[round];
    }

    const ScalarVector ip_x_inverse =
        batch_invert(ip_x, pp.ring_ctx.get());
    ScalarVector ip_x_inverse_square(expected_rounds, zero);
    for (std::size_t round = 0; round < expected_rounds; ++round) {
        ip_x_inverse_square[round] =
            ip_x_inverse[round] * ip_x_inverse[round];
    }

    const ScalarVector ip_s = compute_s(
        ip_x_square, ip_x_inverse, pp.ring_ctx.get(), length);

    // Batch equation (72) with the final inner-product equation. The batch
    // scalar is derived after the complete proof is fixed, so two invalid
    // equations can cancel only with negligible probability. This replaces
    // Kunlun's separate verification MSMs with one final MSM.
    const std::string folded_transcript = inner_transcript.str();
    std::ostringstream batch_transcript;
    batch_transcript.write(
        folded_transcript.data(),
        static_cast<std::streamsize>(folded_transcript.size()));
    batch_transcript << proof.inner_product.a << proof.inner_product.b;
    ZnElement batch = hash_to_zn(batch_transcript.str(), *pp.ring_ctx);
    if (batch.value.is_zero()) {
        batch = one;
    }

    const std::size_t final_msm_size =
        aggregation + 2 * length + 2 * expected_rounds + 6;
    std::vector<const ECPoint*> points(final_msm_size, nullptr);
    ScalarVector scalars(final_msm_size, zero);
    std::size_t cursor = 0;

    // Batched outer equation (72):
    //   C^(z^2,...) h^(delta-t) T1^x T2^(x^2) g^(-taux) = 0.
    for (std::size_t i = 0; i < aggregation; ++i, ++cursor) {
        points[cursor] = &statement.commitments[i];
        scalars[cursor] = batch * z_power[i + 1];
    }
    // h occurs in both equations, so combine its two coefficients and include
    // the base only once in the MSM.
    points[cursor] = &pp.h;
    scalars[cursor++] = batch * (delta - proof.t) + proof.mu;
    points[cursor] = &proof.t1;
    scalars[cursor++] = batch * x;
    points[cursor] = &proof.t2;
    scalars[cursor++] = batch * x_square;

    // Final folded inner-product equation from the top of page 17, after
    // substituting the Bulletproof statement from equation (104). Generator
    // adjustments are absorbed into scalars, avoiding 2*length point copies
    // and length+1 standalone scalar multiplications.
    for (std::size_t i = 0; i < length; ++i, ++cursor) {
        points[cursor] = &pp.vector_g[i];
        scalars[cursor] = ip_s[i] * proof.inner_product.a + z;
    }
    for (std::size_t i = 0; i < length; ++i, ++cursor) {
        points[cursor] = &pp.vector_h[i];
        // Complementing the binary index flips every challenge exponent, so
        // ip_s[length-1-i] is the inverse coefficient required for h_i.
        scalars[cursor] = y_inverse_power[i] *
            (ip_s[length - 1 - i] * proof.inner_product.b - rr[i]);
    }

    points[cursor] = &proof.a;
    scalars[cursor++] = -one;
    points[cursor] = &proof.s;
    scalars[cursor++] = -x;
    points[cursor] = &pp.u;
    scalars[cursor++] = e *
        (proof.inner_product.a * proof.inner_product.b - proof.t);

    for (std::size_t i = 0; i < expected_rounds; ++i, ++cursor) {
        points[cursor] = &proof.inner_product.left[i];
        scalars[cursor] = -ip_x_square[i];
    }
    for (std::size_t i = 0; i < expected_rounds; ++i, ++cursor) {
        points[cursor] = &proof.inner_product.right[i];
        scalars[cursor] = -ip_x_inverse_square[i];
    }

    TAIHANG_ASSERT(cursor == final_msm_size,
                   "Bulletproof verifier MSM size mismatch");
    const ZnElement generator_scalar = batch * (-proof.taux);
    return ec_point_msm_with_generator(
               generator_scalar, points, scalars)
        .is_at_infinity();
}

} // namespace taihang::zkp::range_proofs::bulletproof
