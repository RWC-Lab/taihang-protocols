/****************************************************************************
 * @file      inner_product_proof.cpp
 * @brief     Logarithmic-size Bulletproof inner-product argument.
 *****************************************************************************/

#include <taihang/zkp/range_proofs/inner_product_proof.hpp>

#include <openssl/obj_mac.h>

#include <algorithm>
#include <bit>
#include <cstdint>
#include <ios>
#include <istream>
#include <limits>
#include <ostream>
#include <sstream>
#include <utility>

#include <taihang/common/check.hpp>
#include <taihang/common/config.hpp>
#include <taihang/utility/arithmetic.hpp>

namespace taihang::zkp::range_proofs::inner_product {
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

/**
 * Compute the verifier's s-vector using the recurrence from page 15.
 *
 * For a binary index i, s_i is the product of one x_j or x_j^-1 from every
 * folding round. Once s_0 = product_j x_j^-1 is known, changing the highest
 * set bit of i replaces one inverse by x_j, hence multiplication by x_j^2.
 * This evaluates all n coefficients in O(n), rather than O(n log n).
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

/**
 * Invert a vector with one field inversion using Montgomery's batch trick.
 * Every Fiat-Shamir challenge is normalized to a nonzero scalar first.
 */
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

} // namespace

PublicParameters setup(int curve_id, std::size_t vector_length) {
    TAIHANG_ASSERT(is_pow2(vector_length),
                   "inner-product vector length must be a power of two");

    PublicParameters pp;
    pp.curve_id = curve_id;
    pp.vector_length = vector_length;
    pp.rounds = 0;
    for (std::size_t n = vector_length; n > 1; n /= 2) {
        ++pp.rounds;
    }

    pp.group_ctx = std::make_shared<ECGroup>(curve_id);
    pp.ring_ctx = std::make_shared<Zn>(pp.group_ctx->order);
    pp.g = std::vector<ECPoint>(vector_length, ECPoint(pp.group_ctx));
    pp.h = std::vector<ECPoint>(vector_length, ECPoint(pp.group_ctx));

    // The labels make every generator position independent and reproducible.
    // P-256 uses RFC 9380; derive_generator documents the fallback used by
    // curves for which Taihang does not yet expose an RFC suite.
    for (std::size_t i = 0; i < vector_length; ++i) {
        pp.g[i] = derive_generator(
            "taihang/inner-product/g/" + std::to_string(i), *pp.group_ctx);
        pp.h[i] = derive_generator(
            "taihang/inner-product/h/" + std::to_string(i), *pp.group_ctx);
    }
    pp.u = derive_generator("taihang/inner-product/u", *pp.group_ctx);

    return pp;
}

bool Proof::operator==(const Proof& other) const {
    return left == other.left && right == other.right &&
           a == other.a && b == other.b;
}

std::ostream& operator<<(std::ostream& os, const Proof& proof) {
    const std::uint64_t count =
        static_cast<std::uint64_t>(proof.left.size());
    os.write(reinterpret_cast<const char*>(&count), sizeof(count));

    for (const ECPoint& point : proof.left) {
        os << point;
    }
    for (const ECPoint& point : proof.right) {
        os << point;
    }
    return os << proof.a << proof.b;
}

std::istream& operator>>(std::istream& is, Proof& proof) {
    std::uint64_t count = 0;
    if (!is.read(reinterpret_cast<char*>(&count), sizeof(count))) {
        return is;
    }
    if (count >
        static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
        is.setstate(std::ios::failbit);
        return is;
    }

    // ECPoint and ZnElement encodings do not carry their arithmetic contexts.
    // The caller therefore preinitializes both point vectors and final scalars.
    if (proof.left.size() != count || proof.right.size() != count) {
        is.setstate(std::ios::failbit);
        return is;
    }

    for (std::uint64_t i = 0; i < count && is; ++i) {
        is >> proof.left[i];
    }
    for (std::uint64_t i = 0; i < count && is; ++i) {
        is >> proof.right[i];
    }
    if (is) {
        is >> proof.a >> proof.b;
    }
    return is;
}

namespace {

Proof prove_from_transcript(const PublicParameters& pp,
                            const Witness& witness,
                            std::ostringstream transcript,
                            const ScalarVector* h_factors,
                            const ZnElement& u_factor) {
    TAIHANG_ASSERT(witness.a.size() == pp.vector_length &&
                       witness.b.size() == pp.vector_length,
                   "inner-product witness length mismatch");
    TAIHANG_ASSERT(h_factors == nullptr ||
                       h_factors->size() == pp.vector_length,
                   "inner-product generator-factor length mismatch");

    Proof proof{
        std::vector<ECPoint>(pp.rounds, ECPoint(pp.group_ctx)),
        std::vector<ECPoint>(pp.rounds, ECPoint(pp.group_ctx)),
        ZnElement(pp.ring_ctx),
        ZnElement(pp.ring_ctx)
    };

    std::vector<ECPoint> current_g = pp.g;
    std::vector<ECPoint> current_h = pp.h;
    ScalarVector current_a = witness.a;
    ScalarVector current_b = witness.b;

    for (std::size_t round = 0; round < pp.rounds; ++round) {
        const std::size_t length = current_a.size();
        const std::size_t half = length / 2;

        // Equations (21) and (22): cross inner products between opposite
        // witness halves become the u coefficients in L and R.
        ZnElement c_left = pp.ring_ctx->get_zero();
        ZnElement c_right = pp.ring_ctx->get_zero();
        for (std::size_t i = 0; i < half; ++i) {
            c_left += current_a[i] * current_b[half + i];
            c_right += current_a[half + i] * current_b[i];
        }

        // Equations (23) and (24):
        //   L = g_R*a_L + h_L*b_R + u'*c_L,
        //   R = g_L*a_R + h_R*b_L + u'*c_R.
        // For an embedded proof, H' and u' are represented by scalar factors
        // and never materialized as separate point vectors.
        // Both MSMs have a known size, so their storage is allocated once and
        // populated by index instead of grown incrementally.
        std::vector<ECPoint> points(2 * half + 1, ECPoint(pp.group_ctx));
        ScalarVector scalars(2 * half + 1, pp.ring_ctx->get_zero());

        std::copy_n(current_g.begin() + half, half, points.begin());
        std::copy_n(current_h.begin(), half, points.begin() + half);
        points[2 * half] = pp.u;
        std::copy_n(current_a.begin(), half, scalars.begin());
        for (std::size_t i = 0; i < half; ++i) {
            scalars[half + i] = current_b[half + i];
            if (round == 0 && h_factors != nullptr) {
                scalars[half + i] *= (*h_factors)[i];
            }
        }
        scalars[2 * half] = c_left * u_factor;
        proof.left[round] = ec_point_msm(points, scalars);

        std::copy_n(current_g.begin(), half, points.begin());
        std::copy_n(current_h.begin() + half, half,
                    points.begin() + half);
        std::copy_n(current_a.begin() + half, half, scalars.begin());
        for (std::size_t i = 0; i < half; ++i) {
            scalars[half + i] = current_b[i];
            if (round == 0 && h_factors != nullptr) {
                scalars[half + i] *= (*h_factors)[half + i];
            }
        }
        scalars[2 * half] = c_right * u_factor;
        proof.right[round] = ec_point_msm(points, scalars);

        // Equations (26) and (27): hash all protocol data accumulated so far.
        // hash_to_zn performs the field reduction directly and retains the
        // scalar context needed by every subsequent operation.
        transcript << proof.left[round] << proof.right[round];
        ZnElement x = hash_to_zn(transcript.str(), *pp.ring_ctx);
        if (x.value.is_zero()) {
            // A zero challenge has negligible probability but cannot be
            // inverted. Mapping it to one keeps the prover deterministic.
            x = pp.ring_ctx->get_one();
        }
        const ZnElement x_inverse = x.inv();

        // Equations (29), (30), (33), and (34): fold both generator and
        // witness halves. Each iteration halves the relation dimension while
        // preserving the same inner product.
        std::vector<ECPoint> next_g(half, ECPoint(pp.group_ctx));
        std::vector<ECPoint> next_h(half, ECPoint(pp.group_ctx));
        ScalarVector next_a(half, pp.ring_ctx->get_zero());
        ScalarVector next_b(half, pp.ring_ctx->get_zero());

        // Point folding dominates prover time. For an embedded range proof,
        // absorb H'_i = H_i*h_factor_i into the first fold instead of first
        // materializing every adjusted point. Later rounds operate on the
        // already-adjusted folded generators.
        #pragma omp parallel for num_threads(config::thread_num)
        for (std::size_t i = 0; i < half; ++i) {
            next_g[i] = ec_point_msm(
                current_g[i], x_inverse, current_g[half + i], x);
            if (round == 0 && h_factors != nullptr) {
                const ZnElement left_factor = x * (*h_factors)[i];
                const ZnElement right_factor =
                    x_inverse * (*h_factors)[half + i];
                next_h[i] = ec_point_msm(
                    current_h[i], left_factor,
                    current_h[half + i], right_factor);
            } else {
                next_h[i] = ec_point_msm(
                    current_h[i], x, current_h[half + i], x_inverse);
            }
            next_a[i] = current_a[i] * x +
                        current_a[half + i] * x_inverse;
            next_b[i] = current_b[i] * x_inverse +
                        current_b[half + i] * x;
        }

        current_g = std::move(next_g);
        current_h = std::move(next_h);
        current_a = std::move(next_a);
        current_b = std::move(next_b);
    }

    // After log2(n) rounds, the verifier only needs these two folded scalars.
    proof.a = current_a[0];
    proof.b = current_b[0];
    return proof;
}

} // namespace

Proof prove(const PublicParameters& pp,
            const Statement& statement,
            const Witness& witness,
            std::string_view context) {
    // A standalone proof binds its public statement before the first L/R pair.
    std::ostringstream transcript;
    transcript.write(context.data(),
                     static_cast<std::streamsize>(context.size()));
    transcript << statement.p;
    return prove_from_transcript(
        pp, witness, std::move(transcript), nullptr, pp.ring_ctx->get_one());
}

namespace detail {

Proof prove_embedded(const PublicParameters& pp,
                     const Witness& witness,
                     const std::vector<ZnElement>& h_factors,
                     const ZnElement& u_factor,
                     std::string_view parent_context) {
    // The parent protocol has already serialized the values that uniquely
    // determine its derived inner-product statement.
    std::ostringstream transcript;
    transcript.write(parent_context.data(),
                     static_cast<std::streamsize>(parent_context.size()));
    return prove_from_transcript(
        pp, witness, std::move(transcript), &h_factors, u_factor);
}

} // namespace detail

bool verify(const PublicParameters& pp,
            const Statement& statement,
            const Proof& proof,
            std::string_view context) {
    if (pp.g.size() != pp.vector_length ||
        pp.h.size() != pp.vector_length ||
        proof.left.size() != proof.right.size() ||
        proof.left.size() != pp.rounds) {
        return false;
    }

    std::ostringstream transcript;
    transcript.write(context.data(),
                     static_cast<std::streamsize>(context.size()));
    transcript << statement.p;

    ScalarVector x(pp.rounds, pp.ring_ctx->get_zero());
    ScalarVector x_square(pp.rounds, pp.ring_ctx->get_zero());

    // Reconstruct x_j from each L_j/R_j pair. The verifier only retains the
    // challenges and squares before inverting all challenges as one batch.
    for (std::size_t round = 0; round < pp.rounds; ++round) {
        transcript << proof.left[round] << proof.right[round];
        x[round] = hash_to_zn(transcript.str(), *pp.ring_ctx);
        if (x[round].value.is_zero()) {
            x[round] = pp.ring_ctx->get_one();
        }
        x_square[round] = x[round] * x[round];
    }

    const ScalarVector x_inverse =
        batch_invert(x, pp.ring_ctx.get());
    ScalarVector x_inverse_square(pp.rounds, pp.ring_ctx->get_zero());
    for (std::size_t round = 0; round < pp.rounds; ++round) {
        x_inverse_square[round] =
            x_inverse[round] * x_inverse[round];
    }

    const ScalarVector s =
        compute_s(x_square, x_inverse, pp.ring_ctx.get(), pp.vector_length);

    // Left side of the final equation:
    //   g^(a*s) h^(b*s^-1) u^(a*b).
    const std::size_t final_msm_size = 2 * pp.vector_length + 1;
    std::vector<const ECPoint*> points(final_msm_size, nullptr);
    ScalarVector scalars(final_msm_size, pp.ring_ctx->get_zero());

    for (std::size_t i = 0; i < pp.vector_length; ++i) {
        points[i] = &pp.g[i];
        points[pp.vector_length + i] = &pp.h[i];
        scalars[i] = s[i] * proof.a;
        // Complementing the binary index flips every challenge exponent:
        // s[n-1-i] = s[i]^-1.
        scalars[pp.vector_length + i] =
            s[pp.vector_length - 1 - i] * proof.b;
    }
    points[2 * pp.vector_length] = &pp.u;
    scalars[2 * pp.vector_length] = proof.a * proof.b;
    const ECPoint left = ec_point_msm(points, scalars);

    // Right side of the final equation:
    //   P + sum_j (L_j*x_j^2 + R_j*x_j^-2).
    points = std::vector<const ECPoint*>(2 * pp.rounds + 1, nullptr);
    scalars = ScalarVector(2 * pp.rounds + 1,
                           pp.ring_ctx->get_zero());
    for (std::size_t round = 0; round < pp.rounds; ++round) {
        points[round] = &proof.left[round];
        scalars[round] = x_square[round];
        points[pp.rounds + 1 + round] = &proof.right[round];
        scalars[pp.rounds + 1 + round] = x_inverse_square[round];
    }
    points[pp.rounds] = &statement.p;
    scalars[pp.rounds] = pp.ring_ctx->get_one();
    const ECPoint right = ec_point_msm(points, scalars);

    return left == right;
}

} // namespace taihang::zkp::range_proofs::inner_product
