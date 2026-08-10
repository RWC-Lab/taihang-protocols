#include <gtest/gtest.h>

#include <openssl/obj_mac.h>

#include <algorithm>
#include <sstream>

#include <taihang/zkp/range_proofs/inner_product_proof.hpp>

namespace {

using namespace taihang;
namespace ip = taihang::zkp::range_proofs::inner_product;

class InnerProductProofTest : public ::testing::Test {
protected:
    InnerProductProofTest()
        : pp(ip::setup(NID_X9_62_prime256v1, 8)),
          witness{gen_random_znelement_vector(pp.ring_ctx, pp.vector_length),
                   gen_random_znelement_vector(pp.ring_ctx, pp.vector_length)} {
        const std::size_t msm_size = 2 * pp.vector_length + 1;
        std::vector<ECPoint> points(msm_size, ECPoint(pp.group_ctx));
        std::vector<ZnElement> scalars(msm_size,
                                       pp.ring_ctx->get_zero());

        std::copy(pp.g.begin(), pp.g.end(), points.begin());
        std::copy(pp.h.begin(), pp.h.end(),
                  points.begin() + pp.vector_length);
        points[2 * pp.vector_length] = pp.u;
        std::copy(witness.a.begin(), witness.a.end(), scalars.begin());
        std::copy(witness.b.begin(), witness.b.end(),
                  scalars.begin() + pp.vector_length);

        ZnElement inner = pp.ring_ctx->get_zero();
        for (std::size_t i = 0; i < pp.vector_length; ++i) {
            inner += witness.a[i] * witness.b[i];
        }
        scalars[2 * pp.vector_length] = inner;
        statement.p = ec_point_msm(points, scalars);
    }

    ip::PublicParameters pp;
    ip::Witness witness;
    ip::Statement statement;
};

TEST_F(InnerProductProofTest, SetupCreatesPowerOfTwoGeneratorVectors) {
    EXPECT_EQ(pp.vector_length, 8U);
    EXPECT_EQ(pp.rounds, 3U);
    EXPECT_EQ(pp.g.size(), pp.vector_length);
    EXPECT_EQ(pp.h.size(), pp.vector_length);
    EXPECT_EQ(pp.group_ctx->order, pp.ring_ctx->modulus);
    EXPECT_EQ(pp.g[0], hash_to_curve_standard(
        "taihang/inner-product/g/0",
        "TAIHANG-PROTOCOLS-V01-P256_XMD:SHA-256_SSWU_RO_", *pp.group_ctx));
}

TEST_F(InnerProductProofTest, AcceptsValidProof) {
    const ip::Proof proof =
        ip::prove(pp, statement, witness, "inner-product-test");
    EXPECT_TRUE(ip::verify(pp, statement, proof, "inner-product-test"));
}

TEST_F(InnerProductProofTest, RejectsTamperingAndWrongContext) {
    ip::Proof proof = ip::prove(pp, statement, witness);
    proof.left[0] = proof.left[0] + pp.g[0];
    EXPECT_FALSE(ip::verify(pp, statement, proof));

    proof = ip::prove(pp, statement, witness, "context-a");
    EXPECT_FALSE(ip::verify(pp, statement, proof, "context-b"));

    ip::Statement different_statement{statement.p + pp.g[0]};
    EXPECT_FALSE(ip::verify(pp, different_statement, proof, "context-a"));
}

TEST_F(InnerProductProofTest, SerializationRoundTrip) {
    const ip::Proof proof = ip::prove(pp, statement, witness);
    std::stringstream stream;
    stream << proof;
    ip::Proof decoded;
    decoded.left.resize(pp.rounds, ECPoint(pp.group_ctx));
    decoded.right.resize(pp.rounds, ECPoint(pp.group_ctx));
    decoded.a = ZnElement(pp.ring_ctx);
    decoded.b = ZnElement(pp.ring_ctx);
    stream >> decoded;
    ASSERT_TRUE(stream);
    EXPECT_EQ(proof, decoded);
    EXPECT_TRUE(ip::verify(pp, statement, decoded));
}

TEST(InnerProductProofStandaloneTest, HandlesSingleElementVector) {
    const auto pp = ip::setup(NID_X9_62_prime256v1, 1);
    const ip::Witness witness{
        {ZnElement(pp.ring_ctx, BigInt(uint64_t{7}))},
        {ZnElement(pp.ring_ctx, BigInt(uint64_t{9}))}
    };
    const ip::Statement statement{
        pp.g[0] * witness.a[0] + pp.h[0] * witness.b[0] +
        pp.u * witness.a[0] * witness.b[0]};
    const ip::Proof proof = ip::prove(pp, statement, witness);
    EXPECT_TRUE(ip::verify(pp, statement, proof));
}

} // namespace
