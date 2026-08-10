#include <gtest/gtest.h>

#include <openssl/obj_mac.h>

#include <sstream>

#include <taihang/zkp/range_proofs/bullet_proof.hpp>

namespace {

using namespace taihang;
namespace bp = taihang::zkp::range_proofs::bulletproof;

class BulletProofTest : public ::testing::Test {
protected:
    BulletProofTest()
        : pp(bp::setup(NID_X9_62_prime256v1, 8, 4)),
          witness{
              std::vector<ZnElement>(4, ZnElement(pp.ring_ctx)),
              std::vector<ZnElement>(4, ZnElement(pp.ring_ctx))
          },
          statement{
              std::vector<ECPoint>(4, ECPoint(pp.group_ctx))
          } {
        const BigInt bound(uint64_t{1} << pp.range_bits);
        for (std::size_t i = 0; i < 4; ++i) {
            witness.randomness[i] = pp.ring_ctx->gen_random();
            witness.values[i] =
                ZnElement(pp.ring_ctx, gen_random_bigint_less_than(bound));
            statement.commitments[i] =
                pp.g * witness.randomness[i] + pp.h * witness.values[i];
        }
    }

    bp::PublicParameters pp;
    bp::Witness witness;
    bp::Statement statement;
};

TEST_F(BulletProofTest, SetupInitializesRangeAndGenerators) {
    EXPECT_EQ(pp.range_bits, 8U);
    EXPECT_EQ(pp.max_aggregation, 4U);
    EXPECT_EQ(pp.vector_length, 32U);
    EXPECT_EQ(pp.vector_g.size(), pp.vector_length);
    EXPECT_EQ(pp.vector_h.size(), pp.vector_length);
    EXPECT_EQ(pp.group_ctx->order, pp.ring_ctx->modulus);
    EXPECT_EQ(pp.h, hash_to_curve_standard(
        "taihang/bulletproof/base-h",
        "TAIHANG-PROTOCOLS-V01-P256_XMD:SHA-256_SSWU_RO_", *pp.group_ctx));
}

TEST_F(BulletProofTest, AcceptsAggregatedValuesInRange) {
    const bp::Proof proof = bp::prove(pp, statement, witness, "bulletproof-test");
    EXPECT_TRUE(bp::verify(pp, statement, proof, "bulletproof-test"));
}

TEST_F(BulletProofTest, SupportsSmallerPowerOfTwoAggregation) {
    const bp::Witness smaller_witness{
        {witness.randomness.begin(), witness.randomness.begin() + 2},
        {witness.values.begin(), witness.values.begin() + 2}
    };
    const bp::Statement smaller_statement{
        {statement.commitments.begin(), statement.commitments.begin() + 2}
    };
    const bp::Proof proof = bp::prove(pp, smaller_statement, smaller_witness);
    EXPECT_TRUE(bp::verify(pp, smaller_statement, proof));
}

TEST_F(BulletProofTest, AcceptsRangeBoundaries) {
    const ZnElement zero = pp.ring_ctx->get_zero();
    const ZnElement maximum(
        pp.ring_ctx,
        BigInt((uint64_t{1} << pp.range_bits) - 1));
    bp::Witness boundary{
        std::vector<ZnElement>(4, ZnElement(pp.ring_ctx)),
        std::vector<ZnElement>(4, ZnElement(pp.ring_ctx))
    };
    bp::Statement boundary_statement{
        std::vector<ECPoint>(4, ECPoint(pp.group_ctx))
    };
    for (std::size_t i = 0; i < 4; ++i) {
        boundary.randomness[i] = pp.ring_ctx->gen_random();
        boundary.values[i] = i % 2 == 0 ? zero : maximum;
        boundary_statement.commitments[i] =
            pp.g * boundary.randomness[i] + pp.h * boundary.values[i];
    }
    const bp::Proof proof = bp::prove(pp, boundary_statement, boundary);
    EXPECT_TRUE(bp::verify(pp, boundary_statement, proof));
}

TEST_F(BulletProofTest, RejectsWrongWitnessAndTampering) {
    bp::Witness wrong = witness;
    wrong.values[0] = pp.ring_ctx->get_one();
    EXPECT_FALSE(bp::verify(pp, statement, bp::prove(pp, statement, wrong)));

    const bp::Proof valid = bp::prove(pp, statement, witness);
    bp::Proof tampered = valid;
    tampered.t1 = tampered.t1 + pp.g;
    EXPECT_FALSE(bp::verify(pp, statement, tampered));

    tampered = valid;
    tampered.taux = tampered.taux + pp.ring_ctx->get_one();
    EXPECT_FALSE(bp::verify(pp, statement, tampered));

    tampered = valid;
    tampered.mu = tampered.mu + pp.ring_ctx->get_one();
    EXPECT_FALSE(bp::verify(pp, statement, tampered));

    tampered = valid;
    tampered.t = tampered.t + pp.ring_ctx->get_one();
    EXPECT_FALSE(bp::verify(pp, statement, tampered));

    tampered = valid;
    tampered.inner_product.a =
        tampered.inner_product.a + pp.ring_ctx->get_one();
    EXPECT_FALSE(bp::verify(pp, statement, tampered));

    bp::Proof proof = bp::prove(pp, statement, witness, "context-a");
    EXPECT_FALSE(bp::verify(pp, statement, proof, "context-b"));
}

TEST_F(BulletProofTest, RejectsValueOutsideRange) {
    bp::Witness outside = witness;
    outside.values[0] =
        ZnElement(pp.ring_ctx, BigInt(uint64_t{1} << pp.range_bits));
    bp::Statement outside_statement = statement;
    outside_statement.commitments[0] = pp.g * outside.randomness[0] +
                                       pp.h * outside.values[0];
    EXPECT_FALSE(bp::verify(
        pp,
        outside_statement,
        bp::prove(pp, outside_statement, outside)));
}

TEST_F(BulletProofTest, SerializationRoundTrip) {
    const bp::Proof proof = bp::prove(pp, statement, witness);
    std::stringstream stream;
    stream << proof;
    bp::Proof decoded;
    decoded.a = ECPoint(pp.group_ctx);
    decoded.s = ECPoint(pp.group_ctx);
    decoded.t1 = ECPoint(pp.group_ctx);
    decoded.t2 = ECPoint(pp.group_ctx);
    decoded.taux = ZnElement(pp.ring_ctx);
    decoded.mu = ZnElement(pp.ring_ctx);
    decoded.t = ZnElement(pp.ring_ctx);
    decoded.inner_product.left.resize(5, ECPoint(pp.group_ctx));
    decoded.inner_product.right.resize(5, ECPoint(pp.group_ctx));
    decoded.inner_product.a = ZnElement(pp.ring_ctx);
    decoded.inner_product.b = ZnElement(pp.ring_ctx);
    stream >> decoded;
    ASSERT_TRUE(stream);
    EXPECT_EQ(proof, decoded);
    EXPECT_TRUE(bp::verify(pp, statement, decoded));
}

} // namespace
