#include <gtest/gtest.h>

#include <sstream>
#include <vector>

#include <openssl/obj_mac.h>

#include <taihang/zkp/sigma_protocols/dlog_equality.hpp>

namespace {

using namespace taihang;
using namespace taihang::zkp::nizk::dlog_equality;

class DlogEqualityTest : public ::testing::Test {
protected:
    DlogEqualityTest()
        : pp(setup(NID_X9_62_prime256v1)),
          witness{ZnElement(pp.ring_ctx, BigInt(uint64_t{42}))},
          statement{pp.group_ctx->get_generator(), pp.group_ctx->get_infinity(),
                    pp.group_ctx->gen_random(), pp.group_ctx->get_infinity()} {
        statement.h1 = statement.g1 * witness.w;
        statement.h2 = statement.g2 * witness.w;
    }

    PublicParameters pp;
    Witness witness;
    Statement statement;
};

TEST_F(DlogEqualityTest, SetupInitializesPublicParameters) {
    EXPECT_EQ(pp.curve_id, NID_X9_62_prime256v1);
    ASSERT_NE(pp.group_ctx, nullptr);
    ASSERT_NE(pp.ring_ctx, nullptr);
    EXPECT_EQ(pp.group_ctx->order, pp.ring_ctx->modulus);
}

TEST_F(DlogEqualityTest, AcceptsValidProof) {
    const Proof proof = prove(pp, statement, witness);
    EXPECT_TRUE(verify(pp, statement, proof));
}

TEST_F(DlogEqualityTest, AcceptsZeroWitness) {
    Witness zero_witness{pp.ring_ctx->get_zero()};
    Statement zero_statement{statement.g1, pp.group_ctx->get_infinity(),
                             statement.g2, pp.group_ctx->get_infinity()};
    const Proof proof = prove(pp, zero_statement, zero_witness);
    EXPECT_TRUE(verify(pp, zero_statement, proof));
}

TEST_F(DlogEqualityTest, RejectsWrongStatement) {
    const Proof proof = prove(pp, statement, witness);
    statement.h2 = statement.h2 + statement.g2;
    EXPECT_FALSE(verify(pp, statement, proof));
}

TEST_F(DlogEqualityTest, IncorrectWitnessProducesRejectedProof) {
    Witness wrong_witness{ZnElement(pp.ring_ctx, BigInt(uint64_t{43}))};
    const Proof proof = prove(pp, statement, wrong_witness);
    EXPECT_FALSE(verify(pp, statement, proof));
}

TEST_F(DlogEqualityTest, RejectsTamperedCommitmentsAndResponse) {
    Proof proof = prove(pp, statement, witness);
    proof.c1 = proof.c1 + statement.g1;
    EXPECT_FALSE(verify(pp, statement, proof));
    proof = prove(pp, statement, witness);
    proof.c2 = proof.c2 + statement.g2;
    EXPECT_FALSE(verify(pp, statement, proof));
    proof = prove(pp, statement, witness);
    proof.z = proof.z + pp.ring_ctx->get_one();
    EXPECT_FALSE(verify(pp, statement, proof));
}

TEST_F(DlogEqualityTest, BindsAssociatedContext) {
    const Proof proof = prove(pp, statement, witness, "session-a");
    EXPECT_TRUE(verify(pp, statement, proof, "session-a"));
    EXPECT_FALSE(verify(pp, statement, proof, "session-b"));
}

TEST_F(DlogEqualityTest, SerializationRoundTrip) {
    const Proof proof = prove(pp, statement, witness);
    std::stringstream stream;
    stream << proof;
    Proof decoded{ECPoint(pp.group_ctx), ECPoint(pp.group_ctx), ZnElement(pp.ring_ctx)};
    stream >> decoded;
    ASSERT_TRUE(stream);
    EXPECT_EQ(proof, decoded);
    EXPECT_TRUE(verify(pp, statement, decoded));
}

TEST_F(DlogEqualityTest, DeserializationRejectsNonCanonicalResponse) {
    const Proof proof = prove(pp, statement, witness);
    std::stringstream stream;
    stream << proof.c1 << proof.c2;
    const std::vector<uint8_t> modulus = pp.ring_ctx->modulus.to_bytes();
    stream.write(reinterpret_cast<const char*>(modulus.data()), static_cast<std::streamsize>(modulus.size()));
    Proof decoded{ECPoint(pp.group_ctx), ECPoint(pp.group_ctx), ZnElement(pp.ring_ctx)};
    stream >> decoded;
    EXPECT_TRUE(stream.fail());
}

} // namespace
