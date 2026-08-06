#include <gtest/gtest.h>

#include <sstream>
#include <vector>

#include <openssl/obj_mac.h>

#include <taihang/zkp/sigma_protocols/dlog_knowledge.hpp>

namespace {

using namespace taihang;
using namespace taihang::zkp::nizk::dlog_knowledge;

class DlogKnowledgeTest : public ::testing::Test {
protected:
    DlogKnowledgeTest()
        : pp(setup(NID_X9_62_prime256v1)),
          witness{ZnElement(pp.ring_ctx, BigInt(uint64_t{42}))},
          statement{pp.group_ctx->gen_random(), pp.group_ctx->get_infinity()} {
        statement.h = statement.g * witness.w;
    }

    PublicParameters pp;
    Witness witness;
    Statement statement;
};

TEST_F(DlogKnowledgeTest, SetupInitializesPublicParameters) {
    EXPECT_EQ(pp.curve_id, NID_X9_62_prime256v1);
    ASSERT_NE(pp.group_ctx, nullptr);
    ASSERT_NE(pp.ring_ctx, nullptr);
    EXPECT_EQ(pp.group_ctx->order, pp.ring_ctx->modulus);
}

TEST_F(DlogKnowledgeTest, AcceptsValidProof) {
    const Proof proof = prove(pp, statement, witness);
    EXPECT_TRUE(verify(pp, statement, proof));
}

TEST_F(DlogKnowledgeTest, AcceptsZeroWitness) {
    const Witness zero_witness{pp.ring_ctx->get_zero()};
    const Statement zero_statement{statement.g, pp.group_ctx->get_infinity()};
    const Proof proof = prove(pp, zero_statement, zero_witness);
    EXPECT_TRUE(verify(pp, zero_statement, proof));
}

TEST_F(DlogKnowledgeTest, RejectsWrongStatement) {
    const Proof proof = prove(pp, statement, witness);
    statement.h = statement.h + statement.g;
    EXPECT_FALSE(verify(pp, statement, proof));
}

TEST_F(DlogKnowledgeTest, IncorrectWitnessProducesRejectedProof) {
    const Witness wrong_witness{ZnElement(pp.ring_ctx, BigInt(uint64_t{43}))};
    const Proof proof = prove(pp, statement, wrong_witness);
    EXPECT_FALSE(verify(pp, statement, proof));
}

TEST_F(DlogKnowledgeTest, RejectsTamperedCommitmentAndResponse) {
    Proof proof = prove(pp, statement, witness);
    proof.c = proof.c + statement.g;
    EXPECT_FALSE(verify(pp, statement, proof));

    proof = prove(pp, statement, witness);
    proof.z = proof.z + pp.ring_ctx->get_one();
    EXPECT_FALSE(verify(pp, statement, proof));
}

TEST_F(DlogKnowledgeTest, BindsAssociatedContext) {
    const Proof proof = prove(pp, statement, witness, "session-a");
    EXPECT_TRUE(verify(pp, statement, proof, "session-a"));
    EXPECT_FALSE(verify(pp, statement, proof, "session-b"));
}

TEST_F(DlogKnowledgeTest, SerializationRoundTrip) {
    const Proof proof = prove(pp, statement, witness);
    std::stringstream stream;
    stream << proof;

    Proof decoded{ECPoint(pp.group_ctx), ZnElement(pp.ring_ctx)};
    stream >> decoded;

    ASSERT_TRUE(stream);
    EXPECT_EQ(proof, decoded);
    EXPECT_TRUE(verify(pp, statement, decoded));
}

TEST_F(DlogKnowledgeTest, DeserializationRejectsNonCanonicalResponse) {
    const Proof proof = prove(pp, statement, witness);
    std::stringstream stream;
    stream << proof.c;
    const std::vector<uint8_t> modulus = pp.ring_ctx->modulus.to_bytes();
    stream.write(reinterpret_cast<const char*>(modulus.data()),
                 static_cast<std::streamsize>(modulus.size()));

    Proof decoded{ECPoint(pp.group_ctx), ZnElement(pp.ring_ctx)};
    stream >> decoded;
    EXPECT_TRUE(stream.fail());
}

} // namespace
