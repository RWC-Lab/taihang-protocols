#include <gtest/gtest.h>

#include <openssl/obj_mac.h>
#include <sstream>
#include <vector>

#include <taihang/pke/twisted_elgamal.hpp>
#include <taihang/zkp/sigma_protocols/twisted_elgamal_plaintext_knowledge.hpp>

namespace {

using namespace taihang;
using namespace taihang::pke::twisted_elgamal;
namespace plaintext_knowledge = taihang::zkp::nizk::twisted_elgamal_plaintext_knowledge;

class TwistedElGamalPlaintextKnowledgeTest : public ::testing::Test {
protected:
    TwistedElGamalPlaintextKnowledgeTest()
        : encryption_pp(taihang::pke::twisted_elgamal::setup(NID_X9_62_prime256v1)),
          pp(plaintext_knowledge::setup(encryption_pp)),
          key_pair(keygen(encryption_pp)),
          message(pp.ring_ctx, BigInt(uint64_t{42})),
          randomness(pp.ring_ctx, BigInt(uint64_t{17})) {
        statement.pk = key_pair.first.y;
        statement.ct = encrypt(encryption_pp, key_pair.first, message, randomness);
    }

    taihang::pke::twisted_elgamal::PublicParameters encryption_pp;
    plaintext_knowledge::PublicParameters pp;
    std::pair<PublicKey, SecretKey> key_pair;
    ZnElement message;
    ZnElement randomness;
    plaintext_knowledge::Statement statement;
};

TEST_F(TwistedElGamalPlaintextKnowledgeTest, SetupInitializesParameters) {
    EXPECT_EQ(pp.curve_id, NID_X9_62_prime256v1);
    ASSERT_NE(pp.group_ctx, nullptr);
    ASSERT_NE(pp.ring_ctx, nullptr);
    EXPECT_EQ(pp.group_ctx->order, pp.ring_ctx->modulus);
    EXPECT_EQ(pp.group_ctx.get(), encryption_pp.group_ctx.get());
    EXPECT_EQ(pp.ring_ctx.get(), encryption_pp.ring_ctx.get());
    EXPECT_EQ(pp.g, encryption_pp.g);
    EXPECT_EQ(pp.h, encryption_pp.h);
}

TEST_F(TwistedElGamalPlaintextKnowledgeTest, AcceptsValidProof) {
    const plaintext_knowledge::Proof proof = plaintext_knowledge::prove(
        pp, statement, plaintext_knowledge::Witness{message, randomness});
    EXPECT_TRUE(plaintext_knowledge::verify(pp, statement, proof));
}

TEST_F(TwistedElGamalPlaintextKnowledgeTest, AcceptsZeroMessageAndRandomness) {
    const ZnElement zero = pp.ring_ctx->get_zero();
    plaintext_knowledge::Statement zero_statement{statement.pk,
                             encrypt(encryption_pp, key_pair.first, zero, zero)};
    const plaintext_knowledge::Proof proof = plaintext_knowledge::prove(
        pp, zero_statement, plaintext_knowledge::Witness{zero, zero});
    EXPECT_TRUE(plaintext_knowledge::verify(pp, zero_statement, proof));
}

TEST_F(TwistedElGamalPlaintextKnowledgeTest, RejectsWrongWitnessAndStatement) {
    const plaintext_knowledge::Proof wrong = plaintext_knowledge::prove(
        pp, statement, plaintext_knowledge::Witness{pp.ring_ctx->get_one(), randomness});
    EXPECT_FALSE(plaintext_knowledge::verify(pp, statement, wrong));

    const plaintext_knowledge::Proof proof = plaintext_knowledge::prove(
        pp, statement, plaintext_knowledge::Witness{message, randomness});
    plaintext_knowledge::Statement changed = statement;
    changed.ct.c2 = changed.ct.c2 + pp.g;
    EXPECT_FALSE(plaintext_knowledge::verify(pp, changed, proof));
}

TEST_F(TwistedElGamalPlaintextKnowledgeTest, RejectsTamperedProof) {
    plaintext_knowledge::Proof proof = plaintext_knowledge::prove(
        pp, statement, plaintext_knowledge::Witness{message, randomness});
    proof.c1 = proof.c1 + statement.pk;
    EXPECT_FALSE(plaintext_knowledge::verify(pp, statement, proof));

    proof = plaintext_knowledge::prove(
        pp, statement, plaintext_knowledge::Witness{message, randomness});
    proof.c2 = proof.c2 + pp.g;
    EXPECT_FALSE(plaintext_knowledge::verify(pp, statement, proof));

    proof = plaintext_knowledge::prove(
        pp, statement, plaintext_knowledge::Witness{message, randomness});
    proof.z1 = proof.z1 + pp.ring_ctx->get_one();
    EXPECT_FALSE(plaintext_knowledge::verify(pp, statement, proof));
}

TEST_F(TwistedElGamalPlaintextKnowledgeTest, BindsAssociatedContext) {
    const plaintext_knowledge::Proof proof = plaintext_knowledge::prove(
        pp, statement, plaintext_knowledge::Witness{message, randomness}, "session-a");
    EXPECT_TRUE(plaintext_knowledge::verify(pp, statement, proof, "session-a"));
    EXPECT_FALSE(plaintext_knowledge::verify(pp, statement, proof, "session-b"));
}

TEST_F(TwistedElGamalPlaintextKnowledgeTest, SerializationRoundTrip) {
    const plaintext_knowledge::Proof proof = plaintext_knowledge::prove(
        pp, statement, plaintext_knowledge::Witness{message, randomness});
    std::stringstream stream;
    stream << proof;
    plaintext_knowledge::Proof decoded{ECPoint(pp.group_ctx), ECPoint(pp.group_ctx),
                  ZnElement(pp.ring_ctx), ZnElement(pp.ring_ctx)};
    stream >> decoded;
    ASSERT_TRUE(stream);
    EXPECT_EQ(proof, decoded);
    EXPECT_TRUE(plaintext_knowledge::verify(pp, statement, decoded));
}

TEST_F(TwistedElGamalPlaintextKnowledgeTest, DeserializationRejectsNonCanonicalScalar) {
    const plaintext_knowledge::Proof proof = plaintext_knowledge::prove(
        pp, statement, plaintext_knowledge::Witness{message, randomness});
    std::stringstream stream;
    stream << proof.c1 << proof.c2 << proof.z1;
    const std::vector<uint8_t> modulus = pp.ring_ctx->modulus.to_bytes();
    stream.write(reinterpret_cast<const char*>(modulus.data()),
                 static_cast<std::streamsize>(modulus.size()));
    plaintext_knowledge::Proof decoded{ECPoint(pp.group_ctx), ECPoint(pp.group_ctx),
                                       ZnElement(pp.ring_ctx), ZnElement(pp.ring_ctx)};
    stream >> decoded;
    EXPECT_TRUE(stream.fail());
}

} // namespace
