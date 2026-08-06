#include <gtest/gtest.h>

#include <cstdint>
#include <openssl/obj_mac.h>
#include <sstream>
#include <vector>

#include <taihang/pke/twisted_elgamal.hpp>
#include <taihang/zkp/sigma_protocols/twisted_elgamal_plaintext_equality.hpp>

namespace {

using namespace taihang;
using namespace taihang::pke::twisted_elgamal;
namespace plaintext_equality = taihang::zkp::nizk::twisted_elgamal_plaintext_equality;

class TwistedElGamalPlaintextEqualityTest : public ::testing::Test {
protected:
    static constexpr std::size_t recipient_count = 3;

    TwistedElGamalPlaintextEqualityTest()
        : encryption_pp(taihang::pke::twisted_elgamal::setup(NID_X9_62_prime256v1)),
          pp(plaintext_equality::setup(encryption_pp)),
          message(pp.ring_ctx, BigInt(uint64_t{42})),
          randomness(pp.ring_ctx, BigInt(uint64_t{17})) {
        for (std::size_t i = 0; i < recipient_count; ++i) {
            key_pairs.push_back(keygen(encryption_pp));
            public_keys.push_back(key_pairs.back().first);
        }
        statement.vec_pk.reserve(recipient_count);
        for (const auto& pk : public_keys) statement.vec_pk.push_back(pk.y);
        statement.ct = encrypt(encryption_pp, public_keys, message, randomness);
    }

    taihang::pke::twisted_elgamal::PublicParameters encryption_pp;
    plaintext_equality::PublicParameters pp;
    std::vector<std::pair<PublicKey, SecretKey>> key_pairs;
    std::vector<PublicKey> public_keys;
    ZnElement message;
    ZnElement randomness;
    plaintext_equality::Statement statement;
};

TEST_F(TwistedElGamalPlaintextEqualityTest, SetupInitializesParameters) {
    EXPECT_EQ(pp.curve_id, NID_X9_62_prime256v1);
    ASSERT_NE(pp.group_ctx, nullptr);
    ASSERT_NE(pp.ring_ctx, nullptr);
    EXPECT_EQ(pp.group_ctx.get(), encryption_pp.group_ctx.get());
    EXPECT_EQ(pp.ring_ctx.get(), encryption_pp.ring_ctx.get());
    EXPECT_EQ(pp.g, encryption_pp.g);
    EXPECT_EQ(pp.h, encryption_pp.h);
}

TEST_F(TwistedElGamalPlaintextEqualityTest, AcceptsValidProof) {
    const plaintext_equality::Proof proof = plaintext_equality::prove(
        pp, statement, plaintext_equality::Witness{message, randomness});
    EXPECT_TRUE(plaintext_equality::verify(pp, statement, proof));
}

TEST_F(TwistedElGamalPlaintextEqualityTest, AcceptsZeroMessageAndRandomness) {
    const ZnElement zero = pp.ring_ctx->get_zero();
    plaintext_equality::Statement zero_statement = statement;
    zero_statement.ct = encrypt(encryption_pp, public_keys, zero, zero);
    const plaintext_equality::Proof proof = plaintext_equality::prove(
        pp, zero_statement, plaintext_equality::Witness{zero, zero});
    EXPECT_TRUE(plaintext_equality::verify(pp, zero_statement, proof));
}

TEST_F(TwistedElGamalPlaintextEqualityTest, RejectsWrongRecipientCiphertext) {
    const plaintext_equality::Proof proof = plaintext_equality::prove(
        pp, statement, plaintext_equality::Witness{message, randomness});
    plaintext_equality::Statement changed = statement;
    changed.ct.vec_c1[1] = changed.ct.vec_c1[1] + statement.vec_pk[1];
    EXPECT_FALSE(plaintext_equality::verify(pp, changed, proof));
}

TEST_F(TwistedElGamalPlaintextEqualityTest, RejectsWrongWitnessAndProof) {
    const plaintext_equality::Proof wrong = plaintext_equality::prove(
        pp, statement, plaintext_equality::Witness{pp.ring_ctx->get_one(), randomness});
    EXPECT_FALSE(plaintext_equality::verify(pp, statement, wrong));

    plaintext_equality::Proof proof = plaintext_equality::prove(
        pp, statement, plaintext_equality::Witness{message, randomness});
    proof.vec_c1[0] = proof.vec_c1[0] + statement.vec_pk[0];
    EXPECT_FALSE(plaintext_equality::verify(pp, statement, proof));
    proof = plaintext_equality::prove(
        pp, statement, plaintext_equality::Witness{message, randomness});
    proof.t = proof.t + pp.ring_ctx->get_one();
    EXPECT_FALSE(plaintext_equality::verify(pp, statement, proof));
}

TEST_F(TwistedElGamalPlaintextEqualityTest, RejectsRecipientCountMismatch) {
    const plaintext_equality::Proof proof = plaintext_equality::prove(
        pp, statement, plaintext_equality::Witness{message, randomness});
    plaintext_equality::Statement changed = statement;
    changed.vec_pk.pop_back();
    EXPECT_FALSE(plaintext_equality::verify(pp, changed, proof));
}

TEST_F(TwistedElGamalPlaintextEqualityTest, BindsAssociatedContext) {
    const plaintext_equality::Proof proof = plaintext_equality::prove(
        pp, statement, plaintext_equality::Witness{message, randomness}, "session-a");
    EXPECT_TRUE(plaintext_equality::verify(pp, statement, proof, "session-a"));
    EXPECT_FALSE(plaintext_equality::verify(pp, statement, proof, "session-b"));
}

TEST_F(TwistedElGamalPlaintextEqualityTest, SerializationRoundTrip) {
    const plaintext_equality::Proof proof = plaintext_equality::prove(
        pp, statement, plaintext_equality::Witness{message, randomness});
    std::stringstream stream;
    stream << proof;
    plaintext_equality::Proof decoded;
    decoded.c2 = ECPoint(pp.group_ctx);
    decoded.z = ZnElement(pp.ring_ctx);
    decoded.t = ZnElement(pp.ring_ctx);
    stream >> decoded;
    ASSERT_TRUE(stream);
    EXPECT_EQ(proof, decoded);
    EXPECT_TRUE(plaintext_equality::verify(pp, statement, decoded));
}

TEST_F(TwistedElGamalPlaintextEqualityTest, DeserializationRejectsNonCanonicalScalar) {
    const plaintext_equality::Proof proof = plaintext_equality::prove(
        pp, statement, plaintext_equality::Witness{message, randomness});
    std::stringstream stream;
    const std::uint64_t count = static_cast<std::uint64_t>(proof.vec_c1.size());
    stream.write(reinterpret_cast<const char*>(&count), sizeof(count));
    for (const auto& point : proof.vec_c1) stream << point;
    stream << proof.c2 << proof.z;
    const std::vector<uint8_t> modulus = pp.ring_ctx->modulus.to_bytes();
    stream.write(reinterpret_cast<const char*>(modulus.data()),
                 static_cast<std::streamsize>(modulus.size()));
    plaintext_equality::Proof decoded;
    decoded.c2 = ECPoint(pp.group_ctx);
    decoded.z = ZnElement(pp.ring_ctx);
    decoded.t = ZnElement(pp.ring_ctx);
    stream >> decoded;
    EXPECT_TRUE(stream.fail());
}

} // namespace
