#include <gtest/gtest.h>

#include <cstdint>
#include <memory>
#include <sstream>

#include <openssl/obj_mac.h>

#include <taihang/algorithm/bsgs_dlog.hpp>
#include <taihang/pke/twisted_elgamal.hpp>
#include <taihang/zkp/range_proofs/twisted_elgamal_range_proof.hpp>

namespace {

using namespace taihang;
namespace bulletproof = taihang::zkp::range_proofs::bulletproof;
namespace range_proof =
    taihang::zkp::range_proofs::twisted_elgamal_range_proof;

bulletproof::Proof empty_bulletproof(
    const range_proof::PublicParameters& pp) {
    bulletproof::Proof proof{
        ECPoint(pp.encryption.group_ctx),
        ECPoint(pp.encryption.group_ctx),
        ECPoint(pp.encryption.group_ctx),
        ECPoint(pp.encryption.group_ctx),
        ZnElement(pp.encryption.ring_ctx),
        ZnElement(pp.encryption.ring_ctx),
        ZnElement(pp.encryption.ring_ctx),
        {}};
    std::size_t rounds = 0;
    for (std::size_t length = pp.range.vector_length;
         length > 1;
         length /= 2) {
        ++rounds;
    }
    proof.inner_product.left.resize(
        rounds, ECPoint(pp.encryption.group_ctx));
    proof.inner_product.right.resize(
        rounds, ECPoint(pp.encryption.group_ctx));
    proof.inner_product.a = ZnElement(pp.encryption.ring_ctx);
    proof.inner_product.b = ZnElement(pp.encryption.ring_ctx);
    return proof;
}

class TwistedElGamalRangeProofTest : public ::testing::Test {
protected:
    TwistedElGamalRangeProofTest()
        : encryption_pp(
              pke::twisted_elgamal::setup(NID_X9_62_prime256v1, 8)),
          pp(range_proof::setup(encryption_pp)),
          key_pair(pke::twisted_elgamal::keygen(encryption_pp)),
          plaintext(pp.encryption.ring_ctx, BigInt(uint64_t{42})),
          randomness(pp.encryption.ring_ctx, BigInt(uint64_t{17})),
          statement{key_pair.first,
                    pke::twisted_elgamal::encrypt(encryption_pp,
                                                  key_pair.first,
                                                  plaintext,
                                                  randomness),
                    {BigInt(uint64_t{10}), BigInt(uint64_t{200})}} {}

    void SetUp() override {
        solver = std::make_unique<dlog::BSGSSolver>(
            *encryption_pp.group_ctx,
            encryption_pp.h,
            dlog::BSGSConfig{.range_bits = 8,
                             .tradeoff_num = 0,
                             .thread_num = 1});
        ECPoint baby_step = encryption_pp.group_ctx->get_infinity();
        for (std::size_t i = 0; i < solver->babystep_num; ++i) {
            solver->key_to_index.emplace(
                baby_step.xxhash_to_uint64(), static_cast<std::uint32_t>(i));
            baby_step.add_inplace(encryption_pp.h);
        }
    }

    pke::twisted_elgamal::PublicParameters encryption_pp;
    range_proof::PublicParameters pp;
    std::pair<pke::twisted_elgamal::PublicKey,
              pke::twisted_elgamal::SecretKey>
        key_pair;
    ZnElement plaintext;
    ZnElement randomness;
    range_proof::Statement statement;
    std::unique_ptr<dlog::BSGSSolver> solver;
};

TEST_F(TwistedElGamalRangeProofTest, SetupReusesEncryptionCommitmentBases) {
    EXPECT_EQ(pp.encryption.g, pp.range.g);
    EXPECT_EQ(pp.encryption.h, pp.range.h);
    EXPECT_EQ(pp.encryption.group_ctx.get(), pp.range.group_ctx.get());
    EXPECT_EQ(pp.encryption.ring_ctx.get(), pp.range.ring_ctx.get());
    EXPECT_EQ(pp.range.range_bits, 8U);
    EXPECT_EQ(pp.range.max_aggregation, 2U);
}

TEST_F(TwistedElGamalRangeProofTest, PlaintextKnowledgeProvesInterval) {
    const range_proof::PlaintextKnowledgeProof proof = range_proof::prove(
        pp,
        statement,
        {plaintext, randomness},
        "plaintext-knowledge-test");
    EXPECT_TRUE(range_proof::verify(
        pp, statement, proof, "plaintext-knowledge-test"));
    EXPECT_FALSE(range_proof::verify(
        pp, statement, proof, "wrong-context"));
}

TEST_F(TwistedElGamalRangeProofTest, AcceptsIntervalEndpoints) {
    for (const BigInt& value : {BigInt(uint64_t{10}), BigInt(uint64_t{199})}) {
        range_proof::Statement endpoint_statement = statement;
        endpoint_statement.ciphertext = pke::twisted_elgamal::encrypt(
            encryption_pp,
            key_pair.first,
            ZnElement(pp.encryption.ring_ctx, value),
            randomness);
        const range_proof::PlaintextKnowledgeProof proof = range_proof::prove(
            pp,
            endpoint_statement,
            {ZnElement(pp.encryption.ring_ctx, value), randomness});
        EXPECT_TRUE(range_proof::verify(pp, endpoint_statement, proof));
    }
}

TEST_F(TwistedElGamalRangeProofTest, RejectsValuesOutsideInterval) {
    for (const BigInt& value : {BigInt(uint64_t{9}), BigInt(uint64_t{200})}) {
        range_proof::Statement outside_statement = statement;
        outside_statement.ciphertext = pke::twisted_elgamal::encrypt(
            encryption_pp,
            key_pair.first,
            ZnElement(pp.encryption.ring_ctx, value),
            randomness);
        const range_proof::PlaintextKnowledgeProof proof = range_proof::prove(
            pp,
            outside_statement,
            {ZnElement(pp.encryption.ring_ctx, value), randomness});
        EXPECT_FALSE(range_proof::verify(pp, outside_statement, proof));
    }
}

TEST_F(TwistedElGamalRangeProofTest, SecretKeyKnowledgeProvesInterval) {
    const range_proof::SecretKeyKnowledgeProof proof = range_proof::prove(
        pp,
        statement,
        {key_pair.second},
        *solver,
        "secret-key-knowledge-test");
    EXPECT_TRUE(range_proof::verify(
        pp, statement, proof, "secret-key-knowledge-test"));
}

TEST_F(TwistedElGamalRangeProofTest, RejectsTamperedPlaintextKnowledgeProof) {
    range_proof::PlaintextKnowledgeProof proof = range_proof::prove(
        pp, statement, {plaintext, randomness});
    proof.range.t = proof.range.t + pp.encryption.ring_ctx->get_one();
    EXPECT_FALSE(range_proof::verify(pp, statement, proof));
}

TEST_F(TwistedElGamalRangeProofTest, RejectsTamperedSecretKeyKnowledgeProof) {
    range_proof::SecretKeyKnowledgeProof proof = range_proof::prove(
        pp, statement, {key_pair.second}, *solver);
    proof.refreshed_ciphertext.c2 =
        proof.refreshed_ciphertext.c2 + pp.encryption.h;
    EXPECT_FALSE(range_proof::verify(pp, statement, proof));
}

TEST_F(TwistedElGamalRangeProofTest, SerializationRoundTrips) {
    const range_proof::PlaintextKnowledgeProof plaintext_proof =
        range_proof::prove(pp, statement, {plaintext, randomness});
    std::stringstream plaintext_stream;
    plaintext_stream << plaintext_proof;
    range_proof::PlaintextKnowledgeProof decoded_plaintext{
        {ECPoint(pp.encryption.group_ctx),
         ECPoint(pp.encryption.group_ctx),
         ZnElement(pp.encryption.ring_ctx),
         ZnElement(pp.encryption.ring_ctx)},
        empty_bulletproof(pp)};
    plaintext_stream >> decoded_plaintext;
    ASSERT_TRUE(plaintext_stream);
    EXPECT_EQ(plaintext_proof, decoded_plaintext);
    EXPECT_TRUE(range_proof::verify(pp, statement, decoded_plaintext));

    const range_proof::SecretKeyKnowledgeProof secret_key_proof =
        range_proof::prove(pp, statement, {key_pair.second}, *solver);
    std::stringstream secret_key_stream;
    secret_key_stream << secret_key_proof;
    range_proof::SecretKeyKnowledgeProof decoded_secret_key{
        {ECPoint(pp.encryption.group_ctx), ECPoint(pp.encryption.group_ctx)},
        {ECPoint(pp.encryption.group_ctx),
         ECPoint(pp.encryption.group_ctx),
         ZnElement(pp.encryption.ring_ctx)},
        {ECPoint(pp.encryption.group_ctx),
         ECPoint(pp.encryption.group_ctx),
         ZnElement(pp.encryption.ring_ctx),
         ZnElement(pp.encryption.ring_ctx)},
        empty_bulletproof(pp)};
    secret_key_stream >> decoded_secret_key;
    ASSERT_TRUE(secret_key_stream);
    EXPECT_EQ(secret_key_proof, decoded_secret_key);
    EXPECT_TRUE(range_proof::verify(pp, statement, decoded_secret_key));
}

} // namespace
