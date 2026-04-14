/****************************************************************************
 * @file      test_twisted_elgamal.cpp
 * @brief     GTest suite for Twisted ElGamal PKE.
 * @author    Yu Chen
 *****************************************************************************/

#include <gtest/gtest.h>
#include <taihang/pke/twisted_elgamal.hpp>
#include <taihang/algorithm/bsgs_dlog.hpp>
#include <taihang/crypto/ec_group.hpp>
#include <taihang/crypto/zn.hpp>
#include <openssl/obj_mac.h>
#include <sstream>

using namespace taihang;
using namespace taihang::pke::twisted_elgamal;
using namespace taihang::dlog;

// ============================================================
// Base Fixture — standard ElGamal only
// ============================================================

class TwistedElGamalTest : public ::testing::Test {
protected:
    void SetUp() override {
        pp_std = setup(NID_X9_62_prime256v1, 0);
        pp_exp = setup(NID_X9_62_prime256v1, MSG_BITS);

        // Standard key pairs — bound to pp_std's group
        auto [pk_,  sk_]  = keygen(pp_std);
        pk  = pk_;  sk  = sk_;

        auto [pk2_, sk2_] = keygen(pp_std);
        pk2 = pk2_; sk2 = sk2_;

        // Exponential key pair — bound to pp_exp's group
        // pp_std and pp_exp allocate separate ECGroup instances;
        // mixing their key pairs causes UB in OpenSSL EC operations.
        auto [pk_exp_, sk_exp_] = keygen(pp_exp);
        pk_exp = pk_exp_;
        sk_exp = sk_exp_;
    }

    // MSG_BITS=20, TRADEOFF_NUM=5:
    //   babystep = 2^(10+5) = 2^15 = 32768
    //   giantstep = 2^(10-5) = 2^5  = 32
    //   total range = 2^20
    static constexpr size_t MSG_BITS     = 20;
    static constexpr size_t TRADEOFF_NUM = 5;
    static constexpr size_t THREAD_NUM   = 4;

    PublicParameters pp_std;
    PublicParameters pp_exp;

    PublicKey pk,  pk2;
    SecretKey sk,  sk2;

    PublicKey pk_exp;
    SecretKey sk_exp;
};

// ============================================================
// Exponential Fixture — solver constructed in place, no return-by-value
//
// Returning BSGSSolver by value from a factory function can leave
// absl::flat_hash_map in a valid-but-empty state depending on whether
// NRVO fires. Storing via unique_ptr avoids this entirely.
// ============================================================

class TwistedElGamalExpTest : public TwistedElGamalTest {
protected:
    void SetUp() override {
        TwistedElGamalTest::SetUp();

        solver = std::make_unique<BSGSSolver>(
            *pp_exp.group_ctx,
            pp_exp.h,
            BSGSConfig{
                .range_bits   = MSG_BITS,
                .tradeoff_num = TRADEOFF_NUM,
                .thread_num   = THREAD_NUM
            }
        );
        solver->prepare();
        solver_file = solver->get_table_filename();
    }

    void TearDown() override {
        solver.reset();  // destroy before removing file
        if (!solver_file.empty()) {
            std::remove(solver_file.c_str());
            solver_file.clear();
        }
    }

    std::unique_ptr<BSGSSolver> solver;
    std::string solver_file;
};

// ============================================================
// 1. Setup
// ============================================================

TEST_F(TwistedElGamalTest, Setup_Standard_Fields) {
    EXPECT_EQ(pp_std.msg_len_bits, 0ULL);
    EXPECT_EQ(pp_std.msg_size,     BigInt(0ULL));
    EXPECT_TRUE(pp_std.g.is_on_curve());
    EXPECT_TRUE(pp_std.h.is_on_curve());
    EXPECT_NE(pp_std.g, pp_std.h);
    EXPECT_NE(pp_std.group_ctx, nullptr);
    EXPECT_NE(pp_std.field_ctx,  nullptr);
}

TEST_F(TwistedElGamalTest, Setup_Exponential_Fields) {
    EXPECT_EQ(pp_exp.msg_len_bits, MSG_BITS);
    EXPECT_EQ(pp_exp.msg_size,     BigInt(1ULL << MSG_BITS));
    EXPECT_TRUE(pp_exp.g.is_on_curve());
    EXPECT_TRUE(pp_exp.h.is_on_curve());
    EXPECT_NE(pp_exp.group_ctx, nullptr);
    EXPECT_NE(pp_exp.field_ctx,  nullptr);
}

TEST_F(TwistedElGamalTest, Setup_SameCurve_SameGenerators) {
    PublicParameters pp1 = setup(NID_X9_62_prime256v1);
    PublicParameters pp2 = setup(NID_X9_62_prime256v1);
    EXPECT_EQ(pp1.g, pp2.g);
    EXPECT_EQ(pp1.h, pp2.h);
}

// ============================================================
// 2. KeyGen
// ============================================================

TEST_F(TwistedElGamalTest, KeyGen_PublicKeyIsGeneratorPowSK) {
    EXPECT_EQ(pk.y, pp_std.g.mul_generator(sk.x));
}

TEST_F(TwistedElGamalTest, KeyGen_TwoKeyPairsAreDifferent) {
    EXPECT_NE(pk.y, pk2.y);
}

// ============================================================
// 3. Standard Encrypt / Decrypt  (ECPoint message)
// ============================================================

TEST_F(TwistedElGamalTest, Standard_EncryptDecrypt_RandomPoint) {
    ECPoint m = pp_std.group_ctx->gen_random();
    EXPECT_EQ(decrypt(sk, encrypt(pp_std, pk, m)), m);
}

TEST_F(TwistedElGamalTest, Standard_EncryptDecrypt_Generator) {
    EXPECT_EQ(decrypt(sk, encrypt(pp_std, pk, pp_std.g)), pp_std.g);
}

TEST_F(TwistedElGamalTest, Standard_EncryptDecrypt_Infinity) {
    ECPoint inf = pp_std.group_ctx->get_infinity();
    EXPECT_EQ(decrypt(sk, encrypt(pp_std, pk, inf)), inf);
}

TEST_F(TwistedElGamalTest, Standard_DeterministicWithFixedRandomness) {
    ECPoint   m = pp_std.group_ctx->gen_random();
    ZnElement r = pp_std.field_ctx->gen_random();
    EXPECT_EQ(encrypt(pp_std, pk, m, r), encrypt(pp_std, pk, m, r));
}

TEST_F(TwistedElGamalTest, Standard_FreshEncryptionsAreProbabilistic) {
    ECPoint m = pp_std.group_ctx->gen_random();
    EXPECT_NE(encrypt(pp_std, pk, m), encrypt(pp_std, pk, m));
}

TEST_F(TwistedElGamalTest, Standard_WrongKeyDecryptionFails) {
    ECPoint m = pp_std.group_ctx->gen_random();
    EXPECT_NE(decrypt(sk2, encrypt(pp_std, pk, m)), m);
}

// ============================================================
// 4. Exponential Encrypt / Decrypt  (ZnElement message + BSGS)
// ============================================================

TEST_F(TwistedElGamalExpTest, Exponential_EncryptDecrypt_Zero) {
    ZnElement m(pp_exp.field_ctx, BigInt(0ULL));
    ZnElement md = decrypt_exp(pp_exp, sk_exp,
                               encrypt(pp_exp, pk_exp, m), *solver);
    EXPECT_EQ(md.value, m.value);
}

TEST_F(TwistedElGamalExpTest, Exponential_EncryptDecrypt_One) {
    ZnElement m(pp_exp.field_ctx, BigInt(1ULL));
    ZnElement md = decrypt_exp(pp_exp, sk_exp,
                               encrypt(pp_exp, pk_exp, m), *solver);
    EXPECT_EQ(md.value, m.value);
}

TEST_F(TwistedElGamalExpTest, Exponential_EncryptDecrypt_MaxValue) {
    ZnElement m(pp_exp.field_ctx, BigInt((1ULL << MSG_BITS) - 1));
    ZnElement md = decrypt_exp(pp_exp, sk_exp,
                               encrypt(pp_exp, pk_exp, m), *solver);
    EXPECT_EQ(md.value, m.value);
}

TEST_F(TwistedElGamalExpTest, Exponential_EncryptDecrypt_Random) {
    const BigInt range(1ULL << MSG_BITS);
    for (int i = 0; i < 5; ++i) {
        ZnElement m(pp_exp.field_ctx, gen_random_bigint_less_than(range));
        ZnElement md = decrypt_exp(pp_exp, sk_exp,
                                   encrypt(pp_exp, pk_exp, m), *solver);
        EXPECT_EQ(md.value, m.value) << "i=" << i << " m=" << m.value.to_dec();
    }
}

// ============================================================
// 5. Homomorphic Addition
// ============================================================

TEST_F(TwistedElGamalTest, HomoAdd_DecryptsToSumOfMessages) {
    ECPoint m1 = pp_std.group_ctx->gen_random();
    ECPoint m2 = pp_std.group_ctx->gen_random();
    EXPECT_EQ(decrypt(sk, encrypt(pp_std, pk, m1) + encrypt(pp_std, pk, m2)),
              m1 + m2);
}

TEST_F(TwistedElGamalTest, HomoAdd_OperatorMatchesMethod) {
    ECPoint m1 = pp_std.group_ctx->gen_random();
    ECPoint m2 = pp_std.group_ctx->gen_random();
    Ciphertext ct1 = encrypt(pp_std, pk, m1);
    Ciphertext ct2 = encrypt(pp_std, pk, m2);
    EXPECT_EQ(ct1 + ct2, ct1.homo_add(ct2));
}

TEST_F(TwistedElGamalTest, HomoAdd_Commutativity) {
    ECPoint m1 = pp_std.group_ctx->gen_random();
    ECPoint m2 = pp_std.group_ctx->gen_random();
    Ciphertext ct1 = encrypt(pp_std, pk, m1);
    Ciphertext ct2 = encrypt(pp_std, pk, m2);
    EXPECT_EQ(decrypt(sk, ct1 + ct2), decrypt(sk, ct2 + ct1));
}

TEST_F(TwistedElGamalExpTest, HomoAdd_Exponential) {
    // Quarter range ensures sum fits within MSG_BITS
    const BigInt range(1ULL << (MSG_BITS - 2));
    BigInt raw1 = gen_random_bigint_less_than(range);
    BigInt raw2 = gen_random_bigint_less_than(range);

    ZnElement m1(pp_exp.field_ctx, raw1);
    ZnElement m2(pp_exp.field_ctx, raw2);

    Ciphertext ct_sum = encrypt(pp_exp, pk_exp, m1) + encrypt(pp_exp, pk_exp, m2);
    ZnElement  md     = decrypt_exp(pp_exp, sk_exp, ct_sum, *solver);
    ZnElement  expected(pp_exp.field_ctx, raw1 + raw2);
    EXPECT_EQ(md.value, expected.value);
}

// ============================================================
// 6. Homomorphic Subtraction
// ============================================================

TEST_F(TwistedElGamalTest, HomoSub_DecryptsToMessageDifference) {
    ECPoint m1 = pp_std.group_ctx->gen_random();
    ECPoint m2 = pp_std.group_ctx->gen_random();
    EXPECT_EQ(decrypt(sk, encrypt(pp_std, pk, m1) - encrypt(pp_std, pk, m2)),
              m1 - m2);
}

TEST_F(TwistedElGamalTest, HomoSub_SelfCancelToInfinity) {
    ECPoint m = pp_std.group_ctx->gen_random();
    Ciphertext ct = encrypt(pp_std, pk, m);
    EXPECT_TRUE(decrypt(sk, ct - ct).is_at_infinity());
}

TEST_F(TwistedElGamalTest, HomoSub_OperatorMatchesMethod) {
    ECPoint m1 = pp_std.group_ctx->gen_random();
    ECPoint m2 = pp_std.group_ctx->gen_random();
    Ciphertext ct1 = encrypt(pp_std, pk, m1);
    Ciphertext ct2 = encrypt(pp_std, pk, m2);
    EXPECT_EQ(ct1 - ct2, ct1.homo_sub(ct2));
}

// ============================================================
// 7. Homomorphic Scalar Multiplication
// ============================================================

TEST_F(TwistedElGamalTest, HomoMul_DecryptsToScaledMessage) {
    ECPoint   m = pp_std.group_ctx->gen_random();
    ZnElement k = pp_std.field_ctx->gen_random();
    EXPECT_EQ(decrypt(sk, encrypt(pp_std, pk, m) * k), m * k);
}

TEST_F(TwistedElGamalTest, HomoMul_ScalarZeroGivesInfinity) {
    ECPoint   m    = pp_std.group_ctx->gen_random();
    ZnElement zero(pp_std.field_ctx, BigInt(0ULL));
    EXPECT_TRUE(decrypt(sk, encrypt(pp_std, pk, m) * zero).is_at_infinity());
}

TEST_F(TwistedElGamalTest, HomoMul_ScalarOneIsIdentity) {
    ECPoint   m   = pp_std.group_ctx->gen_random();
    ZnElement one(pp_std.field_ctx, BigInt(1ULL));
    EXPECT_EQ(decrypt(sk, encrypt(pp_std, pk, m) * one), m);
}

TEST_F(TwistedElGamalTest, HomoMul_OperatorMatchesMethod) {
    ECPoint   m = pp_std.group_ctx->gen_random();
    ZnElement k = pp_std.field_ctx->gen_random();
    Ciphertext ct = encrypt(pp_std, pk, m);
    EXPECT_EQ(ct * k, ct.homo_mul(k));
}

// ============================================================
// 8. Re-randomization
// ============================================================

TEST_F(TwistedElGamalTest, ReRand_PreservesPlaintext) {
    ECPoint    m       = pp_std.group_ctx->gen_random();
    Ciphertext ct      = encrypt(pp_std, pk, m);
    Ciphertext ct_rand = re_rand(pp_std, pk, ct);
    EXPECT_NE(ct, ct_rand);
    EXPECT_EQ(decrypt(sk, ct_rand), m);
}

TEST_F(TwistedElGamalTest, ReRand_TwiceProducesDifferentCiphertexts) {
    ECPoint m  = pp_std.group_ctx->gen_random();
    Ciphertext ct = encrypt(pp_std, pk, m);
    EXPECT_NE(re_rand(pp_std, pk, ct), re_rand(pp_std, pk, ct));
}

// ============================================================
// 9. Re-encryption
// ============================================================

TEST_F(TwistedElGamalTest, ReEnc_NewKeyDecryptsCorrectly) {
    ECPoint   m = pp_std.group_ctx->gen_random();
    ZnElement r = pp_std.field_ctx->gen_random();
    Ciphertext ct_new = re_enc(pp_std, pk2, sk, encrypt(pp_std, pk, m), r);
    EXPECT_EQ(decrypt(sk2, ct_new), m);
}

TEST_F(TwistedElGamalTest, ReEnc_OldKeyCannotDecrypt) {
    ECPoint   m = pp_std.group_ctx->gen_random();
    ZnElement r = pp_std.field_ctx->gen_random();
    Ciphertext ct_new = re_enc(pp_std, pk2, sk, encrypt(pp_std, pk, m), r);
    EXPECT_NE(decrypt(sk, ct_new), m);
}

// ============================================================
// 10. Multi-Recipient Encryption
// ============================================================

class TwistedElGamalMrTest : public TwistedElGamalTest {
protected:
    static constexpr size_t N = 4;

    void SetUp() override {
        TwistedElGamalTest::SetUp();
        for (size_t i = 0; i < N; ++i) {
            auto [pki, ski] = keygen(pp_exp);
            vec_pk.push_back(pki);
            vec_sk.push_back(ski);
        }
    }

    std::vector<PublicKey> vec_pk;
    std::vector<SecretKey> vec_sk;
};

TEST_F(TwistedElGamalMrTest, MrEncrypt_AllRecipientsDecryptCorrectly) {
    ZnElement    m(pp_exp.field_ctx, BigInt(12345ULL));
    MrCiphertext ct       = encrypt(pp_exp, vec_pk, m);
    ECPoint      expected = pp_exp.h * m;

    ASSERT_EQ(ct.vec_c1.size(), N);
    for (size_t i = 0; i < N; ++i) {
        EXPECT_EQ(decrypt(vec_sk[i], ct, i), expected) << "recipient=" << i;
    }
}

TEST_F(TwistedElGamalMrTest, MrEncrypt_WrongIndexGivesWrongResult) {
    ZnElement    m(pp_exp.field_ctx, BigInt(42ULL));
    MrCiphertext ct = encrypt(pp_exp, vec_pk, m);
    EXPECT_NE(decrypt(vec_sk[0], ct, 0), decrypt(vec_sk[0], ct, 1));
}

TEST_F(TwistedElGamalMrTest, MrEncrypt_DeterministicWithFixedR) {
    ZnElement m(pp_exp.field_ctx, BigInt(99ULL));
    ZnElement r = pp_exp.field_ctx->gen_random();
    EXPECT_EQ(encrypt(pp_exp, vec_pk, m, r), encrypt(pp_exp, vec_pk, m, r));
}

// ============================================================
// 11. Serialization
// ============================================================

TEST_F(TwistedElGamalTest, Serialization_Ciphertext_RoundTrip) {
    ECPoint    m  = pp_std.group_ctx->gen_random();
    Ciphertext ct = encrypt(pp_std, pk, m);

    std::ostringstream oss;
    oss << ct;

    Ciphertext ct2;
    ct2.c1 = ECPoint(pp_std.group_ctx);
    ct2.c2 = ECPoint(pp_std.group_ctx);
    std::istringstream iss(oss.str());
    iss >> ct2;

    EXPECT_EQ(ct, ct2);
    EXPECT_EQ(decrypt(sk, ct2), m);
}

TEST_F(TwistedElGamalMrTest, Serialization_MrCiphertext_RoundTrip) {
    ZnElement    m  = ZnElement(pp_exp.field_ctx, BigInt(777ULL));
    MrCiphertext ct = encrypt(pp_exp, vec_pk, m);

    std::ostringstream oss;
    oss << ct;

    MrCiphertext ct2;
    for (size_t i = 0; i < N; ++i) ct2.vec_c1.emplace_back(pp_exp.group_ctx);
    ct2.c2 = ECPoint(pp_exp.group_ctx);
    std::istringstream iss(oss.str());
    iss >> ct2;

    EXPECT_EQ(ct, ct2);
}

// ============================================================
// 12. Combined Homomorphic Operations
// ============================================================

TEST_F(TwistedElGamalTest, HomoCombined_ScaleAfterAdd) {
    ECPoint   m1 = pp_std.group_ctx->gen_random();
    ECPoint   m2 = pp_std.group_ctx->gen_random();
    ZnElement k  = pp_std.field_ctx->gen_random();
    Ciphertext ct1 = encrypt(pp_std, pk, m1);
    Ciphertext ct2 = encrypt(pp_std, pk, m2);
    EXPECT_EQ(decrypt(sk, (ct1 + ct2) * k), (m1 + m2) * k);
}

TEST_F(TwistedElGamalTest, HomoCombined_AddThenSubCancel) {
    ECPoint m1 = pp_std.group_ctx->gen_random();
    ECPoint m2 = pp_std.group_ctx->gen_random();
    Ciphertext ct1 = encrypt(pp_std, pk, m1);
    Ciphertext ct2 = encrypt(pp_std, pk, m2);
    EXPECT_EQ(decrypt(sk, (ct1 + ct2) - ct2), m1);
}