#include <gtest/gtest.h>
#include <taihang/pke/elgamal.hpp>
#include <taihang/algorithm/bsgs_dlog.hpp>
#include <taihang/crypto/ec_group.hpp>
#include <taihang/crypto/zn.hpp>
#include <taihang/common/check.hpp>
#include <openssl/obj_mac.h>

using namespace taihang;
using namespace taihang::pke::elgamal;
using namespace taihang::dlog;

class ElGamalTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Use P-256 for standard tests
        pp = setup(NID_X9_62_prime256v1, 0);
        auto keys = keygen(pp);
        pk = keys.first;
        sk = keys.second;
    }

    PublicParameters pp;
    PublicKey pk;
    SecretKey sk;
};

// --- Standard ElGamal (Point Payload) ---

TEST_F(ElGamalTest, StandardEncryptionDecryption) {
    ECPoint m = pp.group_ctx->gen_random();
    
    Ciphertext ct = encrypt(pp, pk, m);
    ECPoint m_dec = decrypt(sk, ct);

    ASSERT_EQ(m, m_dec) << "Decrypted point does not match original message.";
}

TEST_F(ElGamalTest, ReRandomization) {
    ECPoint m = pp.group_ctx->gen_random();
    Ciphertext ct1 = encrypt(pp, pk, m);
    
    // Re-randomize
    Ciphertext ct2 = re_rand(pp, pk, ct1);

    // Ciphertexts should be different (probabilistic)
    ASSERT_FALSE(ct1 == ct2);

    // Decryption should still work
    ECPoint m_dec = decrypt(sk, ct2);
    ASSERT_EQ(m, m_dec);
}

// --- Exponential ElGamal (Scalar Payload) ---

TEST_F(ElGamalTest, ExponentialEncryptionDecryption) {
    // 1. Setup DLog Solver (You already have this)
    size_t range_bits = 16;
    BSGSConfig config = {range_bits, 0, 4};
    BSGSSolver solver(*pp.group_ctx, pp.g, config);
    solver.build_and_save_table();
    solver.construct_hashmap_from_table(solver.get_table_filename());

    // 2. DELETE the 'DLogSolver callback' block entirely. 
    // It is no longer needed.

    // 3. Setup Message
    ZnElement m = ZnElement(pp.field_ctx, BigInt(12345)); 
    
    // 4. Encrypt
    Ciphertext ct = encrypt(pp, pk, m);
    
    // 5. Decrypt
    // FIX: Pass 'solver' directly. The compiler is now happy!
    ZnElement m_dec = decrypt_exp(pp, sk, ct, solver);

    ASSERT_EQ(m, m_dec);
}

TEST_F(ElGamalTest, HomomorphicAddSub) {
    // We verify: Enc(m1) + Enc(m2) == Enc(m1 + m2)
    // Works on the exponents (Exponential mode)
    
    ZnElement m1 = ZnElement(pp.field_ctx, BigInt(100));
    ZnElement m2 = ZnElement(pp.field_ctx, BigInt(50));
    
    Ciphertext ct1 = encrypt(pp, pk, m1);
    Ciphertext ct2 = encrypt(pp, pk, m2);

    // Addition
    Ciphertext ct_sum = ct1 + ct2;
    ECPoint pt_sum = decrypt(sk, ct_sum); // Decrypt to point g^(m1+m2)
    ECPoint expected_sum = pp.g * (m1 + m2);
    ASSERT_EQ(pt_sum, expected_sum);

    // Subtraction
    Ciphertext ct_diff = ct1 - ct2;
    ECPoint pt_diff = decrypt(sk, ct_diff);
    ECPoint expected_diff = pp.g * (m1 - m2);
    ASSERT_EQ(pt_diff, expected_diff);
}

TEST_F(ElGamalTest, HomomorphicScalarMul) {
    // Enc(m) * k == Enc(m * k)
    ZnElement m = ZnElement(pp.field_ctx, BigInt(100));
    ZnElement k = ZnElement(pp.field_ctx, BigInt(3)); 

    Ciphertext ct = encrypt(pp, pk, m);
    Ciphertext ct_scaled = ct * k;

    ECPoint pt_scaled = decrypt(sk, ct_scaled);
    ECPoint expected = pp.g * (m * k);
    ASSERT_EQ(pt_scaled, expected);
}

// --- Multi-Recipient ---

TEST_F(ElGamalTest, MultiRecipientEncryption) {
    size_t num_recipients = 5;
    std::vector<PublicKey> pks;
    std::vector<SecretKey> sks;

    for(size_t i=0; i<num_recipients; ++i) {
        auto pair = keygen(pp);
        pks.push_back(pair.first);
        sks.push_back(pair.second);
    }

    ZnElement m = ZnElement(pp.field_ctx, BigInt(999));
    
    // Encrypt once for all
    MrCiphertext mr_ct = encrypt(pp, pks, m);

    // Verify each recipient can decrypt
    ECPoint expected_pt = pp.g * m; // g^m

    for(size_t i=0; i<num_recipients; ++i) {
        ECPoint dec = decrypt(sks[i], mr_ct, i);
        ASSERT_EQ(dec, expected_pt) << "Recipient " << i << " failed to decrypt";
    }
}

// --- Serialization ---

TEST_F(ElGamalTest, Serialization) {
    ECPoint m = pp.group_ctx->gen_random();
    Ciphertext ct = encrypt(pp, pk, m);

    std::stringstream ss;
    ss << ct;

    Ciphertext ct_loaded;
    // Note: ct_loaded needs context if ECPoint default constructor doesn't provide it implicitly correctly
    // But since serialization writes points, usually deserializer handles it if format is standard.
    // However, ECPoint deserialization relies on having a group. 
    // ct_loaded members are default constructed (default group). P-256 is default so it works.
    ct_loaded.c1 = ECPoint(pp.group_ctx);
    ct_loaded.c2 = ECPoint(pp.group_ctx);
    
    ss >> ct_loaded;

    ASSERT_EQ(ct, ct_loaded);
}