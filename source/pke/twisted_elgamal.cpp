/****************************
 * @file      twisted_elgamal.cpp
 * @brief     Implementation of ECC-based twisted ElGamal PKE scheme.
 * @author    This file is part of Taihang-Protocols, developed by Yu Chen.
 ****************************/

#include <taihang/common/check.hpp>
#include <taihang/pke/twisted_elgamal.hpp>

namespace taihang::pke::twisted_elgamal {

// --- PublicParameters ---
std::string PublicParameters::format() const {
    std::ostringstream oss; 
    oss << "[PublicParameters] \n"
        << "Curve ID: " << curve_id << "\n"
        << "Mode: " << (msg_len_bits == 0 ? "Standard" : "Exponential") << "\n"
        << "Base point g = " << g.to_string() << "\n"
        << "Base Point h = " << h.to_string() << "\n";
    return oss.str();
}

std::ostream& operator<<(std::ostream& os, const PublicParameters& pp) {
    // We serialize the ID and bits. The ECGroup is reconstructed on load.
    os << pp.curve_id << pp.msg_len_bits << pp.g;
    return os;
}

std::istream& operator>>(std::istream& is, PublicParameters& pp) {
    if (!(is >> pp.curve_id >> pp.msg_len_bits)) return is; 

    // Reconstruct contexts based on the received curve ID
    pp.group_ctx = std::make_shared<ECGroup>(pp.curve_id);
    pp.field_ctx = std::make_shared<Zn>(pp.group_ctx->order);
    
    pp.g = ECPoint(pp.group_ctx);
    pp.h = ECPoint(pp.group_ctx);
    is >> pp.g; // Binary read for ECPoint (Octets)
    is >> pp.h; 

    // Safety check for shift
    if (pp.msg_len_bits > 0 && pp.msg_len_bits < 64) {
        pp.msg_size = BigInt(1ULL << pp.msg_len_bits);
    } else {
        pp.msg_size = BigInt(0ULL);
    }

    return is;
}

// --- Ciphertext ---

std::string Ciphertext::format() const {
    std::ostringstream oss; 
    oss << "[Twisted ElGamal Ciphertext] \n"
        << "c1 = " << c1.to_string()
        << "c2 = " << c2.to_string() << "\n";
    return oss.str();
}

Ciphertext Ciphertext::homo_add(const Ciphertext& other) const{
    return { this->c1 + other.c1, this->c2 + other.c2 };
}

Ciphertext Ciphertext::homo_sub(const Ciphertext& other) const{
    return { this->c1 - other.c1, this->c2 - other.c2 };
}

Ciphertext Ciphertext::homo_mul(const ZnElement& k) const{
    return { this->c1 * k, this->c2 * k };
}

Ciphertext Ciphertext::operator+(const Ciphertext& other) const {
    return homo_add(other);
}

Ciphertext Ciphertext::operator-(const Ciphertext& other) const {
    return homo_sub(other);
}

Ciphertext Ciphertext::operator*(const ZnElement& scalar) const {
    return homo_mul(scalar);
}

bool Ciphertext::operator==(const Ciphertext& other) const {
    return (this->c1 == other.c1) && (this->c2 == other.c2);
}

std::ostream& operator<<(std::ostream& os, const Ciphertext& ct) {
    os << ct.c1 << ct.c2;
    return os;
}

std::istream& operator>>(std::istream& is, Ciphertext& ct) {
    is >> ct.c1 >> ct.c2;
    return is;
}

// --- MrCiphertext ---
std::string MrCiphertext::format() const {
    std::ostringstream oss; 
    oss << "[Twisted ElGamal Multi-Recipient Ciphertext] \n";
    oss << "c2 (Common) = " << c2.to_string() << "\n";
    for (size_t i = 0; i < vec_c1.size(); ++i) {
        oss << "c1[" + std::to_string(i) + "] = " << vec_c1[i].to_string() << "\n";
    }
    return oss.str();
}

bool MrCiphertext::operator==(const MrCiphertext& other) const {
    if (vec_c1.size() != other.vec_c1.size()) return false;
    for (size_t i = 0; i < vec_c1.size(); ++i) {
        if (vec_c1[i] != other.vec_c1[i]) return false;
    }
    return c2 == other.c2;
}
// --- Algorithms ---

PublicParameters setup(int curve_id, size_t msg_len_bits) {
    PublicParameters pp;
    pp.curve_id = curve_id;

    // Allocate contexts with stable addresses
    pp.group_ctx = std::make_shared<ECGroup>(pp.curve_id);
    pp.field_ctx = std::make_shared<Zn>(pp.group_ctx->order); 
    pp.g = pp.group_ctx->get_generator();
    pp.h = hash_to_curve_fast(pp.g.to_string(), *pp.group_ctx);

    pp.msg_len_bits = msg_len_bits;
    pp.msg_size = (msg_len_bits > 0) ? (BigInt(1ULL << msg_len_bits)) : BigInt(0ULL);
    return pp;
}

std::pair<PublicKey, SecretKey> keygen(const PublicParameters& pp) {
    ZnElement x = pp.field_ctx->gen_random();
    // ECPoint h = pp.g * x;
    ECPoint y = pp.g.mul_generator(x);
    return {PublicKey{y}, SecretKey{x}};
}

Ciphertext encrypt(const PublicParameters& pp, const PublicKey& pk, const ECPoint& m, const std::optional<ZnElement>& r) {
    ZnElement r_effective = r.has_value() ? *r : pp.field_ctx->gen_random();
    // Returning the object directly using a braced-init-list (the {...} syntax)
    // the compiler performs Return Value Optimization (RVO)
    // return { pp.g * r_effective, (pk.h * r_effective) + m };
    return { pk.y * r_effective, pp.g.mul_generator(r_effective) + m };
}

Ciphertext encrypt(const PublicParameters& pp, const PublicKey& pk, const ZnElement& m, const std::optional<ZnElement>& r) {
    ZnElement r_effective = r.has_value() ? *r : pp.field_ctx->gen_random();
    // Y = pk^k + g^m
    // return { pp.g * r_effective, pk * r_effective + pp.g * m};
    // return { pp.g * r_effective, ec_point_msm({pk.h, pp.g}, {r_effective, m}) }; 

    // c1 = g^r
    ECPoint c1 = pk.y * r_effective;
    // c2 = pk^r + g^m
    // We use ec_point_msm because it's significantly faster for 2 points
    ECPoint c2 = ec_point_msm({pp.g, pp.h}, {r_effective, m});
    
    return { std::move(c1), std::move(c2) };
}

MrCiphertext encrypt(const PublicParameters& pp, const std::vector<PublicKey>& vec_pk, 
                     const ZnElement& m, const std::optional<ZnElement>& r) {
    ZnElement r_effective = r.has_value() ? *r : pp.field_ctx->gen_random();
    MrCiphertext ct;
    // Shared Randomness c1 = g^r
   
    // c1[i] = pk[i]^r
    for (const auto& pk : vec_pk) {
        ct.vec_c1.push_back(pk.y * r_effective);
    }
    // c2 = pk.g^r + h^m
    ct.c2 = ec_point_msm({pp.g, pp.h}, {r_effective, m}); 
    return ct;
}

// Decrypt specific index from MR-Ciphertext: m = c2_i - x*c1
ECPoint decrypt(const SecretKey& sk, const MrCiphertext& ct, size_t index) {
    TAIHANG_ASSERT(index < ct.vec_c1.size(), "Multi-recipient decrypt: index out of bounds");
    return ct.c2 - (ct.vec_c1[index] * sk.x.inv());
}

std::ostream& operator<<(std::ostream& os, const MrCiphertext& ct) {
    for (const auto& c1 : ct.vec_c1) os << c1;
    os << ct.c2;  
    return os;
}

std::istream& operator>>(std::istream& is, MrCiphertext& ct) {
    for (size_t i = 0; i < ct.vec_c1.size(); ++i) is >> ct.vec_c1[i];
    is >> ct.c2; 
    return is;
}

ECPoint decrypt_raw(const SecretKey& sk, const Ciphertext& ct) {
    return ct.c2 - (ct.c1 * sk.x.inv());
}

ZnElement decrypt_exp(const PublicParameters& pp, const SecretKey& sk, const Ciphertext& ct, const dlog::BSGSSolver& solver) {
    ECPoint m = decrypt_raw(sk, ct);
    auto result = solver.solve(m);
    // Ensure the solver actually found a result
    TAIHANG_ASSERT(result.has_value(), "ElGamal: BSGS DLog solver failed to find message.");
    
    // Convert the BigInt result into a ZnElement (the scalar field element)
    return ZnElement(pp.field_ctx, result.value());
}

Ciphertext re_enc(const PublicParameters& pp, const PublicKey& pk, const SecretKey& sk, const Ciphertext& ct, const ZnElement& r) {
    ECPoint m = decrypt_raw(sk, ct);
    return { pk.y * r, (pp.g * r) + m };
}

Ciphertext re_rand(const PublicParameters& pp, const PublicKey& pk, const Ciphertext& ct) {
    ZnElement r = pp.field_ctx->gen_random();
    return { ct.c1 + (pk.y * r), ct.c2 + (pp.g * r) };
}

} // namespace taihang::pke::twisted_elgamal