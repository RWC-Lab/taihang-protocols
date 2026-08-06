/****************************************************************************
 * @file      twisted_elgamal_plaintext_equality.cpp
 * @brief     NIZK proof of multi-recipient twisted-ElGamal plaintext equality.
 *****************************************************************************/

#include <taihang/zkp/sigma_protocols/twisted_elgamal_plaintext_equality.hpp>

#include <cstdint>
#include <ios>
#include <istream>
#include <limits>
#include <ostream>
#include <sstream>
#include <utility>

namespace taihang::zkp::nizk::twisted_elgamal_plaintext_equality {

PublicParameters setup(const pke::twisted_elgamal::PublicParameters& encryption_pp) {
    return {encryption_pp.curve_id,
            encryption_pp.group_ctx,
            encryption_pp.ring_ctx,
            encryption_pp.g,
            encryption_pp.h};
}

bool Proof::operator==(const Proof& other) const {
    return vec_c1 == other.vec_c1 && c2 == other.c2 && z == other.z && t == other.t;
}

std::ostream& operator<<(std::ostream& os, const Proof& proof) {
    const std::uint64_t count = static_cast<std::uint64_t>(proof.vec_c1.size());
    os.write(reinterpret_cast<const char*>(&count), sizeof(count));
    for (const auto& point : proof.vec_c1) os << point;
    return os << proof.c2 << proof.z << proof.t;
}

std::istream& operator>>(std::istream& is, Proof& proof) {
    std::uint64_t count = 0;
    if (!is.read(reinterpret_cast<char*>(&count), sizeof(count))) return is;
    if (count > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
        is.setstate(std::ios::failbit);
        return is;
    }
    proof.vec_c1.clear();
    proof.vec_c1.reserve(static_cast<std::size_t>(count));
    for (std::uint64_t i = 0; i < count && is; ++i) {
        ECPoint point(proof.c2.group_ctx);
        is >> point;
        if (is) proof.vec_c1.push_back(std::move(point));
    }
    if (is) is >> proof.c2 >> proof.z >> proof.t;
    return is;
}

Proof prove(const PublicParameters& pp,
            const Statement& statement,
            const Witness& witness,
            std::string_view context) {
    const ZnElement a = pp.ring_ctx->gen_random();
    const ZnElement b = pp.ring_ctx->gen_random();
    std::vector<ECPoint> vec_c1;
    vec_c1.reserve(statement.vec_pk.size());
    for (const auto& pk : statement.vec_pk) vec_c1.push_back(pk * a);
    ECPoint c2 = ec_point_msm({pp.g, pp.h}, {a, b});
    std::ostringstream transcript;
    transcript.write(context.data(), static_cast<std::streamsize>(context.size()));
    for (const auto& pk : statement.vec_pk) transcript << pk;
    for (const auto& point : statement.ct.vec_c1) transcript << point;
    transcript << statement.ct.c2;
    for (const auto& point : vec_c1) transcript << point;
    transcript << c2;
    const ZnElement e = hash_to_zn(transcript.str(), *pp.ring_ctx);
    return {std::move(vec_c1), std::move(c2), a + e * witness.r, b + e * witness.v};
}

bool verify(const PublicParameters& pp,
            const Statement& statement,
            const Proof& proof,
            std::string_view context) {
    std::ostringstream transcript;
    transcript.write(context.data(), static_cast<std::streamsize>(context.size()));
    for (const auto& pk : statement.vec_pk) transcript << pk;
    for (const auto& point : statement.ct.vec_c1) transcript << point;
    transcript << statement.ct.c2;
    for (const auto& point : proof.vec_c1) transcript << point;
    transcript << proof.c2;
    const ZnElement e = hash_to_zn(transcript.str(), *pp.ring_ctx);
    if (statement.vec_pk.size() != statement.ct.vec_c1.size() ||
        statement.vec_pk.size() != proof.vec_c1.size()) {
        return false;
    }
    for (std::size_t i = 0; i < statement.vec_pk.size(); ++i) {
        if (statement.vec_pk[i] * proof.z !=
            proof.vec_c1[i] + statement.ct.vec_c1[i] * e) {
            return false;
        }
    }
    const ECPoint left = ec_point_msm({pp.g, pp.h}, {proof.z, proof.t});
    const ECPoint right = proof.c2 + statement.ct.c2 * e;
    return left == right;
}

} // namespace taihang::zkp::nizk::twisted_elgamal_plaintext_equality
