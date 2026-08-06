/****************************************************************************
 * @file      dlog_equality.cpp
 * @brief     Non-interactive discrete-log equality proof implementation.
 * @author    This file is part of Taihang-Protocols, developed by Yu Chen.
 *****************************************************************************/

#include <taihang/zkp/sigma_protocols/dlog_equality.hpp>

#include <ios>
#include <istream>
#include <ostream>
#include <sstream>

namespace taihang::zkp::nizk::dlog_equality {

PublicParameters setup(int curve_id) {
    PublicParameters pp;
    pp.curve_id = curve_id;
    pp.group_ctx = std::make_shared<ECGroup>(curve_id);
    pp.ring_ctx = std::make_shared<Zn>(pp.group_ctx->order);
    return pp;
}

bool Proof::operator==(const Proof& other) const {
    return c1 == other.c1 && c2 == other.c2 && z == other.z;
}

std::ostream& operator<<(std::ostream& os, const Proof& proof) {
    return os << proof.c1 << proof.c2 << proof.z;
}

std::istream& operator>>(std::istream& is, Proof& proof) {
    is >> proof.c1 >> proof.c2 >> proof.z;
    return is;
}

Proof prove(const PublicParameters& pp,
            const Statement& statement,
            const Witness& witness,
            std::string_view context) {
                
    const ZnElement r = pp.ring_ctx->gen_random();
    ECPoint c1 = statement.g1 * r;
    ECPoint c2 = statement.g2 * r;
    std::ostringstream input;
    input.write(context.data(), static_cast<std::streamsize>(context.size()));
    input << statement.g1 << statement.h1 << statement.g2 << statement.h2 << c1 << c2;
    const std::string transcript = input.str();
    const ZnElement e = hash_to_zn(transcript, *pp.ring_ctx); // challenge
    const ZnElement z = r + e * witness.w;
    return {std::move(c1), std::move(c2), z};
}

bool verify(const PublicParameters& pp,
            const Statement& statement,
            const Proof& proof,
            std::string_view context) {

    std::ostringstream input;
    input.write(context.data(), static_cast<std::streamsize>(context.size()));
    input << statement.g1 << statement.h1 << statement.g2 << statement.h2 << proof.c1 << proof.c2;
    const std::string transcript = input.str();
    const ZnElement e = hash_to_zn(transcript, *pp.ring_ctx); // challenge
    return statement.g1 * proof.z == proof.c1 + statement.h1 * e &&
           statement.g2 * proof.z == proof.c2 + statement.h2 * e;
}

} // namespace taihang::zkp::nizk::dlog_equality
