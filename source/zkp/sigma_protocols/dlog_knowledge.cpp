/****************************************************************************
 * @file      dlog_knowledge.cpp
 * @brief     Non-interactive Schnorr proof implementation.
 * @author    This file is part of Taihang-Protocols, developed by Yu Chen.
 *****************************************************************************/

#include <taihang/zkp/sigma_protocols/dlog_knowledge.hpp>

#include <ios>
#include <istream>
#include <ostream>
#include <sstream>

namespace taihang::zkp::nizk::dlog_knowledge {

PublicParameters setup(int curve_id) {
    PublicParameters pp;
    pp.curve_id = curve_id;
    pp.group_ctx = std::make_shared<ECGroup>(curve_id);
    pp.ring_ctx = std::make_shared<Zn>(pp.group_ctx->order);
    return pp;
}

bool Proof::operator==(const Proof& other) const {
    return c == other.c && z == other.z;
}

std::ostream& operator<<(std::ostream& os, const Proof& proof) {
    return os << proof.c << proof.z;
}

std::istream& operator>>(std::istream& is, Proof& proof) {
    is >> proof.c >> proof.z;
    return is;
}

Proof prove(const PublicParameters& pp,
            const Statement& statement,
            const Witness& witness,
            std::string_view context) {
    const ZnElement a = pp.ring_ctx->gen_random();
    ECPoint c = statement.g * a;

    std::ostringstream transcript;
    transcript.write(context.data(), static_cast<std::streamsize>(context.size()));
    transcript << statement.g << statement.h << c;
    const ZnElement e = hash_to_zn(transcript.str(), *pp.ring_ctx);
    const ZnElement z = a + e * witness.w;
    return {std::move(c), z};
}

bool verify(const PublicParameters& pp,
            const Statement& statement,
            const Proof& proof,
            std::string_view context) {
    std::ostringstream transcript;
    transcript.write(context.data(), static_cast<std::streamsize>(context.size()));
    transcript << statement.g << statement.h << proof.c;
    const ZnElement e = hash_to_zn(transcript.str(), *pp.ring_ctx);
    return statement.g * proof.z == proof.c + statement.h * e;
}

} // namespace taihang::zkp::nizk::dlog_knowledge
