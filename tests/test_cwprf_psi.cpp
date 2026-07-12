/****************************************************************************
 * @file      cwprf_psi.cpp
 * @brief     Implementation of cwPRF-based two-party PSI.
 * @details   See cwprf_psi.hpp for the protocol description, security
 *            references, and the rationale for why only index-preserving
 *            MembershipMode backends (Truncate, PlainSet) are offered.
 *
 *            Structure of this file:
 *              1. PublicParameters helpers (format / serialize / setup)
 *              2. Internal helpers (truncation)
 *              3. sender() — split into a NormalCurve branch (ECPoint /
 *                 ECGroup) and an X25519 branch (EC25519Point), selected at
 *                 runtime via pp.curve_id == NID_X25519, following the same
 *                 dispatch convention used in taihang::mpc::cwprf_mqrpmt.
 *              4. receiver() — mirrors the same two branches.
 *
 *            The Sender ships information about its doubly-masked X-side values,
 *            F_k1k2(x_i), in an array indexed identically to the Receiver's
 *            own vec_x. The Receiver builds a lookup structure from its own
 *            Y-side values F_k2k1(y_j) and tests each received element
 *            against it; a match at wire-position i is reported as
 *            vec_x[i]. This index alignment is what allows PSI (unlike
 *            cwprf_mqrpmt) to recover actual intersection elements rather
 *            than an opaque indication bit.
 *
 * @author    This file is part of Taihang, developed by Yu Chen.
 *****************************************************************************/

#include <taihang/mpc/psi/cwprf_psi.hpp>
#include <taihang/common/logger.hpp>
#include <format>
#include <chrono>
#include <cmath>
#include <omp.h>
#include <unordered_set>
#include <openssl/obj_mac.h>   // NID_X25519
#include <openssl/rand.h>      // RAND_bytes

namespace taihang::mpc::cwprf_psi {

// ===========================================================================
// PublicParameters helpers
// ===========================================================================

std::string PublicParameters::format() const {
    std::ostringstream oss;
    oss << "[cwPRF-based PSI PublicParameters]\n";
    oss << "Curve ID               :" << curve_id << "\n";
    oss << "log2(sender set size)  :" << log_sender_len << "\n";
    oss << "log2(receiver set size)  :" << log_receiver_len << "\n";
    oss << "Membership-test mode   :"
        << (membership_mode == MembershipMode::Truncate ? "Truncate" : "PlainSet") << "\n";

    if (membership_mode == MembershipMode::Truncate) {
        oss << "Statistical security parameter : " << statistical_security_parameter << "\n";
        oss << "Truncated PRF output length    : " << truncate_byte_len << " bytes\n";
    }
    return oss.str();
}

// Serialisation layout (whitespace separated):
//   curve_id  log_sender_len  log_receiver_len  membership_mode  ssp  truncate_byte_len
// membership_mode is stored as its underlying integer: 0 = Truncate, 1 = PlainSet.
std::ostream& operator<<(std::ostream& os, const PublicParameters& pp) {
    os << pp.curve_id                            << " "
       << pp.log_sender_len                      << " "
       << pp.log_receiver_len                    << " "
       << static_cast<int>(pp.membership_mode)   << " "; 
    if (pp.membership_mode == MembershipMode::Truncate){    
       os << pp.statistical_security_parameter << " "
          << pp.truncate_byte_len;
    }
    
    return os;
}

std::istream& operator>>(std::istream& is, PublicParameters& pp) {
    int mode_int = 0;
    is >> pp.curve_id
       >> pp.log_sender_len
       >> pp.log_receiver_len
       >> mode_int; 

    pp.membership_mode = static_cast<MembershipMode>(mode_int);
    
    if (pp.membership_mode == MembershipMode::Truncate){
        is >> pp.statistical_security_parameter
           >> pp.truncate_byte_len;
    }  

    // Reconstruct contexts with stable heap addresses.
    // X25519 uses no ECGroup/Zn context at all (mirrors cwprf_mqrpmt).
    if (pp.curve_id != NID_X25519) {
        pp.group_ctx = std::make_shared<ECGroup>(pp.curve_id);
        pp.field_ctx = std::make_shared<Zn>(pp.group_ctx->order);
    } else {
        pp.group_ctx = nullptr;
        pp.field_ctx = nullptr;
    }
    return is;
}

// ===========================================================================
// setup
// ===========================================================================

PublicParameters setup(int    curve_id,
                       size_t log_sender_len,
                       size_t log_receiver_len,
                       MembershipMode mode,
                       std::optional<size_t> statistical_security_parameter) {
    PublicParameters pp;
    pp.curve_id = curve_id;

    if (curve_id != NID_X25519) {
        pp.group_ctx = std::make_shared<ECGroup>(pp.curve_id);
        pp.field_ctx = std::make_shared<Zn>(pp.group_ctx->order);
    } else {
        pp.group_ctx = nullptr;
        pp.field_ctx = nullptr;
    }

    pp.log_sender_len = log_sender_len;
    pp.log_receiver_len = log_receiver_len;
    pp.membership_mode = mode;

    if (mode == MembershipMode::Truncate) {
        TAIHANG_ASSERT(statistical_security_parameter.has_value(),
            "cwprf_psi::setup: Truncate mode requires statistical_security_parameter.");
        pp.statistical_security_parameter = statistical_security_parameter.value();

        // Classical cwPRF-PSI truncation length: lambda + log(n1) + log(n2) bits,
        // rounded up to whole bytes.
        // Reference: [CRYPTO 2019 - SpOT: Lightweight PSI from Sparse OT Extension].
        size_t truncate_bit_len =
            pp.statistical_security_parameter + log_sender_len + log_receiver_len;
            pp.truncate_byte_len = (truncate_bit_len + 7) / 8;
    } 
    else {
        // PlainSet: full-length values are sent; truncation is not used.
        pp.statistical_security_parameter = 0;
        pp.truncate_byte_len = 0;
    }

    return pp;
}

// ===========================================================================
// Internal helpers shared by sender() and receiver()
// ===========================================================================

/**
 * @brief Truncates a serialized point's byte representation to the first
 *        `len` bytes and returns it as a binary std::string suitable for
 *        use as an unordered_set key.
 *
 * @details This is the byte-level core of MembershipMode::Truncate: only
 *          the leading `len` bytes of the (already pseudorandom, by the
 *          DH-extraction argument cited in cwprf_psi.hpp) point encoding
 *          are retained, both to save bandwidth and because the leading
 *          bytes alone already provide lambda + log(n1) + log(n2) bits of
 *          collision resistance for this protocol's correctness needs.
 */
inline std::string truncate_to_string(const std::vector<uint8_t>& full_bytes, size_t len) {
    TAIHANG_ASSERT(full_bytes.size() >= len,
        "cwprf_psi: truncate_byte_len exceeds the point's serialized length.");
    return std::string(reinterpret_cast<const char*>(full_bytes.data()), len);
}

// ===========================================================================
// Sender
// ===========================================================================

void sender(net::NetIO& io, const PublicParameters& pp, const std::vector<Block>& vec_y) {
    TAIHANG_TIMER("cwPRF PSI:", "Sender total execution time");
    TAIHANG_LOG("cwPRF PSI:", "Sender protocol context initiated >>>");

    const size_t sender_len = static_cast<size_t>(std::pow(2, pp.log_sender_len));
    const size_t receiver_len = static_cast<size_t>(std::pow(2, pp.log_receiver_len));

    TAIHANG_ASSERT(sender_len == vec_y.size(), "cwPRF PSI: Sender input size mismatch.");

    // -----------------------------------------------------------------
    // NormalCurve branch: ECPoint / ECGroup (e.g. Secp256r1)
    // -----------------------------------------------------------------
    if (pp.curve_id != NID_X25519) {
        // Pick a secret random exponent key k1 from the Zn scalar field.
        ZnElement k1 = pp.field_ctx->gen_random();

        // Step 1: F_k1(H(y_i)) = H(y_i)^k1
        std::vector<ECPoint> vec_fk1_y(sender_len, pp.group_ctx);
        #pragma omp parallel for num_threads(config::thread_num)
        for (size_t i = 0; i < sender_len; ++i) {
            vec_fk1_y[i] = hash_to_curve_fast(vec_y[i], *pp.group_ctx) * k1;
        }

        TAIHANG_LOG("cwPRF PSI [step 1]:", std::format("Sender ===> F_k1(H(y_i)) ===> Receiver [{:.2f} MB]",
                        static_cast<double>(sender_len * pp.group_ctx->get_point_byte_len()) / (1024 * 1024)));
        io.send(vec_fk1_y);

        // Step 2: receive F_k2(H(x_i)) from Receiver, fold in k1 to obtain
        // the doubly-masked values F_k1(F_k2(x_i)) = H(x_i)^{k1*k2}, which
        // remain index-aligned with the Receiver's own vec_x.
        TAIHANG_LOG("cwPRF PSI [step 2]:", "Sender receives F_k2(H(x_i)) from Receiver...");
        std::vector<ECPoint> vec_fk2_x(receiver_len, pp.group_ctx);
        io.recv(vec_fk2_x);

        std::vector<ECPoint> vec_fk1k2_x(receiver_len, pp.group_ctx);
        #pragma omp parallel for num_threads(config::thread_num)
        for (size_t i = 0; i < receiver_len; ++i) {
            vec_fk1k2_x[i] = vec_fk2_x[i] * k1;
        }

        // Step 3: ship the index-aligned, doubly-masked X values to the
        // Receiver, via the selected MembershipMode, so the Receiver can
        // compute the intersection locally. The Sender learns nothing
        // further about X.
        if (pp.membership_mode == MembershipMode::Truncate) {
            std::vector<std::string> vec_truncated_fk1k2_x(receiver_len);
            for (size_t i = 0; i < receiver_len; ++i) {
                vec_truncated_fk1k2_x[i] = truncate_to_string(vec_fk1k2_x[i].to_bytes(), pp.truncate_byte_len);
            }
            io.send(vec_truncated_fk1k2_x);

            TAIHANG_LOG("cwPRF PSI [step 3]:", std::format("Sender ===> Truncate(F_k1k2(x_i)) ===> Receiver [{:.2f} MB]",
                            static_cast<double>(receiver_len * pp.truncate_byte_len) / (1024 * 1024)));
        } 
        else {
            // PlainSet: send full-length values, still index-aligned with
            // vec_x (no shuffling — shuffling would break attribution).
            io.send(vec_fk1k2_x);

            TAIHANG_LOG("cwPRF PSI [step 3]:", std::format("Sender ===> F_k1k2(x_i) [PlainSet] ===> Receiver [{:.2f} MB]",
                            static_cast<double>(receiver_len * pp.group_ctx->get_point_byte_len()) / (1024 * 1024)));
        }
    }
    // -----------------------------------------------------------------
    // X25519 branch: EC25519Point (Montgomery curve)
    // -----------------------------------------------------------------
    else {
        // Pick a secret random exponent key k1: 32 raw CSPRNG bytes.
        std::vector<uint8_t> k1(EC25519Point::SCALAR_BYTE_LEN);
        TAIHANG_CHECK(RAND_bytes(k1.data(), EC25519Point::SCALAR_BYTE_LEN) == 1,
                      "cwPRF PSI: RAND_bytes failed while generating k1.");

        // Step 1: F_k1(H(y_i)) = H(y_i)^k1
        std::vector<EC25519Point> vec_fk1_y(sender_len);
        #pragma omp parallel for num_threads(config::thread_num)
        for (size_t i = 0; i < sender_len; ++i) {
            vec_fk1_y[i] = hash_to_curve25519(vec_y[i]) * k1;
        }

        TAIHANG_LOG("cwPRF PSI [step 1]:", std::format("Sender ===> F_k1(H(y_i)) ===> Receiver [{:.2f} MB]",
                        static_cast<double>(sender_len * EC25519Point::POINT_BYTE_LEN) / (1024 * 1024)));
        io.send(vec_fk1_y);

        // Step 2: receive F_k2(H(x_i)) from Receiver, fold in k1.
        TAIHANG_LOG("cwPRF PSI [step 2]:", "Sender receives F_k2(H(x_i)) from Receiver ...");
        std::vector<EC25519Point> vec_fk2_x(receiver_len);
        io.recv(vec_fk2_x);

        std::vector<EC25519Point> vec_fk1k2_x(receiver_len);
        #pragma omp parallel for num_threads(config::thread_num)
        for (size_t i = 0; i < receiver_len; ++i) {
            vec_fk1k2_x[i] = vec_fk2_x[i] * k1;
        }

        // Step 3: ship index-aligned, doubly-masked X values to the Receiver.
        if (pp.membership_mode == MembershipMode::Truncate) {
            std::vector<std::string> vec_truncated_fk1k2_x(receiver_len);
            for (size_t i = 0; i < receiver_len; ++i) {
                vec_truncated_fk1k2_x[i] = truncate_to_string(vec_fk1k2_x[i].to_bytes(), pp.truncate_byte_len);
            }
            io.send(vec_truncated_fk1k2_x);

            TAIHANG_LOG("cwPRF PSI [step 3]:", std::format("Sender ===> Truncate(F_k1k2(x_i)) ===> Receiver [{:.2f} MB]",
                            static_cast<double>(receiver_len * pp.truncate_byte_len) / (1024 * 1024)));
        } 
        else {
            io.send(vec_fk1k2_x);

            TAIHANG_LOG("cwPRF PSI [step 3]:", std::format("Sender ===> F_k1k2(x_i) [PlainSet] ===> Receiver [{:.2f} MB]",
                            static_cast<double>(receiver_len * EC25519Point::POINT_BYTE_LEN) / (1024 * 1024)));
        }
    }

    TAIHANG_LOG("cwPRF PSI:", "Sender protocol context successfully completed <<<");
}

// ===========================================================================
// Receiver
// ===========================================================================

std::vector<Block> receiver(net::NetIO& io, const PublicParameters& pp, const std::vector<Block>& vec_x) {
    TAIHANG_TIMER("cwPRF PSI:", "Receiver total execution time");
    TAIHANG_LOG("cwPRF PSI:", "Receiver protocol context initiated >>>");

    const size_t sender_len = static_cast<size_t>(std::pow(2, pp.log_sender_len));
    const size_t receiver_len = static_cast<size_t>(std::pow(2, pp.log_receiver_len));

    TAIHANG_ASSERT(receiver_len == vec_x.size(), "cwPRF PSI: Receiver input size mismatch.");

    std::vector<Block> vec_intersection;
    vec_intersection.reserve(receiver_len);

    // -----------------------------------------------------------------
    // NormalCurve branch: ECPoint / ECGroup (e.g. Secp256r1)
    // -----------------------------------------------------------------
    if (pp.curve_id != NID_X25519) {
        // Pick a secret random exponent key k2 from the Zn scalar field.
        ZnElement k2 = pp.field_ctx->gen_random();

        // Step 1: F_k2(H(x_i)) = H(x_i)^k2
        std::vector<ECPoint> vec_fk2_x(receiver_len, pp.group_ctx);
        #pragma omp parallel for num_threads(config::thread_num)
        for (size_t i = 0; i < receiver_len; ++i) {
            vec_fk2_x[i] = hash_to_curve_fast(vec_x[i], *pp.group_ctx) * k2;
        }

        // Step 2: exchange with Sender.
        TAIHANG_LOG("cwPRF PSI [step 1]:", "Receiver receives F_k1(H(y_i)) from Sender ...");
        std::vector<ECPoint> vec_fk1_y(sender_len, pp.group_ctx);
        io.recv(vec_fk1_y);

        TAIHANG_LOG("cwPRF PSI [step 2]:", std::format("Receiver ===> F_k2(H(x_i)) ===> Sender [{:.2f} MB]",
                        static_cast<double>(receiver_len * pp.group_ctx->get_point_byte_len()) / (1024 * 1024)));
        io.send(vec_fk2_x);

        // Step 3: F_k2k1(y_j) = (F_k1(y_j))^k2 = H(y_j)^{k1*k2}.
        // By commutativity of F, this equals H(x_i)^{k1*k2} whenever
        // x_i == y_j — i.e. exactly what the Sender ships as F_k1k2(x_i)
        // below, for matching elements. This set is built once and used
        // as the lookup structure for membership testing.
        std::vector<ECPoint> vec_fk2k1_y(sender_len, pp.group_ctx);
        #pragma omp parallel for num_threads(config::thread_num)
        for (size_t i = 0; i < sender_len; ++i) {
            vec_fk2k1_y[i] = vec_fk1_y[i] * k2;
        }

        // Step 4: receive the Sender's index-aligned, doubly-masked X
        // values, build a local Y-side lookup set, and test each received
        // value in turn. A match at wire-position i is reported as vec_x[i].
        if (pp.membership_mode == MembershipMode::Truncate) {
            TAIHANG_LOG("cwPRF PSI [step 3]:", "Receiver receives Truncate(F_k1k2(x_i)) from Sender...");
            // Pre-size with the correct count AND element length so that
            // recv(vector<string>) can derive both num and len without a header.
            std::vector<std::string> vec_truncated_fk1k2_x(
                receiver_len, std::string(pp.truncate_byte_len, '\0'));
            io.recv(vec_truncated_fk1k2_x);

            std::unordered_set<std::string> set_truncated_fk2k1_y;
            set_truncated_fk2k1_y.reserve(sender_len);
            for (size_t j = 0; j < sender_len; ++j) {
                set_truncated_fk2k1_y.insert(
                    truncate_to_string(vec_fk2k1_y[j].to_bytes(), pp.truncate_byte_len));
            }

            // Collect match flags in parallel, then build the intersection
            // serially — avoids a data race on vec_intersection.push_back().
            std::vector<uint8_t> matched(receiver_len, 0);
            #pragma omp parallel for num_threads(config::thread_num)
            for (size_t i = 0; i < receiver_len; ++i) {
                if (set_truncated_fk2k1_y.contains(vec_truncated_fk1k2_x[i])) {
                    matched[i] = 1;
                }
            }
            for (size_t i = 0; i < receiver_len; ++i) {
                if (matched[i]) vec_intersection.push_back(vec_x[i]);
            }
        }
        else {
            TAIHANG_LOG("cwPRF PSI [step 3]:", "Receiver receives F_k1k2(x_i) [PlainSet] from Sender ...");
            std::vector<ECPoint> vec_fk1k2_x(receiver_len, pp.group_ctx);
            io.recv(vec_fk1k2_x);

            std::unordered_set<ECPoint, ECPointHash> set_fk2k1_y;
            set_fk2k1_y.reserve(sender_len);
            for (size_t j = 0; j < sender_len; ++j) {
                set_fk2k1_y.insert(vec_fk2k1_y[j]);
            }

            std::vector<uint8_t> matched(receiver_len, 0);
            #pragma omp parallel for num_threads(config::thread_num)
            for (size_t i = 0; i < receiver_len; ++i) {
                if (set_fk2k1_y.contains(vec_fk1k2_x[i])) {
                    matched[i] = 1;
                }
            }
            for (size_t i = 0; i < receiver_len; ++i) {
                if (matched[i]) vec_intersection.push_back(vec_x[i]);
            }
        }
    }
    // -----------------------------------------------------------------
    // X25519 branch: EC25519Point
    // -----------------------------------------------------------------
    else {
        // Pick a secret random exponent key k2: 32 raw CSPRNG bytes.
        std::vector<uint8_t> k2(EC25519Point::SCALAR_BYTE_LEN);
        TAIHANG_CHECK(RAND_bytes(k2.data(), EC25519Point::SCALAR_BYTE_LEN) == 1,
                      "cwPRF PSI: RAND_bytes failed while generating k2.");

        // Step 1: F_k2(H(x_i)) = H(x_i)^k2
        std::vector<EC25519Point> vec_fk2_x(receiver_len);
        #pragma omp parallel for num_threads(config::thread_num)
        for (size_t i = 0; i < receiver_len; ++i) {
            vec_fk2_x[i] = hash_to_curve25519(vec_x[i]) * k2;
        }

        // Step 2: exchange with Sender.
        TAIHANG_LOG("cwPRF PSI [step 1]:", "Receiver receives F_k1(H(y_i)) from Sender ...");
        std::vector<EC25519Point> vec_fk1_y(sender_len);
        io.recv(vec_fk1_y);

        TAIHANG_LOG("cwPRF PSI [step 2]:", std::format("Receiver ===> F_k2(H(x_i)) ===> Sender [{:.2f} MB]",
                        static_cast<double>(receiver_len * EC25519Point::POINT_BYTE_LEN) / (1024 * 1024)));
        io.send(vec_fk2_x);

        // Step 3: F_k2k1(y_j) = (F_k1(y_j))^k2, used as the lookup set.
        std::vector<EC25519Point> vec_fk2k1_y(sender_len);
        #pragma omp parallel for num_threads(config::thread_num)
        for (size_t i = 0; i < sender_len; ++i) {
            vec_fk2k1_y[i] = vec_fk1_y[i] * k2;
        }

        // Step 4: receive Sender's index-aligned, doubly-masked X values
        // and test each against the local Y-side lookup set.
        if (pp.membership_mode == MembershipMode::Truncate) {
            TAIHANG_LOG("cwPRF PSI [step 3]:", "Receiver receives Truncate(F_k1k2(x_i)) from Sender ...");
            // Pre-size with the correct count AND element length so that
            // recv(vector<string>) can derive both num and len without a header.
            std::vector<std::string> vec_truncated_fk1k2_x(
                receiver_len, std::string(pp.truncate_byte_len, '\0'));
            io.recv(vec_truncated_fk1k2_x);

            std::unordered_set<std::string> set_truncated_fk2k1_y;
            set_truncated_fk2k1_y.reserve(sender_len);
            for (size_t j = 0; j < sender_len; ++j) {
                set_truncated_fk2k1_y.insert(
                    truncate_to_string(vec_fk2k1_y[j].to_bytes(), pp.truncate_byte_len));
            }

            std::vector<uint8_t> matched(receiver_len, 0);
            #pragma omp parallel for num_threads(config::thread_num)
            for (size_t i = 0; i < receiver_len; ++i) {
                if (set_truncated_fk2k1_y.contains(vec_truncated_fk1k2_x[i])) {
                    matched[i] = 1;
                }
            }
            for (size_t i = 0; i < receiver_len; ++i) {
                if (matched[i]) vec_intersection.push_back(vec_x[i]);
            }
        }
        else {
            TAIHANG_LOG("cwPRF PSI [step 3]:", "Receiver receives F_k1k2(x_i) [PlainSet] from Sender ...");
            std::vector<EC25519Point> vec_fk1k2_x(receiver_len);
            io.recv(vec_fk1k2_x);

            std::unordered_set<EC25519Point, EC25519PointHash> set_fk2k1_y;
            set_fk2k1_y.reserve(sender_len);
            for (size_t j = 0; j < sender_len; ++j) {
                set_fk2k1_y.insert(vec_fk2k1_y[j]);
            }

            std::vector<uint8_t> matched(receiver_len, 0);
            #pragma omp parallel for num_threads(config::thread_num)
            for (size_t i = 0; i < receiver_len; ++i) {
                if (set_fk2k1_y.contains(vec_fk1k2_x[i])) {
                    matched[i] = 1;
                }
            }
            for (size_t i = 0; i < receiver_len; ++i) {
                if (matched[i]) vec_intersection.push_back(vec_x[i]);
            }
        }
    }

    TAIHANG_LOG("cwPRF PSI:", "Receiver protocol context successfully completed <<<");
    return vec_intersection;
}

} // namespace taihang::mpc::cwprf_psi