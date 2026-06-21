/****************************************************************************
 * @file      test_cwprf_mqrpmt.cpp
 * @brief     Google Test unit testing suite for cwPRF-based mqRPMT protocol.
 * @details   Spawns local loopback server-client net tasks concurrently using
 * std::async to mirror full network serialization/deserialization.
 * @author    This file is part of Taihang, developed by Yu Chen.
 *****************************************************************************/

#include <gtest/gtest.h>
#include <taihang/mpc/rpmt/cwprf_mqrpmt.hpp>
#include <taihang/common/logger.hpp>
#include <taihang/crypto/prg.hpp>
#include <future>
#include <set>
#include <cstring>
#include <sstream>

using namespace taihang;
using namespace taihang::mpc::cwprf_mqrpmt;

class CwPRFMqRPMTTest : public ::testing::Test {
protected:
    void SetUp() override {
        std::cout << "[===============================================================]" << std::endl;
    }

    void TearDown() override {
        std::cout << "[===============================================================]" << std::endl;
    }
};

TEST_F(CwPRFMqRPMTTest, EndToEndIntersection) {
    // Protocol Configuration Parameters
    constexpr int kCurveId = 415; // Secp256r1
    constexpr size_t kStatisticalSecurityParameter = 40;
    constexpr size_t kLogServerLen = 6; // 64 elements
    constexpr size_t kLogClientLen = 5; // 32 elements

    size_t server_len = static_cast<size_t>(std::pow(2, kLogServerLen));
    size_t client_len = static_cast<size_t>(std::pow(2, kLogClientLen));

    // Setup configurations matching Taihang pattern
    PublicParameters pp = setup(kCurveId, kStatisticalSecurityParameter, kLogServerLen, kLogClientLen);

    // 1. Generate Synthetic Datasets
    std::vector<Block> vec_y(server_len); // Server Set
    std::vector<Block> vec_x(client_len); // Client Set

    // Correctly initialize seed using lowercase prg namespace and standalone make_block
    Block fixed_seed_block = make_block(0x123456789ABCDEF0ULL, 0x0FEDCBA987654321ULL);
    prg::Seed seed = prg::set_seed(&fixed_seed_block, 0);
    
    std::vector<Block> random_pool(server_len + client_len);
    prg::gen_random_blocks(seed, random_pool.data(), random_pool.size());

    // Distribute to server
    for (size_t i = 0; i < server_len; ++i) {
        vec_y[i] = random_pool[i];
    }

    // Force an intersection overlap for testing correctness (first half of client shares with server)
    size_t expected_intersection_count = client_len / 2;
    
    // Custom comparator lambda for std::set usage with taihang::Block via explicit structural comparison
    auto block_less_than = [](const Block& lhs, const Block& rhs) {
        return std::memcmp(&lhs, &rhs, sizeof(Block)) < 0;
    };
    std::set<Block, decltype(block_less_than)> ground_truth_intersection(block_less_than);

    for (size_t i = 0; i < client_len; ++i) {
        if (i < expected_intersection_count) {
            vec_x[i] = random_pool[i]; // Intersection element
            ground_truth_intersection.insert(vec_x[i]);
        } else {
            vec_x[i] = random_pool[server_len + i]; // Distinct disjoint element
        }
    }

    // Port definition for loopback communication
    const std::string address = "127.0.0.1";
    const uint16_t port = 12345;

    // 2. Spawn Concurrent Channel Roles via std::async
    auto server_task = std::async(std::launch::async, [&]() -> std::vector<uint8_t> {
        // Aligned constructor signature: NetIO(party, address, port)
        net::NetIO io_server("server", address, port); 
        return server(io_server, pp, vec_y);
    });

    auto client_task = std::async(std::launch::async, [&]() {
        // Aligned constructor signature: NetIO(party, address, port)
        net::NetIO io_client("client", address, port); 
        client(io_client, pp, vec_x);
    });

    // Wait for executions and collect the server indication bits
    client_task.get();
    std::vector<uint8_t> vec_indication_bit = server_task.get();

    // 3. Validation Analysis
    TAIHANG_ASSERT(vec_indication_bit.size() == client_len, "Test Failure: Output indicator map size mismatch.");

    size_t detected_intersection_count = 0;
    for (size_t i = 0; i < client_len; ++i) {
        bool exists_in_server = (ground_truth_intersection.find(vec_x[i]) != ground_truth_intersection.end());
        
        if (vec_indication_bit[i] == 1) {
            detected_intersection_count++;
            EXPECT_TRUE(exists_in_server) << "False Positive encountered at index " << i;
        } else {
            EXPECT_FALSE(exists_in_server) << "False Negative encountered at index " << i;
        }
    }

    std::cout << "[ RESULT     ] Expected Intersection Size: " << expected_intersection_count 
              << " | Found: " << detected_intersection_count << std::endl;
    
    EXPECT_GE(detected_intersection_count, expected_intersection_count);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}