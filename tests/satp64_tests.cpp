#include "satp64.hpp"
#include <gtest/gtest.h>
#include <bitset>
#include <random>
#include <vector>
#include <cmath>

TEST(Satp64Test, KnownAnswerTest) {
    constexpr std::array<uint8_t, 16> key = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };
    Satp64 cipher(key);

    uint64_t pt = 0x0123456789ABCDEFULL;
    uint64_t ct = cipher.encrypt_block(pt);

    EXPECT_NE(ct, pt);
    EXPECT_NE(ct, 0x0ULL);

    uint64_t dt = cipher.decrypt_block(ct);
    EXPECT_EQ(dt, pt);
}

TEST(Satp64Test, StrictAvalancheCriterionMatrix) {
    constexpr std::array<uint8_t, 16> key = {
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
    };

    Satp64 cipher(key);
    std::mt19937_64 rng(1337);

    constexpr size_t sample_size = 50000;
    std::vector<std::vector<size_t>> sac_matrix(64, std::vector<size_t>(64, 0));

    for (size_t sample = 0; sample < sample_size; ++sample) {
        uint64_t pt1 = rng();
        uint64_t ct1 = cipher.encrypt_block(pt1);

        for (size_t bit_in = 0; bit_in < 64; ++bit_in) {
            uint64_t pt2 = pt1 ^ (1ULL << bit_in);
            uint64_t ct2 = cipher.encrypt_block(pt2);
            uint64_t diff = ct1 ^ ct2;

            for (size_t bit_out = 0; bit_out < 64; ++bit_out) {
                if ((diff >> bit_out) & 1ULL) {
                    sac_matrix[bit_in][bit_out]++;
                }
            }
        }
    }

    for (size_t in = 0; in < 64; ++in) {
        for (size_t out = 0; out < 64; ++out) {
            double prob = static_cast<double>(sac_matrix[in][out]) / sample_size;
            EXPECT_NEAR(prob, 0.5, 0.03);
        }
    }
}

TEST(Satp64Test, KeyAvalancheCriterion) {
    uint64_t pt = 0xDEADBEEFCAFEBABEULL;
    std::mt19937_64 rng(42);

    constexpr size_t iterations = 10000;
    size_t total_flipped_bits = 0;

    for (size_t i = 0; i < iterations; ++i) {
        std::array<uint8_t, 16> key1{};
        for (auto& byte : key1) byte = static_cast<uint8_t>(rng());

        std::array<uint8_t, 16> key2 = key1;
        size_t byte_idx = rng() % 16;
        size_t bit_idx = rng() % 8;
        key2[byte_idx] ^= (1U << bit_idx);

        Satp64 cipher1(key1);
        Satp64 cipher2(key2);

        uint64_t ct1 = cipher1.encrypt_block(pt);
        uint64_t ct2 = cipher2.encrypt_block(pt);

        total_flipped_bits += std::bitset<64>(ct1 ^ ct2).count();
    }

    double avg_flipped = static_cast<double>(total_flipped_bits) / iterations;
    EXPECT_GE(avg_flipped, 29.5);
    EXPECT_LE(avg_flipped, 34.5);
}
