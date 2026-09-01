#include "satp64.hpp"
#include <gtest/gtest.h>
#include <bitset>
#include <random>

TEST(Satp64Test, BasicEncryptDecrypt) {
    constexpr std::array<uint8_t, 16> key = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
    };

    Satp64 cipher(key);
    uint64_t plaintext = 0x0123456789ABCDEF;

    uint64_t ciphertext = cipher.encrypt_block(plaintext);
    uint64_t decrypted = cipher.decrypt_block(ciphertext);

    EXPECT_NE(plaintext, ciphertext);
    EXPECT_EQ(plaintext, decrypted);
}

TEST(Satp64Test, ZeroBlockAndKey) {
    constexpr std::array<uint8_t, 16> zero_key{};
    Satp64 cipher(zero_key);

    uint64_t plaintext = 0x0;
    uint64_t ciphertext = cipher.encrypt_block(plaintext);
    uint64_t decrypted = cipher.decrypt_block(ciphertext);

    EXPECT_EQ(plaintext, decrypted);
}

TEST(Satp64Test, StrictAvalancheCriterion) {
    constexpr std::array<uint8_t, 16> key = {
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
    };

    Satp64 cipher(key);
    std::mt19937_64 rng(1337);

    constexpr size_t iterations = 10000;
    size_t total_flipped_bits = 0;

    for (size_t i = 0; i < iterations; ++i) {
        uint64_t pt1 = rng();
        size_t bit_to_flip = rng() % 64;
        uint64_t pt2 = pt1 ^ (1ULL << bit_to_flip);

        uint64_t ct1 = cipher.encrypt_block(pt1);
        uint64_t ct2 = cipher.encrypt_block(pt2);

        uint64_t diff = ct1 ^ ct2;
        total_flipped_bits += std::bitset<64>(diff).count();
    }

    double avg_flipped = static_cast<double>(total_flipped_bits) / iterations;

    EXPECT_GE(avg_flipped, 29.0);
    EXPECT_LE(avg_flipped, 35.0);
}
