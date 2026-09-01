#include "satp64.hpp"
#include <cstring>

Satp64::Satp64(std::span<const uint8_t, 16> key) noexcept {
    std::array<uint32_t, 4> w{};
    for (size_t i = 0; i < 4; ++i) {
        std::memcpy(&w[i], key.data() + i * 4, sizeof(uint32_t));
    }

    for (size_t i = 0; i < 8; ++i) {
        size_t k_idx = i % 4;
        size_t k_next = (i + 1) % 4;
        uint32_t rot = std::rotl(w[k_next], static_cast<int>(i + 1));
        round_keys_[i] = (w[k_idx] ^ rot) + 0x9E3779B9u;
    }
}

uint32_t Satp64::apply_sbox(uint32_t val) noexcept {
    uint8_t bytes[4];
    std::memcpy(bytes, &val, sizeof(uint32_t));
    for (size_t i = 0; i < 4; ++i) {
        bytes[i] = SBOX[bytes[i]];
    }
    uint32_t out;
    std::memcpy(&out, bytes, sizeof(uint32_t));
    return out;
}

uint32_t Satp64::feistel_f(uint32_t r, uint32_t k) const noexcept {
    uint32_t x = r ^ k;
    uint32_t y = apply_sbox(x);
    return std::rotl(y, 13) ^ std::rotr(y, 5);
}

uint64_t Satp64::encrypt_block(uint64_t block) const noexcept {
    auto l = static_cast<uint32_t>(block >> 32);
    auto r = static_cast<uint32_t>(block & 0xFFFFFFFFu);

    for (size_t i = 0; i < 8; ++i) {
        uint32_t next_l = r;
        uint32_t next_r = l ^ feistel_f(r, round_keys_[i]);
        l = next_l;
        r = next_r;
    }

    return (static_cast<uint64_t>(r) << 32) | static_cast<uint64_t>(l);
}

uint64_t Satp64::decrypt_block(uint64_t block) const noexcept {
    auto l = static_cast<uint32_t>(block >> 32);
    auto r = static_cast<uint32_t>(block & 0xFFFFFFFFu);

    for (int i = 7; i >= 0; --i) {
        uint32_t next_l = r;
        uint32_t next_r = l ^ feistel_f(r, round_keys_[static_cast<size_t>(i)]);
        l = next_l;
        r = next_r;
    }

    return (static_cast<uint64_t>(r) << 32) | static_cast<uint64_t>(l);
}
