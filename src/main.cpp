#include "satp64.hpp"
#include <cassert>
#include <iostream>

int main() {
    constexpr std::array<uint8_t, 16> key = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
    };

    Satp64 cipher(key);
    constexpr uint64_t plaintext = 0x0123456789ABCDEF;

    uint64_t ciphertext = cipher.encrypt_block(plaintext);
    uint64_t decrypted = cipher.decrypt_block(ciphertext);

    assert(plaintext == decrypted);
    assert(plaintext != ciphertext);

    std::cout << "OK" << std::endl;
    return 0;
}
