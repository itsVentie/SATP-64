# SATP-64

A 64-bit symmetric block cipher with a 128-bit key, implemented in modern C++20.

## Requirements

* CMake 3.20+
* C++20 compliant compiler (MSVC, GCC, Clang)

## Build & Test

```powershell
mkdir build && cd build
cmake ..
cmake --build .
ctest -C Debug --output-on-failure

```
