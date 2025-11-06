#pragma once

#include <windows.h>
#include <iostream>

class MemoryAlloc {
public:
    LPVOID memory;

    MemoryAlloc() : memory(nullptr) {}

    MemoryAlloc(LPVOID mem) : memory(mem) {}

    ~MemoryAlloc();

    MemoryAlloc(const MemoryAlloc& other) = delete;
    MemoryAlloc& operator=(const MemoryAlloc& other) = delete;

    MemoryAlloc(MemoryAlloc&& other) noexcept;

    MemoryAlloc& operator=(MemoryAlloc&& other) noexcept;
};