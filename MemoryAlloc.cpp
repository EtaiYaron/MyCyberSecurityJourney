#include "MemoryAlloc.h"
#include <windows.h> // For VirtualFree

MemoryAlloc::~MemoryAlloc() {
    if (memory) {
        VirtualFree(memory, 0, MEM_RELEASE);
    }
}

MemoryAlloc::MemoryAlloc(MemoryAlloc&& other) noexcept
    : memory(other.memory) {

    other.memory = nullptr;
}

MemoryAlloc& MemoryAlloc::operator=(MemoryAlloc&& other) noexcept {
    if (this == &other) {
        return *this;
    }

    if (memory) {
        VirtualFree(memory, 0, MEM_RELEASE);
    }

    this->memory = other.memory;

    other.memory = nullptr;

    return *this;
}