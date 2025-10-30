#include"MemoryAlloc.h"
#include <stdexcept> 

using namespace std;


MemoryAlloc::MemoryAlloc() {
	// Default constructor logic (if needed)
}

MemoryAlloc::MemoryAlloc(LPVOID memory) {
	if (memory == NULL) {
		throw invalid_argument("VirtualAlloc(MEM_RESERVE) failed or was allocated at a different address.");
	}
	this->memory = memory;

}

MemoryAlloc::~MemoryAlloc() {
	if (memory != NULL) {
		VirtualFree(memory, 0, MEM_RELEASE);
	}
}