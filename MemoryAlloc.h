#pragma once
#include <windows.h>



class MemoryAlloc {
public:
	MemoryAlloc();
	MemoryAlloc(LPVOID);
	~MemoryAlloc();
	LPVOID memory;
};