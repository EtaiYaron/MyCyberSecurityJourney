#pragma once

#include <string>
#include <windows.h>
#include "FileBuffer.h"   
#include "MemoryAlloc.h"  

using namespace std;

class MyLoadLibary {
public:
    string filename;
    DWORD filesizeinBytes;
    FileBuffer fb; 
    DWORD e_lfanew;
    WORD filestate;
    WORD num_of_sections;
    MemoryAlloc memory_alloc; 

    MyLoadLibary(string filename);
    bool Load();

private:
    void SetMemoryProtections();
    void ReadAndValidateHeaders();
    PIMAGE_SECTION_HEADER GetSectionTable(PIMAGE_NT_HEADERS pNtHeaders);
    void MapSectionsToMemory();
    void ResolveDependencies();
    bool ExecuteEntryPoint();
};