#pragma once
#include <windows.h>
#include <string>
#include "FileBuffer.h"
#include "MemoryAlloc.h"


using namespace std;


class MyLoadLibary {

public:
	MyLoadLibary(string);
	bool Load();
private:

	string filename;
	FileBuffer fb;
	DWORD filesizeinBytes;
	WORD filestate;
	DWORD e_lfanew;
	WORD num_of_sections;
	MemoryAlloc memory_alloc;
	void ReadAndValidateHeaders();
	void MapSectionsToMemory();    
	void ResolveDependencies();
	bool ExecuteEntryPoint();
	//const wchar_t* //GetWC(const char*);
	PIMAGE_SECTION_HEADER  GetSectionTable(PIMAGE_NT_HEADERS);


};

