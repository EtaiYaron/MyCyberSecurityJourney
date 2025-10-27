#include <windows.h>
#include <string>
#include "FileBuffer.h"
#pragma once

using namespace std;


class MyLoadLibary {

public:
	MyLoadLibary(string);
	HMODULE Load();
private:
	string filename;
	FileBuffer fb;
	DWORD filesizeinBytes;
	BYTE* pImageBase;
	PIMAGE_NT_HEADERS pNtHeaders;
	bool ReadAndValidateHeaders();
	void MapSectionsToMemory();
	bool HandleRelocations();     
	bool ResolveDependencies();
	bool ExecuteEntryPoint();
	//const wchar_t* //GetWC(const char*);

};

