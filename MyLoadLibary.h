#pragma once
#include <windows.h>
#include <string>
#include "FileBuffer.h"


using namespace std;


class MyLoadLibary {

public:
	MyLoadLibary(string);
	HMODULE Load();
private:
	string filename;
	FileBuffer fb;
	DWORD filesizeinBytes;
	WORD filestate;
	BYTE* pImageBase;
	bool ReadAndValidateHeaders();
	void MapSectionsToMemory();
	bool HandleRelocations();     
	bool ResolveDependencies();
	bool ExecuteEntryPoint();
	//const wchar_t* //GetWC(const char*);

};

